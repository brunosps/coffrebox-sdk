//! People surface (the Stimulus web vault).

use std::fmt::Write as _;

use coffrebox_core::app_token::AppCredentials;
use coffrebox_core::encoding::{b64url_decode, b64url_encode, generate_password, random_uuid_v4};
use coffrebox_core::item::{ItemPayload, decrypt_item, encrypt_item};
use coffrebox_core::kdf::{KdfParams, Kek, derive_account_keys};
use coffrebox_core::keys::{
    UserKeyset, compute_fingerprint_from_envelopes, decode_ed25519_pub, decode_x25519_pub,
    verify_fingerprint_last4,
};
use coffrebox_core::manifest::{
    ManifestItemEntry, MemberRoster, RosterApp, RosterMember, VaultManifest, VaultRole,
};
use coffrebox_core::password_change::{self, PasswordChangeError};
use coffrebox_core::password_policy::check_master_password;
use coffrebox_core::snapshot::EncryptedSnapshot;
use coffrebox_core::trust::{TrustStore, TrustedVault, verify_vault_for_user};
use coffrebox_core::vault::{
    RecipientKind, VaultKey, VaultMeta, decrypt_vault_meta, encrypt_vault_meta, open_vault_key,
    seal_vault_key,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{WasmError, map_err};

fn parse_uuid(s: &str) -> Result<Uuid, WasmError> {
    Uuid::parse_str(s.trim()).map_err(|_| WasmError::msg("[FORMAT] invalid UUID"))
}

#[derive(Serialize, Deserialize)]
struct UnlockedWebSession {
    user_id: Uuid,
    enc_sk_b64: String,
    sign_seed_b64: String,
}

impl UnlockedWebSession {
    fn to_keyset(&self) -> Result<UserKeyset, WasmError> {
        let enc_vec = Zeroizing::new(b64url_decode(&self.enc_sk_b64).map_err(map_err)?);
        let sign_vec = Zeroizing::new(b64url_decode(&self.sign_seed_b64).map_err(map_err)?);
        let enc: [u8; 32] = enc_vec
            .as_slice()
            .try_into()
            .map_err(|_| WasmError::msg("[FORMAT] invalid enc_sk"))?;
        let sign: [u8; 32] = sign_vec
            .as_slice()
            .try_into()
            .map_err(|_| WasmError::msg("[FORMAT] invalid sign_seed"))?;
        Ok(UserKeyset::from_raw(enc, sign))
    }
}

/// Master password problems under the minimum policy (JSON: list of `{code, message}`; empty =
/// ok). `message` is in English; the web vault shows its own text for each `code`.
#[wasm_bindgen]
pub fn master_password_problems(master_password: &str, email: &str, name: &str) -> String {
    let list: Vec<serde_json::Value> = check_master_password(master_password, email, name)
        .into_iter()
        .map(|p| serde_json::json!({ "code": p, "message": p.message() }))
        .collect();
    serde_json::Value::Array(list).to_string()
}

#[wasm_bindgen]
pub fn generate_signup_bundle(
    name: &str,
    email: &str,
    master_password: &str,
) -> Result<String, WasmError> {
    if !check_master_password(master_password, email, name).is_empty() {
        return Err(WasmError::msg(
            "[WEAK_PASSWORD] master password does not meet the minimum policy",
        ));
    }
    let user_id = random_uuid_v4().map_err(map_err)?;
    let kdf = KdfParams::generate_default().map_err(map_err)?;
    let (auth_key, kek) = derive_account_keys(master_password, user_id, &kdf).map_err(map_err)?;
    let keyset = UserKeyset::generate().map_err(map_err)?;
    let encrypted_keyset = keyset.seal(&kek, user_id).map_err(map_err)?;

    serde_json::to_string(&serde_json::json!({
        "request": {
            "user_id": user_id,
            "name": name,
            "email": email,
            "auth_key": auth_key.as_str(),
            "kdf": kdf,
            "enc_public_key": keyset.enc_public_envelope(),
            "sign_public_key": keyset.sign_public_envelope(),
            "encrypted_keyset": encrypted_keyset,
            "fingerprint": keyset.fingerprint(),
        },
        "session": UnlockedWebSession {
            user_id,
            enc_sk_b64: b64url_encode(keyset.enc_secret_bytes()),
            sign_seed_b64: b64url_encode(keyset.sign_seed_bytes()),
        }
    }))
    .map_err(|_| WasmError::msg("[FORMAT] failed to serialize signup"))
}

#[wasm_bindgen]
pub fn derive_login_bundle(
    master_password: &str,
    user_id_str: &str,
    kdf_json: &str,
) -> Result<String, WasmError> {
    let user_id = parse_uuid(user_id_str)?;
    let kdf: KdfParams =
        serde_json::from_str(kdf_json).map_err(|_| WasmError::msg("[FORMAT] invalid kdf"))?;
    let (auth_key, kek) = derive_account_keys(master_password, user_id, &kdf).map_err(map_err)?;

    serde_json::to_string(&serde_json::json!({
        "auth_key": auth_key.as_str(),
        "kek_b64": b64url_encode(kek.as_bytes()),
    }))
    .map_err(|_| WasmError::msg("[FORMAT] failed to serialize login bundle"))
}

#[wasm_bindgen]
pub fn unlock_user_session(
    encrypted_keyset: &str,
    kek_b64: &str,
    user_id_str: &str,
) -> Result<String, WasmError> {
    let user_id = parse_uuid(user_id_str)?;
    let kek_vec = Zeroizing::new(b64url_decode(kek_b64).map_err(map_err)?);
    let kek_bytes: [u8; 32] = kek_vec
        .as_slice()
        .try_into()
        .map_err(|_| WasmError::msg("[FORMAT] invalid kek"))?;
    let kek = Kek::from_bytes(kek_bytes);
    let keyset = UserKeyset::open(encrypted_keyset, &kek, user_id).map_err(map_err)?;

    serde_json::to_string(&UnlockedWebSession {
        user_id,
        enc_sk_b64: b64url_encode(keyset.enc_secret_bytes()),
        sign_seed_b64: b64url_encode(keyset.sign_seed_bytes()),
    })
    .map_err(|_| WasmError::msg("[FORMAT] failed to serialize session"))
}

#[wasm_bindgen]
pub fn create_vault_bundle(
    session_json: &str,
    vault_name: &str,
    kind: &str,
) -> Result<String, WasmError> {
    let session: UnlockedWebSession = serde_json::from_str(session_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid session"))?;
    let keyset = session.to_keyset()?;
    let vault_id = random_uuid_v4().map_err(map_err)?;
    let vk = VaultKey::generate().map_err(map_err)?;
    let (encrypted_meta, meta_sha) =
        encrypt_vault_meta(&vk, vault_id, 1, &VaultMeta::new(vault_name)).map_err(map_err)?;
    let (owner_sealed_vk, owner_vk_sig) = seal_vault_key(
        &vk,
        &keyset.enc_public_bytes(),
        RecipientKind::User,
        vault_id,
        session.user_id,
        1,
        &keyset,
    )
    .map_err(map_err)?;

    let roster = MemberRoster::new(
        vault_id,
        1,
        vec![RosterMember {
            enc_pub: keyset.enc_public_envelope(),
            role: VaultRole::Owner,
            sign_pub: keyset.sign_public_envelope(),
            user_id: session.user_id,
        }],
    )
    .map_err(map_err)?;
    let (roster_json, roster_sig) = roster.sign(&keyset).map_err(map_err)?;

    let manifest =
        VaultManifest::new(vault_id, 1, 1, session.user_id, meta_sha, vec![]).map_err(map_err)?;
    let (manifest_json, manifest_sig) = manifest.sign(&keyset).map_err(map_err)?;

    serde_json::to_string(&serde_json::json!({
        "vault_id": vault_id,
        "kind": kind,
        "encrypted_meta": encrypted_meta,
        "owner_sealed_vk": owner_sealed_vk,
        "owner_vk_sig": owner_vk_sig,
        "manifest": manifest_json,
        "manifest_sig": manifest_sig,
        "member_roster": roster_json,
        "member_roster_sig": roster_sig,
    }))
    .map_err(|_| WasmError::msg("[FORMAT] failed to serialize vault"))
}

#[derive(Deserialize)]
struct VaultSummaryWire {
    vault_id: Uuid,
    kind: String,
    role: String,
    key_version: u32,
    current_revision: u64,
    encrypted_meta: String,
    sealed_vk: String,
    vk_sig: String,
    grantor_sign_public_key: String,
}

#[wasm_bindgen]
pub fn decrypt_vault_list(session_json: &str, vaults_json: &str) -> Result<String, WasmError> {
    let session: UnlockedWebSession = serde_json::from_str(session_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid session"))?;
    let keyset = session.to_keyset()?;
    let list: Vec<VaultSummaryWire> = serde_json::from_str(vaults_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid vault list"))?;

    let mut out = Vec::with_capacity(list.len());
    for entry in list {
        let grantor_pk = decode_ed25519_pub(&entry.grantor_sign_public_key).map_err(map_err)?;
        let vk = open_vault_key(
            &entry.sealed_vk,
            &entry.vk_sig,
            keyset.enc_secret_bytes(),
            &grantor_pk,
            RecipientKind::User,
            entry.vault_id,
            session.user_id,
            entry.key_version,
        )
        .map_err(map_err)?;
        let meta = decrypt_vault_meta(
            &vk,
            entry.vault_id,
            entry.key_version,
            &entry.encrypted_meta,
        )
        .map_err(map_err)?;
        out.push(serde_json::json!({
            "vault_id": entry.vault_id,
            "nome": meta.nome,
            "kind": entry.kind,
            "role": entry.role,
            "key_version": entry.key_version,
            "current_revision": entry.current_revision,
        }));
    }

    serde_json::to_string(&out).map_err(|_| WasmError::msg("[FORMAT] failed to serialize list"))
}

fn open_trust_store(
    session: &UnlockedWebSession,
    keyset: &UserKeyset,
    sealed_trust_state: &str,
) -> Result<TrustStore, WasmError> {
    if sealed_trust_state.trim().is_empty() {
        Ok(TrustStore::new(session.user_id))
    } else {
        TrustStore::open(sealed_trust_state.trim(), keyset, session.user_id).map_err(map_err)
    }
}

/// Opens the trust state stored by the browser (`""` on first use) and verifies the snapshot
/// against the **local** anchor. Never uses the owner key that came from the server as the anchor.
fn verify_with_trust_state(
    session: &UnlockedWebSession,
    keyset: &UserKeyset,
    snapshot: &EncryptedSnapshot,
    sealed_trust_state: &str,
    accept_owner_fingerprint: Option<&str>,
) -> Result<(TrustedVault, TrustStore), WasmError> {
    let mut store = open_trust_store(session, keyset, sealed_trust_state)?;
    let trusted = verify_vault_for_user(
        snapshot,
        session.user_id,
        keyset,
        store.get(snapshot.vault_id),
        accept_owner_fingerprint,
    )
    .map_err(map_err)?;
    store.put(trusted.pin.clone());
    Ok((trusted, store))
}

/// Verifies and decrypts a person's snapshot.
///
/// `trust_state` is the encrypted state returned by the previous call (`""` on first use); the
/// browser must store the `trust_state` from the response. `accept_owner_fingerprint` is passed
/// only after the person confirms an owner key change (`[OWNER_CHANGED]`).
#[wasm_bindgen]
pub fn decrypt_user_snapshot(
    session_json: &str,
    snapshot_json: &str,
    trust_state: &str,
    accept_owner_fingerprint: Option<String>,
) -> Result<String, WasmError> {
    let session: UnlockedWebSession = serde_json::from_str(session_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid session"))?;
    let keyset = session.to_keyset()?;
    let snapshot: EncryptedSnapshot = serde_json::from_str(snapshot_json)
        .map_err(|_| WasmError::msg("[TAMPERED] invalid snapshot JSON"))?;

    let (trusted, store) = verify_with_trust_state(
        &session,
        &keyset,
        &snapshot,
        trust_state,
        accept_owner_fingerprint.as_deref(),
    )?;

    let mut out = serde_json::to_value(&trusted.snapshot)
        .map_err(|_| WasmError::msg("[FORMAT] failed to serialize decrypted snapshot"))?;
    let roster: Vec<serde_json::Value> = trusted
        .roster
        .as_ref()
        .map(|r| {
            r.members
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "user_id": m.user_id,
                        "role": m.role.as_str(),
                        "fingerprint": compute_fingerprint_from_envelopes(&m.enc_pub, &m.sign_pub)
                            .unwrap_or_default(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            "anchor".into(),
            serde_json::to_value(trusted.anchor).unwrap_or_default(),
        );
        obj.insert(
            "owner_user_id".into(),
            serde_json::json!(trusted.owner_user_id),
        );
        obj.insert(
            "owner_fingerprint".into(),
            serde_json::json!(trusted.owner_fingerprint),
        );
        obj.insert(
            "is_owner".into(),
            serde_json::json!(trusted.is_owner(session.user_id)),
        );
        obj.insert("roster".into(), serde_json::Value::Array(roster));
        // Applications in the owner-signed list: only these receive the key in rotations.
        let roster_apps: Vec<Uuid> = trusted
            .roster
            .as_ref()
            .map(|r| r.apps.iter().map(|a| a.app_id).collect())
            .unwrap_or_default();
        obj.insert("roster_apps".into(), serde_json::json!(roster_apps));
        obj.insert(
            "trust_state".into(),
            serde_json::json!(store.seal(&keyset).map_err(map_err)?),
        );
    }
    serde_json::to_string(&out)
        .map_err(|_| WasmError::msg("[FORMAT] failed to serialize decrypted snapshot"))
}

/// Most items one mutation written in the browser may carry (the web `.env` import shows the same
/// limit before encrypting anything).
pub const MAX_ITEMS_PER_MUTATION: usize = 500;

/// One item to write: `id` of an existing item to replace (its version goes up by one), or none
/// for a new item.
#[derive(Deserialize)]
struct ItemUpsertWire {
    #[serde(default)]
    id: Option<String>,
    payload: ItemPayload,
}

#[wasm_bindgen]
pub fn prepare_item_upsert(
    session_json: &str,
    snapshot_json: &str,
    trust_state: &str,
    item_id_opt: Option<String>,
    item_payload_json: &str,
) -> Result<String, WasmError> {
    let payload: ItemPayload = serde_json::from_str(item_payload_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid item payload"))?;
    upsert_items(
        session_json,
        snapshot_json,
        trust_state,
        vec![ItemUpsertWire {
            id: item_id_opt,
            payload,
        }],
    )
}

/// Several items in one mutation (one revision of the vault): `[{"id": "<uuid>" | null,
/// "payload": {...}}]`. Used by the web `.env` import, so either every item is written or none.
#[wasm_bindgen]
pub fn prepare_items_upsert(
    session_json: &str,
    snapshot_json: &str,
    trust_state: &str,
    items_json: &str,
) -> Result<String, WasmError> {
    let items: Vec<ItemUpsertWire> = serde_json::from_str(items_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid item list"))?;
    upsert_items(session_json, snapshot_json, trust_state, items)
}

fn upsert_items(
    session_json: &str,
    snapshot_json: &str,
    trust_state: &str,
    items: Vec<ItemUpsertWire>,
) -> Result<String, WasmError> {
    if items.is_empty() || items.len() > MAX_ITEMS_PER_MUTATION {
        return Err(WasmError::msg(format!(
            "[FORMAT] a mutation carries from 1 to {MAX_ITEMS_PER_MUTATION} items"
        )));
    }
    let session: UnlockedWebSession = serde_json::from_str(session_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid session"))?;
    let keyset = session.to_keyset()?;
    let snapshot: EncryptedSnapshot = serde_json::from_str(snapshot_json)
        .map_err(|_| WasmError::msg("[TAMPERED] invalid snapshot JSON"))?;

    let (trusted, _) = verify_with_trust_state(&session, &keyset, &snapshot, trust_state, None)?;
    let vk = &trusted.vault_key;
    let dec = &trusted.snapshot;
    let old_manifest = VaultManifest::parse_canonical(&snapshot.manifest).map_err(map_err)?;

    let mut written = std::collections::HashSet::new();
    let mut upserts = Vec::with_capacity(items.len());
    let mut new_entries = Vec::with_capacity(items.len());
    for item in items {
        let (item_id, next_ver) = match item.id {
            Some(ref s) if !s.trim().is_empty() => {
                let id = parse_uuid(s)?;
                let prev = dec
                    .items
                    .iter()
                    .find(|i| i.id == id)
                    .map(|i| i.version)
                    .unwrap_or(0);
                (id, prev + 1)
            }
            _ => (random_uuid_v4().map_err(map_err)?, 1),
        };
        if !written.insert(item_id) {
            return Err(WasmError::msg("[FORMAT] the same item appears twice"));
        }
        let (ct, sha) = encrypt_item(
            vk,
            snapshot.vault_id,
            item_id,
            next_ver,
            dec.key_version,
            &item.payload,
        )
        .map_err(map_err)?;
        upserts.push(serde_json::json!({
            "id": item_id,
            "version": next_ver,
            "key_version": dec.key_version,
            "ciphertext": ct,
            "sha256": sha,
        }));
        new_entries.push(ManifestItemEntry {
            id: item_id,
            sha256: sha,
            version: next_ver,
        });
    }

    let mut entries: Vec<ManifestItemEntry> = old_manifest
        .items
        .into_iter()
        .filter(|e| !written.contains(&e.id))
        .collect();
    entries.extend(new_entries);

    let next_manifest = VaultManifest::new(
        snapshot.vault_id,
        dec.revision + 1,
        dec.key_version,
        session.user_id,
        old_manifest.vault_meta_sha256,
        entries,
    )
    .map_err(map_err)?;
    let (manifest_json, manifest_sig) = next_manifest.sign(&keyset).map_err(map_err)?;

    serde_json::to_string(&serde_json::json!({
        "expected_revision": dec.revision,
        "encrypted_meta": null,
        "upserts": upserts,
        "deletes": [],
        "manifest": manifest_json,
        "manifest_sig": manifest_sig,
    }))
    .map_err(|_| WasmError::msg("[FORMAT] failed to serialize mutation"))
}

#[wasm_bindgen]
pub fn prepare_item_delete(
    session_json: &str,
    snapshot_json: &str,
    trust_state: &str,
    item_id_str: &str,
) -> Result<String, WasmError> {
    let session: UnlockedWebSession = serde_json::from_str(session_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid session"))?;
    let keyset = session.to_keyset()?;
    let snapshot: EncryptedSnapshot = serde_json::from_str(snapshot_json)
        .map_err(|_| WasmError::msg("[TAMPERED] invalid snapshot JSON"))?;
    let item_id = parse_uuid(item_id_str)?;

    let (trusted, _) = verify_with_trust_state(&session, &keyset, &snapshot, trust_state, None)?;
    let dec = &trusted.snapshot;
    let old_manifest = VaultManifest::parse_canonical(&snapshot.manifest).map_err(map_err)?;

    let entries: Vec<ManifestItemEntry> = old_manifest
        .items
        .into_iter()
        .filter(|e| e.id != item_id)
        .collect();

    let next_manifest = VaultManifest::new(
        snapshot.vault_id,
        dec.revision + 1,
        dec.key_version,
        session.user_id,
        old_manifest.vault_meta_sha256,
        entries,
    )
    .map_err(map_err)?;
    let (manifest_json, manifest_sig) = next_manifest.sign(&keyset).map_err(map_err)?;

    serde_json::to_string(&serde_json::json!({
        "expected_revision": dec.revision,
        "encrypted_meta": null,
        "upserts": [],
        "deletes": [item_id],
        "manifest": manifest_json,
        "manifest_sig": manifest_sig,
    }))
    .map_err(|_| WasmError::msg("[FORMAT] failed to serialize deletion"))
}

#[derive(Deserialize)]
struct ItemVersionWire {
    version: u32,
    key_version: u32,
    ciphertext: String,
    created_at: String,
}

#[wasm_bindgen]
pub fn decrypt_item_versions(
    session_json: &str,
    snapshot_json: &str,
    trust_state: &str,
    item_id_str: &str,
    versions_json: &str,
) -> Result<String, WasmError> {
    let session: UnlockedWebSession = serde_json::from_str(session_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid session"))?;
    let keyset = session.to_keyset()?;
    let snapshot: EncryptedSnapshot = serde_json::from_str(snapshot_json)
        .map_err(|_| WasmError::msg("[TAMPERED] invalid snapshot JSON"))?;
    let item_id = parse_uuid(item_id_str)?;

    let (trusted, _) = verify_with_trust_state(&session, &keyset, &snapshot, trust_state, None)?;
    let vk = &trusted.vault_key;
    let dec = &trusted.snapshot;
    let raw_versions: Vec<ItemVersionWire> = serde_json::from_str(versions_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid history"))?;

    let mut out = Vec::new();
    for v in raw_versions {
        if v.key_version == dec.key_version
            && let Ok(payload) = decrypt_item(
                vk,
                snapshot.vault_id,
                item_id,
                v.version,
                v.key_version,
                &v.ciphertext,
            )
        {
            out.push(serde_json::json!({
                "version": v.version,
                "created_at": v.created_at,
                "payload": payload,
            }));
        }
    }

    serde_json::to_string(&out).map_err(|_| WasmError::msg("[FORMAT] failed to serialize history"))
}

/// Fingerprint computed locally from the public keys (to show on the confirmation screen; the one
/// the server reports is not used).
#[wasm_bindgen]
pub fn member_fingerprint(
    enc_public_key: &str,
    sign_public_key: &str,
) -> Result<String, WasmError> {
    compute_fingerprint_from_envelopes(enc_public_key, sign_public_key).map_err(map_err)
}

/// Stores in the trust state the role chosen when inviting. On confirmation this role is what
/// counts, not the one the server returns in the invite list.
#[wasm_bindgen]
pub fn record_invite_role(
    session_json: &str,
    trust_state: &str,
    vault_id_str: &str,
    email: &str,
    role_str: &str,
) -> Result<String, WasmError> {
    let session: UnlockedWebSession = serde_json::from_str(session_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid session"))?;
    let keyset = session.to_keyset()?;
    let mut store = open_trust_store(&session, &keyset, trust_state)?;
    let role = VaultRole::parse(role_str).map_err(map_err)?;
    store.record_invite(parse_uuid(vault_id_str)?, email, role);
    store.seal(&keyset).map_err(map_err)
}

/// Role recorded by [`record_invite_role`] (`""` if the invite was not made in this browser).
#[wasm_bindgen]
pub fn invite_role(
    session_json: &str,
    trust_state: &str,
    vault_id_str: &str,
    email: &str,
) -> Result<String, WasmError> {
    let session: UnlockedWebSession = serde_json::from_str(session_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid session"))?;
    let keyset = session.to_keyset()?;
    let store = open_trust_store(&session, &keyset, trust_state)?;
    Ok(store
        .invite_role(parse_uuid(vault_id_str)?, email)
        .map(|r| r.as_str().to_string())
        .unwrap_or_default())
}

/// Grants the VK to a new member. Owner only (the list is signed by the owner's key).
///
/// The fingerprint is computed here from the keys that will be sealed and signed, and must end
/// with the 4 characters the person typed. The next signed list starts only from the list verified
/// in the snapshot; nothing comes from the server's `/members`.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn prepare_member_grant(
    session_json: &str,
    snapshot_json: &str,
    trust_state: &str,
    member_user_id_str: &str,
    member_enc_pub: &str,
    member_sign_pub: &str,
    role_str: &str,
    typed_last4: &str,
) -> Result<String, WasmError> {
    let session: UnlockedWebSession = serde_json::from_str(session_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid session"))?;
    let keyset = session.to_keyset()?;
    let snapshot: EncryptedSnapshot = serde_json::from_str(snapshot_json)
        .map_err(|_| WasmError::msg("[TAMPERED] invalid snapshot"))?;
    let member_id = parse_uuid(member_user_id_str)?;
    let role = VaultRole::parse(role_str).map_err(map_err)?;

    let fingerprint =
        compute_fingerprint_from_envelopes(member_enc_pub, member_sign_pub).map_err(map_err)?;
    if !verify_fingerprint_last4(&fingerprint, typed_last4) {
        return Err(WasmError::msg(
            "[FINGERPRINT] the last 4 characters do not match the computed fingerprint",
        ));
    }

    let (trusted, _) = verify_with_trust_state(&session, &keyset, &snapshot, trust_state, None)?;
    let roster = trusted
        .roster_with_member(
            session.user_id,
            &keyset,
            RosterMember {
                enc_pub: member_enc_pub.to_string(),
                role,
                sign_pub: member_sign_pub.to_string(),
                user_id: member_id,
            },
        )
        .map_err(map_err)?;
    let (roster_json, roster_sig) = roster.sign(&keyset).map_err(map_err)?;

    let enc_pub_bytes = decode_x25519_pub(member_enc_pub).map_err(map_err)?;
    let (sealed_vk, vk_sig) = seal_vault_key(
        &trusted.vault_key,
        &enc_pub_bytes,
        RecipientKind::User,
        snapshot.vault_id,
        member_id,
        trusted.snapshot.key_version,
        &keyset,
    )
    .map_err(map_err)?;

    serde_json::to_string(&serde_json::json!({
        "user_id": member_id,
        "role": role.as_str(),
        "key_version": trusted.snapshot.key_version,
        "sealed_vk": sealed_vk,
        "vk_sig": vk_sig,
        "confirmed_fingerprint": fingerprint,
        "member_roster": roster_json,
        "member_roster_sig": roster_sig,
    }))
    .map_err(|_| WasmError::msg("[FORMAT] failed to serialize grant"))
}

/// Rotates the vault VK. Owner only; the recipients come from the verified signed list.
///
/// `active_app_ids_json` is the list of `app_id`s the server says are active: it can only remove
/// applications from the rotation, never add recipients.
#[wasm_bindgen]
pub fn prepare_key_rotation(
    session_json: &str,
    snapshot_json: &str,
    trust_state: &str,
    exclude_user_id: Option<String>,
    exclude_app_id: Option<String>,
    active_app_ids_json: &str,
) -> Result<String, WasmError> {
    let session: UnlockedWebSession = serde_json::from_str(session_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid session"))?;
    let keyset = session.to_keyset()?;
    let snapshot: EncryptedSnapshot = serde_json::from_str(snapshot_json)
        .map_err(|_| WasmError::msg("[TAMPERED] invalid snapshot"))?;
    let exclude_user = exclude_user_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(parse_uuid)
        .transpose()?;
    let exclude_app = exclude_app_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(parse_uuid)
        .transpose()?;
    let active_apps: Vec<Uuid> = serde_json::from_str(active_app_ids_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid active application list"))?;

    let (trusted, _) = verify_with_trust_state(&session, &keyset, &snapshot, trust_state, None)?;
    let plan = trusted
        .rotation_plan(
            session.user_id,
            &keyset,
            exclude_user,
            exclude_app,
            Some(&active_apps),
        )
        .map_err(map_err)?;
    let dec = &trusted.snapshot;

    let next_kv = dec.key_version + 1;
    let new_vk = VaultKey::generate().map_err(map_err)?;
    let (new_meta, meta_sha) =
        encrypt_vault_meta(&new_vk, snapshot.vault_id, next_kv, &dec.meta).map_err(map_err)?;

    let mut reencrypted_items = Vec::with_capacity(dec.items.len());
    let mut manifest_entries = Vec::with_capacity(dec.items.len());
    for item in &dec.items {
        let next_item_ver = item.version + 1;
        let (ct, sha) = encrypt_item(
            &new_vk,
            snapshot.vault_id,
            item.id,
            next_item_ver,
            next_kv,
            &item.payload,
        )
        .map_err(map_err)?;
        reencrypted_items.push(serde_json::json!({
            "id": item.id,
            "version": next_item_ver,
            "key_version": next_kv,
            "ciphertext": ct,
            "sha256": sha,
        }));
        manifest_entries.push(ManifestItemEntry {
            id: item.id,
            sha256: sha,
            version: next_item_ver,
        });
    }

    let mut member_grants = Vec::with_capacity(plan.member_grants.len());
    for m in &plan.member_grants {
        let pk = decode_x25519_pub(&m.enc_pub).map_err(map_err)?;
        let (sealed_vk, vk_sig) = seal_vault_key(
            &new_vk,
            &pk,
            RecipientKind::User,
            snapshot.vault_id,
            m.user_id,
            next_kv,
            &keyset,
        )
        .map_err(map_err)?;
        member_grants.push(serde_json::json!({
            "user_id": m.user_id,
            "sealed_vk": sealed_vk,
            "vk_sig": vk_sig,
        }));
    }

    let mut app_grants = Vec::with_capacity(plan.app_grants.len());
    for a in &plan.app_grants {
        let pk = decode_x25519_pub(&a.enc_pub).map_err(map_err)?;
        let (sealed_vk, vk_sig) = seal_vault_key(
            &new_vk,
            &pk,
            RecipientKind::App,
            snapshot.vault_id,
            a.app_id,
            next_kv,
            &keyset,
        )
        .map_err(map_err)?;
        app_grants.push(serde_json::json!({
            "app_id": a.app_id,
            "sealed_vk": sealed_vk,
            "vk_sig": vk_sig,
        }));
    }

    let next_manifest = VaultManifest::new(
        snapshot.vault_id,
        dec.revision + 1,
        next_kv,
        session.user_id,
        meta_sha,
        manifest_entries,
    )
    .map_err(map_err)?;
    let (manifest_json, manifest_sig) = next_manifest.sign(&keyset).map_err(map_err)?;
    let (roster_json, roster_sig) = plan.roster.sign(&keyset).map_err(map_err)?;

    serde_json::to_string(&serde_json::json!({
        "expected_revision": dec.revision,
        "new_key_version": next_kv,
        "encrypted_meta": new_meta,
        "items": reencrypted_items,
        "member_grants": member_grants,
        "app_grants": app_grants,
        "manifest": manifest_json,
        "manifest_sig": manifest_sig,
        "member_roster": roster_json,
        "member_roster_sig": roster_sig,
    }))
    .map_err(|_| WasmError::msg("[FORMAT] failed to serialize rotation"))
}

/// Master password change (Conta e segurança). Derives the current `auth_key` (the
/// re-authentication) and, from the new password with a fresh salt, `new_auth_key`, `new_kdf` and
/// the same key pairs sealed under the new `kek`, checked by opening them again.
///
/// Returns the JSON body of `POST /api/v1/auth/password/change` without `totp_code`, which the page
/// adds. Errors: `[SAME_PASSWORD]`, `[WEAK_PASSWORD] [codes...]` (same codes as
/// `master_password_problems`), plus the usual tags.
#[wasm_bindgen]
pub fn prepare_password_change(
    session_json: &str,
    current_password: &str,
    new_password: &str,
    current_kdf_json: &str,
    email: &str,
    name: &str,
) -> Result<String, WasmError> {
    let session: UnlockedWebSession = serde_json::from_str(session_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid session"))?;
    let keyset = session.to_keyset()?;
    let current_kdf: KdfParams = serde_json::from_str(current_kdf_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid kdf"))?;

    let material = password_change::prepare_password_change(
        &keyset,
        session.user_id,
        current_password,
        new_password,
        &current_kdf,
        email,
        name,
    )
    .map_err(|e| match e {
        PasswordChangeError::SameAsCurrent => {
            WasmError::msg("[SAME_PASSWORD] the new master password is the same as the current one")
        }
        PasswordChangeError::Weak(problems) => {
            WasmError::msg(format!("[WEAK_PASSWORD] {}", serde_json::json!(problems)))
        }
        PasswordChangeError::Core(core) => map_err(core),
    })?;
    let (auth_key, _kek) =
        derive_account_keys(current_password, session.user_id, &current_kdf).map_err(map_err)?;

    serde_json::to_string(&serde_json::json!({
        "auth_key": auth_key.as_str(),
        "new_auth_key": material.auth_key.as_str(),
        "new_kdf": material.kdf,
        "new_encrypted_keyset": material.encrypted_keyset,
    }))
    .map_err(|_| WasmError::msg("[FORMAT] failed to serialize password change"))
}

#[wasm_bindgen]
pub fn compute_fingerprint_last4_match(fingerprint: &str, typed: &str) -> bool {
    verify_fingerprint_last4(fingerprint, typed)
}

#[wasm_bindgen]
pub fn generate_random_password(length: u32, symbols: bool) -> Result<String, WasmError> {
    let pw = generate_password(length as usize, symbols).map_err(map_err)?;
    Ok(pw.to_string())
}

/// Renames the vault: encrypts the new name with the current VK and signs a manifest with the
/// new `vault_meta_sha256`, the same items and `revision + 1`. The server only accepts it from a
/// member who can write, and the manifest signature is checked against the signed list as usual.
#[wasm_bindgen]
pub fn prepare_vault_rename(
    session_json: &str,
    snapshot_json: &str,
    trust_state: &str,
    new_name: &str,
) -> Result<String, WasmError> {
    let session: UnlockedWebSession = serde_json::from_str(session_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid session"))?;
    let keyset = session.to_keyset()?;
    let snapshot: EncryptedSnapshot = serde_json::from_str(snapshot_json)
        .map_err(|_| WasmError::msg("[TAMPERED] invalid snapshot JSON"))?;
    let name = new_name.trim();
    if name.is_empty() || name.chars().count() > 120 {
        return Err(WasmError::msg(
            "[FORMAT] the vault name must have between 1 and 120 characters",
        ));
    }

    let (trusted, _) = verify_with_trust_state(&session, &keyset, &snapshot, trust_state, None)?;
    let dec = &trusted.snapshot;
    let old_manifest = VaultManifest::parse_canonical(&snapshot.manifest).map_err(map_err)?;
    let (encrypted_meta, meta_sha) = encrypt_vault_meta(
        &trusted.vault_key,
        snapshot.vault_id,
        dec.key_version,
        &VaultMeta::new(name),
    )
    .map_err(map_err)?;
    let next_manifest = VaultManifest::new(
        snapshot.vault_id,
        dec.revision + 1,
        dec.key_version,
        session.user_id,
        meta_sha,
        old_manifest.items,
    )
    .map_err(map_err)?;
    let (manifest_json, manifest_sig) = next_manifest.sign(&keyset).map_err(map_err)?;

    serde_json::to_string(&serde_json::json!({
        "expected_revision": dec.revision,
        "encrypted_meta": encrypted_meta,
        "upserts": [],
        "deletes": [],
        "manifest": manifest_json,
        "manifest_sig": manifest_sig,
    }))
    .map_err(|_| WasmError::msg("[FORMAT] failed to serialize rename"))
}

/// Fingerprint of the unlocked account, computed from the local keyset (never from the server).
///
/// The last 4 characters are the "security code" an invited person reads to the vault owner.
#[wasm_bindgen]
pub fn session_fingerprint(session_json: &str) -> Result<String, WasmError> {
    let session: UnlockedWebSession = serde_json::from_str(session_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid session"))?;
    Ok(session.to_keyset()?.fingerprint())
}

/// Registers a new application access for a vault. Owner only.
///
/// Generates the application keys here, seals the current VK to it, adds it to the owner-signed
/// list and builds the token with the owner key **verified** against the local anchor (never the
/// one the server sent). Returns `{"request": {...}, "token": "cfb1_app_...", "app_id": "..."}`:
/// `request` goes to `POST /vaults/{id}/apps`; the token is shown once and never sent anywhere.
#[wasm_bindgen]
pub fn prepare_app_grant(
    session_json: &str,
    snapshot_json: &str,
    trust_state: &str,
    app_name: &str,
) -> Result<String, WasmError> {
    let session: UnlockedWebSession = serde_json::from_str(session_json)
        .map_err(|_| WasmError::msg("[FORMAT] invalid session"))?;
    let keyset = session.to_keyset()?;
    let snapshot: EncryptedSnapshot = serde_json::from_str(snapshot_json)
        .map_err(|_| WasmError::msg("[TAMPERED] invalid snapshot"))?;
    let name = app_name.trim();
    if name.is_empty() || name.chars().count() > 128 {
        return Err(WasmError::msg(
            "[FORMAT] the access name must have between 1 and 128 characters",
        ));
    }

    let (trusted, _) = verify_with_trust_state(&session, &keyset, &snapshot, trust_state, None)?;
    if !trusted.is_owner(session.user_id) {
        return Err(WasmError::msg(
            "[FORBIDDEN] only the vault owner registers applications",
        ));
    }

    let app_id = random_uuid_v4().map_err(map_err)?;
    let creds = AppCredentials::generate(app_id, trusted.owner_sign_public_key).map_err(map_err)?;
    let (sealed_vk, vk_sig) = seal_vault_key(
        &trusted.vault_key,
        &creds.enc_public_bytes(),
        RecipientKind::App,
        snapshot.vault_id,
        app_id,
        trusted.snapshot.key_version,
        &keyset,
    )
    .map_err(map_err)?;
    let roster = trusted
        .roster_with_app(
            session.user_id,
            &keyset,
            RosterApp {
                app_id,
                enc_pub: creds.enc_public_envelope(),
                sign_pub: creds.sign_public_envelope(),
            },
        )
        .map_err(map_err)?;
    let (roster_json, roster_sig) = roster.sign(&keyset).map_err(map_err)?;
    let token = creds.to_token();

    serde_json::to_string(&serde_json::json!({
        "app_id": app_id,
        "token": token.as_str(),
        "request": {
            "app_id": app_id,
            "name": name,
            "enc_public_key": creds.enc_public_envelope(),
            "sign_public_key": creds.sign_public_envelope(),
            "sealed_vk": sealed_vk,
            "vk_sig": vk_sig,
            "key_version": trusted.snapshot.key_version,
            "member_roster": roster_json,
            "member_roster_sig": roster_sig,
        },
    }))
    .map_err(|_| WasmError::msg("[FORMAT] failed to serialize application grant"))
}

/// QR code (error correction M) of an `otpauth://` enrollment URI, built here in the browser so
/// the authenticator secret never goes to a third-party service.
///
/// Returns `{"size": n, "path": "..."}`: an SVG path of the dark modules in a `n x n` grid, with
/// no quiet zone (the page adds the margin).
#[wasm_bindgen]
pub fn otpauth_qr_svg_path(uri: &str) -> Result<String, WasmError> {
    use qrcodegen::{QrCode, QrCodeEcc};

    if !uri.starts_with("otpauth://") || uri.len() > 1024 {
        return Err(WasmError::msg("[FORMAT] not an otpauth URI"));
    }
    let qr = QrCode::encode_text(uri, QrCodeEcc::Medium)
        .map_err(|_| WasmError::msg("[FORMAT] URI too long for a QR code"))?;
    let size = qr.size();
    let mut path = String::new();
    for y in 0..size {
        let mut x = 0;
        while x < size {
            if qr.get_module(x, y) {
                let start = x;
                while x < size && qr.get_module(x, y) {
                    x += 1;
                }
                let run = x - start;
                let _ = write!(path, "M{start} {y}h{run}v1h-{run}z");
            } else {
                x += 1;
            }
        }
    }
    serde_json::to_string(&serde_json::json!({ "size": size, "path": path }))
        .map_err(|_| WasmError::msg("[FORMAT] failed to serialize QR code"))
}
