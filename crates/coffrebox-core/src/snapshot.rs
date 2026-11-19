use core::fmt;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::app_token::AppCredentials;
use crate::error::{CoreError, Result};
use crate::item::{ItemPayload, decrypt_item, item_ciphertext_sha256};
use crate::keys::{UserKeyset, decode_ed25519_pub};
use crate::manifest::{VaultManifest, verify_manifest_signature, verify_member_roster};
use crate::vault::{
    RecipientKind, VaultKey, VaultMeta, decrypt_vault_meta, open_vault_key, vault_meta_sha256,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRecipientEnvelope {
    pub kind: RecipientKind,
    pub id: Uuid,
    pub key_version: u32,
    pub sealed_vk: String,
    pub vk_sig: String,
    pub granted_by_user_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedItemWire {
    pub id: Uuid,
    pub version: u32,
    pub key_version: u32,
    pub ciphertext: String,
    pub sha256: String,
}

/// Full encrypted snapshot served by `GET /api/v1/vaults/{id}/snapshot` and stored in `.snapshot`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSnapshot {
    pub v: u32,
    pub vault_id: Uuid,
    pub owner_user_id: Uuid,
    pub owner_sign_public_key: String,
    pub encrypted_meta: String,
    pub recipient: SnapshotRecipientEnvelope,
    pub manifest: String,
    pub manifest_sig: String,
    pub member_roster: Option<String>,
    pub member_roster_sig: Option<String>,
    pub items: Vec<EncryptedItemWire>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DecryptedItem {
    pub id: Uuid,
    pub version: u32,
    pub payload: ItemPayload,
}

impl fmt::Debug for DecryptedItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptedItem")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DecryptedSnapshot {
    pub vault_id: Uuid,
    pub revision: u64,
    pub key_version: u32,
    pub meta: VaultMeta,
    pub items: Vec<DecryptedItem>,
}

impl fmt::Debug for DecryptedSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptedSnapshot")
            .field("vault_id", &self.vault_id)
            .field("revision", &self.revision)
            .field("key_version", &self.key_version)
            .field("items_len", &self.items.len())
            .finish()
    }
}

/// Verifies the whole chain of trust and decrypts a snapshot for an **application** (`COFFREBOX_TOKEN`).
pub fn verify_and_decrypt_for_app(
    snapshot: &EncryptedSnapshot,
    creds: &AppCredentials,
    min_revision: Option<u64>,
) -> Result<DecryptedSnapshot> {
    if snapshot.recipient.kind != RecipientKind::App || snapshot.recipient.id != creds.app_id() {
        return Err(CoreError::ManifestTampered(
            "recipient envelope does not belong to this application",
        ));
    }
    let (_, decrypted) = verify_and_decrypt_internal(
        snapshot,
        RecipientKind::App,
        creds.app_id(),
        creds.x25519_secret_bytes(),
        creds.owner_sign_public_bytes(),
        min_revision,
    )?;
    Ok(decrypted)
}

/// Verifies the whole chain of trust and decrypts a snapshot for a **person** (`UserKeyset`).
pub fn verify_and_decrypt_for_user(
    snapshot: &EncryptedSnapshot,
    user_id: Uuid,
    user_keys: &UserKeyset,
    expected_owner_sign_pk: &[u8; 32],
    min_revision: Option<u64>,
) -> Result<(VaultKey, DecryptedSnapshot)> {
    if snapshot.recipient.kind != RecipientKind::User || snapshot.recipient.id != user_id {
        return Err(CoreError::ManifestTampered(
            "recipient envelope does not belong to this account",
        ));
    }
    verify_and_decrypt_internal(
        snapshot,
        RecipientKind::User,
        user_id,
        user_keys.enc_secret_bytes(),
        expected_owner_sign_pk,
        min_revision,
    )
}

fn verify_and_decrypt_internal(
    snapshot: &EncryptedSnapshot,
    recipient_kind: RecipientKind,
    recipient_id: Uuid,
    recipient_enc_sk: &[u8; 32],
    pinned_owner_sign_pk: &[u8; 32],
    min_revision: Option<u64>,
) -> Result<(VaultKey, DecryptedSnapshot)> {
    if snapshot.v != crate::FORMAT_VERSION {
        return Err(CoreError::InvalidFormat("unsupported snapshot version"));
    }

    // Checks in constant time that the public key in the snapshot matches the pinned anchor.
    let wire_owner_pk = decode_ed25519_pub(&snapshot.owner_sign_public_key)?;
    if !bool::from(wire_owner_pk.ct_eq(pinned_owner_sign_pk)) {
        return Err(CoreError::InvalidSignature);
    }

    // Resolves the authorized public keys (owner only, or the MemberRoster signed by the owner).
    let (writer_sign_pk, grantor_sign_pk) = resolve_signers(snapshot, pinned_owner_sign_pk)?;

    let manifest: VaultManifest =
        verify_manifest_signature(&snapshot.manifest, &snapshot.manifest_sig, &writer_sign_pk)?;

    if manifest.vault_id != snapshot.vault_id {
        return Err(CoreError::ManifestTampered(
            "manifest vault_id differs from the snapshot",
        ));
    }
    if let Some(min_rev) = min_revision
        && manifest.revision < min_rev
    {
        return Err(CoreError::RollbackDetected);
    }
    if snapshot.recipient.key_version != manifest.key_version {
        return Err(CoreError::ManifestTampered(
            "VK envelope key_version differs from the manifest",
        ));
    }

    // Checks the integrity of the encrypted vault name against the hash signed in the manifest.
    let actual_vmeta_sha = vault_meta_sha256(&snapshot.encrypted_meta)?;
    if actual_vmeta_sha != manifest.vault_meta_sha256 {
        return Err(CoreError::ManifestTampered(
            "encrypted_meta does not match the manifest vault_meta_sha256",
        ));
    }

    // Opens the vault key (checks vk_sig before HPKE).
    let vk = open_vault_key(
        &snapshot.recipient.sealed_vk,
        &snapshot.recipient.vk_sig,
        recipient_enc_sk,
        &grantor_sign_pk,
        recipient_kind,
        snapshot.vault_id,
        recipient_id,
        manifest.key_version,
    )?;

    let meta = decrypt_vault_meta(
        &vk,
        snapshot.vault_id,
        manifest.key_version,
        &snapshot.encrypted_meta,
    )?;

    // Checks an exact 1:1 match between the delivered items and the signed manifest.
    if snapshot.items.len() != manifest.items.len() {
        return Err(CoreError::ManifestTampered(
            "item count differs from the signed manifest",
        ));
    }

    let mut sorted_wire = snapshot.items.clone();
    sorted_wire.sort_by_key(|a| a.id.as_hyphenated().to_string());

    let mut decrypted_items = Vec::with_capacity(sorted_wire.len());
    for (wire_item, manifest_entry) in sorted_wire.iter().zip(manifest.items.iter()) {
        if wire_item.id != manifest_entry.id
            || wire_item.version != manifest_entry.version
            || wire_item.key_version != manifest.key_version
        {
            return Err(CoreError::ManifestTampered(
                "item metadata differs from the signed manifest",
            ));
        }
        let computed_sha = item_ciphertext_sha256(&wire_item.ciphertext)?;
        if computed_sha != manifest_entry.sha256 || wire_item.sha256 != manifest_entry.sha256 {
            return Err(CoreError::ManifestTampered(
                "encrypted item SHA-256 differs from the manifest",
            ));
        }
        let payload = decrypt_item(
            &vk,
            snapshot.vault_id,
            wire_item.id,
            wire_item.version,
            manifest.key_version,
            &wire_item.ciphertext,
        )?;
        decrypted_items.push(DecryptedItem {
            id: wire_item.id,
            version: wire_item.version,
            payload,
        });
    }

    Ok((
        vk,
        DecryptedSnapshot {
            vault_id: snapshot.vault_id,
            revision: manifest.revision,
            key_version: manifest.key_version,
            meta,
            items: decrypted_items,
        },
    ))
}

fn resolve_signers(
    snapshot: &EncryptedSnapshot,
    pinned_owner_sign_pk: &[u8; 32],
) -> Result<([u8; 32], [u8; 32])> {
    let raw_manifest = VaultManifest::parse_canonical(&snapshot.manifest)?;

    match (&snapshot.member_roster, &snapshot.member_roster_sig) {
        (Some(roster_json), Some(roster_sig)) => {
            let roster = verify_member_roster(roster_json, roster_sig, pinned_owner_sign_pk)?;
            if roster.vault_id != snapshot.vault_id {
                return Err(CoreError::ManifestTampered(
                    "MemberRoster vault_id differs from the snapshot",
                ));
            }
            let writer = roster
                .find_member(raw_manifest.signed_by)
                .ok_or(CoreError::InvalidSignature)?;
            if !writer.role.can_write_items() {
                return Err(CoreError::InvalidSignature);
            }
            let grantor = roster
                .find_member(snapshot.recipient.granted_by_user_id)
                .ok_or(CoreError::InvalidSignature)?;
            if !grantor.role.can_grant_vk() {
                return Err(CoreError::InvalidSignature);
            }
            Ok((
                decode_ed25519_pub(&writer.sign_pub)?,
                decode_ed25519_pub(&grantor.sign_pub)?,
            ))
        }
        (None, None) => {
            if raw_manifest.signed_by != snapshot.owner_user_id
                || snapshot.recipient.granted_by_user_id != snapshot.owner_user_id
            {
                return Err(CoreError::InvalidSignature);
            }
            Ok((*pinned_owner_sign_pk, *pinned_owner_sign_pk))
        }
        _ => Err(CoreError::ManifestTampered(
            "incomplete member_roster without a signature",
        )),
    }
}
