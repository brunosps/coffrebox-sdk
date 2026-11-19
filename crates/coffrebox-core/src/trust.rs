//! Trust anchor of the clients used by people (the `coffre` CLI and the web vault).
//!
//! The server sends the owner's signing key (`owner_sign_public_key`) in every snapshot. That key
//! is **never** an anchor by itself, because a compromised server can swap it together with
//! everything it signs. The anchor always comes from the client:
//!
//! - **Own vault** (`owner_user_id` is the account itself): the person's own signing key, derived
//!   locally from the session keyset.
//! - **Shared vault**: trust on first use (TOFU). On the first read the client pins the owner key
//!   in a local [`VaultPin`]; from then on any change is refused with
//!   [`CoreError::OwnerKeyChanged`] until the person explicitly confirms the new fingerprint.
//!
//! The same [`VaultPin`] keeps `revision`, `roster_version` and `key_version`, which can only grow
//! (rollback protection for people, as the application SDKs already do).

use core::fmt;
use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::encoding::{b64url_decode, b64url_encode, fill_random};
use crate::error::{CoreError, Result};
use crate::keys::{
    UserKeyset, compute_fingerprint, decode_ed25519_pub, decode_x25519_pub, encode_ed25519_pub,
};
use crate::manifest::{MemberRoster, RosterApp, RosterMember, VaultRole, verify_member_roster};
use crate::snapshot::{DecryptedSnapshot, EncryptedSnapshot, verify_and_decrypt_for_user};
use crate::vault::VaultKey;

pub const TRUST_STATE_PREFIX: &str = "cfb1.trust.";
const TRUST_STATE_DOMAIN: &[u8] = b"coffrebox/v1/local-trust-state";

/// What the client knows about a vault. It lives only on the person's device; it never comes from
/// the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultPin {
    pub vault_id: Uuid,
    pub owner_user_id: Uuid,
    /// Pinned Ed25519 key of the owner (`cfb1.epk.`).
    pub owner_sign_public_key: String,
    /// Owner fingerprint (X25519 + Ed25519 from the signed list), to show in alerts.
    pub owner_fingerprint: Option<String>,
    /// Highest manifest revision seen so far.
    pub revision: u64,
    /// Highest `roster_version` seen so far (0 = vault without a signed list).
    pub roster_version: u32,
    /// Highest `key_version` seen so far.
    pub key_version: u32,
}

impl VaultPin {
    fn display_fingerprint(&self) -> String {
        self.owner_fingerprint
            .clone()
            .unwrap_or_else(|| self.owner_sign_public_key.clone())
    }

    /// Records a local write accepted by the server, so an older snapshot is refused later.
    pub fn record_local_write(&mut self, revision: u64, key_version: u32, roster_version: u32) {
        self.revision = self.revision.max(revision);
        self.key_version = self.key_version.max(key_version);
        self.roster_version = self.roster_version.max(roster_version);
    }
}

/// Set of [`VaultPin`] of an account, persisted by the CLI (`0600` file) and by the web vault
/// (encrypted with [`TrustStore::seal`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustStore {
    pub v: u32,
    pub user_id: Uuid,
    #[serde(default)]
    pub vaults: BTreeMap<Uuid, VaultPin>,
    /// Role chosen when inviting, per vault and email (lowercase). On confirmation this record is
    /// what counts, never the role the server returns in the invite list.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub invites: BTreeMap<Uuid, BTreeMap<String, VaultRole>>,
}

impl TrustStore {
    pub fn new(user_id: Uuid) -> Self {
        Self {
            v: crate::FORMAT_VERSION,
            user_id,
            vaults: BTreeMap::new(),
            invites: BTreeMap::new(),
        }
    }

    pub fn record_invite(&mut self, vault_id: Uuid, email: &str, role: VaultRole) {
        self.invites
            .entry(vault_id)
            .or_default()
            .insert(email.trim().to_lowercase(), role);
    }

    pub fn invite_role(&self, vault_id: Uuid, email: &str) -> Option<VaultRole> {
        self.invites
            .get(&vault_id)
            .and_then(|m| m.get(&email.trim().to_lowercase()))
            .copied()
    }

    pub fn clear_invite(&mut self, vault_id: Uuid, email: &str) {
        if let Some(m) = self.invites.get_mut(&vault_id) {
            m.remove(&email.trim().to_lowercase());
            if m.is_empty() {
                self.invites.remove(&vault_id);
            }
        }
    }

    pub fn get(&self, vault_id: Uuid) -> Option<&VaultPin> {
        self.vaults.get(&vault_id)
    }

    pub fn put(&mut self, pin: VaultPin) {
        self.vaults.insert(pin.vault_id, pin);
    }

    /// Checks the version and owner of the state read from disk or from the browser.
    pub fn validate_for(&self, user_id: Uuid) -> Result<()> {
        if self.v != crate::FORMAT_VERSION {
            return Err(CoreError::InvalidFormat("trust state version"));
        }
        if self.user_id != user_id {
            return Err(CoreError::InvalidFormat(
                "trust state belongs to another account",
            ));
        }
        for (id, pin) in &self.vaults {
            if *id != pin.vault_id {
                return Err(CoreError::InvalidFormat("inconsistent trust state"));
            }
            decode_ed25519_pub(&pin.owner_sign_public_key)?;
        }
        Ok(())
    }

    /// Encrypts the state with a key derived from the person's keyset (`XChaCha20-Poly1305`).
    pub fn seal(&self, keys: &UserKeyset) -> Result<String> {
        let key = local_state_key(keys, self.user_id)?;
        let plain = Zeroizing::new(
            serde_json::to_vec(self).map_err(|_| CoreError::InvalidFormat("json trust"))?,
        );
        let mut nonce = [0u8; 24];
        fill_random(&mut nonce)?;
        let aad = local_state_aad(self.user_id);
        let cipher = XChaCha20Poly1305::new(&Key::from(*key));
        let ct = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plain,
                    aad: &aad,
                },
            )
            .map_err(|_| CoreError::DecryptionFailed)?;
        let mut wire = Vec::with_capacity(24 + ct.len());
        wire.extend_from_slice(&nonce);
        wire.extend_from_slice(&ct);
        Ok(format!("{TRUST_STATE_PREFIX}{}", b64url_encode(&wire)))
    }

    pub fn open(sealed: &str, keys: &UserKeyset, user_id: Uuid) -> Result<Self> {
        let raw = sealed
            .strip_prefix(TRUST_STATE_PREFIX)
            .ok_or(CoreError::InvalidFormat("missing cfb1.trust. prefix"))?;
        let wire = b64url_decode(raw)?;
        if wire.len() < 24 + 16 {
            return Err(CoreError::InvalidFormat("truncated trust state"));
        }
        let (nonce, ct) = wire.split_at(24);
        let nonce: [u8; 24] = nonce
            .try_into()
            .map_err(|_| CoreError::InvalidFormat("invalid nonce"))?;
        let key = local_state_key(keys, user_id)?;
        let aad = local_state_aad(user_id);
        let cipher = XChaCha20Poly1305::new(&Key::from(*key));
        let plain = Zeroizing::new(
            cipher
                .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad: &aad })
                .map_err(|_| CoreError::DecryptionFailed)?,
        );
        let store: Self =
            serde_json::from_slice(&plain).map_err(|_| CoreError::InvalidFormat("trust state"))?;
        store.validate_for(user_id)?;
        Ok(store)
    }
}

fn local_state_key(keys: &UserKeyset, user_id: Uuid) -> Result<Zeroizing<[u8; 32]>> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(keys.sign_seed_bytes());
    ikm[32..].copy_from_slice(keys.enc_secret_bytes());
    let hk = Hkdf::<Sha256>::new(Some(user_id.as_bytes()), &ikm[..]);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(TRUST_STATE_DOMAIN, &mut key[..])
        .map_err(|_| CoreError::InvalidFormat("local state HKDF failed"))?;
    Ok(key)
}

fn local_state_aad(user_id: Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(TRUST_STATE_DOMAIN.len() + 16);
    aad.extend_from_slice(TRUST_STATE_DOMAIN);
    aad.extend_from_slice(user_id.as_bytes());
    aad
}

/// Where the anchor used to verify the snapshot came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorSource {
    /// The person's own vault: the anchor is their own signing key.
    Own,
    /// Shared vault whose owner key was already pinned on this device.
    Pinned,
    /// First use of a shared vault: the owner key was pinned just now.
    FirstUse,
    /// The person explicitly confirmed the owner's new fingerprint.
    Reconfirmed,
}

/// Snapshot verified against a local anchor, with the updated state to persist.
pub struct TrustedVault {
    pub vault_key: VaultKey,
    pub snapshot: DecryptedSnapshot,
    /// Member list signed by the owner, already verified against the anchor.
    pub roster: Option<MemberRoster>,
    pub owner_user_id: Uuid,
    pub owner_sign_public_key: [u8; 32],
    pub owner_fingerprint: Option<String>,
    pub anchor: AnchorSource,
    /// State to store in place of the previous one.
    pub pin: VaultPin,
}

impl fmt::Debug for TrustedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedVault")
            .field("vault_id", &self.snapshot.vault_id)
            .field("anchor", &self.anchor)
            .field("pin", &self.pin)
            .finish_non_exhaustive()
    }
}

impl TrustedVault {
    pub fn roster_version(&self) -> u32 {
        self.roster.as_ref().map(|r| r.roster_version).unwrap_or(0)
    }

    pub fn is_owner(&self, user_id: Uuid) -> bool {
        self.owner_user_id == user_id
    }

    fn require_owner(&self, user_id: Uuid) -> Result<()> {
        if self.is_owner(user_id) {
            Ok(())
        } else {
            Err(CoreError::NotVaultOwner)
        }
    }

    /// Current verified list. For an older own vault without a list, the implicit list with only
    /// the owner (`roster_version` 0, so the next one is 1).
    fn base_roster(&self, user_id: Uuid, user_keys: &UserKeyset) -> Result<MemberRoster> {
        if let Some(r) = &self.roster {
            return Ok(r.clone());
        }
        self.require_owner(user_id)?;
        Ok(MemberRoster {
            apps: Vec::new(),
            members: vec![RosterMember {
                enc_pub: user_keys.enc_public_envelope(),
                role: VaultRole::Owner,
                sign_pub: user_keys.sign_public_envelope(),
                user_id,
            }],
            roster_version: 0,
            v: crate::FORMAT_VERSION,
            vault_id: self.snapshot.vault_id,
        })
    }

    /// Next signed list with the member added (or with its key and role updated).
    ///
    /// Starts only from the list verified against the anchor; nothing comes from the server's
    /// `/members`.
    pub fn roster_with_member(
        &self,
        user_id: Uuid,
        user_keys: &UserKeyset,
        member: RosterMember,
    ) -> Result<MemberRoster> {
        self.require_owner(user_id)?;
        if member.role == VaultRole::Owner || member.user_id == self.owner_user_id {
            return Err(CoreError::InvalidFormat(
                "the owner role belongs to the owner only",
            ));
        }
        let base = self.base_roster(user_id, user_keys)?;
        let mut members: Vec<RosterMember> = base
            .members
            .into_iter()
            .filter(|m| m.user_id != member.user_id)
            .collect();
        members.push(member);
        MemberRoster::new_with_apps(base.vault_id, base.roster_version + 1, members, base.apps)
    }

    /// Next signed list with the application added.
    pub fn roster_with_app(
        &self,
        user_id: Uuid,
        user_keys: &UserKeyset,
        app: RosterApp,
    ) -> Result<MemberRoster> {
        self.require_owner(user_id)?;
        let base = self.base_roster(user_id, user_keys)?;
        let mut apps: Vec<RosterApp> = base
            .apps
            .into_iter()
            .filter(|a| a.app_id != app.app_id)
            .collect();
        apps.push(app);
        MemberRoster::new_with_apps(base.vault_id, base.roster_version + 1, base.members, apps)
    }

    /// Recipients of a new VK, taken **only** from the verified signed list.
    ///
    /// `server_active_apps` (the applications the server says are active) can only remove
    /// applications from the grant list, never add any: at worst the server denies an application
    /// access, but it cannot get the VK.
    pub fn rotation_plan(
        &self,
        user_id: Uuid,
        user_keys: &UserKeyset,
        exclude_user: Option<Uuid>,
        exclude_app: Option<Uuid>,
        server_active_apps: Option<&[Uuid]>,
    ) -> Result<RotationPlan> {
        self.require_owner(user_id)?;
        let base = self.base_roster(user_id, user_keys)?;
        if let Some(u) = exclude_user {
            if u == self.owner_user_id {
                return Err(CoreError::InvalidFormat(
                    "the owner cannot be removed from the vault",
                ));
            }
            if base.find_member(u).is_none() {
                return Err(CoreError::InvalidFormat(
                    "the member to remove is not in the signed list",
                ));
            }
        }
        let members: Vec<RosterMember> = base
            .members
            .into_iter()
            .filter(|m| Some(m.user_id) != exclude_user)
            .collect();
        let roster_apps: Vec<RosterApp> = base
            .apps
            .into_iter()
            .filter(|a| Some(a.app_id) != exclude_app)
            .collect();
        let app_grants: Vec<RosterApp> = roster_apps
            .iter()
            .filter(|a| server_active_apps.is_none_or(|active| active.contains(&a.app_id)))
            .cloned()
            .collect();
        let roster = MemberRoster::new_with_apps(
            base.vault_id,
            base.roster_version + 1,
            members.clone(),
            roster_apps,
        )?;
        Ok(RotationPlan {
            roster,
            member_grants: members,
            app_grants,
        })
    }
}

/// Result of [`TrustedVault::rotation_plan`]: the next list (to be signed by the owner) and who
/// receives the new VK.
#[derive(Debug, Clone)]
pub struct RotationPlan {
    pub roster: MemberRoster,
    pub member_grants: Vec<RosterMember>,
    pub app_grants: Vec<RosterApp>,
}

/// Verifies and decrypts a snapshot for a person using **only** local anchors.
///
/// `pin` is the stored state of this vault (or `None` on first use). Pass
/// `accept_owner_fingerprint` only after the person checked the owner's new fingerprint through
/// another channel.
pub fn verify_vault_for_user(
    snapshot: &EncryptedSnapshot,
    user_id: Uuid,
    user_keys: &UserKeyset,
    pin: Option<&VaultPin>,
    accept_owner_fingerprint: Option<&str>,
) -> Result<TrustedVault> {
    if let Some(p) = pin
        && p.vault_id != snapshot.vault_id
    {
        return Err(CoreError::InvalidFormat(
            "local state belongs to another vault",
        ));
    }

    let presented_pk = decode_ed25519_pub(&snapshot.owner_sign_public_key)?;
    let own_vault = snapshot.owner_user_id == user_id;

    let (anchor, source) = if own_vault {
        if let Some(p) = pin
            && p.owner_user_id != user_id
        {
            // The server now says this vault is mine; before, it belonged to someone else.
            return Err(CoreError::OwnerKeyChanged {
                pinned: p.display_fingerprint(),
                presented: user_keys.fingerprint(),
            });
        }
        (user_keys.sign_public_bytes(), AnchorSource::Own)
    } else {
        match pin {
            Some(p)
                if p.owner_user_id == snapshot.owner_user_id
                    && same_key(&p.owner_sign_public_key, &presented_pk)? =>
            {
                (presented_pk, AnchorSource::Pinned)
            }
            Some(p) => {
                let presented = presented_owner_fingerprint(snapshot, &presented_pk)?;
                match accept_owner_fingerprint {
                    Some(accepted) if fingerprints_match(accepted, &presented) => {
                        (presented_pk, AnchorSource::Reconfirmed)
                    }
                    _ => {
                        return Err(CoreError::OwnerKeyChanged {
                            pinned: p.display_fingerprint(),
                            presented,
                        });
                    }
                }
            }
            None => {
                if let Some(expected) = accept_owner_fingerprint {
                    let presented = presented_owner_fingerprint(snapshot, &presented_pk)?;
                    if !fingerprints_match(expected, &presented) {
                        return Err(CoreError::OwnerKeyChanged {
                            pinned: expected.to_string(),
                            presented,
                        });
                    }
                    (presented_pk, AnchorSource::Reconfirmed)
                } else {
                    (presented_pk, AnchorSource::FirstUse)
                }
            }
        }
    };

    let min_revision = pin.map(|p| p.revision);
    let (vault_key, decrypted) =
        verify_and_decrypt_for_user(snapshot, user_id, user_keys, &anchor, min_revision)?;

    let roster = match (&snapshot.member_roster, &snapshot.member_roster_sig) {
        (Some(json), Some(sig)) => Some(verify_member_roster(json, sig, &anchor)?),
        _ => None,
    };
    check_roster(
        roster.as_ref(),
        snapshot.owner_user_id,
        &anchor,
        user_id,
        source,
    )?;

    let roster_version = roster.as_ref().map(|r| r.roster_version).unwrap_or(0);
    if let Some(p) = pin
        && (decrypted.key_version < p.key_version || roster_version < p.roster_version)
    {
        return Err(CoreError::RollbackDetected);
    }

    let owner_fingerprint = match roster
        .as_ref()
        .and_then(|r| r.find_member(snapshot.owner_user_id))
    {
        Some(owner) => Some(compute_fingerprint(
            &decode_x25519_pub(&owner.enc_pub)?,
            &anchor,
        )),
        None if own_vault => Some(user_keys.fingerprint()),
        None => None,
    };

    let pin = VaultPin {
        vault_id: snapshot.vault_id,
        owner_user_id: snapshot.owner_user_id,
        owner_sign_public_key: encode_ed25519_pub(&anchor),
        owner_fingerprint: owner_fingerprint.clone(),
        revision: pin.map(|p| p.revision).unwrap_or(0).max(decrypted.revision),
        roster_version,
        key_version: decrypted.key_version,
    };

    Ok(TrustedVault {
        vault_key,
        snapshot: decrypted,
        roster,
        owner_user_id: snapshot.owner_user_id,
        owner_sign_public_key: anchor,
        owner_fingerprint,
        anchor: source,
        pin,
    })
}

/// Owner fingerprint as presented by the server, computed from the list signed by the presented
/// key itself (only for showing to the person; it is not an anchor).
fn presented_owner_fingerprint(
    snapshot: &EncryptedSnapshot,
    presented_pk: &[u8; 32],
) -> Result<String> {
    let (json, sig) = match (&snapshot.member_roster, &snapshot.member_roster_sig) {
        (Some(j), Some(s)) => (j, s),
        _ => {
            return Err(CoreError::ManifestTampered(
                "shared vault without a signed member list",
            ));
        }
    };
    let roster = verify_member_roster(json, sig, presented_pk)?;
    let owner = roster
        .find_member(snapshot.owner_user_id)
        .ok_or(CoreError::ManifestTampered(
            "owner missing from the signed member list",
        ))?;
    Ok(compute_fingerprint(
        &decode_x25519_pub(&owner.enc_pub)?,
        presented_pk,
    ))
}

fn check_roster(
    roster: Option<&MemberRoster>,
    owner_user_id: Uuid,
    anchor: &[u8; 32],
    user_id: Uuid,
    source: AnchorSource,
) -> Result<()> {
    let Some(roster) = roster else {
        if source == AnchorSource::Own {
            return Ok(());
        }
        return Err(CoreError::ManifestTampered(
            "shared vault without a signed member list",
        ));
    };

    let owners: Vec<_> = roster
        .members
        .iter()
        .filter(|m| m.role == VaultRole::Owner)
        .collect();
    if owners.len() != 1 || owners[0].user_id != owner_user_id {
        return Err(CoreError::ManifestTampered(
            "member list owner differs from the vault owner",
        ));
    }
    if !same_key(&owners[0].sign_pub, anchor)? {
        return Err(CoreError::ManifestTampered(
            "owner key in the member list differs from the anchor",
        ));
    }
    if roster.find_member(user_id).is_none() {
        return Err(CoreError::ManifestTampered(
            "this account is not in the member list signed by the owner",
        ));
    }
    Ok(())
}

fn same_key(envelope: &str, expected: &[u8; 32]) -> Result<bool> {
    let bytes = decode_ed25519_pub(envelope)?;
    Ok(bool::from(bytes.ct_eq(expected)))
}

/// Compares fingerprints ignoring spaces, hyphens and case.
pub fn fingerprints_match(a: &str, b: &str) -> bool {
    let norm = |s: &str| -> String {
        s.chars()
            .filter(|c| !c.is_ascii_whitespace() && *c != '-')
            .map(|c| c.to_ascii_lowercase())
            .collect()
    };
    let (na, nb) = (norm(a), norm(b));
    na.len() == nb.len() && bool::from(na.as_bytes().ct_eq(nb.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::random_uuid_v4;

    fn pin(vault_id: Uuid, owner: &UserKeyset) -> VaultPin {
        VaultPin {
            vault_id,
            owner_user_id: random_uuid_v4().unwrap(),
            owner_sign_public_key: owner.sign_public_envelope(),
            owner_fingerprint: Some(owner.fingerprint()),
            revision: 7,
            roster_version: 3,
            key_version: 2,
        }
    }

    #[test]
    fn encrypted_trust_state_only_opens_with_the_same_account_keys() {
        let user_id = random_uuid_v4().unwrap();
        let keys = UserKeyset::generate().unwrap();
        let owner = UserKeyset::generate().unwrap();
        let mut store = TrustStore::new(user_id);
        let vault_id = random_uuid_v4().unwrap();
        store.put(pin(vault_id, &owner));

        let sealed = store.seal(&keys).unwrap();
        assert!(sealed.starts_with(TRUST_STATE_PREFIX));
        assert_eq!(TrustStore::open(&sealed, &keys, user_id).unwrap(), store);

        let other = UserKeyset::generate().unwrap();
        assert!(TrustStore::open(&sealed, &other, user_id).is_err());
        assert!(TrustStore::open(&sealed, &keys, random_uuid_v4().unwrap()).is_err());

        let mut tampered = sealed.clone();
        tampered.pop();
        tampered.push(if sealed.ends_with('A') { 'B' } else { 'A' });
        assert!(TrustStore::open(&tampered, &keys, user_id).is_err());
    }

    #[test]
    fn state_of_another_account_or_inconsistent_state_is_refused() {
        let user_id = random_uuid_v4().unwrap();
        let owner = UserKeyset::generate().unwrap();
        let mut store = TrustStore::new(user_id);
        let vault_id = random_uuid_v4().unwrap();
        store.put(pin(vault_id, &owner));
        assert!(store.validate_for(user_id).is_ok());
        assert!(store.validate_for(random_uuid_v4().unwrap()).is_err());

        let mut skewed = store.clone();
        let p = skewed.vaults.remove(&vault_id).unwrap();
        skewed.vaults.insert(random_uuid_v4().unwrap(), p);
        assert!(skewed.validate_for(user_id).is_err());
    }

    #[test]
    fn recording_a_local_write_only_makes_the_state_grow() {
        let owner = UserKeyset::generate().unwrap();
        let mut p = pin(random_uuid_v4().unwrap(), &owner);
        p.record_local_write(5, 1, 1);
        assert_eq!((p.revision, p.key_version, p.roster_version), (7, 2, 3));
        p.record_local_write(8, 3, 4);
        assert_eq!((p.revision, p.key_version, p.roster_version), (8, 3, 4));
    }

    #[test]
    fn key_version_lower_than_already_seen_is_a_rollback() {
        use crate::encoding::random_uuid_v4;
        use crate::manifest::{MemberRoster, RosterMember, VaultManifest};
        use crate::snapshot::SnapshotRecipientEnvelope;
        use crate::vault::{
            RecipientKind, VaultKey, VaultMeta, encrypt_vault_meta, seal_vault_key,
        };

        let user_id = random_uuid_v4().unwrap();
        let keys = UserKeyset::generate().unwrap();
        let vault_id = random_uuid_v4().unwrap();
        let vk = VaultKey::generate().unwrap();
        let snap = |revision: u64, key_version: u32| {
            let (meta, meta_sha) =
                encrypt_vault_meta(&vk, vault_id, key_version, &VaultMeta::new("v")).unwrap();
            let (manifest, manifest_sig) =
                VaultManifest::new(vault_id, revision, key_version, user_id, meta_sha, vec![])
                    .unwrap()
                    .sign(&keys)
                    .unwrap();
            let (sealed_vk, vk_sig) = seal_vault_key(
                &vk,
                &keys.enc_public_bytes(),
                RecipientKind::User,
                vault_id,
                user_id,
                key_version,
                &keys,
            )
            .unwrap();
            let (roster, roster_sig) = MemberRoster::new(
                vault_id,
                1,
                vec![RosterMember {
                    enc_pub: keys.enc_public_envelope(),
                    role: VaultRole::Owner,
                    sign_pub: keys.sign_public_envelope(),
                    user_id,
                }],
            )
            .unwrap()
            .sign(&keys)
            .unwrap();
            EncryptedSnapshot {
                v: 1,
                vault_id,
                owner_user_id: user_id,
                owner_sign_public_key: keys.sign_public_envelope(),
                encrypted_meta: meta,
                recipient: SnapshotRecipientEnvelope {
                    kind: RecipientKind::User,
                    id: user_id,
                    key_version,
                    sealed_vk,
                    vk_sig,
                    granted_by_user_id: user_id,
                },
                manifest,
                manifest_sig,
                member_roster: Some(roster),
                member_roster_sig: Some(roster_sig),
                items: vec![],
            }
        };

        let t = verify_vault_for_user(&snap(4, 2), user_id, &keys, None, None).unwrap();
        assert_eq!(t.anchor, AnchorSource::Own);
        let err = verify_vault_for_user(&snap(5, 1), user_id, &keys, Some(&t.pin), None)
            .expect_err("key_version 1 after 2");
        assert_eq!(err, CoreError::RollbackDetected);
        assert!(verify_vault_for_user(&snap(5, 2), user_id, &keys, Some(&t.pin), None).is_ok());
    }

    #[test]
    fn fingerprint_comparison_ignores_spaces_and_case() {
        assert!(fingerprints_match("ab12 cd34", "AB12-CD34"));
        assert!(!fingerprints_match("ab12 cd34", "ab12 cd35"));
        assert!(!fingerprints_match("ab12", "ab12 cd34"));
    }
}
