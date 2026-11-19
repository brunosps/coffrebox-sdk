use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::keys::{UserKeyset, decode_ed25519_pub, verify_ed25519_strict};

const MANIFEST_DOMAIN_PREFIX: &[u8] = b"coffrebox/v1/manifest\0";
const ROSTER_DOMAIN_PREFIX: &[u8] = b"coffrebox/v1/member-roster\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VaultRole {
    Owner,
    Admin,
    Editor,
    Viewer,
}

impl VaultRole {
    pub fn can_write_items(self) -> bool {
        matches!(self, Self::Owner | Self::Admin | Self::Editor)
    }

    pub fn can_grant_vk(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Editor => "editor",
            Self::Viewer => "viewer",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "owner" => Ok(Self::Owner),
            "admin" => Ok(Self::Admin),
            "editor" => Ok(Self::Editor),
            "viewer" => Ok(Self::Viewer),
            _ => Err(CoreError::InvalidFormat("invalid vault role")),
        }
    }
}

/// Item entry in the canonical manifest (fields in JCS alphabetical order: `id`, `sha256`, `version`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestItemEntry {
    pub id: Uuid,
    pub sha256: String,
    pub version: u32,
}

/// Canonical manifest of a vault (fields in JCS alphabetical order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultManifest {
    pub items: Vec<ManifestItemEntry>,
    pub key_version: u32,
    pub revision: u64,
    pub signed_by: Uuid,
    pub v: u32,
    pub vault_id: Uuid,
    pub vault_meta_sha256: String,
}

impl VaultManifest {
    pub fn new(
        vault_id: Uuid,
        revision: u64,
        key_version: u32,
        signed_by: Uuid,
        vault_meta_sha256: String,
        mut items: Vec<ManifestItemEntry>,
    ) -> Result<Self> {
        if revision == 0 || key_version == 0 {
            return Err(CoreError::InvalidFormat(
                "revision and key_version must be >= 1",
            ));
        }
        if !is_lower_hex_64(&vault_meta_sha256) {
            return Err(CoreError::InvalidFormat("invalid vault_meta_sha256"));
        }
        items.sort_by_key(|a| a.id.as_hyphenated().to_string());
        for win in items.windows(2) {
            if win[0].id == win[1].id {
                return Err(CoreError::InvalidFormat("duplicate item in the manifest"));
            }
        }
        for item in &items {
            if item.version == 0 || !is_lower_hex_64(&item.sha256) {
                return Err(CoreError::InvalidFormat("invalid item entry"));
            }
        }
        Ok(Self {
            items,
            key_version,
            revision,
            signed_by,
            v: crate::FORMAT_VERSION,
            vault_id,
            vault_meta_sha256,
        })
    }

    /// Serializes as Canonical JSON (RFC 8785 JCS): keys in ASCII order, no whitespace.
    pub fn to_canonical_json(&self) -> Result<String> {
        // Re-checks the strict ordering by id before serializing
        let normalized = Self::new(
            self.vault_id,
            self.revision,
            self.key_version,
            self.signed_by,
            self.vault_meta_sha256.clone(),
            self.items.clone(),
        )?;
        serde_json::to_string(&normalized).map_err(|_| CoreError::InvalidFormat("manifest json"))
    }

    /// Strict parse: `raw` must already be identical to the canonical JCS JSON.
    pub fn parse_canonical(raw: &str) -> Result<Self> {
        let parsed: Self = serde_json::from_str(raw)
            .map_err(|_| CoreError::ManifestTampered("malformed manifest JSON"))?;
        if parsed.v != crate::FORMAT_VERSION {
            return Err(CoreError::ManifestTampered("invalid manifest version"));
        }
        let reserialized = parsed
            .to_canonical_json()
            .map_err(|_| CoreError::ManifestTampered("manifest is not in canonical form"))?;
        if reserialized != raw {
            return Err(CoreError::ManifestTampered(
                "manifest is not strict canonical JSON",
            ));
        }
        Ok(parsed)
    }

    pub fn sign(&self, writer_keys: &UserKeyset) -> Result<(String, String)> {
        let canonical = self.to_canonical_json()?;
        let mut msg = Vec::with_capacity(MANIFEST_DOMAIN_PREFIX.len() + canonical.len());
        msg.extend_from_slice(MANIFEST_DOMAIN_PREFIX);
        msg.extend_from_slice(canonical.as_bytes());
        let sig = writer_keys.sign_bytes(&msg);
        Ok((canonical, sig))
    }
}

pub fn verify_manifest_signature(
    canonical_json: &str,
    manifest_sig: &str,
    signer_pub_bytes: &[u8; 32],
) -> Result<VaultManifest> {
    let manifest = VaultManifest::parse_canonical(canonical_json)?;
    let mut msg = Vec::with_capacity(MANIFEST_DOMAIN_PREFIX.len() + canonical_json.len());
    msg.extend_from_slice(MANIFEST_DOMAIN_PREFIX);
    msg.extend_from_slice(canonical_json.as_bytes());
    verify_ed25519_strict(signer_pub_bytes, &msg, manifest_sig)?;
    Ok(manifest)
}

/// Member in the canonical list signed by the owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterMember {
    pub enc_pub: String,
    pub role: VaultRole,
    pub sign_pub: String,
    pub user_id: Uuid,
}

/// Application allowed to receive the VK, registered in the list signed by the owner.
///
/// Fields in JCS alphabetical order: `app_id`, `enc_pub`, `sign_pub`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterApp {
    pub app_id: Uuid,
    pub enc_pub: String,
    pub sign_pub: String,
}

/// Canonical member list of a vault, signed by the owner (`owner_sign_pk`).
///
/// `apps` only appears in the JSON when it is not empty, so older lists (without applications)
/// keep the same canonical form and the same signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRoster {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apps: Vec<RosterApp>,
    pub members: Vec<RosterMember>,
    pub roster_version: u32,
    pub v: u32,
    pub vault_id: Uuid,
}

impl MemberRoster {
    pub fn new(vault_id: Uuid, roster_version: u32, members: Vec<RosterMember>) -> Result<Self> {
        Self::new_with_apps(vault_id, roster_version, members, Vec::new())
    }

    pub fn new_with_apps(
        vault_id: Uuid,
        roster_version: u32,
        mut members: Vec<RosterMember>,
        mut apps: Vec<RosterApp>,
    ) -> Result<Self> {
        if roster_version == 0 || members.is_empty() {
            return Err(CoreError::InvalidFormat("invalid roster"));
        }
        members.sort_by_key(|a| a.user_id.as_hyphenated().to_string());
        for win in members.windows(2) {
            if win[0].user_id == win[1].user_id {
                return Err(CoreError::InvalidFormat("duplicate member in the roster"));
            }
        }
        for m in &members {
            let _ = crate::keys::decode_x25519_pub(&m.enc_pub)?;
            let _ = decode_ed25519_pub(&m.sign_pub)?;
        }
        apps.sort_by_key(|a| a.app_id.as_hyphenated().to_string());
        for win in apps.windows(2) {
            if win[0].app_id == win[1].app_id {
                return Err(CoreError::InvalidFormat(
                    "duplicate application in the roster",
                ));
            }
        }
        for a in &apps {
            let _ = crate::keys::decode_x25519_pub(&a.enc_pub)?;
            let _ = decode_ed25519_pub(&a.sign_pub)?;
        }
        Ok(Self {
            apps,
            members,
            roster_version,
            v: crate::FORMAT_VERSION,
            vault_id,
        })
    }

    pub fn to_canonical_json(&self) -> Result<String> {
        let normalized = Self::new_with_apps(
            self.vault_id,
            self.roster_version,
            self.members.clone(),
            self.apps.clone(),
        )?;
        serde_json::to_string(&normalized).map_err(|_| CoreError::InvalidFormat("json roster"))
    }

    pub fn parse_canonical(raw: &str) -> Result<Self> {
        let parsed: Self = serde_json::from_str(raw)
            .map_err(|_| CoreError::ManifestTampered("malformed roster JSON"))?;
        if parsed.v != crate::FORMAT_VERSION {
            return Err(CoreError::ManifestTampered("invalid roster version"));
        }
        let reserialized = parsed
            .to_canonical_json()
            .map_err(|_| CoreError::ManifestTampered("invalid roster"))?;
        if reserialized != raw {
            return Err(CoreError::ManifestTampered(
                "roster is not strict canonical JSON",
            ));
        }
        Ok(parsed)
    }

    pub fn sign(&self, owner_keys: &UserKeyset) -> Result<(String, String)> {
        let canonical = self.to_canonical_json()?;
        let mut msg = Vec::with_capacity(ROSTER_DOMAIN_PREFIX.len() + canonical.len());
        msg.extend_from_slice(ROSTER_DOMAIN_PREFIX);
        msg.extend_from_slice(canonical.as_bytes());
        let sig = owner_keys.sign_bytes(&msg);
        Ok((canonical, sig))
    }

    pub fn find_member(&self, user_id: Uuid) -> Option<&RosterMember> {
        self.members.iter().find(|m| m.user_id == user_id)
    }

    pub fn find_app(&self, app_id: Uuid) -> Option<&RosterApp> {
        self.apps.iter().find(|a| a.app_id == app_id)
    }
}

pub fn verify_member_roster(
    canonical_json: &str,
    roster_sig: &str,
    owner_sign_pub_bytes: &[u8; 32],
) -> Result<MemberRoster> {
    let roster = MemberRoster::parse_canonical(canonical_json)?;
    let mut msg = Vec::with_capacity(ROSTER_DOMAIN_PREFIX.len() + canonical_json.len());
    msg.extend_from_slice(ROSTER_DOMAIN_PREFIX);
    msg.extend_from_slice(canonical_json.as_bytes());
    verify_ed25519_strict(owner_sign_pub_bytes, &msg, roster_sig)?;
    Ok(roster)
}

fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
