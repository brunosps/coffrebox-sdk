//! Helpers shared by the native `coffrebox-wasm` tests: people with local keys, and building
//! legitimate or forged snapshots.

#![allow(dead_code)]

use coffrebox_core::encoding::{b64url_encode, random_uuid_v4};
use coffrebox_core::item::{ItemPayload, encrypt_item};
use coffrebox_core::keys::UserKeyset;
use coffrebox_core::manifest::{
    ManifestItemEntry, MemberRoster, RosterMember, VaultManifest, VaultRole,
};
use coffrebox_core::snapshot::{EncryptedItemWire, EncryptedSnapshot, SnapshotRecipientEnvelope};
use coffrebox_core::vault::{
    RecipientKind, VaultKey, VaultMeta, encrypt_vault_meta, seal_vault_key,
};
use uuid::Uuid;

pub struct Persona {
    pub id: Uuid,
    pub keys: UserKeyset,
}

impl Persona {
    pub fn new() -> Self {
        Self {
            id: random_uuid_v4().unwrap(),
            keys: UserKeyset::generate().unwrap(),
        }
    }

    pub fn session_json(&self) -> String {
        serde_json::json!({
            "user_id": self.id,
            "enc_sk_b64": b64url_encode(self.keys.enc_secret_bytes()),
            "sign_seed_b64": b64url_encode(self.keys.sign_seed_bytes()),
        })
        .to_string()
    }
}

pub struct Spec<'a> {
    pub vault_id: Uuid,
    pub owner_user_id: Uuid,
    pub owner_signer: &'a UserKeyset,
    pub roster: Option<(u32, Vec<RosterMember>)>,
    pub writer: (Uuid, &'a UserKeyset),
    pub grantor: (Uuid, &'a UserKeyset),
    pub recipient: (Uuid, &'a UserKeyset),
    pub vk: &'a VaultKey,
    pub key_version: u32,
    pub revision: u64,
    pub items: Vec<(Uuid, u32, &'a str, &'a str)>,
}

impl Spec<'_> {
    pub fn build(&self) -> EncryptedSnapshot {
        let (encrypted_meta, meta_sha) = encrypt_vault_meta(
            self.vk,
            self.vault_id,
            self.key_version,
            &VaultMeta::new("vault"),
        )
        .unwrap();
        let mut wire = Vec::new();
        let mut entries = Vec::new();
        for (id, ver, name, value) in &self.items {
            let (ct, sha) = encrypt_item(
                self.vk,
                self.vault_id,
                *id,
                *ver,
                self.key_version,
                &ItemPayload::new_secret(*name, *value),
            )
            .unwrap();
            wire.push(EncryptedItemWire {
                id: *id,
                version: *ver,
                key_version: self.key_version,
                ciphertext: ct,
                sha256: sha.clone(),
            });
            entries.push(ManifestItemEntry {
                id: *id,
                sha256: sha,
                version: *ver,
            });
        }
        wire.sort_by_key(|i| i.id.as_hyphenated().to_string());
        let manifest = VaultManifest::new(
            self.vault_id,
            self.revision,
            self.key_version,
            self.writer.0,
            meta_sha,
            entries,
        )
        .unwrap();
        let (manifest_json, manifest_sig) = manifest.sign(self.writer.1).unwrap();
        let (sealed_vk, vk_sig) = seal_vault_key(
            self.vk,
            &self.recipient.1.enc_public_bytes(),
            RecipientKind::User,
            self.vault_id,
            self.recipient.0,
            self.key_version,
            self.grantor.1,
        )
        .unwrap();
        let (member_roster, member_roster_sig) = match &self.roster {
            Some((ver, members)) => {
                let r = MemberRoster::new(self.vault_id, *ver, members.clone()).unwrap();
                let (j, s) = r.sign(self.owner_signer).unwrap();
                (Some(j), Some(s))
            }
            None => (None, None),
        };
        EncryptedSnapshot {
            v: 1,
            vault_id: self.vault_id,
            owner_user_id: self.owner_user_id,
            owner_sign_public_key: self.owner_signer.sign_public_envelope(),
            encrypted_meta,
            recipient: SnapshotRecipientEnvelope {
                kind: RecipientKind::User,
                id: self.recipient.0,
                key_version: self.key_version,
                sealed_vk,
                vk_sig,
                granted_by_user_id: self.grantor.0,
            },
            manifest: manifest_json,
            manifest_sig,
            member_roster,
            member_roster_sig,
            items: wire,
        }
    }

    pub fn json(&self) -> String {
        serde_json::to_string(&self.build()).unwrap()
    }
}

pub fn entry(p: &Persona, role: VaultRole) -> RosterMember {
    RosterMember {
        enc_pub: p.keys.enc_public_envelope(),
        role,
        sign_pub: p.keys.sign_public_envelope(),
        user_id: p.id,
    }
}
