//! Generates the fictitious fixtures used by the TypeScript SDK tests
//! (`packages/sdk-ts/test/fixtures/vault-app.json`).
//!
//! The application token and the snapshots can only be built in Rust (the WASM does not expose
//! creating application credentials). To regenerate:
//!
//! ```text
//! cargo test -p coffrebox-wasm --test fixtures_sdk_ts -- --ignored
//! ```
//!
//! The non-ignored test checks that the stored fixtures are still valid for the current core.

use std::path::PathBuf;

use coffrebox_core::app_token::AppCredentials;
use coffrebox_core::encoding::random_uuid_v4;
use coffrebox_core::item::{ItemPayload, encrypt_item};
use coffrebox_core::keys::UserKeyset;
use coffrebox_core::manifest::{
    ManifestItemEntry, MemberRoster, RosterApp, RosterMember, VaultManifest, VaultRole,
};
use coffrebox_core::snapshot::{
    EncryptedItemWire, EncryptedSnapshot, SnapshotRecipientEnvelope, verify_and_decrypt_for_app,
};
use coffrebox_core::vault::{
    RecipientKind, VaultKey, VaultMeta, encrypt_vault_meta, seal_vault_key,
};
use uuid::Uuid;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../packages/sdk-ts/test/fixtures/vault-app.json")
}

struct Scenario {
    owner_id: Uuid,
    owner: UserKeyset,
    vault_id: Uuid,
    vk: VaultKey,
    creds: AppCredentials,
}

/// Item of a fictitious snapshot: (id, version, name, value).
type FakeItem<'a> = (Uuid, u32, &'a str, &'a str);

impl Scenario {
    fn new() -> Self {
        let owner = UserKeyset::generate().unwrap();
        let app_id = random_uuid_v4().unwrap();
        Self {
            owner_id: random_uuid_v4().unwrap(),
            creds: AppCredentials::generate(app_id, owner.sign_public_bytes()).unwrap(),
            owner,
            vault_id: random_uuid_v4().unwrap(),
            vk: VaultKey::generate().unwrap(),
        }
    }

    fn snapshot(&self, revision: u64, items: &[FakeItem<'_>]) -> EncryptedSnapshot {
        let (encrypted_meta, meta_sha) = encrypt_vault_meta(
            &self.vk,
            self.vault_id,
            1,
            &VaultMeta::new("fictitious-api"),
        )
        .unwrap();
        let mut entries = Vec::new();
        let mut wire = Vec::new();
        for (id, version, name, value) in items {
            let (ct, sha) = encrypt_item(
                &self.vk,
                self.vault_id,
                *id,
                *version,
                1,
                &ItemPayload::new_secret(*name, *value),
            )
            .unwrap();
            entries.push(ManifestItemEntry {
                id: *id,
                sha256: sha.clone(),
                version: *version,
            });
            wire.push(EncryptedItemWire {
                id: *id,
                version: *version,
                key_version: 1,
                ciphertext: ct,
                sha256: sha,
            });
        }
        let (manifest, manifest_sig) =
            VaultManifest::new(self.vault_id, revision, 1, self.owner_id, meta_sha, entries)
                .unwrap()
                .sign(&self.owner)
                .unwrap();
        let (sealed_vk, vk_sig) = seal_vault_key(
            &self.vk,
            &self.creds.enc_public_bytes(),
            RecipientKind::App,
            self.vault_id,
            self.creds.app_id(),
            1,
            &self.owner,
        )
        .unwrap();
        let (roster, roster_sig) = MemberRoster::new_with_apps(
            self.vault_id,
            2,
            vec![RosterMember {
                enc_pub: self.owner.enc_public_envelope(),
                role: VaultRole::Owner,
                sign_pub: self.owner.sign_public_envelope(),
                user_id: self.owner_id,
            }],
            vec![RosterApp {
                app_id: self.creds.app_id(),
                enc_pub: self.creds.enc_public_envelope(),
                sign_pub: self.creds.sign_public_envelope(),
            }],
        )
        .unwrap()
        .sign(&self.owner)
        .unwrap();
        EncryptedSnapshot {
            v: 1,
            vault_id: self.vault_id,
            owner_user_id: self.owner_id,
            owner_sign_public_key: self.owner.sign_public_envelope(),
            encrypted_meta,
            recipient: SnapshotRecipientEnvelope {
                kind: RecipientKind::App,
                id: self.creds.app_id(),
                key_version: 1,
                sealed_vk,
                vk_sig,
                granted_by_user_id: self.owner_id,
            },
            manifest,
            manifest_sig,
            member_roster: Some(roster),
            member_roster_sig: Some(roster_sig),
            items: wire,
        }
    }
}

#[test]
#[ignore = "regenerates the TypeScript SDK fixtures"]
fn generate_sdk_ts_fixtures() {
    const DB_V1: &str = "postgres://fictitious:v1@db.internal/app";
    const DB_V2: &str = "postgres://fictitious:v2@db.internal/app";
    const REDIS: &str = "redis://fictitious@cache.internal:6379/0";
    const API_KEY: &str = "fictitious-api-key-0001";

    let c = Scenario::new();
    let app_id = c.creds.app_id();
    let db = random_uuid_v4().unwrap();
    let redis = random_uuid_v4().unwrap();

    let rev2 = c.snapshot(2, &[(db, 1, "DATABASE_URL", DB_V1)]);
    let rev3 = c.snapshot(3, &[(db, 2, "DATABASE_URL", DB_V2)]);
    // A new secret, DATABASE_URL unchanged.
    let rev4 = c.snapshot(
        4,
        &[
            (db, 2, "DATABASE_URL", DB_V2),
            (redis, 1, "REDIS_URL", REDIS),
        ],
    );
    // DATABASE_URL removed from the vault.
    let rev5 = c.snapshot(5, &[(redis, 1, "REDIS_URL", REDIS)]);

    // An item injected outside the signed manifest.
    let mut injected = rev3.clone();
    let mut extra = rev3.items[0].clone();
    extra.id = random_uuid_v4().unwrap();
    injected.items.push(extra);

    // VK envelope swapped for an attacker's (a VK the attacker knows, signed by the attacker).
    let attacker = UserKeyset::generate().unwrap();
    let mut attacker_vk = rev3.clone();
    let (sealed, sig) = seal_vault_key(
        &VaultKey::generate().unwrap(),
        &c.creds.enc_public_bytes(),
        RecipientKind::App,
        c.vault_id,
        app_id,
        1,
        &attacker,
    )
    .unwrap();
    attacker_vk.recipient.sealed_vk = sealed;
    attacker_vk.recipient.vk_sig = sig;

    // A second application, in another vault, for the two-clients-in-one-process tests.
    let other = Scenario::new();
    let other_snap = other.snapshot(1, &[(random_uuid_v4().unwrap(), 1, "API_KEY", API_KEY)]);

    let out = serde_json::json!({
        "notice": "Fictitious fixtures for tests. Regenerate with: cargo test -p coffrebox-wasm --test fixtures_sdk_ts -- --ignored",
        "token": &*c.creds.to_token(),
        "app_id": app_id,
        "vault_id": c.vault_id,
        "snapshots": {
            "rev2": rev2,
            "rev3": rev3,
            "rev4": rev4,
            "rev5": rev5,
            "injected_item": injected,
            "attacker_vk": attacker_vk,
        },
        "values": {
            "rev2": DB_V1,
            "rev3": DB_V2,
            "redis": REDIS,
        },
        "other": {
            "token": &*other.creds.to_token(),
            "app_id": other.creds.app_id(),
            "vault_id": other.vault_id,
            "snapshot": other_snap,
            "api_key": API_KEY,
        }
    });
    std::fs::write(
        fixture_path(),
        serde_json::to_string_pretty(&out).unwrap() + "\n",
    )
    .unwrap();
}

#[test]
fn sdk_ts_fixtures_are_still_valid() {
    let raw = std::fs::read_to_string(fixture_path()).expect("missing TS SDK fixtures");
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let creds = AppCredentials::parse_token(v["token"].as_str().unwrap()).unwrap();
    let snap = |k: &str| -> EncryptedSnapshot {
        serde_json::from_value(v["snapshots"][k].clone()).unwrap()
    };
    assert_eq!(
        verify_and_decrypt_for_app(&snap("rev2"), &creds, None)
            .unwrap()
            .revision,
        2
    );
    assert_eq!(
        verify_and_decrypt_for_app(&snap("rev3"), &creds, Some(3))
            .unwrap()
            .revision,
        3
    );
    assert!(verify_and_decrypt_for_app(&snap("rev2"), &creds, Some(3)).is_err());
    for (k, rev) in [("rev4", 4), ("rev5", 5)] {
        assert_eq!(
            verify_and_decrypt_for_app(&snap(k), &creds, Some(3))
                .unwrap()
                .revision,
            rev
        );
    }
    let other_creds = AppCredentials::parse_token(v["other"]["token"].as_str().unwrap()).unwrap();
    let other_snap: EncryptedSnapshot =
        serde_json::from_value(v["other"]["snapshot"].clone()).unwrap();
    assert!(verify_and_decrypt_for_app(&other_snap, &other_creds, None).is_ok());
    // One application's credential does not open the other's vault.
    assert!(verify_and_decrypt_for_app(&other_snap, &creds, None).is_err());
    assert!(verify_and_decrypt_for_app(&snap("injected_item"), &creds, None).is_err());
    assert!(verify_and_decrypt_for_app(&snap("attacker_vk"), &creds, None).is_err());
}
