//! Web vault trust anchor: the people WASM functions must never use the owner key that comes in the
//! server response as the anchor.

mod common;

use coffrebox_core::encoding::random_uuid_v4;
use coffrebox_core::item::{ItemPayload, decrypt_item};
use coffrebox_core::manifest::VaultRole;
use coffrebox_core::snapshot::EncryptedSnapshot;
use coffrebox_core::vault::VaultKey;
use coffrebox_wasm::{decrypt_user_snapshot, prepare_item_upsert};
use common::*;

/// The victim's "own" vault, where the server swapped the owner's signing key for the attacker's.
fn forged_own_vault(victim: &Persona, attacker: &Persona, vk: &VaultKey) -> EncryptedSnapshot {
    let mut forged_owner = entry(victim, VaultRole::Owner);
    forged_owner.sign_pub = attacker.keys.sign_public_envelope();
    Spec {
        vault_id: random_uuid_v4().unwrap(),
        owner_user_id: victim.id,
        owner_signer: &attacker.keys,
        roster: Some((1, vec![forged_owner])),
        writer: (victim.id, &attacker.keys),
        grantor: (victim.id, &attacker.keys),
        recipient: (victim.id, &victim.keys),
        vk,
        key_version: 1,
        revision: 3,
        items: vec![(
            random_uuid_v4().unwrap(),
            1,
            "DATABASE_URL",
            "postgres://forged",
        )],
    }
    .build()
}

#[test]
fn web_attack_own_vault_signed_by_attacker_is_refused_on_decrypt() {
    let victim = Persona::new();
    let attacker = Persona::new();
    let attacker_vk = VaultKey::generate().unwrap();
    let forged = forged_own_vault(&victim, &attacker, &attacker_vk);

    let res = decrypt_user_snapshot(
        &victim.session_json(),
        &serde_json::to_string(&forged).unwrap(),
        "",
        None,
    );
    assert!(
        res.is_err(),
        "the WASM accepted an own vault signed by the attacker's key: {}",
        res.unwrap_or_default()
    );
}

#[test]
fn web_attack_item_written_to_forged_vault_does_not_leak_to_attacker_vk() {
    let victim = Persona::new();
    let attacker = Persona::new();
    let attacker_vk = VaultKey::generate().unwrap();
    let forged = forged_own_vault(&victim, &attacker, &attacker_vk);

    let res = prepare_item_upsert(
        &victim.session_json(),
        &serde_json::to_string(&forged).unwrap(),
        "",
        None,
        &serde_json::to_string(&ItemPayload::new_secret("PASSWORD", "real-secret")).unwrap(),
    );
    if let Ok(mutation) = res {
        let body: serde_json::Value = serde_json::from_str(&mutation).unwrap();
        let up = &body["upserts"][0];
        let payload = decrypt_item(
            &attacker_vk,
            forged.vault_id,
            serde_json::from_value(up["id"].clone()).unwrap(),
            up["version"].as_u64().unwrap() as u32,
            up["key_version"].as_u64().unwrap() as u32,
            up["ciphertext"].as_str().unwrap(),
        )
        .expect("the mutation was encrypted with the attacker's VK");
        panic!(
            "the secret was encrypted with the attacker's VK and leaked: {}",
            payload.valor
        );
    }
}

#[test]
fn web_attack_owner_key_swap_after_first_use_requires_confirmation() {
    let owner = Persona::new();
    let member = Persona::new();
    let attacker = Persona::new();
    let vault_id = random_uuid_v4().unwrap();
    let vk = VaultKey::generate().unwrap();
    let item = random_uuid_v4().unwrap();

    let legit = Spec {
        vault_id,
        owner_user_id: owner.id,
        owner_signer: &owner.keys,
        roster: Some((
            2,
            vec![
                entry(&owner, VaultRole::Owner),
                entry(&member, VaultRole::Editor),
            ],
        )),
        writer: (owner.id, &owner.keys),
        grantor: (owner.id, &owner.keys),
        recipient: (member.id, &member.keys),
        vk: &vk,
        key_version: 1,
        revision: 2,
        items: vec![(item, 1, "API_KEY", "legit")],
    };
    let first: serde_json::Value = serde_json::from_str(
        &decrypt_user_snapshot(&member.session_json(), &legit.json(), "", None).unwrap(),
    )
    .unwrap();
    assert_eq!(first["anchor"], "first_use");
    let state = first["trust_state"].as_str().unwrap().to_string();
    assert!(state.starts_with("cfb1.trust."));

    let attacker_vk = VaultKey::generate().unwrap();
    let mut forged_owner = entry(&owner, VaultRole::Owner);
    forged_owner.sign_pub = attacker.keys.sign_public_envelope();
    let forged = Spec {
        vault_id,
        owner_user_id: owner.id,
        owner_signer: &attacker.keys,
        roster: Some((3, vec![forged_owner, entry(&member, VaultRole::Editor)])),
        writer: (owner.id, &attacker.keys),
        grantor: (owner.id, &attacker.keys),
        recipient: (member.id, &member.keys),
        vk: &attacker_vk,
        key_version: 1,
        revision: 3,
        items: vec![(item, 2, "API_KEY", "from-attacker")],
    };

    let err = decrypt_user_snapshot(&member.session_json(), &forged.json(), &state, None)
        .expect_err("the owner key swap must not pass silently");
    let msg = err.message();
    assert!(msg.starts_with("[OWNER_CHANGED] "), "{msg}");
    let detail: serde_json::Value =
        serde_json::from_str(msg.trim_start_matches("[OWNER_CHANGED] ")).unwrap();
    assert_eq!(detail["pinned"], first["owner_fingerprint"]);

    // Another account's state cannot be used (it is encrypted with the keys of whoever stored it).
    assert!(decrypt_user_snapshot(&attacker.session_json(), &forged.json(), &state, None).is_err());

    // The snapshot is accepted only with explicit confirmation of the presented fingerprint.
    let presented = detail["presented"].as_str().unwrap().to_string();
    let accepted: serde_json::Value = serde_json::from_str(
        &decrypt_user_snapshot(
            &member.session_json(),
            &forged.json(),
            &state,
            Some(presented),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(accepted["anchor"], "reconfirmed");
}
