//! Web vault rollback protection: `revision` and `roster_version` can only grow compared with the
//! trust state stored by the browser.

mod common;

use coffrebox_core::encoding::random_uuid_v4;
use coffrebox_core::manifest::VaultRole;
use coffrebox_core::vault::VaultKey;
use coffrebox_wasm::decrypt_user_snapshot;
use common::*;

fn trust_state(out: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(out).unwrap();
    v["trust_state"].as_str().unwrap().to_string()
}

#[test]
fn web_attack_old_revision_is_refused() {
    let owner = Persona::new();
    let vk = VaultKey::generate().unwrap();
    let vault_id = random_uuid_v4().unwrap();
    let item = random_uuid_v4().unwrap();
    let spec = |revision: u64, version: u32, value: &'static str| {
        own_vault(
            &owner,
            &vk,
            vault_id,
            revision,
            vec![(item, version, "PASSWORD", value)],
        )
    };

    let current =
        decrypt_user_snapshot(&owner.session_json(), &spec(5, 2, "new").json(), "", None).unwrap();
    let err = decrypt_user_snapshot(
        &owner.session_json(),
        &spec(3, 1, "old").json(),
        &trust_state(&current),
        None,
    )
    .expect_err("revision 3 after 5 must be refused");
    assert!(err.message().starts_with("[ROLLBACK]"), "{}", err.message());
}

#[test]
fn web_attack_old_member_list_is_refused() {
    let owner = Persona::new();
    let member = Persona::new();
    let removed = Persona::new();
    let vk = VaultKey::generate().unwrap();
    let vault_id = random_uuid_v4().unwrap();

    let v3 = Spec {
        vault_id,
        owner_user_id: owner.id,
        owner_signer: &owner.keys,
        roster: Some((
            3,
            vec![
                entry(&owner, VaultRole::Owner),
                entry(&member, VaultRole::Viewer),
            ],
        )),
        writer: (owner.id, &owner.keys),
        grantor: (owner.id, &owner.keys),
        recipient: (member.id, &member.keys),
        vk: &vk,
        key_version: 1,
        revision: 6,
        items: vec![],
    };
    let ok = decrypt_user_snapshot(&member.session_json(), &v3.json(), "", None).unwrap();

    let v2_with_removed = Spec {
        vault_id,
        owner_user_id: owner.id,
        owner_signer: &owner.keys,
        roster: Some((
            2,
            vec![
                entry(&owner, VaultRole::Owner),
                entry(&member, VaultRole::Viewer),
                entry(&removed, VaultRole::Editor),
            ],
        )),
        writer: (removed.id, &removed.keys),
        grantor: (owner.id, &owner.keys),
        recipient: (member.id, &member.keys),
        vk: &vk,
        key_version: 1,
        revision: 7,
        items: vec![(random_uuid_v4().unwrap(), 1, "PIX", "from-removed")],
    };
    let err = decrypt_user_snapshot(
        &member.session_json(),
        &v2_with_removed.json(),
        &trust_state(&ok),
        None,
    )
    .expect_err("list v2 after v3 must be refused");
    assert!(err.message().starts_with("[ROLLBACK]"), "{}", err.message());
}
