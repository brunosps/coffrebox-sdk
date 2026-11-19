//! Web vault members and rotation: the member list and the rotation recipients come from the list
//! signed by the owner, not from the server's `/members` and `/apps` lists.

mod common;

use coffrebox_core::encoding::random_uuid_v4;
use coffrebox_core::manifest::{MemberRoster, VaultRole};
use coffrebox_core::vault::{RecipientKind, VaultKey, open_vault_key};
use coffrebox_wasm::{member_fingerprint, prepare_key_rotation, prepare_member_grant};
use common::*;
use uuid::Uuid;

#[test]
fn web_attack_grant_does_not_copy_server_injected_members_into_the_signed_list() {
    let owner = Persona::new();
    let editor = Persona::new();
    let newcomer = Persona::new();
    let attacker = Persona::new();
    let vk = VaultKey::generate().unwrap();
    let vault_id = random_uuid_v4().unwrap();
    let snap = Spec {
        vault_id,
        owner_user_id: owner.id,
        owner_signer: &owner.keys,
        roster: Some((
            2,
            vec![
                entry(&owner, VaultRole::Owner),
                entry(&editor, VaultRole::Editor),
            ],
        )),
        writer: (owner.id, &owner.keys),
        grantor: (owner.id, &owner.keys),
        recipient: (owner.id, &owner.keys),
        vk: &vk,
        key_version: 1,
        revision: 2,
        items: vec![],
    }
    .json();

    // The web vault used to build the new list from the server's `/members` (where the editor
    // showed up with the attacker's key and an admin was injected). Now the grant only receives the
    // new member's data; the rest comes from the signed list verified in the snapshot.
    let fp = newcomer.keys.fingerprint();
    let out = prepare_member_grant(
        &owner.session_json(),
        &snap,
        "",
        &newcomer.id.to_string(),
        &newcomer.keys.enc_public_envelope(),
        &newcomer.keys.sign_public_envelope(),
        "viewer",
        &fp[fp.len() - 4..],
    )
    .unwrap();
    let body: serde_json::Value = serde_json::from_str(&out).unwrap();
    let roster = MemberRoster::parse_canonical(body["member_roster"].as_str().unwrap()).unwrap();
    assert!(
        roster.find_member(attacker.id).is_none(),
        "a member injected by the server got into the list signed by the owner"
    );
    assert_eq!(
        roster.find_member(editor.id).unwrap().enc_pub,
        editor.keys.enc_public_envelope(),
        "the signed list received the editor key swapped by the server"
    );
}

#[test]
fn web_attack_rotation_does_not_seal_vk_for_server_keys() {
    let owner = Persona::new();
    let editor = Persona::new();
    let viewer = Persona::new();
    let attacker = Persona::new();
    let vk = VaultKey::generate().unwrap();
    let vault_id = random_uuid_v4().unwrap();
    let snap = Spec {
        vault_id,
        owner_user_id: owner.id,
        owner_signer: &owner.keys,
        roster: Some((
            3,
            vec![
                entry(&owner, VaultRole::Owner),
                entry(&editor, VaultRole::Editor),
                entry(&viewer, VaultRole::Viewer),
            ],
        )),
        writer: (owner.id, &owner.keys),
        grantor: (owner.id, &owner.keys),
        recipient: (owner.id, &owner.keys),
        vk: &vk,
        key_version: 1,
        revision: 4,
        items: vec![(random_uuid_v4().unwrap(), 1, "SECRET", "value")],
    }
    .json();

    // The "remaining" members used to come from the server's `/members` (editor with the attacker's
    // key and an injected member). Now the rotation only receives who leaves; the recipients come
    // from the signed list.
    let out = prepare_key_rotation(
        &owner.session_json(),
        &snap,
        "",
        Some(viewer.id.to_string()),
        None,
        "[]",
    )
    .unwrap();
    let body: serde_json::Value = serde_json::from_str(&out).unwrap();
    for g in body["member_grants"].as_array().unwrap() {
        let uid: Uuid = serde_json::from_value(g["user_id"].clone()).unwrap();
        let opened = open_vault_key(
            g["sealed_vk"].as_str().unwrap(),
            g["vk_sig"].as_str().unwrap(),
            attacker.keys.enc_secret_bytes(),
            &owner.keys.sign_public_bytes(),
            RecipientKind::User,
            vault_id,
            uid,
            2,
        );
        assert!(
            opened.is_err(),
            "the new VK was sealed for an attacker key (recipient {uid})"
        );
        assert_ne!(uid, viewer.id, "the removed member received the new VK");
    }
    let roster = MemberRoster::parse_canonical(body["member_roster"].as_str().unwrap()).unwrap();
    assert!(roster.find_member(attacker.id).is_none());
    assert!(roster.find_member(viewer.id).is_none());
    assert_eq!(
        roster.find_member(editor.id).unwrap().enc_pub,
        editor.keys.enc_public_envelope()
    );
}

#[test]
fn web_grant_checks_the_fingerprint_computed_from_the_sealed_keys() {
    let owner = Persona::new();
    let member = Persona::new();
    let attacker = Persona::new();
    let vk = VaultKey::generate().unwrap();
    let vault_id = random_uuid_v4().unwrap();
    let snap = Spec {
        vault_id,
        owner_user_id: owner.id,
        owner_signer: &owner.keys,
        roster: Some((1, vec![entry(&owner, VaultRole::Owner)])),
        writer: (owner.id, &owner.keys),
        grantor: (owner.id, &owner.keys),
        recipient: (owner.id, &owner.keys),
        vk: &vk,
        key_version: 1,
        revision: 1,
        items: vec![],
    }
    .json();

    // The server hands over the attacker's keys; the owner types the 4 digits the member read out.
    let member_fp = member.keys.fingerprint();
    let err = prepare_member_grant(
        &owner.session_json(),
        &snap,
        "",
        &member.id.to_string(),
        &attacker.keys.enc_public_envelope(),
        &attacker.keys.sign_public_envelope(),
        "editor",
        &member_fp[member_fp.len() - 4..],
    )
    .expect_err("the grant must refuse keys that do not match the typed fingerprint");
    assert!(
        err.message().starts_with("[FINGERPRINT]"),
        "{}",
        err.message()
    );

    assert_eq!(
        member_fingerprint(
            &member.keys.enc_public_envelope(),
            &member.keys.sign_public_envelope()
        )
        .unwrap(),
        member_fp
    );

    // Whoever is not the owner does not sign the list.
    let viewer = Persona::new();
    let viewer_snap = Spec {
        vault_id,
        owner_user_id: owner.id,
        owner_signer: &owner.keys,
        roster: Some((
            2,
            vec![
                entry(&owner, VaultRole::Owner),
                entry(&viewer, VaultRole::Admin),
            ],
        )),
        writer: (owner.id, &owner.keys),
        grantor: (owner.id, &owner.keys),
        recipient: (viewer.id, &viewer.keys),
        vk: &vk,
        key_version: 1,
        revision: 2,
        items: vec![],
    }
    .json();
    let err = prepare_member_grant(
        &viewer.session_json(),
        &viewer_snap,
        "",
        &member.id.to_string(),
        &member.keys.enc_public_envelope(),
        &member.keys.sign_public_envelope(),
        "viewer",
        &member_fp[member_fp.len() - 4..],
    )
    .expect_err("only the owner changes the signed list");
    assert!(
        err.message().starts_with("[FORBIDDEN]"),
        "{}",
        err.message()
    );
}
