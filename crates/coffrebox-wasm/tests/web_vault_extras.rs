//! Web vault additions: application access created in the browser, own fingerprint and the QR code
//! of the authenticator enrollment URI.

mod common;

use coffrebox_core::app_token::AppCredentials;
use coffrebox_core::encoding::random_uuid_v4;
use coffrebox_core::manifest::VaultManifest;
use coffrebox_core::manifest::{MemberRoster, VaultRole};
use coffrebox_core::vault::{RecipientKind, VaultKey, open_vault_key};
use coffrebox_wasm::{
    decrypt_user_snapshot, otpauth_qr_svg_path, prepare_app_grant, prepare_vault_rename,
    session_fingerprint,
};
use common::*;
use uuid::Uuid;

fn shared_snapshot(owner: &Persona, editor: &Persona, vk: &VaultKey, vault_id: Uuid) -> String {
    Spec {
        vault_id,
        owner_user_id: owner.id,
        owner_signer: &owner.keys,
        roster: Some((
            2,
            vec![
                entry(owner, VaultRole::Owner),
                entry(editor, VaultRole::Editor),
            ],
        )),
        writer: (owner.id, &owner.keys),
        grantor: (owner.id, &owner.keys),
        recipient: (owner.id, &owner.keys),
        vk,
        key_version: 1,
        revision: 2,
        items: vec![(random_uuid_v4().unwrap(), 1, "DATABASE_URL", "fictitious")],
    }
    .json()
}

#[test]
fn app_grant_builds_a_token_anchored_on_the_verified_owner_key() {
    let owner = Persona::new();
    let editor = Persona::new();
    let vk = VaultKey::generate().unwrap();
    let vault_id = random_uuid_v4().unwrap();
    let snap = shared_snapshot(&owner, &editor, &vk, vault_id);

    let out = prepare_app_grant(&owner.session_json(), &snap, "", "  Loja — produção ").unwrap();
    let body: serde_json::Value = serde_json::from_str(&out).unwrap();
    let app_id: Uuid = serde_json::from_value(body["app_id"].clone()).unwrap();
    let req = &body["request"];
    assert_eq!(req["name"], "Loja — produção");
    assert_eq!(req["app_id"], body["app_id"]);
    assert_eq!(req["key_version"], 1);

    // The token carries the owner key verified locally and opens the VK sealed for the app.
    let creds = AppCredentials::parse_token(body["token"].as_str().unwrap()).unwrap();
    assert_eq!(creds.app_id(), app_id);
    assert_eq!(
        creds.owner_sign_public_bytes(),
        &owner.keys.sign_public_bytes()
    );
    let opened = open_vault_key(
        req["sealed_vk"].as_str().unwrap(),
        req["vk_sig"].as_str().unwrap(),
        creds.x25519_secret_bytes(),
        &owner.keys.sign_public_bytes(),
        RecipientKind::App,
        vault_id,
        app_id,
        1,
    )
    .unwrap();
    assert_eq!(opened.as_bytes(), vk.as_bytes());

    // The application enters the owner-signed list, next to the members already in it.
    let roster = MemberRoster::parse_canonical(req["member_roster"].as_str().unwrap()).unwrap();
    assert_eq!(roster.roster_version, 3);
    assert_eq!(
        roster.find_app(app_id).unwrap().enc_pub,
        creds.enc_public_envelope()
    );
    assert!(roster.find_member(editor.id).is_some());
}

#[test]
fn app_grant_is_refused_for_anyone_but_the_owner() {
    let owner = Persona::new();
    let editor = Persona::new();
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
                entry(&editor, VaultRole::Admin),
            ],
        )),
        writer: (owner.id, &owner.keys),
        grantor: (owner.id, &owner.keys),
        recipient: (editor.id, &editor.keys),
        vk: &vk,
        key_version: 1,
        revision: 2,
        items: vec![],
    }
    .json();

    let err = prepare_app_grant(&editor.session_json(), &snap, "", "Worker").unwrap_err();
    assert!(
        err.message().starts_with("[FORBIDDEN]"),
        "{}",
        err.message()
    );
}

#[test]
fn app_grant_rejects_empty_or_huge_names() {
    let owner = Persona::new();
    let editor = Persona::new();
    let vk = VaultKey::generate().unwrap();
    let snap = shared_snapshot(&owner, &editor, &vk, random_uuid_v4().unwrap());
    for name in ["", "   ", &"x".repeat(129)] {
        let err = prepare_app_grant(&owner.session_json(), &snap, "", name).unwrap_err();
        assert!(err.message().starts_with("[FORMAT]"), "{}", err.message());
    }
}

#[test]
fn session_fingerprint_comes_from_the_local_keyset() {
    let p = Persona::new();
    assert_eq!(
        session_fingerprint(&p.session_json()).unwrap(),
        p.keys.fingerprint()
    );
}

#[test]
fn qr_path_covers_a_square_grid_and_only_accepts_otpauth() {
    let out = otpauth_qr_svg_path(
        "otpauth://totp/Coffrebox:pessoa%40ficticio.local?secret=JBSWY3DPEHPK3PXP&issuer=Coffrebox",
    )
    .unwrap();
    let body: serde_json::Value = serde_json::from_str(&out).unwrap();
    let size = body["size"].as_i64().unwrap();
    assert!((21..=177).contains(&size), "QR size {size}");
    let path = body["path"].as_str().unwrap();
    assert!(path.starts_with('M') && path.ends_with('z'));
    // Every module drawn is inside the grid.
    for cmd in path.split('M').skip(1) {
        let mut it = cmd.trim_end_matches('z').split(['h', 'v', ' ']);
        let x: i64 = it.next().unwrap().parse().unwrap();
        let y: i64 = it.next().unwrap().parse().unwrap();
        let run: i64 = it.next().unwrap().parse().unwrap();
        assert!(x >= 0 && y >= 0 && y < size && x + run <= size);
    }

    for bad in ["https://example.com", "javascript:alert(1)", ""] {
        assert!(otpauth_qr_svg_path(bad).is_err(), "{bad}");
    }
    assert!(otpauth_qr_svg_path(&format!("otpauth://{}", "a".repeat(2000))).is_err());
}

#[test]
fn rename_keeps_the_items_and_signs_the_new_meta() {
    let owner = Persona::new();
    let editor = Persona::new();
    let vk = VaultKey::generate().unwrap();
    let vault_id = random_uuid_v4().unwrap();
    let snap = shared_snapshot(&owner, &editor, &vk, vault_id);

    let out = prepare_vault_rename(&owner.session_json(), &snap, "", "  Família  ").unwrap();
    let body: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(body["expected_revision"], 2);
    assert!(body["upserts"].as_array().unwrap().is_empty());
    assert!(body["deletes"].as_array().unwrap().is_empty());
    let novo = VaultManifest::parse_canonical(body["manifest"].as_str().unwrap()).unwrap();
    let antigo: serde_json::Value = serde_json::from_str(&snap).unwrap();
    let antigo = VaultManifest::parse_canonical(antigo["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(novo.revision, 3);
    assert_eq!(novo.items, antigo.items, "renomear não mexe nos itens");
    assert_ne!(novo.vault_meta_sha256, antigo.vault_meta_sha256);

    // O snapshot com o nome novo abre e mostra o nome sem espaços nas pontas.
    let mut v: serde_json::Value = serde_json::from_str(&snap).unwrap();
    v["encrypted_meta"] = body["encrypted_meta"].clone();
    v["manifest"] = body["manifest"].clone();
    v["manifest_sig"] = body["manifest_sig"].clone();
    let aberto: serde_json::Value = serde_json::from_str(
        &decrypt_user_snapshot(&owner.session_json(), &v.to_string(), "", None).unwrap(),
    )
    .unwrap();
    assert_eq!(aberto["meta"]["nome"], "Família");

    for ruim in ["", "   ", &"x".repeat(121)] {
        let err = prepare_vault_rename(&owner.session_json(), &snap, "", ruim).unwrap_err();
        assert!(err.message().starts_with("[FORMAT]"), "{}", err.message());
    }
}
