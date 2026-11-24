//! Item 2 das correções da Fase 2: impressão digital, papéis e destinatários da rotação de chave
//! não podem vir do servidor. Tudo sai da lista de membros assinada pelo dono e de cálculo local.

mod common;

use coffrebox_core::app_token::AppCredentials;
use coffrebox_core::manifest::{MemberRoster, VaultRole};
use coffrebox_core::vault::{RecipientKind, VaultKey, open_vault_key};
use common::*;
use serde_json::{Value, json};
use uuid::Uuid;

fn member_json(p: &Persona, role: &str) -> Value {
    json!({
        "user_id": p.id,
        "email": p.email,
        "role": role,
        "enc_public_key": p.keys.enc_public_envelope(),
        "sign_public_key": p.keys.sign_public_envelope(),
        "key_version": 1,
        "confirmed_fingerprint": p.keys.fingerprint(),
        "current_fingerprint": p.keys.fingerprint(),
        "key_changed": false,
    })
}

fn last4(fp: &str) -> String {
    fp[fp.len() - 4..].to_string()
}

/// Tenta abrir um envelope de VK concedido pela dona com uma chave privada qualquer.
fn opens_with(
    grant: &Value,
    kind: RecipientKind,
    recipient_id: Uuid,
    enc_sk: &[u8; 32],
    grantor_sign_pk: &[u8; 32],
    vault_id: Uuid,
    key_version: u32,
) -> bool {
    open_vault_key(
        grant["sealed_vk"].as_str().unwrap_or_default(),
        grant["vk_sig"].as_str().unwrap_or_default(),
        enc_sk,
        grantor_sign_pk,
        kind,
        vault_id,
        recipient_id,
        key_version,
    )
    .is_ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn ataque_impressao_digital_do_servidor_nao_libera_vk_para_chave_trocada() {
    let srv = FakeServer::start().await;
    let dona = Persona::new("dona@ficticio.local");
    let membro = Persona::new("membro@ficticio.local");
    let atacante = Persona::new("atacante@ficticio.local");
    let home = temp_dir("membro-fp");
    let sess = home.join("session.json");
    write_session(&sess, &srv.url, &dona);

    let vault_id = new_id();
    let vk = VaultKey::generate().unwrap();
    let snap = SnapSpec {
        vault_id,
        owner_user_id: dona.id,
        owner_signer: &dona.keys,
        roster: Some(vec![dona.roster_entry(VaultRole::Owner)]),
        roster_version: 1,
        roster_apps: vec![],
        writer: (dona.id, &dona.keys),
        grantor: (dona.id, &dona.keys),
        recipient: (dona.id, &dona.keys),
        vk: &vk,
        key_version: 1,
        revision: 2,
        items: vec![(new_id(), 1, "SEGREDO", "valor")],
    };
    srv.route("GET", &snapshot_path(vault_id), 200, snap.json());

    // O servidor devolve as chaves do atacante, mas a impressão digital verdadeira do membro.
    let mut lookup = membro.lookup_json();
    lookup["enc_public_key"] = json!(atacante.keys.enc_public_envelope());
    lookup["sign_public_key"] = json!(atacante.keys.sign_public_envelope());
    srv.route("GET", "/api/v1/users/lookup", 200, lookup);
    srv.route(
        "GET",
        &format!("/api/v1/vaults/{vault_id}/invites"),
        200,
        json!({ "invites": [{ "email": membro.email, "role": "editor" }] }),
    );
    srv.route(
        "GET",
        &format!("/api/v1/vaults/{vault_id}/members"),
        200,
        json!({ "members": [member_json(&dona, "owner")] }),
    );
    let members_path = format!("/api/v1/vaults/{vault_id}/members");
    srv.route("POST", &members_path, 201, json!({}));

    let run = coffre(
        &["member", "confirm", &vault_id.to_string(), &membro.email],
        Some(&format!("{}\n", last4(&membro.keys.fingerprint()))),
        &sess,
        &home,
    )
    .await;

    for body in srv.posts_to(&members_path) {
        assert!(
            !opens_with(
                &body,
                RecipientKind::User,
                membro.id,
                atacante.keys.enc_secret_bytes(),
                &dona.keys.sign_public_bytes(),
                vault_id,
                1,
            ),
            "a VK foi selada para a chave do atacante depois de a dona confirmar a impressão digital do membro"
        );
    }
    assert!(
        !run.ok,
        "a confirmação precisa falhar: a impressão digital das chaves seladas não é a digitada"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ataque_servidor_nao_escala_o_papel_do_convite() {
    let srv = FakeServer::start().await;
    let dona = Persona::new("dona@ficticio.local");
    let membro = Persona::new("membro@ficticio.local");
    let home = temp_dir("membro-papel");
    let sess = home.join("session.json");
    write_session(&sess, &srv.url, &dona);

    let vault_id = new_id();
    let vk = VaultKey::generate().unwrap();
    let snap = SnapSpec {
        vault_id,
        owner_user_id: dona.id,
        owner_signer: &dona.keys,
        roster: Some(vec![dona.roster_entry(VaultRole::Owner)]),
        roster_version: 1,
        roster_apps: vec![],
        writer: (dona.id, &dona.keys),
        grantor: (dona.id, &dona.keys),
        recipient: (dona.id, &dona.keys),
        vk: &vk,
        key_version: 1,
        revision: 2,
        items: vec![],
    };
    srv.route("GET", &snapshot_path(vault_id), 200, snap.json());
    let invites_path = format!("/api/v1/vaults/{vault_id}/invites");
    srv.route("POST", &invites_path, 201, json!({}));

    let convite = coffre(
        &[
            "member",
            "invite",
            &vault_id.to_string(),
            &membro.email,
            "--papel",
            "viewer",
        ],
        None,
        &sess,
        &home,
    )
    .await;
    assert!(convite.ok, "{}", convite.stderr);

    // O servidor adultera o papel do convite para admin.
    srv.route(
        "GET",
        &invites_path,
        200,
        json!({ "invites": [{ "email": membro.email, "role": "admin" }] }),
    );
    srv.route("GET", "/api/v1/users/lookup", 200, membro.lookup_json());
    srv.route(
        "GET",
        &format!("/api/v1/vaults/{vault_id}/members"),
        200,
        json!({ "members": [member_json(&dona, "owner")] }),
    );
    let members_path = format!("/api/v1/vaults/{vault_id}/members");
    srv.route("POST", &members_path, 201, json!({}));

    let run = coffre(
        &["member", "confirm", &vault_id.to_string(), &membro.email],
        Some(&format!("{}\n", last4(&membro.keys.fingerprint()))),
        &sess,
        &home,
    )
    .await;
    assert!(run.ok, "confirmação legítima falhou: {}", run.stderr);

    let posted = srv.posts_to(&members_path);
    assert_eq!(posted.len(), 1);
    assert_eq!(
        posted[0]["role"], "viewer",
        "o papel enviado ao servidor veio do convite adulterado"
    );
    let roster =
        MemberRoster::parse_canonical(posted[0]["member_roster"].as_str().unwrap()).unwrap();
    assert_eq!(
        roster.find_member(membro.id).unwrap().role,
        VaultRole::Viewer,
        "a lista assinada pela dona recebeu o papel escalado pelo servidor"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ataque_rotacao_no_member_rm_nao_sela_vk_para_destinatarios_injetados() {
    let srv = FakeServer::start().await;
    let dona = Persona::new("dona@ficticio.local");
    let editor = Persona::new("editor@ficticio.local");
    let viewer = Persona::new("viewer@ficticio.local");
    let atacante = Persona::new("atacante@ficticio.local");
    let app_do_atacante =
        AppCredentials::generate(new_id(), dona.keys.sign_public_bytes()).unwrap();
    let home = temp_dir("rotacao-injecao");
    let sess = home.join("session.json");
    write_session(&sess, &srv.url, &dona);

    let vault_id = new_id();
    let vk = VaultKey::generate().unwrap();
    let snap = SnapSpec {
        vault_id,
        owner_user_id: dona.id,
        owner_signer: &dona.keys,
        roster: Some(vec![
            dona.roster_entry(VaultRole::Owner),
            editor.roster_entry(VaultRole::Editor),
            viewer.roster_entry(VaultRole::Viewer),
        ]),
        roster_version: 3,
        roster_apps: vec![],
        writer: (dona.id, &dona.keys),
        grantor: (dona.id, &dona.keys),
        recipient: (dona.id, &dona.keys),
        vk: &vk,
        key_version: 1,
        revision: 5,
        items: vec![(new_id(), 1, "SEGREDO", "valor")],
    };
    srv.route("GET", &snapshot_path(vault_id), 200, snap.json());

    // /members: chave do editor trocada pela do atacante e um admin injetado.
    let mut editor_trocado = member_json(&editor, "editor");
    editor_trocado["enc_public_key"] = json!(atacante.keys.enc_public_envelope());
    srv.route(
        "GET",
        &format!("/api/v1/vaults/{vault_id}/members"),
        200,
        json!({ "members": [
            member_json(&dona, "owner"),
            editor_trocado,
            member_json(&viewer, "viewer"),
            member_json(&atacante, "admin"),
        ]}),
    );
    // /apps: uma aplicação com chaves do atacante aparece como ativa.
    srv.route(
        "GET",
        &format!("/api/v1/vaults/{vault_id}/apps"),
        200,
        json!({ "apps": [{
            "app_id": app_do_atacante.app_id(),
            "name": "app-fantasma",
            "enc_public_key": app_do_atacante.enc_public_envelope(),
            "sign_public_key": app_do_atacante.sign_public_envelope(),
            "key_version": 1,
            "revoked_at": null,
        }]}),
    );
    let remove_path = format!("/api/v1/vaults/{vault_id}/members/{}/remove", viewer.id);
    srv.route("POST", &remove_path, 200, json!({ "key_version": 2 }));

    let run = coffre(
        &["member", "rm", &vault_id.to_string(), &viewer.email],
        None,
        &sess,
        &home,
    )
    .await;
    assert!(run.ok, "member rm legítimo falhou: {}", run.stderr);

    let posted = srv.posts_to(&remove_path);
    assert_eq!(posted.len(), 1);
    let body = &posted[0];
    let owner_pk = dona.keys.sign_public_bytes();

    for g in body["member_grants"].as_array().unwrap() {
        let uid: Uuid = serde_json::from_value(g["user_id"].clone()).unwrap();
        assert!(
            !opens_with(
                g,
                RecipientKind::User,
                uid,
                atacante.keys.enc_secret_bytes(),
                &owner_pk,
                vault_id,
                2
            ),
            "a nova VK foi selada para uma chave do atacante (destinatário {uid})"
        );
        assert_ne!(uid, viewer.id, "o membro removido recebeu a nova VK");
    }
    for g in body["app_grants"].as_array().unwrap() {
        assert!(
            !opens_with(
                g,
                RecipientKind::App,
                app_do_atacante.app_id(),
                app_do_atacante.x25519_secret_bytes(),
                &owner_pk,
                vault_id,
                2
            ),
            "a nova VK foi selada para uma aplicação que não está na lista assinada"
        );
    }

    let roster = MemberRoster::parse_canonical(body["member_roster"].as_str().unwrap()).unwrap();
    assert!(
        roster.find_member(atacante.id).is_none(),
        "membro injetado pelo servidor entrou na lista assinada"
    );
    assert_eq!(
        roster.find_member(editor.id).unwrap().enc_pub,
        editor.keys.enc_public_envelope(),
        "a lista assinada recebeu a chave trocada pelo servidor"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rotacao_usa_a_chave_da_aplicacao_da_lista_assinada_e_nao_a_do_servidor() {
    use coffrebox_core::manifest::RosterApp;

    let srv = FakeServer::start().await;
    let dona = Persona::new("dona@ficticio.local");
    let atacante = Persona::new("atacante@ficticio.local");
    let fica = AppCredentials::generate(new_id(), dona.keys.sign_public_bytes()).unwrap();
    let sai = AppCredentials::generate(new_id(), dona.keys.sign_public_bytes()).unwrap();
    let home = temp_dir("rotacao-app");
    let sess = home.join("session.json");
    write_session(&sess, &srv.url, &dona);

    let roster_app = |c: &AppCredentials| RosterApp {
        app_id: c.app_id(),
        enc_pub: c.enc_public_envelope(),
        sign_pub: c.sign_public_envelope(),
    };
    let vault_id = new_id();
    let vk = VaultKey::generate().unwrap();
    let snap = SnapSpec {
        vault_id,
        owner_user_id: dona.id,
        owner_signer: &dona.keys,
        roster: Some(vec![dona.roster_entry(VaultRole::Owner)]),
        roster_version: 3,
        roster_apps: vec![roster_app(&fica), roster_app(&sai)],
        writer: (dona.id, &dona.keys),
        grantor: (dona.id, &dona.keys),
        recipient: (dona.id, &dona.keys),
        vk: &vk,
        key_version: 1,
        revision: 4,
        items: vec![(new_id(), 1, "DATABASE_URL", "postgres://x")],
    };
    srv.route("GET", &snapshot_path(vault_id), 200, snap.json());
    // O servidor lista a aplicação que fica com a chave X25519 do atacante.
    srv.route(
        "GET",
        &format!("/api/v1/vaults/{vault_id}/apps"),
        200,
        json!({ "apps": [
            { "app_id": fica.app_id(), "name": "fica", "revoked_at": null,
              "enc_public_key": atacante.keys.enc_public_envelope(),
              "sign_public_key": fica.sign_public_envelope(), "key_version": 1 },
            { "app_id": sai.app_id(), "name": "sai", "revoked_at": null,
              "enc_public_key": sai.enc_public_envelope(),
              "sign_public_key": sai.sign_public_envelope(), "key_version": 1 },
        ]}),
    );
    let revoke = format!("/api/v1/vaults/{vault_id}/apps/{}/revoke", sai.app_id());
    srv.route("POST", &revoke, 200, json!({ "key_version": 2 }));

    let run = coffre(
        &["app", "revoke", "sai", "--vault", &vault_id.to_string()],
        None,
        &sess,
        &home,
    )
    .await;
    assert!(run.ok, "{}", run.stderr);

    let body = &srv.posts_to(&revoke)[0];
    let grants = body["app_grants"].as_array().unwrap();
    assert_eq!(grants.len(), 1, "só a aplicação que fica recebe a nova VK");
    assert!(opens_with(
        &grants[0],
        RecipientKind::App,
        fica.app_id(),
        fica.x25519_secret_bytes(),
        &dona.keys.sign_public_bytes(),
        vault_id,
        2
    ));
    assert!(!opens_with(
        &grants[0],
        RecipientKind::App,
        fica.app_id(),
        atacante.keys.enc_secret_bytes(),
        &dona.keys.sign_public_bytes(),
        vault_id,
        2
    ));
    let roster = MemberRoster::parse_canonical(body["member_roster"].as_str().unwrap()).unwrap();
    assert!(roster.find_app(sai.app_id()).is_none());
    assert!(roster.find_app(fica.app_id()).is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn somente_a_dona_altera_a_lista_assinada() {
    let srv = FakeServer::start().await;
    let dona = Persona::new("dona@ficticio.local");
    let admin = Persona::new("admin@ficticio.local");
    let novo = Persona::new("novo@ficticio.local");
    let home = temp_dir("so-dona");
    let sess = home.join("session.json");
    write_session(&sess, &srv.url, &admin);

    let vault_id = new_id();
    let vk = VaultKey::generate().unwrap();
    let snap = SnapSpec {
        vault_id,
        owner_user_id: dona.id,
        owner_signer: &dona.keys,
        roster: Some(vec![
            dona.roster_entry(VaultRole::Owner),
            admin.roster_entry(VaultRole::Admin),
        ]),
        roster_version: 2,
        roster_apps: vec![],
        writer: (dona.id, &dona.keys),
        grantor: (dona.id, &dona.keys),
        recipient: (admin.id, &admin.keys),
        vk: &vk,
        key_version: 1,
        revision: 2,
        items: vec![],
    };
    srv.route("GET", &snapshot_path(vault_id), 200, snap.json());
    srv.route("GET", "/api/v1/users/lookup", 200, novo.lookup_json());
    let id = vault_id.to_string();

    let confirm = coffre(
        &["member", "confirm", &id, &novo.email, "--papel", "viewer"],
        Some(&format!("{}\n", last4(&novo.keys.fingerprint()))),
        &sess,
        &home,
    )
    .await;
    assert!(!confirm.ok);
    assert!(
        confirm.stderr.contains("Somente o dono"),
        "{}",
        confirm.stderr
    );

    let rm = coffre(&["member", "rm", &id, &dona.email], None, &sess, &home).await;
    assert!(!rm.ok);
    assert!(rm.stderr.contains("Somente o dono"), "{}", rm.stderr);
    assert!(
        srv.captured().iter().all(|c| c.method != "POST"),
        "nenhuma alteração pode ser enviada por quem não é dono"
    );
}
