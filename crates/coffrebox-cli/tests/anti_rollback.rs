//! Item 3 das correções da Fase 2: proteção contra volta no tempo para pessoas.
//!
//! O servidor reapresenta snapshots antigos, legitimamente assinados, para desfazer escritas ou
//! reabilitar quem já saiu da lista de membros. A CLI precisa recusar `revision` e `roster_version`
//! menores que as já vistas neste aparelho.

mod common;

use coffrebox_core::manifest::VaultRole;
use coffrebox_core::vault::VaultKey;
use common::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn ataque_snapshot_antigo_do_vault_proprio_e_recusado() {
    let srv = FakeServer::start().await;
    let dona = Persona::new("dona@ficticio.local");
    let home = temp_dir("rollback-revisao");
    let sess = home.join("session.json");
    write_session(&sess, &srv.url, &dona);

    let vault_id = new_id();
    let item = new_id();
    let vk = VaultKey::generate().unwrap();
    let spec = |revision: u64, version: u32, valor: &'static str| SnapSpec {
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
        revision,
        items: vec![(item, version, "SENHA_DB", valor)],
    };
    let atual = spec(5, 2, "senha-nova").json();
    let antigo = spec(3, 1, "senha-antiga-vazada").json();
    let id = vault_id.to_string();

    srv.route("GET", &snapshot_path(vault_id), 200, atual);
    let r = coffre(&["get", &id, "SENHA_DB"], None, &sess, &home).await;
    assert!(r.ok, "{}", r.stderr);
    assert_eq!(r.stdout.trim(), "senha-nova");

    srv.route("GET", &snapshot_path(vault_id), 200, antigo);
    let r = coffre(&["get", &id, "SENHA_DB"], None, &sess, &home).await;
    assert!(
        !r.ok,
        "a CLI aceitou voltar da revisão 5 para a 3 e imprimiu: {}",
        r.stdout.trim()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ataque_servidor_descarta_escrita_e_reapresenta_o_snapshot_anterior() {
    let srv = FakeServer::start().await;
    let dona = Persona::new("dona@ficticio.local");
    let home = temp_dir("rollback-escrita");
    let sess = home.join("session.json");
    write_session(&sess, &srv.url, &dona);

    let vault_id = new_id();
    let vk = VaultKey::generate().unwrap();
    let antes = SnapSpec {
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
        revision: 4,
        items: vec![(new_id(), 1, "API_TOKEN", "token-revogado")],
    };
    srv.route("GET", &snapshot_path(vault_id), 200, antes.json());
    srv.route(
        "POST",
        &format!("/api/v1/vaults/{vault_id}/mutations"),
        200,
        json!({ "revision": 5 }),
    );
    let id = vault_id.to_string();

    // A dona troca o token comprometido; o servidor aceita, mas continua servindo a revisão 4.
    let set = coffre(&["set", &id, "API_TOKEN"], Some("token-novo"), &sess, &home).await;
    assert!(set.ok, "{}", set.stderr);

    let r = coffre(&["get", &id, "API_TOKEN"], None, &sess, &home).await;
    assert!(
        !r.ok,
        "a CLI aceitou um snapshot anterior à própria escrita e imprimiu: {}",
        r.stdout.trim()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ataque_lista_de_membros_antiga_reabilita_editor_removido() {
    let srv = FakeServer::start().await;
    let dona = Persona::new("dona@ficticio.local");
    let membro = Persona::new("membro@ficticio.local");
    let removido = Persona::new("removido@ficticio.local");
    let home = temp_dir("rollback-roster");
    let sess = home.join("session.json");
    write_session(&sess, &srv.url, &membro);

    let vault_id = new_id();
    let vk = VaultKey::generate().unwrap();
    let id = vault_id.to_string();

    // Lista atual (v3): o editor removido já não consta.
    let atual = SnapSpec {
        vault_id,
        owner_user_id: dona.id,
        owner_signer: &dona.keys,
        roster: Some(vec![
            dona.roster_entry(VaultRole::Owner),
            membro.roster_entry(VaultRole::Viewer),
        ]),
        roster_version: 3,
        roster_apps: vec![],
        writer: (dona.id, &dona.keys),
        grantor: (dona.id, &dona.keys),
        recipient: (membro.id, &membro.keys),
        vk: &vk,
        key_version: 1,
        revision: 6,
        items: vec![(new_id(), 1, "PIX_CHAVE", "chave-legitima")],
    };
    srv.route("GET", &snapshot_path(vault_id), 200, atual.json());
    let r = coffre(&["get", &id, "PIX_CHAVE"], None, &sess, &home).await;
    assert!(r.ok, "{}", r.stderr);

    // O servidor volta a lista para a v2 (ainda assinada pela dona, com o editor removido) e
    // entrega um manifesto novo assinado por esse editor.
    let reabilitado = SnapSpec {
        vault_id,
        owner_user_id: dona.id,
        owner_signer: &dona.keys,
        roster: Some(vec![
            dona.roster_entry(VaultRole::Owner),
            membro.roster_entry(VaultRole::Viewer),
            removido.roster_entry(VaultRole::Editor),
        ]),
        roster_version: 2,
        roster_apps: vec![],
        writer: (removido.id, &removido.keys),
        grantor: (dona.id, &dona.keys),
        recipient: (membro.id, &membro.keys),
        vk: &vk,
        key_version: 1,
        revision: 7,
        items: vec![(new_id(), 1, "PIX_CHAVE", "chave-do-removido")],
    };
    srv.route("GET", &snapshot_path(vault_id), 200, reabilitado.json());
    let r = coffre(&["get", &id, "PIX_CHAVE"], None, &sess, &home).await;
    assert!(
        !r.ok,
        "a CLI aceitou a lista de membros v2 depois da v3 e imprimiu: {}",
        r.stdout.trim()
    );
}
