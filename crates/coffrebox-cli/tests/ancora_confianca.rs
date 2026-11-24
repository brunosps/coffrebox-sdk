//! Item 1 das correções da Fase 2: a âncora de confiança da CLI não pode vir do servidor.
//!
//! Cada teste monta um servidor invadido que entrega um vault assinado pela chave de um atacante e
//! confere que a CLI recusa o vault em vez de ler ou gravar segredos com a VK do atacante.

mod common;

use coffrebox_core::app_token::AppCredentials;
use coffrebox_core::item::decrypt_item;
use coffrebox_core::manifest::VaultRole;
use coffrebox_core::vault::VaultKey;
use common::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn ataque_vault_proprio_assinado_pelo_atacante_e_recusado_no_get() {
    let srv = FakeServer::start().await;
    let vitima = Persona::new("vitima@ficticio.local");
    let atacante = Persona::new("atacante@ficticio.local");
    let home = temp_dir("ancora-get");
    let sess = home.join("session.json");
    write_session(&sess, &srv.url, &vitima);

    let vault_id = new_id();
    let vk_atacante = VaultKey::generate().unwrap();
    // O servidor diz que a vítima é a dona, mas entrega a chave de assinatura do atacante.
    let mut dono_forjado = vitima.roster_entry(VaultRole::Owner);
    dono_forjado.sign_pub = atacante.keys.sign_public_envelope();
    let forjado = SnapSpec {
        vault_id,
        owner_user_id: vitima.id,
        owner_signer: &atacante.keys,
        roster: Some(vec![dono_forjado]),
        roster_version: 1,
        roster_apps: vec![],
        writer: (vitima.id, &atacante.keys),
        grantor: (vitima.id, &atacante.keys),
        recipient: (vitima.id, &vitima.keys),
        vk: &vk_atacante,
        key_version: 1,
        revision: 3,
        items: vec![(
            new_id(),
            1,
            "DATABASE_URL",
            "postgres://forjado-pelo-atacante",
        )],
    };
    srv.route("GET", &snapshot_path(vault_id), 200, forjado.json());

    let run = coffre(
        &["get", &vault_id.to_string(), "DATABASE_URL"],
        None,
        &sess,
        &home,
    )
    .await;
    assert!(
        !run.ok,
        "a CLI aceitou um vault próprio assinado pela chave do atacante e imprimiu: {}",
        run.stdout.trim()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ataque_vault_proprio_forjado_nao_recebe_segredo_no_set() {
    let srv = FakeServer::start().await;
    let vitima = Persona::new("vitima@ficticio.local");
    let atacante = Persona::new("atacante@ficticio.local");
    let home = temp_dir("ancora-set");
    let sess = home.join("session.json");
    write_session(&sess, &srv.url, &vitima);

    let vault_id = new_id();
    let vk_atacante = VaultKey::generate().unwrap();
    let mut dono_forjado = vitima.roster_entry(VaultRole::Owner);
    dono_forjado.sign_pub = atacante.keys.sign_public_envelope();
    let forjado = SnapSpec {
        vault_id,
        owner_user_id: vitima.id,
        owner_signer: &atacante.keys,
        roster: Some(vec![dono_forjado]),
        roster_version: 1,
        roster_apps: vec![],
        writer: (vitima.id, &atacante.keys),
        grantor: (vitima.id, &atacante.keys),
        recipient: (vitima.id, &vitima.keys),
        vk: &vk_atacante,
        key_version: 1,
        revision: 3,
        items: vec![],
    };
    srv.route("GET", &snapshot_path(vault_id), 200, forjado.json());
    let mutations = format!("/api/v1/vaults/{vault_id}/mutations");
    srv.route("POST", &mutations, 200, json!({ "revision": 4 }));

    let run = coffre(
        &["set", &vault_id.to_string(), "SENHA_REAL"],
        Some("segredo-que-nao-pode-vazar"),
        &sess,
        &home,
    )
    .await;

    for body in srv.posts_to(&mutations) {
        let up = &body["upserts"][0];
        let item_id = serde_json::from_value(up["id"].clone()).unwrap();
        let version = up["version"].as_u64().unwrap() as u32;
        let kv = up["key_version"].as_u64().unwrap() as u32;
        let ct = up["ciphertext"].as_str().unwrap();
        if let Ok(payload) = decrypt_item(&vk_atacante, vault_id, item_id, version, kv, ct) {
            panic!(
                "o segredo foi cifrado com a VK do atacante e vazou: {}",
                payload.valor
            );
        }
    }
    assert!(!run.ok, "o `coffre set` precisa recusar o vault forjado");
}

#[tokio::test(flavor = "multi_thread")]
async fn ataque_troca_da_chave_do_dono_em_vault_compartilhado_e_recusada_depois_do_primeiro_uso() {
    let srv = FakeServer::start().await;
    let dona = Persona::new("dona@ficticio.local");
    let membro = Persona::new("membro@ficticio.local");
    let atacante = Persona::new("atacante@ficticio.local");
    let home = temp_dir("ancora-tofu");
    let sess = home.join("session.json");
    write_session(&sess, &srv.url, &membro);

    let vault_id = new_id();
    let vk = VaultKey::generate().unwrap();
    let legitimo = SnapSpec {
        vault_id,
        owner_user_id: dona.id,
        owner_signer: &dona.keys,
        roster: Some(vec![
            dona.roster_entry(VaultRole::Owner),
            membro.roster_entry(VaultRole::Editor),
        ]),
        roster_version: 2,
        roster_apps: vec![],
        writer: (dona.id, &dona.keys),
        grantor: (dona.id, &dona.keys),
        recipient: (membro.id, &membro.keys),
        vk: &vk,
        key_version: 1,
        revision: 4,
        items: vec![(new_id(), 1, "API_KEY", "valor-legitimo")],
    };
    srv.route("GET", &snapshot_path(vault_id), 200, legitimo.json());

    // Primeiro uso: a CLI fixa a chave da dona (TOFU) e lê normalmente.
    let primeiro = coffre(
        &["get", &vault_id.to_string(), "API_KEY"],
        None,
        &sess,
        &home,
    )
    .await;
    assert!(
        primeiro.ok,
        "primeiro uso legítimo falhou: {}",
        primeiro.stderr
    );
    assert_eq!(primeiro.stdout.trim(), "valor-legitimo");

    // Depois o servidor troca a chave da dona pela do atacante, mantendo o mesmo user_id.
    let vk_atacante = VaultKey::generate().unwrap();
    let mut dona_forjada = dona.roster_entry(VaultRole::Owner);
    dona_forjada.sign_pub = atacante.keys.sign_public_envelope();
    let forjado = SnapSpec {
        vault_id,
        owner_user_id: dona.id,
        owner_signer: &atacante.keys,
        roster: Some(vec![dona_forjada, membro.roster_entry(VaultRole::Editor)]),
        roster_version: 3,
        roster_apps: vec![],
        writer: (dona.id, &atacante.keys),
        grantor: (dona.id, &atacante.keys),
        recipient: (membro.id, &membro.keys),
        vk: &vk_atacante,
        key_version: 1,
        revision: 5,
        items: vec![(new_id(), 1, "API_KEY", "valor-do-atacante")],
    };
    srv.route("GET", &snapshot_path(vault_id), 200, forjado.json());

    let troca = coffre(
        &["get", &vault_id.to_string(), "API_KEY"],
        None,
        &sess,
        &home,
    )
    .await;
    assert!(
        !troca.ok,
        "a CLI aceitou a troca silenciosa da chave da dona e imprimiu: {}",
        troca.stdout.trim()
    );

    // O servidor também não pode simplesmente apontar outro dono para o mesmo vault.
    let outro_dono = SnapSpec {
        vault_id,
        owner_user_id: atacante.id,
        owner_signer: &atacante.keys,
        roster: Some(vec![
            atacante.roster_entry(VaultRole::Owner),
            membro.roster_entry(VaultRole::Editor),
        ]),
        roster_version: 3,
        roster_apps: vec![],
        writer: (atacante.id, &atacante.keys),
        grantor: (atacante.id, &atacante.keys),
        recipient: (membro.id, &membro.keys),
        vk: &vk_atacante,
        key_version: 1,
        revision: 5,
        items: vec![(new_id(), 1, "API_KEY", "valor-do-atacante")],
    };
    srv.route("GET", &snapshot_path(vault_id), 200, outro_dono.json());
    let troca_dono = coffre(
        &["get", &vault_id.to_string(), "API_KEY"],
        None,
        &sess,
        &home,
    )
    .await;
    assert!(
        !troca_dono.ok,
        "a CLI aceitou outro dono para um vault já fixado e imprimiu: {}",
        troca_dono.stdout.trim()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ataque_app_create_nao_grava_chave_do_atacante_como_ancora_do_token() {
    let srv = FakeServer::start().await;
    let vitima = Persona::new("vitima@ficticio.local");
    let atacante = Persona::new("atacante@ficticio.local");
    let home = temp_dir("ancora-app");
    let sess = home.join("session.json");
    write_session(&sess, &srv.url, &vitima);

    let vault_id = new_id();
    let vk_atacante = VaultKey::generate().unwrap();
    let mut dono_forjado = vitima.roster_entry(VaultRole::Owner);
    dono_forjado.sign_pub = atacante.keys.sign_public_envelope();
    let forjado = SnapSpec {
        vault_id,
        owner_user_id: vitima.id,
        owner_signer: &atacante.keys,
        roster: Some(vec![dono_forjado]),
        roster_version: 1,
        roster_apps: vec![],
        writer: (vitima.id, &atacante.keys),
        grantor: (vitima.id, &atacante.keys),
        recipient: (vitima.id, &vitima.keys),
        vk: &vk_atacante,
        key_version: 1,
        revision: 3,
        items: vec![],
    };
    srv.route("GET", &snapshot_path(vault_id), 200, forjado.json());
    let apps = format!("/api/v1/vaults/{vault_id}/apps");
    srv.route("POST", &apps, 201, json!({ "app_id": new_id() }));

    let run = coffre(
        &[
            "app",
            "create",
            "api-pagamentos",
            "--vault",
            &vault_id.to_string(),
        ],
        None,
        &sess,
        &home,
    )
    .await;

    if run.ok {
        let token = run.stdout.trim();
        let creds = AppCredentials::parse_token(token).unwrap();
        assert_eq!(
            creds.owner_sign_public_bytes(),
            &vitima.keys.sign_public_bytes(),
            "o token da aplicação foi emitido com a chave do atacante como âncora"
        );
    }
    assert!(
        srv.posts_to(&apps).is_empty(),
        "a CLI registrou uma aplicação num vault forjado"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn vault_proprio_legitimo_continua_funcionando_e_token_usa_a_propria_chave() {
    let srv = FakeServer::start().await;
    let dona = Persona::new("dona@ficticio.local");
    let home = temp_dir("ancora-legitimo");
    let sess = home.join("session.json");
    write_session(&sess, &srv.url, &dona);

    let vault_id = new_id();
    let vk = VaultKey::generate().unwrap();
    let legitimo = SnapSpec {
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
        items: vec![(new_id(), 1, "DATABASE_URL", "postgres://legitimo")],
    };
    srv.route("GET", &snapshot_path(vault_id), 200, legitimo.json());
    let apps = format!("/api/v1/vaults/{vault_id}/apps");
    srv.route("POST", &apps, 201, json!({ "app_id": new_id() }));

    let get = coffre(
        &["get", &vault_id.to_string(), "DATABASE_URL"],
        None,
        &sess,
        &home,
    )
    .await;
    assert!(get.ok, "leitura legítima falhou: {}", get.stderr);
    assert_eq!(get.stdout.trim(), "postgres://legitimo");

    let app = coffre(
        &["app", "create", "api", "--vault", &vault_id.to_string()],
        None,
        &sess,
        &home,
    )
    .await;
    assert!(app.ok, "app create legítimo falhou: {}", app.stderr);
    let creds = AppCredentials::parse_token(app.stdout.trim()).unwrap();
    assert_eq!(
        creds.owner_sign_public_bytes(),
        &dona.keys.sign_public_bytes()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn troca_da_chave_do_dono_so_vale_depois_de_confirmacao_explicita() {
    use coffrebox_core::keys::compute_fingerprint;

    let srv = FakeServer::start().await;
    let dona = Persona::new("dona@ficticio.local");
    let nova_chave_da_dona = Persona::new("dona@ficticio.local");
    let membro = Persona::new("membro@ficticio.local");
    let home = temp_dir("ancora-confiar");
    let sess = home.join("session.json");
    write_session(&sess, &srv.url, &membro);

    let vault_id = new_id();
    let vk = VaultKey::generate().unwrap();
    let antes = SnapSpec {
        vault_id,
        owner_user_id: dona.id,
        owner_signer: &dona.keys,
        roster: Some(vec![
            dona.roster_entry(VaultRole::Owner),
            membro.roster_entry(VaultRole::Viewer),
        ]),
        roster_version: 2,
        roster_apps: vec![],
        writer: (dona.id, &dona.keys),
        grantor: (dona.id, &dona.keys),
        recipient: (membro.id, &membro.keys),
        vk: &vk,
        key_version: 1,
        revision: 2,
        items: vec![(new_id(), 1, "TOKEN", "antes")],
    };
    srv.route("GET", &snapshot_path(vault_id), 200, antes.json());
    let id = vault_id.to_string();
    assert!(coffre(&["get", &id, "TOKEN"], None, &sess, &home).await.ok);

    // A dona recriou as chaves; o servidor passa a entregar a lista assinada pela chave nova.
    let mut dona_nova = nova_chave_da_dona.roster_entry(VaultRole::Owner);
    dona_nova.user_id = dona.id;
    let depois = SnapSpec {
        vault_id,
        owner_user_id: dona.id,
        owner_signer: &nova_chave_da_dona.keys,
        roster: Some(vec![dona_nova, membro.roster_entry(VaultRole::Viewer)]),
        roster_version: 3,
        roster_apps: vec![],
        writer: (dona.id, &nova_chave_da_dona.keys),
        grantor: (dona.id, &nova_chave_da_dona.keys),
        recipient: (membro.id, &membro.keys),
        vk: &vk,
        key_version: 1,
        revision: 3,
        items: vec![(new_id(), 1, "TOKEN", "depois")],
    };
    srv.route("GET", &snapshot_path(vault_id), 200, depois.json());

    let recusado = coffre(&["get", &id, "TOKEN"], None, &sess, &home).await;
    assert!(!recusado.ok);
    assert!(
        recusado.stderr.contains("a chave do dono do vault"),
        "o alerta precisa explicar a troca da chave do dono: {}",
        recusado.stderr
    );

    let nova_fp = compute_fingerprint(
        &nova_chave_da_dona.keys.enc_public_bytes(),
        &nova_chave_da_dona.keys.sign_public_bytes(),
    );
    let last4 = &nova_fp[nova_fp.len() - 4..];
    let errado = if last4 == "0000" { "ffff" } else { "0000" };

    let negado = coffre(
        &["vault", "confiar", &id],
        Some(&format!("{errado}\n")),
        &sess,
        &home,
    )
    .await;
    assert!(!negado.ok, "confiar com dígitos errados precisa falhar");
    assert!(!coffre(&["get", &id, "TOKEN"], None, &sess, &home).await.ok);

    let aceito = coffre(
        &["vault", "confiar", &id],
        Some(&format!("{last4}\n")),
        &sess,
        &home,
    )
    .await;
    assert!(
        aceito.ok,
        "confiar com os dígitos certos falhou: {}",
        aceito.stderr
    );

    let lido = coffre(&["get", &id, "TOKEN"], None, &sess, &home).await;
    assert!(lido.ok, "{}", lido.stderr);
    assert_eq!(lido.stdout.trim(), "depois");
}
