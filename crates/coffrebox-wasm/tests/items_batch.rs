//! Several items in one mutation (the web `.env` import): one revision, new items and replaced ones
//! together, and the limits the browser relies on.

mod common;

use coffrebox_core::encoding::random_uuid_v4;
use coffrebox_core::item::{ItemPayload, decrypt_item};
use coffrebox_core::manifest::VaultManifest;
use coffrebox_core::vault::VaultKey;
use coffrebox_wasm::{MAX_ITEMS_PER_MUTATION, prepare_item_upsert, prepare_items_upsert};
use common::*;
use uuid::Uuid;

struct Cofre {
    owner: Persona,
    vk: VaultKey,
    vault_id: Uuid,
    existente: Uuid,
    outro: Uuid,
    snap: String,
}

fn cofre() -> Cofre {
    let owner = Persona::new();
    let vk = VaultKey::generate().unwrap();
    let vault_id = random_uuid_v4().unwrap();
    let existente = random_uuid_v4().unwrap();
    let outro = random_uuid_v4().unwrap();
    let snap = own_vault(
        &owner,
        &vk,
        vault_id,
        4,
        vec![
            (existente, 3, "DATABASE_URL", "postgres://antigo-ficticio"),
            (outro, 1, "REDIS_URL", "redis://ficticio"),
        ],
    )
    .json();
    Cofre {
        owner,
        vk,
        vault_id,
        existente,
        outro,
        snap,
    }
}

fn lista(itens: &[(Option<Uuid>, &str, &str)]) -> String {
    serde_json::to_string(
        &itens
            .iter()
            .map(|(id, nome, valor)| {
                serde_json::json!({ "id": id, "payload": ItemPayload::new_secret(*nome, *valor) })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

#[test]
fn new_and_replaced_items_go_in_one_revision() {
    let c = cofre();
    let itens = lista(&[
        (None, "SENTRY_DSN", "https://ficticio@sentry.exemplo/1"),
        (
            Some(c.existente),
            "DATABASE_URL",
            "postgres://novo-ficticio",
        ),
        (None, "SMTP_PASSWORD", "senha-ficticia"),
    ]);
    let out = prepare_items_upsert(&c.owner.session_json(), &c.snap, "", &itens).unwrap();
    let body: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(body["expected_revision"], 4);
    assert!(body["deletes"].as_array().unwrap().is_empty());
    let ups = body["upserts"].as_array().unwrap();
    assert_eq!(ups.len(), 3);

    let mut nomes = Vec::new();
    for up in ups {
        let id: Uuid = serde_json::from_value(up["id"].clone()).unwrap();
        let versao = up["version"].as_u64().unwrap() as u32;
        if id == c.existente {
            assert_eq!(versao, 4, "substituir sobe a versão do item existente");
        } else {
            assert_eq!(versao, 1);
            assert_ne!(id, c.outro);
        }
        let p = decrypt_item(
            &c.vk,
            c.vault_id,
            id,
            versao,
            1,
            up["ciphertext"].as_str().unwrap(),
        )
        .unwrap();
        nomes.push((p.nome.clone(), p.valor.clone()));
    }
    assert!(nomes.contains(&("DATABASE_URL".into(), "postgres://novo-ficticio".into())));
    assert!(nomes.contains(&(
        "SENTRY_DSN".into(),
        "https://ficticio@sentry.exemplo/1".into()
    )));

    // O manifesto assinado lista o item que ficou de fora (REDIS_URL) e os três gravados, sem repetir.
    let m = VaultManifest::parse_canonical(body["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(m.revision, 5);
    assert_eq!(m.items.len(), 4);
    assert!(m.items.iter().any(|e| e.id == c.outro && e.version == 1));
    assert_eq!(m.items.iter().filter(|e| e.id == c.existente).count(), 1);
    for up in ups {
        let id: Uuid = serde_json::from_value(up["id"].clone()).unwrap();
        let e = m.items.iter().find(|e| e.id == id).unwrap();
        assert_eq!(e.sha256, up["sha256"].as_str().unwrap());
    }
}

#[test]
fn one_item_still_goes_through_the_same_path() {
    let c = cofre();
    let out = prepare_item_upsert(
        &c.owner.session_json(),
        &c.snap,
        "",
        Some(c.outro.to_string()),
        &serde_json::to_string(&ItemPayload::new_secret(
            "REDIS_URL",
            "redis://novo-ficticio",
        ))
        .unwrap(),
    )
    .unwrap();
    let body: serde_json::Value = serde_json::from_str(&out).unwrap();
    let ups = body["upserts"].as_array().unwrap();
    assert_eq!(ups.len(), 1);
    assert_eq!(ups[0]["version"], 2);
    let m = VaultManifest::parse_canonical(body["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(m.items.len(), 2);
}

#[test]
fn refuses_empty_too_many_repeated_or_malformed_lists() {
    let c = cofre();
    let sessao = c.owner.session_json();
    let erro = |itens: &str| prepare_items_upsert(&sessao, &c.snap, "", itens).unwrap_err();

    assert!(erro("[]").message().starts_with("[FORMAT]"));
    assert!(erro("{\"id\": null}").message().starts_with("[FORMAT]"));
    assert!(
        erro("[{\"id\": null}]").message().starts_with("[FORMAT]"),
        "sem payload"
    );

    let repetido = lista(&[
        (Some(c.existente), "DATABASE_URL", "a"),
        (Some(c.existente), "DATABASE_URL", "b"),
    ]);
    assert!(erro(&repetido).message().contains("twice"));

    let nomes: Vec<String> = (0..=MAX_ITEMS_PER_MUTATION)
        .map(|i| format!("VAR_{i}"))
        .collect();
    let muitos: Vec<(Option<Uuid>, &str, &str)> =
        nomes.iter().map(|n| (None, n.as_str(), "x")).collect();
    assert!(erro(&lista(&muitos)).message().starts_with("[FORMAT]"));
    assert!(
        prepare_items_upsert(
            &sessao,
            &c.snap,
            "",
            &lista(&muitos[..MAX_ITEMS_PER_MUTATION])
        )
        .is_ok()
    );
}
