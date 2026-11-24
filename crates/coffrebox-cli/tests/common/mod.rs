//! Servidor malicioso simulado para testar a CLI `coffre` sem Docker.
//!
//! O servidor responde com JSON montado pelo próprio teste (snapshots forjados com a chave de um
//! atacante, listas de membros adulteradas, revisões antigas) e grava cada requisição recebida, para
//! que o teste confira o que a CLI aceitou e o que ela enviou.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use coffrebox_core::encoding::{b64url_encode, random_uuid_v4};
use coffrebox_core::item::{ItemPayload, encrypt_item};
use coffrebox_core::keys::UserKeyset;
use coffrebox_core::manifest::{
    ManifestItemEntry, MemberRoster, RosterApp, RosterMember, VaultManifest, VaultRole,
};
use coffrebox_core::snapshot::{EncryptedItemWire, EncryptedSnapshot, SnapshotRecipientEnvelope};
use coffrebox_core::vault::{
    RecipientKind, VaultKey, VaultMeta, encrypt_vault_meta, seal_vault_key,
};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Captured {
    pub method: String,
    pub path: String,
    pub body: Value,
}

#[derive(Default)]
struct FakeState {
    routes: HashMap<(String, String), (u16, Value)>,
    captured: Vec<Captured>,
}

type Shared = Arc<Mutex<FakeState>>;

pub struct FakeServer {
    pub url: String,
    state: Shared,
}

impl FakeServer {
    pub async fn start() -> Self {
        let state: Shared = Arc::default();
        let app = Router::new().fallback(handle).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            url: format!("http://{addr}"),
            state,
        }
    }

    /// Define a resposta para `METHOD path` (a query string é ignorada).
    pub fn route(&self, method: &str, path: &str, status: u16, body: Value) {
        self.state
            .lock()
            .unwrap()
            .routes
            .insert((method.to_string(), path.to_string()), (status, body));
    }

    pub fn captured(&self) -> Vec<Captured> {
        self.state.lock().unwrap().captured.clone()
    }

    pub fn posts_to(&self, path: &str) -> Vec<Value> {
        self.captured()
            .into_iter()
            .filter(|c| c.method == "POST" && c.path == path)
            .map(|c| c.body)
            .collect()
    }
}

async fn handle(State(state): State<Shared>, method: Method, uri: Uri, body: Bytes) -> Response {
    let path = uri.path().to_string();
    let body_json = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let mut guard = state.lock().unwrap();
    guard.captured.push(Captured {
        method: method.to_string(),
        path: path.clone(),
        body: body_json,
    });
    match guard.routes.get(&(method.to_string(), path)) {
        Some((status, value)) => (
            StatusCode::from_u16(*status).unwrap(),
            axum::Json(value.clone()),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            axum::Json(json!({ "error": { "message": "rota não simulada" } })),
        )
            .into_response(),
    }
}

/// Pessoa com par de chaves gerado localmente pelo teste.
pub struct Persona {
    pub id: Uuid,
    pub email: String,
    pub keys: UserKeyset,
}

impl Persona {
    pub fn new(email: &str) -> Self {
        Self {
            id: random_uuid_v4().unwrap(),
            email: email.to_string(),
            keys: UserKeyset::generate().unwrap(),
        }
    }

    pub fn roster_entry(&self, role: VaultRole) -> RosterMember {
        RosterMember {
            enc_pub: self.keys.enc_public_envelope(),
            role,
            sign_pub: self.keys.sign_public_envelope(),
            user_id: self.id,
        }
    }

    pub fn lookup_json(&self) -> Value {
        json!({
            "user_id": self.id,
            "email": self.email,
            "enc_public_key": self.keys.enc_public_envelope(),
            "sign_public_key": self.keys.sign_public_envelope(),
            "fingerprint": self.keys.fingerprint(),
        })
    }
}

/// Grava o arquivo de sessão da CLI (o mesmo formato de `store::StoredCliSession`).
pub fn write_session(path: &Path, server_url: &str, who: &Persona) {
    let sess = json!({
        "server_url": server_url,
        "email": who.email,
        "user_id": who.id,
        "access_token": "cfb1_sess_ficticio",
        "enc_sk_b64": b64url_encode(who.keys.enc_secret_bytes()),
        "sign_seed_b64": b64url_encode(who.keys.sign_seed_bytes()),
        "fingerprint": who.keys.fingerprint(),
    });
    std::fs::write(path, serde_json::to_vec(&sess).unwrap()).unwrap();
}

pub fn temp_dir(prefix: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("{prefix}-{}", random_uuid_v4().unwrap()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub struct CliRun {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Executa o binário `coffre` com a sessão indicada; `home` isola config e estado local.
pub async fn coffre(args: &[&str], stdin: Option<&str>, session: &Path, home: &Path) -> CliRun {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;

    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_coffre"));
    cmd.args(args)
        .env("COFFREBOX_NO_KEYRING", "1")
        .env("COFFREBOX_SESSION_FILE", session)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env_remove("COFFREBOX_TOKEN")
        .env_remove("COFFREBOX_URL")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    if let Some(input) = stdin {
        let mut cin = child.stdin.take().unwrap();
        cin.write_all(input.as_bytes()).await.unwrap();
        drop(cin);
    }
    let out = child.wait_with_output().await.unwrap();
    CliRun {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

/// Descrição de um snapshot (legítimo ou forjado) entregue pelo servidor simulado.
pub struct SnapSpec<'a> {
    pub vault_id: Uuid,
    pub owner_user_id: Uuid,
    /// Chave que vai em `owner_sign_public_key` e assina a lista de membros.
    pub owner_signer: &'a UserKeyset,
    /// `None` gera snapshot sem `member_roster`.
    pub roster: Option<Vec<RosterMember>>,
    pub roster_version: u32,
    /// Aplicações na lista assinada (só vale quando `roster` é `Some`).
    pub roster_apps: Vec<RosterApp>,
    pub writer: (Uuid, &'a UserKeyset),
    pub grantor: (Uuid, &'a UserKeyset),
    pub recipient: (Uuid, &'a UserKeyset),
    pub vk: &'a VaultKey,
    pub key_version: u32,
    pub revision: u64,
    pub items: Vec<(Uuid, u32, &'a str, &'a str)>,
}

impl SnapSpec<'_> {
    pub fn build(&self) -> EncryptedSnapshot {
        let (encrypted_meta, meta_sha) = encrypt_vault_meta(
            self.vk,
            self.vault_id,
            self.key_version,
            &VaultMeta::new("equipe"),
        )
        .unwrap();

        let mut wire_items = Vec::new();
        let mut entries = Vec::new();
        for (id, version, nome, valor) in &self.items {
            let (ct, sha) = encrypt_item(
                self.vk,
                self.vault_id,
                *id,
                *version,
                self.key_version,
                &ItemPayload::new_secret(*nome, *valor),
            )
            .unwrap();
            wire_items.push(EncryptedItemWire {
                id: *id,
                version: *version,
                key_version: self.key_version,
                ciphertext: ct,
                sha256: sha.clone(),
            });
            entries.push(ManifestItemEntry {
                id: *id,
                sha256: sha,
                version: *version,
            });
        }
        wire_items.sort_by_key(|i| i.id.as_hyphenated().to_string());

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
            Some(members) => {
                let roster = MemberRoster::new_with_apps(
                    self.vault_id,
                    self.roster_version,
                    members.clone(),
                    self.roster_apps.clone(),
                )
                .unwrap();
                let (rj, rs) = roster.sign(self.owner_signer).unwrap();
                (Some(rj), Some(rs))
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
            items: wire_items,
        }
    }

    pub fn json(&self) -> Value {
        serde_json::to_value(self.build()).unwrap()
    }
}

pub fn snapshot_path(vault_id: Uuid) -> String {
    format!("/api/v1/vaults/{vault_id}/snapshot")
}

pub fn new_id() -> Uuid {
    random_uuid_v4().unwrap()
}
