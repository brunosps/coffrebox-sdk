//! Shared helpers: fictitious vaults built with `coffrebox-core` and a fake Coffrebox server.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use coffrebox_core::app_token::AppCredentials;
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
use uuid::Uuid;

pub const DB_V1: &str = "postgres://fictitious:v1@db.internal/app";
pub const DB_V2: &str = "postgres://fictitious:v2@db.internal/app";
pub const REDIS: &str = "redis://fictitious@cache.internal:6379/0";
pub const API_KEY: &str = "fictitious-api-key-0001";

/// One application with access to one vault.
pub struct Scenario {
    owner_id: Uuid,
    owner: UserKeyset,
    pub vault_id: Uuid,
    vk: VaultKey,
    pub creds: AppCredentials,
    db: Uuid,
    redis: Uuid,
}

impl Scenario {
    pub fn new() -> Self {
        let owner = UserKeyset::generate().unwrap();
        let app_id = random_uuid_v4().unwrap();
        Self {
            owner_id: random_uuid_v4().unwrap(),
            creds: AppCredentials::generate(app_id, owner.sign_public_bytes()).unwrap(),
            owner,
            vault_id: random_uuid_v4().unwrap(),
            vk: VaultKey::generate().unwrap(),
            db: random_uuid_v4().unwrap(),
            redis: random_uuid_v4().unwrap(),
        }
    }

    pub fn token(&self) -> String {
        self.creds.to_token().to_string()
    }

    pub fn app_id(&self) -> Uuid {
        self.creds.app_id()
    }

    /// rev2: DATABASE_URL v1 · rev3: DATABASE_URL v2 · rev4: + REDIS_URL · rev5: only REDIS_URL.
    pub fn rev(&self, revision: u64) -> EncryptedSnapshot {
        let items: Vec<(Uuid, u32, &str, &str)> = match revision {
            2 => vec![(self.db, 1, "DATABASE_URL", DB_V1)],
            3 => vec![(self.db, 2, "DATABASE_URL", DB_V2)],
            4 => vec![
                (self.db, 2, "DATABASE_URL", DB_V2),
                (self.redis, 1, "REDIS_URL", REDIS),
            ],
            5 => vec![(self.redis, 1, "REDIS_URL", REDIS)],
            other => panic!("no fixture for revision {other}"),
        };
        self.snapshot(revision, &items)
    }

    /// A snapshot with an item the signed manifest does not list.
    pub fn injected(&self) -> EncryptedSnapshot {
        let mut snap = self.rev(3);
        let mut extra = snap.items[0].clone();
        extra.id = random_uuid_v4().unwrap();
        snap.items.push(extra);
        snap
    }

    pub fn snapshot(&self, revision: u64, items: &[(Uuid, u32, &str, &str)]) -> EncryptedSnapshot {
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

#[derive(Default)]
pub struct ServerState {
    /// app_id -> (vault_id, snapshot served).
    apps: HashMap<Uuid, (Uuid, EncryptedSnapshot)>,
    revoked: bool,
    down: bool,
    snapshot_requests: u32,
    not_modified: u32,
}

/// Fake server: accepts any challenge signature and serves the configured snapshots.
#[derive(Clone)]
pub struct FakeServer {
    pub url: String,
    state: Arc<Mutex<ServerState>>,
}

fn revision_of(snap: &EncryptedSnapshot) -> u64 {
    let manifest: serde_json::Value = serde_json::from_str(&snap.manifest).unwrap();
    manifest["revision"].as_u64().unwrap()
}

type Shared = Arc<Mutex<ServerState>>;

async fn challenge(State(st): State<Shared>) -> Response {
    let st = st.lock().unwrap();
    if st.down {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if st.revoked {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(serde_json::json!({ "nonce": b64url_encode(&[7u8; 32]) })).into_response()
}

async fn token(State(st): State<Shared>, Json(body): Json<serde_json::Value>) -> Response {
    let st = st.lock().unwrap();
    if st.down {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let app_id: Uuid = body["app_id"].as_str().unwrap().parse().unwrap();
    match (st.revoked, st.apps.get(&app_id)) {
        (false, Some((vault_id, _))) => Json(serde_json::json!({
            "access_token": format!("cfb1_at_{app_id}"),
            "vault_id": vault_id,
            "expires_in": 900,
        }))
        .into_response(),
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
}

async fn snapshot(
    State(st): State<Shared>,
    Path(vault_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    let mut st = st.lock().unwrap();
    if st.down {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if st.revoked {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(snap) = st
        .apps
        .values()
        .find(|(v, _)| *v == vault_id)
        .map(|(_, s)| s.clone())
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    st.snapshot_requests += 1;
    let etag = format!("\"{}\"", revision_of(&snap));
    if headers.get("if-none-match").and_then(|v| v.to_str().ok()) == Some(etag.as_str()) {
        st.not_modified += 1;
        return StatusCode::NOT_MODIFIED.into_response();
    }
    Json(snap).into_response()
}

impl FakeServer {
    fn router(state: Shared) -> Router {
        Router::new()
            .route("/api/v1/apps/auth/challenge", post(challenge))
            .route("/api/v1/apps/auth/token", post(token))
            .route("/api/v1/vaults/{vault_id}/snapshot", get(snapshot))
            .with_state(state)
    }

    /// Starts on the current tokio runtime.
    pub async fn start() -> Self {
        let state: Shared = Arc::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = Self::router(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { url, state }
    }

    /// Starts on a dedicated thread with its own runtime (for the blocking API tests).
    pub fn start_in_thread() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let server = FakeServer::start().await;
                tx.send(server).unwrap();
                std::future::pending::<()>().await;
            });
        });
        rx.recv().unwrap()
    }

    pub fn serve(&self, scenario: &Scenario, snap: EncryptedSnapshot) {
        self.state
            .lock()
            .unwrap()
            .apps
            .insert(scenario.app_id(), (scenario.vault_id, snap));
    }

    pub fn set_revoked(&self, revoked: bool) {
        self.state.lock().unwrap().revoked = revoked;
    }

    pub fn set_down(&self, down: bool) {
        self.state.lock().unwrap().down = down;
    }

    pub fn snapshot_requests(&self) -> u32 {
        self.state.lock().unwrap().snapshot_requests
    }

    pub fn not_modified(&self) -> u32 {
        self.state.lock().unwrap().not_modified
    }
}

pub fn temp_cache_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cfb-sdk-rs-{tag}-{}", random_uuid_v4().unwrap()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Polls `cond` for up to 10 seconds.
pub async fn eventually(mut cond: impl FnMut() -> bool) {
    for _ in 0..200 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("condition not reached within 10 seconds");
}

/// Blocking version of [`eventually`].
pub fn eventually_blocking(mut cond: impl FnMut() -> bool) {
    for _ in 0..200 {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("condition not reached within 10 seconds");
}
