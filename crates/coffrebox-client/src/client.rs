use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use coffrebox_core::app_token::AppCredentials;
use coffrebox_core::snapshot::{DecryptedSnapshot, EncryptedSnapshot, verify_and_decrypt_for_app};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock, broadcast};
use uuid::Uuid;

use crate::cache::{
    current_epoch_ms, read_latest_disk_snapshot, wipe_app_cache, write_disk_snapshot,
};
use crate::{ClientConfig, Error, OfflineMode};

type ChangeCallback = Box<dyn Fn(&[String]) + Send + Sync>;

#[derive(Deserialize)]
struct ChallengeResponse {
    nonce: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    vault_id: Uuid,
    expires_in: u64,
}

struct AccessSession {
    token: SecretString,
    vault_id: Uuid,
    expires_at: Instant,
}

struct MemoryState {
    highest_revision: Option<u64>,
    key_version: Option<u32>,
    secrets: BTreeMap<String, SecretString>,
    expires_at: Instant,
    cached_snapshot: Option<EncryptedSnapshot>,
}

struct Inner {
    http: reqwest::Client,
    base_url: String,
    creds: AppCredentials,
    app_cache_dir: PathBuf,
    ttl: Duration,
    max_stale: Duration,
    offline: OfflineMode,
    session: Mutex<Option<AccessSession>>,
    state: RwLock<MemoryState>,
    refresh_lock: Mutex<()>,
    listeners: StdMutex<Vec<ChangeCallback>>,
    changes: broadcast::Sender<Vec<String>>,
    watch_task: StdMutex<Option<tokio::task::AbortHandle>>,
    closed: AtomicBool,
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Ok(slot) = self.watch_task.get_mut()
            && let Some(task) = slot.take()
        {
            task.abort();
        }
    }
}

/// Asynchronous client (tokio). Cheap to clone: clones share the same state.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("coffrebox::Client")
            .field("base_url", &self.inner.base_url)
            .field("app_id", &self.inner.creds.app_id())
            .finish()
    }
}

fn validate_base_url(raw: &str) -> Result<String, Error> {
    let trimmed = raw.trim().trim_end_matches('/').to_string();
    if trimmed.is_empty() {
        return Err(Error::config("the server URL is empty"));
    }
    let parsed = reqwest::Url::parse(&trimmed)
        .map_err(|_| Error::config("COFFREBOX_URL is not a valid URL"))?;
    match parsed.scheme() {
        "https" => {}
        "http" => {
            let loopback = matches!(
                parsed.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
            );
            if !loopback {
                tracing::warn!(
                    "COFFREBOX_URL uses plain http:// outside localhost; use https:// in production"
                );
            }
        }
        _ => {
            return Err(Error::config(
                "COFFREBOX_URL must use https:// (or http:// for local development)",
            ));
        }
    }
    Ok(trimmed)
}

impl Client {
    /// Connects with `COFFREBOX_URL`, `COFFREBOX_TOKEN` and `COFFREBOX_CACHE_DIR`.
    pub async fn from_env() -> Result<Self, Error> {
        Self::connect(ClientConfig::from_env()?).await
    }

    /// Connects and loads the secrets into memory, without touching the process environment.
    ///
    /// Without [`crate::Watch`] there are no background requests; `get()` refreshes on demand
    /// after `ttl`.
    pub async fn connect(config: ClientConfig) -> Result<Self, Error> {
        let watch = config.watch.interval()?;
        let client = Self::connect_without_watch(&config).await?;
        if let Some(interval) = watch {
            client.start_watch(interval);
        }
        Ok(client)
    }

    pub(crate) async fn connect_without_watch(config: &ClientConfig) -> Result<Self, Error> {
        let base_url = validate_base_url(&config.url)?;
        let creds =
            AppCredentials::parse_token(config.token.expose_secret()).map_err(Error::from_token)?;

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| Error::config(format!("HTTP client setup failed: {e}")))?;

        let app_cache_dir = config.cache_dir.join(creds.app_id().to_string());

        // The highest revision already written to disk is enforced from the start (rollback protection).
        let (boot_highest_rev, boot_cached_snap) = match read_latest_disk_snapshot(&app_cache_dir)?
        {
            Some(env) => {
                let dec = verify_and_decrypt_for_app(&env.snapshot, &creds, None)?;
                (Some(dec.revision), Some(env.snapshot))
            }
            None => (None, None),
        };

        let (changes, _) = broadcast::channel(16);
        let client = Self {
            inner: Arc::new(Inner {
                http,
                base_url,
                creds,
                app_cache_dir,
                ttl: config.ttl,
                max_stale: config.max_stale,
                offline: config.offline,
                session: Mutex::new(None),
                state: RwLock::new(MemoryState {
                    highest_revision: boot_highest_rev,
                    key_version: None,
                    secrets: BTreeMap::new(),
                    expires_at: Instant::now(),
                    cached_snapshot: boot_cached_snap,
                }),
                refresh_lock: Mutex::new(()),
                listeners: StdMutex::new(Vec::new()),
                changes,
                watch_task: StdMutex::new(None),
                closed: AtomicBool::new(false),
            }),
        };
        client.refresh().await?;
        Ok(client)
    }

    /// Returns a secret, or [`Error::NotFound`].
    pub async fn get(&self, name: &str) -> Result<SecretString, Error> {
        self.ensure_fresh().await?;
        let guard = self.inner.state.read().await;
        guard
            .secrets
            .get(name)
            .cloned()
            .ok_or_else(|| Error::NotFound {
                key: name.to_string(),
            })
    }

    /// Returns a secret, or `None` when it does not exist.
    pub async fn get_optional(&self, name: &str) -> Result<Option<SecretString>, Error> {
        self.ensure_fresh().await?;
        let guard = self.inner.state.read().await;
        Ok(guard.secrets.get(name).cloned())
    }

    /// Returns every secret of the vault.
    pub async fn all(&self) -> Result<BTreeMap<String, SecretString>, Error> {
        self.ensure_fresh().await?;
        let guard = self.inner.state.read().await;
        Ok(guard.secrets.clone())
    }

    /// One-off copy of the current secrets into the process environment (`override = false`).
    ///
    /// # Call it before other threads exist
    ///
    /// Changing environment variables while other threads run is undefined behavior on several
    /// platforms (that is why `std::env::set_var` is `unsafe` in Rust 2024). Prefer
    /// [`crate::blocking::load`] at the very start of `main`, or pass values explicitly with
    /// [`Client::all`] (for example `std::process::Command::envs`).
    pub fn load_into_env(&self) -> Result<(), Error> {
        self.load_into_env_with_override(false)
    }

    /// Same as [`Client::load_into_env`], optionally replacing variables that already exist.
    pub fn load_into_env_with_override(&self, override_existing: bool) -> Result<(), Error> {
        let guard = self
            .inner
            .state
            .try_read()
            .map_err(|_| Error::config("the secrets are being refreshed; try again"))?;
        set_env_vars(&guard.secrets, override_existing);
        Ok(())
    }

    pub(crate) async fn write_env(&self, override_existing: bool) {
        let guard = self.inner.state.read().await;
        set_env_vars(&guard.secrets, override_existing);
    }

    /// Calls `callback` with the names of the secrets that changed (sorted).
    pub fn on_change<F>(&self, callback: F)
    where
        F: Fn(&[String]) + Send + Sync + 'static,
    {
        if let Ok(mut listeners) = self.inner.listeners.lock() {
            listeners.push(Box::new(callback));
        }
    }

    /// Receives the names of the secrets that changed. Lagging receivers skip old notifications.
    pub fn subscribe(&self) -> broadcast::Receiver<Vec<String>> {
        self.inner.changes.subscribe()
    }

    /// `true` while background polling is active.
    pub fn watching(&self) -> bool {
        self.inner
            .watch_task
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    /// Checks the server now (a `304 Not Modified` costs almost nothing).
    pub async fn refresh(&self) -> Result<(), Error> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::config("this Coffrebox client is closed"));
        }
        let _guard = self.inner.refresh_lock.lock().await;
        match self.try_online_refresh().await {
            Ok(()) => Ok(()),
            Err(Error::Revoked) => {
                wipe_app_cache(&self.inner.app_cache_dir);
                let mut st = self.inner.state.write().await;
                st.secrets.clear();
                st.cached_snapshot = None;
                *self.inner.session.lock().await = None;
                Err(Error::Revoked)
            }
            Err(Error::Offline { detail }) => self.fallback_offline(&detail).await,
            Err(other) => Err(other),
        }
    }

    /// Stops background polling and forgets the secrets kept in memory.
    pub async fn close(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        self.stop_watch();
        self.inner.state.write().await.secrets.clear();
        *self.inner.session.lock().await = None;
    }

    pub(crate) fn start_watch(&self, interval: Duration) {
        let weak = Arc::downgrade(&self.inner);
        let task = tokio::spawn(async move {
            let start = tokio::time::Instant::now() + interval;
            let mut ticker = tokio::time::interval_at(start, interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let Some(inner) = weak.upgrade() else { break };
                let client = Client { inner };
                if let Err(err) = client.refresh().await {
                    tracing::warn!(
                        error = %err,
                        "Coffrebox background check failed; keeping the last known secrets"
                    );
                }
            }
        });
        if let Ok(mut slot) = self.inner.watch_task.lock()
            && let Some(old) = slot.replace(task.abort_handle())
        {
            old.abort();
        }
    }

    fn stop_watch(&self) {
        if let Ok(mut slot) = self.inner.watch_task.lock()
            && let Some(task) = slot.take()
        {
            task.abort();
        }
    }

    async fn ensure_fresh(&self) -> Result<(), Error> {
        let expired = {
            let guard = self.inner.state.read().await;
            Instant::now() >= guard.expires_at || guard.secrets.is_empty()
        };
        if expired {
            self.refresh().await?;
        }
        Ok(())
    }

    async fn post(
        &self,
        url: String,
        body: serde_json::Value,
        what: &str,
    ) -> Result<reqwest::Response, Error> {
        let resp = self
            .inner
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                Error::offline(format!(
                    "could not reach the server ({what}): {}",
                    e.without_url()
                ))
            })?;
        match resp.status().as_u16() {
            200 => Ok(resp),
            401 | 403 => Err(Error::Revoked),
            code => Err(Error::offline(format!(
                "the server answered HTTP {code} ({what})"
            ))),
        }
    }

    async fn obtain_access_session(&self) -> Result<(SecretString, Uuid), Error> {
        {
            let guard = self.inner.session.lock().await;
            if let Some(ref s) = *guard
                && Instant::now() + Duration::from_secs(15) < s.expires_at
            {
                return Ok((s.token.clone(), s.vault_id));
            }
        }

        let ch_resp = self
            .post(
                format!("{}/api/v1/apps/auth/challenge", self.inner.base_url),
                serde_json::json!({ "app_id": self.inner.creds.app_id() }),
                "authentication challenge",
            )
            .await?;
        let ch_body: ChallengeResponse = ch_resp
            .json()
            .await
            .map_err(|_| Error::offline("invalid authentication challenge response"))?;
        let signature = self
            .inner
            .creds
            .sign_auth_challenge(&ch_body.nonce)
            .map_err(|_| Error::offline("invalid authentication challenge"))?;

        let tok_resp = self
            .post(
                format!("{}/api/v1/apps/auth/token", self.inner.base_url),
                serde_json::json!({
                    "app_id": self.inner.creds.app_id(),
                    "nonce": ch_body.nonce,
                    "signature": signature,
                }),
                "access token",
            )
            .await?;
        let tok_body: TokenResponse = tok_resp
            .json()
            .await
            .map_err(|_| Error::offline("invalid access token response"))?;

        let access = SecretString::from(tok_body.access_token);
        let ttl = Duration::from_secs(tok_body.expires_in.max(30));
        *self.inner.session.lock().await = Some(AccessSession {
            token: access.clone(),
            vault_id: tok_body.vault_id,
            expires_at: Instant::now() + ttl,
        });
        Ok((access, tok_body.vault_id))
    }

    async fn try_online_refresh(&self) -> Result<(), Error> {
        let (access_token, vault_id) = self.obtain_access_session().await?;

        let (min_rev, current_snap) = {
            let guard = self.inner.state.read().await;
            (guard.highest_revision, guard.cached_snapshot.clone())
        };

        let snap_url = format!("{}/api/v1/vaults/{vault_id}/snapshot", self.inner.base_url);
        let mut req = self
            .inner
            .http
            .get(&snap_url)
            .bearer_auth(access_token.expose_secret());
        if let (Some(rev), Some(_)) = (min_rev, &current_snap) {
            req = req.header("If-None-Match", format!("\"{rev}\""));
        }

        let resp = req.send().await.map_err(|e| {
            Error::offline(format!(
                "could not reach the server (snapshot): {}",
                e.without_url()
            ))
        })?;

        match resp.status().as_u16() {
            304 => {
                let Some(existing) = current_snap else {
                    return Err(Error::offline(
                        "the server answered 304 without a cached snapshot",
                    ));
                };
                let dec = verify_and_decrypt_for_app(&existing, &self.inner.creds, min_rev)?;
                write_disk_snapshot(&self.inner.app_cache_dir, vault_id, &existing)?;
                self.apply_decrypted(existing, dec).await;
                Ok(())
            }
            200 => {
                let wire_snap: EncryptedSnapshot = resp
                    .json()
                    .await
                    .map_err(|_| Error::tampered("the snapshot response is not valid JSON"))?;
                if wire_snap.vault_id != vault_id {
                    return Err(Error::tampered(
                        "the snapshot belongs to a different vault than the one authorized",
                    ));
                }
                let dec = verify_and_decrypt_for_app(&wire_snap, &self.inner.creds, min_rev)?;
                write_disk_snapshot(&self.inner.app_cache_dir, vault_id, &wire_snap)?;
                self.apply_decrypted(wire_snap, dec).await;
                Ok(())
            }
            401 | 403 => Err(Error::Revoked),
            code => Err(Error::offline(format!(
                "the server answered HTTP {code} (snapshot)"
            ))),
        }
    }

    async fn fallback_offline(&self, reason: &str) -> Result<(), Error> {
        if self.inner.offline == OfflineMode::Fail {
            return Err(Error::offline(reason));
        }

        let disk_env = read_latest_disk_snapshot(&self.inner.app_cache_dir)?.ok_or_else(|| {
            Error::offline(format!(
                "{reason}; there is no encrypted snapshot in the disk cache"
            ))
        })?;

        let age_ms = current_epoch_ms().saturating_sub(disk_env.fetched_at_ms);
        if Duration::from_millis(age_ms) > self.inner.max_stale {
            return Err(Error::StaleCache);
        }

        let min_rev = self.inner.state.read().await.highest_revision;
        let dec = verify_and_decrypt_for_app(&disk_env.snapshot, &self.inner.creds, min_rev)?;

        tracing::warn!(
            app_id = %self.inner.creds.app_id(),
            vault_id = %dec.vault_id,
            revision = dec.revision,
            age_ms = age_ms,
            "Coffrebox server unreachable; using the encrypted local cache"
        );

        self.apply_decrypted(disk_env.snapshot, dec).await;
        Ok(())
    }

    async fn apply_decrypted(&self, raw_snap: EncryptedSnapshot, dec: DecryptedSnapshot) {
        let mut next_map = BTreeMap::new();
        for item in dec.items {
            next_map.insert(
                item.payload.nome.clone(),
                SecretString::from(item.payload.valor.clone()),
            );
        }

        let changed: Vec<String> = {
            let mut st = self.inner.state.write().await;
            let mut changed = BTreeSet::new();
            if st.key_version.is_some() {
                for (k, v) in &next_map {
                    match st.secrets.get(k) {
                        Some(old) if old.expose_secret() == v.expose_secret() => {}
                        _ => {
                            changed.insert(k.clone());
                        }
                    }
                }
                for old_k in st.secrets.keys() {
                    if !next_map.contains_key(old_k) {
                        changed.insert(old_k.clone());
                    }
                }
                if st.key_version != Some(dec.key_version) && changed.is_empty() {
                    changed.extend(next_map.keys().cloned());
                }
            }
            st.highest_revision = Some(dec.revision);
            st.key_version = Some(dec.key_version);
            st.secrets = next_map;
            st.expires_at = Instant::now() + self.inner.ttl;
            st.cached_snapshot = Some(raw_snap);
            changed.into_iter().collect()
        };

        if changed.is_empty() {
            return;
        }
        let _ = self.inner.changes.send(changed.clone());
        if let Ok(listeners) = self.inner.listeners.lock() {
            for cb in listeners.iter() {
                cb(&changed);
            }
        }
    }
}

fn set_env_vars(secrets: &BTreeMap<String, SecretString>, override_existing: bool) {
    for (k, v) in secrets {
        if override_existing || std::env::var_os(k).is_none() {
            // SAFETY: documented contract of `load`/`load_into_env`: call it before other threads
            // read or write the environment.
            #[allow(unsafe_code)]
            unsafe {
                std::env::set_var(k, v.expose_secret());
            }
        }
    }
}
