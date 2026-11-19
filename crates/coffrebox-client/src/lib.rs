#![deny(unsafe_code)]
//! Official Rust SDK for [Coffrebox](https://github.com/brunosps/coffrebox-sdk), a zero-knowledge
//! secrets vault: the server stores your secrets but can never read them.
//!
//! **Beta (0.x):** not externally audited yet; formats and API may change before 1.0.
//!
//! An application reads its vault with an access token (`COFFREBOX_TOKEN`). Everything is
//! verified and decrypted locally; the server only ever sees ciphertext. Values are cached on disk
//! as the encrypted snapshot, so the app still starts when the server is down.
//!
//! ```no_run
//! # async fn run() -> Result<(), coffrebox::Error> {
//! // Reads COFFREBOX_URL and COFFREBOX_TOKEN, fills the environment, fails if it cannot.
//! let vault = coffrebox::load().await?;
//! let db = vault.get("DATABASE_URL").await?;
//! # let _ = db;
//! # Ok(()) }
//! ```
//!
//! Programs without tokio use [`blocking`]. The on-disk cache format is shared with the npm SDK
//! `@brunosps00/coffrebox`: one can read what the other wrote.

mod cache;
mod client;
mod config;
mod error;

pub mod blocking;

pub use cache::DiskSnapshotEnvelope;
pub use client::Client;
pub use config::{
    ClientConfig, DEFAULT_MAX_STALE, DEFAULT_TTL, DEFAULT_WATCH_INTERVAL, MIN_WATCH_INTERVAL,
    OfflineMode, Watch, default_cache_dir,
};
pub use error::Error;
pub use secrecy::{ExposeSecret, SecretString};

/// Version of the snapshot and token formats this SDK reads.
pub const FORMAT_VERSION: u32 = coffrebox_core::FORMAT_VERSION;

/// Reads `COFFREBOX_URL`, `COFFREBOX_TOKEN` and `COFFREBOX_CACHE_DIR`, fills the process
/// environment with the vault secrets (existing variables are kept) and returns the client.
///
/// Fails closed: it returns an error if the secrets cannot be loaded (server down without a valid
/// cache, revoked access, tampered snapshot), so the program does not start half-configured.
///
/// # Environment and threads
///
/// Writing environment variables while other threads run is undefined behavior on several
/// platforms. Call it before spawning threads: in `#[tokio::main(flavor = "current_thread")]`,
/// or use [`blocking::load`] at the very start of `main` and build your runtime afterwards. With
/// [`Watch`] on, later changes are reported through [`Client::on_change`] /
/// [`Client::subscribe`] and returned by [`Client::get`], but the environment is not rewritten.
pub async fn load() -> Result<Client, Error> {
    load_with(ClientConfig::from_env()?).await
}

/// [`load`] with explicit options (`override_env`, `watch`, …).
pub async fn load_with(config: ClientConfig) -> Result<Client, Error> {
    let watch = config.watch.interval()?;
    let client = Client::connect_without_watch(&config).await?;
    client.write_env(config.override_env).await;
    if let Some(interval) = watch {
        client.start_watch(interval);
    }
    Ok(client)
}
