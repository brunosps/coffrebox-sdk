# coffrebox

Zero-knowledge secrets for Rust apps. Your program reads its
[Coffrebox](https://github.com/brunosps/coffrebox-sdk) vault at startup; the server stores the
secrets but can never read them.

**Guide:** <https://coffrebox.net/docs/en/rust> (Portuguese: <https://coffrebox.net/docs/rust>).

> **Beta (0.x).** This SDK has not had an external security audit yet, and the API and on-disk
> formats may still change before 1.0. Pin the version you test with.

- Everything is verified and decrypted **in your process**: the server only sees ciphertext.
- Signed manifests and **rollback protection**: old, removed or injected secrets are refused.
- **Encrypted offline cache** shared with the npm SDK `@brunosps00/coffrebox`: your program still
  starts from the last snapshot when the server is down.
- No background traffic unless you turn on [`Watch`](https://docs.rs/coffrebox/latest/coffrebox/enum.Watch.html).
- Async (tokio) and blocking APIs. Values are `secrecy::SecretString`.

## Install

```toml
[dependencies]
coffrebox = "0.1"
```

Minimum Rust version: 1.89.

## Quickstart

Give the process two environment variables:

```sh
COFFREBOX_URL=https://vault.example.com
COFFREBOX_TOKEN=cfb1_app_...   # shown once when the application access is created
```

### Blocking (recommended for filling the environment)

```rust
fn main() -> Result<(), coffrebox::Error> {
    // First thing in main, before any thread exists.
    let vault = coffrebox::blocking::load()?;

    let db_url = std::env::var("DATABASE_URL").expect("loaded from Coffrebox");
    // Build your tokio runtime, start the server, ...
    drop((vault, db_url));
    Ok(())
}
```

### Async

```rust
use coffrebox::ExposeSecret;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), coffrebox::Error> {
    let vault = coffrebox::load().await?;
    let db_url = vault.get("DATABASE_URL").await?;
    println!("connecting to {} chars of DATABASE_URL", db_url.expose_secret().len());
    Ok(())
}
```

`load()` **fails closed**: it returns an error if the secrets cannot be loaded (server unreachable
and no valid cache, access revoked, tampered response), so the program does not start
half-configured.

> **Environment and threads.** Writing environment variables while other threads run is undefined
> behavior on several platforms (`std::env::set_var` is `unsafe` in Rust 2024). Call
> `blocking::load()` at the very start of `main`, or `load()` on a current-thread runtime before
> spawning threads. If you do not need the environment, use `Client::connect` and `get()`.

## Options

```rust
use std::time::Duration;
use coffrebox::{ClientConfig, OfflineMode, Watch};

let config = ClientConfig::from_env()?           // COFFREBOX_URL, COFFREBOX_TOKEN, COFFREBOX_CACHE_DIR
    .with_override_env(false)                    // keep variables that already exist (default)
    .with_watch(Watch::default_interval())       // poll every 5 minutes (default: Watch::Off)
    .with_ttl(Duration::from_secs(300))          // how long get() trusts the values in memory
    .with_max_stale(Duration::from_secs(72 * 3600)) // oldest disk cache accepted when offline
    .with_offline(OfflineMode::UseCache);        // or OfflineMode::Fail
let vault = coffrebox::load_with(config).await?;
```

`ClientConfig::new(url, token)` builds a configuration without reading `COFFREBOX_URL` and
`COFFREBOX_TOKEN`.

## Live updates (`Watch`)

With `Watch::Off` (the default) the vault is read once and there are **no background requests**;
`get()` refreshes on demand after `ttl`.

With `Watch::Every(interval)` (minimum 30 s) or `Watch::default_interval()` (5 minutes), the SDK
asks the server whether the vault changed:

- **Nothing changed:** `304 Not Modified`, no body, nothing decrypted.
- **Something changed:** the whole encrypted vault is sent (a few KB), verified, and compared
  locally. You get the exact names:

```rust
vault.on_change(|names| println!("changed: {names:?}"));

let mut changes = vault.subscribe(); // tokio broadcast receiver
while let Ok(names) = changes.recv().await { /* reconnect, ... */ }
```

`get()` returns the new values right away. Unlike the npm SDK, the Rust SDK **does not rewrite the
process environment after startup** (see the note on threads above): react to `on_change` and read
with `get()`.

Cost while `Watch` is on: about 12 checks per hour per process plus an access-token renewal every
15 minutes, roughly 20 small requests per hour.

## Errors

`coffrebox::Error` never contains secret values or tokens. `Error::code()` returns the same stable
codes as the npm SDK:

| Variant | `code()` | When |
|---|---|---|
| `NotFound { key }` | `COFFREBOX_NOT_FOUND` | `get()` of a secret that does not exist. |
| `Revoked` | `COFFREBOX_REVOKED` | The access was revoked (HTTP 401/403). The disk cache is wiped. |
| `Offline { detail }` | `COFFREBOX_OFFLINE` | Server unreachable and no usable cache (or `OfflineMode::Fail`). |
| `Tampered { reason }` | `COFFREBOX_TAMPERED` | A signature, integrity or rollback check failed. |
| `StaleCache` | `COFFREBOX_STALE_CACHE` | Server unreachable and the disk cache is older than `max_stale`. |
| `InvalidConfig(_)` | `COFFREBOX_INVALID_CONFIG` | Missing or invalid URL, token or option; cache I/O problem; client closed. |

## Two vaults in one process

Each access token opens exactly one vault. Create one client per token:

```rust
use coffrebox::{Client, ClientConfig};

let own = Client::connect(ClientConfig::new(&url, own_token)).await?;
let shared = Client::connect(ClientConfig::new(&url, shared_token)).await?;
```

## Security notes

- **The token is the key.** `COFFREBOX_TOKEN` contains the application's private keys: whoever has
  it can read that vault (only that vault, read-only). Store it like a password; revoke the access
  if a machine leaks.
- **Cache on disk is ciphertext only**, written atomically in
  `<cache_dir>/<app_id>/<vault_id>.snapshot` with mode `0600`.
- **Rollback protection**: a revision lower than one already seen (in memory or on disk) is refused.
- **Revocation**: on HTTP 401/403 the cache is wiped and `Error::Revoked` is returned.

## Examples

See [`examples/`](./examples): `blocking.rs`, `async_watch.rs` and `two_vaults.rs`.

## License

MIT
