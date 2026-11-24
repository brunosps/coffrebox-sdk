# @brunosps00/coffrebox

Zero-knowledge secrets for Node.js apps. Your app loads its [Coffrebox](https://github.com/brunosps/coffrebox-sdk)
vault into `process.env` at startup; the server stores the secrets but can never read them.

**Guide:** <https://coffrebox.net/docs/en/node> (Portuguese: <https://coffrebox.net/docs/node>).

> **Beta (0.x).** This SDK has not had an external security audit yet, and the API and on-disk
> formats may still change before 1.0. Pin the version you test with.

- Everything is verified and decrypted **in your process**: the server only sees ciphertext.
- Signed manifests and **rollback protection**: a server that tries to serve an old, removed or
  injected secret is detected and refused.
- **Encrypted offline cache**: if the server is down, your app still starts from the last
  snapshot (encrypted on disk, never plaintext).
- No background traffic unless you ask for live updates (`watch`).
- Node.js 20+, ESM and CommonJS, TypeScript types included, no native dependencies (the crypto
  core ships as WebAssembly).

## Install

```sh
npm install @brunosps00/coffrebox
```

## Quickstart

Create an application access in your Coffrebox vault and give the process two environment
variables:

```sh
COFFREBOX_URL=https://vault.example.com
COFFREBOX_TOKEN=cfb1_app_...   # shown once when the access is created
```

Load the secrets explicitly, at the top of your entry point, before the rest of the app:

```js
import { Coffrebox } from "@brunosps00/coffrebox";

const vault = await Coffrebox.load();

// process.env.DATABASE_URL is now set
startServer();
```

`load()` **fails closed**: if the secrets cannot be loaded (server unreachable and no valid cache,
access revoked, tampered response) it throws, so your app does not start half-configured.

Nothing happens on `import`: the SDK only talks to the server when you call `load()` or
`connect()`.

### CommonJS

```js
const { Coffrebox } = require("@brunosps00/coffrebox");

async function main() {
  await Coffrebox.load();
  require("./server").start();
}
main();
```

## Options

```js
const vault = await Coffrebox.load({
  override: false,       // keep variables that already exist in process.env (default)
  watch: false,          // live updates, see below (default: off)
  url: "https://...",    // default: COFFREBOX_URL
  token: "cfb1_app_...", // default: COFFREBOX_TOKEN
  cacheDir: "/var/cache/my-app", // default: COFFREBOX_CACHE_DIR, then ~/.cache/coffrebox
  ttlMs: 5 * 60_000,     // how long get() trusts the values in memory
  maxStaleMs: 72 * 3_600_000, // oldest disk cache accepted when the server is down
  offline: "use-cache",  // or "fail": never start from the disk cache
  warn: (msg) => logger.warn(msg), // default: console.warn
});
```

| Option | Default | Meaning |
|---|---|---|
| `override` | `false` | When a variable already exists in `process.env`: `false` keeps it, `true` replaces it with the vault value. |
| `watch` | off | `true` or `{ intervalMs }`: poll the vault and keep `process.env` up to date. Minimum interval: 30 s. |
| `url` / `token` | env vars | Server URL and application token. |
| `cacheDir` | `COFFREBOX_CACHE_DIR` | Where the encrypted snapshot is cached (folder `0700`, file `0600`). |
| `ttlMs` | 5 min | After this, `get()` checks the server again on demand. |
| `maxStaleMs` | 72 h | With the server down, a disk cache older than this is refused. |
| `offline` | `"use-cache"` | `"fail"` makes an unreachable server an error even if a cache exists. |

## Live updates (`watch`)

With `watch` off (the default), `load()` reads the vault once and makes **no further requests in
the background**. Restart the app to pick up new values.

With `watch` on, the SDK asks the server every interval (default 5 minutes) whether the vault
changed:

```js
const vault = await Coffrebox.load({ watch: true }); // or { watch: { intervalMs: 60_000 } }

vault.onChange((names) => {
  console.log("changed:", names); // e.g. ["DATABASE_URL"]
  // reconnect your database pool, etc.
});
```

- **Nothing changed:** the server answers `304 Not Modified` with no body. Nothing is downloaded
  or decrypted.
- **Something changed:** the server sends the whole encrypted vault (a few KB for dozens of
  secrets). The signature covers the whole set, which is what stops a server from hiding or
  swapping a single item. The SDK compares old and new values locally and calls `onChange` with
  the exact names. The server cannot tell you which name changed: names are encrypted too.
- `process.env` is updated only for variables the SDK set itself. A variable you defined before
  `load()` is never touched (unless `override: true`). If a secret is removed from the vault, the
  SDK removes it from `process.env` (or restores the value it replaced).
- Code that already read `process.env.X` keeps the old value: use `onChange` to react.
- If a background check fails, the last known values stay in place and `warn` is called.

**Cost:** about 12 checks per hour per process, plus an access-token renewal every 15 minutes
(2 small requests). That is roughly 20 small requests per hour per running process, only while
`watch` is on.

## Reading values

```js
const vault = await Coffrebox.connect(); // like load(), but does not touch process.env

await vault.get("DATABASE_URL");          // throws NotFoundError if missing
await vault.getOptional("SENTRY_DSN");    // undefined if missing
await vault.all();                        // { NAME: value, ... }
await vault.loadIntoEnv({ override: false }); // one-off copy into process.env
await vault.refresh();                    // check the server now
const off = vault.onChange((names) => {}); // returns an unsubscribe function
await vault.close();                      // stop polling, forget the values in memory
```

## Errors

Every error extends `CoffreboxError` and has a stable `code`. Messages never include secret
values or tokens.

| Class | `code` | When |
|---|---|---|
| `NotFoundError` | `COFFREBOX_NOT_FOUND` | `get()` of a secret that does not exist. |
| `RevokedError` | `COFFREBOX_REVOKED` | The access was revoked (HTTP 401/403). The disk cache is wiped. |
| `OfflineError` | `COFFREBOX_OFFLINE` | Server unreachable and no usable cache (or `offline: "fail"`). |
| `TamperedError` | `COFFREBOX_TAMPERED` | A signature, integrity or rollback check failed. Nothing from that response is used. |
| `StaleCacheError` | `COFFREBOX_STALE_CACHE` | Server unreachable and the disk cache is older than `maxStaleMs`. |
| `ConfigError` | `COFFREBOX_INVALID_CONFIG` | Missing or invalid URL, token or option, or the client was closed. |

```js
import { Coffrebox, CoffreboxError } from "@brunosps00/coffrebox";

try {
  await Coffrebox.load();
} catch (err) {
  if (err instanceof CoffreboxError) console.error(err.code, err.message);
  process.exit(1);
}
```

## Two vaults in one process

Each access token reads exactly one vault. To read two, create two clients with explicit options
(the cache keeps them apart):

```js
const own = await Coffrebox.connect({ url, token: process.env.COFFREBOX_TOKEN });
const shared = await Coffrebox.connect({ url, token: process.env.SHARED_COFFREBOX_TOKEN });

const dbUrl = await own.get("DATABASE_URL");
const apiKey = await shared.get("PAYMENTS_API_KEY");
```

## Security notes

- **The token is the key.** `COFFREBOX_TOKEN` contains the application's private keys: whoever has
  it can read that vault (and only that vault, read-only). Store it like a password and revoke
  the access if a machine leaks.
- **Cache on disk is ciphertext only**: the snapshot exactly as the server sent it, in
  `<cacheDir>/<app_id>/<vault_id>.snapshot`, written atomically with mode `0600`.
- **Rollback protection**: a snapshot with a revision lower than one already seen (in memory or on
  disk) is refused, so a server cannot bring back an old secret.
- **Revocation**: on HTTP 401/403 the SDK wipes the cache and throws `RevokedError`.
- Use `https://` in production; the SDK warns about plain `http://` outside localhost.

## Examples

See [`examples/`](./examples): a plain script, an Express server with `watch`, and two vaults in
one process.

## License

MIT
