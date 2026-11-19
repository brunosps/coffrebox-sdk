# Coffrebox SDKs

Open-source part of [Coffrebox](https://github.com/brunosps/coffrebox-sdk), a zero-knowledge
secrets vault: the server stores your secrets but can never read them. Applications read their
vault with an access token; everything is verified and decrypted locally.

> **Beta (0.x).** Not externally audited yet. The API and the on-disk formats may still change
> before 1.0.

| Package | Where | What |
|---|---|---|
| [`@brunosps00/coffrebox`](packages/sdk-ts) | npm | Node.js 20+ SDK: `await Coffrebox.load()` fills `process.env`. |
| [`coffrebox`](crates/coffrebox-client) | crates.io | Rust SDK (async and blocking). |
| [`coffrebox-core`](crates/coffrebox-core) | crates.io | Cryptography and formats shared by both SDKs. |
| [`coffrebox-wasm`](crates/coffrebox-wasm) | — | WebAssembly bindings bundled inside the npm package. |

Both SDKs read and write the same encrypted cache format, verify the same signatures and refuse
rollbacks the same way: the crypto exists once, in Rust, and the npm package runs it as
WebAssembly.

## Quickstart

```js
// Node.js
import { Coffrebox } from "@brunosps00/coffrebox";
const vault = await Coffrebox.load(); // COFFREBOX_URL + COFFREBOX_TOKEN
```

```rust
// Rust
let vault = coffrebox::blocking::load()?; // first thing in main
```

## Building from source

```sh
cargo test --workspace

# npm package (needs wasm-pack)
cd packages/sdk-ts
npm ci
npm run build:wasm
npm run build
npm test
```

## Security

The cryptographic design and the threat model — what Coffrebox protects against and what it
does not — are specified in [docs/CRYPTO.md](docs/CRYPTO.md).

Please report vulnerabilities privately through GitHub security advisories on this repository
rather than in public issues.

## License

MIT
