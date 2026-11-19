# coffrebox-core

Cryptography and formats of [Coffrebox](https://github.com/brunosps/coffrebox-sdk), a
zero-knowledge secrets vault. No I/O; compiles to `wasm32`.

> **Beta (0.x).** Not externally audited yet; formats may change before 1.0.

Most users want the SDKs instead:

- Rust: [`coffrebox`](https://crates.io/crates/coffrebox)
- Node.js: [`@brunosps00/coffrebox`](https://www.npmjs.com/package/@brunosps00/coffrebox)

This crate holds what both SDKs share: application tokens (`cfb1_app_…`, with a CRC32 against
copy errors), HPKE sealing of vault keys (RFC 9180, X25519 + ChaCha20-Poly1305), XChaCha20-Poly1305
items with full associated data, Ed25519-signed canonical manifests and member rosters, and the
verification of a vault snapshot (signatures, item set, revision floor) before anything is
decrypted.

Only maintained primitives are used (`hpke`, `chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`,
`argon2`, `hkdf`, `sha2`); secrets are zeroized and never printed by `Debug`.

## License

MIT
