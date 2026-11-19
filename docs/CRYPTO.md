# Cryptographic Specification and Threat Model (`CRYPTO.md`)

> **Status:** normative contract (v1). Every implementation — `coffrebox-core`, `coffrebox-wasm`,
> the Rust SDK (`coffrebox`), the npm SDK (`@brunosps00/coffrebox`), and the Coffrebox server and
> person-facing clients (CLI and web vault) — **must** follow exactly the formats, derivation
> domains and invariants described here.
>
> The server and the person-facing clients are not part of this repository. They are described
> here because the SDKs verify what they produce.

---

## 1. Non-negotiable rules

1. **No home-made cryptography.** Only standard primitives from maintained crates:
   - `hpke` (RFC 9180)
   - `chacha20poly1305` (`XChaCha20Poly1305` for symmetric AEAD; `ChaCha20Poly1305` inside the
     HPKE suite)
   - `ed25519-dalek` (Ed25519 signatures, verified with `verify_strict`)
   - `x25519-dalek` (Diffie-Hellman key agreement over Curve25519)
   - `argon2` (`Argon2id`, version `0x13`)
   - `hkdf` and `sha2` (`Hkdf<Sha256>`, `Sha256`)
   - `getrandom` (the operating system CSPRNG, and `crypto.getRandomValues` on `wasm32`)
   - `zeroize` (`Zeroize` and `ZeroizeOnDrop` on every key, seed, password and decrypted buffer)
   - `subtle` (`ConstantTimeEq` for constant-time comparison)
2. **The cryptography exists once, in Rust (`coffrebox-core`).** The browser and the TypeScript
   SDK run the same code compiled to WebAssembly (`coffrebox-wasm`). TypeScript never
   reimplements primitives or envelope parsers.
3. **Explicit versioning everywhere.** Every text envelope starts with the prefix `cfb1.` (or
   `cfb1_app_` / `cfb1_at_` / `cfb1_ust_` for credentials), and every encrypted or signed JSON
   structure carries `"v": 1`.
4. **Secrets stay out of logs, errors and `Debug`.** No type that holds a master password, account
   secret, authenticator secret or code, recovery code, private key, vault key, token or item
   value may implement `Display` with the real content, and its `Debug` must print
   `"[REDACTED]"`.

---

## 2. Threat model

Coffrebox is a **zero-knowledge** vault. This section states plainly what the system guarantees
and where its guarantees end.

### 2.1 What Coffrebox PROTECTS against

| Attack | How Coffrebox protects |
|---|---|
| **Compromised server (disk, memory or internal traffic read)** | The server never receives the master password, the private keys of people or applications, vault keys (VK) in clear, vault names, item names or secret values. Everything arrives and stays end-to-end encrypted. What the server keeps that helps an attacker is each account's secret, used to check the password (§4.1); see the "whole server compromised" limit in §2.2. |
| **Database stolen without the server keys (`pg_dump`, leaked backup, disk snapshot, SQL injection)** | An attacker with the full dump **cannot test password guesses offline**: the verifier is `Argon2id(HMAC(account_secret, auth_key))`, and the keyset sits inside an envelope keyed by the same secret, which only opens with the server's account key (kept outside the database and its backups). Authenticator secrets are sealed with a separate server key, and recovery codes only exist as HMACs. See §4.1 and §4.5. |
| **Leaked master password (phishing, reuse, shoulder surfing)** | The authenticator app is mandatory: without its code (or a single-use recovery code) the right password neither opens a session nor returns the keyset. |
| **Malicious server moving items between places or versions** | Every XChaCha20-Poly1305 ciphertext binds `vault_id`, `item_id`, `item_version` and `key_version` in the **AAD**. Moving a ciphertext to another item, vault or version breaks the Poly1305 tag. |
| **Malicious server injecting, hiding or rolling back items (CLI and SDKs)** | Every write produces a **canonical manifest** with a monotonic `revision`, the `key_version` and the `SHA-256` of each encrypted item, signed with Ed25519 by an authorized member. The SDKs, the CLI and the web vault refuse any item outside the signed manifest. The SDKs refuse a `revision` lower than the one already stored in the local cache; the CLI and the web vault keep, per vault, the highest `revision`, `roster_version` and `key_version` seen (including their own writes) and refuse lower values (*rollback* protection, §5.6). |
| **Malicious server swapping the VK envelope for one keyed by the attacker** | The HPKE envelope of the VK comes with an Ed25519 signature from whoever granted the access, checked against an anchor that **never comes from the server**: the `owner_sign_pk` embedded in the application token, the person's own key (own vault) or the owner's key pinned on first use (shared vault). See §5.6. |
| **Malicious server swapping a vault owner's key** | The CLI and the web vault keep, per `vault_id`, the owner key seen on first use and refuse any change until the person checks the new fingerprint through another channel. See §5.6. |
| **Authorization bug in the API between applications** | Isolation between applications is **cryptographic**, not only logical: the VK of vault B is sealed with HPKE only to the public keys of that vault's members and applications. Even if a server bug handed vault B's snapshot to application A, application A has no X25519 private key able to open the envelope. |

### 2.2 What Coffrebox does NOT protect against

| Explicit limit | Real consequence and operational mitigation |
|---|---|
| **Compromised server against people using the web vault in a browser** | An attacker who controls the server can tamper with the HTML, JavaScript or WASM delivered to the browser and capture the master password (and the authenticator code) the moment the person signs in to the web vault. Strict CSP and SRI headers protect against ordinary XSS, but **not** against a hostile server that controls its own HTML. For operations that must not trust the server operator, use the locally installed CLI and SDKs. |
| **Compromised application host** | If the machine running a consuming application is compromised, the attacker reads that application's `COFFREBOX_TOKEN` (and its running memory) and gets read access **to that application's vault only** — no other vault and no person's account. **Mandatory operational rule:** never host the Coffrebox server on the same machine as the applications that consume secrets, and always use one vault per application. |
| **Compromised person device while unlocked** | Local malware with access to the process memory, the terminal or the unlocked operating-system keychain can read the secrets accessed on that machine. |
| **Metadata visible to the server** | The server knows: account and invite e-mails, which accounts and `app_id`s belong to each `vault_id` and with which role (`owner`, `admin`, `editor`, `viewer`), the number and approximate size of encrypted items, access frequency and times, and the IPs recorded in the audit log. *(Vault names and item names are **not** visible metadata: they are always encrypted.)* |
| **Whole server compromised (database and server keys together)** | With the database and the server's account key together, the attacker opens each account's secret and can try to guess **weak** master passwords offline, against the client-side Argon2id (64 MiB, t=3). Until 2026-11-18 a 128-bit Secret Key prevented this even in that scenario; it was removed for usability (people no longer keep any code). Mitigation: a strong master-password policy in the client (§4.4), heavy Argon2id, and the server key stored outside the database and its backups. |
| **Lost master password** | There is no recovery through the server. Without the master password, the account's private keysets are unrecoverable; that person's individual vaults are lost for good, and shared vaults can only be recovered if another member with access shares them again with a new account. |
| **Lost phone with the authenticator app** | The person signs in with a printed recovery code (single use). Without them, the server administrator removes the authenticator with a host-only admin command and the person enrolls another one on the next sign-in. Whoever administers the host can therefore turn off the second factor of any account; the master password is still required. |

---

## 3. Encoding conventions and primitives

- **Base64url (`b64url`):** RFC 4648 §5, URL-safe alphabet (`A-Za-z0-9-_`), **no padding
  (`=`)**. Decoding rejects characters outside the alphabet, superfluous padding and non-zero
  trailing bits (canonical encoding).
- **UUID in binary concatenations (`uuid_16B`):** the raw 16 big-endian bytes of the RFC 9562 UUID
  (not the 36 ASCII characters).
- **Integers in binary concatenations (`u32_be`):** 4 unsigned big-endian bytes
  (`u32::to_be_bytes()`).
- **Canonical JSON (JCS — RFC 8785):**
  - UTF-8 without BOM;
  - no whitespace or line breaks between structural tokens;
  - keys of every object sorted lexicographically by Unicode code unit (equivalent to ASCII order
    for our keys);
  - deterministic lists (`items`, `members`) sorted ascending by their identifier field (`id` /
    `user_id` as a lowercase hyphenated UUID), without duplicates.

---

## 4. Person account (master password, account secret and authenticator app)

### 4.1 Account secret kept by the server

Until 2026-11-18 the account used a two-part derivation (master password + a 128-bit **Secret
Key** that only existed on the person's devices and in a printed Emergency Kit). For usability the
Secret Key was removed: the person only has to remember the master password, and the server now
keeps an **account secret** that plays part of the same role. Accounts in the old format do not
work with the new server (nothing had been released, so there is no migration).

- At sign-up the **server** generates `account_secret`: 32 random bytes per account.
- The database only holds the seal:
  `users.account_secret = "cfb1.acct." || kid || "." || b64url(nonce_24B || XChaCha20-Poly1305(K_account, account_secret, AAD))`,
  with
  - `K_account = HKDF-SHA256(salt = "coffrebox/v1", ikm = server_account_key, info = "coffrebox/v1/account-secret-at-rest")`;
  - `kid` = 4 bytes of `HKDF(…, info = "coffrebox/v1/account-key-id")` in hexadecimal, so the
    server knows which of its keys opens each row;
  - `AAD = "coffrebox/v1/account-secret" || user_id_16B`.
- `server_account_key` is kept outside the database and the database backups (an environment
  variable; mandatory outside development mode, the server does not start without it).
- **Password verifier:**
  `password_hash = Argon2id(b64url(HMAC-SHA256(account_secret, "coffrebox/v1/password-verifier" || auth_key_wire)))`.
  The plain `auth_key` is never stored.
- **Keyset envelope:** the `encrypted_keyset` that the client encrypted with the `kek` (§4.3) is
  encrypted again by the server:
  `users.encrypted_keyset = "cfb1.kswrap." || b64url(nonce_24B || XChaCha20-Poly1305(K_wrap, encrypted_keyset, "coffrebox/v1/keyset-wrap" || user_id_16B))`,
  with `K_wrap = HKDF-SHA256(salt = "coffrebox/v1", ikm = account_secret, info = "coffrebox/v1/keyset-wrap")`.
  The server only removes the envelope and returns the keyset after the password **and** the
  second factor check out (§4.5).
- **Per-account rotation:** `POST /api/v1/auth/account-secret/rotate` (full session, `auth_key`
  again and an authenticator code, §4.5) generates a new `account_secret` and rebuilds the
  verifier and the envelope in one transaction. The old verifier stops working.
- **Server key rotation:** the current value moves to a "previous key" variable, the new key takes
  its place, and a host-only admin command reseals every row (the previous key only opens; new
  seals always use the current key). Afterwards the "previous key" variable is removed.

**What this protects and what it does not:** whoever takes **only the database** (dump, leaked
backup, SQL injection) cannot test password guesses or open keysets, because the
`account_secret` is missing. Whoever takes **the database and the server account key together**
opens each account's secret and can try to guess weak master passwords offline, against the
client-side Argon2id (§4.2). The Secret Key prevented that even in this case; the compensation now
is the client-side master-password policy (§4.4) and heavy Argon2id.

### 4.2 Deriving `pw`, `root`, `auth_key` and `kek`

1. **Master password normalization:**
   ```text
   pw_utf8 = Unicode_NFKC(master_password).as_utf8_bytes()
   ```
   No `trim()` is applied: leading, inner and trailing spaces are part of the passphrase.

2. **Slow derivation with Argon2id (`pw`):**
   ```text
   pw = Argon2id_v19(
       password = pw_utf8,
       salt     = account_salt,   // 16 random bytes generated at sign-up
       m_cost   = 65536,          // 64 MiB (in KiB)
       t_cost   = 3,              // 3 iterations
       p_cost   = 1,              // 1 lane (works on single-threaded WebAssembly)
       output   = 32 bytes
   )
   ```
   - The parameters `(kdf_salt, kdf_m_kib, kdf_t_cost, kdf_p_cost)` are stored per account so they
     can be hardened later without breaking existing accounts.
   - **Client-side floor (anti-downgrade):** the client **refuses** to derive at sign-in if the
     server returns `kdf_m_kib < 65536`, `kdf_t_cost < 3`, `kdf_p_cost < 1`,
     `kdf_m_kib > 1048576` (1 GiB anti-DoS ceiling) or `len(kdf_salt) < 16`.

3. **Root key (`root`), v2 derivation (master password only):**
   ```text
   root = HKDF-SHA256(
       salt = user_id_16B,                             // account UUID as 16 BE bytes
       ikm  = pw,                                      // 32 bytes from Argon2id
       info = b"coffrebox/v2/root",
       L    = 32
   )
   ```
   The labels moved from `v1` to `v2` when the Secret Key left the `ikm`.

4. **Authentication key (`auth_key`) and key-encryption key (`kek`):**
   ```text
   auth_key_raw = HKDF-SHA256(salt = b"", ikm = root, info = b"coffrebox/v2/auth", L = 32)
   kek          = HKDF-SHA256(salt = b"", ikm = root, info = b"coffrebox/v2/kek",  L = 32)
   ```
   - The client encodes `auth_key_wire = "cfb1.auth." + b64url(auth_key_raw)` and sends it to the
     server as the authentication credential.
   - The server mixes `auth_key_wire` with the account secret before Argon2id (§4.1): the stored
     password hash never holds anything that checks the password without the server key.
   - `pw` and `root` are zeroized right after deriving `auth_key` and `kek`.

5. **Pre-login without e-mail enumeration:**
   - To get `(user_id, kdf_salt, kdf_params)` before signing in, the client calls
     `POST /api/v1/auth/prelogin { "email": "..." }`.
   - If the e-mail does not exist, the server deterministically synthesizes `pseudo_user_id` (a
     UUID v4 formatted from `HMAC-SHA256(PRELOGIN_SECRET, "uid:" || email_lower)[0..16]`) and
     `pseudo_salt` (`HMAC-SHA256(PRELOGIN_SECRET, "salt:" || email_lower)[0..16]`) with the
     default parameters `(65536, 3, 1)`. The following sign-in fails indistinguishably.
     `PRELOGIN_SECRET` is a server secret, mandatory outside development mode: the server does not
     start without it, and no known default value is used in production.

### 4.3 Person key pair and fingerprint

- At sign-up the client generates:
  - **Encryption (X25519):** `enc_sk` (32 random bytes) and `enc_pub = X25519_Basepoint(enc_sk)`
    (32 bytes).
  - **Signing (Ed25519):** `sign_seed` (32 random bytes) and `sign_pub = Ed25519_Public(sign_seed)`
    (32 bytes).
- **Encrypted private keyset (`encrypted_keyset`):**
  - Canonical JSON before encryption:
    ```json
    {"enc_sk":"<b64url_32B>","sign_seed":"<b64url_32B>","v":1}
    ```
  - Encrypted with **XChaCha20-Poly1305** under `kek`:
    - `nonce`: 24 random bytes (`getrandom`)
    - `aad`: `b"coffrebox/v1/keyset" || user_id_16B` (19 + 16 = 35 bytes)
  - Envelope format:
    ```text
    cfb1.keyset.<b64url(nonce_24B || ciphertext || tag_16B)>
    ```
- **Public keys stored in the clear on the server:**
  - `enc_pub`: `cfb1.xpk.<b64url(enc_pub_32B)>`
  - `sign_pub`: `cfb1.epk.<b64url(sign_pub_32B)>`
- **Fingerprint:**
  ```text
  fp_bytes = SHA-256(enc_pub_32B || sign_pub_32B)[0..16]   // first 128 bits
  ```
  Shown as lowercase hexadecimal in 8 groups of 4 characters separated by spaces:
  ```text
  a1b2 c3d4 e5f6 0718 293a 4b5c 6d7e 8f90
  ```
  Used to confirm members' identities out of band (CLI and web vault).

### 4.4 Master-password policy (client side)

Without the Secret Key, the strength of the master password is the last barrier against someone
holding the database and the server keys together. The server never sees the password, so the
policy runs in the client (`coffrebox_core::password_policy`, used by the CLI and, through WASM,
by the web vault) and refuses sign-up with:

- fewer than **12 characters** (after NFKC);
- a common password (short list: `senha`, `password`, `qwerty`, `123456`…), alone or only
  surrounded by digits and symbols;
- the e-mail (local part) or the person's name inside the password;
- three or fewer distinct characters.

The suggestion shown is a phrase of four random words.

### 4.5 Mandatory authenticator app and recovery codes

- **Mandatory for people.** Sign-up creates the account without the authenticator and returns only
  a **restricted token** (`scope = 'totp_setup'`, 30 minutes), valid exclusively for
  `POST /auth/totp/setup` and `POST /auth/totp/enable`. No vault, member, session or account
  route accepts it, and no web session is opened before the authenticator. Signing in with the
  right password to an account without an authenticator (interrupted sign-up or administrator
  reset) again returns only the restricted token.
- **Full session** = a token with `scope = 'full'` (or a web session) **and** an enabled
  authenticator. The check runs for both the API and the server-rendered pages.
- **Authenticator code:** TOTP RFC 6238 (SHA-1, 6 digits, 30 s, ±1 step window). The accepted step
  is recorded and only later steps are valid afterwards, including the code used to turn the
  authenticator on. The secret is sealed at rest (`cfb1.totp.`, with a key derived from a
  dedicated server key).
- **Activation:** `totp/setup` stores the new secret as pending; `totp/enable` checks a code from
  it and only then makes it the active secret. For someone holding the restricted token, activation
  revokes that token and returns the full session with the keyset.
- **Re-authentication for sensitive actions:** changing devices, generating recovery codes and
  rotating the account secret do not accept just the open session (which may have been stolen).
  Each one asks for the `auth_key` again, checked against the verifier as at sign-in, and a fresh
  second factor: an authenticator code from a step later than the last accepted one (the step is
  then spent) or, only when changing devices, a recovery code (also spent). Limits: 20 attempts
  per minute per IP and 10 per account; every refusal goes to the audit log
  (`user.reauth.fail`).
- **Changing devices:** `totp/setup` with a full session and re-authentication stores the new
  secret as pending; it only replaces the old one at `totp/enable`, so the current device keeps
  working until the confirmation. The person is notified by e-mail. There is no "disable".
- **Recovery codes:** generated at the first activation (and again with
  `POST /auth/recovery-codes`, with re-authentication by an authenticator code, which invalidates
  the previous ones and sends an e-mail notice). There are 10 per account, 60 bits each, in the
  format `XXXX-XXXX-XXXX` in Crockford Base32 (input tolerates lowercase, `O/0`, `I/L/1`, spaces
  and hyphens). The database only keeps
  `HMAC-SHA256(K_rec, "coffrebox/v1/recovery-code" || user_id_16B || code)`, with
  `K_rec = HKDF(server_totp_key, info = "coffrebox/v1/recovery-codes")`. Each code can replace the
  authenticator code once (`recovery_code` at sign-in); the use goes to the audit log
  (`user.recovery_code.use`) and triggers an e-mail notice.
- **Reset by the server administrator:** a host-only admin command (there is no administrator role
  on the web) removes the authenticator and the codes, ends every session, records
  `user.totp.admin_reset` and sends an e-mail notice. The master password is still required and
  the vaults do not change: the second factor controls access to the server, not the encryption.

---

## 5. Vault, vault key (VK), items and manifest

### 5.1 Vault key (VK) and vault metadata

- Each vault has:
  - `vault_id`: a UUID v4 generated at creation;
  - `vk`: 32 random bytes (`[u8; 32]`, 256 bits) generated in the client;
  - `key_version`: a `u32` starting at `1` and incremented by 1 at each key rotation.
- **Encrypted vault name (`encrypted_meta`):**
  - Canonical JSON plaintext (the field names are part of the wire format and stay as they are):
    ```json
    {"nome":" Production — Payments ","v":1}
    ```
  - Encrypted with **XChaCha20-Poly1305** under `vk`:
    - `nonce`: 24 random bytes
    - `aad`: `b"coffrebox/v1/vault-meta" || vault_id_16B || key_version_u32_be` (23 + 16 + 4 = 43
      bytes)
  - Envelope:
    ```text
    cfb1.vmeta.<b64url(nonce_24B || ciphertext || tag_16B)>
    ```

### 5.2 Sealing the VK with HPKE (RFC 9180) and signature

The VK is sealed individually to each member (`recipient_id = user_id`) and each application
(`recipient_id = app_id`) with their X25519 public key:

- **HPKE suite (RFC 9180):**
  - Mode: `Base` (`0x00`)
  - KEM: `DHKEM(X25519, HKDF-SHA256)` (`0x0020`)
  - KDF: `HKDF-SHA256` (`0x0001`)
  - AEAD: `ChaCha20Poly1305` (`0x0003`)
- **Sealing parameters (`seal`):**
  - `plaintext`: `vk` (32 raw bytes)
  - `info`: `b"coffrebox/v1/vault-key"` (22 bytes)
  - `aad`: `b"coffrebox/v1/vk-aad" || recipient_kind_1B || vault_id_16B || recipient_id_16B || key_version_u32_be`
    - where `recipient_kind_1B` is `0x01` for a person (`user`) and `0x02` for an application
      (`app`), so a user UUID and an application UUID can never collide; total = 19 + 1 + 16 + 16
      + 4 = 56 bytes.
- **Serialized envelope (`sealed_vk`):**
  ```text
  cfb1.vk.<b64url(encapped_key_32B || aead_ciphertext_32B || aead_tag_16B)>
  ```
  *(Fixed binary length of 80 bytes.)*
- **Ed25519 signature of the grantor (`vk_sig`):**
  Whoever grants the access (`granted_by_user_id`) signs:
  ```text
  vk_grant_msg = b"coffrebox/v1/vk-grant"
              || recipient_kind_1B
              || vault_id_16B
              || recipient_id_16B
              || key_version_u32_be
              || SHA-256(encapped_key_32B || aead_ciphertext_32B || aead_tag_16B)
  ```
  *(21 + 1 + 16 + 16 + 4 + 32 = 90 bytes.)*
  Signature envelope:
  ```text
  cfb1.sig.<b64url(ed25519_sig_64B)>
  ```

### 5.3 Item format and encryption

- **JSON plaintext (`"v": 1`)** — the field names and the `tipo` values are Portuguese and are part
  of the encrypted wire format, so they stay as they are:
  ```json
  {
    "nome": "DATABASE_URL",
    "nota": "Primary database",
    "tipo": "segredo",
    "totp": null,
    "url": null,
    "usuario": null,
    "v": 1,
    "valor": "postgres://app_fictitious:fictitious_password@db.internal:5432/app"
  }
  ```
  - `nome` = name, `valor` = value, `nota` = note, `usuario` = username, `tipo` = kind.
  - `tipo` is `"segredo"` (secret), `"login"` or `"nota"` (note).
  - In application vaults and in the SDKs, `nome` is the secret's name (e.g. `DATABASE_URL`) and
    `valor` is its content.
  - **Everything is encrypted in a single AEAD payload**, including `nome` and `tipo`. The server
    never learns any item name.
- **XChaCha20-Poly1305 encryption:**
  - Key: the `vk` for `key_version`
  - `nonce`: 24 random bytes (`getrandom`)
  - `aad`:
    ```text
    b"coffrebox/v1/item" || vault_id_16B || item_id_16B || item_version_u32_be || key_version_u32_be
    ```
    *(17 + 16 + 16 + 4 + 4 = 57 fixed bytes.)*
  - Envelope:
    ```text
    cfb1.item.<b64url(nonce_24B || ciphertext || tag_16B)>
    ```
- **Hash of the encrypted item:**
  `hex_lower(SHA-256(nonce_24B || ciphertext || tag_16B))` (64 lowercase hex characters over the
  binary bytes of the decoded envelope).

### 5.4 Vault manifest and chain of trust

- **Manifest structure (canonical JSON, RFC 8785):**
  ```json
  {
    "items": [
      {
        "id": "018f3a10-1111-7000-8000-000000000001",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "version": 1
      }
    ],
    "key_version": 1,
    "revision": 1,
    "signed_by": "018f3a00-0000-7000-8000-000000000001",
    "v": 1,
    "vault_id": "018f3a05-0000-7000-8000-000000000001",
    "vault_meta_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
  }
  ```
  - `revision` (`u64 >= 1`): strictly increasing on every vault mutation (item creation, edit or
    removal, vault rename or key rotation).
  - `vault_meta_sha256`: `hex_lower(SHA-256(binary_bytes_of_vmeta))`, which also protects the
    encrypted vault name from being swapped by the server.
- **Manifest signature:**
  ```text
  manifest_msg = b"coffrebox/v1/manifest\x00" || canonical_manifest_utf8_bytes
  manifest_sig = Ed25519.Sign(writer_sign_sk, manifest_msg)
  ```
  Envelope: `cfb1.sig.<b64url(manifest_sig_64B)>`.
- **Chain-of-trust verification:**
  - **Owner-only vaults:** `manifest.signed_by` must be the `owner_user_id`, and `manifest_sig` and
    `vk_sig` must verify directly with `owner_sign_pk` (`verify_strict`).
  - **Shared vaults:** the owner signs a canonical `MemberRoster`
    (`{"apps":[{"app_id":"...","enc_pub":"...","sign_pub":"..."}],"members":[{"enc_pub":"...","role":"owner|admin|editor|viewer","sign_pub":"...","user_id":"..."}],"roster_version":1,"v":1,"vault_id":"..."}`)
    under the domain `b"coffrebox/v1/member-roster\x00"`. The `apps` field only appears when there
    are applications, so older rosters keep the same canonical form and signature.
    **Compatibility:** SDKs and WASM builds from before `apps` existed refuse rosters that contain
    it (the canonical form does not match); update SDKs, WASM and CLI together before creating
    applications in a vault. Clients and SDKs first verify the `MemberRoster` with
    `owner_sign_pk`, then confirm that:
    1. the signer of `vk_sig` has the `owner` or `admin` role in the `MemberRoster`;
    2. `manifest.signed_by` has the `owner`, `admin` or `editor` role in the `MemberRoster`.
  - **Who changes the roster:** only the owner, because the signature is theirs. The server, the
    CLI and the web vault refuse to confirm or remove members and to create or revoke applications
    when the caller is not the owner.
  - **New member:** the fingerprint shown and checked (last 4 characters) is computed in the client
    from the keys that are about to be sealed to and listed in the roster; a fingerprint sent by
    the server is only used to warn about a mismatch. The role comes from the local record made at
    invite time, never from the server's invite list.
  - **`roster_version`** only grows: the server refuses to store an equal or lower version, and
    clients keep the highest version seen (§5.6).

### 5.5 Vault key rotation (`key_version + 1`)

When a member is removed or an application is revoked, the client of the person doing it
performs, atomically:

1. Decrypts the vault name and every active item with the current `vk`;
2. Generates a new random 256-bit `vk_new` and sets `new_key_version = key_version + 1`;
3. Re-encrypts the vault name and every active item with fresh 24-byte nonces and
   `new_key_version` in the AAD (incrementing each re-encrypted item's `item_version`);
4. Seals `vk_new` with HPKE only to the members and applications of the **verified signed roster**
   (minus whoever is leaving), using the public keys in it, and signs each `vk_sig` envelope. The
   server's `/members` and `/apps` lists never add recipients or swap keys; `/apps` can only take
   applications out of the rotation (at worst it denies access to an application, but never
   receives the VK). An application that is active on the server but missing from the signed
   roster does not receive the new key and triggers a warning;
5. Builds and signs the new manifest (`revision + 1`, `key_version + 1`) and the new
   `MemberRoster` (`roster_version + 1`, without whoever left) and sends everything to the server
   in a single transaction with optimistic concurrency control (`expected_revision`).

Only the owner performs the rotation, since it always produces a new signed roster.

### 5.6 Trust anchor of the person-facing clients (CLI and web vault)

The snapshot delivered by the server includes `owner_user_id` and `owner_sign_public_key`. These
fields are **not** an anchor: a compromised server can swap them together with the
`MemberRoster`, the manifest and the VK envelope, signing everything with its own key. The anchor
used to verify the snapshot always comes from the client
(`coffrebox_core::trust::verify_vault_for_user`):

1. **Own vault** (`owner_user_id` is the person's own account): the anchor is the person's own
   Ed25519 key, derived locally from the session keyset. A snapshot that says "this vault is
   yours" but is signed by another key is refused immediately, without TOFU.
2. **Shared vault** (`owner_user_id` is another account): trust on first use (*TOFU*). On the first
   read the client pins a `VaultPin` with `owner_user_id`, `owner_sign_public_key` and the owner's
   fingerprint (computed from the owner's entry in the `MemberRoster`) and asks the person to check
   those digits with the owner. From then on:
   - a different key or a different `owner_user_id` for the same `vault_id` raises
     `OwnerKeyChanged` with both fingerprints, and nothing is read or written;
   - the change is only accepted when the person types the last 4 characters of the **received**
     fingerprint (an explicit trust command in the CLI; a seal-colored alert in the web vault).
3. **Roster consistent with the anchor:** the `MemberRoster` must have exactly one `owner`, who
   must be the snapshot's `owner_user_id`, whose `sign_pub` must equal the anchor, and it must
   include the person's own account. A shared vault without a signed `MemberRoster` is refused.
4. **Application token:** creating an application writes into the token the `owner_sign_pk`
   **verified** by the steps above, never the value received from the server.

**Where the state lives:**
- **CLI:** a per-account trust file next to the session file, written with mode `0600` and an
  atomic `rename`. It survives sign-out.
- **Web vault:** `localStorage["cfb_trust_<user_id>"]` holds the encrypted `TrustStore`
  (`cfb1.trust.<b64url(nonce_24B || ct)>`, `XChaCha20-Poly1305` with key
  `HKDF-SHA256(salt = user_id, ikm = sign_seed || enc_sk, info = "coffrebox/v1/local-trust-state")`
  and AAD `"coffrebox/v1/local-trust-state" || user_id`). If the browser clears that storage, the
  next access is a first use again.

**Known limit:** on a new device (or with the state cleared), the first access to a shared vault
trusts whatever the server presents. That is why the first use shows the owner's fingerprint,
which must be checked outside the system.

---

## 6. Application credential, authentication and cache

### 6.1 Application token (`COFFREBOX_TOKEN`)

Creating an application generates `x25519_sk` (32B) and `ed25519_seed` (32B) in the client, sends
only the public keys to the server to register `app_id` (UUID, 16B) and builds locally the token,
which is shown **only once**:

```text
body_112B = app_id_16B || x25519_sk_32B || ed25519_seed_32B || owner_sign_pk_32B
crc_4B    = CRC32_IEEE_BE(b"cfb1_app_" || body_112B)
token     = "cfb1_app_" + b64url(body_112B || crc_4B)
```

- Binary length: `112 + 4 = 116` bytes (`155` `b64url` characters, `164` characters in total with
  `cfb1_app_`).
- The CRC32 exists **only** to detect truncation or copy errors in environment variables before
  any network call.
- The `owner_sign_pk` inside the token is an **immutable trust anchor (*pinned root*)**: even a
  fully compromised server cannot sign manifests or VK envelopes the application accepts without
  the vault owner's Ed25519 private key. The CLI writes there the owner key it verified locally
  (§5.6), never the one that comes in the snapshot.

### 6.2 Ed25519 challenge-response and access token

1. `POST /api/v1/apps/auth/challenge { "app_id": "<uuid>" }`
   - The server generates a 32-byte random `nonce` with `getrandom`, stores it with
     `expires_at = now() + 60s` and `used_at = NULL`, and returns the `nonce` as `b64url`.
2. The SDK signs in the client:
   ```text
   challenge_msg = b"coffrebox/v1/app-auth" || app_id_16B || nonce_32B   // 21 + 16 + 32 = 69 bytes
   sig           = Ed25519.Sign(app_ed25519_sk, challenge_msg)
   ```
3. `POST /api/v1/apps/auth/token { "app_id": "<uuid>", "nonce": "<b64url_32B>", "signature": "cfb1.sig.<b64url_64B>" }`
   - The server consumes the challenge atomically (only an unused, unexpired challenge for that
     `app_id` and nonce hash is accepted, and it is marked used in the same statement), refuses a
     revoked application, verifies `sig` with `verify_strict` against the application's
     registered signing key and issues an opaque access token `cfb1_at_<b64url_32B>` valid for
     **15 minutes (900 s)**, bound only to the application's `vault_id`.
   - The server stores **only `SHA-256(access_token_utf8)`**, never the token itself.

### 6.3 Full snapshot verification in the SDK and on-disk cache format

On `200 OK` from `GET /api/v1/vaults/{id}/snapshot`, the SDK (Rust, or TypeScript through WASM)
always runs, in this order:

1. Confirms `snapshot.manifest.vault_id == expected_vault_id` and
   `snapshot.manifest.revision >= cached_revision` (refuses a *rollback* with a `Tampered` error).
2. Verifies the Ed25519 signature of the canonical manifest against `owner_sign_pk` (or a
   `MemberRoster` signed by `owner_sign_pk`).
3. Verifies the Ed25519 `vk_sig` over the `sealed_vk` envelope addressed to `app_id` and
   `snapshot.manifest.key_version`.
4. Opens `sealed_vk` with HPKE using the application's `x25519_sk` and the application AAD
   (`recipient_kind = 0x02`).
5. Checks that the delivered `items` have exactly the IDs, versions and `SHA-256` listed in the
   signed manifest (any extra, missing or mismatched item aborts everything with a `Tampered`
   error).
6. Decrypts each item with `XChaCha20-Poly1305`, checking its full AAD, and fills the in-memory
   cache for `ttlMs`.

**On-disk cache (shared by the TypeScript and Rust SDKs):**
- Path: `<cacheDir>/<app_id>/<vault_id>.snapshot` (directory mode `0700`, file `0600`, written to
  `<vault_id>.snapshot.tmp.<pid>` with `fsync` followed by an atomic `rename`).
- JSON content (`"v": 1`): **only the encrypted snapshot exactly as validated**, plus the local
  validation time:
  ```json
  {
    "fetched_at_ms": 1794969600000,
    "snapshot": { "... original encrypted envelopes and signatures ..." },
    "v": 1
  }
  ```
- **No plaintext value is ever written to disk.** When starting offline from the disk cache, the
  SDK reruns verification steps 1–6 with the `COFFREBOX_TOKEN` in memory and checks
  `now_ms - fetched_at_ms <= maxStaleMs`.
- On `401 Unauthorized` or `403 Forbidden` (revoked application), the SDK **immediately deletes**
  the `.snapshot` file, clears the in-memory cache and returns a typed `Revoked` error.
