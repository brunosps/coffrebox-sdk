use core::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::encoding::{b64url_decode, b64url_encode, fill_random};
use crate::error::{CoreError, Result};

pub const DEFAULT_ARGON2_M_KIB: u32 = 65_536; // 64 MiB
pub const DEFAULT_ARGON2_T_COST: u32 = 3;
pub const DEFAULT_ARGON2_P_COST: u32 = 1;
pub const MAX_ARGON2_M_KIB: u32 = 1_048_576; // 1 GiB (anti-DoS ceiling)
pub const MIN_SALT_LEN: usize = 16;

pub const AUTH_KEY_PREFIX: &str = "cfb1.auth.";

/// Public Argon2id derivation parameters stored per account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub salt: String,
    pub m_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    pub fn generate_default() -> Result<Self> {
        let mut salt = [0u8; MIN_SALT_LEN];
        fill_random(&mut salt)?;
        Ok(Self {
            salt: b64url_encode(&salt),
            m_kib: DEFAULT_ARGON2_M_KIB,
            t_cost: DEFAULT_ARGON2_T_COST,
            p_cost: DEFAULT_ARGON2_P_COST,
        })
    }

    /// Checks the minimum floor on the client to block KDF downgrade attacks.
    pub fn decode_and_validate(&self) -> Result<Vec<u8>> {
        let salt_bytes = b64url_decode(&self.salt)?;
        if salt_bytes.len() < MIN_SALT_LEN
            || self.m_kib < DEFAULT_ARGON2_M_KIB
            || self.m_kib > MAX_ARGON2_M_KIB
            || self.t_cost < DEFAULT_ARGON2_T_COST
            || self.p_cost < DEFAULT_ARGON2_P_COST
        {
            return Err(CoreError::WeakKdfParams);
        }
        Ok(salt_bytes)
    }
}

/// Authentication key sent to the server (`cfb1.auth.<b64url_32B>`).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AuthKey(String);

impl fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthKey([REDACTED])")
    }
}

impl PartialEq for AuthKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for AuthKey {}

impl AuthKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate_envelope(wire: &str) -> Result<()> {
        let raw = wire
            .strip_prefix(AUTH_KEY_PREFIX)
            .ok_or(CoreError::InvalidFormat("missing cfb1.auth. prefix"))?;
        let decoded = b64url_decode(raw)?;
        if decoded.len() != 32 {
            return Err(CoreError::InvalidFormat("auth_key must be 32 bytes"));
        }
        Ok(())
    }
}

/// Key Encryption Key (`kek`) derived locally; it never leaves the client.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Kek([u8; 32]);

impl fmt::Debug for Kek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Kek([REDACTED])")
    }
}

impl Kek {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derives `auth_key` and `kek` from the master password (NFKC), the `user_id` and the account's
/// Argon2id parameters only (v2 derivation: the person no longer holds a Secret Key).
///
/// The `auth_key` goes to the server, which mixes it with the account secret it stores before
/// checking it (see `docs/CRYPTO.md` §4). The `kek` never leaves the client.
pub fn derive_account_keys(
    master_password: &str,
    user_id: Uuid,
    params: &KdfParams,
) -> Result<(AuthKey, Kek)> {
    if master_password.is_empty() {
        return Err(CoreError::InvalidFormat("empty master password"));
    }
    let salt_bytes = params.decode_and_validate()?;

    let pw_nfkc = Zeroizing::new(master_password.nfkc().collect::<String>());
    let argon_params = Params::new(params.m_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|_| CoreError::WeakKdfParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut ikm = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(pw_nfkc.as_bytes(), &salt_bytes, &mut ikm[..])
        .map_err(|_| CoreError::WeakKdfParams)?;

    let root_hkdf = Hkdf::<Sha256>::new(Some(user_id.as_bytes()), &ikm[..]);
    let mut root = Zeroizing::new([0u8; 32]);
    root_hkdf
        .expand(b"coffrebox/v2/root", &mut root[..])
        .map_err(|_| CoreError::InvalidFormat("HKDF root failed"))?;

    let sub_hkdf = Hkdf::<Sha256>::new(Some(b""), &root[..]);
    let mut auth_raw = Zeroizing::new([0u8; 32]);
    sub_hkdf
        .expand(b"coffrebox/v2/auth", &mut auth_raw[..])
        .map_err(|_| CoreError::InvalidFormat("HKDF auth failed"))?;

    // The kek is written straight into the `Kek` (zeroized on drop), with no loose copy on the stack.
    let mut kek = Kek([0u8; 32]);
    sub_hkdf
        .expand(b"coffrebox/v2/kek", &mut kek.0)
        .map_err(|_| CoreError::InvalidFormat("HKDF kek failed"))?;

    let auth_wire = format!("{AUTH_KEY_PREFIX}{}", b64url_encode(&auth_raw[..]));
    Ok((AuthKey(auth_wire), kek))
}
