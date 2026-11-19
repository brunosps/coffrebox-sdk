use core::fmt;

use crc32fast::Hasher as Crc32Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::encoding::{b64url_decode, b64url_encode, fill_random};
use crate::error::{CoreError, Result};
use crate::keys::{
    decode_ed25519_pub, encode_ed25519_pub, encode_ed25519_sig, encode_x25519_pub,
    verify_ed25519_strict,
};

pub const APP_TOKEN_PREFIX: &str = "cfb1_app_";
const APP_AUTH_DOMAIN: &[u8] = b"coffrebox/v1/app-auth";

/// Full credential decoded from a `COFFREBOX_TOKEN` (`cfb1_app_...`).
#[derive(Clone)]
pub struct AppCredentials {
    app_id: Uuid,
    x25519_sk: [u8; 32],
    ed25519_seed: [u8; 32],
    owner_sign_pk: [u8; 32],
}

impl Zeroize for AppCredentials {
    fn zeroize(&mut self) {
        self.x25519_sk.zeroize();
        self.ed25519_seed.zeroize();
        self.owner_sign_pk.zeroize();
    }
}

impl Drop for AppCredentials {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AppCredentials {}

impl fmt::Debug for AppCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppCredentials")
            .field("app_id", &self.app_id)
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

impl AppCredentials {
    pub fn generate(app_id: Uuid, owner_sign_pk: [u8; 32]) -> Result<Self> {
        let mut x25519_sk = [0u8; 32];
        let mut ed25519_seed = [0u8; 32];
        fill_random(&mut x25519_sk)?;
        fill_random(&mut ed25519_seed)?;
        Ok(Self {
            app_id,
            x25519_sk,
            ed25519_seed,
            owner_sign_pk,
        })
    }

    pub fn from_parts(
        app_id: Uuid,
        x25519_sk: [u8; 32],
        ed25519_seed: [u8; 32],
        owner_sign_pk: [u8; 32],
    ) -> Self {
        Self {
            app_id,
            x25519_sk,
            ed25519_seed,
            owner_sign_pk,
        }
    }

    pub fn app_id(&self) -> Uuid {
        self.app_id
    }

    pub fn x25519_secret_bytes(&self) -> &[u8; 32] {
        &self.x25519_sk
    }

    pub fn owner_sign_public_bytes(&self) -> &[u8; 32] {
        &self.owner_sign_pk
    }

    pub fn enc_public_bytes(&self) -> [u8; 32] {
        let sk = X25519StaticSecret::from(self.x25519_sk);
        X25519PublicKey::from(&sk).to_bytes()
    }

    pub fn sign_public_bytes(&self) -> [u8; 32] {
        let sk = SigningKey::from_bytes(&self.ed25519_seed);
        sk.verifying_key().to_bytes()
    }

    pub fn enc_public_envelope(&self) -> String {
        encode_x25519_pub(&self.enc_public_bytes())
    }

    pub fn sign_public_envelope(&self) -> String {
        encode_ed25519_pub(&self.sign_public_bytes())
    }

    /// Serializes `cfb1_app_` + `base64url(app_id_16 || x25519_sk_32 || ed25519_seed_32 || owner_sign_pk_32 || crc32_4)`.
    pub fn to_token(&self) -> Zeroizing<String> {
        let mut body = Zeroizing::new([0u8; 116]);
        body[0..16].copy_from_slice(self.app_id.as_bytes());
        body[16..48].copy_from_slice(&self.x25519_sk);
        body[48..80].copy_from_slice(&self.ed25519_seed);
        body[80..112].copy_from_slice(&self.owner_sign_pk);

        let crc = compute_token_crc32(&body[0..112]);
        body[112..116].copy_from_slice(&crc);

        Zeroizing::new(format!("{APP_TOKEN_PREFIX}{}", b64url_encode(&body[..])))
    }

    pub fn parse_token(token: &str) -> Result<Self> {
        let trimmed = token.trim();
        let b64 = trimmed
            .strip_prefix(APP_TOKEN_PREFIX)
            .ok_or(CoreError::InvalidFormat("missing cfb1_app_ prefix"))?;
        let raw = Zeroizing::new(b64url_decode(b64)?);
        if raw.len() != 116 {
            return Err(CoreError::InvalidFormat(
                "application token must decode to 116 bytes",
            ));
        }
        let expected_crc = compute_token_crc32(&raw[0..112]);
        let actual_crc = &raw[112..116];
        if !bool::from(expected_crc.ct_eq(actual_crc)) {
            return Err(CoreError::ChecksumMismatch);
        }

        let app_id = Uuid::from_slice(&raw[0..16])
            .map_err(|_| CoreError::InvalidFormat("invalid app_id"))?;
        let mut x25519_sk = [0u8; 32];
        let mut ed25519_seed = [0u8; 32];
        let mut owner_sign_pk = [0u8; 32];
        x25519_sk.copy_from_slice(&raw[16..48]);
        ed25519_seed.copy_from_slice(&raw[48..80]);
        owner_sign_pk.copy_from_slice(&raw[80..112]);

        Ok(Self {
            app_id,
            x25519_sk,
            ed25519_seed,
            owner_sign_pk,
        })
    }

    /// Signs the authentication challenge `"coffrebox/v1/app-auth" || app_id_16B || nonce_32B`.
    pub fn sign_auth_challenge(&self, nonce_b64: &str) -> Result<String> {
        let nonce = b64url_decode(nonce_b64)?;
        if nonce.len() != 32 {
            return Err(CoreError::InvalidFormat("challenge nonce must be 32 bytes"));
        }
        let msg = build_challenge_message(self.app_id, &nonce);
        let sk = SigningKey::from_bytes(&self.ed25519_seed);
        let sig: Signature = sk.sign(&msg);
        Ok(encode_ed25519_sig(&sig.to_bytes()))
    }
}

fn compute_token_crc32(body_112: &[u8]) -> [u8; 4] {
    let mut hasher = Crc32Hasher::new();
    hasher.update(APP_TOKEN_PREFIX.as_bytes());
    hasher.update(body_112);
    hasher.finalize().to_be_bytes()
}

fn build_challenge_message(app_id: Uuid, nonce_32: &[u8]) -> [u8; 69] {
    let mut msg = [0u8; 69];
    msg[0..21].copy_from_slice(APP_AUTH_DOMAIN);
    msg[21..37].copy_from_slice(app_id.as_bytes());
    msg[37..69].copy_from_slice(nonce_32);
    msg
}

/// Server side: verifies the application's Ed25519 answer to the 32-byte challenge.
pub fn verify_app_challenge_signature(
    sign_pub_envelope: &str,
    app_id: Uuid,
    nonce_b64: &str,
    sig_envelope: &str,
) -> Result<()> {
    let sign_pub = decode_ed25519_pub(sign_pub_envelope)?;
    let nonce = b64url_decode(nonce_b64)?;
    if nonce.len() != 32 {
        return Err(CoreError::InvalidFormat("nonce must be 32 bytes"));
    }
    let msg = build_challenge_message(app_id, &nonce);
    verify_ed25519_strict(&sign_pub, &msg, sig_envelope)
}
