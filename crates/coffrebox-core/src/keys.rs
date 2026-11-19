use core::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::encoding::{b64url_decode, b64url_encode, fill_random, sha256_bytes};
use crate::error::{CoreError, Result};
use crate::kdf::Kek;

pub const X25519_PUB_PREFIX: &str = "cfb1.xpk.";
pub const ED25519_PUB_PREFIX: &str = "cfb1.epk.";
pub const ED25519_SIG_PREFIX: &str = "cfb1.sig.";
pub const KEYSET_ENVELOPE_PREFIX: &str = "cfb1.keyset.";

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct KeysetPlaintext {
    enc_sk: String,
    sign_seed: String,
    v: u32,
}

/// A person's private and public key pairs (X25519 + Ed25519).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct UserKeyset {
    enc_sk_bytes: [u8; 32],
    sign_seed_bytes: [u8; 32],
}

impl fmt::Debug for UserKeyset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserKeyset([REDACTED])")
    }
}

impl UserKeyset {
    pub fn generate() -> Result<Self> {
        let mut enc_sk_bytes = [0u8; 32];
        let mut sign_seed_bytes = [0u8; 32];
        fill_random(&mut enc_sk_bytes)?;
        fill_random(&mut sign_seed_bytes)?;
        Ok(Self {
            enc_sk_bytes,
            sign_seed_bytes,
        })
    }

    pub fn from_raw(enc_sk_bytes: [u8; 32], sign_seed_bytes: [u8; 32]) -> Self {
        Self {
            enc_sk_bytes,
            sign_seed_bytes,
        }
    }

    pub fn enc_secret_bytes(&self) -> &[u8; 32] {
        &self.enc_sk_bytes
    }

    pub fn sign_seed_bytes(&self) -> &[u8; 32] {
        &self.sign_seed_bytes
    }

    pub fn enc_public_bytes(&self) -> [u8; 32] {
        let sk = X25519StaticSecret::from(self.enc_sk_bytes);
        X25519PublicKey::from(&sk).to_bytes()
    }

    pub fn sign_public_bytes(&self) -> [u8; 32] {
        let sk = SigningKey::from_bytes(&self.sign_seed_bytes);
        sk.verifying_key().to_bytes()
    }

    pub fn enc_public_envelope(&self) -> String {
        encode_x25519_pub(&self.enc_public_bytes())
    }

    pub fn sign_public_envelope(&self) -> String {
        encode_ed25519_pub(&self.sign_public_bytes())
    }

    pub fn fingerprint(&self) -> String {
        compute_fingerprint(&self.enc_public_bytes(), &self.sign_public_bytes())
    }

    pub fn sign_bytes(&self, message: &[u8]) -> String {
        let sk = SigningKey::from_bytes(&self.sign_seed_bytes);
        let sig: Signature = sk.sign(message);
        encode_ed25519_sig(&sig.to_bytes())
    }

    /// Encrypts the key pairs with `kek` (`XChaCha20-Poly1305`, AAD `"coffrebox/v1/keyset" || user_id`).
    pub fn seal(&self, kek: &Kek, user_id: Uuid) -> Result<String> {
        let plain = KeysetPlaintext {
            enc_sk: b64url_encode(&self.enc_sk_bytes),
            sign_seed: b64url_encode(&self.sign_seed_bytes),
            v: crate::FORMAT_VERSION,
        };
        let json_bytes = Zeroizing::new(
            serde_json::to_vec(&plain).map_err(|_| CoreError::InvalidFormat("json keyset"))?,
        );

        let mut nonce = [0u8; 24];
        fill_random(&mut nonce)?;
        let aad = keyset_aad(user_id);

        let cipher = XChaCha20Poly1305::new(&Key::from(*kek.as_bytes()));
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &json_bytes,
                    aad: &aad,
                },
            )
            .map_err(|_| CoreError::DecryptionFailed)?;

        let mut wire = Vec::with_capacity(24 + ciphertext.len());
        wire.extend_from_slice(&nonce);
        wire.extend_from_slice(&ciphertext);
        Ok(format!("{KEYSET_ENVELOPE_PREFIX}{}", b64url_encode(&wire)))
    }

    /// Opens the `encrypted_keyset`, checking the AAD bound to the `user_id`.
    pub fn open(envelope: &str, kek: &Kek, user_id: Uuid) -> Result<Self> {
        let raw_b64 = envelope
            .strip_prefix(KEYSET_ENVELOPE_PREFIX)
            .ok_or(CoreError::InvalidFormat("missing cfb1.keyset. prefix"))?;
        let wire = b64url_decode(raw_b64)?;
        if wire.len() < 24 + 16 {
            return Err(CoreError::InvalidFormat("truncated keyset envelope"));
        }
        let (nonce, ciphertext) = wire.split_at(24);
        let aad = keyset_aad(user_id);

        let nonce_arr: [u8; 24] = nonce
            .try_into()
            .map_err(|_| CoreError::InvalidFormat("invalid nonce"))?;
        let cipher = XChaCha20Poly1305::new(&Key::from(*kek.as_bytes()));
        let plain_bytes = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(nonce_arr),
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| CoreError::DecryptionFailed)?,
        );

        let parsed: KeysetPlaintext =
            serde_json::from_slice(&plain_bytes).map_err(|_| CoreError::InvalidFormat("keyset"))?;
        if parsed.v != crate::FORMAT_VERSION {
            return Err(CoreError::InvalidFormat("unsupported keyset version"));
        }

        let enc_vec = Zeroizing::new(b64url_decode(&parsed.enc_sk)?);
        let sign_vec = Zeroizing::new(b64url_decode(&parsed.sign_seed)?);
        let enc_sk_bytes: [u8; 32] = enc_vec
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::InvalidFormat("invalid enc_sk length"))?;
        let sign_seed_bytes: [u8; 32] = sign_vec
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::InvalidFormat("invalid sign_seed length"))?;

        Ok(Self {
            enc_sk_bytes,
            sign_seed_bytes,
        })
    }
}

fn keyset_aad(user_id: Uuid) -> [u8; 35] {
    let mut aad = [0u8; 35];
    aad[..19].copy_from_slice(b"coffrebox/v1/keyset");
    aad[19..35].copy_from_slice(user_id.as_bytes());
    aad
}

pub fn encode_x25519_pub(bytes: &[u8; 32]) -> String {
    format!("{X25519_PUB_PREFIX}{}", b64url_encode(bytes))
}

pub fn decode_x25519_pub(envelope: &str) -> Result<[u8; 32]> {
    let raw = envelope
        .strip_prefix(X25519_PUB_PREFIX)
        .ok_or(CoreError::InvalidFormat("missing cfb1.xpk. prefix"))?;
    let vec = b64url_decode(raw)?;
    vec.try_into()
        .map_err(|_| CoreError::InvalidFormat("X25519 public key must be 32 bytes"))
}

pub fn encode_ed25519_pub(bytes: &[u8; 32]) -> String {
    format!("{ED25519_PUB_PREFIX}{}", b64url_encode(bytes))
}

pub fn decode_ed25519_pub(envelope: &str) -> Result<[u8; 32]> {
    let raw = envelope
        .strip_prefix(ED25519_PUB_PREFIX)
        .ok_or(CoreError::InvalidFormat("missing cfb1.epk. prefix"))?;
    let vec = b64url_decode(raw)?;
    vec.try_into()
        .map_err(|_| CoreError::InvalidFormat("Ed25519 public key must be 32 bytes"))
}

pub fn encode_ed25519_sig(bytes: &[u8; 64]) -> String {
    format!("{ED25519_SIG_PREFIX}{}", b64url_encode(bytes))
}

pub fn decode_ed25519_sig(envelope: &str) -> Result<[u8; 64]> {
    let raw = envelope
        .strip_prefix(ED25519_SIG_PREFIX)
        .ok_or(CoreError::InvalidFormat("missing cfb1.sig. prefix"))?;
    let vec = b64url_decode(raw)?;
    vec.try_into()
        .map_err(|_| CoreError::InvalidFormat("Ed25519 signature must be 64 bytes"))
}

/// Strictly verifies (`verify_strict`) an Ed25519 signature.
pub fn verify_ed25519_strict(
    sign_pub_bytes: &[u8; 32],
    message: &[u8],
    sig_envelope: &str,
) -> Result<()> {
    let vk = VerifyingKey::from_bytes(sign_pub_bytes).map_err(|_| CoreError::InvalidSignature)?;
    let sig_bytes = decode_ed25519_sig(sig_envelope)?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(message, &sig)
        .map_err(|_| CoreError::InvalidSignature)
}

/// Computes the 128-bit fingerprint as 8 groups of 4 hexadecimal characters.
pub fn compute_fingerprint(enc_pub: &[u8; 32], sign_pub: &[u8; 32]) -> String {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(enc_pub);
    input[32..64].copy_from_slice(sign_pub);
    let digest = sha256_bytes(&input);
    let hex32 = hex::encode(&digest[..16]);
    format!(
        "{} {} {} {} {} {} {} {}",
        &hex32[0..4],
        &hex32[4..8],
        &hex32[8..12],
        &hex32[12..16],
        &hex32[16..20],
        &hex32[20..24],
        &hex32[24..28],
        &hex32[28..32],
    )
}

pub fn compute_fingerprint_from_envelopes(enc_pub_env: &str, sign_pub_env: &str) -> Result<String> {
    let enc_pub = decode_x25519_pub(enc_pub_env)?;
    let sign_pub = decode_ed25519_pub(sign_pub_env)?;
    Ok(compute_fingerprint(&enc_pub, &sign_pub))
}

/// Checks the last 4 hexadecimal digits of the fingerprint in constant time.
pub fn verify_fingerprint_last4(fingerprint: &str, typed_last4: &str) -> bool {
    let clean_fp: String = fingerprint
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let clean_in: String = typed_last4
        .trim()
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if clean_fp.len() != 32 || clean_in.len() != 4 {
        return false;
    }
    clean_fp.as_bytes()[28..32]
        .ct_eq(clean_in.as_bytes())
        .into()
}
