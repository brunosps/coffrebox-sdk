use core::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hpke::aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::encoding::{b64url_decode, b64url_encode, fill_random, sha256_bytes, sha256_hex};
use crate::error::{CoreError, Result};
use crate::keys::{UserKeyset, verify_ed25519_strict};

pub const VAULT_KEY_ENVELOPE_PREFIX: &str = "cfb1.vk.";
pub const VAULT_META_ENVELOPE_PREFIX: &str = "cfb1.vmeta.";
pub const HPKE_VAULT_KEY_INFO: &[u8] = b"coffrebox/v1/vault-key";

type HpkeKem = X25519HkdfSha256;
type HpkeKdf = HkdfSha256;
type HpkeAead = HpkeChaCha20Poly1305;

/// Recipient kind, for domain separation in the AAD and in the HPKE envelope signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecipientKind {
    User,
    App,
}

impl RecipientKind {
    pub fn tag_byte(self) -> u8 {
        match self {
            Self::User => 0x01,
            Self::App => 0x02,
        }
    }
}

/// 256-bit symmetric key of a vault (`VK`).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; 32]);

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKey([REDACTED])")
    }
}

impl PartialEq for VaultKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for VaultKey {}

impl VaultKey {
    pub fn generate() -> Result<Self> {
        let mut raw = [0u8; 32];
        fill_random(&mut raw)?;
        Ok(Self(raw))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Encrypted vault metadata (the server never sees the vault name). `nome` (name) is part of the
/// encrypted wire format and stays as it is.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct VaultMeta {
    pub nome: String,
    pub v: u32,
}

impl fmt::Debug for VaultMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultMeta([REDACTED])")
    }
}

impl VaultMeta {
    pub fn new(nome: impl Into<String>) -> Self {
        Self {
            nome: nome.into(),
            v: crate::FORMAT_VERSION,
        }
    }
}

fn vault_meta_aad(vault_id: Uuid, key_version: u32) -> [u8; 43] {
    let mut aad = [0u8; 43];
    aad[..23].copy_from_slice(b"coffrebox/v1/vault-meta");
    aad[23..39].copy_from_slice(vault_id.as_bytes());
    aad[39..43].copy_from_slice(&key_version.to_be_bytes());
    aad
}

pub fn encrypt_vault_meta(
    vk: &VaultKey,
    vault_id: Uuid,
    key_version: u32,
    meta: &VaultMeta,
) -> Result<(String, String)> {
    let plain = Zeroizing::new(
        serde_json::to_vec(meta).map_err(|_| CoreError::InvalidFormat("json vault_meta"))?,
    );
    let mut nonce = [0u8; 24];
    fill_random(&mut nonce)?;
    let aad = vault_meta_aad(vault_id, key_version);

    let cipher = XChaCha20Poly1305::new(&Key::from(*vk.as_bytes()));
    let ct = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plain,
                aad: &aad,
            },
        )
        .map_err(|_| CoreError::DecryptionFailed)?;

    let mut wire = Vec::with_capacity(24 + ct.len());
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&ct);
    let sha = sha256_hex(&wire);
    let env = format!("{VAULT_META_ENVELOPE_PREFIX}{}", b64url_encode(&wire));
    Ok((env, sha))
}

pub fn vault_meta_sha256(envelope: &str) -> Result<String> {
    let raw_b64 = envelope
        .strip_prefix(VAULT_META_ENVELOPE_PREFIX)
        .ok_or(CoreError::InvalidFormat("missing cfb1.vmeta. prefix"))?;
    let wire = b64url_decode(raw_b64)?;
    if wire.len() < 24 + 16 {
        return Err(CoreError::InvalidFormat("truncated vmeta envelope"));
    }
    Ok(sha256_hex(&wire))
}

pub fn decrypt_vault_meta(
    vk: &VaultKey,
    vault_id: Uuid,
    key_version: u32,
    envelope: &str,
) -> Result<VaultMeta> {
    let raw_b64 = envelope
        .strip_prefix(VAULT_META_ENVELOPE_PREFIX)
        .ok_or(CoreError::InvalidFormat("missing cfb1.vmeta. prefix"))?;
    let wire = b64url_decode(raw_b64)?;
    if wire.len() < 24 + 16 {
        return Err(CoreError::InvalidFormat("truncated vmeta envelope"));
    }
    let (nonce, ct) = wire.split_at(24);
    let aad = vault_meta_aad(vault_id, key_version);

    let nonce_arr: [u8; 24] = nonce
        .try_into()
        .map_err(|_| CoreError::InvalidFormat("invalid nonce"))?;
    let cipher = XChaCha20Poly1305::new(&Key::from(*vk.as_bytes()));
    let plain = Zeroizing::new(
        cipher
            .decrypt(&XNonce::from(nonce_arr), Payload { msg: ct, aad: &aad })
            .map_err(|_| CoreError::DecryptionFailed)?,
    );

    let parsed: VaultMeta =
        serde_json::from_slice(&plain).map_err(|_| CoreError::InvalidFormat("vmeta json"))?;
    if parsed.v != crate::FORMAT_VERSION {
        return Err(CoreError::InvalidFormat("unsupported vmeta version"));
    }
    Ok(parsed)
}

fn hpke_vk_aad(
    recipient_kind: RecipientKind,
    vault_id: Uuid,
    recipient_id: Uuid,
    key_version: u32,
) -> [u8; 56] {
    let mut aad = [0u8; 56];
    aad[..19].copy_from_slice(b"coffrebox/v1/vk-aad");
    aad[19] = recipient_kind.tag_byte();
    aad[20..36].copy_from_slice(vault_id.as_bytes());
    aad[36..52].copy_from_slice(recipient_id.as_bytes());
    aad[52..56].copy_from_slice(&key_version.to_be_bytes());
    aad
}

fn vk_grant_sig_message(
    recipient_kind: RecipientKind,
    vault_id: Uuid,
    recipient_id: Uuid,
    key_version: u32,
    raw_hpke_envelope_80b: &[u8],
) -> [u8; 90] {
    let env_hash = sha256_bytes(raw_hpke_envelope_80b);
    let mut msg = [0u8; 90];
    msg[..21].copy_from_slice(b"coffrebox/v1/vk-grant");
    msg[21] = recipient_kind.tag_byte();
    msg[22..38].copy_from_slice(vault_id.as_bytes());
    msg[38..54].copy_from_slice(recipient_id.as_bytes());
    msg[54..58].copy_from_slice(&key_version.to_be_bytes());
    msg[58..90].copy_from_slice(&env_hash);
    msg
}

/// Seals the `VaultKey` with HPKE (RFC 9180 Base) for the recipient and signs the envelope with Ed25519.
pub fn seal_vault_key(
    vk: &VaultKey,
    recipient_enc_pub: &[u8; 32],
    recipient_kind: RecipientKind,
    vault_id: Uuid,
    recipient_id: Uuid,
    key_version: u32,
    grantor_keys: &UserKeyset,
) -> Result<(String, String)> {
    let recip_pk = <HpkeKem as KemTrait>::PublicKey::from_bytes(recipient_enc_pub)
        .map_err(|_| CoreError::HpkeFailed)?;
    let aad = hpke_vk_aad(recipient_kind, vault_id, recipient_id, key_version);

    let (encapped_key, ciphertext) = hpke::single_shot_seal::<HpkeAead, HpkeKdf, HpkeKem>(
        &OpModeS::Base,
        &recip_pk,
        HPKE_VAULT_KEY_INFO,
        vk.as_bytes(),
        &aad,
    )
    .map_err(|_| CoreError::HpkeFailed)?;

    let enc_bytes = encapped_key.to_bytes();
    let mut wire = Vec::with_capacity(enc_bytes.len() + ciphertext.len());
    wire.extend_from_slice(&enc_bytes);
    wire.extend_from_slice(&ciphertext);

    let sig_msg = vk_grant_sig_message(recipient_kind, vault_id, recipient_id, key_version, &wire);
    let vk_sig = grantor_keys.sign_bytes(&sig_msg);
    let sealed_vk = format!("{VAULT_KEY_ENVELOPE_PREFIX}{}", b64url_encode(&wire));

    Ok((sealed_vk, vk_sig))
}

/// Verifies the grantor's Ed25519 signature first, then opens the `VaultKey` through HPKE.
#[allow(clippy::too_many_arguments)]
pub fn open_vault_key(
    sealed_vk: &str,
    vk_sig: &str,
    recipient_enc_sk: &[u8; 32],
    grantor_sign_pub: &[u8; 32],
    recipient_kind: RecipientKind,
    vault_id: Uuid,
    recipient_id: Uuid,
    key_version: u32,
) -> Result<VaultKey> {
    let raw_b64 = sealed_vk
        .strip_prefix(VAULT_KEY_ENVELOPE_PREFIX)
        .ok_or(CoreError::InvalidFormat("missing cfb1.vk. prefix"))?;
    let wire = b64url_decode(raw_b64)?;
    if wire.len() != 80 {
        return Err(CoreError::InvalidFormat(
            "HPKE envelope must be 80 bytes (32B enc + 48B ct)",
        ));
    }

    let sig_msg = vk_grant_sig_message(recipient_kind, vault_id, recipient_id, key_version, &wire);
    verify_ed25519_strict(grantor_sign_pub, &sig_msg, vk_sig)?;

    let (enc_slice, ct_slice) = wire.split_at(32);
    let recip_sk = <HpkeKem as KemTrait>::PrivateKey::from_bytes(recipient_enc_sk)
        .map_err(|_| CoreError::HpkeFailed)?;
    let encapped_key = <HpkeKem as KemTrait>::EncappedKey::from_bytes(enc_slice)
        .map_err(|_| CoreError::HpkeFailed)?;
    let aad = hpke_vk_aad(recipient_kind, vault_id, recipient_id, key_version);

    let plaintext = Zeroizing::new(
        hpke::single_shot_open::<HpkeAead, HpkeKdf, HpkeKem>(
            &OpModeR::Base,
            &recip_sk,
            &encapped_key,
            HPKE_VAULT_KEY_INFO,
            ct_slice,
            &aad,
        )
        .map_err(|_| CoreError::HpkeFailed)?,
    );

    let vk_bytes: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::HpkeFailed)?;
    Ok(VaultKey(vk_bytes))
}
