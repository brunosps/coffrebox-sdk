use core::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::encoding::{b64url_decode, b64url_encode, fill_random, sha256_hex};
use crate::error::{CoreError, Result};
use crate::vault::VaultKey;

pub const ITEM_ENVELOPE_PREFIX: &str = "cfb1.item.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemKind {
    Segredo,
    Login,
    Nota,
}

/// Full content of an item before encryption (including its `nome`, the item name).
///
/// Field names are part of the encrypted wire format (`docs/CRYPTO.md`) and stay as they are.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ItemPayload {
    pub nome: String,
    pub nota: Option<String>,
    pub tipo: ItemKind,
    pub totp: Option<String>,
    pub url: Option<String>,
    pub usuario: Option<String>,
    pub v: u32,
    pub valor: String,
}

impl Zeroize for ItemPayload {
    fn zeroize(&mut self) {
        self.nome.zeroize();
        self.valor.zeroize();
        if let Some(ref mut s) = self.nota {
            s.zeroize();
        }
        if let Some(ref mut s) = self.totp {
            s.zeroize();
        }
        if let Some(ref mut s) = self.url {
            s.zeroize();
        }
        if let Some(ref mut s) = self.usuario {
            s.zeroize();
        }
    }
}

impl Drop for ItemPayload {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ItemPayload {}

impl fmt::Debug for ItemPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemPayload")
            .field("v", &self.v)
            .field("tipo", &self.tipo)
            .field("nome", &"[REDACTED]")
            .field("valor", &"[REDACTED]")
            .finish()
    }
}

impl ItemPayload {
    pub fn new_secret(nome: impl Into<String>, valor: impl Into<String>) -> Self {
        Self {
            nome: nome.into(),
            nota: None,
            tipo: ItemKind::Segredo,
            totp: None,
            url: None,
            usuario: None,
            v: crate::FORMAT_VERSION,
            valor: valor.into(),
        }
    }
}

fn item_aad(vault_id: Uuid, item_id: Uuid, item_version: u32, key_version: u32) -> [u8; 57] {
    let mut aad = [0u8; 57];
    aad[..17].copy_from_slice(b"coffrebox/v1/item");
    aad[17..33].copy_from_slice(vault_id.as_bytes());
    aad[33..49].copy_from_slice(item_id.as_bytes());
    aad[49..53].copy_from_slice(&item_version.to_be_bytes());
    aad[53..57].copy_from_slice(&key_version.to_be_bytes());
    aad
}

/// Encrypts an item with `XChaCha20-Poly1305` under the VK and returns `(envelope, sha256_hex_64)`.
pub fn encrypt_item(
    vk: &VaultKey,
    vault_id: Uuid,
    item_id: Uuid,
    item_version: u32,
    key_version: u32,
    payload: &ItemPayload,
) -> Result<(String, String)> {
    let json_bytes = Zeroizing::new(
        serde_json::to_vec(payload).map_err(|_| CoreError::InvalidFormat("json item"))?,
    );
    let mut nonce = [0u8; 24];
    fill_random(&mut nonce)?;
    let aad = item_aad(vault_id, item_id, item_version, key_version);

    let cipher = XChaCha20Poly1305::new(&Key::from(*vk.as_bytes()));
    let ct = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &json_bytes,
                aad: &aad,
            },
        )
        .map_err(|_| CoreError::DecryptionFailed)?;

    let mut wire = Vec::with_capacity(24 + ct.len());
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&ct);
    let sha = sha256_hex(&wire);
    let env = format!("{ITEM_ENVELOPE_PREFIX}{}", b64url_encode(&wire));
    Ok((env, sha))
}

/// Computes the SHA-256 hex (64 chars) of the binary bytes of the `cfb1.item.<b64url>` envelope.
pub fn item_ciphertext_sha256(envelope: &str) -> Result<String> {
    let raw_b64 = envelope
        .strip_prefix(ITEM_ENVELOPE_PREFIX)
        .ok_or(CoreError::InvalidFormat("missing cfb1.item. prefix"))?;
    let wire = b64url_decode(raw_b64)?;
    if wire.len() < 24 + 16 {
        return Err(CoreError::InvalidFormat("truncated item envelope"));
    }
    Ok(sha256_hex(&wire))
}

/// Decrypts an item, checking the whole AAD (`vault_id`, `item_id`, `item_version`, `key_version`).
pub fn decrypt_item(
    vk: &VaultKey,
    vault_id: Uuid,
    item_id: Uuid,
    item_version: u32,
    key_version: u32,
    envelope: &str,
) -> Result<ItemPayload> {
    let raw_b64 = envelope
        .strip_prefix(ITEM_ENVELOPE_PREFIX)
        .ok_or(CoreError::InvalidFormat("missing cfb1.item. prefix"))?;
    let wire = b64url_decode(raw_b64)?;
    if wire.len() < 24 + 16 {
        return Err(CoreError::InvalidFormat("truncated item envelope"));
    }
    let (nonce, ct) = wire.split_at(24);
    let aad = item_aad(vault_id, item_id, item_version, key_version);

    let nonce_arr: [u8; 24] = nonce
        .try_into()
        .map_err(|_| CoreError::InvalidFormat("invalid nonce"))?;
    let cipher = XChaCha20Poly1305::new(&Key::from(*vk.as_bytes()));
    let plain = Zeroizing::new(
        cipher
            .decrypt(&XNonce::from(nonce_arr), Payload { msg: ct, aad: &aad })
            .map_err(|_| CoreError::DecryptionFailed)?,
    );

    let parsed: ItemPayload =
        serde_json::from_slice(&plain).map_err(|_| CoreError::InvalidFormat("item json"))?;
    if parsed.v != crate::FORMAT_VERSION {
        return Err(CoreError::InvalidFormat("unsupported item version"));
    }
    Ok(parsed)
}
