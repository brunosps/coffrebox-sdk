//! Application surface (TypeScript SDK `@brunosps00/coffrebox`).

use std::collections::BTreeMap;

use coffrebox_core::app_token::AppCredentials;
use coffrebox_core::snapshot::{EncryptedSnapshot, verify_and_decrypt_for_app};
use wasm_bindgen::prelude::*;

use crate::{WasmError, map_err};

#[wasm_bindgen]
pub fn parse_app_token_info(token: &str) -> Result<String, WasmError> {
    let creds = AppCredentials::parse_token(token).map_err(map_err)?;
    serde_json::to_string(&serde_json::json!({
        "app_id": creds.app_id(),
    }))
    .map_err(|_| WasmError::msg("[FORMAT] failed to serialize app_info"))
}

#[wasm_bindgen]
pub fn sign_app_challenge(token: &str, nonce_b64: &str) -> Result<String, WasmError> {
    let creds = AppCredentials::parse_token(token).map_err(map_err)?;
    creds.sign_auth_challenge(nonce_b64).map_err(map_err)
}

#[wasm_bindgen]
pub fn verify_and_decrypt_app_snapshot(
    snapshot_json: &str,
    token: &str,
    min_revision: Option<f64>,
) -> Result<String, WasmError> {
    let creds = AppCredentials::parse_token(token).map_err(map_err)?;
    let snapshot: EncryptedSnapshot = serde_json::from_str(snapshot_json)
        .map_err(|_| WasmError::msg("[TAMPERED] invalid snapshot JSON"))?;
    let min_rev = min_revision.map(|v| v as u64);

    let decrypted = verify_and_decrypt_for_app(&snapshot, &creds, min_rev).map_err(map_err)?;

    let mut secrets = BTreeMap::new();
    for item in &decrypted.items {
        secrets.insert(item.payload.nome.clone(), item.payload.valor.clone());
    }

    serde_json::to_string(&serde_json::json!({
        "vault_id": decrypted.vault_id,
        "vault_name": decrypted.meta.nome,
        "revision": decrypted.revision,
        "key_version": decrypted.key_version,
        "secrets": secrets,
    }))
    .map_err(|_| WasmError::msg("[FORMAT] failed to serialize secrets"))
}
