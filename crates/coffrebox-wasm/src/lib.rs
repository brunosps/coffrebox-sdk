#![forbid(unsafe_code)]
//! WebAssembly bindings (`wasm-bindgen`) over `coffrebox-core` for the TypeScript SDK and the web
//! vault.
//!
//! Two surfaces, each behind a feature:
//! - `app`: what the npm SDK uses (application token, challenge and application snapshot).
//! - `people`: the web vault (account, vaults, items, members, rotation).
//!
//! The default enables both. The npm SDK builds only `app` (`--no-default-features --features app`).

use coffrebox_core::error::CoreError;
use wasm_bindgen::prelude::*;

#[cfg(feature = "app")]
mod app;
#[cfg(feature = "app")]
pub use app::*;

#[cfg(feature = "people")]
mod people;
#[cfg(feature = "people")]
pub use people::*;

/// Error handed to JavaScript as tagged text (`[TAMPERED] ...`).
///
/// It is kept apart from `JsValue` so the exported functions also run and are tested outside
/// wasm32 (the `JsValue` is only created at the JavaScript boundary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmError(String);

impl WasmError {
    #[allow(dead_code)]
    pub(crate) fn msg(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    pub fn message(&self) -> &str {
        &self.0
    }
}

impl From<WasmError> for JsValue {
    fn from(err: WasmError) -> Self {
        JsValue::from_str(&err.0)
    }
}

#[allow(dead_code)]
pub(crate) fn map_err(err: CoreError) -> WasmError {
    let tag = match &err {
        CoreError::OwnerKeyChanged { pinned, presented } => {
            // JavaScript shows both fingerprints in the alert and only accepts the new one after
            // the person types its last 4 characters.
            return WasmError::msg(format!(
                "[OWNER_CHANGED] {}",
                serde_json::json!({ "pinned": pinned, "presented": presented })
            ));
        }
        CoreError::RollbackDetected => "ROLLBACK",
        CoreError::ManifestTampered(_) | CoreError::InvalidSignature => "TAMPERED",
        CoreError::DecryptionFailed | CoreError::HpkeFailed => "TAMPERED",
        CoreError::NotVaultOwner => "FORBIDDEN",
        CoreError::ChecksumMismatch => "CHECKSUM",
        CoreError::WeakKdfParams => "WEAK_KDF",
        CoreError::InvalidFormat(_) => "FORMAT",
        CoreError::Entropy => "ENTROPY",
    };
    WasmError::msg(format!("[{tag}] {err}"))
}

/// Returns the format version supported by the WebAssembly module.
#[wasm_bindgen]
pub fn format_version() -> u32 {
    coffrebox_core::FORMAT_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_version() {
        assert_eq!(format_version(), 1);
    }

    #[cfg(feature = "people")]
    #[test]
    fn generates_password() {
        let pw = generate_random_password(24, true).unwrap();
        assert_eq!(pw.len(), 24);
    }

    #[cfg(feature = "people")]
    #[test]
    fn prepares_password_change_for_the_web_vault() {
        use coffrebox_core::kdf::{KdfParams, derive_account_keys};
        use coffrebox_core::keys::UserKeyset;

        let signup: serde_json::Value = serde_json::from_str(
            &generate_signup_bundle(
                "Pessoa",
                "pessoa@ficticio.local",
                "cadeira-laranja-voo-tambor",
            )
            .unwrap(),
        )
        .unwrap();
        let session = signup["session"].to_string();
        let kdf = signup["request"]["kdf"].to_string();
        let user_id =
            uuid::Uuid::parse_str(signup["request"]["user_id"].as_str().unwrap()).unwrap();

        let body: serde_json::Value = serde_json::from_str(
            &prepare_password_change(
                &session,
                "cadeira-laranja-voo-tambor",
                "pavio-netuno-cobre-lenco-vinte",
                &kdf,
                "pessoa@ficticio.local",
                "Pessoa",
            )
            .unwrap(),
        )
        .unwrap();
        // `auth_key` is the current one (re-authentication), the same the signup sent.
        assert_eq!(body["auth_key"], signup["request"]["auth_key"]);
        assert_ne!(body["new_auth_key"], body["auth_key"]);
        assert_ne!(body["new_kdf"]["salt"], signup["request"]["kdf"]["salt"]);
        let new_kdf: KdfParams = serde_json::from_value(body["new_kdf"].clone()).unwrap();
        let (_, kek) =
            derive_account_keys("pavio-netuno-cobre-lenco-vinte", user_id, &new_kdf).unwrap();
        let opened = UserKeyset::open(
            body["new_encrypted_keyset"].as_str().unwrap(),
            &kek,
            user_id,
        )
        .unwrap();
        assert_eq!(
            opened.fingerprint(),
            signup["request"]["fingerprint"].as_str().unwrap()
        );

        let err = prepare_password_change(
            &session,
            "cadeira-laranja-voo-tambor",
            "cadeira-laranja-voo-tambor",
            &kdf,
            "pessoa@ficticio.local",
            "Pessoa",
        )
        .unwrap_err();
        assert!(err.message().starts_with("[SAME_PASSWORD]"));
        let err = prepare_password_change(
            &session,
            "cadeira-laranja-voo-tambor",
            "curta",
            &kdf,
            "pessoa@ficticio.local",
            "Pessoa",
        )
        .unwrap_err();
        assert!(
            err.message().starts_with("[WEAK_PASSWORD] [\"too_short\""),
            "{err:?}"
        );
    }
}
