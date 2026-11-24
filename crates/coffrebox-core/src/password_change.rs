//! Master password change, client side (CLI and web vault through WASM).
//!
//! The person's key pairs do not change: the same `enc_sk` and `sign_seed` are sealed again under
//! the `kek` of the new password, with a fresh Argon2id salt. Public keys, fingerprint, `user_id`
//! and vault access stay the same. The server only swaps the password verifier, the KDF
//! parameters and the keyset envelope (see `docs/CRYPTO.md` §4.6).

use subtle::ConstantTimeEq;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::kdf::{AuthKey, KdfParams, derive_account_keys};
use crate::keys::UserKeyset;
use crate::password_policy::{MasterPasswordProblem, check_master_password};

/// What goes to `POST /api/v1/auth/password/change` besides the re-authentication fields.
#[derive(Debug, Clone)]
pub struct NewPasswordMaterial {
    /// `cfb1.auth.` derived from the new password and the new KDF parameters.
    pub auth_key: AuthKey,
    /// New Argon2id parameters, with a fresh 16-byte salt.
    pub kdf: KdfParams,
    /// The same key pairs sealed under the new `kek` (`cfb1.keyset.`).
    pub encrypted_keyset: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PasswordChangeError {
    #[error("the new master password is the same as the current one")]
    SameAsCurrent,

    #[error("the new master password does not meet the minimum policy")]
    Weak(Vec<MasterPasswordProblem>),

    #[error(transparent)]
    Core(#[from] CoreError),
}

/// Prepares a master password change for the account `user_id` whose key pairs are `keyset`.
///
/// Refuses a new password equal to the current one (after NFKC) or one that fails
/// [`check_master_password`]. Before returning, it opens the new envelope with the new `kek` and
/// checks that it gives back exactly the same key pairs: a broken envelope would lock the person
/// out of the account for good.
pub fn prepare_password_change(
    keyset: &UserKeyset,
    user_id: Uuid,
    current_password: &str,
    new_password: &str,
    current_kdf: &KdfParams,
    email: &str,
    name: &str,
) -> Result<NewPasswordMaterial, PasswordChangeError> {
    let current_nfkc = Zeroizing::new(current_password.nfkc().collect::<String>());
    let new_nfkc = Zeroizing::new(new_password.nfkc().collect::<String>());
    if bool::from(current_nfkc.as_bytes().ct_eq(new_nfkc.as_bytes())) {
        return Err(PasswordChangeError::SameAsCurrent);
    }
    let problems = check_master_password(new_password, email, name);
    if !problems.is_empty() {
        return Err(PasswordChangeError::Weak(problems));
    }

    // A fresh salt: never the one the current password used.
    let kdf = loop {
        let candidate = KdfParams::generate_default()?;
        if candidate.salt != current_kdf.salt {
            break candidate;
        }
    };
    let (auth_key, kek) = derive_account_keys(new_password, user_id, &kdf)?;
    let encrypted_keyset = keyset.seal(&kek, user_id)?;

    let reopened = UserKeyset::open(&encrypted_keyset, &kek, user_id)?;
    let same_enc = reopened.enc_secret_bytes().ct_eq(keyset.enc_secret_bytes());
    let same_sign = reopened.sign_seed_bytes().ct_eq(keyset.sign_seed_bytes());
    if !bool::from(same_enc & same_sign) {
        return Err(CoreError::InvalidFormat("keyset round-trip check failed").into());
    }
    crate::keys::check_keyset_envelope_shape(&encrypted_keyset)?;

    Ok(NewPasswordMaterial {
        auth_key,
        kdf,
        encrypted_keyset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::random_uuid_v4;
    use crate::keys::{KEYSET_ENVELOPE_PREFIX, check_keyset_envelope_shape};

    const CURRENT: &str = "cadeira-laranja-voo-tambor-ficticia";
    const NEW: &str = "pavio-netuno-cobre-lenco-vinte";

    #[test]
    fn new_envelope_opens_with_the_new_password_only() {
        let user_id = random_uuid_v4().unwrap();
        let current_kdf = KdfParams::generate_default().unwrap();
        let keyset = UserKeyset::generate().unwrap();
        let material = prepare_password_change(
            &keyset,
            user_id,
            CURRENT,
            NEW,
            &current_kdf,
            "pessoa@ficticio.local",
            "Pessoa",
        )
        .unwrap();

        assert_ne!(material.kdf.salt, current_kdf.salt);
        material.kdf.decode_and_validate().unwrap();
        check_keyset_envelope_shape(&material.encrypted_keyset).unwrap();

        // Same derivation the login does with the new password and the new parameters.
        let (auth, kek) = derive_account_keys(NEW, user_id, &material.kdf).unwrap();
        assert_eq!(auth, material.auth_key);
        let opened = UserKeyset::open(&material.encrypted_keyset, &kek, user_id).unwrap();
        assert_eq!(opened.fingerprint(), keyset.fingerprint());
        assert_eq!(opened.enc_secret_bytes(), keyset.enc_secret_bytes());
        assert_eq!(opened.sign_seed_bytes(), keyset.sign_seed_bytes());

        // The old password does not open the new envelope, even with the new parameters.
        let (old_auth, old_kek) = derive_account_keys(CURRENT, user_id, &material.kdf).unwrap();
        assert_ne!(old_auth, material.auth_key);
        assert_eq!(
            UserKeyset::open(&material.encrypted_keyset, &old_kek, user_id).unwrap_err(),
            CoreError::DecryptionFailed
        );
        // Nor does another account id (AAD).
        let other = random_uuid_v4().unwrap();
        assert!(UserKeyset::open(&material.encrypted_keyset, &kek, other).is_err());
    }

    #[test]
    fn refuses_same_password_even_with_another_unicode_form() {
        let user_id = random_uuid_v4().unwrap();
        let kdf = KdfParams::generate_default().unwrap();
        let keyset = UserKeyset::generate().unwrap();
        // "ﬁ" (U+FB01) becomes "fi" under NFKC.
        let err = prepare_password_change(
            &keyset,
            user_id,
            "ﬁgo-laranja-voo-tambor",
            "figo-laranja-voo-tambor",
            &kdf,
            "pessoa@ficticio.local",
            "Pessoa",
        )
        .unwrap_err();
        assert_eq!(err, PasswordChangeError::SameAsCurrent);
    }

    #[test]
    fn refuses_weak_new_password_with_the_policy_problems() {
        let user_id = random_uuid_v4().unwrap();
        let kdf = KdfParams::generate_default().unwrap();
        let keyset = UserKeyset::generate().unwrap();
        let err = prepare_password_change(
            &keyset,
            user_id,
            CURRENT,
            "senha123",
            &kdf,
            "pessoa@ficticio.local",
            "Pessoa",
        )
        .unwrap_err();
        match err {
            PasswordChangeError::Weak(problems) => {
                assert!(problems.contains(&MasterPasswordProblem::TooShort));
                assert!(problems.contains(&MasterPasswordProblem::Common));
            }
            other => panic!("expected Weak, got {other:?}"),
        }
        let err = prepare_password_change(
            &keyset,
            user_id,
            CURRENT,
            "pessoa-ficticio-local-2026",
            &kdf,
            "pessoa@ficticio.local",
            "Pessoa",
        )
        .unwrap_err();
        assert_eq!(
            err,
            PasswordChangeError::Weak(vec![MasterPasswordProblem::ContainsPersonalInfo])
        );
    }

    #[test]
    fn keyset_shape_check_rejects_what_the_client_could_never_open() {
        let user_id = random_uuid_v4().unwrap();
        let kdf = KdfParams::generate_default().unwrap();
        let (_, kek) = derive_account_keys(CURRENT, user_id, &kdf).unwrap();
        let good = UserKeyset::generate().unwrap().seal(&kek, user_id).unwrap();
        check_keyset_envelope_shape(&good).unwrap();

        let body = good.strip_prefix(KEYSET_ENVELOPE_PREFIX).unwrap();
        for bad in [
            format!("cfb1.vk.{body}"),
            format!("{KEYSET_ENVELOPE_PREFIX}{}", &body[..body.len() - 4]),
            format!("{KEYSET_ENVELOPE_PREFIX}{body}AAAA"),
            format!("{KEYSET_ENVELOPE_PREFIX}{body}="),
            format!("{KEYSET_ENVELOPE_PREFIX}not*base64"),
            KEYSET_ENVELOPE_PREFIX.to_string(),
        ] {
            assert!(check_keyset_envelope_shape(&bad).is_err(), "accepted {bad}");
        }
    }
}
