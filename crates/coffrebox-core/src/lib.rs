#![forbid(unsafe_code)]
//! I/O-free cryptographic core of Coffrebox (`coffrebox-core`).
//!
//! Implements exactly the normative contract in `docs/CRYPTO.md`:
//! - Account derivation from the master password (`Argon2id` 64 MiB + `HKDF-SHA256`, labels
//!   `coffrebox/v2/*`)
//! - X25519 and Ed25519 key pairs encrypted under `kek` (`XChaCha20-Poly1305`)
//! - `VaultKey` sealing with `HPKE` (RFC 9180 Base: `X25519`, `HKDF-SHA256`, `ChaCha20-Poly1305`) + Ed25519 signature
//! - Encryption of items and vault names with `XChaCha20-Poly1305` and full AADs
//! - Manifest in Canonical JSON (RFC 8785) and `MemberRoster`, both signed with Ed25519 (`verify_strict`)
//! - `cfb1_app_` application credential with CRC32 and Ed25519 challenge-response

pub mod app_token;
pub mod encoding;
pub mod error;
pub mod item;
pub mod kdf;
pub mod keys;
pub mod manifest;
pub mod password_change;
pub mod password_policy;
pub mod snapshot;
pub mod trust;
pub mod vault;

/// Current version of the envelopes (`cfb1.*`) and JSON structures (`"v": 1`).
pub const FORMAT_VERSION: u32 = 1;

/// Version prefix of the serialized envelopes of protocol v1.
pub const ENVELOPE_PREFIX: &str = "cfb1.";

#[cfg(test)]
mod tests {
    use hpke::aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305;
    use hpke::kdf::HkdfSha256;
    use hpke::kem::X25519HkdfSha256;
    use hpke::{Deserializable, Kem as KemTrait, OpModeR};
    use proptest::prelude::*;
    use uuid::Uuid;

    use crate::app_token::{AppCredentials, verify_app_challenge_signature};
    use crate::encoding::{b64url_encode, crockford_encode, crockford_normalize};
    use crate::error::CoreError;
    use crate::item::{ItemPayload, decrypt_item, encrypt_item};
    use crate::kdf::{KdfParams, derive_account_keys};
    use crate::keys::{UserKeyset, verify_fingerprint_last4};
    use crate::manifest::{
        ManifestItemEntry, MemberRoster, RosterMember, VaultManifest, VaultRole,
    };
    use crate::snapshot::{
        EncryptedItemWire, EncryptedSnapshot, SnapshotRecipientEnvelope,
        verify_and_decrypt_for_app, verify_and_decrypt_for_user,
    };
    use crate::vault::{
        RecipientKind, VaultKey, VaultMeta, encrypt_vault_meta, open_vault_key, seal_vault_key,
    };

    /// Official RFC 9180 test vector, Appendix A.2.1 / A.2.1.1:
    /// mode = 0x00 (Base), kem_id = 0x0020 (DHKEM(X25519, HKDF-SHA256)),
    /// kdf_id = 0x0001 (HKDF-SHA256), aead_id = 0x0003 (ChaCha20Poly1305)
    #[test]
    fn official_rfc9180_vector_appendix_a2_1_x25519_hkdf_sha256_chacha20poly1305() {
        let ikm_r = hex::decode("1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df")
            .unwrap();
        let expected_pk_rm =
            hex::decode("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a")
                .unwrap();
        let enc = hex::decode("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a")
            .unwrap();
        let info = hex::decode("4f6465206f6e2061204772656369616e2055726e").unwrap();
        let aad_0 = hex::decode("436f756e742d30").unwrap();
        let ct_0 = hex::decode(
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
        )
        .unwrap();
        let expected_pt =
            hex::decode("4265617574792069732074727574682c20747275746820626561757479").unwrap();

        let (sk_r, pk_r) = <X25519HkdfSha256 as KemTrait>::derive_keypair(&ikm_r);
        assert_eq!(
            hpke::Serializable::to_bytes(&pk_r).as_slice(),
            expected_pk_rm.as_slice()
        );

        let encapped = <X25519HkdfSha256 as KemTrait>::EncappedKey::from_bytes(&enc).unwrap();
        let mut ctx_r = hpke::setup_receiver::<HpkeChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &sk_r,
            &encapped,
            &info,
        )
        .unwrap();

        let opened = ctx_r.open(&ct_0, &aad_0).unwrap();
        assert_eq!(opened, expected_pt);
    }

    #[test]
    fn account_derivation_keyset_and_debug_redaction() {
        let user_id = Uuid::from_u128(0x018f_3a00_0000_7000_8000_0000_0000_0001);
        let params = KdfParams::generate_default().unwrap();
        let (auth_key, kek) =
            derive_account_keys("fictitious-test-master-password", user_id, &params).unwrap();
        // Same password, account and parameters: same keys (the derivation is deterministic).
        let (auth_again, _) =
            derive_account_keys("fictitious-test-master-password", user_id, &params).unwrap();
        assert_eq!(auth_key, auth_again);
        // Another account with the same password derives another auth_key.
        let (auth_other, _) = derive_account_keys(
            "fictitious-test-master-password",
            Uuid::from_u128(7),
            &params,
        )
        .unwrap();
        assert_ne!(auth_key, auth_other);
        assert_eq!(format!("{auth_key:?}"), "AuthKey([REDACTED])");
        assert_eq!(format!("{kek:?}"), "Kek([REDACTED])");

        let keyset = UserKeyset::generate().unwrap();
        let sealed = keyset.seal(&kek, user_id).unwrap();
        let opened = UserKeyset::open(&sealed, &kek, user_id).unwrap();
        assert_eq!(keyset.fingerprint(), opened.fingerprint());

        // A wrong user ID in the AAD must fail
        let other_user = Uuid::from_u128(0x018f_3a00_0000_7000_8000_0000_0000_0099);
        assert_eq!(
            UserKeyset::open(&sealed, &kek, other_user).unwrap_err(),
            CoreError::DecryptionFailed
        );

        let fp = keyset.fingerprint();
        let last4 = &fp[fp.len() - 4..];
        assert!(verify_fingerprint_last4(&fp, &last4.to_uppercase()));
        assert!(!verify_fingerprint_last4(&fp, "zzzz"));
    }

    #[test]
    fn client_refuses_kdf_downgrade() {
        let user_id = Uuid::from_u128(1);
        let weak = KdfParams {
            salt: b64url_encode(&[7u8; 16]),
            m_kib: 4096, // below 64 MiB
            t_cost: 3,
            p_cost: 1,
        };
        assert_eq!(
            derive_account_keys("any-fictitious-password", user_id, &weak).unwrap_err(),
            CoreError::WeakKdfParams
        );
    }

    #[test]
    fn full_vault_snapshot_flow_and_tamper_defenses() {
        let owner_id = Uuid::from_u128(10);
        let app_id = Uuid::from_u128(20);
        let vault_id = Uuid::from_u128(30);
        let item_id = Uuid::from_u128(40);

        let owner_keys = UserKeyset::generate().unwrap();
        let app_creds = AppCredentials::generate(app_id, owner_keys.sign_public_bytes()).unwrap();

        // Application Ed25519 challenge-response
        let nonce_b64 = b64url_encode(&[0x42u8; 32]);
        let sig = app_creds.sign_auth_challenge(&nonce_b64).unwrap();
        verify_app_challenge_signature(&app_creds.sign_public_envelope(), app_id, &nonce_b64, &sig)
            .unwrap();

        let vk = VaultKey::generate().unwrap();
        let (encrypted_meta, meta_sha) =
            encrypt_vault_meta(&vk, vault_id, 1, &VaultMeta::new("payments-dev")).unwrap();
        let (ct, item_sha) = encrypt_item(
            &vk,
            vault_id,
            item_id,
            1,
            1,
            &ItemPayload::new_secret("DATABASE_URL", "postgres://fictitious:test@localhost/db"),
        )
        .unwrap();

        let (sealed_vk, vk_sig) = seal_vault_key(
            &vk,
            &app_creds.enc_public_bytes(),
            RecipientKind::App,
            vault_id,
            app_id,
            1,
            &owner_keys,
        )
        .unwrap();

        let manifest = VaultManifest::new(
            vault_id,
            2,
            1,
            owner_id,
            meta_sha,
            vec![ManifestItemEntry {
                id: item_id,
                sha256: item_sha.clone(),
                version: 1,
            }],
        )
        .unwrap();
        let (manifest_json, manifest_sig) = manifest.sign(&owner_keys).unwrap();

        let snapshot = EncryptedSnapshot {
            v: 1,
            vault_id,
            owner_user_id: owner_id,
            owner_sign_public_key: owner_keys.sign_public_envelope(),
            encrypted_meta,
            recipient: SnapshotRecipientEnvelope {
                kind: RecipientKind::App,
                id: app_id,
                key_version: 1,
                sealed_vk,
                vk_sig,
                granted_by_user_id: owner_id,
            },
            manifest: manifest_json,
            manifest_sig,
            member_roster: None,
            member_roster_sig: None,
            items: vec![EncryptedItemWire {
                id: item_id,
                version: 1,
                key_version: 1,
                ciphertext: ct.clone(),
                sha256: item_sha,
            }],
        };

        let decrypted = verify_and_decrypt_for_app(&snapshot, &app_creds, Some(2)).unwrap();
        assert_eq!(decrypted.meta.nome, "payments-dev");
        assert_eq!(decrypted.items.len(), 1);
        assert_eq!(decrypted.items[0].payload.nome, "DATABASE_URL");

        // Attack 1: a wrong AAD (another vault_id) fails to decrypt
        assert_eq!(
            decrypt_item(&vk, Uuid::from_u128(999), item_id, 1, 1, &ct).unwrap_err(),
            CoreError::DecryptionFailed
        );

        // Attack 2: a revision rollback is refused
        assert_eq!(
            verify_and_decrypt_for_app(&snapshot, &app_creds, Some(3)).unwrap_err(),
            CoreError::RollbackDetected
        );

        // Attack 3: the server swaps the VK envelope for an attacker's
        let attacker_keys = UserKeyset::generate().unwrap();
        let fake_vk = VaultKey::generate().unwrap();
        let (fake_sealed, fake_sig) = seal_vault_key(
            &fake_vk,
            &app_creds.enc_public_bytes(),
            RecipientKind::App,
            vault_id,
            app_id,
            1,
            &attacker_keys,
        )
        .unwrap();
        let mut swapped = snapshot.clone();
        swapped.recipient.sealed_vk = fake_sealed;
        swapped.recipient.vk_sig = fake_sig;
        assert_eq!(
            verify_and_decrypt_for_app(&swapped, &app_creds, None).unwrap_err(),
            CoreError::InvalidSignature
        );

        // Attack 4: the server injects an extra item outside the signed manifest
        let extra_id = Uuid::from_u128(41);
        let (extra_ct, extra_sha) = encrypt_item(
            &vk,
            vault_id,
            extra_id,
            1,
            1,
            &ItemPayload::new_secret("INJECTED", "malicious"),
        )
        .unwrap();
        let mut injected = snapshot.clone();
        injected.items.push(EncryptedItemWire {
            id: extra_id,
            version: 1,
            key_version: 1,
            ciphertext: extra_ct,
            sha256: extra_sha,
        });
        assert!(matches!(
            verify_and_decrypt_for_app(&injected, &app_creds, None).unwrap_err(),
            CoreError::ManifestTampered(_)
        ));
    }

    #[test]
    fn member_roster_lets_editor_write_and_blocks_viewer() {
        let owner_id = Uuid::from_u128(1);
        let editor_id = Uuid::from_u128(2);
        let viewer_id = Uuid::from_u128(3);
        let vault_id = Uuid::from_u128(100);

        let owner_keys = UserKeyset::generate().unwrap();
        let editor_keys = UserKeyset::generate().unwrap();
        let viewer_keys = UserKeyset::generate().unwrap();
        let vk = VaultKey::generate().unwrap();

        let roster = MemberRoster::new(
            vault_id,
            1,
            vec![
                RosterMember {
                    enc_pub: owner_keys.enc_public_envelope(),
                    role: VaultRole::Owner,
                    sign_pub: owner_keys.sign_public_envelope(),
                    user_id: owner_id,
                },
                RosterMember {
                    enc_pub: editor_keys.enc_public_envelope(),
                    role: VaultRole::Editor,
                    sign_pub: editor_keys.sign_public_envelope(),
                    user_id: editor_id,
                },
                RosterMember {
                    enc_pub: viewer_keys.enc_public_envelope(),
                    role: VaultRole::Viewer,
                    sign_pub: viewer_keys.sign_public_envelope(),
                    user_id: viewer_id,
                },
            ],
        )
        .unwrap();
        let (roster_json, roster_sig) = roster.sign(&owner_keys).unwrap();

        let (encrypted_meta, meta_sha) =
            encrypt_vault_meta(&vk, vault_id, 1, &VaultMeta::new("team")).unwrap();
        let (viewer_sealed_vk, viewer_vk_sig) = seal_vault_key(
            &vk,
            &viewer_keys.enc_public_bytes(),
            RecipientKind::User,
            vault_id,
            viewer_id,
            1,
            &owner_keys,
        )
        .unwrap();

        // A manifest signed by the editor must be accepted
        let editor_manifest =
            VaultManifest::new(vault_id, 1, 1, editor_id, meta_sha.clone(), vec![]).unwrap();
        let (m_json, m_sig) = editor_manifest.sign(&editor_keys).unwrap();

        let ok_snap = EncryptedSnapshot {
            v: 1,
            vault_id,
            owner_user_id: owner_id,
            owner_sign_public_key: owner_keys.sign_public_envelope(),
            encrypted_meta: encrypted_meta.clone(),
            recipient: SnapshotRecipientEnvelope {
                kind: RecipientKind::User,
                id: viewer_id,
                key_version: 1,
                sealed_vk: viewer_sealed_vk.clone(),
                vk_sig: viewer_vk_sig.clone(),
                granted_by_user_id: owner_id,
            },
            manifest: m_json,
            manifest_sig: m_sig,
            member_roster: Some(roster_json.clone()),
            member_roster_sig: Some(roster_sig.clone()),
            items: vec![],
        };
        verify_and_decrypt_for_user(
            &ok_snap,
            viewer_id,
            &viewer_keys,
            &owner_keys.sign_public_bytes(),
            None,
        )
        .unwrap();

        // A manifest signed by the viewer must be refused
        let viewer_manifest =
            VaultManifest::new(vault_id, 2, 1, viewer_id, meta_sha, vec![]).unwrap();
        let (bad_json, bad_sig) = viewer_manifest.sign(&viewer_keys).unwrap();
        let mut bad_snap = ok_snap;
        bad_snap.manifest = bad_json;
        bad_snap.manifest_sig = bad_sig;
        assert_eq!(
            verify_and_decrypt_for_user(
                &bad_snap,
                viewer_id,
                &viewer_keys,
                &owner_keys.sign_public_bytes(),
                None,
            )
            .unwrap_err(),
            CoreError::InvalidSignature
        );
    }

    proptest! {
        #[test]
        fn prop_crockford_normalizes_its_own_text_and_tolerates_lowercase(raw in any::<[u8; 16]>()) {
            let encoded = crockford_encode(&raw);
            prop_assert_eq!(crockford_normalize(&encoded).unwrap(), encoded.clone());
            let grouped = format!("{}-{}", &encoded[..4], &encoded[4..]).to_lowercase();
            prop_assert_eq!(crockford_normalize(&grouped).unwrap(), encoded);
        }

        #[test]
        fn prop_app_token_roundtrip_and_corruption_detection(
            app_id_u128 in any::<u128>(),
            x_sk in any::<[u8; 32]>(),
            ed_seed in any::<[u8; 32]>(),
            owner_pk in any::<[u8; 32]>(),
            flip_pos in 10usize..150usize,
        ) {
            let creds = AppCredentials::from_parts(Uuid::from_u128(app_id_u128), x_sk, ed_seed, owner_pk);
            let tok = creds.to_token();
            let parsed = AppCredentials::parse_token(&tok).unwrap();
            prop_assert_eq!(parsed.app_id(), creds.app_id());
            prop_assert_eq!(parsed.x25519_secret_bytes(), creds.x25519_secret_bytes());
            prop_assert_eq!(parsed.owner_sign_public_bytes(), creds.owner_sign_public_bytes());

            // Changing 1 character in the middle of the base64url must fail (CRC32 or base64)
            let mut bytes = tok.as_bytes().to_vec();
            bytes[flip_pos] = if bytes[flip_pos] == b'A' { b'B' } else { b'A' };
            let corrupted = String::from_utf8(bytes).unwrap();
            prop_assert!(AppCredentials::parse_token(&corrupted).is_err());
        }

        #[test]
        fn prop_item_aead_roundtrip_and_aad_rejection(
            vk_raw in any::<[u8; 32]>(),
            vault_u128 in any::<u128>(),
            item_u128 in any::<u128>(),
            item_ver in 1u32..1000u32,
            key_ver in 1u32..100u32,
            nome in ".{1,40}",
            valor in ".{0,120}",
        ) {
            let vk = VaultKey::from_bytes(vk_raw);
            let vault_id = Uuid::from_u128(vault_u128);
            let item_id = Uuid::from_u128(item_u128);
            let payload = ItemPayload::new_secret(nome.clone(), valor.clone());

            let (env, _sha) = encrypt_item(&vk, vault_id, item_id, item_ver, key_ver, &payload).unwrap();
            let opened = decrypt_item(&vk, vault_id, item_id, item_ver, key_ver, &env).unwrap();
            prop_assert_eq!(&opened.nome, &nome);
            prop_assert_eq!(&opened.valor, &valor);

            // Changing item_version or key_version in the AAD must fail
            prop_assert!(decrypt_item(&vk, vault_id, item_id, item_ver + 1, key_ver, &env).is_err());
            prop_assert!(decrypt_item(&vk, vault_id, item_id, item_ver, key_ver + 1, &env).is_err());
        }

        #[test]
        fn prop_hpke_vk_roundtrip(
            vk_raw in any::<[u8; 32]>(),
            vault_u128 in any::<u128>(),
            recip_u128 in any::<u128>(),
            key_ver in 1u32..50u32,
        ) {
            let grantor = UserKeyset::generate().unwrap();
            let recipient = UserKeyset::generate().unwrap();
            let vk = VaultKey::from_bytes(vk_raw);
            let vault_id = Uuid::from_u128(vault_u128);
            let recip_id = Uuid::from_u128(recip_u128);

            let (sealed, sig) = seal_vault_key(
                &vk,
                &recipient.enc_public_bytes(),
                RecipientKind::User,
                vault_id,
                recip_id,
                key_ver,
                &grantor,
            ).unwrap();

            let opened = open_vault_key(
                &sealed,
                &sig,
                recipient.enc_secret_bytes(),
                &grantor.sign_public_bytes(),
                RecipientKind::User,
                vault_id,
                recip_id,
                key_ver,
            ).unwrap();
            prop_assert_eq!(opened, vk);
        }
    }
}
