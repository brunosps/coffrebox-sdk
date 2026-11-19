use thiserror::Error;

pub type Result<T> = core::result::Result<T, CoreError>;

/// Errors of the cryptographic core (`coffrebox-core`).
///
/// No variant stores or formats secret values, keys or tokens.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoreError {
    #[error("invalid envelope format or version: {0}")]
    InvalidFormat(&'static str),

    #[error("invalid token CRC32 checksum (copy error or truncation)")]
    ChecksumMismatch,

    #[error("KDF parameters below the minimum security policy")]
    WeakKdfParams,

    #[error("failed to get cryptographic entropy from the system")]
    Entropy,

    #[error("invalid Ed25519 signature, or signed by an unauthorized key")]
    InvalidSignature,

    #[error("authenticated decryption failed (wrong key or tampered AAD)")]
    DecryptionFailed,

    #[error("HPKE encapsulation/opening failed")]
    HpkeFailed,

    #[error("manifest revision lower than the known revision (rollback attempt)")]
    RollbackDetected,

    #[error("manifest integrity violated: {0}")]
    ManifestTampered(&'static str),

    /// The owner key of an already pinned vault changed. The fields are public fingerprints, so
    /// the interface can show them to the person before any confirmation.
    #[error(
        "the vault owner key changed (pinned fingerprint: {pinned}; presented now: {presented})"
    )]
    OwnerKeyChanged { pinned: String, presented: String },

    #[error("only the vault owner can change the signed member list")]
    NotVaultOwner,
}
