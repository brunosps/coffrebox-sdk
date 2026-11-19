use coffrebox_core::error::CoreError;
use thiserror::Error;

/// Errors returned by the SDK. Messages never contain secret values, tokens or access tokens.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The secret does not exist in the vault.
    #[error("secret '{key}' was not found in the vault")]
    NotFound { key: String },

    /// The server rejected this application (revoked, unknown or unauthorized). The disk cache is wiped.
    #[error("the application access was revoked or is not authorized by the server")]
    Revoked,

    /// The server is unreachable and no usable cache is available (or [`crate::OfflineMode::Fail`]).
    #[error("the server is unreachable and no offline cache is available: {detail}")]
    Offline { detail: String },

    /// A signature, integrity or rollback check failed. Nothing from that response is used.
    #[error("snapshot integrity check failed: {reason}")]
    Tampered { reason: String },

    /// The server is unreachable and the encrypted disk cache is older than `max_stale`.
    #[error("the server is unreachable and the encrypted disk cache is older than max_stale")]
    StaleCache,

    /// Invalid or missing configuration (URL, token, options) or an I/O problem with the cache dir.
    #[error("invalid Coffrebox configuration: {0}")]
    InvalidConfig(String),
}

impl Error {
    /// Stable machine-readable code, identical to the `code` of the npm SDK errors.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "COFFREBOX_NOT_FOUND",
            Self::Revoked => "COFFREBOX_REVOKED",
            Self::Offline { .. } => "COFFREBOX_OFFLINE",
            Self::Tampered { .. } => "COFFREBOX_TAMPERED",
            Self::StaleCache => "COFFREBOX_STALE_CACHE",
            Self::InvalidConfig(_) => "COFFREBOX_INVALID_CONFIG",
        }
    }

    pub(crate) fn offline(detail: impl Into<String>) -> Self {
        Self::Offline {
            detail: detail.into(),
        }
    }

    pub(crate) fn tampered(reason: impl Into<String>) -> Self {
        Self::Tampered {
            reason: reason.into(),
        }
    }

    pub(crate) fn config(message: impl Into<String>) -> Self {
        Self::InvalidConfig(message.into())
    }

    /// Error from the core while parsing the application token.
    pub(crate) fn from_token(err: CoreError) -> Self {
        match err {
            CoreError::ChecksumMismatch => Self::config(
                "COFFREBOX_TOKEN is malformed (checksum mismatch, probably a copy error)",
            ),
            _ => Self::config("COFFREBOX_TOKEN is malformed"),
        }
    }
}

/// Error from the core while verifying a snapshot.
impl From<CoreError> for Error {
    fn from(err: CoreError) -> Self {
        match err {
            CoreError::RollbackDetected => {
                Self::tampered("the snapshot revision is older than one already seen (rollback)")
            }
            CoreError::InvalidFormat(_) => Self::tampered("the snapshot format is invalid"),
            _ => Self::tampered("a signature or integrity check did not match"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_name_the_secret_without_values() {
        let err = Error::NotFound {
            key: "DATABASE_URL".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "secret 'DATABASE_URL' was not found in the vault"
        );
        assert_eq!(err.code(), "COFFREBOX_NOT_FOUND");
    }

    #[test]
    fn codes_match_the_npm_sdk() {
        assert_eq!(Error::Revoked.code(), "COFFREBOX_REVOKED");
        assert_eq!(Error::offline("x").code(), "COFFREBOX_OFFLINE");
        assert_eq!(Error::tampered("x").code(), "COFFREBOX_TAMPERED");
        assert_eq!(Error::StaleCache.code(), "COFFREBOX_STALE_CACHE");
        assert_eq!(Error::config("x").code(), "COFFREBOX_INVALID_CONFIG");
        assert_eq!(
            Error::from(CoreError::RollbackDetected).code(),
            "COFFREBOX_TAMPERED"
        );
    }
}
