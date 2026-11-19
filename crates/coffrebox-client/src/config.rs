use std::path::PathBuf;
use std::time::Duration;

use secrecy::SecretString;

use crate::Error;

/// How long values stay fresh in memory before `get()` refreshes on demand.
pub const DEFAULT_TTL: Duration = Duration::from_secs(5 * 60);
/// Maximum age of the disk cache used when the server is unreachable.
pub const DEFAULT_MAX_STALE: Duration = Duration::from_secs(72 * 3600);
/// Default polling interval when [`Watch`] is on.
pub const DEFAULT_WATCH_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Smallest polling interval accepted by [`Watch::Every`].
pub const MIN_WATCH_INTERVAL: Duration = Duration::from_secs(30);

/// What to do when the server is unreachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OfflineMode {
    /// Start from the encrypted disk cache if it is younger than `max_stale` (default).
    #[default]
    UseCache,
    /// Fail with [`Error::Offline`].
    Fail,
}

/// Background polling for changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Watch {
    /// No background requests (default).
    #[default]
    Off,
    /// Ask the server every `Duration` whether the vault changed (at least [`MIN_WATCH_INTERVAL`]).
    Every(Duration),
    #[doc(hidden)]
    EveryUnchecked(Duration),
}

impl Watch {
    /// Polling every [`DEFAULT_WATCH_INTERVAL`] (5 minutes).
    pub fn default_interval() -> Self {
        Self::Every(DEFAULT_WATCH_INTERVAL)
    }

    /// Validated interval, or `None` when off.
    pub(crate) fn interval(self) -> Result<Option<Duration>, Error> {
        match self {
            Self::Off => Ok(None),
            Self::EveryUnchecked(d) => Ok(Some(d)),
            Self::Every(d) if d < MIN_WATCH_INTERVAL => Err(Error::config(format!(
                "the watch interval must be at least {} seconds",
                MIN_WATCH_INTERVAL.as_secs()
            ))),
            Self::Every(d) => Ok(Some(d)),
        }
    }
}

/// Client configuration. Build it with [`ClientConfig::from_env`] or [`ClientConfig::new`] and the
/// `with_*` methods.
#[derive(Clone)]
#[non_exhaustive]
pub struct ClientConfig {
    pub url: String,
    pub token: SecretString,
    pub cache_dir: PathBuf,
    pub ttl: Duration,
    pub max_stale: Duration,
    pub offline: OfflineMode,
    pub watch: Watch,
    /// Used by [`crate::load_with`]: when a variable already exists, `false` keeps it.
    pub override_env: bool,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("url", &self.url)
            .field("token", &"[REDACTED]")
            .field("cache_dir", &self.cache_dir)
            .field("ttl", &self.ttl)
            .field("max_stale", &self.max_stale)
            .field("offline", &self.offline)
            .field("watch", &self.watch)
            .field("override_env", &self.override_env)
            .finish()
    }
}

impl ClientConfig {
    /// Configuration with an explicit server URL and application token. The cache directory comes
    /// from `COFFREBOX_CACHE_DIR` or the user cache directory.
    pub fn new(url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            token: SecretString::from(token.into()),
            cache_dir: std::env::var_os("COFFREBOX_CACHE_DIR")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(default_cache_dir),
            ttl: DEFAULT_TTL,
            max_stale: DEFAULT_MAX_STALE,
            offline: OfflineMode::UseCache,
            watch: Watch::Off,
            override_env: false,
        }
    }

    /// Reads `COFFREBOX_URL`, `COFFREBOX_TOKEN` and `COFFREBOX_CACHE_DIR`.
    pub fn from_env() -> Result<Self, Error> {
        let url = std::env::var("COFFREBOX_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| Error::config("COFFREBOX_URL is not set"))?;
        let token = std::env::var("COFFREBOX_TOKEN")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| Error::config("COFFREBOX_TOKEN is not set"))?;
        Ok(Self::new(url, token.trim()))
    }

    pub fn with_cache_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cache_dir = dir.into();
        self
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn with_max_stale(mut self, max_stale: Duration) -> Self {
        self.max_stale = max_stale;
        self
    }

    pub fn with_offline(mut self, offline: OfflineMode) -> Self {
        self.offline = offline;
        self
    }

    pub fn with_watch(mut self, watch: Watch) -> Self {
        self.watch = watch;
        self
    }

    pub fn with_override_env(mut self, override_env: bool) -> Self {
        self.override_env = override_env;
        self
    }
}

/// `$XDG_CACHE_HOME/coffrebox`, then `~/.cache/coffrebox`, then the temp dir.
pub fn default_cache_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME")
        && !xdg.is_empty()
    {
        return PathBuf::from(xdg).join("coffrebox");
    }
    if let Ok(home) = std::env::var("HOME")
        && !home.is_empty()
    {
        return PathBuf::from(home).join(".cache").join("coffrebox");
    }
    std::env::temp_dir().join("coffrebox-cache")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_interval_has_a_floor() {
        assert_eq!(Watch::Off.interval().unwrap(), None);
        assert_eq!(
            Watch::default_interval().interval().unwrap(),
            Some(DEFAULT_WATCH_INTERVAL)
        );
        assert!(Watch::Every(Duration::from_secs(1)).interval().is_err());
    }

    #[test]
    fn debug_hides_the_token() {
        let cfg = ClientConfig::new("https://vault.example.com", "cfb1_app_fictitious");
        assert!(!format!("{cfg:?}").contains("cfb1_app_fictitious"));
    }
}
