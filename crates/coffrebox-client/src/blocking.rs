//! Blocking API for programs without tokio (CLIs, scripts, `build.rs`).
//!
//! The client owns a single-threaded tokio runtime and drives it on the calling thread. With
//! [`crate::Watch`] on, one extra thread wakes up every interval to check the server. Do not call
//! these functions from inside an async runtime (tokio panics when a runtime is nested).
//!
//! ```no_run
//! fn main() -> Result<(), coffrebox::Error> {
//!     // First thing in main, before any thread exists: fills the environment.
//!     let vault = coffrebox::blocking::load()?;
//!     let db = std::env::var("DATABASE_URL").expect("set by Coffrebox");
//!     # let _ = (vault, db);
//!     Ok(())
//! }
//! ```

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use secrecy::SecretString;

use crate::{ClientConfig, Error, Watch};

type SharedRuntime = Arc<Mutex<tokio::runtime::Runtime>>;

struct WatchThread {
    stop: Arc<(Mutex<bool>, Condvar)>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for WatchThread {
    fn drop(&mut self) {
        let (lock, cvar) = &*self.stop;
        if let Ok(mut stopped) = lock.lock() {
            *stopped = true;
        }
        cvar.notify_all();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Blocking client. See [`crate::Client`] for the meaning of each method.
pub struct Client {
    rt: SharedRuntime,
    inner: crate::Client,
    watch: Mutex<Option<WatchThread>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("coffrebox::blocking::Client")
            .field(&self.inner)
            .finish()
    }
}

fn new_runtime() -> Result<SharedRuntime, Error> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map(|rt| Arc::new(Mutex::new(rt)))
        .map_err(|e| Error::config(format!("could not start the internal runtime: {e}")))
}

fn run<F: Future>(rt: &SharedRuntime, fut: F) -> F::Output {
    let guard = rt.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.block_on(fut)
}

/// Reads `COFFREBOX_URL` and `COFFREBOX_TOKEN`, fills the process environment and returns the
/// client. Fails closed (returns an error) if the secrets cannot be loaded.
///
/// Call it at the very start of `main`, before any other thread exists.
pub fn load() -> Result<Client, Error> {
    load_with(ClientConfig::from_env()?)
}

/// [`load`] with explicit options (`override_env`, `watch`, …).
pub fn load_with(config: ClientConfig) -> Result<Client, Error> {
    let watch = config.watch.interval()?;
    let rt = new_runtime()?;
    let inner = run(&rt, crate::load_with(config.with_watch(Watch::Off)))?;
    Ok(Client::with_watch(rt, inner, watch))
}

/// Connects without touching the process environment.
pub fn connect(config: ClientConfig) -> Result<Client, Error> {
    let watch = config.watch.interval()?;
    let rt = new_runtime()?;
    let inner = run(&rt, crate::Client::connect(config.with_watch(Watch::Off)))?;
    Ok(Client::with_watch(rt, inner, watch))
}

impl Client {
    fn with_watch(rt: SharedRuntime, inner: crate::Client, watch: Option<Duration>) -> Self {
        let client = Self {
            rt,
            inner,
            watch: Mutex::new(None),
        };
        if let Some(interval) = watch {
            client.start_watch(interval);
        }
        client
    }

    fn start_watch(&self, interval: Duration) {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let rt = Arc::clone(&self.rt);
        let inner = self.inner.clone();
        let thread_stop = Arc::clone(&stop);
        let handle = std::thread::Builder::new()
            .name("coffrebox-watch".to_string())
            .spawn(move || {
                let (lock, cvar) = &*thread_stop;
                loop {
                    let Ok(guard) = lock.lock() else { return };
                    let Ok((stopped, _)) =
                        cvar.wait_timeout_while(guard, interval, |stopped| !*stopped)
                    else {
                        return;
                    };
                    if *stopped {
                        return;
                    }
                    drop(stopped);
                    if let Err(err) = run(&rt, inner.refresh()) {
                        tracing::warn!(
                            error = %err,
                            "Coffrebox background check failed; keeping the last known secrets"
                        );
                    }
                }
            });
        if let Ok(handle) = handle
            && let Ok(mut slot) = self.watch.lock()
        {
            *slot = Some(WatchThread {
                stop,
                handle: Some(handle),
            });
        }
    }

    pub fn get(&self, name: &str) -> Result<SecretString, Error> {
        run(&self.rt, self.inner.get(name))
    }

    pub fn get_optional(&self, name: &str) -> Result<Option<SecretString>, Error> {
        run(&self.rt, self.inner.get_optional(name))
    }

    pub fn all(&self) -> Result<BTreeMap<String, SecretString>, Error> {
        run(&self.rt, self.inner.all())
    }

    pub fn refresh(&self) -> Result<(), Error> {
        run(&self.rt, self.inner.refresh())
    }

    /// Calls `callback` with the names of the secrets that changed (sorted).
    pub fn on_change<F>(&self, callback: F)
    where
        F: Fn(&[String]) + Send + Sync + 'static,
    {
        self.inner.on_change(callback);
    }

    pub fn watching(&self) -> bool {
        self.watch
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    /// See [`crate::Client::load_into_env`] (same thread-safety contract).
    pub fn load_into_env(&self) -> Result<(), Error> {
        self.inner.load_into_env()
    }

    /// Stops the watch thread and forgets the secrets kept in memory.
    pub fn close(&self) {
        if let Ok(mut slot) = self.watch.lock() {
            slot.take();
        }
        run(&self.rt, self.inner.close());
    }

    /// The asynchronous client behind this one.
    pub fn as_async(&self) -> &crate::Client {
        &self.inner
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.watch.lock() {
            slot.take();
        }
    }
}
