//! `coffrebox::load_with`: fills the environment, `override_env`, fail-closed start, and watch
//! keeping values fresh without rewriting the environment.
//!
//! A single test on a current-thread runtime: writing the environment while other test threads
//! run is undefined behavior, so this binary has exactly one test.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use coffrebox::{ClientConfig, Error, ExposeSecret, Watch};
use common::*;

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

#[allow(unsafe_code)]
fn set(name: &str, value: Option<&str>) {
    // SAFETY: single-threaded test binary (see the module docs).
    unsafe {
        match value {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        }
    }
}

#[tokio::test]
async fn load_fills_the_environment_and_fails_closed() {
    let srv = FakeServer::start().await;
    let s = Scenario::new();
    srv.serve(&s, s.rev(2));
    let config = || ClientConfig::new(&srv.url, s.token()).with_cache_dir(temp_cache_dir("env"));

    // Fills the environment.
    set("DATABASE_URL", None);
    let client = coffrebox::load_with(config()).await.unwrap();
    assert_eq!(var("DATABASE_URL").as_deref(), Some(DB_V1));
    client.close().await;

    // Existing variables win unless override_env is true.
    set("DATABASE_URL", Some("postgres://local-override"));
    coffrebox::load_with(config()).await.unwrap();
    assert_eq!(
        var("DATABASE_URL").as_deref(),
        Some("postgres://local-override")
    );
    coffrebox::load_with(config().with_override_env(true))
        .await
        .unwrap();
    assert_eq!(var("DATABASE_URL").as_deref(), Some(DB_V1));

    // Fails closed and leaves the environment alone.
    set("DATABASE_URL", None);
    srv.set_revoked(true);
    let err = coffrebox::load_with(config()).await.unwrap_err();
    assert_eq!(err, Error::Revoked);
    assert_eq!(var("DATABASE_URL"), None);
    srv.set_revoked(false);

    // With watch on, get() follows the vault; the environment keeps the value loaded at start.
    let client = coffrebox::load_with(
        config().with_watch(Watch::EveryUnchecked(Duration::from_millis(200))),
    )
    .await
    .unwrap();
    let seen = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
    let sink = Arc::clone(&seen);
    client.on_change(move |names| sink.lock().unwrap().push(names.to_vec()));
    srv.serve(&s, s.rev(3));
    eventually(|| !seen.lock().unwrap().is_empty()).await;
    assert_eq!(
        client.get("DATABASE_URL").await.unwrap().expose_secret(),
        DB_V2
    );
    assert_eq!(var("DATABASE_URL").as_deref(), Some(DB_V1));
    client.close().await;
    set("DATABASE_URL", None);
}
