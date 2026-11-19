//! Async client: no background requests without watch, polling with 304, change notifications,
//! fail-closed start and two vaults in one process.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use coffrebox::{Client, ClientConfig, Error, ExposeSecret, OfflineMode, Watch};
use common::*;

const FAST: Watch = Watch::EveryUnchecked(Duration::from_millis(200));

fn config(srv: &FakeServer, s: &Scenario, tag: &str) -> ClientConfig {
    ClientConfig::new(&srv.url, s.token()).with_cache_dir(temp_cache_dir(tag))
}

fn record_changes(client: &Client) -> Arc<Mutex<Vec<Vec<String>>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    client.on_change(move |names| sink.lock().unwrap().push(names.to_vec()));
    seen
}

#[tokio::test]
async fn without_watch_there_are_no_background_requests() {
    let srv = FakeServer::start().await;
    let s = Scenario::new();
    srv.serve(&s, s.rev(2));
    let client = Client::connect(config(&srv, &s, "nowatch")).await.unwrap();
    assert!(!client.watching());
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(srv.snapshot_requests(), 1);
}

#[tokio::test]
async fn watch_with_304_changes_nothing() {
    let srv = FakeServer::start().await;
    let s = Scenario::new();
    srv.serve(&s, s.rev(2));
    let client = Client::connect(config(&srv, &s, "w304").with_watch(FAST))
        .await
        .unwrap();
    let changes = record_changes(&client);
    assert!(client.watching());
    eventually(|| srv.not_modified() >= 2).await;
    assert!(changes.lock().unwrap().is_empty());
    assert_eq!(
        client.get("DATABASE_URL").await.unwrap().expose_secret(),
        DB_V1
    );
}

#[tokio::test]
async fn watch_reports_the_names_that_changed() {
    let srv = FakeServer::start().await;
    let s = Scenario::new();
    srv.serve(&s, s.rev(2));
    let client = Client::connect(config(&srv, &s, "wchange").with_watch(FAST))
        .await
        .unwrap();
    let changes = record_changes(&client);
    let mut rx = client.subscribe();

    srv.serve(&s, s.rev(3));
    eventually(|| changes.lock().unwrap().len() == 1).await;
    assert_eq!(changes.lock().unwrap()[0], vec!["DATABASE_URL"]);
    assert_eq!(rx.recv().await.unwrap(), vec!["DATABASE_URL"]);
    assert_eq!(
        client.get("DATABASE_URL").await.unwrap().expose_secret(),
        DB_V2
    );

    srv.serve(&s, s.rev(4));
    eventually(|| changes.lock().unwrap().len() == 2).await;
    assert_eq!(changes.lock().unwrap()[1], vec!["REDIS_URL"]);

    srv.serve(&s, s.rev(5));
    eventually(|| changes.lock().unwrap().len() == 3).await;
    assert_eq!(changes.lock().unwrap()[2], vec!["DATABASE_URL"]);
    assert!(client.get_optional("DATABASE_URL").await.unwrap().is_none());
}

#[tokio::test]
async fn close_stops_the_watch() {
    let srv = FakeServer::start().await;
    let s = Scenario::new();
    srv.serve(&s, s.rev(2));
    let client = Client::connect(config(&srv, &s, "wclose").with_watch(FAST))
        .await
        .unwrap();
    client.close().await;
    assert!(!client.watching());
    let before = srv.snapshot_requests();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(srv.snapshot_requests(), before);
}

#[tokio::test]
async fn watch_interval_has_a_floor() {
    let srv = FakeServer::start().await;
    let s = Scenario::new();
    srv.serve(&s, s.rev(2));
    let err = Client::connect(
        config(&srv, &s, "wfloor").with_watch(Watch::Every(Duration::from_secs(1))),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "COFFREBOX_INVALID_CONFIG");
}

#[tokio::test]
async fn start_fails_closed() {
    let srv = FakeServer::start().await;
    let s = Scenario::new();

    srv.serve(&s, s.injected());
    let err = Client::connect(config(&srv, &s, "ftamper"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Tampered { .. }), "{err:?}");

    srv.serve(&s, s.rev(2));
    srv.set_revoked(true);
    let err = Client::connect(config(&srv, &s, "frevoked"))
        .await
        .unwrap_err();
    assert_eq!(err, Error::Revoked);

    srv.set_revoked(false);
    srv.set_down(true);
    let err = Client::connect(config(&srv, &s, "fdown"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "COFFREBOX_OFFLINE");

    let err = Client::connect(config(&srv, &s, "fdown2").with_offline(OfflineMode::Fail))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "COFFREBOX_OFFLINE");

    let err = Client::connect(ClientConfig::new("ftp://example.invalid", s.token()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "COFFREBOX_INVALID_CONFIG");
    let err = Client::connect(ClientConfig::new(&srv.url, format!("{}x", s.token())))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "COFFREBOX_INVALID_CONFIG");
}

#[tokio::test]
async fn two_clients_read_their_own_vaults() {
    let srv = FakeServer::start().await;
    let main = Scenario::new();
    let other = Scenario::new();
    srv.serve(&main, main.rev(2));
    srv.serve(
        &other,
        other.snapshot(
            1,
            &[(
                coffrebox_core::encoding::random_uuid_v4().unwrap(),
                1,
                "API_KEY",
                API_KEY,
            )],
        ),
    );
    let cache = temp_cache_dir("two");

    let a = Client::connect(ClientConfig::new(&srv.url, main.token()).with_cache_dir(&cache))
        .await
        .unwrap();
    let b = Client::connect(ClientConfig::new(&srv.url, other.token()).with_cache_dir(&cache))
        .await
        .unwrap();
    assert_eq!(a.get("DATABASE_URL").await.unwrap().expose_secret(), DB_V1);
    assert_eq!(b.get("API_KEY").await.unwrap().expose_secret(), API_KEY);
    assert!(a.get_optional("API_KEY").await.unwrap().is_none());
    assert!(b.get_optional("DATABASE_URL").await.unwrap().is_none());
    assert!(cache.join(main.app_id().to_string()).exists());
    assert!(cache.join(other.app_id().to_string()).exists());
}
