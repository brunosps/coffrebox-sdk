//! `coffrebox::blocking`: no tokio in the caller, environment filled at start, watch thread.
//! A single test because it writes the process environment.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use coffrebox::{ClientConfig, ExposeSecret, Watch, blocking};
use common::*;

#[test]
fn blocking_load_and_watch() {
    let srv = FakeServer::start_in_thread();
    let s = Scenario::new();
    srv.serve(&s, s.rev(2));
    let config = || ClientConfig::new(&srv.url, s.token()).with_cache_dir(temp_cache_dir("blk"));

    #[allow(unsafe_code)]
    // SAFETY: the only other thread is the fake server, which never reads the environment.
    unsafe {
        std::env::remove_var("DATABASE_URL");
    }
    let client = blocking::load_with(config()).unwrap();
    assert_eq!(std::env::var("DATABASE_URL").as_deref(), Ok(DB_V1));
    assert_eq!(client.get("DATABASE_URL").unwrap().expose_secret(), DB_V1);
    assert!(!client.watching());
    client.close();

    let watched =
        blocking::connect(config().with_watch(Watch::EveryUnchecked(Duration::from_millis(200))))
            .unwrap();
    assert!(watched.watching());
    let seen = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
    let sink = Arc::clone(&seen);
    watched.on_change(move |names| sink.lock().unwrap().push(names.to_vec()));

    srv.serve(&s, s.rev(3));
    eventually_blocking(|| !seen.lock().unwrap().is_empty());
    assert_eq!(seen.lock().unwrap()[0], vec!["DATABASE_URL"]);
    assert_eq!(watched.get("DATABASE_URL").unwrap().expose_secret(), DB_V2);

    watched.close();
    assert!(!watched.watching());
    let before = srv.snapshot_requests();
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(srv.snapshot_requests(), before);

    #[allow(unsafe_code)]
    // SAFETY: same as above.
    unsafe {
        std::env::remove_var("DATABASE_URL");
    }
}
