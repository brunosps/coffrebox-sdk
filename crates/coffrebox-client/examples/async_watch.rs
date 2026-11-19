//! Async client that follows changes in the vault.
//!
//! ```sh
//! COFFREBOX_URL=https://vault.example.com COFFREBOX_TOKEN=cfb1_app_... \
//!     cargo run --example async_watch
//! ```

use coffrebox::{ClientConfig, ExposeSecret, Watch};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), coffrebox::Error> {
    let config = ClientConfig::from_env()?.with_watch(Watch::default_interval());
    let vault = coffrebox::load_with(config).await?;

    let db_url = vault.get("DATABASE_URL").await?;
    println!(
        "DATABASE_URL has {} characters",
        db_url.expose_secret().len()
    );

    let mut changes = vault.subscribe();
    while let Ok(names) = changes.recv().await {
        // Read the new values with get(); the environment keeps the startup values.
        println!("changed in the vault: {names:?}");
    }
    Ok(())
}
