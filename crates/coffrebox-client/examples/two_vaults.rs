//! One process reading two vaults: each access token opens exactly one vault.
//!
//! ```sh
//! COFFREBOX_URL=... COFFREBOX_TOKEN=... SHARED_COFFREBOX_TOKEN=... cargo run --example two_vaults
//! ```

use coffrebox::{Client, ClientConfig};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), coffrebox::Error> {
    let url = std::env::var("COFFREBOX_URL").unwrap_or_default();
    let own_token = std::env::var("COFFREBOX_TOKEN").unwrap_or_default();
    let shared_token = std::env::var("SHARED_COFFREBOX_TOKEN").unwrap_or_default();

    let own = Client::connect(ClientConfig::new(&url, own_token)).await?;
    let shared = Client::connect(ClientConfig::new(&url, shared_token)).await?;

    let db = own.get_optional("DATABASE_URL").await?;
    let api = shared.get_optional("PAYMENTS_API_KEY").await?;
    println!(
        "own vault: DATABASE_URL {}",
        if db.is_some() { "loaded" } else { "missing" }
    );
    println!(
        "shared vault: PAYMENTS_API_KEY {}",
        if api.is_some() { "loaded" } else { "missing" }
    );
    Ok(())
}
