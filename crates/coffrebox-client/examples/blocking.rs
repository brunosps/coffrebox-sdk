//! Fill the environment at the start of `main`, without tokio in your code.
//!
//! ```sh
//! COFFREBOX_URL=https://vault.example.com COFFREBOX_TOKEN=cfb1_app_... \
//!     cargo run --example blocking
//! ```

fn main() {
    // Before any other thread exists: environment writes are only safe here.
    let vault = match coffrebox::blocking::load() {
        Ok(vault) => vault,
        Err(err) => {
            // Fail closed: do not run without configuration.
            eprintln!("{}: {err}", err.code());
            std::process::exit(1);
        }
    };

    let state = if std::env::var_os("DATABASE_URL").is_some() {
        "set"
    } else {
        "missing"
    };
    println!("DATABASE_URL is {state}");
    vault.close();
}
