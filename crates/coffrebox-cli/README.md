# coffrebox-cli

`coffre`, the command-line client for [Coffrebox](https://coffrebox.net/docs/en), a zero-knowledge
secrets vault: the server stores your secrets but can never read them.

- **`coffre run -- <command>`** runs any program (Python, Go, PHP, Java, Ruby, .NET, shell, CI
  steps) with your vault's secrets in its environment. No SDK and no `.env` file on disk.
- Manage vaults, secrets, application accesses and shared-vault members from the terminal. Your
  master password is typed here and never leaves your computer: only a key derived from it goes to
  the server.

> **Beta (0.x).** Not externally audited yet. The CLI's messages are in Portuguese for now.

## Install

Prebuilt binaries for Linux (static, any distribution), macOS and Windows, with a `SHA256SUMS`
file, are attached to each [GitHub release](https://github.com/brunosps/coffrebox-sdk/releases).
Or build from source (Rust 1.89+):

```sh
cargo install coffrebox-cli --locked
```

## Use

```sh
# On a server or in CI: COFFREBOX_URL and COFFREBOX_TOKEN are in the environment
coffre run -- node server.js

# On your computer, with your own account
coffre login --server https://coffrebox.net --email you@example.com
coffre run --vault "Payments API" -- npm run dev
```

With `COFFREBOX_TOKEN` set, the CLI reads that access's vault and the token is **not** passed to
the program, which only receives the secrets. On Linux and macOS the program replaces the CLI in
the same process, so it gets signals directly and its exit code is the CLI's exit code.

Full guide: <https://coffrebox.net/docs/en/cli>.

## License

MIT
