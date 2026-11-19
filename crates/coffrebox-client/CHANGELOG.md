# Changelog

## 0.1.0 (beta)

First public release.

- `coffrebox::load()` / `load_with(config)`: fill the process environment, fail closed, return the
  client. `ClientConfig::with_override_env` (default `false`).
- `coffrebox::blocking`: `load`, `load_with`, `connect` and `blocking::Client` for programs
  without tokio.
- `Watch`: background polling with `If-None-Match` (default off; `Watch::default_interval()` is 5
  minutes; minimum 30 seconds). Changes are reported by `on_change` and `subscribe()`; the
  environment is not rewritten after startup.
- `ClientConfig::new(url, token)` and `with_*` builders; the struct is `#[non_exhaustive]`.
- English error messages and `Error::code()` with the same codes as the npm SDK.
- Same encrypted on-disk cache format as `@brunosps00/coffrebox`.
