# Changelog

## 0.1.0 (beta)

First public release.

- `Coffrebox.load()`: explicit call that fills `process.env`, fails closed, and returns the client.
  Options `override` (default `false`) and `watch` (default off).
- `watch`: polling with `If-None-Match` (a `304` costs almost nothing). Default interval 5 minutes,
  minimum 30 seconds. Changes update the variables the SDK owns and call `onChange(names)`.
- `connect()` no longer polls in the background unless `watch` is set; `get()` still refreshes on
  demand after `ttlMs`.
- Errors carry a stable `code` (`COFFREBOX_*`) and English messages; new `ConfigError`.
- `offline` accepts `"use-cache"` and `"fail"`.
- The bundled WebAssembly only contains the application surface of the core.
