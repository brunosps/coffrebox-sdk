export {
  type ChangeListener,
  Coffrebox,
  type CoffreboxOptions,
  DEFAULT_MAX_STALE_MS,
  DEFAULT_TTL_MS,
  DEFAULT_WATCH_INTERVAL_MS,
  type LoadIntoEnvOptions,
  type LoadOptions,
  MIN_WATCH_INTERVAL_MS,
  type OfflineMode,
  type WatchOption,
} from "./client.js";
export {
  CoffreboxError,
  type CoffreboxErrorCode,
  type CoffreboxErrorKind,
  ConfigError,
  NotFoundError,
  OfflineError,
  RevokedError,
  StaleCacheError,
  TamperedError,
} from "./errors.js";

/** Version of the snapshot and token formats this SDK reads. */
export const FORMAT_VERSION = 1;
