/** Error category, stable across versions (also available as `code`). */
export type CoffreboxErrorKind =
  | "NotFound"
  | "Revoked"
  | "Offline"
  | "Tampered"
  | "StaleCache"
  | "Config";

/** Stable machine-readable error code. */
export type CoffreboxErrorCode =
  | "COFFREBOX_NOT_FOUND"
  | "COFFREBOX_REVOKED"
  | "COFFREBOX_OFFLINE"
  | "COFFREBOX_TAMPERED"
  | "COFFREBOX_STALE_CACHE"
  | "COFFREBOX_INVALID_CONFIG";

const CODES: Record<CoffreboxErrorKind, CoffreboxErrorCode> = {
  NotFound: "COFFREBOX_NOT_FOUND",
  Revoked: "COFFREBOX_REVOKED",
  Offline: "COFFREBOX_OFFLINE",
  Tampered: "COFFREBOX_TAMPERED",
  StaleCache: "COFFREBOX_STALE_CACHE",
  Config: "COFFREBOX_INVALID_CONFIG",
};

/**
 * Base class for every error thrown by the SDK.
 *
 * Messages never contain secret values, tokens or access tokens.
 */
export class CoffreboxError extends Error {
  public readonly kind: CoffreboxErrorKind;
  public readonly code: CoffreboxErrorCode;

  public constructor(kind: CoffreboxErrorKind, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = `Coffrebox${kind}Error`;
    this.kind = kind;
    this.code = CODES[kind];
  }
}

/** The secret does not exist in the vault. */
export class NotFoundError extends CoffreboxError {
  public readonly secretName: string;

  public constructor(secretName: string) {
    super("NotFound", `Secret '${secretName}' was not found in the vault.`);
    this.secretName = secretName;
  }
}

/** The server rejected this application (revoked, unknown or unauthorized). The disk cache is wiped. */
export class RevokedError extends CoffreboxError {
  public constructor() {
    super("Revoked", "The application access was revoked or is not authorized by the server.");
  }
}

/** The server is unreachable and no usable cache is available (or `offline: "fail"`). */
export class OfflineError extends CoffreboxError {
  public constructor(detail = "The server is unreachable and no offline cache is available.") {
    super("Offline", detail);
  }
}

/** A signature, integrity or rollback check failed. Nothing from that response is used. */
export class TamperedError extends CoffreboxError {
  public constructor(reason: string, options?: { cause?: unknown }) {
    super("Tampered", `Snapshot integrity check failed: ${reason}`, options);
  }
}

/** The server is unreachable and the encrypted disk cache is older than `maxStaleMs`. */
export class StaleCacheError extends CoffreboxError {
  public constructor() {
    super(
      "StaleCache",
      "The server is unreachable and the encrypted disk cache is older than maxStaleMs.",
    );
  }
}

/** Invalid or missing configuration (URL, token, options), or the client was closed. */
export class ConfigError extends CoffreboxError {
  public constructor(message: string, options?: { cause?: unknown }) {
    super("Config", message, options);
  }
}
