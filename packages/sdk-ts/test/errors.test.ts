import { describe, expect, it } from "vitest";
import {
  ConfigError,
  FORMAT_VERSION,
  NotFoundError,
  OfflineError,
  RevokedError,
  StaleCacheError,
  TamperedError,
} from "../src/index.js";

describe("@brunosps00/coffrebox — errors", () => {
  it("exposes format version 1", () => {
    expect(FORMAT_VERSION).toBe(1);
  });

  it("has a stable kind and code for every error", () => {
    const cases: [Error & { kind: string; code: string }, string, string][] = [
      [new NotFoundError("DATABASE_URL"), "NotFound", "COFFREBOX_NOT_FOUND"],
      [new RevokedError(), "Revoked", "COFFREBOX_REVOKED"],
      [new OfflineError(), "Offline", "COFFREBOX_OFFLINE"],
      [new TamperedError("rollback"), "Tampered", "COFFREBOX_TAMPERED"],
      [new StaleCacheError(), "StaleCache", "COFFREBOX_STALE_CACHE"],
      [new ConfigError("missing token"), "Config", "COFFREBOX_INVALID_CONFIG"],
    ];
    for (const [err, kind, code] of cases) {
      expect(err.kind).toBe(kind);
      expect(err.code).toBe(code);
    }
  });

  it("names the missing secret without exposing any value", () => {
    const err = new NotFoundError("DATABASE_URL");
    expect(err.message).toBe("Secret 'DATABASE_URL' was not found in the vault.");
    expect(err.secretName).toBe("DATABASE_URL");
  });
});
