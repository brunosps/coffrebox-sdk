import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { ConfigError, TamperedError } from "./errors.js";

export interface WasmBindings {
  format_version(): number;
  parse_app_token_info(token: string): string;
  sign_app_challenge(token: string, nonceB64: string): string;
  verify_and_decrypt_app_snapshot(
    snapshotJson: string,
    token: string,
    minRevision?: number,
  ): string;
}

export interface DecryptedAppSnapshot {
  vault_id: string;
  vault_name: string;
  revision: number;
  key_version: number;
  secrets: Record<string, string>;
}

let cachedWasm: WasmBindings | null = null;

export function getWasm(): WasmBindings {
  if (cachedWasm !== null) {
    return cachedWasm;
  }
  const basePath =
    typeof __filename !== "undefined" ? __filename : fileURLToPath(import.meta.url);
  const req = createRequire(basePath);
  cachedWasm = req("../wasm/coffrebox_wasm.js") as WasmBindings;
  return cachedWasm;
}

function rawMessage(err: unknown): string {
  return typeof err === "string" ? err : err instanceof Error ? err.message : String(err);
}

/**
 * Maps a tagged error from the WebAssembly core (`[TAG] detail`) to an SDK error with an English
 * message. The original (non-secret) core message is kept as `cause` for debugging.
 */
export function mapWasmError(err: unknown, context: "token" | "snapshot"): Error {
  const msg = rawMessage(err);
  const cause = new Error(msg);
  const tag = /^\[([A-Z_]+)\]/.exec(msg)?.[1];
  if (context === "token" && (tag === "CHECKSUM" || tag === "FORMAT")) {
    return new ConfigError(
      tag === "CHECKSUM"
        ? "COFFREBOX_TOKEN is malformed (checksum mismatch, probably a copy error)."
        : "COFFREBOX_TOKEN is malformed.",
      { cause },
    );
  }
  switch (tag) {
    case "ROLLBACK":
      return new TamperedError(
        "the snapshot revision is older than one already seen (rollback).",
        { cause },
      );
    case "FORMAT":
      return new TamperedError("the snapshot format is invalid.", { cause });
    default:
      return new TamperedError("a signature or integrity check did not match.", { cause });
  }
}

export function parseAppIdFromToken(token: string): string {
  const wasm = getWasm();
  try {
    const raw = wasm.parse_app_token_info(token);
    const parsed = JSON.parse(raw) as { app_id: string };
    return parsed.app_id;
  } catch (err) {
    throw mapWasmError(err, "token");
  }
}

export function signChallengeWithWasm(token: string, nonceB64: string): string {
  const wasm = getWasm();
  try {
    return wasm.sign_app_challenge(token, nonceB64);
  } catch (err) {
    throw mapWasmError(err, "token");
  }
}

export function verifyAndDecryptSnapshotWithWasm(
  snapshotObj: unknown,
  token: string,
  minRevision?: number,
): DecryptedAppSnapshot {
  const wasm = getWasm();
  try {
    const raw = JSON.stringify(snapshotObj);
    const out = wasm.verify_and_decrypt_app_snapshot(raw, token, minRevision);
    return JSON.parse(out) as DecryptedAppSnapshot;
  } catch (err) {
    throw mapWasmError(err, "snapshot");
  }
}
