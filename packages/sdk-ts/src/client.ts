import * as path from "node:path";
import {
  readLatestDiskSnapshot,
  resolveDefaultCacheDir,
  wipeAppCacheDir,
  writeAtomicSnapshot,
} from "./cache.js";
import {
  ConfigError,
  NotFoundError,
  OfflineError,
  RevokedError,
  StaleCacheError,
  TamperedError,
} from "./errors.js";
import {
  parseAppIdFromToken,
  signChallengeWithWasm,
  verifyAndDecryptSnapshotWithWasm,
} from "./wasm.js";

/** What to do when the server is unreachable. */
export type OfflineMode = "use-cache" | "fail";

/** Live updates: `true` uses the default interval (5 minutes). */
export type WatchOption = boolean | { intervalMs?: number };

export interface CoffreboxOptions {
  /** Server URL. Default: `COFFREBOX_URL`. */
  url?: string;
  /** Application access token (`cfb1_app_…`). Default: `COFFREBOX_TOKEN`. */
  token?: string;
  /** Where the encrypted snapshot is cached. Default: `COFFREBOX_CACHE_DIR`, then the user cache dir. */
  cacheDir?: string;
  /** How long values stay fresh in memory before `get()` refreshes on demand. Default: 5 minutes. */
  ttlMs?: number;
  /** Maximum age of the disk cache when the server is unreachable. Default: 72 hours. */
  maxStaleMs?: number;
  /** `"use-cache"` (default) starts from the encrypted disk cache when the server is down; `"fail"` does not. */
  offline?: OfflineMode;
  /** Poll the vault for changes in the background. Default: off (no background requests). */
  watch?: WatchOption;
  /** Receives warnings (offline mode, failed background checks). Default: `console.warn`. */
  warn?: (message: string) => void;
}

export interface LoadOptions extends CoffreboxOptions {
  /** When a variable already exists in `process.env`: `false` (default) keeps it, `true` replaces it. */
  override?: boolean;
}

export interface LoadIntoEnvOptions {
  override?: boolean;
}

export type ChangeListener = (names: string[]) => void;

export const DEFAULT_TTL_MS = 5 * 60_000;
export const DEFAULT_MAX_STALE_MS = 72 * 3_600_000;
export const DEFAULT_WATCH_INTERVAL_MS = 5 * 60_000;
export const MIN_WATCH_INTERVAL_MS = 30_000;

interface AccessSession {
  accessToken: string;
  vaultId: string;
  expiresAtMs: number;
}

interface EnvBinding {
  override: boolean;
  /** Variables whose current value was written by the SDK. */
  owned: Set<string>;
  /** Value each owned variable had before the SDK wrote it (`undefined` = it did not exist). */
  original: Map<string, string | undefined>;
}

function resolveOfflineMode(value: string | undefined): OfflineMode {
  switch (value ?? "use-cache") {
    case "use-cache":
      return "use-cache";
    case "fail":
      return "fail";
    default:
      throw new ConfigError(`Invalid offline mode '${value}': use "use-cache" or "fail".`);
  }
}

function resolveWatchInterval(watch: WatchOption | undefined): number | null {
  if (watch === undefined || watch === false) {
    return null;
  }
  const intervalMs = watch === true ? DEFAULT_WATCH_INTERVAL_MS : (watch.intervalMs ?? DEFAULT_WATCH_INTERVAL_MS);
  if (!Number.isFinite(intervalMs) || intervalMs < MIN_WATCH_INTERVAL_MS) {
    throw new ConfigError(
      `watch.intervalMs must be at least ${MIN_WATCH_INTERVAL_MS} ms (got ${intervalMs}).`,
    );
  }
  return intervalMs;
}

function resolveBaseUrl(raw: string, warn: (message: string) => void): string {
  const trimmed = raw.trim().replace(/\/+$/, "");
  if (!trimmed) {
    throw new ConfigError("COFFREBOX_URL is not set (or the url option is empty).");
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch (cause) {
    throw new ConfigError("COFFREBOX_URL is not a valid URL.", { cause });
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new ConfigError("COFFREBOX_URL must use https:// (or http:// for local development).");
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(parsed.hostname);
  if (parsed.protocol === "http:" && !loopback) {
    warn("[coffrebox] COFFREBOX_URL uses plain http:// outside localhost; use https:// in production.");
  }
  return trimmed;
}

export class Coffrebox {
  readonly #baseUrl: string;
  readonly #token: string;
  readonly #appId: string;
  readonly #appCacheDir: string;
  readonly #ttlMs: number;
  readonly #maxStaleMs: number;
  readonly #offline: OfflineMode;
  readonly #warn: (message: string) => void;

  #session: AccessSession | null = null;
  #secrets = new Map<string, string>();
  #highestRevision: number | undefined = undefined;
  #keyVersion: number | undefined = undefined;
  #cachedSnapshot: Record<string, unknown> | null = null;
  #expiresAtMs = 0;
  #refreshInFlight: Promise<void> | null = null;
  #listeners = new Set<ChangeListener>();
  #watchTimer: NodeJS.Timeout | null = null;
  #envBinding: EnvBinding | null = null;
  #closed = false;

  private constructor(params: {
    baseUrl: string;
    token: string;
    appId: string;
    appCacheDir: string;
    ttlMs: number;
    maxStaleMs: number;
    offline: OfflineMode;
    warn: (message: string) => void;
  }) {
    this.#baseUrl = params.baseUrl;
    this.#token = params.token;
    this.#appId = params.appId;
    this.#appCacheDir = params.appCacheDir;
    this.#ttlMs = params.ttlMs;
    this.#maxStaleMs = params.maxStaleMs;
    this.#offline = params.offline;
    this.#warn = params.warn;
  }

  /**
   * Connects, fills `process.env` with the vault secrets and returns the client.
   *
   * Fails closed: it throws if the secrets cannot be loaded (server down without a valid cache,
   * revoked access, tampered snapshot), so the app does not start without its configuration.
   */
  public static async load(options: LoadOptions = {}): Promise<Coffrebox> {
    const watchIntervalMs = resolveWatchInterval(options.watch);
    const client = await Coffrebox.connect({ ...options, watch: false });
    client.#envBinding = { override: options.override ?? false, owned: new Set(), original: new Map() };
    client.#syncEnv(new Map(), client.#secrets);
    if (watchIntervalMs !== null) {
      client.#startWatch(watchIntervalMs);
    }
    return client;
  }

  /**
   * Connects and loads the secrets into memory, without touching `process.env`.
   *
   * Without `watch` there are no background requests; `get()` refreshes on demand after `ttlMs`.
   */
  public static async connect(options: CoffreboxOptions = {}): Promise<Coffrebox> {
    const warn = options.warn ?? ((msg: string) => console.warn(msg));
    const baseUrl = resolveBaseUrl(options.url ?? process.env.COFFREBOX_URL ?? "", warn);
    const token = (options.token ?? process.env.COFFREBOX_TOKEN ?? "").trim();
    if (!token) {
      throw new ConfigError("COFFREBOX_TOKEN is not set (or the token option is empty).");
    }
    const offline = resolveOfflineMode(options.offline);
    const watchIntervalMs = resolveWatchInterval(options.watch);

    const appId = parseAppIdFromToken(token);
    const cacheRoot = options.cacheDir?.trim() || resolveDefaultCacheDir();

    const client = new Coffrebox({
      baseUrl,
      token,
      appId,
      appCacheDir: path.join(cacheRoot, appId),
      ttlMs: options.ttlMs ?? DEFAULT_TTL_MS,
      maxStaleMs: options.maxStaleMs ?? DEFAULT_MAX_STALE_MS,
      offline,
      warn,
    });

    await client.#bootstrapRevisionAnchor();
    await client.refresh();
    if (watchIntervalMs !== null) {
      client.#startWatch(watchIntervalMs);
    }
    return client;
  }

  /** Returns a secret, or throws `NotFoundError`. */
  public async get(name: string): Promise<string> {
    await this.#ensureFresh();
    const val = this.#secrets.get(name);
    if (val === undefined) {
      throw new NotFoundError(name);
    }
    return val;
  }

  /** Returns a secret, or `undefined` when it does not exist. */
  public async getOptional(name: string): Promise<string | undefined> {
    await this.#ensureFresh();
    return this.#secrets.get(name);
  }

  /** Returns every secret of the vault. */
  public async all(): Promise<Record<string, string>> {
    await this.#ensureFresh();
    return Object.fromEntries(this.#secrets.entries());
  }

  /** One-off copy of the current secrets into `process.env` (not kept in sync; see `load()`). */
  public async loadIntoEnv(options: LoadIntoEnvOptions = {}): Promise<void> {
    await this.#ensureFresh();
    const override = options.override ?? false;
    for (const [k, v] of this.#secrets.entries()) {
      if (override || process.env[k] === undefined) {
        process.env[k] = v;
      }
    }
  }

  /** Called with the names of the secrets that changed. Returns a function that unsubscribes. */
  public onChange(listener: ChangeListener): () => void {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  /** `true` while background polling (`watch`) is active. */
  public get watching(): boolean {
    return this.#watchTimer !== null;
  }

  /** Checks the server now (a `304 Not Modified` costs almost nothing). */
  public async refresh(): Promise<void> {
    if (this.#closed) {
      throw new ConfigError("This Coffrebox client is closed.");
    }
    if (this.#refreshInFlight !== null) {
      return this.#refreshInFlight;
    }
    this.#refreshInFlight = this.#doRefresh().finally(() => {
      this.#refreshInFlight = null;
    });
    return this.#refreshInFlight;
  }

  /** Stops background polling and forgets the secrets kept in memory. `process.env` is left as is. */
  public async close(): Promise<void> {
    this.#closed = true;
    if (this.#watchTimer !== null) {
      clearInterval(this.#watchTimer);
      this.#watchTimer = null;
    }
    this.#secrets.clear();
    this.#session = null;
    this.#listeners.clear();
    this.#envBinding = null;
  }

  async #bootstrapRevisionAnchor(): Promise<void> {
    const disk = await readLatestDiskSnapshot(this.#appCacheDir);
    if (disk !== null) {
      const dec = verifyAndDecryptSnapshotWithWasm(disk.snapshot, this.#token, undefined);
      this.#highestRevision = dec.revision;
      this.#cachedSnapshot = disk.snapshot;
    }
  }

  #startWatch(intervalMs: number): void {
    const timer = setInterval(() => {
      if (this.#closed) {
        return;
      }
      this.refresh().catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        this.#warn(`[coffrebox] Background check failed; keeping the last known secrets. ${msg}`);
      });
    }, intervalMs);
    timer.unref?.();
    this.#watchTimer = timer;
  }

  async #ensureFresh(): Promise<void> {
    if (Date.now() >= this.#expiresAtMs || this.#secrets.size === 0) {
      await this.refresh();
    }
  }

  async #doRefresh(): Promise<void> {
    try {
      await this.#onlineRefresh();
    } catch (err) {
      if (err instanceof RevokedError) {
        await wipeAppCacheDir(this.#appCacheDir);
        this.#secrets.clear();
        this.#cachedSnapshot = null;
        this.#session = null;
        throw err;
      }
      if (err instanceof OfflineError) {
        await this.#offlineFallback(err.message);
        return;
      }
      throw err;
    }
  }

  async #post(url: string, body: unknown, what: string): Promise<Response> {
    let res: Response;
    try {
      res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    } catch {
      throw new OfflineError(`Could not reach the server (${what}).`);
    }
    if (res.status === 401 || res.status === 403) {
      throw new RevokedError();
    }
    if (!res.ok) {
      throw new OfflineError(`The server answered HTTP ${res.status} (${what}).`);
    }
    return res;
  }

  async #obtainSession(): Promise<AccessSession> {
    if (this.#session !== null && Date.now() + 15_000 < this.#session.expiresAtMs) {
      return this.#session;
    }

    const challengeRes = await this.#post(
      `${this.#baseUrl}/api/v1/apps/auth/challenge`,
      { app_id: this.#appId },
      "authentication challenge",
    );
    const challengeBody = (await challengeRes.json()) as { nonce: string };
    const signature = signChallengeWithWasm(this.#token, challengeBody.nonce);

    const tokenRes = await this.#post(
      `${this.#baseUrl}/api/v1/apps/auth/token`,
      { app_id: this.#appId, nonce: challengeBody.nonce, signature },
      "access token",
    );
    const tokenBody = (await tokenRes.json()) as {
      access_token: string;
      vault_id: string;
      expires_in: number;
    };

    const sess: AccessSession = {
      accessToken: tokenBody.access_token,
      vaultId: tokenBody.vault_id,
      expiresAtMs: Date.now() + Math.max(tokenBody.expires_in, 30) * 1000,
    };
    this.#session = sess;
    return sess;
  }

  async #onlineRefresh(): Promise<void> {
    const sess = await this.#obtainSession();
    const headers: Record<string, string> = {
      Authorization: `Bearer ${sess.accessToken}`,
    };
    if (this.#highestRevision !== undefined && this.#cachedSnapshot !== null) {
      headers["If-None-Match"] = `"${this.#highestRevision}"`;
    }

    let snapRes: Response;
    try {
      snapRes = await fetch(`${this.#baseUrl}/api/v1/vaults/${sess.vaultId}/snapshot`, {
        method: "GET",
        headers,
      });
    } catch {
      throw new OfflineError("Could not reach the server (snapshot).");
    }

    if (snapRes.status === 401 || snapRes.status === 403) {
      throw new RevokedError();
    }
    if (snapRes.status === 304 && this.#cachedSnapshot !== null) {
      const dec = verifyAndDecryptSnapshotWithWasm(
        this.#cachedSnapshot,
        this.#token,
        this.#highestRevision,
      );
      await writeAtomicSnapshot(this.#appCacheDir, sess.vaultId, this.#cachedSnapshot);
      this.#applyDecrypted(this.#cachedSnapshot, dec);
      return;
    }
    if (!snapRes.ok) {
      throw new OfflineError(`The server answered HTTP ${snapRes.status} (snapshot).`);
    }

    let wireSnap: Record<string, unknown>;
    try {
      wireSnap = (await snapRes.json()) as Record<string, unknown>;
    } catch {
      throw new TamperedError("the snapshot response is not valid JSON.");
    }

    if (wireSnap.vault_id !== sess.vaultId) {
      throw new TamperedError("the snapshot belongs to a different vault than the one authorized.");
    }

    const dec = verifyAndDecryptSnapshotWithWasm(wireSnap, this.#token, this.#highestRevision);
    await writeAtomicSnapshot(this.#appCacheDir, sess.vaultId, wireSnap);
    this.#applyDecrypted(wireSnap, dec);
  }

  async #offlineFallback(reason: string): Promise<void> {
    if (this.#offline === "fail") {
      throw new OfflineError(reason);
    }

    const disk = await readLatestDiskSnapshot(this.#appCacheDir);
    if (disk === null) {
      throw new OfflineError(`${reason} There is no encrypted snapshot in the disk cache.`);
    }

    const ageMs = Math.max(0, Date.now() - disk.fetched_at_ms);
    if (ageMs > this.#maxStaleMs) {
      throw new StaleCacheError();
    }

    const dec = verifyAndDecryptSnapshotWithWasm(disk.snapshot, this.#token, this.#highestRevision);
    this.#warn(
      `[coffrebox] Server unreachable; using the encrypted local cache (app=${this.#appId}, vault=${dec.vault_id}, revision=${dec.revision}, ageMs=${ageMs}).`,
    );
    this.#applyDecrypted(disk.snapshot, dec);
  }

  /** Keeps `process.env` in line with the vault for the variables the SDK owns (see `load()`). */
  #syncEnv(prev: Map<string, string>, next: Map<string, string>): void {
    const env = this.#envBinding;
    if (env === null) {
      return;
    }
    for (const [k, v] of next) {
      if (env.owned.has(k)) {
        process.env[k] = v;
        continue;
      }
      const existing = process.env[k];
      if (existing === undefined || env.override) {
        env.original.set(k, existing);
        env.owned.add(k);
        process.env[k] = v;
      }
    }
    for (const k of prev.keys()) {
      if (!next.has(k) && env.owned.has(k)) {
        const original = env.original.get(k);
        if (original === undefined) {
          delete process.env[k];
        } else {
          process.env[k] = original;
        }
        env.owned.delete(k);
        env.original.delete(k);
      }
    }
  }

  #applyDecrypted(
    rawSnap: Record<string, unknown>,
    dec: {
      vault_id: string;
      revision: number;
      key_version: number;
      secrets: Record<string, string>;
    },
  ): void {
    const prevMap = this.#secrets;
    const nextMap = new Map<string, string>(Object.entries(dec.secrets));
    const changed = new Set<string>();
    const hadPrior = this.#keyVersion !== undefined;

    if (hadPrior) {
      for (const [k, v] of nextMap.entries()) {
        if (prevMap.get(k) !== v) {
          changed.add(k);
        }
      }
      for (const oldKey of prevMap.keys()) {
        if (!nextMap.has(oldKey)) {
          changed.add(oldKey);
        }
      }
      if (this.#keyVersion !== dec.key_version && changed.size === 0) {
        for (const k of nextMap.keys()) {
          changed.add(k);
        }
      }
    }

    this.#highestRevision = dec.revision;
    this.#keyVersion = dec.key_version;
    this.#secrets = nextMap;
    this.#cachedSnapshot = rawSnap;
    this.#expiresAtMs = Date.now() + this.#ttlMs;

    if (changed.size === 0) {
      return;
    }
    if (this.#watchTimer !== null) {
      this.#syncEnv(prevMap, nextMap);
    }
    const names = Array.from(changed).sort();
    for (const listener of this.#listeners) {
      try {
        listener(names);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        this.#warn(`[coffrebox] An onChange listener threw: ${msg}`);
      }
    }
  }
}
