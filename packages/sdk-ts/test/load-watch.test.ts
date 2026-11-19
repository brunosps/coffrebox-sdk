// Coffrebox.load(): explicit env loading, override, watch (polling with 304), fail-closed start
// and several clients in one process.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  Coffrebox,
  ConfigError,
  type LoadOptions,
  OfflineError,
  RevokedError,
  TamperedError,
} from "../src/index.js";
import { diskRevision, fx, onCleanup, runCleanups, scenario } from "./helpers/fake-server.js";

const VARS = ["DATABASE_URL", "REDIS_URL", "API_KEY"];
const FIVE_MINUTES = 5 * 60_000;

beforeEach(() => {
  for (const v of VARS) delete process.env[v];
});

afterEach(async () => {
  vi.useRealTimers();
  await runCleanups();
  for (const v of VARS) delete process.env[v];
});

async function load(url: string, cacheDir: string, extra: Partial<LoadOptions> = {}) {
  const client = await Coffrebox.load({
    url,
    token: fx.token,
    cacheDir,
    warn: () => undefined,
    ...extra,
  });
  onCleanup(() => client.close());
  return client;
}

/** Fakes only the polling timer, so HTTP and the fake server keep real timers. */
function fakeIntervals(): void {
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
}

async function tick(): Promise<void> {
  await vi.advanceTimersByTimeAsync(FIVE_MINUTES);
}

describe("Coffrebox.load()", () => {
  it("fills process.env and returns the client", async () => {
    const { srv, cacheDir } = await scenario();
    const client = await load(srv.url, cacheDir);
    expect(process.env.DATABASE_URL).toBe(fx.values.rev2);
    expect(await client.get("DATABASE_URL")).toBe(fx.values.rev2);
  });

  it("keeps variables that already exist unless override is true", async () => {
    const { srv, cacheDir } = await scenario();
    process.env.DATABASE_URL = "postgres://local-override";
    await load(srv.url, cacheDir);
    expect(process.env.DATABASE_URL).toBe("postgres://local-override");

    await load(srv.url, cacheDir, { override: true });
    expect(process.env.DATABASE_URL).toBe(fx.values.rev2);
  });

  it("fails closed when the server is down and there is no cache", async () => {
    const { srv, cacheDir } = await scenario();
    await srv.stop();
    await expect(load(srv.url, cacheDir)).rejects.toBeInstanceOf(OfflineError);
    expect(process.env.DATABASE_URL).toBeUndefined();
  });

  it("fails closed when the access is revoked", async () => {
    const { srv, cacheDir } = await scenario();
    srv.revoked = true;
    await expect(load(srv.url, cacheDir)).rejects.toBeInstanceOf(RevokedError);
    expect(process.env.DATABASE_URL).toBeUndefined();
  });

  it("fails closed when the snapshot is tampered with", async () => {
    const { srv, cacheDir } = await scenario();
    srv.serve(fx.snapshots.injected_item);
    await expect(load(srv.url, cacheDir)).rejects.toBeInstanceOf(TamperedError);
    expect(process.env.DATABASE_URL).toBeUndefined();
  });

  it("rejects invalid configuration with a stable code", async () => {
    const { srv, cacheDir } = await scenario();
    await expect(load(srv.url, cacheDir, { token: "" })).rejects.toMatchObject({
      code: "COFFREBOX_INVALID_CONFIG",
    });
    await expect(load("ftp://example.invalid", cacheDir)).rejects.toBeInstanceOf(ConfigError);
    await expect(load(srv.url, cacheDir, { token: `${fx.token}x` })).rejects.toBeInstanceOf(
      ConfigError,
    );
    await expect(load(srv.url, cacheDir, { watch: { intervalMs: 1_000 } })).rejects.toBeInstanceOf(
      ConfigError,
    );
  });
});

describe("without watch", () => {
  it("load() and connect() leave no timer and make no further requests", async () => {
    fakeIntervals();
    const { srv, cacheDir } = await scenario();
    await load(srv.url, cacheDir);
    const other = await Coffrebox.connect({ url: srv.url, token: fx.token, cacheDir });
    onCleanup(() => other.close());
    expect(vi.getTimerCount()).toBe(0);
    expect(other.watching).toBe(false);

    const requests = srv.snapshotRequests;
    await vi.advanceTimersByTimeAsync(60 * 60_000);
    expect(srv.snapshotRequests).toBe(requests);
  });
});

describe("with watch", () => {
  it("polls every 5 minutes by default; a 304 changes nothing", async () => {
    fakeIntervals();
    const { srv, cacheDir } = await scenario();
    const client = await load(srv.url, cacheDir, { watch: true });
    const changes: string[][] = [];
    client.onChange((names) => changes.push(names));
    expect(vi.getTimerCount()).toBe(1);

    await tick();
    await vi.waitFor(() => expect(srv.notModified).toBe(1));
    expect(changes).toEqual([]);
    expect(process.env.DATABASE_URL).toBe(fx.values.rev2);
  });

  it("updates process.env and reports the changed names", async () => {
    fakeIntervals();
    const { srv, cacheDir } = await scenario();
    const client = await load(srv.url, cacheDir, { watch: true });
    const changes: string[][] = [];
    client.onChange((names) => changes.push(names));

    srv.serve(fx.snapshots.rev3);
    await tick();
    await vi.waitFor(() => expect(changes).toEqual([["DATABASE_URL"]]));
    expect(process.env.DATABASE_URL).toBe(fx.values.rev3);
    expect(await diskRevision(cacheDir)).toBe(3);

    srv.serve(fx.snapshots.rev4);
    await tick();
    await vi.waitFor(() => expect(changes.at(-1)).toEqual(["REDIS_URL"]));
    expect(process.env.REDIS_URL).toBe(fx.values.redis);

    // DATABASE_URL leaves the vault: the SDK put it in the env, so it removes it.
    srv.serve(fx.snapshots.rev5);
    await tick();
    await vi.waitFor(() => expect(changes.at(-1)).toEqual(["DATABASE_URL"]));
    expect(process.env.DATABASE_URL).toBeUndefined();
    expect(process.env.REDIS_URL).toBe(fx.values.redis);
  });

  it("never touches a variable it did not set (override: false)", async () => {
    fakeIntervals();
    const { srv, cacheDir } = await scenario();
    process.env.DATABASE_URL = "postgres://local-override";
    const client = await load(srv.url, cacheDir, { watch: true });
    const changes: string[][] = [];
    client.onChange((names) => changes.push(names));

    srv.serve(fx.snapshots.rev3);
    await tick();
    await vi.waitFor(() => expect(changes).toEqual([["DATABASE_URL"]]));
    expect(process.env.DATABASE_URL).toBe("postgres://local-override");
    expect(await client.get("DATABASE_URL")).toBe(fx.values.rev3);

    srv.serve(fx.snapshots.rev5);
    await tick();
    await vi.waitFor(() => expect(changes.at(-1)).toEqual(["DATABASE_URL", "REDIS_URL"]));
    expect(process.env.DATABASE_URL).toBe("postgres://local-override");
  });

  it("with override: true, restores the original value when the secret leaves the vault", async () => {
    fakeIntervals();
    const { srv, cacheDir } = await scenario();
    process.env.DATABASE_URL = "postgres://local-override";
    const client = await load(srv.url, cacheDir, { watch: true, override: true });
    const changes: string[][] = [];
    client.onChange((names) => changes.push(names));
    expect(process.env.DATABASE_URL).toBe(fx.values.rev2);

    srv.serve(fx.snapshots.rev5);
    await tick();
    await vi.waitFor(() => expect(changes.length).toBe(1));
    expect(process.env.DATABASE_URL).toBe("postgres://local-override");
  });

  it("keeps the last known values and warns when a background check fails", async () => {
    fakeIntervals();
    const { srv, cacheDir } = await scenario();
    const warnings: string[] = [];
    const client = await load(srv.url, cacheDir, {
      watch: { intervalMs: 60_000 },
      offline: "fail",
      warn: (m) => warnings.push(m),
    });
    await srv.stop();
    await vi.advanceTimersByTimeAsync(60_000);
    await vi.waitFor(() => expect(warnings.join("\n")).toContain("Background check failed"));
    expect(process.env.DATABASE_URL).toBe(fx.values.rev2);
    expect(await client.getOptional("DATABASE_URL")).toBe(fx.values.rev2);
  });

  it("close() stops polling", async () => {
    fakeIntervals();
    const { srv, cacheDir } = await scenario();
    const client = await load(srv.url, cacheDir, { watch: true });
    expect(client.watching).toBe(true);
    await client.close();
    expect(vi.getTimerCount()).toBe(0);
    const requests = srv.snapshotRequests;
    await tick();
    expect(srv.snapshotRequests).toBe(requests);
  });
});

describe("two vaults in one process", () => {
  it("two clients with explicit url and token read their own vaults and caches", async () => {
    const { srv, cacheDir } = await scenario();
    const main = await Coffrebox.connect({ url: srv.url, token: fx.token, cacheDir });
    const other = await Coffrebox.connect({ url: srv.url, token: fx.other.token, cacheDir });
    onCleanup(() => main.close());
    onCleanup(() => other.close());

    expect(await main.get("DATABASE_URL")).toBe(fx.values.rev2);
    expect(await other.get("API_KEY")).toBe(fx.other.api_key);
    expect(await main.getOptional("API_KEY")).toBeUndefined();
    expect(await other.getOptional("DATABASE_URL")).toBeUndefined();
    expect(await diskRevision(cacheDir)).toBe(2);
    expect(await diskRevision(cacheDir, fx.other.app_id, fx.other.vault_id)).toBe(1);
  });
});
