// SDK against a fake HTTP server: offline mode, rollback protection and tampering.
//
// Token and snapshots come from `fixtures/vault-app.json` (fictitious, generated in Rust by
// `cargo test -p coffrebox-wasm --test fixtures_sdk_ts -- --ignored`).
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  Coffrebox,
  type CoffreboxOptions,
  ConfigError,
  OfflineError,
  TamperedError,
} from "../src/index.js";
import { diskRevision, fx, onCleanup, runCleanups, scenario } from "./helpers/fake-server.js";

afterEach(runCleanups);

async function connect(
  url: string,
  cacheDir: string,
  extra: Partial<CoffreboxOptions> = {},
): Promise<Coffrebox> {
  const client = await Coffrebox.connect({
    url,
    token: fx.token,
    cacheDir,
    ttlMs: 60_000,
    warn: () => undefined,
    ...extra,
  });
  onCleanup(() => client.close());
  return client;
}

describe("offline mode", () => {
  it("offline: 'fail' refuses the disk cache when the server goes down", async () => {
    const { srv, cacheDir } = await scenario();
    const client = await connect(srv.url, cacheDir, { offline: "fail" });
    expect(await client.get("DATABASE_URL")).toBe(fx.values.rev2);
    expect(await diskRevision(cacheDir)).toBe(2);

    await srv.stop();
    await expect(client.refresh()).rejects.toBeInstanceOf(OfflineError);
    await expect(connect(srv.url, cacheDir, { offline: "fail" })).rejects.toBeInstanceOf(
      OfflineError,
    );
  });

  it("offline: 'use-cache' reads the encrypted cache and warns when the server goes down", async () => {
    const { srv, cacheDir } = await scenario();
    await connect(srv.url, cacheDir);
    await srv.stop();

    const warnings: string[] = [];
    const offline = await connect(srv.url, cacheDir, { warn: (m) => warnings.push(m) });
    expect(await offline.get("DATABASE_URL")).toBe(fx.values.rev2);
    expect(warnings.join("\n")).toContain("using the encrypted local cache");
    expect(warnings.join("\n")).not.toContain(fx.values.rev2);
  });

  it("offline: 'use-cache' refuses a cache older than maxStaleMs", async () => {
    const { srv, cacheDir } = await scenario();
    await connect(srv.url, cacheDir);
    await srv.stop();
    await new Promise((r) => setTimeout(r, 20));
    await expect(connect(srv.url, cacheDir, { maxStaleMs: 1 })).rejects.toMatchObject({
      kind: "StaleCache",
      code: "COFFREBOX_STALE_CACHE",
    });
  });

  it("refuses an unknown offline mode", async () => {
    const { srv, cacheDir } = await scenario();
    await expect(
      connect(srv.url, cacheDir, {
        offline: "sometimes" as unknown as CoffreboxOptions["offline"],
      }),
    ).rejects.toBeInstanceOf(ConfigError);
  });
});

describe("rollback protection", () => {
  it("refuses a revision older than the one seen in memory and keeps the newer cache", async () => {
    const { srv, cacheDir } = await scenario();
    srv.serve(fx.snapshots.rev3);
    const client = await connect(srv.url, cacheDir);
    expect(await client.get("DATABASE_URL")).toBe(fx.values.rev3);

    srv.serve(fx.snapshots.rev2);
    await expect(client.refresh()).rejects.toBeInstanceOf(TamperedError);
    expect(await client.get("DATABASE_URL")).toBe(fx.values.rev3);
    expect(await diskRevision(cacheDir)).toBe(3);
  });

  it("refuses a revision older than the one in the disk cache in a new process", async () => {
    const { srv, cacheDir } = await scenario();
    srv.serve(fx.snapshots.rev3);
    await connect(srv.url, cacheDir);

    srv.serve(fx.snapshots.rev2);
    await expect(connect(srv.url, cacheDir)).rejects.toMatchObject({
      code: "COFFREBOX_TAMPERED",
      message: expect.stringContaining("rollback"),
    });
    expect(await diskRevision(cacheDir)).toBe(3);
  });
});

describe("server tampering", () => {
  for (const kind of ["injected_item", "attacker_vk"] as const) {
    it(`refuses a snapshot with ${kind} and writes nothing to disk`, async () => {
      const { srv, cacheDir } = await scenario();
      srv.serve(fx.snapshots[kind]);
      await expect(connect(srv.url, cacheDir)).rejects.toBeInstanceOf(TamperedError);
      expect(srv.snapshotRequests).toBe(1);
      await expect(fs.readdir(path.join(cacheDir, fx.app_id))).rejects.toThrow();
    });
  }

  it("does not replace a good cache with a tampered snapshot", async () => {
    const { srv, cacheDir } = await scenario();
    const client = await connect(srv.url, cacheDir);
    srv.serve(fx.snapshots.injected_item);
    await expect(client.refresh()).rejects.toBeInstanceOf(TamperedError);
    expect(await diskRevision(cacheDir)).toBe(2);
    expect(await client.get("DATABASE_URL")).toBe(fx.values.rev2);
  });
});
