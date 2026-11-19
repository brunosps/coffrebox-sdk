// Fake Coffrebox server for the SDK tests: accepts any challenge signature and serves the
// configured snapshots (fictitious fixtures generated in Rust, see `fixtures/vault-app.json`).
import * as fs from "node:fs/promises";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

export interface Fixtures {
  token: string;
  app_id: string;
  vault_id: string;
  snapshots: Record<
    "rev2" | "rev3" | "rev4" | "rev5" | "injected_item" | "attacker_vk",
    Record<string, unknown>
  >;
  values: Record<"rev2" | "rev3" | "redis", string>;
  other: {
    token: string;
    app_id: string;
    vault_id: string;
    snapshot: Record<string, unknown>;
    api_key: string;
  };
}

const here = path.dirname(fileURLToPath(import.meta.url));
export const fx = JSON.parse(
  await fs.readFile(path.join(here, "..", "fixtures", "vault-app.json"), "utf8"),
) as Fixtures;

function revisionOf(snapshot: Record<string, unknown>): number {
  return (JSON.parse(snapshot.manifest as string) as { revision: number }).revision;
}

export class FakeServer {
  /** app_id -> vault served to that application. */
  readonly apps = new Map<string, { vaultId: string; snapshot: Record<string, unknown> }>();
  revoked = false;
  snapshotRequests = 0;
  notModified = 0;
  url = "";
  readonly #server: http.Server;

  constructor() {
    this.apps.set(fx.app_id, { vaultId: fx.vault_id, snapshot: fx.snapshots.rev2 });
    this.apps.set(fx.other.app_id, { vaultId: fx.other.vault_id, snapshot: fx.other.snapshot });
    this.#server = http.createServer((req, res) => {
      const send = (status: number, body?: unknown) => {
        res.statusCode = status;
        if (body === undefined) {
          res.end();
          return;
        }
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify(body));
      };
      let raw = "";
      req.on("data", (chunk) => {
        raw += chunk;
      });
      req.on("end", () => {
        if (this.revoked) {
          send(401, { error: { code: "revoked" } });
          return;
        }
        if (req.method === "POST" && req.url === "/api/v1/apps/auth/challenge") {
          send(200, { nonce: Buffer.alloc(32, 7).toString("base64url") });
          return;
        }
        if (req.method === "POST" && req.url === "/api/v1/apps/auth/token") {
          const { app_id } = JSON.parse(raw) as { app_id: string };
          const app = this.apps.get(app_id);
          if (app === undefined) {
            send(401, { error: { code: "unknown_app" } });
            return;
          }
          send(200, { access_token: `cfb1_at_${app_id}`, vault_id: app.vaultId, expires_in: 900 });
          return;
        }
        const match = /^\/api\/v1\/vaults\/([^/]+)\/snapshot$/.exec(req.url ?? "");
        if (req.method === "GET" && match) {
          const app = [...this.apps.values()].find((a) => a.vaultId === match[1]);
          if (app === undefined) {
            send(404, { error: { code: "not_found" } });
            return;
          }
          this.snapshotRequests += 1;
          if (req.headers["if-none-match"] === `"${revisionOf(app.snapshot)}"`) {
            this.notModified += 1;
            send(304);
            return;
          }
          send(200, app.snapshot);
          return;
        }
        send(404, { error: { message: "route not simulated" } });
      });
    });
  }

  /** Changes what the main fixture application receives. */
  serve(snapshot: Record<string, unknown>): void {
    this.apps.set(fx.app_id, { vaultId: fx.vault_id, snapshot });
  }

  async start(): Promise<void> {
    await new Promise<void>((resolve) => this.#server.listen(0, "127.0.0.1", resolve));
    const { port } = this.#server.address() as { port: number };
    this.url = `http://127.0.0.1:${port}`;
  }

  async stop(): Promise<void> {
    this.#server.closeAllConnections();
    await new Promise<void>((resolve) => this.#server.close(() => resolve()));
  }
}

const cleanups: Array<() => Promise<void>> = [];

export async function runCleanups(): Promise<void> {
  for (const fn of cleanups.splice(0).reverse()) {
    await fn().catch(() => undefined);
  }
}

export function onCleanup(fn: () => Promise<void>): void {
  cleanups.push(fn);
}

export async function scenario(): Promise<{ srv: FakeServer; cacheDir: string }> {
  const srv = new FakeServer();
  await srv.start();
  onCleanup(() => srv.stop());
  const cacheDir = await fs.mkdtemp(path.join(os.tmpdir(), "cfb-sdk-ts-"));
  onCleanup(() => fs.rm(cacheDir, { recursive: true, force: true }));
  return { srv, cacheDir };
}

export async function diskRevision(
  cacheDir: string,
  appId = fx.app_id,
  vaultId = fx.vault_id,
): Promise<number> {
  const file = path.join(cacheDir, appId, `${vaultId}.snapshot`);
  const env = JSON.parse(await fs.readFile(file, "utf8")) as { snapshot: { manifest: string } };
  return (JSON.parse(env.snapshot.manifest) as { revision: number }).revision;
}
