import { randomBytes } from "node:crypto";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { TamperedError } from "./errors.js";

export interface DiskSnapshotEnvelope {
  fetched_at_ms: number;
  snapshot: Record<string, unknown>;
  v: number;
}

export function resolveDefaultCacheDir(): string {
  const envDir = process.env.COFFREBOX_CACHE_DIR?.trim();
  if (envDir) {
    return envDir;
  }
  const xdg = process.env.XDG_CACHE_HOME?.trim();
  if (xdg) {
    return path.join(xdg, "coffrebox");
  }
  const home = os.homedir();
  if (home) {
    return path.join(home, ".cache", "coffrebox");
  }
  return path.join(os.tmpdir(), "coffrebox-cache");
}

export async function writeAtomicSnapshot(
  appCacheDir: string,
  vaultId: string,
  snapshot: Record<string, unknown>,
): Promise<void> {
  await fs.mkdir(appCacheDir, { recursive: true, mode: 0o700 });
  await fs.chmod(appCacheDir, 0o700).catch(() => undefined);

  const envelope: DiskSnapshotEnvelope = {
    fetched_at_ms: Date.now(),
    snapshot,
    v: 1,
  };
  const payload = Buffer.from(JSON.stringify(envelope), "utf8");
  const suffix = randomBytes(6).toString("hex");
  const tmpPath = path.join(appCacheDir, `${vaultId}.snapshot.tmp.${suffix}`);
  const finalPath = path.join(appCacheDir, `${vaultId}.snapshot`);

  const handle = await fs.open(tmpPath, "wx", 0o600);
  try {
    await handle.writeFile(payload);
    await handle.sync();
  } finally {
    await handle.close();
  }

  await fs.rename(tmpPath, finalPath);
}

export async function readLatestDiskSnapshot(
  appCacheDir: string,
): Promise<DiskSnapshotEnvelope | null> {
  let entries: string[];
  try {
    entries = await fs.readdir(appCacheDir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw err;
  }

  let best: DiskSnapshotEnvelope | null = null;
  for (const name of entries) {
    if (!name.endsWith(".snapshot")) {
      continue;
    }
    const full = path.join(appCacheDir, name);
    let raw: string;
    try {
      raw = await fs.readFile(full, "utf8");
    } catch {
      throw new TamperedError("the .snapshot cache file is unreadable.");
    }
    let parsed: DiskSnapshotEnvelope;
    try {
      parsed = JSON.parse(raw) as DiskSnapshotEnvelope;
    } catch {
      throw new TamperedError("the .snapshot cache file is corrupted.");
    }
    if (parsed.v !== 1 || typeof parsed.fetched_at_ms !== "number" || !parsed.snapshot) {
      throw new TamperedError("the .snapshot cache file has an unknown format or version.");
    }
    if (best === null || parsed.fetched_at_ms >= best.fetched_at_ms) {
      best = parsed;
    }
  }
  return best;
}

export async function wipeAppCacheDir(appCacheDir: string): Promise<void> {
  await fs.rm(appCacheDir, { recursive: true, force: true });
}
