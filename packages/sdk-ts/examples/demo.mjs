import { Coffrebox } from "../dist/index.js";

const cfb = await Coffrebox.connect({
  ttlMs: Number(process.env.COFFREBOX_DEMO_TTL_MS ?? 300_000),
  maxStaleMs: Number(process.env.COFFREBOX_DEMO_MAX_STALE_MS ?? 72 * 3_600_000),
  offline: process.env.COFFREBOX_DEMO_OFFLINE === "fail" ? "fail" : "use-cache",
});

try {
  const keyName = process.env.COFFREBOX_DEMO_KEY ?? "DATABASE_URL";
  const value = await cfb.get(keyName);
  process.stdout.write(`${value}\n`);
} finally {
  await cfb.close();
}
