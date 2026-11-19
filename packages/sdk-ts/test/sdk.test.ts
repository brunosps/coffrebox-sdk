import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Coffrebox, ConfigError } from "../src/index.js";
import { getWasm } from "../src/wasm.js";

describe("@brunosps00/coffrebox — WebAssembly bridge", () => {
  const tmpDirs: string[] = [];

  afterEach(async () => {
    for (const d of tmpDirs.splice(0)) {
      await fs.rm(d, { recursive: true, force: true });
    }
  });

  it("rejects a malformed token before touching the network", async () => {
    const cacheDir = await fs.mkdtemp(path.join(os.tmpdir(), "cfb-sdk-ts-"));
    tmpDirs.push(cacheDir);

    await expect(
      Coffrebox.connect({
        url: "http://127.0.0.1:9",
        token: "cfb1_app_invalid",
        cacheDir,
      }),
    ).rejects.toBeInstanceOf(ConfigError);
  });

  it("ships only the application surface of the WebAssembly core", () => {
    const exported = Object.keys(getWasm()).filter((k) => !k.startsWith("__"));
    expect(exported.sort()).toEqual([
      "format_version",
      "parse_app_token_info",
      "sign_app_challenge",
      "verify_and_decrypt_app_snapshot",
    ]);
  });
});
