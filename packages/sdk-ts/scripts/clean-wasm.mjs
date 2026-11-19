// Removes the files wasm-pack writes next to the module that must not end up in the npm package
// (its ignore file with `*` would also hide the module from `npm pack`) and marks the folder as
// CommonJS, since the generated glue uses `exports` and the package itself is `"type": "module"`.
import { rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const wasmDir = join(dirname(fileURLToPath(import.meta.url)), "..", "wasm");
const generated = [".git" + "ignore", "README.md", "LICENSE", "coffrebox_wasm_bg.wasm.d.ts"];
for (const name of generated) {
  await rm(join(wasmDir, name), { force: true });
}
await writeFile(join(wasmDir, "package.json"), `${JSON.stringify({ type: "commonjs" }, null, 2)}\n`);
