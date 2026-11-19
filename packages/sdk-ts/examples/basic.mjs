// Plain script: load the vault into process.env, then use it.
//
//   COFFREBOX_URL=https://vault.example.com COFFREBOX_TOKEN=cfb1_app_... node examples/basic.mjs
import { Coffrebox, CoffreboxError } from "@brunosps00/coffrebox";

try {
  await Coffrebox.load();
} catch (err) {
  // Fail closed: do not run without configuration.
  console.error(err instanceof CoffreboxError ? `${err.code}: ${err.message}` : err);
  process.exit(1);
}

console.log("DATABASE_URL is", process.env.DATABASE_URL ? "set" : "missing");
