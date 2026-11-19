// Express server that reloads its database pool when DATABASE_URL changes in the vault.
//
//   npm install express pg
//   COFFREBOX_URL=... COFFREBOX_TOKEN=... node examples/express.mjs
import { Coffrebox } from "@brunosps00/coffrebox";

// Loads before anything else reads process.env; checks for changes every 5 minutes.
const vault = await Coffrebox.load({ watch: true });

const { default: express } = await import("express");
const { default: pg } = await import("pg");

let pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

vault.onChange(async (names) => {
  if (names.includes("DATABASE_URL")) {
    const old = pool;
    pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
    await old.end();
  }
});

const app = express();
app.get("/health", async (_req, res) => {
  await pool.query("select 1");
  res.send("ok");
});

const server = app.listen(Number(process.env.PORT ?? 3000));

process.on("SIGTERM", async () => {
  server.close();
  await vault.close();
  await pool.end();
});
