// One process reading two vaults: each access token opens exactly one vault.
//
//   COFFREBOX_URL=... COFFREBOX_TOKEN=... SHARED_COFFREBOX_TOKEN=... node examples/two-vaults.mjs
import { Coffrebox } from "@brunosps00/coffrebox";

const url = process.env.COFFREBOX_URL;

const own = await Coffrebox.connect({ url, token: process.env.COFFREBOX_TOKEN });
const shared = await Coffrebox.connect({ url, token: process.env.SHARED_COFFREBOX_TOKEN });

try {
  const dbUrl = await own.get("DATABASE_URL");
  const apiKey = await shared.getOptional("PAYMENTS_API_KEY");
  console.log("own vault:", dbUrl ? "DATABASE_URL loaded" : "empty");
  console.log("shared vault:", apiKey ? "PAYMENTS_API_KEY loaded" : "no PAYMENTS_API_KEY");
} finally {
  await own.close();
  await shared.close();
}
