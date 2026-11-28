// SPDX-License-Identifier: GPL-3.0-only
// CI deploy helper: wrangler.jsonc + the D1 database id + Access settings → wrangler.deploy.json.
// Refuses to produce a config that could expose the admin API: production entry point only, no
// workers.dev / preview URLs, Access team + audience both set.
import { readFileSync, writeFileSync } from "node:fs";

const [databaseId, rawTeam, rawAud] = process.argv.slice(2);
// accept "https://team.cloudflareaccess.com/", "team.cloudflareaccess.com" or just "team"
let team = (rawTeam ?? "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/+$/, "");
if (/^[a-z0-9-]+$/.test(team)) team += ".cloudflareaccess.com";
const aud = (rawAud ?? "").trim().toLowerCase();
const strip = (s) => s.replace(/^\s*\/\/.*$/gm, "").replace(/,(\s*[}\]])/g, "$1");
const cfg = JSON.parse(strip(readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8")));
const fail = (m) => {
  console.error(`deploy-config: ${m}`);
  process.exit(1);
};
if (!/^[0-9a-f-]{36}$/.test(databaseId ?? "")) fail("D1 database id missing");
if (!/^[a-z0-9-]+\.cloudflareaccess\.com$/.test(team)) fail("ACCESS_TEAM_DOMAIN must be <team>.cloudflareaccess.com");
if (!/^[0-9a-f]{64}$/.test(aud)) fail("ACCESS_AUD must be the Access application's 64-hex audience tag");
if (cfg.main !== "src/index.ts") fail("main must be src/index.ts");
if (cfg.workers_dev !== false || cfg.preview_urls !== false) fail("workers_dev and preview_urls must be false");
cfg.d1_databases[0].database_id = databaseId;
cfg.vars = { ...cfg.vars, ACCESS_TEAM_DOMAIN: team, ACCESS_AUD: aud };
delete cfg.$schema;
writeFileSync(new URL("../wrangler.deploy.json", import.meta.url), JSON.stringify(cfg, null, 2));
console.log(`deploy-config: ok (routes ${cfg.routes.map((r) => r.pattern).join(", ")})`);
