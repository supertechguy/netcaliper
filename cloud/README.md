# cloud

Cloudflare Worker (TypeScript + Hono) + D1 + dashboard for netcaliper. Design: docs/ARCHITECTURE.md §7;
deployment: docs/DEPLOY.md.

| Path | What |
|---|---|
| `src/index.ts` | routes, security headers, cron entry |
| `src/device.ts` | device token auth, enrollment, config pull |
| `src/sync.ts` | `POST /api/v1/sync`: validation, batched inserts within the statement budget, usage meter, back-off |
| `src/access.ts` | Cloudflare Access JWT verification (RS256, JWKS cache, fails closed) |
| `src/admin.ts` | dashboard API (Access-protected) |
| `src/retention.ts` | daily pruning |
| `src/records.gen.ts` | generated from `/schemas` (`npm run types`; CI checks it) |
| `src/dev.ts`, `wrangler.dev.jsonc` | local development only — never deployed |
| `public/` | dashboard (plain HTML/JS/CSS; `icons.js` generated from the device's icons) |
| `migrations/` | D1 schema (never edit an applied migration) |

```sh
npm ci && npm run check   # typecheck, types drift, tests
npm run dev               # local Worker + dashboard on http://127.0.0.1:8787
```
