// SPDX-License-Identifier: GPL-3.0-only
// netcaliper cloud Worker: device API (token auth), admin API + dashboard (Cloudflare Access + our
// own JWT check), daily retention cron. See docs/ARCHITECTURE.md §7.
import { Hono, type MiddlewareHandler } from "hono";
import { verifyAccess, type AccessIdentity } from "./access";
import { admin } from "./admin";
import { authDevice, handleConfig, handleEnroll } from "./device";
import { retention } from "./retention";
import { handleSync } from "./sync";
import { HttpError, type Env } from "./util";

type Ctx = { Bindings: Env; Variables: { who: AccessIdentity } };
const app = new Hono<Ctx>();

const SECURITY_HEADERS: Record<string, string> = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "cross-origin-opener-policy": "same-origin",
  "content-security-policy":
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self';" +
    " frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
};

app.onError((err, c) => {
  if (err instanceof HttpError) return c.json({ error: err.message }, err.status);
  console.error(err);
  return c.json({ error: "internal error" }, 500);
});

app.use("*", async (c, next) => {
  await next();
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) c.res.headers.set(k, v);
  if (c.req.path.startsWith("/api/")) c.res.headers.set("cache-control", "no-store");
});

// ---- device API (Access bypass on these three paths; the device token is the auth)
app.get("/api/v1/health", (c) => c.json({ ok: true }));
app.post("/api/v1/enroll", (c) => handleEnroll(c.req.raw, c.env));
app.post("/api/v1/sync", async (c) => handleSync(c.req.raw, c.env, await authDevice(c.req.raw, c.env)));
app.get("/api/v1/config", async (c) => handleConfig(c.req.raw, c.env, await authDevice(c.req.raw, c.env)));

// ---- everything else: Cloudflare Access identity required, verified here too
const requireAccess: MiddlewareHandler<Ctx> = async (c, next) => {
  const who = await verifyAccess(c.req.raw, c.env);
  if (!who) throw new HttpError(403, "Cloudflare Access login required");
  c.set("who", who);
  const m = c.req.method;
  if (m !== "GET" && m !== "HEAD") {
    // CSRF: Access authenticates with a cookie, so state changes must be same-origin JSON requests
    // (a cross-site form can't send application/json without a CORS preflight we never answer).
    const origin = c.req.header("origin");
    if (origin && origin !== new URL(c.req.url).origin) throw new HttpError(403, "cross-origin request refused");
    const ct = (c.req.header("content-type") ?? "").split(";")[0]!.trim();
    if (ct !== "application/json") throw new HttpError(415, "application/json expected");
  }
  await next();
};
app.use("/api/v1/admin/*", requireAccess);
app.route("/api/v1/admin", admin);
app.all("/api/*", () => {
  throw new HttpError(404, "not found");
});

app.use("*", requireAccess);
app.get("*", async (c) => {
  const res = await c.env.ASSETS.fetch(c.req.raw);
  return new Response(res.body, res); // asset responses have immutable headers
});

export default {
  fetch: app.fetch,
  async scheduled(_ev: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(
      retention(env).then((r) => {
        console.log("retention", JSON.stringify(r));
      }),
    );
  },
} satisfies ExportedHandler<Env>;
