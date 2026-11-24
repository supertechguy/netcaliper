// SPDX-License-Identifier: GPL-3.0-only
// LOCAL DEVELOPMENT ONLY (wrangler.dev.jsonc → `npm run dev`). Stands in for Cloudflare Access so the
// dashboard can be used on localhost: makes a throwaway key pair, serves it as the team JWKS and signs
// a "dev@localhost" identity onto each request — which then goes through the *real* verifier in
// access.ts. Refuses anything that isn't addressed to localhost. The production config (wrangler.jsonc)
// never references this file.
import worker from "./index";
import { b64url, type Env } from "./util";

const TEAM = "https://netcaliper-dev.cloudflareaccess.com";
const AUD = "dev";
let pair: Promise<CryptoKeyPair> | null = null;
const keys = () =>
  (pair ??= crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  ) as Promise<CryptoKeyPair>);

const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  if (url === `${TEAM}/cdn-cgi/access/certs`) {
    const jwk = await crypto.subtle.exportKey("jwk", (await keys()).publicKey);
    return Response.json({ keys: [{ ...jwk, kid: "dev" }] });
  }
  return realFetch(input, init);
}) as typeof fetch;

async function devJwt(): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const enc = (o: unknown) => b64url(new TextEncoder().encode(JSON.stringify(o)));
  const head = enc({ alg: "RS256", kid: "dev" });
  const body = enc({ aud: [AUD], iss: TEAM, email: "dev@localhost", iat: now, exp: now + 300 });
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", (await keys()).privateKey, new TextEncoder().encode(`${head}.${body}`));
  return `${head}.${body}.${b64url(new Uint8Array(sig))}`;
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const host = new URL(req.url).hostname;
    if (host !== "localhost" && host !== "127.0.0.1") return new Response("dev worker: localhost only", { status: 403 });
    const r = new Request(req);
    if (!new URL(req.url).pathname.match(/^\/api\/v1\/(enroll|sync|config|health)$/)) {
      r.headers.set("cf-access-jwt-assertion", await devJwt());
    }
    return worker.fetch(r, { ...env, ACCESS_TEAM_DOMAIN: TEAM, ACCESS_AUD: AUD }, ctx);
  },
  scheduled: worker.scheduled,
} satisfies ExportedHandler<Env>;
