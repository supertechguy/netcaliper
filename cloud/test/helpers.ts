// SPDX-License-Identifier: GPL-3.0-only
import { exports } from "cloudflare:workers";
import { vi } from "vitest";
import { b64url, uuid7 } from "../src/util";

export const HOST = "https://netcaliper.supertechguy.net";
export const TEAM = "https://netcaliper-test.cloudflareaccess.com";
export const AUD = "test-aud";

export function call(path: string, init: RequestInit = {}): Promise<Response> {
  return exports.default.fetch(new Request(HOST + path, init));
}

// ---- Cloudflare Access: a key pair made per test run (nothing committed), served as the team JWKS

let keys: Promise<CryptoKeyPair> | null = null;
const KID = "test-kid";
function keyPair(): Promise<CryptoKeyPair> {
  keys ??= crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  ) as Promise<CryptoKeyPair>;
  return keys;
}

export async function stubJwks(): Promise<void> {
  const pub = (await crypto.subtle.exportKey("jwk", (await keyPair()).publicKey)) as JsonWebKey;
  const real = globalThis.fetch;
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url === `${TEAM}/cdn-cgi/access/certs`) {
      return Response.json({ keys: [{ ...pub, kid: KID, alg: "RS256", use: "sig" }] });
    }
    return real(input, init);
  });
}

export async function jwt(over: Record<string, unknown> = {}, signWith?: CryptoKey): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const enc = (o: unknown) => b64url(new TextEncoder().encode(JSON.stringify(o)));
  const head = enc({ alg: "RS256", kid: KID, typ: "JWT" });
  const body = enc({ aud: [AUD], iss: TEAM, email: "admin@example.com", iat: now, nbf: now - 5, exp: now + 600, ...over });
  const key = signWith ?? (await keyPair()).privateKey;
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(`${head}.${body}`));
  return `${head}.${body}.${b64url(new Uint8Array(sig))}`;
}

export async function admin(path: string, init: RequestInit & { json?: unknown } = {}): Promise<Response> {
  await stubJwks();
  const headers = new Headers(init.headers);
  headers.set("cf-access-jwt-assertion", await jwt());
  let body = init.body;
  if (init.json !== undefined) {
    headers.set("content-type", "application/json");
    body = JSON.stringify(init.json);
  }
  return call(path, { ...init, headers, body });
}

export async function enroll(name = "uconsole-1", siteId?: string): Promise<{ token: string; device_id: string }> {
  const code = (await (await admin("/api/v1/admin/enroll-codes", { method: "POST", json: { name, site_id: siteId } })).json()) as {
    code: string;
  };
  const r = await call("/api/v1/enroll", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ code: code.code, info: { version: "0.4.0", platform: "uconsole-cm4" } }),
  });
  if (r.status !== 200) throw new Error(`enroll failed: ${r.status} ${await r.text()}`);
  return (await r.json()) as { token: string; device_id: string };
}

// ---- records shaped exactly like the device's outbox payloads (pydantic model_dump_json)

const ts = (offsetS = 0) => new Date(Date.now() + offsetS * 1000).toISOString().replace("Z", "000Z");

export function runRec(over: Record<string, unknown> = {}) {
  const id = uuid7();
  return {
    id,
    kind: "test_run",
    v: 1,
    data: { id, site_id: null, profile_id: "wired-basic", started_at: ts(), finished_at: null, status: "running", clock_synced: true, summary: {}, ...over },
  };
}

export function resultRec(runId: string, over: Record<string, unknown> = {}) {
  const id = uuid7();
  return {
    id,
    kind: "test_result",
    v: 1,
    data: {
      id,
      run_id: runId,
      module_id: "wifi.scan",
      module_version: "1",
      status: "pass",
      started_at: ts(),
      finished_at: ts(1),
      metrics: { bssids: 25 },
      details: { clients: [{ mac: "02:00:00:00:00:01" }] },
      message: "25 BSSIDs",
      artifacts: [],
      ...over,
    },
  };
}

export function findingRec(runId: string | null) {
  const id = uuid7();
  return {
    id,
    kind: "finding",
    v: 1,
    data: { id, run_id: runId, severity: "medium", rule_id: "wifi.wps", title: "WPS enabled", evidence: { bssid: "02:00:00:00:00:02" }, created_at: ts() },
  };
}

export function auditRec(prev = "0".repeat(64), hash = "a".repeat(64)) {
  const id = uuid7();
  return {
    id,
    kind: "audit",
    v: 1,
    data: { id, ts: ts(), actor: "local", action: "plane.move_in", engagement_id: null, detail: { mac: "02:00:00:00:00:03" }, prev_hash: prev, hash },
  };
}

export async function sync(token: string, records: unknown[], gzip = false): Promise<Response> {
  let body: BodyInit = JSON.stringify({ batch_id: uuid7(), records });
  const headers: Record<string, string> = { authorization: `Bearer ${token}`, "content-type": "application/json" };
  if (gzip) {
    body = await new Response(new Blob([body]).stream().pipeThrough(new CompressionStream("gzip"))).arrayBuffer();
    headers["content-encoding"] = "gzip";
  }
  return call("/api/v1/sync", { method: "POST", headers, body });
}
