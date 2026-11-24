// SPDX-License-Identifier: GPL-3.0-only
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { checkProfile } from "../src/admin";
import type { Device } from "../src/device";
import { retention } from "../src/retention";
import { handleSync, MAX_STATEMENTS } from "../src/sync";
import { uuid7 } from "../src/util";
import {
  admin,
  AUD,
  auditRec,
  call,
  enroll,
  findingRec,
  HOST,
  jwt,
  resultRec,
  runRec,
  stubJwks,
  sync,
  TEAM,
} from "./helpers";

type SyncOut = {
  acked: string[];
  rejected: { id: string; reason: string; retry: boolean }[];
  backoff_s?: number;
  limits: { max_records: number };
};

describe("enrollment", () => {
  it("issues a token for a valid code, once", async () => {
    await stubJwks();
    const codeRes = await admin("/api/v1/admin/enroll-codes", { method: "POST", json: { name: "bench" } });
    expect(codeRes.status).toBe(200);
    const { code } = (await codeRes.json()) as { code: string };
    expect(code).toMatch(/^[0-9A-Z]{5}-[0-9A-Z]{5}$/);
    // the clear code is never stored
    const stored = await env.DB.prepare("SELECT * FROM enroll_codes").first<Record<string, string>>();
    expect(JSON.stringify(stored)).not.toContain(code.replace("-", ""));

    const go = (c: string) =>
      call("/api/v1/enroll", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ code: c }) });
    const r = await go(code.toLowerCase()); // case/separator-insensitive
    expect(r.status).toBe(200);
    const body = (await r.json()) as { token: string; device_id: string; name: string };
    expect(body.name).toBe("bench");
    expect(body.token.length).toBeGreaterThanOrEqual(43);
    const tok = await env.DB.prepare("SELECT token_hash FROM device_tokens").first<{ token_hash: string }>();
    expect(tok!.token_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(tok!.token_hash).not.toBe(body.token);
    expect((await go(code)).status).toBe(401); // single use
  });

  it("rejects expired and malformed codes", async () => {
    await stubJwks();
    const { code } = (await (await admin("/api/v1/admin/enroll-codes", { method: "POST", json: { name: "x" } })).json()) as { code: string };
    await env.DB.prepare("UPDATE enroll_codes SET expires_at = '2000-01-01T00:00:00.000Z'").run();
    const go = (c: unknown) =>
      call("/api/v1/enroll", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ code: c }) });
    expect((await go(code)).status).toBe(401);
    expect((await go("nope")).status).toBe(400);
    expect((await go(42)).status).toBe(400);
  });

  it("revoked devices are locked out", async () => {
    const { token, device_id } = await enroll();
    expect((await sync(token, [])).status).toBe(200);
    expect((await admin(`/api/v1/admin/devices/${device_id}/revoke`, { method: "POST", json: {} })).status).toBe(200);
    expect((await sync(token, [])).status).toBe(401);
    expect((await sync("x".repeat(43), [])).status).toBe(401);
    expect((await call("/api/v1/sync", { method: "POST" })).status).toBe(401);
  });
});

describe("sync", () => {
  it("stores every record kind, stamped with the token's device", async () => {
    const { token, device_id } = await enroll();
    const run = runRec();
    const recs = [run, resultRec(run.id), findingRec(run.id), auditRec()];
    const r = await sync(token, recs, true);
    expect(r.status).toBe(200);
    const out = (await r.json()) as SyncOut;
    expect(out.rejected).toEqual([]);
    expect(new Set(out.acked)).toEqual(new Set(recs.map((x) => x.id)));
    for (const t of ["test_runs", "test_results", "findings", "audit_log"]) {
      const row = await env.DB.prepare(`SELECT device_id FROM ${t}`).first<{ device_id: string }>();
      expect(row!.device_id).toBe(device_id);
    }
    // client MACs are kept in result details (documented decision)
    const body = await env.DB.prepare("SELECT body FROM test_results").first<{ body: string }>();
    expect(body!.body).toContain("02:00:00:00:00:01");
    const meter = await env.DB.prepare("SELECT requests, rows_written FROM usage_meter").first<{ requests: number; rows_written: number }>();
    expect(meter!.requests).toBe(2); // enroll + sync
    expect(meter!.rows_written).toBeGreaterThanOrEqual(4);
  });

  it("is idempotent, and a finished run updates the one first sent as running", async () => {
    const { token } = await enroll();
    const run = runRec();
    const res = resultRec(run.id);
    await sync(token, [run, res]);
    const again = (await (await sync(token, [run, res])).json()) as SyncOut;
    expect(again.acked.length).toBe(2);
    expect((await env.DB.prepare("SELECT count(*) AS n FROM test_results").first<{ n: number }>())!.n).toBe(1);
    const done = { ...run, data: { ...run.data, status: "pass", finished_at: new Date().toISOString(), summary: { steps: 3 } } };
    await sync(token, [done]);
    const row = await env.DB.prepare("SELECT status, summary FROM test_runs").first<{ status: string; summary: string }>();
    expect(row!.status).toBe("pass");
    expect(JSON.parse(row!.summary)).toEqual({ steps: 3 });
  });

  it("a device cannot overwrite another device's run", async () => {
    const a = await enroll("a");
    const b = await enroll("b");
    const run = runRec();
    await sync(a.token, [run]);
    await sync(b.token, [{ ...run, data: { ...run.data, status: "fail" } }]);
    const row = await env.DB.prepare("SELECT status, device_id FROM test_runs").first<{ status: string; device_id: string }>();
    expect(row).toEqual({ status: "running", device_id: a.device_id });
  });

  it("rejects malformed records and keeps newer schema versions queued", async () => {
    const { token } = await enroll();
    const run = runRec();
    const bad = resultRec(run.id, { status: "great" });
    const newer = { ...findingRec(null), v: 2 };
    const mismatch = { ...auditRec(), id: uuid7() };
    const nohash = auditRec("zz", "yy");
    const out = (await (await sync(token, [run, bad, newer, mismatch, nohash, { id: "x" }])).json()) as SyncOut;
    expect(out.acked).toEqual([run.id]);
    const by = Object.fromEntries(out.rejected.map((r) => [r.id, r]));
    expect(by[bad.id]).toMatchObject({ reason: "bad status", retry: false });
    expect(by[newer.id]!.retry).toBe(true);
    expect(by[mismatch.id]!.reason).toBe("id mismatch");
    expect(by[nohash.id]!.reason).toBe("bad hash");
  });

  it("refuses bad bodies", async () => {
    const { token } = await enroll();
    const h = { authorization: `Bearer ${token}`, "content-type": "application/json" };
    expect((await call("/api/v1/sync", { method: "POST", headers: h, body: "{" })).status).toBe(400);
    expect((await call("/api/v1/sync", { method: "POST", headers: { ...h, "content-encoding": "gzip" }, body: "not gzip" })).status).toBe(400);
    expect((await call("/api/v1/sync", { method: "POST", headers: { ...h, "content-type": "text/plain" }, body: "{}" })).status).toBe(415);
    const big = JSON.stringify({ records: [], pad: "x".repeat(5_000_000) });
    expect((await call("/api/v1/sync", { method: "POST", headers: h, body: big })).status).toBe(413);
  });

  it("backs off near the daily row budget and keeps only essentials past 90 %", async () => {
    const { token } = await enroll();
    const day = new Date().toISOString().slice(0, 10);
    const setMeter = (n: number) =>
      env.DB.prepare("INSERT INTO usage_meter(day, rows_written) VALUES (?1, ?2) ON CONFLICT(day) DO UPDATE SET rows_written = ?2")
        .bind(day, n)
        .run();
    await setMeter(75_000);
    let out = (await (await sync(token, [])).json()) as SyncOut;
    expect(out.backoff_s).toBe(900);
    expect(out.limits.max_records).toBe(50);

    await setMeter(95_000);
    const run = runRec();
    const f = findingRec(run.id);
    const a = auditRec();
    out = (await (await sync(token, [run, f, a])).json()) as SyncOut;
    expect(new Set(out.acked)).toEqual(new Set([f.id, a.id])); // the run waits (not rejected)
    expect(out.rejected).toEqual([]);
    expect(out.backoff_s).toBeGreaterThan(900);

    await setMeter(100_000);
    out = (await (await sync(token, [auditRec()])).json()) as SyncOut;
    expect(out.acked).toEqual([]);
  });

  it(`a maximum-size request stays within ${MAX_STATEMENTS} D1 statements`, async () => {
    const { device_id } = await enroll();
    // Count every statement the handler sends, batched or not.
    let statements = 0;
    const db = env.DB;
    const counting = new Proxy(db, {
      get(t, p) {
        if (p === "prepare")
          return (sql: string) => {
            const s = t.prepare(sql);
            const wrap = (st: D1PreparedStatement): D1PreparedStatement =>
              new Proxy(st, {
                get(x, q) {
                  if (q === "bind") return (...a: unknown[]) => wrap(x.bind(...a));
                  if (q === "first" || q === "run" || q === "all" || q === "raw")
                    return (...a: unknown[]) => {
                      statements++;
                      return (x[q] as (...b: unknown[]) => unknown)(...a);
                    };
                  const v = Reflect.get(x, q);
                  return typeof v === "function" ? v.bind(x) : v;
                },
              });
            return wrap(s);
          };
        if (p === "batch")
          return (s: D1PreparedStatement[]) => {
            statements += s.length;
            return t.batch(s);
          };
        const v = Reflect.get(t, p);
        return typeof v === "function" ? v.bind(t) : v;
      },
    });
    const runs = Array.from({ length: 20 }, () => runRec());
    const recs: unknown[] = [...runs];
    for (let i = recs.length; i < 200; i++) {
      const k = i % 4;
      const run = runs[i % 20]!;
      recs.push(k === 0 ? findingRec(run.id) : k === 1 ? auditRec() : resultRec(run.id));
    }
    const req = new Request(`${HOST}/api/v1/sync`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ records: recs }),
    });
    const dev: Device = { id: device_id, name: "x", site_id: null };
    const out = (await (await handleSync(req, { ...env, DB: counting }, dev)).json()) as SyncOut;
    expect(out.acked.length).toBe(200);
    expect(statements + 1).toBeLessThanOrEqual(MAX_STATEMENTS); // + the token lookup
  });
});

describe("Cloudflare Access", () => {
  it("guards the admin API and the dashboard", async () => {
    await stubJwks();
    expect((await call("/api/v1/admin/me")).status).toBe(403);
    expect((await call("/")).status).toBe(403);
    const me = await admin("/api/v1/admin/me");
    expect(await me.json()).toEqual({ email: "admin@example.com" });
    const page = await admin("/");
    expect(page.status).toBe(200);
    expect(page.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
  });

  it("rejects forged, foreign, expired and mis-addressed tokens", async () => {
    await stubJwks();
    const other = (await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const now = Math.floor(Date.now() / 1000);
    const cases = [
      await jwt({}, other.privateKey),
      await jwt({ aud: ["someone-else"] }),
      await jwt({ iss: "https://evil.cloudflareaccess.com" }),
      await jwt({ exp: now - 3600 }),
      await jwt({ nbf: now + 3600 }),
      (await jwt()).replace(/\.[^.]+$/, ".AAAA"),
      "not-a-jwt",
    ];
    for (const t of cases) {
      const r = await call("/api/v1/admin/me", { headers: { "cf-access-jwt-assertion": t } });
      expect(r.status, t.slice(0, 20)).toBe(403);
    }
    // and the good one works with the same stubbed key set
    const ok = await call("/api/v1/admin/me", { headers: { "cf-access-jwt-assertion": await jwt({ aud: AUD }) } });
    expect(ok.status).toBe(200);
  });

  it("fails closed when Access isn't configured", async () => {
    const { verifyAccess } = await import("../src/access");
    await stubJwks();
    const req = new Request(HOST, { headers: { "cf-access-jwt-assertion": await jwt() } });
    expect(await verifyAccess(req, { ...env, ACCESS_AUD: "" })).toBeNull();
    expect(await verifyAccess(req, { ...env, ACCESS_TEAM_DOMAIN: "" })).toBeNull();
    expect(await verifyAccess(req, { ...env, ACCESS_TEAM_DOMAIN: "evil.example.com" })).toBeNull();
    expect(await verifyAccess(req, env)).toEqual({ email: "admin@example.com" });
    expect(TEAM).toContain("cloudflareaccess.com");
  });

  it("refuses cross-site state changes", async () => {
    const form = await admin("/api/v1/admin/sites", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "name=x",
    });
    expect(form.status).toBe(415);
    const foreign = await admin("/api/v1/admin/sites", { method: "POST", headers: { origin: "https://evil.example" }, json: { name: "x" } });
    expect(foreign.status).toBe(403);
  });
});

describe("config pull", () => {
  it("serves profiles with an ETag and 304s when unchanged", async () => {
    const site = (await (await admin("/api/v1/admin/sites", { method: "POST", json: { name: "HQ" } })).json()) as { id: string };
    const { token } = await enroll("d", site.id);
    const get = (etag?: string) =>
      call("/api/v1/config", { headers: { authorization: `Bearer ${token}`, ...(etag ? { "if-none-match": etag } : {}) } });
    const first = await get();
    const etag = first.headers.get("etag")!;
    const cfg = (await first.json()) as { site: { name: string }; profiles: unknown[] };
    expect(cfg.site.name).toBe("HQ");
    expect(cfg.profiles).toEqual([]);
    expect((await get(etag)).status).toBe(304);

    const p = { id: "branch-office", name: "Branch office", interface: "test-wired", steps: [{ module: "wired.link" }, { module: "net.dhcp" }] };
    expect((await admin("/api/v1/admin/profiles/branch-office", { method: "PUT", json: p })).status).toBe(200);
    const next = await get(etag);
    expect(next.status).toBe(200);
    expect(((await next.json()) as { profiles: { id: string }[] }).profiles[0]!.id).toBe("branch-office");
  });

  it("never accepts credentials in cloud profiles", () => {
    expect(checkProfile({ id: "x", name: "x", steps: [{ module: "wifi.connect", config: { ssid: "a", passphrase: "secret123" } }] })).toMatch(
      /credentials/,
    );
    expect(checkProfile({ id: "x", name: "x", steps: [{ module: "wired.dot1x", config: { password: "p" } }] })).toMatch(/credentials/);
    expect(checkProfile({ id: "X Y", name: "x", steps: [{ module: "a.b" }] })).toMatch(/^id/);
    expect(checkProfile({ id: "x", name: "x", steps: [] })).toMatch(/steps/);
    expect(checkProfile({ id: "x", name: "x", steps: [{ module: "wifi.scan" }] })).toBeNull();
  });
});

describe("retention cron", () => {
  it("drops old result bodies but keeps runs, in bounded chunks", async () => {
    const { token } = await enroll();
    const old = runRec({ started_at: "2020-01-01T00:00:00.000000Z" });
    const fresh = runRec();
    await sync(token, [old, fresh, resultRec(old.id), resultRec(old.id), resultRec(fresh.id), findingRec(old.id)]);
    await env.DB.prepare("UPDATE findings SET created_at = '2020-01-01T00:00:00.000Z'").run();
    const rep = await retention(env);
    expect(rep).toMatchObject({ runs_pruned: 1, results_deleted: 2, findings_deleted: 1 });
    expect(rep.statements).toBeLessThan(50);
    const runs = await env.DB.prepare("SELECT id, results_pruned FROM test_runs ORDER BY started_at").all();
    expect(runs.results).toEqual([
      { id: old.id, results_pruned: 1 },
      { id: fresh.id, results_pruned: 0 },
    ]);
    expect((await env.DB.prepare("SELECT count(*) AS n FROM test_results").first<{ n: number }>())!.n).toBe(1);
    expect((await retention(env)).runs_pruned).toBe(0); // nothing left to do
  });
});

describe("dashboard data", () => {
  it("lists runs with keyset paging and shows a run with its results", async () => {
    const { token, device_id } = await enroll();
    const runs = Array.from({ length: 3 }, (_, i) => runRec({ started_at: `2026-11-2${i}T10:00:00.000000Z` }));
    await sync(token, [...runs, resultRec(runs[2]!.id), findingRec(runs[2]!.id)]);
    const page = (await (await admin(`/api/v1/admin/runs?limit=2&device_id=${device_id}`)).json()) as {
      runs: { id: string }[];
      next: string;
    };
    expect(page.runs.map((r) => r.id)).toEqual([runs[2]!.id, runs[1]!.id]);
    const rest = (await (await admin(`/api/v1/admin/runs?limit=2&before=${encodeURIComponent(page.next)}`)).json()) as { runs: { id: string }[] };
    expect(rest.runs.map((r) => r.id)).toEqual([runs[0]!.id]);
    const one = (await (await admin(`/api/v1/admin/runs/${runs[2]!.id}`)).json()) as { results: unknown[]; findings: unknown[] };
    expect(one.results.length).toBe(1);
    expect(one.findings.length).toBe(1);
    const ov = (await (await admin("/api/v1/admin/overview")).json()) as { devices: unknown[]; usage: unknown[] };
    expect(ov.devices.length).toBe(1);
    expect(ov.usage.length).toBe(1);
  });

  it("reports audit chain linkage", async () => {
    const { token, device_id } = await enroll();
    const a = auditRec("0".repeat(64), "1".repeat(64));
    const b = auditRec("1".repeat(64), "2".repeat(64));
    (b.data as { ts: string }).ts = new Date(Date.now() + 1000).toISOString();
    await sync(token, [a, b]);
    const out = (await (await admin(`/api/v1/admin/audit?device_id=${device_id}`)).json()) as { linked: (boolean | null)[] };
    expect(out.linked).toEqual([true, null]);
  });
});
