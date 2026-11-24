// SPDX-License-Identifier: GPL-3.0-only
// /api/v1/admin/* — behind Cloudflare Access *and* our own JWT check (see access.ts). Every list is
// keyset-paginated on an indexed column with a hard LIMIT: no unbounded scans, no COUNT(*).
import { Hono } from "hono";
import type { AccessIdentity } from "./access";
import { HttpError, newEnrollCode, normalizeEnrollCode, nowIso, sha256hex, utcDay, uuid7, type Env } from "./util";

type Ctx = { Bindings: Env; Variables: { who: AccessIdentity } };
export const admin = new Hono<Ctx>();

const PAGE = 50;
const ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const limit = (v: string | undefined): number => Math.min(Math.max(Number(v) || PAGE, 1), 100);
const parse = <T>(s: string | null | undefined, d: T): T => {
  try {
    return s ? (JSON.parse(s) as T) : d;
  } catch {
    return d;
  }
};

async function jsonBody(req: Request): Promise<Record<string, unknown>> {
  const t = await req.text();
  if (t.length > 64 * 1024) throw new HttpError(413, "body too large");
  try {
    const v = JSON.parse(t || "{}");
    if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error();
    return v as Record<string, unknown>;
  } catch {
    throw new HttpError(400, "JSON object expected");
  }
}

admin.get("/me", (c) => c.json({ email: c.get("who").email }));

admin.get("/overview", async (c) => {
  const db = c.env.DB;
  const since = utcDay(new Date(Date.now() - 13 * 86400_000));
  const [devices, usage, recent] = await db.batch([
    db.prepare(
      "SELECT d.id, d.name, d.site_id, s.name AS site, d.created_at, d.last_seen_at, d.revoked_at, d.info" +
        " FROM devices d LEFT JOIN sites s ON s.id = d.site_id ORDER BY d.created_at DESC LIMIT 200",
    ),
    db.prepare("SELECT day, requests, rows_written FROM usage_meter WHERE day >= ? ORDER BY day").bind(since),
    db.prepare(
      "SELECT r.id, r.device_id, r.profile_id, r.started_at, r.status, r.summary FROM test_runs r" +
        " ORDER BY r.started_at DESC LIMIT 10",
    ),
  ]);
  return c.json({
    devices: (devices!.results as Record<string, unknown>[]).map((d) => ({ ...d, info: parse(d.info as string, {}) })),
    usage: usage!.results,
    budget: Number(c.env.DAILY_ROW_BUDGET) || 100_000,
    recent: (recent!.results as Record<string, unknown>[]).map((r) => ({ ...r, summary: parse(r.summary as string, {}) })),
  });
});

// ---- enrollment & devices

admin.post("/enroll-codes", async (c) => {
  const b = await jsonBody(c.req.raw);
  const name = typeof b.name === "string" ? b.name.trim().slice(0, 64) : "";
  if (!name) throw new HttpError(400, "device name required");
  const site = typeof b.site_id === "string" && b.site_id ? b.site_id : null;
  if (site && !(await c.env.DB.prepare("SELECT 1 FROM sites WHERE id = ?").bind(site).first()))
    throw new HttpError(404, "no such site");
  const code = newEnrollCode();
  const now = new Date();
  const expires = nowIso(new Date(now.getTime() + 15 * 60_000));
  await c.env.DB.prepare(
    "INSERT INTO enroll_codes(code_hash, device_name, site_id, created_at, expires_at, created_by) VALUES (?,?,?,?,?,?)",
  )
    .bind(await sha256hex(normalizeEnrollCode(code)!), name, site, nowIso(now), expires, c.get("who").email)
    .run();
  // The code is shown once and never stored in clear.
  return c.json({ code, expires_at: expires, name });
});

admin.post("/devices/:id/revoke", async (c) => {
  const id = c.req.param("id");
  const now = nowIso();
  const [d] = await c.env.DB.batch([
    c.env.DB.prepare("UPDATE devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").bind(now, id),
    c.env.DB.prepare("UPDATE device_tokens SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL").bind(
      now,
      id,
    ),
  ]);
  if (!d!.meta.changes) throw new HttpError(404, "no such active device");
  return c.json({ ok: true, revoked_at: now });
});

admin.post("/devices/:id", async (c) => {
  const b = await jsonBody(c.req.raw);
  const name = typeof b.name === "string" ? b.name.trim().slice(0, 64) : null;
  const site = b.site_id === null || typeof b.site_id === "string" ? (b.site_id as string | null) || null : undefined;
  const r = await c.env.DB.prepare(
    "UPDATE devices SET name = COALESCE(?1, name), site_id = CASE WHEN ?2 = 1 THEN ?3 ELSE site_id END WHERE id = ?4",
  )
    .bind(name || null, site === undefined ? 0 : 1, site ?? null, c.req.param("id"))
    .run();
  if (!r.meta.changes) throw new HttpError(404, "no such device");
  return c.json({ ok: true });
});

// ---- sites

admin.get("/sites", async (c) => {
  const r = await c.env.DB.prepare("SELECT id, name, created_at FROM sites ORDER BY name LIMIT 500").all();
  return c.json({ sites: r.results });
});

admin.post("/sites", async (c) => {
  const b = await jsonBody(c.req.raw);
  const name = typeof b.name === "string" ? b.name.trim().slice(0, 80) : "";
  if (!name) throw new HttpError(400, "site name required");
  const id = uuid7();
  await c.env.DB.batch([
    c.env.DB.prepare("INSERT INTO sites(id, name, created_at) VALUES (?, ?, ?)").bind(id, name, nowIso()),
    bumpConfig(c.env.DB),
  ]);
  return c.json({ id, name });
});

// ---- runs / results / findings / audit

admin.get("/runs", async (c) => {
  const q = c.req.query();
  const before = q.before ?? "9999";
  const n = limit(q.limit);
  const stmt = q.device_id
    ? c.env.DB.prepare(
        "SELECT id, device_id, site_id, profile_id, started_at, finished_at, status, clock_synced, summary, results_pruned" +
          " FROM test_runs WHERE device_id = ? AND started_at < ? ORDER BY started_at DESC LIMIT ?",
      ).bind(q.device_id, before, n)
    : c.env.DB.prepare(
        "SELECT id, device_id, site_id, profile_id, started_at, finished_at, status, clock_synced, summary, results_pruned" +
          " FROM test_runs WHERE started_at < ? ORDER BY started_at DESC LIMIT ?",
      ).bind(before, n);
  const r = await stmt.all<{ summary: string; started_at: string }>();
  const runs = r.results.map((x) => ({ ...x, summary: parse(x.summary, {}) }));
  return c.json({ runs, next: runs.length === n ? runs[runs.length - 1]!.started_at : null });
});

admin.get("/runs/:id", async (c) => {
  const id = c.req.param("id");
  const [run, results, findings] = await c.env.DB.batch([
    c.env.DB.prepare("SELECT * FROM test_runs WHERE id = ?").bind(id),
    c.env.DB.prepare("SELECT body FROM test_results WHERE run_id = ? ORDER BY started_at LIMIT 500").bind(id),
    c.env.DB.prepare("SELECT * FROM findings WHERE run_id = ? LIMIT 500").bind(id),
  ]);
  const r = run!.results[0] as { summary: string } | undefined;
  if (!r) throw new HttpError(404, "no such run");
  return c.json({
    run: { ...r, summary: parse(r.summary, {}) },
    results: (results!.results as { body: string }[]).map((x) => parse(x.body, {})),
    findings: (findings!.results as { evidence: string }[]).map((f) => ({ ...f, evidence: parse(f.evidence, {}) })),
  });
});

admin.get("/findings", async (c) => {
  const q = c.req.query();
  const n = limit(q.limit);
  const r = await c.env.DB.prepare(
    "SELECT id, device_id, run_id, severity, rule_id, title, created_at, evidence FROM findings" +
      " WHERE created_at < ? ORDER BY created_at DESC LIMIT ?",
  )
    .bind(q.before ?? "9999", n)
    .all<{ evidence: string; created_at: string }>();
  const findings = r.results.map((f) => ({ ...f, evidence: parse(f.evidence, {}) }));
  return c.json({ findings, next: findings.length === n ? findings[findings.length - 1]!.created_at : null });
});

admin.get("/audit", async (c) => {
  const q = c.req.query();
  if (!q.device_id) throw new HttpError(400, "device_id required");
  const n = limit(q.limit);
  const r = await c.env.DB.prepare(
    "SELECT id, ts, actor, action, engagement_id, detail, prev_hash, hash FROM audit_log" +
      " WHERE device_id = ? AND ts < ? ORDER BY ts DESC LIMIT ?",
  )
    .bind(q.device_id, q.before ?? "9999", n)
    .all<{ detail: string; ts: string; prev_hash: string; hash: string }>();
  const entries = r.results.map((e) => ({ ...e, detail: parse(e.detail, {}) }));
  // Chain linkage within the page (newest first): each entry's prev_hash is the next one's hash.
  const linked = entries.map((e, i) => (i + 1 < entries.length ? e.prev_hash === entries[i + 1]!.hash : null));
  return c.json({ entries, linked, next: entries.length === n ? entries[entries.length - 1]!.ts : null });
});

// ---- profiles (pushed to devices via /api/v1/config)

function bumpConfig(db: D1Database): D1PreparedStatement {
  return db.prepare(
    "UPDATE settings SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'config_version'",
  );
}

export function checkProfile(p: unknown): string | null {
  if (!p || typeof p !== "object") return "profile must be an object";
  const x = p as Record<string, unknown>;
  if (typeof x.id !== "string" || !ID_RE.test(x.id)) return "id: lowercase letters, digits, . _ - (max 64)";
  if (typeof x.name !== "string" || !x.name.trim() || x.name.length > 80) return "name required (max 80)";
  if (x.interface !== undefined && x.interface !== "test-wired" && x.interface !== "test-wifi")
    return "interface: test-wired or test-wifi";
  if (!Array.isArray(x.steps) || x.steps.length === 0 || x.steps.length > 50) return "steps: 1-50 entries";
  for (const s of x.steps) {
    if (!s || typeof s !== "object") return "each step must be an object";
    const st = s as Record<string, unknown>;
    if (typeof st.module !== "string" || !/^[a-z0-9_]+(\.[a-z0-9_]+)+$/.test(st.module)) return "step.module invalid";
    if (st.config !== undefined && (typeof st.config !== "object" || Array.isArray(st.config)))
      return "step.config must be an object";
    if (st.thresholds !== undefined && !Array.isArray(st.thresholds)) return "step.thresholds must be a list";
  }
  // Credentials never live in the cloud: they stay in the device's local secret store.
  if (/"(password|passphrase|private_key_password|psk)"\s*:/i.test(JSON.stringify(x.steps)))
    return "credentials can't be stored in cloud profiles — save them on the device";
  return null;
}

admin.get("/profiles", async (c) => {
  const r = await c.env.DB.prepare("SELECT body, updated_at FROM profiles ORDER BY id LIMIT 200").all<{
    body: string;
    updated_at: string;
  }>();
  return c.json({ profiles: r.results.map((p) => ({ ...parse(p.body, {}), updated_at: p.updated_at })) });
});

admin.put("/profiles/:id", async (c) => {
  const b = await jsonBody(c.req.raw);
  if (b.id !== c.req.param("id")) throw new HttpError(400, "id in path and body differ");
  const err = checkProfile(b);
  if (err) throw new HttpError(400, err);
  const body = {
    id: b.id,
    name: b.name,
    description: typeof b.description === "string" ? b.description.slice(0, 500) : "",
    interface: b.interface ?? "test-wired",
    steps: b.steps,
  };
  await c.env.DB.batch([
    c.env.DB.prepare(
      "INSERT INTO profiles(id, body, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(id) DO UPDATE SET body = ?2, updated_at = ?3",
    ).bind(body.id, JSON.stringify(body), nowIso()),
    bumpConfig(c.env.DB),
  ]);
  return c.json(body);
});

admin.delete("/profiles/:id", async (c) => {
  const [r] = await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM profiles WHERE id = ?").bind(c.req.param("id")),
    bumpConfig(c.env.DB),
  ]);
  if (!r!.meta.changes) throw new HttpError(404, "no such profile");
  return c.json({ ok: true });
});

// ---- settings (retention)

const TUNABLE = ["retention_result_days", "retention_finding_days", "retention_usage_days"] as const;

admin.get("/settings", async (c) => {
  const r = await c.env.DB.prepare("SELECT key, value FROM settings").all<{ key: string; value: string }>();
  return c.json(Object.fromEntries(r.results.map((x) => [x.key, x.value])));
});

admin.post("/settings", async (c) => {
  const b = await jsonBody(c.req.raw);
  const stmts: D1PreparedStatement[] = [];
  for (const k of TUNABLE) {
    if (b[k] === undefined) continue;
    const v = Number(b[k]);
    if (!Number.isInteger(v) || v < 7 || v > 3650) throw new HttpError(400, `${k}: 7-3650 days`);
    stmts.push(c.env.DB.prepare("UPDATE settings SET value = ? WHERE key = ?").bind(String(v), k));
  }
  if (stmts.length) await c.env.DB.batch(stmts);
  return c.json({ ok: true });
});
