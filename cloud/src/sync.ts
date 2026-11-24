// SPDX-License-Identifier: GPL-3.0-only
// POST /api/v1/sync — device batches → D1, within the Workers Free budget (ARCHITECTURE §7.2):
//  * ≤ 40 D1 statements per request: multi-row INSERTs (≤ 100 bound params each) in one db.batch();
//    whatever doesn't fit is simply not acked and the device sends it next time.
//  * writes keyed by record id → replays are no-ops (runs are the exception: a run is sent again
//    when it finishes, so it is upserted — only by the device that created it).
//  * usage_meter is bumped once per request with the rows this request actually wrote.
//  * device_id / site_id come from the token, never from the payload.
import type { AuditEntry, Finding, RecordKind, TestResult, TestRun } from "./records.gen";
import { SCHEMA_VERSIONS } from "./records.gen";
import { HttpError, nowIso, readBody, utcDay, UUID_RE, type Env } from "./util";
import type { Device } from "./device";

export const MAX_STATEMENTS = 40;
export const MAX_PARAMS = 100;
export const MAX_WIRE_BYTES = 1_048_576; // compressed
export const MAX_PLAIN_BYTES = 4_194_304;
export const MAX_RECORD_BYTES = 512 * 1024;
export const MAX_RECORDS = 200;
const FIXED_STATEMENTS = 3; // usage read happens before; usage write + last_seen + slack

type Row = (string | number | null)[];
interface Table {
  sql: string; // INSERT INTO t(cols) VALUES
  cols: number;
  conflict: string;
}

const TABLES: Record<RecordKind, Table> = {
  test_run: {
    sql: "INSERT INTO test_runs(id, device_id, site_id, profile_id, started_at, finished_at, status, clock_synced, summary, received_at) VALUES ",
    cols: 10,
    conflict:
      " ON CONFLICT(id) DO UPDATE SET finished_at = excluded.finished_at, status = excluded.status," +
      " summary = excluded.summary, clock_synced = excluded.clock_synced, received_at = excluded.received_at" +
      " WHERE test_runs.device_id = excluded.device_id",
  },
  test_result: {
    sql: "INSERT INTO test_results(id, run_id, device_id, module_id, status, started_at, message, metrics, body) VALUES ",
    cols: 9,
    conflict: " ON CONFLICT(id) DO NOTHING",
  },
  finding: {
    sql: "INSERT INTO findings(id, device_id, run_id, severity, rule_id, title, created_at, evidence) VALUES ",
    cols: 8,
    conflict: " ON CONFLICT(id) DO NOTHING",
  },
  audit: {
    sql: "INSERT INTO audit_log(id, device_id, ts, actor, action, engagement_id, detail, prev_hash, hash) VALUES ",
    cols: 9,
    conflict: " ON CONFLICT(id) DO NOTHING",
  },
};
// Priority when the budget is nearly used up: only these are still accepted.
const ESSENTIAL: ReadonlySet<RecordKind> = new Set(["audit", "finding"]);

interface WireRecord {
  id: string;
  kind: string;
  v: number;
  data: Record<string, unknown>;
}
export interface Rejected {
  id: string;
  reason: string;
  retry: boolean; // true: keep it queued (e.g. newer schema than this server knows)
}

const STATUS = new Set(["pass", "warn", "fail", "error", "skipped"]);
const SEVERITY = new Set(["info", "low", "medium", "high", "critical"]);
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

const str = (v: unknown, max = 256): v is string => typeof v === "string" && v.length <= max;
const optStr = (v: unknown, max = 256): v is string | null | undefined => v == null || str(v, max);
const iso = (v: unknown): v is string => typeof v === "string" && ISO_RE.test(v);
const obj = (v: unknown): v is Record<string, unknown> =>
  v === undefined || (typeof v === "object" && v !== null && !Array.isArray(v));
const json = (v: unknown): string => JSON.stringify(v ?? {});
const normIso = (v: string): string => new Date(v).toISOString();

/** Validate one record and turn it into a row; returns a reason string when it's unacceptable. */
function toRow(r: WireRecord, dev: Device, received: string, size: number): Row | string {
  const d = r.data;
  if (size > MAX_RECORD_BYTES) return `record larger than ${MAX_RECORD_BYTES} bytes`;
  switch (r.kind as RecordKind) {
    case "test_run": {
      const x = d as TestRun;
      const status = x.status ?? "running";
      if (!iso(x.started_at) || !(x.finished_at == null || iso(x.finished_at))) return "bad timestamps";
      if (status !== "running" && !STATUS.has(status)) return "bad status";
      if (!optStr(x.profile_id, 64) || !optStr(x.site_id, 64) || !obj(x.summary)) return "bad fields";
      return [
        r.id,
        dev.id,
        dev.site_id ?? x.site_id ?? null,
        x.profile_id ?? null,
        normIso(x.started_at),
        x.finished_at ? normIso(x.finished_at) : null,
        status,
        x.clock_synced ? 1 : 0,
        json(x.summary),
        received,
      ];
    }
    case "test_result": {
      const x = d as unknown as TestResult;
      if (!str(x.run_id, 36) || !UUID_RE.test(x.run_id)) return "bad run_id";
      if (!str(x.module_id, 64) || !str(x.module_version, 32)) return "bad module";
      if (!STATUS.has(x.status)) return "bad status";
      if (!iso(x.started_at) || !iso(x.finished_at)) return "bad timestamps";
      if (!optStr(x.message, 2000) || !obj(x.metrics) || !obj(x.details)) return "bad fields";
      if (x.artifacts !== undefined && !Array.isArray(x.artifacts)) return "bad artifacts";
      return [
        r.id,
        x.run_id,
        dev.id,
        x.module_id,
        x.status,
        normIso(x.started_at),
        x.message ?? "",
        json(x.metrics),
        JSON.stringify(x),
      ];
    }
    case "finding": {
      const x = d as unknown as Finding;
      if (!SEVERITY.has(x.severity) || !str(x.rule_id, 128) || !str(x.title, 500)) return "bad fields";
      if (!(x.run_id == null || (typeof x.run_id === "string" && UUID_RE.test(x.run_id)))) return "bad run_id";
      if (!iso(x.created_at) || !obj(x.evidence)) return "bad fields";
      return [r.id, dev.id, x.run_id ?? null, x.severity, x.rule_id, x.title, normIso(x.created_at), json(x.evidence)];
    }
    case "audit": {
      const x = d as unknown as AuditEntry;
      if (!iso(x.ts) || !str(x.actor, 128) || !str(x.action, 128) || !obj(x.detail)) return "bad fields";
      if (!optStr(x.engagement_id, 64)) return "bad engagement_id";
      const hex = /^[0-9a-f]{64}$/;
      if (!str(x.prev_hash) || !hex.test(x.prev_hash) || !str(x.hash) || !hex.test(x.hash)) return "bad hash";
      // ts kept verbatim: it's part of the hashed body, so the chain can be re-verified here.
      return [r.id, dev.id, x.ts, x.actor, x.action, x.engagement_id ?? null, json(x.detail), x.prev_hash, x.hash];
    }
    default:
      return "unknown kind";
  }
}

export interface SyncLimits {
  max_records: number;
  max_bytes: number;
}

/** Budget level from today's meter: 0 normal, 1 back off (> 70 %), 2 essentials only (> 90 %), 3 full. */
export function budgetLevel(written: number, budget: number): 0 | 1 | 2 | 3 {
  const f = written / budget;
  return f >= 1 ? 3 : f > 0.9 ? 2 : f > 0.7 ? 1 : 0;
}

function secondsToUtcMidnight(now: Date): number {
  const m = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1);
  return Math.ceil((m - now.getTime()) / 1000);
}

export async function handleSync(req: Request, env: Env, dev: Device): Promise<Response> {
  const ctype = (req.headers.get("content-type") ?? "").split(";")[0]!.trim();
  if (ctype !== "application/json") throw new HttpError(415, "application/json expected");
  const text = await readBody(req, MAX_WIRE_BYTES, MAX_PLAIN_BYTES);
  let body: { batch_id?: unknown; records?: unknown };
  try {
    body = JSON.parse(text);
  } catch {
    throw new HttpError(400, "invalid JSON");
  }
  if (!Array.isArray(body.records)) throw new HttpError(400, "records[] expected");

  const now = new Date();
  const day = utcDay(now);
  const budget = Number(env.DAILY_ROW_BUDGET) || 100_000;
  const meter = await env.DB.prepare("SELECT rows_written FROM usage_meter WHERE day = ?")
    .bind(day)
    .first<{ rows_written: number }>();
  const level = budgetLevel(meter?.rows_written ?? 0, budget);
  const limits: SyncLimits = { max_records: level === 0 ? MAX_RECORDS : 50, max_bytes: 256_000 };

  const received = nowIso(now);
  const rejected: Rejected[] = [];
  const byKind = new Map<RecordKind, { ids: string[]; rows: Row[] }>();
  const seen = new Set<string>();
  for (const raw of body.records.slice(0, MAX_RECORDS)) {
    const r = raw as WireRecord;
    const id = typeof r?.id === "string" ? r.id : "";
    if (!UUID_RE.test(id) || typeof r.data !== "object" || r.data === null || seen.has(id)) {
      if (id) rejected.push({ id, reason: "malformed record", retry: false });
      continue;
    }
    seen.add(id);
    const kind = r.kind as RecordKind;
    if (!(kind in SCHEMA_VERSIONS)) {
      rejected.push({ id, reason: `unknown kind ${String(r.kind).slice(0, 32)}`, retry: true });
      continue;
    }
    if (r.v !== SCHEMA_VERSIONS[kind]) {
      // A newer device schema than this Worker knows: keep it queued until the cloud is updated.
      rejected.push({ id, reason: `schema_version ${r.v} not supported (have ${SCHEMA_VERSIONS[kind]})`, retry: r.v > SCHEMA_VERSIONS[kind] });
      continue;
    }
    if (r.data.id !== undefined && r.data.id !== id) {
      rejected.push({ id, reason: "id mismatch", retry: false });
      continue;
    }
    if (level === 3 || (level === 2 && !ESSENTIAL.has(kind))) continue; // deferred: not acked, not rejected
    const row = toRow(r, dev, received, JSON.stringify(r.data).length);
    if (typeof row === "string") {
      rejected.push({ id, reason: row, retry: false });
      continue;
    }
    const g = byKind.get(kind) ?? { ids: [], rows: [] };
    g.ids.push(id);
    g.rows.push(row);
    byKind.set(kind, g);
  }

  // Build multi-row statements; stop when the statement budget is used up (rest: not acked).
  const stmts: D1PreparedStatement[] = [];
  const acked: string[] = [];
  const order: RecordKind[] = ["audit", "finding", "test_run", "test_result"];
  outer: for (const kind of order) {
    const g = byKind.get(kind);
    if (!g) continue;
    const t = TABLES[kind];
    const per = Math.floor(MAX_PARAMS / t.cols);
    for (let i = 0; i < g.rows.length; i += per) {
      if (stmts.length >= MAX_STATEMENTS - FIXED_STATEMENTS) break outer;
      const chunk = g.rows.slice(i, i + per);
      const ph = `(${Array(t.cols).fill("?").join(",")})`;
      stmts.push(
        env.DB.prepare(t.sql + chunk.map(() => ph).join(",") + t.conflict).bind(...chunk.flat()),
      );
      acked.push(...g.ids.slice(i, i + per));
    }
  }

  let written = 0;
  if (stmts.length) {
    const res = await env.DB.batch(stmts);
    for (const r of res) written += r.meta.rows_written ?? 0;
  }
  // last_seen throttled to once per 10 min: the statement always runs, but only writes when stale.
  const stale = nowIso(new Date(now.getTime() - 10 * 60_000));
  const tail = await env.DB.batch([
    env.DB.prepare(
      "UPDATE devices SET last_seen_at = ?1 WHERE id = ?2 AND (last_seen_at IS NULL OR last_seen_at < ?3)",
    ).bind(received, dev.id, stale),
    env.DB.prepare(
      "INSERT INTO usage_meter(day, requests, rows_written) VALUES (?1, 1, ?2) ON CONFLICT(day) DO UPDATE" +
        " SET requests = requests + 1, rows_written = rows_written + ?2",
    ).bind(day, written + 1),
  ]);
  written += tail[0]?.meta.rows_written ?? 0;

  const after = budgetLevel((meter?.rows_written ?? 0) + written, budget);
  const out: Record<string, unknown> = { acked, rejected, limits, received_at: received };
  if (after >= 1) {
    out.backoff_s = after === 1 ? 900 : Math.min(3600, secondsToUtcMidnight(now));
  }
  return Response.json(out);
}
