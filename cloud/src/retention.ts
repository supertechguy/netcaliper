// SPDX-License-Identifier: GPL-3.0-only
// Daily cron. Stays under the per-invocation query limit: bounded loops, small chunks, and a run
// that doesn't finish simply continues tomorrow (the WHERE clauses are the cursor).
import { nowIso, setting, utcDay, type Env } from "./util";

const RUN_CHUNK = 20; // runs whose results are dropped per iteration
const MAX_ROUNDS = 8; // 3 statements each
const FINDING_CHUNK = 500;

export interface RetentionReport {
  runs_pruned: number;
  results_deleted: number;
  findings_deleted: number;
  usage_deleted: number;
  codes_deleted: number;
  statements: number;
}

export async function retention(env: Env, now = new Date()): Promise<RetentionReport> {
  const db = env.DB;
  const days = async (k: string, d: number) => Number(await setting(db, k, String(d))) || d;
  const ago = (n: number) => nowIso(new Date(now.getTime() - n * 86400_000));
  const resultCut = ago(await days("retention_result_days", 90));
  const findingCut = ago(await days("retention_finding_days", 365));
  const usageCut = utcDay(new Date(now.getTime() - (await days("retention_usage_days", 90)) * 86400_000));
  const rep: RetentionReport = {
    runs_pruned: 0,
    results_deleted: 0,
    findings_deleted: 0,
    usage_deleted: 0,
    codes_deleted: 0,
    statements: 3,
  };
  let written = 0;

  // Result bodies (the bulky part) go after N days; the run and its summary stay.
  for (let i = 0; i < MAX_ROUNDS; i++) {
    const runs = await db
      .prepare("SELECT id FROM test_runs WHERE started_at < ? AND results_pruned = 0 ORDER BY started_at LIMIT ?")
      .bind(resultCut, RUN_CHUNK)
      .all<{ id: string }>();
    rep.statements++;
    if (!runs.results.length) break;
    const ids = runs.results.map((r) => r.id);
    const ph = ids.map(() => "?").join(",");
    const [del, upd] = await db.batch([
      db.prepare(`DELETE FROM test_results WHERE run_id IN (${ph})`).bind(...ids),
      db.prepare(`UPDATE test_runs SET results_pruned = 1 WHERE id IN (${ph})`).bind(...ids),
    ]);
    rep.statements += 2;
    rep.results_deleted += del!.meta.changes ?? 0;
    rep.runs_pruned += upd!.meta.changes ?? 0;
    written += (del!.meta.rows_written ?? 0) + (upd!.meta.rows_written ?? 0);
    if (ids.length < RUN_CHUNK) break;
  }

  const [f, u, e] = await db.batch([
    db
      .prepare(
        "DELETE FROM findings WHERE id IN (SELECT id FROM findings WHERE created_at < ? ORDER BY created_at LIMIT ?)",
      )
      .bind(findingCut, FINDING_CHUNK),
    db.prepare("DELETE FROM usage_meter WHERE day < ?").bind(usageCut),
    db.prepare("DELETE FROM enroll_codes WHERE expires_at < ?").bind(ago(1)),
  ]);
  rep.statements += 3;
  rep.findings_deleted = f!.meta.changes ?? 0;
  rep.usage_deleted = u!.meta.changes ?? 0;
  rep.codes_deleted = e!.meta.changes ?? 0;
  written += (f!.meta.rows_written ?? 0) + (u!.meta.rows_written ?? 0) + (e!.meta.rows_written ?? 0);

  await db
    .prepare(
      "INSERT INTO usage_meter(day, requests, rows_written) VALUES (?1, 1, ?2) ON CONFLICT(day) DO UPDATE" +
        " SET requests = requests + 1, rows_written = rows_written + ?2",
    )
    .bind(utcDay(now), written + 1)
    .run();
  rep.statements++;
  return rep;
}
