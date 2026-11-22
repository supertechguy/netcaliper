-- SPDX-License-Identifier: GPL-3.0-only
CREATE TABLE IF NOT EXISTS sites (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS test_runs (
  id TEXT PRIMARY KEY, site_id TEXT, profile_id TEXT, started_at TEXT NOT NULL, finished_at TEXT,
  status TEXT NOT NULL, clock_synced INTEGER NOT NULL, summary TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_test_runs_started ON test_runs(started_at);
CREATE TABLE IF NOT EXISTS test_results (
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES test_runs(id), module_id TEXT NOT NULL,
  status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL, body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_test_results_run ON test_results(run_id);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, run_id TEXT, severity TEXT NOT NULL, rule_id TEXT NOT NULL,
  created_at TEXT NOT NULL, body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS engagements (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, expires_at TEXT NOT NULL, body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, ts TEXT NOT NULL,
  actor TEXT NOT NULL, action TEXT NOT NULL, engagement_id TEXT, detail TEXT NOT NULL,
  prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY, run_id TEXT, name TEXT NOT NULL, path TEXT NOT NULL,
  size INTEGER NOT NULL, sha256 TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS outbox (
  record_id TEXT PRIMARY KEY, kind TEXT NOT NULL, schema_version INTEGER NOT NULL,
  priority INTEGER NOT NULL DEFAULT 0, payload TEXT NOT NULL, created_at TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL, acked_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_outbox_pending ON outbox(acked_at, priority, next_attempt_at);
CREATE TABLE IF NOT EXISTS kv (
  key TEXT PRIMARY KEY, value TEXT NOT NULL
);
