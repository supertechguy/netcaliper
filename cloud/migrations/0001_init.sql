-- SPDX-License-Identifier: GPL-3.0-only
-- netcaliper cloud schema v1. Free-tier budget (ARCHITECTURE §7.2): every index costs a written row
-- per insert, so only columns that are actually filtered/sorted on are indexed.

CREATE TABLE sites (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  site_id TEXT REFERENCES sites(id),
  created_at TEXT NOT NULL,
  last_seen_at TEXT,
  revoked_at TEXT,
  info TEXT NOT NULL DEFAULT '{}'           -- version / platform reported at enrollment and sync
);

-- One-time enrollment codes: only the SHA-256 is stored; 15 min TTL; single use.
CREATE TABLE enroll_codes (
  code_hash TEXT PRIMARY KEY,
  device_name TEXT NOT NULL,
  site_id TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_by TEXT NOT NULL
);

-- Device bearer tokens (32 random bytes): only the SHA-256 is stored.
CREATE TABLE device_tokens (
  token_hash TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id),
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE test_runs (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  site_id TEXT,
  profile_id TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,
  clock_synced INTEGER NOT NULL,
  summary TEXT NOT NULL DEFAULT '{}',
  received_at TEXT NOT NULL,
  results_pruned INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX ix_runs_started ON test_runs(started_at);
CREATE INDEX ix_runs_device ON test_runs(device_id, started_at);

-- One row per module result. `body` = the full result JSON (details included); dropped by the
-- retention cron after N days while the run + its summary stay.
CREATE TABLE test_results (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  module_id TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  message TEXT NOT NULL DEFAULT '',
  metrics TEXT NOT NULL DEFAULT '{}',
  body TEXT NOT NULL
);
CREATE INDEX ix_results_run ON test_results(run_id);

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  run_id TEXT,
  severity TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  created_at TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX ix_findings_created ON findings(created_at);

-- Hash-chained on the device; stored as received so the chain can be re-verified here.
CREATE TABLE audit_log (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  engagement_id TEXT,
  detail TEXT NOT NULL DEFAULT '{}',
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX ix_audit_device_ts ON audit_log(device_id, ts);

-- Profiles pushed down to devices (GET /api/v1/config). Body = the device's Profile YAML model as JSON.
CREATE TABLE profiles (
  id TEXT PRIMARY KEY,
  body TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- One row per UTC day, bumped once per request (never per row).
CREATE TABLE usage_meter (
  day TEXT PRIMARY KEY,
  requests INTEGER NOT NULL DEFAULT 0,
  rows_written INTEGER NOT NULL DEFAULT 0,
  rows_read INTEGER NOT NULL DEFAULT 0
);

-- Tunables (retention days, config version for ETag, retention cursor).
CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT INTO settings(key, value) VALUES
  ('config_version', '1'),
  ('retention_result_days', '90'),
  ('retention_finding_days', '365'),
  ('retention_usage_days', '90');
