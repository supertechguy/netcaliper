# SPDX-License-Identifier: GPL-3.0-only
"""Repository: stores records and enqueues them for sync atomically."""

from __future__ import annotations

import json

from .db import Database
from .outbox import enqueue
from .records import Finding, Record, TestResult, TestRun


class Repository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def save(self, record: Record) -> None:
        conn = self.db.conn
        try:
            await self._store(record)
            await enqueue(conn, record)
            await conn.commit()
        except BaseException:
            await conn.rollback()
            raise

    async def _store(self, r: Record) -> None:
        conn = self.db.conn
        if isinstance(r, TestRun):
            await conn.execute(
                "INSERT INTO test_runs(id, site_id, profile_id, started_at, finished_at, status,"
                " clock_synced, summary) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET"
                " finished_at=excluded.finished_at, status=excluded.status, summary=excluded.summary",
                (
                    r.id,
                    r.site_id,
                    r.profile_id,
                    r.started_at.isoformat(),
                    r.finished_at.isoformat() if r.finished_at else None,
                    r.status,
                    int(r.clock_synced),
                    json.dumps(r.summary),
                ),
            )
        elif isinstance(r, TestResult):
            await conn.execute(
                "INSERT INTO test_results(id, run_id, module_id, status, started_at, finished_at, body)"
                " VALUES (?,?,?,?,?,?,?)",
                (
                    r.id,
                    r.run_id,
                    r.module_id,
                    r.status,
                    r.started_at.isoformat(),
                    r.finished_at.isoformat(),
                    r.model_dump_json(),
                ),
            )
        elif isinstance(r, Finding):
            await conn.execute(
                "INSERT INTO findings(id, run_id, severity, rule_id, created_at, body) VALUES (?,?,?,?,?,?)",
                (r.id, r.run_id, r.severity, r.rule_id, r.created_at.isoformat(), r.model_dump_json()),
            )
        else:
            raise TypeError(f"Repository cannot store {type(r).__name__}; use its dedicated store")
