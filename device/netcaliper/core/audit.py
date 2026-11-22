# SPDX-License-Identifier: GPL-3.0-only
"""Append-only, hash-chained audit log for active actions. Entries sync with top priority."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .db import Database
from .outbox import enqueue
from .records import AuditEntry

GENESIS = "0" * 64


def entry_hash(e: AuditEntry) -> str:
    body = e.model_dump(mode="json", exclude={"hash"})
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class AuditLog:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def _last_hash(self) -> str:
        async with self.db.conn.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1") as cur:
            row = await cur.fetchone()
        return str(row[0]) if row else GENESIS

    async def append(
        self, actor: str, action: str, detail: dict[str, Any] | None = None, engagement_id: str | None = None
    ) -> AuditEntry:
        conn = self.db.conn
        try:
            entry = AuditEntry(
                actor=actor,
                action=action,
                detail=detail or {},
                engagement_id=engagement_id,
                prev_hash=await self._last_hash(),
            )
            entry.hash = entry_hash(entry)
            await conn.execute(
                "INSERT INTO audit_log(id, ts, actor, action, engagement_id, detail, prev_hash, hash)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (
                    entry.id,
                    entry.ts.isoformat(),
                    actor,
                    action,
                    engagement_id,
                    json.dumps(entry.detail),
                    entry.prev_hash,
                    entry.hash,
                ),
            )
            await enqueue(conn, entry)
            await conn.commit()
        except BaseException:
            await conn.rollback()
            raise
        return entry

    async def verify(self) -> tuple[bool, int | None]:
        """Returns (ok, first_bad_seq)."""
        prev = GENESIS
        async with self.db.conn.execute(
            "SELECT seq, id, ts, actor, action, engagement_id, detail, prev_hash, hash"
            " FROM audit_log ORDER BY seq"
        ) as cur:
            async for row in cur:
                e = AuditEntry(
                    id=row["id"],
                    ts=row["ts"],
                    actor=row["actor"],
                    action=row["action"],
                    engagement_id=row["engagement_id"],
                    detail=json.loads(row["detail"]),
                    prev_hash=row["prev_hash"],
                )
                if row["prev_hash"] != prev or entry_hash(e) != row["hash"]:
                    return False, int(row["seq"])
                prev = row["hash"]
        return True, None
