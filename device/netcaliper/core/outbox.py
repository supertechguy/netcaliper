# SPDX-License-Identifier: GPL-3.0-only
"""Outbox: every syncable record is enqueued in the same transaction that stores it."""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import timedelta

import aiosqlite

from .db import Database
from .ids import utcnow
from .records import Record

BACKOFF_BASE_S = 30
BACKOFF_CAP_S = 3600


def _iso(dt: object) -> str:
    return dt.isoformat() if hasattr(dt, "isoformat") else str(dt)


async def enqueue(conn: aiosqlite.Connection, record: Record) -> None:
    """Call inside the caller's transaction (no commit here)."""
    await conn.execute(
        "INSERT INTO outbox(record_id, kind, schema_version, priority, payload, created_at, next_attempt_at)"
        " VALUES (?,?,?,?,?,?,?) ON CONFLICT(record_id) DO UPDATE SET payload=excluded.payload,"
        " acked_at=NULL, attempts=0, next_attempt_at=excluded.next_attempt_at",
        (
            record.id,
            record.KIND,
            record.SCHEMA_VERSION,
            record.SYNC_PRIORITY,
            record.model_dump_json(),
            utcnow().isoformat(),
            utcnow().isoformat(),
        ),
    )


@dataclass(frozen=True)
class OutboxItem:
    record_id: str
    kind: str
    schema_version: int
    payload: dict[str, object]
    attempts: int


class Outbox:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def pending_count(self) -> int:
        async with self.db.conn.execute("SELECT count(*) FROM outbox WHERE acked_at IS NULL") as cur:
            row = await cur.fetchone()
        return int(row[0]) if row else 0

    async def next_batch(self, max_records: int = 200, max_bytes: int = 256_000) -> list[OutboxItem]:
        now = utcnow().isoformat()
        items: list[OutboxItem] = []
        size = 0
        async with self.db.conn.execute(
            "SELECT record_id, kind, schema_version, payload, attempts FROM outbox"
            " WHERE acked_at IS NULL AND next_attempt_at <= ? ORDER BY priority, created_at LIMIT ?",
            (now, max_records),
        ) as cur:
            async for row in cur:
                size += len(row["payload"])
                if items and size > max_bytes:
                    break
                items.append(
                    OutboxItem(
                        row["record_id"],
                        row["kind"],
                        row["schema_version"],
                        json.loads(row["payload"]),
                        row["attempts"],
                    )
                )
        return items

    async def ack(self, record_ids: list[str]) -> None:
        now = utcnow().isoformat()
        await self.db.conn.executemany(
            "UPDATE outbox SET acked_at=? WHERE record_id=?", [(now, rid) for rid in record_ids]
        )
        await self.db.conn.commit()

    async def fail(self, record_ids: list[str]) -> None:
        """Exponential backoff with jitter per record."""
        conn = self.db.conn
        for rid in record_ids:
            async with conn.execute("SELECT attempts FROM outbox WHERE record_id=?", (rid,)) as cur:
                row = await cur.fetchone()
            if row is None:
                continue
            attempts = int(row[0]) + 1
            delay = min(BACKOFF_CAP_S, BACKOFF_BASE_S * 2 ** (attempts - 1))
            delay = delay * (0.5 + random.random() / 2)  # noqa: S311 - jitter, not crypto
            nxt = utcnow() + timedelta(seconds=delay)
            await conn.execute(
                "UPDATE outbox SET attempts=?, next_attempt_at=? WHERE record_id=?",
                (attempts, nxt.isoformat(), rid),
            )
        await conn.commit()
