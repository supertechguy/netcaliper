# SPDX-License-Identifier: GPL-3.0-only
"""SQLite (WAL) access with numbered SQL migrations shipped in netcaliper/core/migrations."""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from types import TracebackType

import aiosqlite


class Database:
    def __init__(self, path: Path | str) -> None:
        self.path = str(path)
        self._conn: aiosqlite.Connection | None = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("database not open")
        return self._conn

    async def open(self) -> Database:
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.execute("PRAGMA busy_timeout=5000")
        await self.migrate()
        return self

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    async def __aenter__(self) -> Database:
        return await self.open()

    async def __aexit__(
        self, et: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None
    ) -> None:
        await self.close()

    async def migrate(self) -> list[str]:
        conn = self.conn
        await conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY)")
        async with conn.execute("SELECT name FROM schema_migrations") as cur:
            done = {row[0] async for row in cur}
        applied: list[str] = []
        files = sorted(
            (f for f in resources.files("netcaliper.core.migrations").iterdir() if f.name.endswith(".sql")),
            key=lambda f: f.name,
        )
        for f in files:
            if f.name in done:
                continue
            await conn.executescript(f.read_text())
            await conn.execute("INSERT INTO schema_migrations(name) VALUES (?)", (f.name,))
            applied.append(f.name)
        await conn.commit()
        return applied
