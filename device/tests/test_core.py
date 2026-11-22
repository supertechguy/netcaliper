# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

import sqlite3
import uuid
from datetime import timedelta
from pathlib import Path

import pytest

from netcaliper.core.audit import AuditLog
from netcaliper.core.config import load_settings
from netcaliper.core.db import Database
from netcaliper.core.engagement import Engagement, ScopeError, ScopeGuard
from netcaliper.core.ids import utcnow, uuid7
from netcaliper.core.outbox import Outbox
from netcaliper.core.records import Finding, TestResult, TestRun
from netcaliper.core.repo import Repository


def test_uuid7_version_and_order() -> None:
    a, b = uuid7(), uuid7()
    assert a.version == 7 and a.variant == uuid.RFC_4122
    assert str(a)[:8] <= str(b)[:8]  # millisecond prefix is monotonic


def test_settings_file_and_env(tmp_path: Path) -> None:
    f = tmp_path / "n.toml"
    f.write_text('test_netns = "x"\n[web]\nport = 9000\n')
    s = load_settings(f, env={"NETCALIPER_WEB__HOST": "0.0.0.0", "NETCALIPER_HW": "mock:empty"})
    assert (s.test_netns, s.web.port, s.web.host, s.hardware.mode) == ("x", 9000, "0.0.0.0", "mock:empty")


async def test_migrations_idempotent(tmp_path: Path) -> None:
    async with Database(tmp_path / "a.db") as db:
        assert await db.migrate() == []


async def test_repo_writes_record_and_outbox_atomically(db: Database) -> None:
    repo, ob = Repository(db), Outbox(db)
    run = TestRun()
    await repo.save(run)
    now = utcnow()
    await repo.save(
        TestResult(
            run_id=run.id, module_id="x", module_version="1", status="pass", started_at=now, finished_at=now
        )
    )
    assert await ob.pending_count() == 2
    # a failing store must not leave an orphan outbox row
    with pytest.raises(sqlite3.IntegrityError):
        await repo.save(
            TestResult(
                run_id="missing-run",
                module_id="x",
                module_version="1",
                status="pass",
                started_at=now,
                finished_at=now,
            )
        )
    assert await ob.pending_count() == 2


async def test_outbox_priority_ack_and_backoff(db: Database) -> None:
    repo, ob, audit = Repository(db), Outbox(db), AuditLog(db)
    await repo.save(Finding(severity="low", rule_id="r", title="t"))
    await audit.append("tester", "x")
    batch = await ob.next_batch()
    assert [i.kind for i in batch] == ["audit", "finding"]  # audit log syncs first
    await ob.ack([batch[0].record_id])
    await ob.fail([batch[1].record_id])
    assert await ob.pending_count() == 1
    assert await ob.next_batch() == []  # backed off


async def test_audit_chain_detects_tampering(db: Database) -> None:
    log = AuditLog(db)
    for i in range(3):
        await log.append("t", "act", {"i": i})
    assert await log.verify() == (True, None)
    await db.conn.execute("UPDATE audit_log SET detail='{\"i\": 99}' WHERE seq=2")
    await db.conn.commit()
    assert await log.verify() == (False, 2)


def _eng(**kw: object) -> Engagement:
    base: dict[str, object] = dict(
        name="e",
        authorized_by="jer",
        authorized_cidrs=["10.0.0.0/24"],
        excluded_cidrs=["10.0.0.1/32"],
        expires_at=utcnow() + timedelta(hours=1),
    )
    base.update(kw)
    return Engagement.model_validate(base)


async def _fake_resolver(host: str) -> list[str]:
    return {"in.example": ["10.0.0.5"], "split.example": ["10.0.0.6", "192.168.1.1"]}[host]


@pytest.mark.parametrize(
    ("targets", "allowed"),
    [
        (["10.0.0.5"], True),
        (["10.0.0.0/25"], False),  # overlaps the excluded gateway
        (["10.0.0.128/25"], True),
        (["10.0.0.2-20"], True),
        (["10.0.0.1"], False),
        (["10.0.1.5"], False),
        (["in.example"], True),
        (["split.example"], False),  # every resolved address must be in scope
        ([], False),
    ],
)
async def test_scope_guard(targets: list[str], allowed: bool) -> None:
    d = await ScopeGuard(_eng(), resolver=_fake_resolver).check(targets)
    assert d.allowed is allowed


async def test_scope_guard_requires_live_engagement() -> None:
    with pytest.raises(ScopeError):
        await ScopeGuard(None).authorize(["10.0.0.5"])
    expired = _eng(expires_at=utcnow() - timedelta(seconds=1))
    assert not (await ScopeGuard(expired).check(["10.0.0.5"])).allowed
    limited = _eng(allowed_modules=["security.nmap"])
    assert not (await ScopeGuard(limited).check(["10.0.0.5"], module_id="security.vuln")).allowed
