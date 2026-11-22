# SPDX-License-Identifier: GPL-3.0-only
"""Syncable record types. These are the single source of truth for the device<->cloud schema
(exported to /schemas as JSON Schema; the Worker's TS types are generated from them)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field

from .ids import new_id, utcnow

Status = Literal["pass", "warn", "fail", "error", "skipped"]
Severity = Literal["info", "low", "medium", "high", "critical"]


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid")
    KIND: ClassVar[str]
    SCHEMA_VERSION: ClassVar[int] = 1
    SYNC_PRIORITY: ClassVar[int] = 0  # lower syncs first

    id: str = Field(default_factory=new_id)


class TestRun(Record):
    __test__ = False  # not a pytest class
    KIND = "test_run"
    site_id: str | None = None
    profile_id: str | None = None
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    status: Status | Literal["running"] = "running"
    clock_synced: bool = False
    summary: dict[str, Any] = Field(default_factory=dict)


class TestResult(Record):
    __test__ = False
    KIND = "test_result"
    run_id: str
    module_id: str
    module_version: str
    status: Status
    started_at: datetime
    finished_at: datetime
    metrics: dict[str, float | int | str | bool | None] = Field(default_factory=dict)
    details: dict[str, Any] = Field(default_factory=dict)
    message: str = ""
    artifacts: list[ArtifactRef] = Field(default_factory=list)


class ArtifactRef(BaseModel):
    """Metadata only — artifact bytes never leave the device."""

    name: str
    size: int
    sha256: str


class Finding(Record):
    KIND = "finding"
    SYNC_PRIORITY = 1
    run_id: str | None = None
    severity: Severity
    rule_id: str
    title: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)


class AuditEntry(Record):
    KIND = "audit"
    SYNC_PRIORITY = -10  # audit log always syncs first
    ts: datetime = Field(default_factory=utcnow)
    actor: str
    action: str
    engagement_id: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = ""
    hash: str = ""


TestResult.model_rebuild()

RECORD_TYPES: tuple[type[Record], ...] = (TestRun, TestResult, Finding, AuditEntry)
