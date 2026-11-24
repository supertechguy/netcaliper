# SPDX-License-Identifier: GPL-3.0-only
"""Cloud sync client (ARCHITECTURE §7.7). Runs in core, in the root namespace — test interfaces live
in `ncal-test`, so this traffic can only leave through the management uplink.

* Enrollment: a one-time code from the dashboard → device token, kept in the local secret store
  (0600, never synced). Only the token's SHA-256 exists in the cloud.
* Push: outbox batches, oldest/highest-priority first (audit log first), gzip JSON. The server says
  which records it stored (acked), refused for good (rejected) or wants later (neither); it can also
  ask us to back off (free-tier budget). Network/server errors → exponential backoff with jitter,
  capped at 1 h. A revoked token stops sync until the device is enrolled again.
* Pull: GET /config with ETag; cloud profiles are validated and written to `data_dir/cloud-profiles`
  (local profiles in /etc still win over them).
"""

from __future__ import annotations

import asyncio
import contextlib
import gzip
import json
import logging
import platform
import random
import socket
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .. import __version__
from .audit import AuditLog
from .https import HttpsError, check_url, request
from .outbox import Outbox
from .secrets import SecretStore

log = logging.getLogger(__name__)

SECRET = "cloud"  # noqa: S105 - name of the secret-store entry, not a secret
PUSH_IDLE_S = 30.0
PULL_EVERY_S = 900.0
BACKOFF_BASE_S = 30.0
BACKOFF_CAP_S = 3600.0
DEFAULT_MAX_RECORDS = 200
MAX_BYTES = 256_000


def platform_label() -> str:
    return f"{platform.system()}-{platform.machine()}"


class SyncError(Exception):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class CloudSync:
    def __init__(
        self,
        outbox: Outbox,
        secrets: SecretStore,
        audit: AuditLog,
        profiles_dir: Path,
        default_server: str,
        allowed: bool = True,
        known_modules: Callable[[], set[str]] | None = None,
        platform_name: Callable[[], str] = platform_label,
    ) -> None:
        self.outbox = outbox
        self.secrets = secrets
        self.audit = audit
        self.profiles_dir = profiles_dir
        self.default_server = default_server
        self.allowed = allowed
        self.known_modules = known_modules
        self.platform_name = platform_name
        self.max_records = DEFAULT_MAX_RECORDS
        self.max_bytes = MAX_BYTES
        self.last_ok: str | None = None
        self.last_pull: str | None = None
        self.last_error: str | None = None
        self.backoff_until = 0.0  # monotonic
        self.revoked = False
        self.site: str | None = None
        self.profile_ids: list[str] = []
        self.profiles_skipped: list[str] = []  # "id: reason" — shown in Settings
        self._failures = 0
        self._etag: str | None = None
        self._next_pull = 0.0
        self._wake = asyncio.Event()
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ state

    @property
    def creds(self) -> dict[str, str] | None:
        c = self.secrets.get(SECRET)
        return c if c and c.get("token") else None

    @property
    def enrolled(self) -> bool:
        return self.creds is not None

    @property
    def active(self) -> bool:
        return self.allowed and self.enrolled and not self.revoked

    def status(self) -> dict[str, Any]:
        c = self.creds or {}
        wait = max(0.0, self.backoff_until - time.monotonic())
        return {
            "allowed": self.allowed,
            "enrolled": bool(c),
            "server": c.get("server") or self.default_server,
            "device_id": c.get("device_id"),
            "device_name": c.get("name"),
            "site": self.site,
            "revoked": self.revoked,
            "last_ok": self.last_ok,
            "last_pull": self.last_pull,
            "last_error": self.last_error,
            "backoff_s": round(wait),
            "profiles": self.profile_ids,
            "profiles_skipped": self.profiles_skipped,
        }

    def wake(self) -> None:
        """Sync now (e.g. a run just finished, or the user pressed the button)."""
        self.backoff_until = 0.0
        self._next_pull = 0.0
        self._wake.set()

    # ------------------------------------------------------------------ enrollment

    async def enroll(self, code: str, server: str | None = None) -> dict[str, Any]:
        base = check_url(server or self.default_server)
        info = {
            "version": __version__,
            "platform": self.platform_name(),
            "hostname": socket.gethostname()[:64],
        }
        try:
            r = await request(
                "POST",
                f"{base}/api/v1/enroll",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"code": code.strip(), "info": info}).encode(),
                timeout=20,
            )
        except (OSError, TimeoutError) as e:
            raise SyncError(f"can't reach {base}: {e}") from e
        body = _json(r.body)
        if r.status != 200:
            raise SyncError(str(body.get("error") or f"enrollment failed ({r.status})"))
        token, device_id = body.get("token"), body.get("device_id")
        if not isinstance(token, str) or not isinstance(device_id, str):
            raise SyncError("unexpected enrollment response")
        self.secrets.put(
            SECRET,
            {"server": base, "token": token, "device_id": device_id, "name": str(body.get("name") or "")},
        )
        self.revoked, self.last_error, self._failures, self._etag = False, None, 0, None
        await self.audit.append("local", "cloud.enroll", {"server": base, "device_id": device_id})
        self.wake()
        return {"device_id": device_id, "name": body.get("name"), "server": base}

    async def unenroll(self) -> None:
        """Forget the token locally (revoke it in the dashboard too). Queued records stay queued."""
        c = self.creds
        self.secrets.delete(SECRET)
        self.revoked, self.last_ok, self.site, self._etag = False, None, None, None
        if c:
            await self.audit.append(
                "local", "cloud.unenroll", {"server": c.get("server"), "device_id": c.get("device_id")}
            )

    # ------------------------------------------------------------------ push

    async def push_once(self) -> dict[str, int]:
        """One batch. Returns counts; raises SyncError on transport/server errors."""
        c = self.creds
        if not c:
            raise SyncError("not enrolled")
        items = await self.outbox.next_batch(self.max_records, self.max_bytes)
        if not items:
            return {"sent": 0, "acked": 0, "rejected": 0}
        payload = {
            "batch_id": items[0].record_id,
            "records": [
                {"id": i.record_id, "kind": i.kind, "v": i.schema_version, "data": i.payload} for i in items
            ],
        }
        raw = await asyncio.to_thread(
            lambda: gzip.compress(json.dumps(payload, separators=(",", ":")).encode(), 6)
        )
        r = await self._call(
            "POST", "/api/v1/sync", c, raw, {"Content-Type": "application/json", "Content-Encoding": "gzip"}
        )
        if r.status == 413:
            self.max_records = max(1, len(items) // 2)
            self.max_bytes = max(16_000, self.max_bytes // 2)
            raise SyncError("batch too large; retrying smaller")
        body = self._check(r)
        acked = [x for x in body.get("acked", []) if isinstance(x, str)]
        rejected = [
            x for x in body.get("rejected", []) if isinstance(x, dict) and isinstance(x.get("id"), str)
        ]
        if acked:
            await self.outbox.ack(acked)
        final = {x["id"]: str(x.get("reason", "rejected")) for x in rejected if not x.get("retry")}
        if final:
            await self.outbox.reject(final)
            log.warning("cloud rejected %d record(s): %s", len(final), next(iter(final.values())))
        later = [x["id"] for x in rejected if x.get("retry")]
        if later:
            await self.outbox.fail(later)
        limits = body.get("limits") or {}
        if isinstance(limits.get("max_records"), int):
            self.max_records = max(1, min(DEFAULT_MAX_RECORDS, limits["max_records"]))
        if isinstance(limits.get("max_bytes"), int):
            self.max_bytes = max(16_000, min(MAX_BYTES, limits["max_bytes"]))
        if isinstance(body.get("backoff_s"), int | float) and body["backoff_s"] > 0:
            self.backoff_until = time.monotonic() + min(float(body["backoff_s"]), BACKOFF_CAP_S)
        self.last_ok, self.last_error, self._failures = _now(), None, 0
        return {"sent": len(items), "acked": len(acked), "rejected": len(final)}

    # ------------------------------------------------------------------ pull

    async def pull_config(self) -> bool:
        """Returns True when new config was applied."""
        c = self.creds
        if not c:
            raise SyncError("not enrolled")
        hdrs = {"If-None-Match": self._etag} if self._etag else {}
        r = await self._call("GET", "/api/v1/config", c, b"", hdrs)
        if r.status == 304:
            self.last_pull = self.last_ok = _now()
            return False
        body = self._check(r)
        self.last_pull = self.last_ok = _now()
        site = body.get("site")
        self.site = str(site.get("name")) if isinstance(site, dict) else None
        raw_profiles = body.get("profiles")
        profiles: list[Any] = raw_profiles if isinstance(raw_profiles, list) else []
        self.profile_ids, self.profiles_skipped = await asyncio.to_thread(self._write_profiles, profiles)
        self._etag = r.headers.get("etag")
        return True

    def _write_profiles(self, profiles: list[Any]) -> tuple[list[str], list[str]]:
        from ..modules.autotest import Profile

        known = self.known_modules() if self.known_modules else None
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        keep: set[str] = set()
        skipped: list[str] = []
        for raw in profiles:
            try:
                p = Profile.model_validate({**raw, "source": "cloud"})
            except (ValidationError, TypeError) as e:
                pid = raw.get("id", "?") if isinstance(raw, dict) else "?"
                skipped.append(f"{pid}: invalid ({str(e).splitlines()[0][:80]})")
                log.warning("cloud profile skipped: %s", e)
                continue
            if known is not None and (bad := [s.module for s in p.steps if s.module not in known]):
                skipped.append(f"{p.id}: unknown module(s) {', '.join(bad)}")
                log.warning("cloud profile %s skipped: unknown module(s) %s", p.id, bad)
                continue
            name = f"{p.id}.yaml"
            data = p.model_dump(mode="json", exclude={"source"})
            (self.profiles_dir / name).write_text(yaml.safe_dump(data, sort_keys=False))
            keep.add(name)
        for f in self.profiles_dir.glob("*.yaml"):
            if f.name not in keep:
                f.unlink()
        return sorted(k.removesuffix(".yaml") for k in keep), skipped

    # ------------------------------------------------------------------ transport

    async def _call(
        self, method: str, path: str, c: dict[str, str], body: bytes, headers: dict[str, str]
    ) -> Any:
        try:
            return await request(
                method,
                c["server"] + path,
                headers={"Authorization": f"Bearer {c['token']}", **headers},
                body=body,
                timeout=60,
            )
        except (OSError, TimeoutError, HttpsError, ValueError) as e:
            raise SyncError(f"network: {e or type(e).__name__}") from e

    def _check(self, r: Any) -> dict[str, Any]:
        body = _json(r.body)
        if r.status == 401:
            self.revoked = True
            raise SyncError("device token refused — revoked in the dashboard? Enroll again.")
        if r.status != 200:
            raise SyncError(f"server {r.status}: {body.get('error') or ''}".strip())
        return body

    # ------------------------------------------------------------------ loop

    async def run(self) -> None:
        while True:
            delay = PUSH_IDLE_S
            if self.active and time.monotonic() >= self.backoff_until:
                async with self._lock:
                    delay = await self._cycle()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), timeout=max(1.0, delay))
            self._wake.clear()

    async def sync_now(self) -> dict[str, Any]:
        """Manual 'Sync now': one push (draining a few batches) and a config pull."""
        if not self.enrolled:
            raise SyncError("not enrolled")
        self.revoked = False
        self.backoff_until = 0.0
        self._next_pull = 0.0
        async with self._lock:
            await self._cycle(max_batches=10)
        return self.status()

    async def _cycle(self, max_batches: int = 5) -> float:
        try:
            for _ in range(max_batches):
                res = await self.push_once()
                if res["sent"] < self.max_records or time.monotonic() < self.backoff_until:
                    break
            if time.monotonic() >= self._next_pull:
                await self.pull_config()
                self._next_pull = time.monotonic() + PULL_EVERY_S
        except SyncError as e:
            self.last_error = str(e)
            if self.revoked:
                return PUSH_IDLE_S
            self._failures += 1
            wait: float = min(BACKOFF_CAP_S, BACKOFF_BASE_S * 2.0 ** (self._failures - 1))
            wait *= 0.5 + random.random() / 2  # noqa: S311 - jitter, not crypto
            self.backoff_until = time.monotonic() + wait
            log.info("sync: %s (retry in %.0f s)", e, wait)
            return wait
        return max(PUSH_IDLE_S, self.backoff_until - time.monotonic())


def _json(raw: bytes) -> dict[str, Any]:
    try:
        v = json.loads(raw or b"{}")
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {}
