# SPDX-License-Identifier: GPL-3.0-only
"""Remote browser access: one local admin password, session cookies, failed-login throttling.

* Loopback (the kiosk) never needs a login. Anything else must arrive on the TLS listener and carry a
  valid session; without a password set, remote access is simply closed.
* Password: scrypt (stdlib, memory-hard; N=2^15, r=8, p=1) in the local secret store (0600, never
  synced). It can only be set or removed at the device itself (loopback).
* Sessions: 32 random bytes in an HttpOnly, Secure, SameSite=Strict cookie; kept in memory only (a
  restart logs everyone out), 12 h absolute lifetime.
* Throttling: 5 failures per source address per 5 minutes, 20 overall, then 429 until the window passes.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import secrets as pysecrets
import time
from collections import deque

from ..core.secrets import SecretStore

SECRET = "web_admin"  # noqa: S105 - name of the secret-store entry, not a secret
COOKIE = "ncal_session"
SESSION_S = 12 * 3600
MIN_PASSWORD = 10
WINDOW_S = 300.0
PER_IP_FAILS = 5
GLOBAL_FAILS = 20
_N, _R, _P = 2**15, 8, 1


def _scrypt(password: str, salt: bytes, n: int = _N, r: int = _R, p: int = _P) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, maxmem=128 * 1024 * 1024, dklen=32)


class Auth:
    def __init__(self, secrets: SecretStore) -> None:
        self.secrets = secrets
        self._sessions: dict[str, float] = {}
        self._fails: dict[str, deque[float]] = {}
        self._all_fails: deque[float] = deque()

    # ---- password

    @property
    def configured(self) -> bool:
        s = self.secrets.get(SECRET)
        return bool(s and s.get("hash"))

    async def set_password(self, password: str) -> None:
        if len(password) < MIN_PASSWORD:
            raise ValueError(f"at least {MIN_PASSWORD} characters")
        if len(password) > 256:
            raise ValueError("at most 256 characters")
        salt = os.urandom(16)
        digest = await asyncio.to_thread(_scrypt, password, salt)
        self.secrets.put(
            SECRET,
            {
                "alg": "scrypt",
                "n": str(_N),
                "r": str(_R),
                "p": str(_P),
                "salt": salt.hex(),
                "hash": digest.hex(),
            },
        )
        self._sessions.clear()  # a new password ends every remote session

    def clear_password(self) -> None:
        self.secrets.delete(SECRET)
        self._sessions.clear()

    async def check_password(self, password: str) -> bool:
        s = self.secrets.get(SECRET)
        if not s or s.get("alg") != "scrypt" or len(password) > 256:
            return False
        digest = await asyncio.to_thread(
            _scrypt, password, bytes.fromhex(s["salt"]), int(s["n"]), int(s["r"]), int(s["p"])
        )
        return hmac.compare_digest(digest.hex(), s["hash"])

    # ---- throttling

    def _prune(self, q: deque[float], now: float) -> None:
        while q and now - q[0] > WINDOW_S:
            q.popleft()

    def throttled(self, ip: str) -> bool:
        now = time.monotonic()
        q = self._fails.get(ip, deque())
        self._prune(q, now)
        self._prune(self._all_fails, now)
        return len(q) >= PER_IP_FAILS or len(self._all_fails) >= GLOBAL_FAILS

    def failed(self, ip: str) -> None:
        now = time.monotonic()
        self._fails.setdefault(ip, deque()).append(now)
        self._all_fails.append(now)
        if len(self._fails) > 1000:  # bounded memory
            self._fails.pop(next(iter(self._fails)))

    # ---- sessions

    def new_session(self) -> str:
        now = time.monotonic()
        self._sessions = {k: v for k, v in self._sessions.items() if v > now}
        token = pysecrets.token_urlsafe(32)
        self._sessions[token] = now + SESSION_S
        return token

    def valid(self, token: str | None) -> bool:
        if not token:
            return False
        exp = self._sessions.get(token)
        if exp is None or exp < time.monotonic():
            self._sessions.pop(token, None)
            return False
        return True

    def end(self, token: str | None) -> None:
        if token:
            self._sessions.pop(token, None)


def cert_fingerprint(path: str) -> str | None:
    """SHA-256 fingerprint of a PEM certificate (to compare with what the browser shows)."""
    import base64
    import re
    from pathlib import Path

    try:
        pem = Path(path).read_text()
    except OSError:
        return None
    m = re.search(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", pem, re.S)
    if not m:
        return None
    der = base64.b64decode("".join(m.group(1).split()))
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i : i + 2] for i in range(0, len(h), 2))
