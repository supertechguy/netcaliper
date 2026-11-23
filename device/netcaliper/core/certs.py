# SPDX-License-Identifier: GPL-3.0-only
"""Local certificate store for EAP-TLS / server validation (wired 802.1X and Wi-Fi).

Files live in `data_dir/certs/` (0700 dir, 0600 files) — outside SQLite, so they can never reach
the sync outbox. Names are restricted so they map to a fixed path; content must look like a PEM
certificate / key (or DER), so arbitrary files can't be planted here.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal

Kind = Literal["ca", "cert", "key"]
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$")
_EXT: dict[Kind, str] = {"ca": ".ca.pem", "cert": ".crt.pem", "key": ".key.pem"}
MAX_BYTES = 64 * 1024


class CertError(ValueError):
    pass


def _check(kind: Kind, data: bytes) -> None:
    if not data or len(data) > MAX_BYTES:
        raise CertError(f"file must be 1 B - {MAX_BYTES // 1024} KiB")
    text = data.decode("ascii", "replace")
    if kind in ("ca", "cert"):
        ok = "-----BEGIN CERTIFICATE-----" in text or data[:1] == b"\x30"  # PEM or DER SEQUENCE
    else:
        ok = (
            bool(re.search(r"-----BEGIN (ENCRYPTED |RSA |EC )?PRIVATE KEY-----", text)) or data[:1] == b"\x30"
        )
    if not ok:
        raise CertError("not a PEM/DER " + ("private key" if kind == "key" else "certificate"))


class CertStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, name: str, kind: Kind) -> Path:
        if not _NAME.match(name):
            raise CertError("name: letters, digits, . _ - (max 48)")
        return self.root / f"{name}{_EXT[kind]}"

    def put(self, name: str, kind: Kind, data: bytes) -> Path:
        _check(kind, data)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        path = self._path(name, kind)
        tmp = path.with_name(f".{path.name}.{os.getpid()}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
        return path

    def path(self, name: str, kind: Kind) -> Path | None:
        try:
            p = self._path(name, kind)
        except CertError:
            return None
        return p if p.is_file() else None

    def list(self) -> dict[str, list[Kind]]:
        """name -> kinds present."""
        out: dict[str, list[Kind]] = {}
        if not self.root.is_dir():
            return out
        for p in sorted(self.root.iterdir()):
            for kind, ext in _EXT.items():
                if p.name.endswith(ext) and not p.name.startswith("."):
                    out.setdefault(p.name[: -len(ext)], []).append(kind)
        return out

    def delete(self, name: str) -> None:
        for kind in _EXT:
            p = self.path(name, kind)
            if p is not None:
                p.unlink()
