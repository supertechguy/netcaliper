# SPDX-License-Identifier: GPL-3.0-only
"""Local-only secrets (e.g. 802.1X credentials). A 0600 JSON file in the data dir — deliberately not
in SQLite, so nothing here can ever be enqueued in the sync outbox. Never logged, never rendered."""

from __future__ import annotations

import json
import os
from pathlib import Path


class SecretStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def _load(self) -> dict[str, dict[str, str]]:
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def get(self, name: str) -> dict[str, str] | None:
        v = self._load().get(name)
        return dict(v) if isinstance(v, dict) else None

    def put(self, name: str, value: dict[str, str]) -> None:
        data = self._load()
        data[name] = value
        self._write(data)

    def delete(self, name: str) -> None:
        data = self._load()
        if data.pop(name, None) is not None:
            self._write(data)

    def _write(self, data: dict[str, dict[str, str]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp, self.path)
