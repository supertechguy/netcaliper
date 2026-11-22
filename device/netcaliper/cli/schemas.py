# SPDX-License-Identifier: GPL-3.0-only
"""Export record JSON Schemas (the device<->cloud contract) to /schemas."""

from __future__ import annotations

import json
from pathlib import Path

from ..core.records import RECORD_TYPES


def render() -> dict[str, str]:
    out: dict[str, str] = {}
    for t in RECORD_TYPES:
        schema = t.model_json_schema()
        schema["x-netcaliper"] = {"kind": t.KIND, "schema_version": t.SCHEMA_VERSION}
        out[f"{t.KIND}.schema.json"] = json.dumps(schema, indent=2, sort_keys=True) + "\n"
    return out


def export(out_dir: Path, check: bool = False) -> list[str]:
    """Write schemas; with check=True, return the names that differ instead of writing."""
    drift: list[str] = []
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, text in render().items():
        path = out_dir / name
        if check:
            if not path.exists() or path.read_text() != text:
                drift.append(name)
        else:
            path.write_text(text)
    return drift
