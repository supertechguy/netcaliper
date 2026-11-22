# SPDX-License-Identifier: GPL-3.0-only
"""netcaliper command line."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from ..core.config import load_settings


def _repo_schemas_dir() -> Path:
    return Path(__file__).resolve().parents[3] / "schemas"


def cmd_doctor(args: argparse.Namespace) -> int:
    from ..drivers.detect import detect
    from ..drivers.snapshot import anonymize, collect_real, dump_snapshot, load_fixture
    from .doctor import build_report, render_json, render_text

    settings = load_settings()
    mode = f"mock:{args.fixture}" if args.fixture else settings.hardware.mode
    snap = (
        load_fixture(mode.partition(":")[2] or "uconsole-cm4-full")
        if mode.startswith("mock")
        else collect_real()
    )
    if args.record:
        out = anonymize(snap) if args.anonymize else snap
        Path(args.record).write_text(dump_snapshot(out))
        print(f"snapshot written to {args.record}", file=sys.stderr)
    inv = detect(snap, settings.hardware.roles)
    rep = build_report(settings, snap, inv)
    print(
        render_json(rep) if args.json else render_text(rep, color=sys.stdout.isatty() and not args.no_color)
    )
    return 1 if rep.worst == "fail" else 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from ..web.app import create_app

    settings = load_settings()
    if args.data_dir:
        settings.data_dir = Path(args.data_dir)
    host = args.host or settings.web.host
    port = args.port or settings.web.port
    uvicorn.run(create_app(settings), host=host, port=port, log_level="info")
    return 0


def cmd_schemas(args: argparse.Namespace) -> int:
    from .schemas import export

    out = Path(args.out) if args.out else _repo_schemas_dir()
    drift = export(out, check=args.check)
    if args.check and drift:
        print("schemas out of date: " + ", ".join(drift) + " — run `netcaliper schemas`", file=sys.stderr)
        return 1
    return 0


def cmd_db(args: argparse.Namespace) -> int:
    from ..core.db import Database

    async def go() -> list[str]:
        async with Database(load_settings().db_path) as db:
            return await db.migrate()

    print("\n".join(asyncio.run(go())) or "up to date")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="netcaliper")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", help="report hardware, capabilities, dependencies, services")
    d.add_argument("--json", action="store_true")
    d.add_argument("--no-color", action="store_true")
    d.add_argument("--fixture", help="use a mock hardware fixture instead of the real system")
    d.add_argument("--record", metavar="FILE", help="write the raw system snapshot (fixture YAML)")
    d.add_argument("--anonymize", action="store_true", help="scrub MACs/serials when recording")
    d.set_defaults(fn=cmd_doctor)

    s = sub.add_parser("serve", help="run the web UI/API")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    s.add_argument("--data-dir")
    s.set_defaults(fn=cmd_serve)

    sc = sub.add_parser("schemas", help="export record JSON Schemas")
    sc.add_argument("--out")
    sc.add_argument("--check", action="store_true", help="fail if committed schemas are stale")
    sc.set_defaults(fn=cmd_schemas)

    db = sub.add_parser("db", help="apply database migrations")
    db.set_defaults(fn=cmd_db)

    args = ap.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
