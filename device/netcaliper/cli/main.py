# SPDX-License-Identifier: GPL-3.0-only
"""netcaliper command line."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any

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
    agent_note = None
    if not mode.startswith("mock") and settings.agent_socket.exists():
        snap, agent_note = _merge_agent_view(settings, snap)
    inv = detect(snap, settings.hardware.roles)
    if agent_note:
        inv.warnings.append(agent_note)
    rep = build_report(settings, snap, inv)
    print(
        render_json(rep) if args.json else render_text(rep, color=sys.stdout.isatty() and not args.no_color)
    )
    return 1 if rep.worst == "fail" else 0


def _merge_agent_view(settings: Any, snap: Any) -> tuple[Any, str | None]:
    from ..core.rpc import RpcClient, RpcError
    from ..drivers.snapshot import NetInterface, Wiphy, merge_netns

    try:
        view = asyncio.run(RpcClient(settings.agent_socket, timeout=10).call("snapshot.net"))
    except (RpcError, TimeoutError, OSError) as e:
        return snap, f"test-plane agent unreachable ({e}); test-netns devices not shown"
    merged = merge_netns(
        snap,
        str(view["netns"]),
        [NetInterface.model_validate(n) for n in view["net"]],
        [Wiphy.model_validate(w) for w in view["wiphys"]],
    )
    return merged, None


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


def _daemon_logging() -> None:
    import logging

    # journald adds timestamps; keep lines short.
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


def cmd_helper(args: argparse.Namespace) -> int:
    from ..helper.ops import Ops
    from ..helper.server import build_server

    _daemon_logging()
    settings = load_settings()
    server = build_server(Ops(settings.test_netns), settings.helper_socket, args.service_user)
    asyncio.run(server.serve_forever())
    return 0


def cmd_agent(args: argparse.Namespace) -> int:
    from ..agent.server import build_server

    _daemon_logging()
    settings = load_settings()
    asyncio.run(build_server(settings.test_netns, settings.agent_socket).serve_forever())
    return 0


def cmd_netns(args: argparse.Namespace) -> int:
    from ..helper.ops import OpError, Ops

    settings = load_settings()
    ops = Ops(settings.test_netns)
    nft = Path(args.nft) if args.nft else settings.config_dir / "nftables/ncal-test.nft"
    try:
        done = asyncio.run(
            ops.netns_up(nft if nft.exists() or args.nft else None)
            if args.action == "up"
            else ops.netns_down()
        )
    except OpError as e:
        print(f"netns {args.action} failed: {e}", file=sys.stderr)
        return 1
    for line in done:
        print(line)
    return 0


def main(argv: list[str] | None = None) -> int:
    from .. import __version__

    ap = argparse.ArgumentParser(prog="netcaliper")
    ap.add_argument("--version", action="version", version=f"netcaliper {__version__}")
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

    h = sub.add_parser("helper", help="run the privileged helper daemon (root; systemd)")
    h.add_argument("--service-user", default="netcaliper")
    h.set_defaults(fn=cmd_helper)

    ag = sub.add_parser("agent", help="run the test-plane agent (inside the test netns; systemd)")
    ag.set_defaults(fn=cmd_agent)

    ns = sub.add_parser("netns", help="create/tear down the test network namespace (root)")
    ns.add_argument("action", choices=["up", "down"])
    ns.add_argument("--nft", help="nftables ruleset to load inside the namespace")
    ns.set_defaults(fn=cmd_netns)

    args = ap.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
