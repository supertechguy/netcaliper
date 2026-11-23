# SPDX-License-Identifier: GPL-3.0-only
"""Phase 1 plumbing: RPC, helper actions/ops, agent, test-plane reconcile, netns merge, hotplug."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

from netcaliper.agent.server import make_handlers as agent_handlers
from netcaliper.core.audit import AuditLog
from netcaliper.core.db import Database
from netcaliper.core.rpc import RpcClient, RpcError, RpcServer
from netcaliper.core.testplane import TestPlane, plan, watch_hotplug
from netcaliper.drivers.detect import detect
from netcaliper.drivers.registry import HardwareRegistry
from netcaliper.drivers.snapshot import NetInterface, Wiphy, load_fixture, merge_netns
from netcaliper.helper.actions import Action
from netcaliper.helper.ops import OpError, Ops
from netcaliper.helper.server import make_handlers as helper_handlers

NS = "ncal-test"
ACTION: TypeAdapter[Action] = TypeAdapter(Action)


# ---------------------------------------------------------------- action validation


def test_actions_are_strict() -> None:
    a = ACTION.validate_python({"action": "plane.move_in", "mac": "00:05:1B:D1:EB:73"})
    assert a.model_dump()["mac"] == "00:05:1b:d1:eb:73"
    for bad in (
        {"action": "plane.move_in", "mac": "eth1"},
        {"action": "plane.move_in", "mac": "00:05:1b:d1:eb:73; reboot"},
        {"action": "plane.move_in", "mac": "00:05:1b:d1:eb:73", "ifname": "eth0"},  # extra field
        {"action": "wifi.set_regdomain", "country": "USA"},
        {"action": "exec", "argv": ["sh"]},
        {"action": "nm.set_unmanaged", "macs": ["00:00:00:00:00:01"] * 33},
    ):
        with pytest.raises(ValidationError):
            ACTION.validate_python(bad)
    assert (
        ACTION.validate_python({"action": "wifi.set_regdomain", "country": "us"}).model_dump()["country"]
        == "US"
    )


# ---------------------------------------------------------------- RPC


@pytest.fixture
def sock(tmp_path: Path) -> Path:
    # AF_UNIX paths are limited to ~108 bytes; pytest tmp paths can exceed that.
    d = Path("/tmp") / f"ncal-test-{os.getpid()}-{tmp_path.name[-20:]}"
    d.mkdir(exist_ok=True)
    yield d / "s.sock"  # type: ignore[misc]
    for p in d.iterdir():
        p.unlink()
    d.rmdir()


async def test_rpc_roundtrip_and_errors(sock: Path) -> None:
    async def echo(params: dict[str, Any], peer: Any) -> Any:
        return {"got": params, "uid": peer.uid}

    async def boom(params: dict[str, Any], peer: Any) -> Any:
        raise KeyError("secret detail")

    srv = RpcServer(sock, {"echo": echo, "boom": boom}, {os.getuid()})
    await srv.start()
    try:
        assert oct(sock.stat().st_mode & 0o777) == "0o660"
        c = RpcClient(sock)
        assert await c.call("echo", {"a": 1}) == {"got": {"a": 1}, "uid": os.getuid()}
        with pytest.raises(RpcError) as e:
            await c.call("nope")
        assert e.value.code == "unknown_method"
        with pytest.raises(RpcError) as e:
            await c.call("boom")
        assert e.value.code == "internal" and "secret" not in e.value.message
        # raw garbage
        r, w = await asyncio.open_unix_connection(str(sock))
        w.write(b"not json\n")
        await w.drain()
        assert json.loads(await r.readline())["error"]["code"] == "bad_json"
        w.close()
    finally:
        await srv.close()
    assert not sock.exists()


async def test_rpc_rejects_unknown_uid(sock: Path) -> None:
    srv = RpcServer(sock, {}, allowed_uids={os.getuid() + 12345})
    await srv.start()
    try:
        with pytest.raises(RpcError) as e:
            await RpcClient(sock).call("ping")
        assert e.value.code == "denied"
    finally:
        await srv.close()


async def test_rpc_unreachable(tmp_path: Path) -> None:
    with pytest.raises(RpcError) as e:
        await RpcClient(tmp_path / "missing.sock").call("ping")
    assert e.value.code == "unreachable"


# ---------------------------------------------------------------- helper ops (fake sysfs + runner)


class FakeRunner:
    def __init__(self, netns_links: list[dict[str, Any]] | None = None, iw_wiphy: int | None = None) -> None:
        self.calls: list[list[str]] = []
        self.netns_links = netns_links or []
        self.iw_wiphy = iw_wiphy

    async def __call__(self, argv: list[str]) -> tuple[int, str, str]:
        self.calls.append(argv)
        if argv[:5] == ["ip", "-n", NS, "-j", "link"]:
            return 0, json.dumps(self.netns_links), ""
        if argv[-1] == "info" and "iw" in argv:
            return (
                (0, f"Interface x\n\twiphy {self.iw_wiphy}\n", "")
                if self.iw_wiphy is not None
                else (1, "", "")
            )
        return 0, "", ""


def fake_sysfs(root: Path) -> Path:
    net = root / "class/net"
    for name, mac, phy in (
        ("eth1", "00:05:1b:d1:eb:73", None),
        ("wlan2", "9c:ef:d5:f9:52:54", "phy1"),
        ("wlan0", "2c:cf:67:4a:0d:82", "phy0"),
    ):
        (net / name).mkdir(parents=True)
        (net / name / "address").write_text(mac + "\n")
        if phy:
            (net / name / "phy80211").mkdir()
            (net / name / "phy80211/name").write_text(phy + "\n")
    return root


@pytest.fixture
def ops(tmp_path: Path) -> tuple[Ops, FakeRunner]:
    runner = FakeRunner()
    (tmp_path / "netns").mkdir()
    (tmp_path / "netns" / NS).touch()
    (tmp_path / "nm").mkdir()
    o = Ops(
        NS,
        runner=runner,
        sysfs=fake_sysfs(tmp_path / "sys"),
        nm_conf=tmp_path / "nm/90-netcaliper-unmanaged.conf",
        netns_dir=tmp_path / "netns",
        default_routes=lambda: {"wlan0", "eth1"},
    )
    return o, runner


async def test_move_in_wired_and_wifi(ops: tuple[Ops, FakeRunner]) -> None:
    o, run = ops
    assert (await o.move_in("00:05:1b:d1:eb:73"))["ifname"] == "eth1"
    assert run.calls[-1] == ["ip", "link", "set", "dev", "eth1", "netns", NS]
    assert (await o.move_in("9c:ef:d5:f9:52:54"))["phy"] == "phy1"
    assert run.calls[-1] == ["iw", "phy", "phy1", "set", "netns", "name", NS]


async def test_move_in_refuses_sole_default_route(ops: tuple[Ops, FakeRunner]) -> None:
    o, _ = ops
    o.default_routes = lambda: {"wlan0"}
    with pytest.raises(OpError) as e:
        await o.move_in("2c:cf:67:4a:0d:82")
    assert e.value.code == "only_default_route"


async def test_move_in_unknown_and_already(ops: tuple[Ops, FakeRunner]) -> None:
    o, run = ops
    with pytest.raises(OpError):
        await o.move_in("de:ad:be:ef:00:01")
    run.netns_links = [{"ifname": "eth9", "address": "de:ad:be:ef:00:01"}]
    assert (await o.move_in("de:ad:be:ef:00:01"))["already"] is True


async def test_move_in_requires_netns(ops: tuple[Ops, FakeRunner]) -> None:
    o, _ = ops
    (o.netns_dir / NS).unlink()
    with pytest.raises(OpError) as e:
        await o.move_in("00:05:1b:d1:eb:73")
    assert e.value.code == "no_netns"


async def test_move_out(ops: tuple[Ops, FakeRunner]) -> None:
    o, run = ops
    run.netns_links = [{"ifname": "wlan5", "address": "aa:bb:cc:dd:ee:ff"}]
    run.iw_wiphy = 3
    await o.move_out("aa:bb:cc:dd:ee:ff")
    assert run.calls[-1] == ["ip", "netns", "exec", NS, "iw", "phy#3", "set", "netns", "1"]
    run.iw_wiphy = None
    await o.move_out("aa:bb:cc:dd:ee:ff")
    assert run.calls[-1] == ["ip", "-n", NS, "link", "set", "dev", "wlan5", "netns", "1"]
    assert (await o.move_out("00:05:1b:d1:eb:73"))["already"] is True  # still in root


async def test_nm_unmanaged_file(ops: tuple[Ops, FakeRunner]) -> None:
    o, _ = ops
    r = await o.set_nm_unmanaged(["9c:ef:d5:f9:52:54", "00:05:1b:d1:eb:73"])
    assert r["nm"] == "configured"
    body = o.nm_conf.read_text()
    assert "unmanaged-devices=mac:00:05:1b:d1:eb:73;mac:9c:ef:d5:f9:52:54" in body
    assert (await o.set_nm_unmanaged(["00:05:1b:d1:eb:73", "9c:ef:d5:f9:52:54"]))["nm"] == "unchanged"
    await o.set_nm_unmanaged([])
    assert not o.nm_conf.exists()


async def test_netns_up_down(ops: tuple[Ops, FakeRunner], tmp_path: Path) -> None:
    o, run = ops
    (o.netns_dir / NS).unlink()
    nft = tmp_path / "r.nft"
    nft.write_text("table inet netcaliper {}\n")
    done = await o.netns_up(nft)
    assert ["ip", "netns", "add", NS] in run.calls
    assert ["ip", "netns", "exec", NS, "nft", "-f", str(nft)] in run.calls
    assert any("net.ipv4.ip_forward=0" in c[-1] for c in run.calls)
    assert done[0] == f"created netns {NS}"
    with pytest.raises(OpError):
        await o.netns_up(tmp_path / "missing.nft")


async def test_helper_handlers_validate_before_acting(ops: tuple[Ops, FakeRunner]) -> None:
    o, run = ops
    h = helper_handlers(o)
    assert set(h) == {"ping", "nm.set_unmanaged", "plane.move_in", "plane.move_out", "wifi.set_regdomain"}
    with pytest.raises(RpcError) as e:
        await h["plane.move_in"]({"mac": "eth1"}, None)
    assert e.value.code == "invalid" and run.calls == []
    # `action` in params can't redirect to a different handler
    with pytest.raises(RpcError):
        await h["ping"]({"action": "plane.move_in", "mac": "00:05:1b:d1:eb:73"}, None)
    with pytest.raises(RpcError) as e:
        await h["plane.move_in"]({"mac": "de:ad:be:ef:00:02"}, None)
    assert e.value.code == "not_found"


async def test_agent_snapshot_handler(tmp_path: Path) -> None:
    h = agent_handlers(NS, sysfs=fake_sysfs(tmp_path))
    view = await h["snapshot.net"]({}, None)
    assert view["netns"] == NS and {n["name"] for n in view["net"]} == {"eth1", "wlan0", "wlan2"}
    assert (await h["ping"]({}, None))["netns"] == NS


# ---------------------------------------------------------------- netns merge + plan


def _split(fixture: str, macs_in_ns: set[str]) -> tuple[Any, list[NetInterface], list[Wiphy]]:
    """Simulate the real split: root sees everything except what's in the test netns."""
    snap = load_fixture(fixture)
    moved = [n for n in snap.net if n.mac in macs_in_ns]
    phys = {n.phy for n in moved if n.phy}
    root = snap.model_copy(deep=True)
    root.net = [n for n in root.net if n.mac not in macs_in_ns]
    root.wiphys = [w for w in root.wiphys if w.name not in phys]
    return root, moved, [w for w in snap.wiphys if w.name in phys]


def test_plan_moves_test_roles_in() -> None:
    inv = detect(load_fixture("uconsole-cm4-dongles"))
    p = plan(inv, NS)
    names = {s.name.split()[1] for s in p.steps}
    assert {s.op for s in p.steps} == {"plane.move_in"}
    assert names == {"AX88179", "MT7610U", "RTL8188CUS"}
    assert len(p.unmanaged_macs) == 3


def test_merge_keeps_roles_and_tags_netns() -> None:
    full = load_fixture("uconsole-cm4-dongles")
    test_macs = {d.mac for d in detect(full).devices if d.role in ("test-wired", "test-wifi", "monitor")}
    root, moved, phys = _split("uconsole-cm4-dongles", test_macs)
    for n in moved:
        n.default_route = True  # e.g. DHCP inside the test netns: must not make it mgmt
    merged = merge_netns(root, NS, moved, phys)
    inv = detect(merged)
    roles = {d.name.split()[1]: (d.role, d.netns) for d in inv.devices if d.kind in ("nic", "wifi")}
    assert roles["AX88179"] == ("test-wired", NS)
    assert roles["MT7610U"] == ("monitor", NS)
    assert roles["RTL8188CUS"] == ("test-wifi", NS)
    assert roles["(brcmfmac)"] == ("mgmt", None)
    assert plan(inv, NS).steps == []


def test_plan_releases_devices_that_left_test_roles() -> None:
    full = load_fixture("uconsole-cm4-dongles")
    inv = detect(full)
    ax = next(d for d in inv.devices if "AX88179" in d.name)
    root, moved, phys = _split("uconsole-cm4-dongles", {ax.mac or ""})
    inv = detect(merge_netns(root, NS, moved, phys), {ax.id: "unused"})
    steps = [s for s in plan(inv, NS).steps if s.mac == ax.mac]
    assert [s.op for s in steps] == ["plane.move_out"]


class FakeHelper:
    def __init__(self, fail: set[str] | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.fail = fail or set()

    async def call(
        self, method: str, params: dict[str, Any] | None = None, timeout: float | None = None
    ) -> Any:
        self.calls.append((method, params or {}))
        if (params or {}).get("mac") in self.fail:
            raise RpcError("command_failed", "boom")
        return {"moved": True}


async def test_testplane_reconcile_audits_and_is_idempotent(db: Database) -> None:
    inv = detect(load_fixture("uconsole-cm4-dongles"))
    ax = next(d for d in inv.devices if "AX88179" in d.name)
    helper = FakeHelper(fail={ax.mac or ""})
    audit = AuditLog(db)
    tp = TestPlane(helper, NS, audit)
    out = await tp.reconcile(inv)
    assert helper.calls[0][0] == "nm.set_unmanaged"
    assert sum(o.ok for o in out) == 2 and tp.last_error and "command_failed" in tp.last_error
    rows = await (await db.conn.execute("SELECT action FROM audit_log ORDER BY rowid")).fetchall()
    assert sorted(r[0] for r in rows) == ["plane.move_in", "plane.move_in", "plane.move_in.failed"]
    assert (await audit.verify())[0]
    # Same inventory, NM already configured: only the move steps are retried, NM isn't touched.
    helper.calls.clear()
    await tp.reconcile(inv)
    assert all(m != "nm.set_unmanaged" for m, _ in helper.calls)


async def test_testplane_helper_down() -> None:
    class Down:
        async def call(self, method: str, params: Any = None, timeout: float | None = None) -> Any:
            raise RpcError("unreachable", "helper.sock")

    tp = TestPlane(Down(), NS)
    assert await tp.reconcile(detect(load_fixture("uconsole-cm4-dongles"))) == []
    assert tp.last_error and "unreachable" in tp.last_error


# ---------------------------------------------------------------- registry + agent


class FakeAgent:
    def __init__(self, net: list[NetInterface], wiphys: list[Wiphy], fail: bool = False) -> None:
        self.net, self.wiphys, self.fail = net, wiphys, fail

    async def call(self, method: str, params: Any = None, timeout: float | None = None) -> Any:
        if self.fail:
            raise RpcError("unreachable", "agent.sock")
        assert method == "snapshot.net"
        return {
            "netns": NS,
            "net": [n.model_dump() for n in self.net],
            "wiphys": [w.model_dump() for w in self.wiphys],
        }


async def test_registry_merges_agent_view() -> None:
    full = load_fixture("uconsole-cm4-dongles")
    mt = next(d for d in detect(full).devices if "MT7610U" in d.name)
    root, moved, phys = _split("uconsole-cm4-dongles", {mt.mac or ""})
    reg = HardwareRegistry(lambda: root, agent=FakeAgent(moved, phys))
    inv = await reg.refresh()
    dev = next(d for d in inv.devices if "MT7610U" in d.name)
    assert dev.netns == NS and dev.role == "monitor"

    reg.agent = FakeAgent([], [], fail=True)
    inv = await reg.refresh()
    assert any("agent unreachable" in w for w in inv.warnings)
    assert not any("MT7610U" in d.name for d in inv.devices)


# ---------------------------------------------------------------- hotplug


async def test_hotplug_watcher_fires_once_per_change() -> None:
    sigs = iter([("a",), ("a",), ("a", "b"), ("a", "b"), ("a", "b")])
    last = ("a", "b")
    fired = asyncio.Event()
    count = 0

    def sig() -> tuple[str, ...]:
        return next(sigs, last)

    async def changed() -> None:
        nonlocal count
        count += 1
        fired.set()

    task = asyncio.create_task(watch_hotplug(changed, 0.01, signature=sig, settle=0.01))
    await asyncio.wait_for(fired.wait(), 2)
    await asyncio.sleep(0.1)
    task.cancel()
    assert count == 1


async def test_rpc_public_methods_for_other_uids(sock: Path) -> None:
    async def ping(params: dict[str, Any], peer: Any) -> Any:
        return "pong"

    async def act(params: dict[str, Any], peer: Any) -> Any:
        return "did it"

    srv = RpcServer(sock, {"ping": ping, "act": act}, {os.getuid() + 1}, public_methods=frozenset({"ping"}))
    await srv.start()
    try:
        c = RpcClient(sock)
        assert await c.call("ping") == "pong"
        with pytest.raises(RpcError) as e:
            await c.call("act")
        assert e.value.code == "denied"
    finally:
        await srv.close()
