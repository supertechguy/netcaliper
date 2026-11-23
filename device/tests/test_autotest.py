# SPDX-License-Identifier: GPL-3.0-only
"""AutoTest orchestration on MockNet, the agent's module.run contract, and the web flow."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from netcaliper.agent.server import make_handlers
from netcaliper.core.audit import AuditLog
from netcaliper.core.config import Settings
from netcaliper.core.db import Database
from netcaliper.core.repo import Repository
from netcaliper.core.rpc import Peer, RpcError
from netcaliper.drivers.registry import HardwareRegistry
from netcaliper.modules.autotest import AutoTest, Busy, Profile, load_profiles
from netcaliper.modules.base import Activity, ModuleConfig, ModuleResult, RunContext, TestModule
from netcaliper.modules.registry import all_modules
from netcaliper.modules.runner import ModuleRunner, ModuleStep
from netcaliper.net.mock import MockNet
from netcaliper.web.app import create_app

PEER = Peer(pid=1, uid=0, gid=0)


def _at(db: Database, registry: HardwareRegistry, net: Any, **kw: Any) -> tuple[AutoTest, Repository]:
    repo = Repository(db)
    return AutoTest(ModuleRunner(all_modules(), repo, AuditLog(db)), registry, repo, net=net, **kw), repo


def _fast(p: Profile) -> Profile:
    """The default profile with the LLDP listen window shortened."""
    for s in p.steps:
        if s.module == "wired.switchinfo":
            s.config["listen_s"] = 0.2
    return p


def by_module(run: Any) -> dict[str, Any]:
    return {s.module: s for s in run.steps}


def test_builtin_and_local_profiles(tmp_path: Path) -> None:
    (tmp_path / "default.yaml").write_text("id: default\nname: Mine\nsteps: [{module: wired.link}]\n")
    (tmp_path / "broken.yaml").write_text("id: [\n")
    (tmp_path / "bad.yaml").write_text("name: no id\nsteps: []\n")
    ps = load_profiles(tmp_path)
    assert set(ps) == {"default", "wifi"} and ps["default"].name == "Mine" and ps["default"].source == "local"
    mods = all_modules()
    for builtin in load_profiles().values():
        assert builtin.source == "builtin" and all(s.module in mods for s in builtin.steps)
        for s in builtin.steps:
            mods[s.module].Config.model_validate(s.config)
    assert load_profiles()["wifi"].interface == "test-wifi"


async def test_default_profile_on_healthy_network(db: Database, registry: HardwareRegistry) -> None:
    at, repo = _at(db, registry, MockNet())
    at.start(_fast(load_profiles()["default"]))
    run = await at.wait()
    assert run is not None and run.done
    m = by_module(run)
    assert all(s.status in ("pass", "warn") for s in run.steps), [
        (s.module, s.status, s.message) for s in run.steps
    ]
    assert m["wired.switchinfo"].metrics["switch"] == "idf2-access-sw1"
    assert m["wired.dhcp"].metrics["servers"] == 1
    # Persisted: run + one result per step; the summary counts add up.
    stored = await repo.get_run(run.run_id)
    assert stored is not None and stored.status == run.status and stored.finished_at is not None
    assert len(await repo.results(run.run_id)) == len(run.steps)
    assert sum(stored.summary["counts"].values()) == len(run.steps)
    # Outbox has the run (once, upserted) and every result.
    cur = await db.conn.execute("SELECT kind, COUNT(*) FROM outbox GROUP BY kind")
    counts = dict(await cur.fetchall())
    assert counts["test_run"] == 1 and counts["test_result"] == len(run.steps)


async def test_rogue_dhcp_is_a_finding(db: Database, registry: HardwareRegistry) -> None:
    at, repo = _at(db, registry, MockNet(rogue_dhcp=True))
    at.start(_fast(load_profiles()["default"]))
    run = await at.wait()
    assert run is not None
    assert by_module(run)["wired.dhcp"].status == "warn"
    f = await repo.findings(run.run_id)
    assert [x.rule_id for x in f] == ["dhcp.multiple_servers"] and f[0].severity == "high"
    assert "10.99.0.1" in f[0].evidence["suspects"]


async def test_failures_cascade_sensibly(db: Database, registry: HardwareRegistry) -> None:
    at, _ = _at(db, registry, MockNet(no_dhcp=True))
    at.start(_fast(load_profiles()["default"]))
    run = await at.wait()
    assert run is not None and run.status == "fail"
    m = by_module(run)
    assert m["wired.dhcp"].status == "fail"
    assert m["net.dns"].status == "skipped" and m["net.gateway"].status == "skipped"

    at, _ = _at(db, registry, MockNet(dead_gateway=True))
    at.start(_fast(load_profiles()["default"]))
    run = await at.wait()
    assert run is not None and by_module(run)["net.gateway"].status == "fail"


async def test_thresholds_from_profile_apply(db: Database, registry: HardwareRegistry) -> None:
    at, _ = _at(db, registry, MockNet())
    p = Profile(
        id="t",
        name="t",
        steps=[
            ModuleStep(module="wired.dhcp"),
            ModuleStep(module="net.gateway", thresholds=[{"metric": "rtt_avg_ms", "fail": "> 0.001"}]),  # type: ignore[list-item]
        ],
    )
    at.start(p)
    run = await at.wait()
    assert run is not None and by_module(run)["net.gateway"].status == "fail"


async def test_one_run_at_a_time_and_cancel(db: Database, registry: HardwareRegistry) -> None:
    at, repo = _at(db, registry, MockNet(delay=5))
    p = load_profiles()["default"]
    run = at.start(p)
    with pytest.raises(Busy):
        at.start(p)
    await asyncio.sleep(0.05)
    await at.cancel()
    assert run.done and run.message == "cancelled" and run.status == "error"
    stored = await repo.get_run(run.run_id)
    assert stored is not None and stored.status == "error"


async def test_no_test_interface_skips_test_ns_steps(db: Database) -> None:
    reg = HardwareRegistry.from_mode("mock:uconsole-cm4")
    await reg.refresh()
    at, _ = _at(db, reg, MockNet())
    at.start(_fast(load_profiles()["default"]))
    run = await at.wait()
    assert run is not None and all(s.status == "skipped" for s in run.steps)


async def test_real_mode_requires_interface_in_test_netns(db: Database, registry: HardwareRegistry) -> None:
    class Agent:
        calls: list[str] = []

        async def call(
            self, method: str, params: dict[str, Any] | None = None, timeout: float | None = None
        ) -> Any:
            self.calls.append(method)
            raise AssertionError("must not be called")

    agent = Agent()
    at, _ = _at(db, registry, None, agent=agent, test_netns="ncal-test")
    at.start(_fast(load_profiles()["default"]))
    run = await at.wait()
    assert run is not None and all(s.status == "skipped" for s in run.steps)
    assert "test namespace" in run.steps[0].message and agent.calls == []


# ---------------------------------------------------------------- agent


@pytest.fixture
def sysfs(tmp_path: Path) -> Path:
    (tmp_path / "class/net/eth1").mkdir(parents=True)
    return tmp_path


async def test_agent_module_run_roundtrip_keeps_session(
    sysfs: Path, db: Database, registry: HardwareRegistry
) -> None:
    h = make_handlers("ncal-test", sysfs, net=MockNet())
    r = await h["module.run"]({"module": "wired.dhcp", "config": {}, "ifname": "eth1", "run_id": "r1"}, PEER)
    assert r["result"]["status"] == "pass" and r["session"]["lease"]["ip"] == "192.168.1.57"
    r2 = await h["module.run"](
        {"module": "net.gateway", "config": {}, "ifname": "eth1", "session": r["session"]}, PEER
    )
    assert r2["result"]["status"] == "pass"

    # Through the runner: core dispatches test-ns modules to the agent and merges the session back.
    class Agent:
        async def call(
            self, method: str, params: dict[str, Any] | None = None, timeout: float | None = None
        ) -> Any:
            return await h[method](params or {}, PEER)

    runner = ModuleRunner(all_modules(), None, AuditLog(db))
    ctx = RunContext(run_id="r2", hardware=registry, guard=None, ifname="eth1", agent=Agent())  # type: ignore[arg-type]
    await runner.run_step(ctx, ModuleStep(module="wired.dhcp"))
    assert ctx.session["lease"]["router"] == "192.168.1.1"
    tr = await runner.run_step(ctx, ModuleStep(module="net.gateway"))
    assert tr.status == "pass"


async def test_agent_refuses_bad_requests(sysfs: Path) -> None:
    h = make_handlers("ncal-test", sysfs, net=MockNet())
    for params in (
        {"module": "system.hardware", "ifname": "eth1"},  # root-executor module
        {"module": "nope", "ifname": "eth1"},
        {"module": "wired.link", "ifname": "eth9"},  # not in this netns
        {"module": "wired.link", "ifname": "../../etc"},
        {"module": "wired.dhcp", "ifname": "eth1", "config": {"timeout_s": -1}},
    ):
        with pytest.raises(RpcError) as e:
            await h["module.run"](params, PEER)
        assert e.value.code == "bad_request", params


async def test_agent_refuses_active_modules(sysfs: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class Scan(TestModule[ModuleConfig]):
        id = "test.active-scan"
        activity = Activity.ACTIVE
        executor = "test-ns"

        async def run(self, ctx: RunContext, cfg: ModuleConfig) -> ModuleResult:
            raise AssertionError("must never run")

    import netcaliper.modules.registry as reg

    monkeypatch.setitem(reg._BUILTIN, Scan.id, Scan)
    h = make_handlers("ncal-test", sysfs, net=MockNet())
    with pytest.raises(RpcError) as e:
        await h["module.run"]({"module": Scan.id, "ifname": "eth1"}, PEER)
    assert e.value.code == "forbidden"


# ---------------------------------------------------------------- web


@pytest.fixture
async def client(settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    (settings.config_dir / "profiles").mkdir(parents=True)
    (settings.config_dir / "profiles" / "quick.yaml").write_text(
        "id: quick\nname: Quick\nsteps: [{module: wired.link}, {module: wired.dhcp}, {module: net.gateway}]\n"
    )
    app = create_app(settings, test_net=MockNet())
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            c.app = app  # type: ignore[attr-defined]
            yield c


async def test_web_autotest_flow(client: httpx.AsyncClient) -> None:
    page = await client.get("/s/autotest")
    assert page.status_code == 200 and "/autotest/start/default" in page.text and "Run Quick" in page.text
    r = await client.post("/autotest/start/quick")
    assert r.status_code == 200 and "Link" in r.text
    run = await client.app.state.autotest.wait()  # type: ignore[attr-defined]
    final = await client.get(f"/partials/run/{run.run_id}")
    assert "hx-trigger" not in final.text and f"/results/{run.run_id}" in final.text  # polling stops
    lst = await client.get("/s/results")
    assert f"/results/{run.run_id}" in lst.text
    detail = await client.get(f"/results/{run.run_id}")
    assert detail.status_code == 200 and "Gateway" in detail.text and "rtt_avg_ms" in detail.text
    api = (await client.get(f"/api/v1/runs/{run.run_id}")).json()
    assert len(api["results"]) == 3 and api["live"]["status"] == run.status
    assert (await client.post("/autotest/start/nope")).status_code == 404
    assert (await client.get("/results/nope")).status_code == 404


async def test_web_api_busy_and_cross_origin(client: httpx.AsyncClient) -> None:
    assert (await client.post("/api/v1/autotest/quick")).status_code == 202
    assert (await client.post("/api/v1/autotest/quick")).status_code == 409
    await client.app.state.autotest.wait()  # type: ignore[attr-defined]
    evil = await client.post("/api/v1/autotest/quick", headers={"origin": "http://evil.example"})
    assert evil.status_code == 403
    ok = await client.post("/api/v1/autotest/quick", headers={"origin": "http://test"})
    assert ok.status_code == 202
    await client.app.state.autotest.wait()  # type: ignore[attr-defined]


async def test_ipv6_prefix_only_advertisers_are_not_rogue(db: Database, registry: HardwareRegistry) -> None:
    """Seen on a real LAN: Thread border routers send lifetime-0 RAs. Not a rogue-RA warning."""
    p = Profile(id="v6", name="v6", steps=[ModuleStep(module="wired.ipv6")])
    at, repo = _at(db, registry, MockNet(thread_brs=4))
    at.start(p)
    run = await at.wait()
    assert run is not None
    s = by_module(run)["wired.ipv6"]
    assert s.status == "pass" and s.metrics["routers"] == 1 and s.metrics["advertisers"] == 5, s.message
    assert await repo.findings(run.run_id) == []

    at, repo = _at(db, registry, MockNet(rogue_ra=True, thread_brs=2))
    at.start(p)
    run = await at.wait()
    assert run is not None
    s = by_module(run)["wired.ipv6"]
    assert s.status == "warn" and "rogue" in s.message
    assert [f.rule_id for f in await repo.findings(run.run_id)] == ["ipv6.multiple_routers"]

    at, _ = _at(db, registry, MockNet(ipv6=False))
    at.start(p)
    run = await at.wait()
    assert run is not None and by_module(run)["wired.ipv6"].status == "pass"


async def test_switchinfo_names_other_devices_heard(db: Database, registry: HardwareRegistry) -> None:
    from netcaliper.net.base import Neighbor

    class Net(MockNet):
        async def listen_neighbors(self, ifname: str, duration_s: float) -> list[Neighbor]:
            return [
                Neighbor(
                    protocol="cdp", src_mac="aa:00:00:00:00:01", system_name="edge-router", port_id="ether3"
                ),
                Neighbor(
                    protocol="lldp", src_mac="bb:00:00:00:00:01", system_name="access-sw", port_id="Port 15"
                ),
            ]

    at, _ = _at(db, registry, Net())
    at.start(Profile(id="s", name="s", steps=[ModuleStep(module="wired.switchinfo", config={"listen_s": 1})]))
    run = await at.wait()
    assert run is not None
    s = by_module(run)["wired.switchinfo"]
    assert s.metrics["switch"] == "access-sw" and s.metrics["port"] == "Port 15"  # LLDP preferred
    assert "also heard: edge-router (cdp)" in s.message


async def test_wired_screen_one_shot_tests(client: httpx.AsyncClient) -> None:
    page = await client.get("/s/wired")
    assert page.status_code == 200 and "/wired/run/blink" in page.text and "Test VLANs" in page.text
    r = await client.post("/wired/run/blink")
    assert "Port blink" in r.text
    run = await client.app.state.autotest.wait()  # type: ignore[attr-defined]
    assert run.profile_id == "wired.blink" and run.status == "pass"
    assert "Port blink" in (await client.get("/s/wired")).text  # last wired run shown on return

    bad = await client.post("/wired/vlan", data={"vlans": "10, 5000"})
    assert "VLAN IDs" in bad.text and client.app.state.autotest.current.profile_id == "wired.blink"  # type: ignore[attr-defined]
    await client.post("/wired/vlan", data={"vlans": "10 20,20"})
    run = await client.app.state.autotest.wait()  # type: ignore[attr-defined]
    assert run.profile_name == "VLANs 10, 20" and run.steps[-1].status == "pass"
    assert (await client.post("/wired/run/nope")).status_code == 404


async def test_dot1x_credentials_local_only(client: httpx.AsyncClient, settings: Settings) -> None:
    assert "credentials first" in (await client.post("/wired/dot1x")).text
    bad = await client.post(
        "/wired/dot1x/credentials", data={"method": "peap", "identity": 'x"y', "password": "p"}
    )
    assert "no quotes" in bad.text
    ok = await client.post(
        "/wired/dot1x/credentials", data={"method": "peap", "identity": "alice", "password": "Tr0ub4dor"}
    )
    assert "Saved PEAP" in ok.text
    f = settings.data_dir / "secrets.json"
    assert f.stat().st_mode & 0o777 == 0o600
    page = (await client.get("/s/wired")).text
    assert "alice" in page and "Tr0ub4dor" not in page and "(unchanged)" in page
    # Saving again without a password keeps the stored one.
    await client.post("/wired/dot1x/credentials", data={"method": "ttls", "identity": "alice"})
    assert json.loads(f.read_text())["dot1x"] == {
        "method": "ttls",
        "identity": "alice",
        "password": "Tr0ub4dor",
    }

    await client.post("/wired/dot1x")
    run = await client.app.state.autotest.wait()  # type: ignore[attr-defined]
    assert run.steps[-1].status == "pass" and "TTLS as alice" in run.steps[-1].message
    # The password is nowhere in what's stored or queued for sync.
    db = client.app.state.db  # type: ignore[attr-defined]
    for table in ("test_runs", "test_results", "outbox", "findings", "audit_log", "kv"):
        cur = await db.conn.execute(f"SELECT * FROM {table}")
        assert "Tr0ub4dor" not in repr(await cur.fetchall()), table
    api = await client.get(f"/api/v1/runs/{run.run_id}")
    assert "Tr0ub4dor" not in api.text

    assert "removed" in (await client.post("/wired/dot1x/clear")).text
    assert "dot1x" not in json.loads(f.read_text())
