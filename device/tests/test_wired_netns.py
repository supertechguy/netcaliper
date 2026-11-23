# SPDX-License-Identifier: GPL-3.0-only
"""Wired AutoTest end to end against real servers in network namespaces. Needs root + dnsmasq
(hostapd for 802.1X). The client side runs the *agent's* module.run handler inside its own netns,
so this exercises agent → module → RealNet → raw sockets exactly as on the device.

    ns C  (client)   vethc ──┐
    ns S  (switch)           └─ ports ─ br0 192.0.2.1/24 2001:db8:10::1/64   dnsmasq A (DHCP/DNS/RA/DHCPv6)
                             ┌─ portr ┘ br0.30 198.51.100.1/24 (VLAN 30)     http :8080, LLDP/CDP/EDP emitter
    ns R  (rogue)    vethr ──┘ 10.99.0.1/24                                  dnsmasq B (DHCP, delayed)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from netcaliper.drivers.snapshot import which

pytestmark = pytest.mark.netns

DNSMASQ = which("dnsmasq")
HOSTAPD = which("hostapd")
WPA = which("wpa_supplicant")
IP = which("ip") or "ip"


def sh(*argv: str, ns: str | None = None, check: bool = True) -> str:
    cmd = [IP, "netns", "exec", ns, *argv] if ns else list(argv)
    if not ns:
        cmd[0] = which(cmd[0]) or cmd[0]
    return subprocess.run(cmd, check=check, capture_output=True, text=True).stdout


def bg(ns: str, *argv: str, log: Path) -> subprocess.Popen[bytes]:
    f = log.open("wb")
    return subprocess.Popen([IP, "netns", "exec", ns, *argv], stdout=f, stderr=subprocess.STDOUT)


def nodad(ns: str) -> None:
    for k in ("all", "default"):
        sh("sysctl", "-qw", f"net.ipv6.conf.{k}.accept_dad=0", ns=ns)


EMITTER = """
import sys, time
from netcaliper.net import discovery
from netcaliper.net.packets import RawSocket
ifname, mac = sys.argv[1], sys.argv[2]
frames = [
    discovery.build_lldp(mac, "it-switch", "gi1/0/7", port_description="netns port", native_vlan=10,
                         voice_vlan=20, mgmt_ip="192.0.2.1"),
    discovery.build_cdp(mac, "it-switch", "GigabitEthernet1/0/7", platform="netns", native_vlan=10),
    discovery.build_edp(mac, "it-switch", 1, 7, vlans=(10,)),
]
with RawSocket(ifname) as s:
    while True:
        for f in frames:
            s.send(f)
        time.sleep(0.5)
"""

CLIENT = """
import asyncio, json, sys
from pathlib import Path
from netcaliper.agent.server import make_handlers
from netcaliper.core.rpc import Peer

async def main():
    ifname, steps = sys.argv[1], json.loads(sys.argv[2])
    h = make_handlers("client", Path("/sys"))
    session, out = {}, {}
    for mod, cfg in steps:
        params = {"module": mod, "config": cfg, "ifname": ifname, "session": session}
        r = await h["module.run"](params, Peer(0, 0, 0))
        session = r["session"]
        out[mod] = r["result"]
    print(json.dumps(out))

asyncio.run(main())
"""


def run_modules(ns: str, ifname: str, steps: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    p = subprocess.run(
        [IP, "netns", "exec", ns, sys.executable, "-c", CLIENT, ifname, json.dumps(steps)],
        capture_output=True,
        text=True,
        timeout=240,
    )
    assert p.returncode == 0, p.stderr[-3000:]
    out: dict[str, Any] = json.loads(p.stdout.strip().splitlines()[-1])
    return out


@pytest.fixture
def lab(tmp_path: Path) -> Iterator[dict[str, Any]]:
    if not DNSMASQ:
        pytest.skip("dnsmasq not installed")
    n = os.getpid() % 10000
    c, s, r = f"ncal-itc{n}", f"ncal-its{n}", f"ncal-itr{n}"
    procs: list[subprocess.Popen[bytes]] = []
    try:
        for ns in (c, s, r):
            sh(IP, "netns", "add", ns)
            nodad(ns)
        sh(IP, "-n", s, "link", "add", "br0", "type", "bridge", "stp_state", "0", "forward_delay", "0")
        sh(IP, "-n", s, "link", "set", "br0", "address", "02:00:00:00:5b:01")
        sh(
            IP,
            "-n",
            s,
            "link",
            "add",
            "ports",
            "address",
            "02:00:00:00:5b:02",
            "type",
            "veth",
            "peer",
            "name",
            "vethc",
            "address",
            "02:00:00:00:5c:01",
            "netns",
            c,
        )
        sh(
            IP,
            "-n",
            s,
            "link",
            "add",
            "portr",
            "address",
            "02:00:00:00:5b:03",
            "type",
            "veth",
            "peer",
            "name",
            "vethr",
            "address",
            "02:00:00:00:5d:01",
            "netns",
            r,
        )
        for port in ("ports", "portr"):
            sh(IP, "-n", s, "link", "set", port, "master", "br0", "up")
        sh(IP, "-n", s, "link", "set", "br0", "up")
        sh(IP, "-n", s, "addr", "add", "192.0.2.1/24", "dev", "br0")
        sh(IP, "-n", s, "addr", "add", "2001:db8:10::1/64", "dev", "br0", "nodad")
        sh(IP, "-n", s, "link", "add", "link", "br0", "name", "br0.30", "type", "vlan", "id", "30")
        sh(IP, "-n", s, "link", "set", "br0.30", "up")
        sh(IP, "-n", s, "addr", "add", "198.51.100.1/24", "dev", "br0.30")
        sh(IP, "-n", r, "link", "set", "vethr", "up")
        sh(IP, "-n", r, "addr", "add", "10.99.0.1/24", "dev", "vethr")
        sh(IP, "-n", c, "link", "set", "lo", "up")  # vethc stays down: wired.link times link-up

        common = [
            "--keep-in-foreground",
            "--conf-file=/dev/null",
            "--user=root",
            "--bind-interfaces",
            "--except-interface=lo",
            "--log-dhcp",
            "--no-ping",  # its ping-before-offer delay would let the rogue win the race
        ]
        procs.append(
            bg(
                s,
                DNSMASQ,
                *common,
                "--interface=br0",
                "--interface=br0.30",
                "--no-resolv",
                "--no-hosts",
                "--address=/example.test/192.0.2.1",
                "--dhcp-range=192.0.2.100,192.0.2.150,255.255.255.0,1h",
                "--dhcp-range=198.51.100.100,198.51.100.150,255.255.255.0,1h",
                "--dhcp-range=2001:db8:10::100,2001:db8:10::1ff,64,1h",
                "--enable-ra",
                "--dhcp-option=option6:dns-server,[2001:db8:10::1]",
                f"--dhcp-leasefile={tmp_path}/a.leases",
                f"--pid-file={tmp_path}/a.pid",
                log=tmp_path / "dnsmasq-a.log",
            )
        )
        procs.append(
            bg(
                r,
                DNSMASQ,
                *common,
                "--interface=vethr",
                "--port=0",
                "--dhcp-reply-delay=1",
                "--dhcp-range=10.99.0.100,10.99.0.150,255.255.255.0,1h",
                f"--dhcp-leasefile={tmp_path}/b.leases",
                f"--pid-file={tmp_path}/b.pid",
                log=tmp_path / "dnsmasq-b.log",
            )
        )
        www = tmp_path / "www"
        www.mkdir()
        (www / "index.html").write_text("ok\n")
        procs.append(
            bg(
                s,
                sys.executable,
                "-m",
                "http.server",
                "8080",
                "--bind",
                "192.0.2.1",
                "--directory",
                str(www),
                log=tmp_path / "http.log",
            )
        )
        procs.append(
            bg(s, sys.executable, "-c", EMITTER, "ports", "02:00:00:00:5b:02", log=tmp_path / "emit.log")
        )
        time.sleep(1.5)
        for p in procs:
            assert p.poll() is None, (tmp_path / "dnsmasq-a.log").read_text()[-2000:]
        yield {"client": c, "switch": s, "rogue": r, "ifname": "vethc", "logs": tmp_path}
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        for ns in (c, s, r):
            subprocess.run([IP, "netns", "del", ns], check=False, capture_output=True)


def test_wired_autotest_against_real_servers(lab: dict[str, Any]) -> None:
    out = run_modules(
        lab["client"],
        lab["ifname"],
        [
            ("wired.link", {}),
            ("wired.switchinfo", {"listen_s": 5}),
            ("wired.dhcp", {"collect_s": 2.0}),
            ("net.dns", {"names": ["example.test"]}),
            ("net.gateway", {"count": 3}),
            ("wired.ipv6", {}),
            (
                "net.targets",
                {
                    "probes": [
                        {"kind": "ping", "target": "192.0.2.1"},
                        {"kind": "tcp", "target": "192.0.2.1", "port": 53},
                        {"kind": "http", "target": "http://example.test:8080/"},
                    ],
                    "count": 3,
                },
            ),
            ("wired.vlan", {"vlans": [30, 99], "timeout_s": 4}),
            ("wired.cable", {}),
            ("wired.blink", {"times": 2, "period_s": 0.4}),
        ],
    )
    msg = {k: (v["status"], v["message"]) for k, v in out.items()}
    print(json.dumps(msg, indent=1))

    link = out["wired.link"]
    assert link["status"] == "pass" and link["metrics"]["carrier"] is True, msg
    assert link["metrics"]["link_up_ms"] is not None  # it was down: link-up was timed

    sw = out["wired.switchinfo"]["metrics"]
    assert sw["switch"] == "it-switch" and sw["port"] == "gi1/0/7" and sw["native_vlan"] == 10, msg
    assert sw["voice_vlan"] == 20 and set(sw["protocols"].split(",")) >= {"cdp", "lldp"}

    dhcp = out["wired.dhcp"]
    assert dhcp["metrics"]["ip"].startswith("192.0.2.") and dhcp["metrics"]["router"] == "192.0.2.1", msg
    assert dhcp["metrics"]["servers"] == 2 and dhcp["status"] == "warn"  # the rogue answered too
    assert {f["rule_id"] for f in dhcp["findings"]} == {"dhcp.multiple_servers"}
    assert (
        "10.99.0.1" in dhcp["findings"][0]["evidence"]["suspects"]
        or len(dhcp["findings"][0]["evidence"]["suspects"]) == 2
    )

    assert out["net.dns"]["status"] == "pass", msg
    gw = out["net.gateway"]["metrics"]
    assert (
        out["net.gateway"]["status"] == "pass" and gw["mac"] == "02:00:00:00:5b:01" and gw["loss_pct"] == 0
    ), msg

    v6 = out["wired.ipv6"]
    assert v6["metrics"]["routers"] == 1 and "2001:db8:10::/64" in v6["metrics"]["prefixes"], msg
    assert v6["metrics"]["dhcp6"] is True, msg

    tg = out["net.targets"]
    assert tg["status"] == "pass" and tg["metrics"]["failed"] == 0, (msg, tg["details"])

    vl = {v["vlan"]: v for v in out["wired.vlan"]["details"]["vlans"]}
    assert vl[30]["ok"] and vl[30]["ip"].startswith("198.51.100.") and not vl[99]["ok"], msg
    assert out["wired.vlan"]["status"] == "warn"
    assert not Path("/sys/class/net/vethc.30").exists()  # (root ns view) and cleaned up in the client ns:
    assert "vethc.30" not in sh(IP, "-br", "link", ns=lab["client"])

    assert out["wired.cable"]["status"] == "skipped", msg  # veth has no PHY diagnostics
    assert out["wired.blink"]["metrics"]["cycles"] == 2, msg


HOSTAPD_CONF = """interface={iface}
driver=wired
ieee8021x=1
eap_server=1
eap_user_file={users}
use_pae_group_addr=1
ctrl_interface={ctrl}
"""


@pytest.mark.skipif(not (HOSTAPD and WPA), reason="hostapd + wpa_supplicant needed")
@pytest.mark.parametrize(("password", "ok"), [("s3cret", True), ("wrong", False)])
def test_wired_8021x_md5(tmp_path: Path, password: str, ok: bool) -> None:
    n = os.getpid() % 10000
    c, a = f"ncal-ixc{n}", f"ncal-ixa{n}"
    proc = None
    try:
        for ns in (c, a):
            sh(IP, "netns", "add", ns)
        sh(
            IP,
            "-n",
            a,
            "link",
            "add",
            "auth0",
            "address",
            "02:00:00:00:6a:01",
            "type",
            "veth",
            "peer",
            "name",
            "sup0",
            "address",
            "02:00:00:00:6b:01",
            "netns",
            c,
        )
        sh(IP, "-n", a, "link", "set", "auth0", "up")
        sh(IP, "-n", c, "link", "set", "sup0", "up")
        users = tmp_path / "users"
        users.write_text('"alice" MD5 "s3cret"\n')
        conf = tmp_path / "hostapd.conf"
        conf.write_text(HOSTAPD_CONF.format(iface="auth0", users=users, ctrl=tmp_path / "hctrl"))
        assert HOSTAPD
        proc = bg(a, HOSTAPD, str(conf), log=tmp_path / "hostapd.log")
        time.sleep(1.0)
        assert proc.poll() is None, (tmp_path / "hostapd.log").read_text()
        out = run_modules(
            c,
            "sup0",
            [("wired.dot1x", {"method": "md5", "identity": "alice", "password": password, "timeout_s": 15})],
        )
        r = out["wired.dot1x"]
        assert (r["status"] == "pass") is ok, (r, (tmp_path / "hostapd.log").read_text()[-1500:])
        if ok:
            assert r["metrics"]["auth_ms"] > 0
        # Credentials never linger on disk.
        assert not [p for p in Path(os.environ.get("TMPDIR", "/tmp")).glob("ncal-8021x-*")]
    finally:
        if proc:
            proc.terminate()
            proc.wait(5)
        for ns in (c, a):
            subprocess.run([IP, "netns", "del", ns], check=False, capture_output=True)
        shutil.rmtree(tmp_path / "hctrl", ignore_errors=True)
