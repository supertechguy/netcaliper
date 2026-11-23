# SPDX-License-Identifier: GPL-3.0-only
"""Real namespaces, real `ip`/`nft`: the helper's ops against a veth pair. Needs root."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from netcaliper.drivers.snapshot import which
from netcaliper.helper.ops import Ops

pytestmark = pytest.mark.netns

RULESET = Path(__file__).parents[2] / "installer/nftables/ncal-test.nft"


def sh(*argv: str) -> str:
    exe = which(argv[0]) or argv[0]
    return subprocess.run([exe, *argv[1:]], check=True, capture_output=True, text=True).stdout


@pytest.fixture
def veth() -> tuple[str, str]:
    n = os.getpid() % 10000
    a, b = f"ncv{n}a", f"ncv{n}b"
    # Explicit locally-administered MAC: udev's MACAddressPolicy would otherwise rewrite a random
    # veth MAC moments after creation (seen on Ubuntu runners).
    mac = f"02:00:00:00:{n // 100:02d}:{n % 100:02d}"
    sh("ip", "link", "add", a, "type", "veth", "peer", "name", b, "address", mac)
    yield b, mac  # type: ignore[misc]
    subprocess.run([which("ip") or "ip", "link", "del", a], check=False, capture_output=True)


async def test_netns_lifecycle_and_moves(veth: tuple[str, str]) -> None:
    name, mac = veth
    ns = f"ncal-it-{os.getpid()}"
    ops = Ops(ns, default_routes=set)
    try:
        await ops.netns_up(RULESET if which("nft") else None)
        assert ops.netns_present()
        assert (await ops.netns_up(None)) == []  # idempotent: nothing created twice
        assert "0" in sh("ip", "netns", "exec", ns, "sysctl", "-n", "net.ipv4.ip_forward")
        if which("nft"):
            assert "table inet netcaliper" in sh("ip", "netns", "exec", ns, "nft", "list", "tables")
            await ops.netns_up(RULESET)  # reloading the ruleset must be atomic + idempotent

        res = await ops.move_in(mac)
        assert res["moved"] and not Path(f"/sys/class/net/{name}").exists()
        assert name in sh("ip", "-n", ns, "-br", "link")
        assert (await ops.move_in(mac))["already"]

        res = await ops.move_out(mac)
        assert res["moved"] and Path(f"/sys/class/net/{name}").exists()
    finally:
        await ops.netns_down()
    assert not ops.netns_present()
