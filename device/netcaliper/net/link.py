# SPDX-License-Identifier: GPL-3.0-only
"""Link layer in the test netns: status (sysfs + `ethtool --json`), admin up with link-up timing,
port blink (link bounce), VLAN sub-interfaces, cable diagnostics. Needs CAP_NET_ADMIN."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from ..drivers.snapshot import which
from .base import CableResult, LinkStatus
from .packets import now_ms


async def run(*argv: str, timeout_s: float = 30.0) -> tuple[int, str, str]:
    exe = which(argv[0])
    if exe is None:
        return 127, "", f"{argv[0]} not found"
    p = await asyncio.create_subprocess_exec(
        exe, *argv[1:], stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        out, err = await asyncio.wait_for(p.communicate(), timeout_s)
    except TimeoutError:
        p.kill()
        return 124, "", "timeout"
    return p.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")


async def must(*argv: str) -> str:
    rc, out, err = await run(*argv)
    if rc != 0:
        raise RuntimeError(f"{argv[0]} {' '.join(argv[1:3])}: {err.strip()[:200]}")
    return out


def _sys(ifname: str, attr: str) -> str | None:
    try:
        return Path(f"/sys/class/net/{ifname}/{attr}").read_text().strip()
    except OSError:  # e.g. reading speed while the link is down → EINVAL
        return None


async def ethtool_json(ifname: str) -> dict[str, Any]:
    rc, out, _ = await run("ethtool", "--json", ifname)
    if rc != 0 or not out.strip():
        return {}
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return {}
    return data[0] if isinstance(data, list) and data else {}


async def status(ifname: str) -> LinkStatus:
    carrier = _sys(ifname, "carrier") == "1"
    speed = _sys(ifname, "speed") if carrier else None
    duplex = _sys(ifname, "duplex") if carrier else None
    et = await ethtool_json(ifname)
    changes = _sys(ifname, "carrier_changes")
    mtu = _sys(ifname, "mtu")
    return LinkStatus(
        ifname=ifname,
        carrier=carrier,
        speed_mbps=int(speed) if speed and speed.lstrip("-").isdigit() and int(speed) > 0 else None,
        duplex="full" if duplex == "full" else "half" if duplex == "half" else "unknown",
        autoneg=et.get("auto-negotiation") if isinstance(et.get("auto-negotiation"), bool) else None,
        advertised=list(et.get("advertised-link-modes") or []),
        partner_advertised=list(et.get("link-partner-advertised-link-modes") or []),
        supported=list(et.get("supported-link-modes") or []),
        carrier_changes=int(changes) if changes and changes.isdigit() else None,
        mtu=int(mtu) if mtu and mtu.isdigit() else None,
        mac=_sys(ifname, "address") or "",
    )


async def wait_carrier(ifname: str, timeout_s: float) -> float | None:
    t0 = now_ms()
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _sys(ifname, "carrier") == "1":
            return round(now_ms() - t0, 1)
        await asyncio.sleep(0.05)
    return None


async def up(ifname: str, timeout_s: float = 10.0) -> LinkStatus:
    """Admin-up and time carrier. If it was already up, link_up_ms stays None (not measured)."""
    already = _sys(ifname, "operstate") == "up" and _sys(ifname, "carrier") == "1"
    ms = None
    if not already:
        await must("ip", "link", "set", "dev", ifname, "up")
        ms = await wait_carrier(ifname, timeout_s)
    st = await status(ifname)
    st.link_up_ms = ms
    return st


async def bounce(ifname: str, times: int, period_s: float) -> int:
    """Port blink: toggle the link so the switch-port LED blinks. Returns completed cycles."""
    done = 0
    for _ in range(times):
        await must("ip", "link", "set", "dev", ifname, "down")
        await asyncio.sleep(period_s / 2)
        await must("ip", "link", "set", "dev", ifname, "up")
        await asyncio.sleep(period_s / 2)
        done += 1
    return done


def vlan_name(ifname: str, vid: int) -> str:
    return f"{ifname[:9]}.{vid}"  # IFNAMSIZ 16 incl. NUL


async def vlan_add(ifname: str, vid: int) -> str:
    name = vlan_name(ifname, vid)
    if _sys(name, "ifindex") is None:
        await must("ip", "link", "add", "link", ifname, "name", name, "type", "vlan", "id", str(vid))
    await must("ip", "link", "set", "dev", name, "up")
    return name


async def vlan_del(name: str) -> None:
    if _sys(name, "ifindex") is not None:
        await must("ip", "link", "del", "dev", name)


async def cable_test(ifname: str) -> CableResult:
    rc, out, err = await run("ethtool", "--json", "--cable-test", ifname, timeout_s=60)
    if rc != 0:
        msg = err.strip() or out.strip()
        if "not supported" in msg.lower():
            msg = "cable diagnostics not supported by this NIC/PHY"
        return CableResult(supported=False, error=msg[:200] or f"ethtool exit {rc}")
    pairs: list[dict[str, str | float | None]] = []
    try:
        for item in json.loads(out):
            for r in item.get("results", []) if isinstance(item, dict) else []:
                pairs.append({"pair": r.get("pair"), "code": r.get("code"), "length_m": r.get("length")})
    except json.JSONDecodeError:
        return CableResult(supported=True, error="unparseable ethtool output")
    return CableResult(supported=True, pairs=pairs)


async def apply_lease(ifname: str, ip: str, prefixlen: int, router: str | None) -> None:
    await must("ip", "addr", "flush", "dev", ifname, "scope", "global")
    await must("ip", "addr", "add", f"{ip}/{prefixlen}", "dev", ifname)
    if router:
        await must("ip", "route", "replace", "default", "via", router, "dev", ifname)


async def release(ifname: str) -> None:
    await run("ip", "route", "flush", "dev", ifname)
    await run("ip", "addr", "flush", "dev", ifname, "scope", "global")
