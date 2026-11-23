# SPDX-License-Identifier: GPL-3.0-only
"""Implementations of helper actions. Fixed argv lists only; names come from the kernel, not callers."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..drivers.snapshot import default_route_ifaces, which

Runner = Callable[[list[str]], Awaitable[tuple[int, str, str]]]
IFNAME = re.compile(r"^[A-Za-z0-9_.:@-]{1,15}$")
PHYNAME = re.compile(r"^phy[0-9]{1,4}$")
NM_CONF = Path("/etc/NetworkManager/conf.d/90-netcaliper-unmanaged.conf")

# Test-plane namespace defaults: never route, never auto-configure. Tests configure explicitly.
NETNS_SYSCTLS = {
    "net.ipv4.ip_forward": "0",
    "net.ipv6.conf.all.forwarding": "0",
    "net.ipv6.conf.default.accept_ra": "0",
    "net.ipv6.conf.default.autoconf": "0",
    "net.ipv4.conf.default.rp_filter": "0",  # rogue-DHCP/asymmetric tests need to see everything
}


class OpError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


async def run_exec(argv: list[str]) -> tuple[int, str, str]:
    exe = which(argv[0])
    if exe is None:
        raise OpError("missing_tool", argv[0])
    proc = await asyncio.create_subprocess_exec(
        exe, *argv[1:], stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), 30)
    except TimeoutError:
        proc.kill()
        raise OpError("timeout", argv[0]) from None
    return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")


@dataclass
class Located:
    ifname: str
    phy: str | None  # set for Wi-Fi: radios move as a whole phy


class Ops:
    def __init__(
        self,
        netns: str,
        runner: Runner = run_exec,
        sysfs: Path = Path("/sys"),
        nm_conf: Path = NM_CONF,
        netns_dir: Path = Path("/run/netns"),
        default_routes: Callable[[], set[str]] = default_route_ifaces,
    ) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", netns):
            raise ValueError(f"bad netns name {netns!r}")
        self.netns = netns
        self.run = runner
        self.sysfs = sysfs
        self.nm_conf = nm_conf
        self.netns_dir = netns_dir
        self.default_routes = default_routes

    async def _must(self, argv: list[str]) -> str:
        rc, out, err = await self.run(argv)
        if rc != 0:
            raise OpError(
                "command_failed", f"{argv[0]} {argv[1] if len(argv) > 1 else ''}: {err.strip()[:200]}"
            )
        return out

    # ------------------------------------------------------------ lookups

    def find_root(self, mac: str) -> Located | None:
        for n in sorted((self.sysfs / "class/net").glob("*")):
            addr = (n / "address").read_text().strip().lower() if (n / "address").exists() else ""
            if addr != mac or not IFNAME.match(n.name):
                continue
            phy = None
            if (n / "phy80211/name").exists():
                phy = (n / "phy80211/name").read_text().strip()
                if not PHYNAME.match(phy):
                    raise OpError("bad_phy", phy)
            return Located(n.name, phy)
        return None

    async def find_in_netns(self, mac: str) -> Located | None:
        rc, out, _ = await self.run(["ip", "-n", self.netns, "-j", "link", "show"])
        if rc != 0:
            return None
        for link in json.loads(out or "[]"):
            if str(link.get("address", "")).lower() == mac and IFNAME.match(str(link.get("ifname", ""))):
                name = str(link["ifname"])
                rc, info, _ = await self.run(["ip", "netns", "exec", self.netns, "iw", "dev", name, "info"])
                m = re.search(r"^\s*wiphy (\d+)", info, re.M) if rc == 0 else None
                return Located(name, f"phy#{m.group(1)}" if m else None)
        return None

    # ------------------------------------------------------------ actions

    async def ping(self) -> dict[str, Any]:
        return {"pid": os.getpid(), "netns": self.netns, "netns_present": self.netns_present()}

    def netns_present(self) -> bool:
        return (self.netns_dir / self.netns).exists()

    async def set_nm_unmanaged(self, macs: list[str]) -> dict[str, Any]:
        if not self.nm_conf.parent.is_dir():
            return {"nm": "absent"}
        macs = sorted(set(macs))
        current = self.nm_conf.read_text() if self.nm_conf.exists() else None
        body = (
            "# Managed by netcaliper-helper: test-plane interfaces NetworkManager must not touch.\n"
            "[keyfile]\nunmanaged-devices=" + ";".join(f"mac:{m}" for m in macs) + "\n"
            if macs
            else None
        )
        if body == current:
            return {"nm": "unchanged", "macs": macs}
        if body is not None:
            tmp = self.nm_conf.with_suffix(".tmp")
            tmp.write_text(body)
            tmp.chmod(0o644)
            tmp.replace(self.nm_conf)
        else:
            with contextlib.suppress(FileNotFoundError):
                self.nm_conf.unlink()
        reloaded = False
        if which("nmcli"):
            rc, _, _ = await self.run(["nmcli", "general", "reload", "conf"])
            reloaded = rc == 0
        return {"nm": "configured", "macs": macs, "reloaded": reloaded}

    async def move_in(self, mac: str) -> dict[str, Any]:
        if not self.netns_present():
            raise OpError("no_netns", self.netns)
        loc = self.find_root(mac)
        if loc is None:
            if await self.find_in_netns(mac):
                return {"moved": False, "already": True}
            raise OpError("not_found", mac)
        routes = self.default_routes()
        if loc.ifname in routes and len(routes) == 1:
            # Would cut the device off (and maybe the user's SSH session). Refuse; never guess.
            raise OpError("only_default_route", loc.ifname)
        if loc.phy:
            await self._must(["iw", "phy", loc.phy, "set", "netns", "name", self.netns])
        else:
            await self._must(["ip", "link", "set", "dev", loc.ifname, "netns", self.netns])
        return {"moved": True, "ifname": loc.ifname, "phy": loc.phy}

    async def move_out(self, mac: str) -> dict[str, Any]:
        loc = await self.find_in_netns(mac) if self.netns_present() else None
        if loc is None:
            if self.find_root(mac):
                return {"moved": False, "already": True}
            raise OpError("not_found", mac)
        if loc.phy:
            await self._must(["ip", "netns", "exec", self.netns, "iw", loc.phy, "set", "netns", "1"])
        else:
            await self._must(["ip", "-n", self.netns, "link", "set", "dev", loc.ifname, "netns", "1"])
        return {"moved": True, "ifname": loc.ifname, "phy": loc.phy}

    async def set_regdomain(self, country: str) -> dict[str, Any]:
        await self._must(["iw", "reg", "set", country])
        return {"country": country}

    # ------------------------------------------------------------ netns lifecycle (oneshot unit)

    async def netns_up(self, nft_file: Path | None) -> list[str]:
        done: list[str] = []
        if not self.netns_present():
            await self._must(["ip", "netns", "add", self.netns])
            done.append(f"created netns {self.netns}")
        await self._must(["ip", "-n", self.netns, "link", "set", "lo", "up"])
        for key, value in NETNS_SYSCTLS.items():
            await self._must(["ip", "netns", "exec", self.netns, "sysctl", "-q", "-w", f"{key}={value}"])
        if nft_file is not None:
            if not await asyncio.to_thread(nft_file.is_file):
                raise OpError("missing_ruleset", str(nft_file))
            await self._must(["ip", "netns", "exec", self.netns, "nft", "-f", str(nft_file)])
            done.append(f"loaded {nft_file.name}")
        return done

    async def netns_down(self) -> list[str]:
        """Deleting the netns returns every physical link and phy to the root namespace."""
        if not self.netns_present():
            return []
        await self._must(["ip", "netns", "delete", self.netns])
        return [f"deleted netns {self.netns}"]
