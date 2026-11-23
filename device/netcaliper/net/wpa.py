# SPDX-License-Identifier: GPL-3.0-only
"""wpa_supplicant for Wi-Fi tests: config generation (with injection-safe values), process
lifetime, and an event-driven control-socket client (events carry precise connection timings).

Credentials live in a 0600 config in the agent's PrivateTmp only while the test runs.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import os
import re
import shutil
import socket
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..drivers.snapshot import which
from .wifi_base import WifiCreds

_SAFE = re.compile(r'^[^"\\\n\r]*$')
_BSSID = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_seq = itertools.count(1)


class ConfigError(ValueError):
    pass


def _q(v: str, what: str) -> str:
    if not _SAFE.match(v):
        raise ConfigError(f"{what} may not contain quotes, backslashes or line breaks")
    return f'"{v}"'


def network_block(c: WifiCreds, security: str) -> str:
    """`security` is resolved (not "auto")."""
    lines = [f"ssid={c.ssid.encode().hex()}", "scan_ssid=1"]  # hex: any SSID bytes are safe
    if c.bssid:
        if not _BSSID.match(c.bssid.lower()):
            raise ConfigError("invalid BSSID")
        lines.append(f"bssid={c.bssid.lower()}")
    if c.freqs:
        lines.append("scan_freq=" + " ".join(str(int(f)) for f in c.freqs[:64]))
    if security == "open":
        lines.append("key_mgmt=NONE")
    elif security == "owe":
        lines += ["key_mgmt=OWE", "ieee80211w=2"]
    elif security in ("psk", "sae", "psk-sae"):
        p = c.passphrase or ""
        if not 8 <= len(p) <= 63:
            raise ConfigError("passphrase must be 8-63 characters")
        if security == "psk":
            lines += ["key_mgmt=WPA-PSK WPA-PSK-SHA256", f"psk={_q(p, 'passphrase')}", "ieee80211w=1"]
        elif security == "sae":
            lines += ["key_mgmt=SAE", f"sae_password={_q(p, 'passphrase')}", "ieee80211w=2"]
        else:
            lines += [
                "key_mgmt=WPA-PSK SAE",
                f"psk={_q(p, 'passphrase')}",
                f"sae_password={_q(p, 'passphrase')}",
                "ieee80211w=1",
            ]
    elif security == "eap":
        if not c.identity:
            raise ConfigError("EAP needs an identity")
        lines += ["key_mgmt=WPA-EAP WPA-EAP-SHA256", "ieee80211w=1", f"identity={_q(c.identity, 'identity')}"]
        if c.eap_method == "tls":
            if not (c.client_cert and c.private_key):
                raise ConfigError("EAP-TLS needs a client certificate and key")
            lines += [
                "eap=TLS",
                f"client_cert={_q(c.client_cert, 'path')}",
                f"private_key={_q(c.private_key, 'path')}",
            ]
            if c.private_key_password:
                lines.append(f"private_key_passwd={_q(c.private_key_password, 'key password')}")
        else:
            lines += (
                ["eap=PEAP", 'phase2="auth=MSCHAPV2"']
                if c.eap_method == "peap"
                else ["eap=TTLS", 'phase2="auth=PAP"']
            )
            lines.append(f"password={_q(c.password or '', 'password')}")
        if c.ca_cert:
            lines.append(f"ca_cert={_q(c.ca_cert, 'path')}")
    else:
        raise ConfigError(f"unknown security {security!r}")
    # disabled until SELECT_NETWORK, so the event monitor is attached before anything happens
    return "network={\n\tdisabled=1\n" + "".join(f"\t{line}\n" for line in lines) + "}\n"


class Ctrl:
    """wpa_supplicant control socket (datagram). One instance per purpose: requests or events."""

    def __init__(self, path: Path, local_dir: Path) -> None:
        self.path = path
        self.local = local_dir / f"c{os.getpid()}-{next(_seq)}"
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(str(self.local))
        self.sock.connect(str(path))
        self.sock.setblocking(False)

    def close(self) -> None:
        self.sock.close()
        with contextlib.suppress(OSError):
            self.local.unlink()

    async def _recv(self, timeout: float) -> str:
        loop = asyncio.get_running_loop()
        data = await asyncio.wait_for(loop.sock_recv(self.sock, 8192), timeout)
        return data.decode(errors="replace")

    async def request(self, cmd: str, timeout: float = 5.0) -> str:
        loop = asyncio.get_running_loop()
        await loop.sock_sendall(self.sock, cmd.encode())
        deadline = time.monotonic() + timeout
        while True:
            reply = await self._recv(max(0.01, deadline - time.monotonic()))
            if not reply.startswith("<"):  # unsolicited events start with "<level>"
                return reply

    async def attach(self) -> None:
        if (await self.request("ATTACH")).strip() != "OK":
            raise RuntimeError("wpa_supplicant ATTACH failed")

    async def event(self, timeout: float) -> str | None:
        try:
            msg = await self._recv(timeout)
        except TimeoutError:
            return None
        return re.sub(r"^<\d+>", "", msg)


def kv(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


@dataclass
class Supplicant:
    ifname: str
    proc: asyncio.subprocess.Process
    dir: Path
    ctrl: Ctrl
    mon: Ctrl
    t0: float = field(default_factory=time.monotonic)

    async def stop(self) -> None:
        for c in (self.ctrl, self.mon):
            c.close()
        if self.proc.returncode is None:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), 3)
            except TimeoutError:
                self.proc.kill()
                await self.proc.wait()
        shutil.rmtree(self.dir, ignore_errors=True)  # removes the config with the credentials


async def start(ifname: str, network: str, country: str | None = None) -> Supplicant:
    exe = which("wpa_supplicant")
    if exe is None:
        raise RuntimeError("wpa_supplicant not installed")
    d = Path(tempfile.mkdtemp(prefix="ncal-wifi-"))
    os.chmod(d, 0o700)
    conf = d / "wpa.conf"
    head = f"ctrl_interface={d}/ctrl\nupdate_config=0\nap_scan=1\n"
    if country and re.fullmatch(r"[A-Z]{2}", country):
        head += f"country={country}\n"
    fd = os.open(conf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(head + network)
    proc = await asyncio.create_subprocess_exec(
        exe,
        "-i",
        ifname,
        "-D",
        "nl80211",
        "-c",
        str(conf),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    sock_path = d / "ctrl" / ifname
    for _ in range(100):
        if sock_path.exists() or proc.returncode is not None:
            break
        await asyncio.sleep(0.05)
    if not sock_path.exists():
        err = (
            (await proc.stderr.read()).decode(errors="replace")
            if proc.stderr and proc.returncode is not None
            else ""
        )
        if proc.returncode is None:
            proc.kill()
        shutil.rmtree(d, ignore_errors=True)
        raise RuntimeError(f"wpa_supplicant did not start: {err.strip()[:200]}")
    mon = Ctrl(sock_path, d)
    await mon.attach()
    return Supplicant(ifname, proc, d, Ctrl(sock_path, d), mon)
