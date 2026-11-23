# SPDX-License-Identifier: GPL-3.0-only
"""Wired 802.1X via wpa_supplicant (-D wired) in the test netns: time to EAP success/failure.

PEAP/MSCHAPv2, TTLS/PAP, MD5 and EAP-TLS (client certificate from the local cert store).
The config holding credentials lives in a 0600 file in the agent's private tmp and is removed
as soon as the attempt ends.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import tempfile
import time
from pathlib import Path

from ..drivers.snapshot import which
from .base import Dot1xResult, TlsFiles
from .link import run
from .packets import now_ms

METHODS = {
    "peap": 'eap=PEAP\n\tphase2="auth=MSCHAPV2"',
    "ttls": 'eap=TTLS\n\tphase2="auth=PAP"',
    "md5": "eap=MD5",
    "tls": "eap=TLS",
}
_SAFE = re.compile(r'^[^"\\\n\r]*$')  # no quote/backslash/newline: can't break out of the config


def config(method: str, identity: str, password: str | None, tls: TlsFiles | None = None) -> str:
    if method not in METHODS:
        raise ValueError(f"unsupported EAP method {method!r} (supported: {', '.join(METHODS)})")
    tls = tls or TlsFiles()
    for v in (identity, password or "", *(x or "" for x in tls.model_dump().values())):
        if not _SAFE.match(v):
            raise ValueError("identity/password may not contain quotes, backslashes or newlines")
    files = ""
    if method == "tls":
        if not (tls.client_cert and tls.private_key):
            raise ValueError("EAP-TLS needs a client certificate and private key")
        files += f'\tclient_cert="{tls.client_cert}"\n\tprivate_key="{tls.private_key}"\n'
        if tls.private_key_password:
            files += f'\tprivate_key_passwd="{tls.private_key_password}"\n'
        password = None
    if tls.ca_cert:
        files += f'\tca_cert="{tls.ca_cert}"\n'
    return (
        "ap_scan=0\n"
        "network={\n"
        "\tkey_mgmt=IEEE8021X\n"
        f"\t{METHODS[method]}\n"
        f'\tidentity="{identity}"\n'
        + (f'\tpassword="{password}"\n' if password is not None else "")
        + files
        + "\teapol_flags=0\n"
        "}\n"
    )


async def authenticate(
    ifname: str,
    method: str,
    identity: str,
    password: str | None,
    timeout_s: float = 30.0,
    tls: TlsFiles | None = None,
) -> Dot1xResult:
    if not which("wpa_supplicant") or not which("wpa_cli"):
        return Dot1xResult(ok=False, method=method, state="unavailable", error="wpa_supplicant not installed")
    try:
        conf_text = config(method, identity, password, tls)
    except ValueError as e:
        return Dot1xResult(ok=False, method=method, state="config", error=str(e))
    with tempfile.TemporaryDirectory(prefix="ncal-8021x-") as d:
        conf, ctrl = Path(d) / "wpa.conf", Path(d) / "ctrl"
        fd = os.open(conf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(conf_text)
        exe = which("wpa_supplicant")
        assert exe
        t0 = now_ms()
        proc = await asyncio.create_subprocess_exec(
            exe,
            "-i",
            ifname,
            "-D",
            "wired",
            "-c",
            str(conf),
            "-C",
            str(ctrl),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        state = "STARTED"
        try:
            deadline = time.monotonic() + timeout_s
            while time.monotonic() < deadline:
                if proc.returncode is not None:
                    err = (await proc.stderr.read()).decode(errors="replace") if proc.stderr else ""
                    return Dot1xResult(ok=False, method=method, state="exited", error=err.strip()[:200])
                rc, out, _ = await run("wpa_cli", "-p", str(ctrl), "-i", ifname, "status", timeout_s=2)
                if rc == 0:
                    fields = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
                    eap = fields.get("EAP state", "")
                    pae = fields.get("Supplicant PAE state", "")
                    state = eap or pae or state
                    if eap == "SUCCESS" or pae == "AUTHENTICATED":
                        return Dot1xResult(
                            ok=True, method=method, state="AUTHENTICATED", auth_ms=round(now_ms() - t0, 1)
                        )
                    if eap == "FAILURE" or pae == "HELD":
                        return Dot1xResult(
                            ok=False,
                            method=method,
                            state=pae or eap,
                            auth_ms=round(now_ms() - t0, 1),
                            error="authentication rejected",
                        )
                await asyncio.sleep(0.2)
            return Dot1xResult(
                ok=False, method=method, state=state, error=f"no result within {timeout_s:.0f} s"
            )
        finally:
            if proc.returncode is None:
                proc.terminate()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(proc.wait(), 3)
                if proc.returncode is None:
                    proc.kill()
