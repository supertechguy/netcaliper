# SPDX-License-Identifier: GPL-3.0-only
"""Wi-Fi screen: one-shot tests, the saved network (local secrets), the cert store, scan/client
tables and Locate (signal of one transmitter, polled by the page)."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from ..core.certs import CertError, CertStore, Kind
from ..core.rpc import RpcClient, RpcError
from ..core.secrets import SecretStore
from ..modules.autotest import AutoTest, Profile, RunState
from ..modules.runner import ModuleStep
from ..net.wifi_base import TestWifi
from .sections import BY_SLUG

SECURITY = ("auto", "open", "owe", "psk", "sae", "psk-sae", "eap")
EAP = ("peap", "ttls", "tls")
_BAD = '"\\\n\r'
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")

_CONNECT = [
    ModuleStep(module="wifi.connect"),
    ModuleStep(module="wifi.dhcp"),
    ModuleStep(module="net.dns", config={"names": ["example.com"]}),
    ModuleStep(module="net.gateway"),
]
WIFI_TESTS: dict[str, tuple[str, str, list[ModuleStep]]] = {
    "scan": (
        "Scan",
        "networks, security, channels",
        [ModuleStep(module="wifi.scan"), ModuleStep(module="wifi.channels")],
    ),
    "connect": ("Connect", "assoc/auth timing, DHCP, DNS, gateway", _CONNECT),
    "roam": ("Roam", "between APs of the saved network", [*_CONNECT[:2], ModuleStep(module="wifi.roam")]),
    "clients": (
        "Clients",
        "monitor radio, 20 s",
        [ModuleStep(module="wifi.clients", config={"duration_s": 20})],
    ),
}


def resolve_wifi(step: ModuleStep, secrets: SecretStore, certs: CertStore) -> ModuleStep:
    """Fill in the saved network / cert paths for Wi-Fi (and 802.1X) steps. Secrets only ever travel
    core → agent over the local socket; they're never in results, logs or the outbox."""
    saved = secrets.get("wifi") or {}
    cfg = dict(step.config)
    if step.module == "wifi.connect":
        if not cfg.get("ssid"):
            cfg = {**{k: v for k, v in saved.items() if v not in (None, "")}, **cfg}
        elif cfg.get("ssid") == saved.get("ssid"):
            cfg = {**{k: v for k, v in saved.items() if v not in (None, "")}, **cfg}
    elif step.module == "wifi.channels" and not cfg.get("ssid") and saved.get("ssid"):
        cfg["ssid"] = saved["ssid"]
    elif step.module != "wired.dot1x":
        return step
    kinds: dict[str, Kind] = {"ca_cert": "ca", "client_cert": "cert", "private_key": "key"}
    for field, kind in kinds.items():
        name = cfg.get(field)
        if name and "/" not in name:
            path = certs.path(name, kind)
            cfg[field] = str(path) if path else None
    if cfg.get("eap_method") != "tls" and cfg.get("method") != "tls":
        for k in ("client_cert", "private_key", "private_key_password"):
            cfg.pop(k, None)
    return step.model_copy(update={"config": cfg})


def install(
    app: FastAPI,
    templates: Jinja2Templates,
    ctx: Callable[..., dict[str, Any]],
    start_partial: Callable[[Request, Profile], HTMLResponse],
    notice: Callable[..., HTMLResponse],
    agent: RpcClient | None,
) -> None:
    secrets: SecretStore = app.state.secrets
    certs: CertStore = app.state.certs

    def radio(role: str) -> Any:
        devs = app.state.registry.inventory.by_role(role)
        return devs[0] if devs else None

    def last_wifi_run() -> RunState | None:
        at: AutoTest = app.state.autotest
        return next((r for r in reversed(at.history.values()) if r.profile_id.startswith("wifi")), None)

    def network() -> dict[str, Any]:
        s = secrets.get("wifi") or {}
        return {
            "ssid": s.get("ssid", ""),
            "security": s.get("security", "auto"),
            "eap_method": s.get("eap_method", "peap"),
            "identity": s.get("identity", ""),
            "ca_cert": s.get("ca_cert", ""),
            "client_cert": s.get("client_cert", ""),
            "has_passphrase": bool(s.get("passphrase")),
            "has_password": bool(s.get("password")),
        }

    @app.get("/s/wifi", response_class=HTMLResponse)
    async def wifi_page(request: Request) -> HTMLResponse:
        at: AutoTest = app.state.autotest
        run = at.current if at.current and at.current.profile_id.startswith("wifi") else None
        return templates.TemplateResponse(
            request,
            "sections/wifi.html",
            ctx(
                request,
                section=BY_SLUG["wifi"],
                tests=WIFI_TESTS,
                run=run,
                last=last_wifi_run(),
                test_radio=radio("test-wifi"),
                monitor=radio("monitor"),
                net=network(),
                security=SECURITY,
                eap=EAP,
                certs=certs.list(),
            ),
        )

    @app.post("/wifi/run/{key}", response_class=HTMLResponse)
    async def wifi_run(request: Request, key: str) -> HTMLResponse:
        if key == "full":
            from ..modules.autotest import load_profiles

            st = app.state.settings
            p = load_profiles(st.config_dir / "profiles", st.cloud_profiles_dir).get("wifi")
            if p is None:
                raise HTTPException(404)
            return start_partial(request, p)
        if key not in WIFI_TESTS:
            raise HTTPException(404)
        if key in ("connect", "roam") and not (secrets.get("wifi") or {}).get("ssid"):
            return notice(request, "Save a network first.")
        title, _, steps = WIFI_TESTS[key]
        return start_partial(
            request,
            Profile(
                id=f"wifi.{key}",
                name=f"Wi-Fi {title}",
                interface="test-wifi",
                steps=[s.model_copy(deep=True) for s in steps],
            ),
        )

    @app.post("/wifi/network", response_class=HTMLResponse)
    async def wifi_network(
        request: Request,
        ssid: str = Form(""),
        security: str = Form("auto"),
        passphrase: str = Form(""),
        eap_method: str = Form("peap"),
        identity: str = Form(""),
        password: str = Form(""),
        ca_cert: str = Form(""),
        client_cert: str = Form(""),
        private_key_password: str = Form(""),
    ) -> HTMLResponse:
        ssid = ssid.strip()
        if not ssid or len(ssid.encode()) > 32:
            return notice(request, "SSID required (max 32 bytes).")
        if security not in SECURITY or eap_method not in EAP:
            return notice(request, "unsupported security")
        vals = (identity, passphrase, password, private_key_password)
        if any(c in v for v in vals for c in _BAD) or any(len(v) > 256 for v in vals):
            return notice(request, "No quotes, backslashes or line breaks in credentials.")
        if passphrase and not 8 <= len(passphrase) <= 63:
            return notice(request, "Passphrase must be 8-63 characters.")
        listed = certs.list()
        if ca_cert and "ca" not in listed.get(ca_cert, []):
            return notice(request, f"no CA certificate named {ca_cert}")
        if client_cert and not {"cert", "key"} <= set(listed.get(client_cert, [])):
            return notice(request, f"{client_cert}: needs both a certificate and a key")
        if security == "eap" and eap_method == "tls" and not client_cert:
            return notice(request, "EAP-TLS needs a client certificate (import one below).")
        old = secrets.get("wifi") or {}
        same = old.get("ssid") == ssid

        def keep(new: str, key: str) -> str:
            return new or (old.get(key, "") if same else "")

        secrets.put(
            "wifi",
            {
                "ssid": ssid,
                "security": security,
                "eap_method": eap_method,
                "identity": identity.strip(),
                "passphrase": keep(passphrase, "passphrase"),
                "password": keep(password, "password"),
                "ca_cert": ca_cert,
                "client_cert": client_cert,
                "private_key": client_cert,
                "private_key_password": keep(private_key_password, "private_key_password"),
            },
        )
        return notice(request, f"Saved {ssid} (credentials stay on this device).", "ok")

    @app.post("/wifi/network/clear", response_class=HTMLResponse)
    async def wifi_network_clear(request: Request) -> HTMLResponse:
        secrets.delete("wifi")
        return notice(request, "Saved network removed.", "ok")

    @app.post("/certs", response_class=HTMLResponse)
    async def cert_upload(
        request: Request,
        name: str = Form(""),
        kind: str = Form("ca"),
        file: UploadFile = File(...),  # noqa: B008 - FastAPI idiom
    ) -> HTMLResponse:
        if kind not in ("ca", "cert", "key"):
            return notice(request, "kind must be ca, cert or key")
        data = await file.read(64 * 1024 + 1)
        try:
            certs.put(name.strip(), kind, data)  # type: ignore[arg-type]
        except CertError as e:
            return notice(request, str(e))
        return notice(request, f"Imported {kind} {name} (stored on this device only).", "ok")

    @app.post("/certs/{name}/delete", response_class=HTMLResponse)
    async def cert_delete(request: Request, name: str) -> HTMLResponse:
        try:
            certs.delete(name)
        except CertError as e:
            return notice(request, str(e))
        return notice(request, f"Removed {name}.", "ok")

    @app.get("/partials/wifi/view/{run_id}", response_class=HTMLResponse)
    async def wifi_view(request: Request, run_id: str) -> HTMLResponse:
        live = app.state.autotest.history.get(run_id)
        results = {r.module_id: r for r in await app.state.repo.results(run_id)}
        return templates.TemplateResponse(
            request,
            "partials/wifi_view.html",
            ctx(
                request,
                live=live,
                scan=results.get("wifi.scan"),
                chans=results.get("wifi.channels"),
                clients=results.get("wifi.clients"),
            ),
        )

    @app.get("/s/wifi/locate", response_class=HTMLResponse)
    async def locate_page(request: Request, mac: str, freq: int, label: str = "") -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "sections/locate.html",
            ctx(
                request,
                section=BY_SLUG["wifi"],
                mac=mac,
                freq=freq,
                label=label[:40],
                radio=radio("monitor") or radio("test-wifi"),
            ),
        )

    last_sample = {"t": 0.0}

    @app.get("/api/v1/wifi/sample")
    async def wifi_sample(mac: str, freq: int) -> JSONResponse:
        at: AutoTest = app.state.autotest
        if not _MAC.match(mac.lower()) or not 2400 <= freq <= 7125:
            return JSONResponse({"detail": "invalid mac/freq"}, status_code=400)
        if at.busy:
            return JSONResponse({"detail": "a test run is using the radios"}, status_code=409)
        dev = radio("monitor") or radio("test-wifi")
        if dev is None or dev.ifname is None:
            return JSONResponse({"detail": "no test radio"}, status_code=409)
        if time.monotonic() - last_sample["t"] < 0.2:  # one sampler at a time is plenty
            return JSONResponse({"detail": "too fast"}, status_code=429)
        last_sample["t"] = time.monotonic()
        params = {"ifname": dev.ifname, "mac": mac.lower(), "freq": freq, "duration_s": 0.5}
        try:
            if agent is not None:
                samples = await agent.call("wifi.sample", params, timeout=10)
            elif isinstance(at.net, TestWifi):
                samples = [s.model_dump() for s in await at.net.wifi_sample(dev.ifname, mac, freq, 0.5)]
            else:
                return JSONResponse({"detail": "no Wi-Fi test plane"}, status_code=409)
        except RpcError as e:
            return JSONResponse({"detail": f"{e.code}: {e.message}"}, status_code=502)
        sig = [s["signal_dbm"] for s in samples]
        return JSONResponse(
            {
                "samples": len(sig),
                "signal_dbm": max(sig) if sig else None,
                "avg_dbm": round(sum(sig) / len(sig), 1) if sig else None,
            }
        )
