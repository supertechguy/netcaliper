# SPDX-License-Identifier: GPL-3.0-only
"""Wi-Fi measurement models and the TestWifi protocol (RealNet / MockNet implement it)."""

from __future__ import annotations

from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field

Band = Literal["2.4", "5", "6", "?"]


def freq_to_channel(freq: int) -> int:
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if 5150 <= freq <= 5895:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return 0


def band_of(freq: int) -> Band:
    if 2400 <= freq < 2500:
        return "2.4"
    if 5150 <= freq < 5925:
        return "5"
    if 5925 <= freq <= 7125:
        return "6"
    return "?"


class Bss(BaseModel):
    bssid: str
    ssid: str = ""
    hidden: bool = False
    freq: int
    channel: int
    band: Band
    width_mhz: int = 20
    center_channel: int | None = None  # of the whole (bonded) channel
    signal_dbm: float | None = None
    beacon_interval: int | None = None
    security: str = "Open"  # display label, e.g. "WPA2/WPA3-Personal"
    akms: list[str] = Field(default_factory=list)  # psk, sae, 8021x, owe, ft-*, …
    pairwise: list[str] = Field(default_factory=list)  # ccmp, tkip, gcmp-256, …
    group: str | None = None
    pmf: Literal["required", "capable", "no"] = "no"
    wps: bool = False
    wps_state: str | None = None  # "configured" / "unconfigured"
    wps_locked: bool | None = None
    wps_device: str | None = None
    standards: list[str] = Field(default_factory=list)  # b g a n ac ax be
    streams: int | None = None
    country: str | None = None
    stations: int | None = None  # QBSS load
    utilization_pct: float | None = None  # QBSS channel utilisation as the AP sees it
    k: bool = False  # 802.11k radio measurement
    v: bool = False  # 802.11v BSS transition
    r: bool = False  # 802.11r fast transition (mobility domain)
    seen_ms_ago: int | None = None
    associated: bool = False
    reported_by: str | None = None  # learned from this AP's frame (MBSSID / ML / RNR), not heard directly
    mld: str | None = None  # Wi-Fi 7 multi-link device address
    radios: list[str] = Field(default_factory=list)  # which of our radios heard it


class SurveyChannel(BaseModel):
    freq: int
    channel: int
    noise_dbm: int | None = None
    busy_pct: float | None = None  # our radio's own measurement
    in_use: bool = False
    radio: str = ""


class ScanResult(BaseModel):
    bss: list[Bss] = Field(default_factory=list)
    survey: list[SurveyChannel] = Field(default_factory=list)
    radios: dict[str, str] = Field(default_factory=dict)  # ifname -> "ok" or error
    duration_ms: float | None = None


class WifiCreds(BaseModel):
    """Everything wpa_supplicant needs; secrets come from the local store, never from results."""

    ssid: str = Field(min_length=1, max_length=32)
    security: Literal["auto", "open", "owe", "psk", "sae", "psk-sae", "eap"] = "auto"
    passphrase: str | None = Field(None, repr=False)
    eap_method: Literal["peap", "ttls", "tls"] = "peap"
    identity: str | None = None
    password: str | None = Field(None, repr=False)
    ca_cert: str | None = None  # file paths (resolved from the cert store by core)
    client_cert: str | None = None
    private_key: str | None = None
    private_key_password: str | None = Field(None, repr=False)
    bssid: str | None = None  # pin to one AP
    freqs: list[int] = Field(default_factory=list)  # where the SSID was heard: scan only there


class WifiEvent(BaseModel):
    t_ms: float
    event: str


class WifiConnectResult(BaseModel):
    ok: bool
    ssid: str
    bssid: str | None = None
    freq: int | None = None
    channel: int | None = None
    key_mgmt: str | None = None
    pairwise: str | None = None
    generation: str | None = None  # "4" = Wi-Fi 4 / 802.11n, …
    scan_ms: float | None = None
    auth_ms: float | None = None
    assoc_ms: float | None = None
    eap_ms: float | None = None
    key_ms: float | None = None
    connect_ms: float | None = None  # first auth attempt → connected (excludes scanning)
    total_ms: float | None = None
    signal_dbm: int | None = None
    noise_dbm: int | None = None
    tx_rate_mbps: float | None = None
    width: str | None = None
    reason: str | None = None  # WRONG_KEY, NETWORK_NOT_FOUND, ASSOC_REJECT status=17, …
    error: str | None = None
    events: list[WifiEvent] = Field(default_factory=list)


class RoamAttempt(BaseModel):
    from_bssid: str
    to_bssid: str
    ok: bool
    ms: float | None = None  # ROAM command → connected to the new AP
    gap_ms: float | None = None  # longest gap without ping replies around the roam
    lost: int | None = None
    sent: int | None = None
    error: str | None = None


class Client(BaseModel):
    mac: str
    bssid: str | None = None  # associated AP (from data frames)
    ssid: str | None = None
    signal_dbm: float | None = None
    freq: int | None = None  # where it was last heard (for Locate)
    frames: int = 0
    randomized: bool = False  # locally administered MAC
    probes: list[str] = Field(default_factory=list)  # SSIDs it probed for


class MonitorResult(BaseModel):
    clients: list[Client] = Field(default_factory=list)
    aps: dict[str, str] = Field(default_factory=dict)  # bssid -> ssid heard in beacons
    deauth: dict[str, int] = Field(default_factory=dict)  # transmitter -> deauth/disassoc count
    channels: list[int] = Field(default_factory=list)
    frames: int = 0
    duration_ms: float | None = None


class Sample(BaseModel):
    t_ms: float
    signal_dbm: float


@runtime_checkable
class TestWifi(Protocol):
    async def wifi_scan(
        self, ifnames: list[str], timeout_s: float = 25.0, freqs: list[int] | None = None
    ) -> ScanResult: ...
    async def wifi_connect(
        self, ifname: str, creds: WifiCreds, timeout_s: float = 30.0
    ) -> WifiConnectResult: ...
    async def wifi_roam(
        self, ifname: str, bssid: str, gateway: str | None, timeout_s: float = 10.0
    ) -> RoamAttempt: ...
    async def wifi_disconnect(self, ifname: str) -> None: ...
    async def wifi_monitor(
        self, ifname: str, duration_s: float, freqs: list[int] | None = None
    ) -> MonitorResult: ...
    async def wifi_sample(
        self, ifname: str, mac: str, freq: int, duration_s: float = 0.5
    ) -> list[Sample]: ...
