# netcaliper — Architecture

> Status: **draft for review** (pre-Phase 0). Living document; update it when a decision changes.
> Limits quoted for Cloudflare were checked against developers.cloudflare.com on 2026-11-22.

netcaliper is an open, DIY handheld network tester (EtherScope nXG + CyberScope class) for a
Raspberry Pi, prototyped on a ClockworkPi uConsole (CM4). It has three deliverables in one monorepo:

| Deliverable | Language | Where it runs |
|---|---|---|
| `device/` — appliance app (backend, UI, drivers, test modules, CLI) | Python ≥ 3.11 | Pi (ARM64), dev laptop (x86) |
| `installer/` — idempotent installer, systemd units, udev, kiosk | bash | Pi OS 64-bit (Trixie, Bookworm); Debian/Ubuntu x86 `--dev` |
| `cloud/` — sync server + dashboard ("Link-Live" replacement) | TypeScript (Hono) | Cloudflare Workers + D1, free tier |

---

## 1. Design principles

1. **Measure, never interfere.** Passive by default; active probing gated by Engagements; attack
   features are out of scope (see §9).
2. **Hardware behind capabilities.** Modules ask for *capabilities* (`wifi.monitor`, `sdr.subghz`),
   never for devices or interface names. Every driver has a mock. The whole app runs on a laptop
   with zero special hardware.
3. **Detect, don't configure.** Radios found via nl80211 capabilities, NICs via driver + USB ID +
   sysfs path, platform via device tree. Interface names are display-only.
4. **Isolation of the test plane.** Test interfaces live in the `ncal-test` network namespace so
   tests can never disturb the management uplink, and hostile networks can't reach the box's services.
5. **Local-first.** SQLite is the source of truth on the device. The cloud is an eventually
   consistent replica of *summaries*. Raw artifacts (pcaps, scan dumps) never leave the device.
6. **Least privilege.** Unprivileged service user + ambient `CAP_NET_RAW`/`CAP_NET_ADMIN`; a tiny
   allowlisted root helper for the few things that really need root.
7. **One schema.** Record types are defined once (Pydantic, device side) and exported as JSON
   Schema → generated TypeScript types for the Worker, checked in CI.

---

## 2. Process model (device)

```
                         root network namespace                    │   netns: ncal-test
                                                                   │
  ┌────────────┐  HTTP/WS  ┌──────────────────────────────┐        │  ┌───────────────────────────┐
  │ cage +     │──────────▶│ netcaliper-core  (user ncal) │ JSON-  │  │ netcaliper-agent (user    │
  │ Chromium   │ :8080     │  FastAPI UI/API, scheduler,  │ RPC on │  │ ncal, NET_RAW+NET_ADMIN)  │
  │ (user      │           │  SQLite+outbox, engagements, │ unix   │  │  runs netns-bound modules:│
  │ ncal-kiosk)│           │  audit, sync client, root-ns │ socket │  │  wired, wifi, discovery,  │
  └────────────┘           │  drivers (BLE, SDR, nRF24,   │◀──────▶│  │  security, perf, capture  │
                           │  probe, PoE, mgmt Wi-Fi)     │        │  │                           │
                           └──────────────┬───────────────┘        │  │  test NICs, test/monitor  │
                                          │ unix socket            │  │  Wi-Fi phys, VLAN subifs  │
                           ┌──────────────▼───────────────┐        │  └───────────────────────────┘
                           │ netcaliper-helper (root)     │  moves phys/links into netns,
                           │  allowlisted actions only    │  nft rule toggles, NM unmanage,
                           └──────────────────────────────┘  regdomain, rfkill
```

**Why a separate agent process?** Entering a netns (`setns`) requires `CAP_SYS_ADMIN`, which we
refuse to give the core. Instead systemd starts `netcaliper-agent` *already inside* the namespace
(`NetworkNamespacePath=/run/netns/ncal-test`) with only the two network caps. Unix sockets live on
the filesystem, so core ↔ agent IPC crosses the netns boundary freely. Modules declare which
executor they need (`executor = "test-ns" | "root"`); the scheduler dispatches accordingly. Same
module interface in both.

| Unit | User | Caps | Purpose |
|---|---|---|---|
| `netcaliper-netns.service` | root (oneshot) | — | create `ncal-test`, load its nftables ruleset, sysctls (no forwarding, `accept_ra` per-iface) |
| `netcaliper-helper.service` | root | — | allowlisted privileged actions over `/run/netcaliper/helper.sock` |
| `netcaliper-agent.service` | `netcaliper` | `NET_RAW NET_ADMIN` (ambient) | test-plane executor inside `ncal-test` |
| `netcaliper-core.service` | `netcaliper` | `NET_RAW NET_ADMIN` (ambient) | web/API, DB, scheduler, root-ns drivers |
| `netcaliper-kiosk.service` | `ncal-kiosk` | none | `cage -- chromium --kiosk http://localhost:8080` on tty1, `Restart=always` |
| `netcaliper-sync.timer/.service` | `netcaliper` | — | triggers outbox flush + config pull (core also syncs opportunistically) |

The kiosk runs as its own user with no network capabilities: a browser exploit from a malicious
captive portal page rendered in the UI can't touch raw sockets.

### 2.1 Privileged helper

- Listens on a unix socket, mode 0660 group `netcaliper`; verifies `SO_PEERCRED` uid.
- Each action is a Pydantic model with strict validation (e.g. `MovePhyToNetns(phy: PhyIndex)`,
  `SetNmUnmanaged(mac: MacAddr)`, `OpenReflectorPort(port: int in 5201..5299, ttl_s: ≤3600)`).
- No shell, no arbitrary paths, no generic "run command". Every call is audit-logged.
- Target size: a few hundred lines, 100 % test coverage, reviewed separately (see `SECURITY.md`).

### 2.2 Interface roles & assignment

Roles: `test-wired`, `test-wifi`, `monitor`, `mgmt`, `unused`. Assignment is keyed by a **stable
device identity** (`usb:<bus-path>:<vid>:<pid>` + permanent MAC + driver), persisted in config,
never by ifname.

Defaults (overridable in Settings):
- internal `brcmfmac` (CYW43455) → `mgmt` (and BLE via `hci0`)
- first wired NIC that isn't the board's own Ethernet → `test-wired`
- best monitor-capable radio (scored: monitor support, bands, driver reliability table) → `monitor`
- remaining Wi-Fi radios → `test-wifi`

Placement (`core/testplane.py`, implemented in Phase 1): after each detection, core computes a plan
(test roles → into `ncal-test`, anything else found there → back out) and asks the helper to apply it:
first the NetworkManager keyfile (`unmanaged-devices=mac:…`, so NM never races us), then one
`plane.move_in`/`plane.move_out` per device, each audit-logged. Wi-Fi moves per *phy*
(`iw phy <n> set netns name ncal-test`). Once moved, devices are invisible from the root namespace, so
core merges the agent's `snapshot.net` view (systemd ≥ 257 gives a netns-bound service a matching sysfs
mount) and tags each device with `netns`. A default route inside the test netns never makes a device
`mgmt`.

Hotplug: a cheap polling signature (USB device + root-netns netdev listing, every 5 s, then a 2 s
settle) triggers detect → plan → apply. No udev/netlink dependency; same behavior on every distro.

---

## 3. Capability & driver layer (`device/netcaliper/drivers/`)

```python
class Capability(StrEnum):
    WIRED_TEST = "wired.test"; WIRED_CABLE_TEST = "wired.cable_test"; WIRED_MULTIGIG = "wired.multigig"
    WIFI_SCAN = "wifi.scan"; WIFI_MONITOR = "wifi.monitor"; WIFI_CONNECT = "wifi.connect"
    WIFI_5G = "wifi.band.5"; WIFI_6G = "wifi.band.6"; WIFI_AX = "wifi.ax"
    BLE_SCAN = "ble.scan"; SDR_SUBGHZ = "sdr.subghz"; SPECTRUM_2G4 = "spectrum.2g4"
    SPECTRUM_WIDEBAND = "spectrum.wideband"        # future HackRF slot
    HID_RF_DETECT = "hid_rf.detect"                 # nRF24 MouseJack detection
    PROBE_WIREMAP = "probe.wiremap"; PROBE_TONE = "probe.tone"; PROBE_LENGTH = "probe.length"
    POE_MEASURE = "poe.measure"; GPS = "gps"; BATTERY = "platform.battery"
```

- **`HardwareDevice`**: `id` (stable), `kind`, `driver`, `usb_id`, `bus_path`, `ifname|phy|hci|serial`,
  `capabilities: dict[Capability, CapState]` where `CapState ∈ {ok, degraded(reason), absent}`, `role`.
- **Hotplug is normal, not exceptional:** USB hubs drop out (observed on the dev box: the whole hub
  disappeared mid-session). Detection is re-run on udev/netlink events; a module losing its device
  mid-run ends with `error(device_lost)`, never a crash.
- **Detectors** (one per kind) produce `HardwareDevice`s from real system sources:
  nl80211 (`iw` machine-parsed today, behind a source interface so pyroute2 can replace it) for
  radios, rtnetlink + sysfs +
  `ethtool` ioctls for NICs, pyusb for SDR/nRF24/probe/PoE, BlueZ D-Bus for BLE, device-tree for platform.
- **Capability probing is generic:** e.g. cable test = issue the ethtool netlink cable-test request
  and map `EOPNOTSUPP` → `absent("PHY has no cable diagnostics — requires netcaliper probe")`.
- **Driver quirks table** (`drivers/quirks.py`): known-bad combos degrade capabilities instead of
  failing, e.g. `rtl8192cu` monitor → `degraded("in-kernel driver monitor mode unreliable")`.
- **Driver interfaces** (ABCs) per kind: `WiredNic`, `WifiRadio`, `BleAdapter`, `SubGhzSdr`,
  `Nrf24Radio`, `WiremapProbe`, `PoeModule`, `WidebandSdr`, `Gps`, `Platform`.
- **Mocks:** each interface has a mock fed by a YAML *hardware fixture*. `NETCALIPER_HW=mock:<fixture>`
  (default in dev/tests). Detection is a pure function of a `SystemSnapshot` (sysfs + `iw` + `ethtool`
  + platform facts), so `netcaliper doctor --record FILE --anonymize` captures a real machine as a
  fixture. Fixtures shipped: `empty`, `uconsole-cm4-full` (everything in the hardware table),
  `uconsole-cm4-future` (+ MT7921AU, RTL8156B, probe, PoE), `devbox-jer` (recorded on the x86 dev box). Mocks generate plausible, deterministic data
  (seeded) — beacons, DHCP offers, LLDP frames, rtl_433 JSON — so UI and modules are fully exercisable.
- **Mixed mode:** `NETCALIPER_HW=real` with per-kind overrides (`mock_kinds = ["poe", "probe"]`).

### Platform detection
`/proc/device-tree/model` + `compatible` → `rpi-cm4`, `rpi-cm5`, `rpi-4`, `rpi-5`, `x86-generic`, …;
uConsole detected by DSI panel connector/resolution and ClockworkPi overlay/PMIC presence
(AXP228 battery via `/sys/class/power_supply`). Platform drives: USB bandwidth expectations,
battery readout, display rotation, backlight control.

---

## 4. Test modules (`device/netcaliper/modules/`)

```python
class Activity(StrEnum):
    PASSIVE = "passive"            # listening, own-link tests, DHCP/DNS/gateway, ARP on local segment
    ACTIVE = "active"              # nmap beyond host discovery, NSE, SNMP of others, segmentation
    # (there is deliberately no "intrusive" level: we don't build those)

class TestModule(ABC, Generic[C]):
    id: ClassVar[str]                     # "wired.dhcp"
    version: ClassVar[str]
    requires: ClassVar[set[Capability]]   # all required
    optional: ClassVar[set[Capability]]   # enriches result if present
    activity: ClassVar[Activity]
    executor: ClassVar[Literal["test-ns", "root"]]
    Config: ClassVar[type[C]]             # Pydantic model; drives the settings form too

    async def run(self, ctx: RunContext, cfg: C) -> ModuleResult: ...
```

- **`RunContext`**: `progress(pct, msg, data)` → WebSocket stream; `devices` (resolved by capability);
  `guard` (engagement scope check — mandatory call for ACTIVE modules, enforced by the runner which
  refuses to execute ACTIVE modules without a valid engagement covering the targets); `artifacts`
  (local-only file store); `cancel` token; `clock` (wall + monotonic).
- **`ModuleResult`**: `status ∈ {pass, warn, fail, error, skipped}`, `metrics: dict[str, float|str]`,
  `details` (structured, module-specific), `entities` (hosts/BSSIDs/BLE/RF signals found),
  `findings`, `artifacts` (refs only).
- **Thresholds** are declarative in profiles and evaluated by the runner, not the module:
  `{metric: "dhcp.offer_ms", warn: "> 500", fail: "> 2000"}`. Modules just report metrics.
- **AutoTest profile** = ordered list of `{module, config, thresholds, continue_on_fail}` + the
  interface/VLAN/SSID it applies to. Profiles are versioned and syncable from the cloud.
- A module registry discovers modules via entry points so future hardware modules are plug-ins.

### Key implementation choices

| Area | Choice | Why |
|---|---|---|
| DHCP | own client (dpkt parse + our builders over `AF_PACKET`) | measure each DORA phase, **collect every OFFER** (rogue detection) — `dhclient` stops at the first. Lease then applied with pyroute2 in the netns. |
| LLDP/CDP/EDP | **own `AF_PACKET` receiver + own TLV parsers (dpkt for CDP); optional LLDP transmit** | `lldpd` is a long-running daemon that transmits by default, isn't netns/test-session aware, and hides link-up→first-frame timing. We need on-demand capture per test, precise timing, VLAN-subif awareness, and raw TLVs in results. LLDP-MED and EDP parsers are ours; dpkt covers CDP. |
| Link | rtnetlink + ethtool netlink (`linkmodes`, `linkstate`) | advertised vs. partner vs. negotiated, link-up timing, flap counter from carrier events |
| VLAN | 802.1Q subinterfaces in the netns, one per VLAN profile | each gets its own DHCP/DNS/target run |
| 802.1X | `wpa_supplicant -Dwired` / nl80211, driven via control socket | event timestamps → auth timing |
| DNS / ping / TCP / HTTP / FTP | dnspython, icmplib, asyncio sockets, httpx, aioftp | async, timing-accurate, no subprocess per probe |
| Wi-Fi scan | nl80211 scan with raw IE parsing (own IE decoder; dpkt `ieee80211` for monitor frames) + `survey dump` for noise/busy time | full security/PMF/WPS/QBSS/HT/VHT/HE decoding; monitor-mode beacon capture adds client discovery |
| nmap | subprocess `nmap --privileged -oX -` (works with ambient caps), XML parsed | stream progress via `--stats-every` |
| Vuln lookup | **decoupled**: scan in netns → CPEs → enrichment in core (see §8) | `vulners` NSE needs internet from the *test* network |
| SNMP | pysnmp (v1/v2c/v3, async) | |
| BLE | bleak (BlueZ D-Bus) | |
| SDR | `rtl_433 -F json` and `rtl_power` subprocesses, parsed streams | |
| nRF24 | pyusb port of RFStorm/MouseJack tooling (Python 3) | |
| Heatmaps | numpy/scipy interpolation (IDW default, RBF optional) → PNG server-side | CM4 handles it; cloud viewer does the same in JS on canvas |
| PDF reports | headless Chromium `--print-to-pdf` (already installed for the kiosk); WeasyPrint fallback in `--dev` | no extra heavy deps |

---

## 5. Device storage (`device/netcaliper/core/db`)

- SQLite (WAL) at `/var/lib/netcaliper/netcaliper.db`, accessed via aiosqlite; numbered SQL migrations.
- Tables mirror the cloud model (§7) plus local-only: `artifacts`, `outbox`, `kv_config_cache`.
- **Outbox pattern:** every syncable record write and its `outbox` row are in one transaction.
  `outbox(record_uuid PK, kind, schema_version, payload JSON, created_at, attempts, next_attempt_at, acked_at)`.
- IDs: UUIDv7 (time-sortable; nice for indexes on both sides).
- Timestamps: UTC wall clock + `clock_synced` flag (Pi has no battery RTC; a run before NTP sync is
  marked so the dashboard doesn't misplace it).
- Artifacts (pcaps, raw nmap XML, rtl_power CSV, heatmap PNGs) on disk under
  `/var/lib/netcaliper/artifacts/<run>/…`, quota-managed; cloud only receives `{name, size, sha256}`.

---

## 6. Web UI (`device/netcaliper/web/`)

- FastAPI + Jinja2 + HTMX + Alpine.js; uPlot, cytoscape.js vendored under `web/static/vendor/`
  with versions + hashes recorded in `VENDORED.md`. No CDNs, no Node on the Pi.
- 1280×720, dark phosphor-green theme shared with netlog/netdash (CSS variables in one file).
- **Keyboard-first:** home tile grid navigable with arrows/Enter; single-key hotkeys per tile
  (`A`utoTest, `W`ired, `F`i (Wi-Fi), `D`iscovery, `S`ecurity, `M`apper, `R`F, `T`ools,
  `L`og/Results, `,` Settings); `Esc` back, `?` help overlay, focus ring always visible. Trackball =
  mouse. Minimum target 48 px, base font ~20 px.
- Live data over WebSockets (`/ws/runs/{id}`, `/ws/stream/{topic}`) rendered by small Alpine components.
- Locate "Geiger counter" tone is generated in-browser (Web Audio), so no audio stack in the backend.
- Status bar: battery, mgmt link, sync state (queued count / last sync / backoff), active engagement, clock-sync warning.
- **Access:** server listens on 0.0.0.0:8080 *in the root netns* (test interfaces are physically
  unreachable from it — they're in `ncal-test`). Root-ns nftables allows 8080 only on `lo` and the
  `mgmt` interface. Localhost (kiosk) needs no login; any other source requires login (local admin
  password set at install, argon2id hash, session cookie) and HTTPS (self-signed cert generated by installer).

---

## 7. Cloud (`cloud/`)

### 7.1 Stack decision: TypeScript + Hono (not Python Workers, yet)
Python Workers went GA in Sept 2026 and can run FastAPI, which is tempting for code sharing.
Still TypeScript for v1 because:
- **Free plan CPU limit is 10 ms per request.** Pyodide's startup and interpretation overhead eats a
  large share of that; a TS Worker spends it on decompressing and inserting. This is the deciding factor.
- Hono + D1 + Workers static assets is the well-trodden path; typed D1 bindings, mature `wrangler` + Vitest pool.
- The "share models" benefit is captured anyway by generating TS types from the device's JSON Schemas.
Revisit if we ever move to Workers Paid.

### 7.2 Free-tier budget (verified 2026-11-22)

| Limit (Workers Free) | Value | Design response |
|---|---|---|
| Worker requests | 100k/day | devices sync in batches on a timer, not per result; dashboard uses few, aggregated calls |
| CPU per request | **10 ms** | small gzip batches (start ≤ 64 KB compressed, tune by measurement); SHA-256 (not argon2) for high-entropy tokens; no server-side rendering of heatmaps/PDFs |
| D1 queries per invocation | 50 | per request ≤ 40 statements; multi-row `INSERT … VALUES (…),(…)` (≤ 100 bound params each) via `db.batch()`; server returns what it acked, device retries the rest |
| D1 rows read | 5M/day | every WHERE/ORDER BY column indexed; pre-aggregated counters; ETag on `/config`; no `COUNT(*)` over big tables in the dashboard |
| D1 rows written | 100k/day — **indexes add written rows**; since 2026-09-01 queries *fail* past the cap until 00:00 UTC | usage meter + device back-off; minimal indexes on write-heavy tables; throttled `last_seen` updates |
| D1 storage | 500 MB/db, 5 GB/account, 10 dbs | retention cron; blobs compressed, stored as `BLOB` (not base64) |
| Row / value size | 2 MB | per-run blob capped at 512 KB compressed; above that the blob is trimmed (entities summarized) and flagged |

### 7.3 Data model (D1)
`sites`, `devices`, `enroll_codes`, `device_tokens`, `engagements`, `profiles`, `policies`,
`authorized_lists` (devices/APs/vendors), `test_runs` (summary + `blob` gzip JSON),
`test_results` (one row per module result: status + key metrics), `hosts`, `wifi_bssids`,
`ble_devices`, `rf_signals` (inventory, upserted per site by natural key), `surveys`,
`survey_points` (grid-aggregated, not raw samples), `findings`, `audit_log`, `usage_meter`
(one row per UTC day), `share_links`.

- Writes keyed by record UUID: `INSERT … ON CONFLICT(id) DO NOTHING` → replays are free of side effects.
- Inventory upserts: `ON CONFLICT(site_id, mac) DO UPDATE SET last_seen = excluded.last_seen
  WHERE excluded.last_seen > last_seen + 3600` — avoids burning writes on every sighting.
- `usage_meter` is bumped **once per sync request** with that request's computed row count (not per row).

### 7.4 API v1
Host: **`netcaliper.supertechguy.net`** (Worker custom domain; the `supertechguy.net` zone must be on
Cloudflare). The `workers.dev` route is disabled so Access can't be sidestepped.

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/v1/enroll` | one-time code (hash stored, 15 min TTL, single use) | returns device token (32 random bytes); server stores SHA-256 only |
| `POST /api/v1/sync` | `Bearer <device token>` | body: gzip JSON `{batch_id, records[]}` → `{acked[], rejected[{id,reason}], backoff_s?, limits}` |
| `GET /api/v1/config` | `Bearer` | profiles, engagements, policies, authorized lists, sites; `ETag`/`If-None-Match` |
| `/api/v1/admin/*`, dashboard | Cloudflare Access | Worker **also validates the `Cf-Access-Jwt-Assertion` JWT** (cached JWKS) — Access alone can be bypassed if the Worker is reachable on another hostname; `workers_dev = false` and `preview_urls = false` |
| `/share/<token>` | signed, expiring share token | read-only report view; Access bypass policy on this path only |

Back-off: when today's `usage_meter.rows_written` > 70 % of budget the server returns `backoff_s`
and a reduced `limits.max_records`; > 90 % only audit-log and findings records are accepted. Devices
keep queuing locally regardless.

### 7.5 Retention cron
Daily Cron Trigger: delete `test_results` rows older than N days (run summary + blob kept), drop
blobs older than M days, condense `survey_points`, prune `usage_meter` > 90 days. N/M configurable
in a `settings` table. Each cron run keeps under the per-invocation query limit (chunked deletes,
resumable cursor).

### 7.6 Dashboard
Static assets served by the Worker; small TS + vendored uPlot/cytoscape (Node *is* fine here —
it builds in GitHub Actions, not on the Pi). Views: sites → devices → runs → results; inventory;
findings with filters; survey heatmap viewer (client-side IDW on canvas); audit log; enrollment &
revocation; editors for engagements/policies/profiles. Reports rendered client-side from the run
blob with print CSS (PDF via browser print).

### 7.7 Device sync client
Runs in core; uses the `mgmt` interface only (bound via `SO_BINDTODEVICE`) unless "allow sync over
test port" is enabled, in which case the request is proxied through the agent. Exponential backoff
with jitter (cap 1 h), honors `backoff_s`, batches oldest-first, audit log prioritized.

---

## 8. Security features (CyberScope parity)

- **Engagements:** `{name, authorized_cidrs[], authorized_ssids[], excluded_cidrs[], authorized_by,
  starts_at, expires_at, allowed_module_ids[]?}`. Created on device or in the dashboard (synced down).
- **Scope guard:** every ACTIVE module calls `ctx.guard.authorize(targets)` — CIDRs, hostnames
  (resolved, every address checked), and nmap target specs are expanded and must be ⊆ authorized − excluded.
  The runner enforces it (module can't skip it). Uncovered network → confirmation screen; the
  decision is audit-logged.
- **Audit log:** append-only, hash-chained (`prev_hash`) for tamper evidence; syncs with priority.
- **Vulnerability assessment:** nmap `-sV` + selected NSE `vuln` scripts in the netns. CPE → CVE
  enrichment happens in core over mgmt: (a) vulners API — opt-in, since it discloses
  CPEs to a third party; (b) offline: an updatable local CVE/CPE index (vulscan-style CSVs) pulled
  over mgmt. **Greenbone/OpenVAS on the device: rejected** (gvmd + ospd-openvas + redis + PostgreSQL + multi-GB
  feeds; it needs more RAM than a CM4 and takes far too long to sync feeds and start).
  Optional later: import a GVM XML report produced elsewhere.
- **Policy engine:** declarative rules (YAML/JSON, editable in dashboard) evaluated over entities →
  findings `{severity, rule_id, entity, evidence}`.
- **Rogue detection, wireless posture, segmentation matrix, inventory export (CSV/JSON).**
- **Self-protection nftables (inside `ncal-test`):** `input` default drop; allow established/related,
  DHCPv4 client (udp 68), DHCPv6 client (udp 546), ICMP/ICMPv6 essentials (ND, RA, echo-reply);
  reflector/iperf ports only while explicitly enabled (helper action with TTL). `forward` drop,
  `ip_forward=0`. No listening sockets in the netns except during reflector mode.

## 9. Out of scope (enforced in review)
Credential brute-forcing, deauth/disassoc, packet injection for attack purposes, keystroke
injection (MouseJack is *detection only*: sniffed payloads are discarded in the driver, only
address/vendor/protocol fingerprints are kept), jamming, anything that disrupts rather than measures.
"Transmit" features we *do* have, all benign: DHCP/DNS/ICMP/TCP/HTTP client traffic, optional LLDP
announce, iperf, ARP sweep, port blink on our own link.

---

## 10. Installer (`installer/`)
`install.sh [--dev] [--no-kiosk] [--start-kiosk] [--vnc|--no-vnc] [--skip-apt] [--branch X]`, idempotent
(every step is check-then-apply). `--dev` = x86/dev host: services, no kiosk, no OS tweaks; the app is
installed (non-editable) from the working tree, and re-running after edits reinstalls only when the
source hash changed.
OS detection: Pi OS Trixie / Bookworm arm64, Debian/Ubuntu x86 (`--dev`).
**Reference uConsole base image: ClockworkPi `uConsole_CM4_v3.1_64bit.img`** (vendor kernel +
overlays for panel, keyboard, AXP228 PMIC). The installer treats it as "fresh Pi OS": it detects the
Debian release from `/etc/os-release` (never assumes), leaves the ClockworkPi kernel/overlays and
their apt repo alone, and refuses on Python < 3.11. Stock Pi OS + ClockworkPi apt packages should
also work but is secondary. Kiosk notes for this image: it ships a desktop + display manager, so
kiosk mode disables the DM (restorable via `uninstall.sh` / `--no-kiosk`); the DSI panel is natively
portrait (720×1280), so rotation is applied in the cage session (`wlr-randr --transform`) based on the
detected DRM connector, not taken from the desktop's config.

**Facts from the real unit (2026-11-22):** Debian 13 Trixie, Python 3.13.5, kernel `6.12.62-v8+`
(ClockworkPi), CM4 4 GB, 238 GB SD, `lightdm` + labwc desktop, ClockworkPi apt repo on its `bookworm`
channel. Installer implications:
- `/usr/sbin` is not on unprivileged users' PATH — code resolves tools via `drivers.snapshot.which()`.
- The image's labwc env sets `WLR_DRM_FORCE_LIBLIFTOFF=1`; carry it into the cage kiosk session.
- `mkinitramfs` fails (`failed to determine device for /`, root is `/dev/root`), which wedges apt
  upgrades. Firmware boots without an initramfs (`root=PARTUUID=…`), so the installer drops in
  `/etc/initramfs-tools/conf.d/root-device-workaround` (`MODULES=most`) and runs `dpkg --configure -a`
  before installing anything.
- Debian's `rtl-sdr` package does **not** blacklist the DVB modules — the installer must.
- NetworkManager DHCPs any USB NIC it sees (AX88179 got the lowest-metric default route, ahead of
  the Wi-Fi mgmt link). The installer writes an NM `unmanaged-devices` drop-in keyed by MAC for every
  test-role interface (regenerated on role change) before moving it into `ncal-test`. Detection
  already prefers built-in interfaces for mgmt and never takes the only wired NIC.
- Kiosk: `cage -s` on tty1 via `PAMName=` (logind session, no seatd). logind only activates a session
  on the foreground VT, so the unit runs `chvt 1` first (needed after stopping lightdm). The DSI panel
  is rotated by `wlr-randr --transform 270` inside the session; Chromium gets a fresh profile per start.
- Power saving: `swayidle` in the session drives `kiosk-display dim|blank|wake` (defaults: dim to
  level 1 at 540 s, backlight off at 600 s; `KIOSK_*` in `/etc/netcaliper/kiosk.env`, optional
  `KIOSK_BLANK_S_BATTERY`). Blanking powers the backlight down (`bl_power=4`) rather than the output:
  cage 0.3 has no wlr-output-power-management, and disabling the output (which does work via
  wlr-randr) would disconnect VNC viewers. The page mirrors the timeout (`data-blank-after`) so the
  waking key/click is swallowed and htmx polling pauses while dark. Test-plane interfaces stay
  administratively down unless a test brings them up; the CPU governor is the image's `ondemand`.
- VNC (opt-in `--vnc`, remembered): `wayvnc` inside the cage session (cage 0.3 offers screencopy +
  virtual keyboard/pointer, so view *and* control work); see SECURITY.md. `/etc/netcaliper` is 0751 so
  the kiosk user can reach `wayvnc/` without being able to list or read the rest.
- Measured on the uConsole (2026-11-23): ~21 s to userspace with kiosk; reinstall ~65 s; an
  immediate re-run changes nothing.
- uConsole has no Ethernet jack; the CM4's `eth0` (bcmgenet) is forced `unused`. The keyboard MCU
  (`1eaf:0024`) identifies the platform. Steps: apt deps (package
names resolved per release, e.g. `chromium` vs `chromium-browser`) → users (`netcaliper`, `ncal-kiosk`)
→ `/opt/netcaliper` venv (system Python) → `/etc/netcaliper`, `/var/lib/netcaliper` → modprobe
blacklist (`dvb_usb_rtl28xxu`, `rtl2832`, `rtl2832_sdr`) → udev rules (RTL-SDR, nRF24 `1915:0102`,
probe/PoE VID:PIDs) → NM unmanaged config → nftables → systemd units → kiosk (tty1, cage, Chromium
flags, crash restart, cursor hiding) → splash/branding → platform tweaks (uConsole rotation,
backlight, battery) → `netcaliper doctor`. `uninstall.sh` reverses it (keeps data unless `--purge`).

## 11. License
GPL-3.0 for the whole repo — `LICENSE` at root, SPDX headers in source files.
**scapy is not used** (GPL-2.0-only, incompatible with GPL-3.0). Packet parsing uses dpkt (BSD-3);
frame builders and `AF_PACKET`/BPF capture are our own (`netcaliper/net/`). Check every new
dependency's license is GPL-3.0-compatible. Subprocess-invoked tools (nmap, rtl_433,
iperf3, tshark, wpa_supplicant) are separate programs and don't affect our license.

## 12. Repo layout
```
netcaliper/
  device/  pyproject.toml, netcaliper/{core,drivers,modules,web,cli,agent,helper}, tests/
  schemas/ JSON Schemas exported from device models (generated, committed, CI-checked)
  installer/ install.sh, uninstall.sh, lib/, systemd/, udev/, nftables/, kiosk/, branding/
  cloud/   src/ (Hono Worker), migrations/, dashboard/, wrangler.toml, test/
  hardware/ probe + PoE specs (docs only)
  docs/    ARCHITECTURE.md, ROADMAP.md, HARDWARE.md, SECURITY.md
  .github/workflows/ device-ci (x86 + arm64), cloud-ci, cloud-deploy
```

## 13. Testing strategy
- `pytest` + `pytest-asyncio`; default runs entirely on mocks (`NETCALIPER_HW=mock:uconsole-cm4-full`).
- `@pytest.mark.hw` — needs real hardware, auto-skips when the capability isn't detected.
- `@pytest.mark.netns` — needs root; builds veth pairs + throwaway netns with `dnsmasq`
  (multiple DHCP servers for rogue tests), an LLDP/CDP emitter built on our own frame builders, etc. Real-protocol integration tests without hardware; run in CI (GitHub runners have sudo).
- Cloud: Vitest with `@cloudflare/vitest-pool-workers` + local D1; a budget test asserts a max-size
  sync request stays under 50 queries.
- CI: device tests on x86 (Python 3.11 / 3.13 / 3.14) and native arm64 runners (3.11 / 3.13); an
  installer job does a real `--dev` install/re-run/uninstall on a systemd runner.
