# netcaliper — Roadmap

> Living document. Update the **Status** column in the same commit as the work.
> Status values: `planned` · `in progress` · `done` · `blocked (hw)` · `stub` (interface + "not detected" only) · `won't do`.
> Source column: **E** = EtherScope nXG, **C** = CyberScope, **X** = netcaliper extra.

## Decisions
| Date | Decision |
|---|---|
| 2026-11-22 | uConsole base image: ClockworkPi `uConsole_CM4_v3.1_64bit` — confirmed Debian 13 Trixie, Python 3.13.5, CM4 4 GB |
| 2026-11-22 | Cloud host: `netcaliper.supertechguy.net` (Worker custom domain, `workers.dev` disabled) |
| 2026-11-22 | License: GPL-3.0; **no scapy** (GPL-2.0-only) — dpkt + own builders/capture |
| 2026-11-22 | Repo private until end of Phase 1, then public; commits use GitHub noreply email |
| 2026-11-22 | Cloud language: TypeScript + Hono (Python Workers rejected for now: 10 ms free-tier CPU) |
| 2026-11-23 | Remote view/control via opt-in VNC (`wayvnc` in the kiosk session, auth + TLS/RSA-AES, root netns only) |
| 2026-11-23 | Remote *browser* access (login + TLS) moved from Phase 1 to Phase 4 (with enrollment); VNC covers remote use until then |
| 2026-11-23 | Repo made public (end of Phase 1); history rewritten so all commits use the noreply email; arm64 CI moved to native runners |
| 2026-11-23 | Screen blanking via backlight power (not output power-off): cage lacks output-power protocol, and disabling the output would drop VNC viewers |
| 2026-11-23 | Hotplug by polling a USB/netdev signature (5 s) instead of udev/netlink — portable, no extra deps |
| 2026-11-23 | Wired tests use own packet code (dpkt + AF_PACKET/raw sockets) and `ip`/`ethtool`/`wpa_supplicant` subprocesses — no pyroute2/dnspython/httpx dependencies; test-ns modules run in the agent via `module.run`, which refuses ACTIVE modules |
| 2026-11-23 | Rogue-RA = more than one IPv6 *default* router; lifetime-0 prefix advertisers (Thread border routers) are informational |
| 2026-11-23 | 802.1X credentials stored only on the device (0600 file outside SQLite, never synced); EAP-TLS deferred to Phase 3 alongside Wi-Fi EAP and a shared cert store |
| 2026-11-23 | Added `python-multipart` (Apache-2.0) for UI form posts |
| 2026-11-23 | Wi-Fi via own nl80211 genetlink client + own IE decoder (no pyroute2/iw parsing); `iw` only for mode/channel changes; wpa_supplicant with event-driven timings |
| 2026-11-23 | Client MAC addresses, AP associations and probed SSIDs are kept in Wi-Fi results (and sync as metadata); frame payloads are never read |
| 2026-11-23 | One saved Wi-Fi network + EAP-TLS cert store, both local-only (shared with wired 802.1X) |
| 2026-11-23 | UI icons: pixel-grid inline SVG in the boot-splash style (no image assets) |
| 2026-11-24 | Cloud: `@cloudflare/vitest-plugin` (pool-workers was renamed), Vitest 5, Hono 4 (all MIT/Apache-2.0); dashboard is plain JS (no build, no vendored libs yet) |
| 2026-11-24 | Result bodies stored as JSON text in D1 (no in-Worker gzip: 10 ms CPU); retention drops them after 90 days, runs kept |
| 2026-11-24 | Remote access password hashed with stdlib scrypt instead of argon2id (no new dependency); HTTPS on :8443 alongside the loopback kiosk listener |
| 2026-11-24 | Sync needs no `SO_BINDTODEVICE`: core is in the root netns, test ports are in `ncal-test` |

## Phases

| # | Phase | Exit criteria | Status |
|---|---|---|---|
| 0 | Foundation | scaffold, docs, config, SQLite + outbox, capability layer + mocks + fixtures, `netcaliper doctor` detects all current hardware, FastAPI UI shell with home tiles + keyboard nav, CI green | done |
| 1 | Installer + kiosk | fresh Pi OS → boots into UI on uConsole; `--dev` on x86; `ncal-test` netns + agent + helper; nftables; idempotent re-run; uninstall | done (uConsole: boot-to-kiosk, reinstall, uninstall verified; x86 `--dev` verified in CI) |
| 2 | Wired AutoTest | link, LLDP/CDP/EDP, DHCP (+rogue), DNS, gateway, IPv6, ping/TCP/HTTP/FTP, VLAN, 802.1X wired, profiles + thresholds, port blink, cable-test probe, results screen; netns integration tests | done (AutoTest + Wired screen on the uConsole/AX88179 against a real LAN; netns tests in CI and on device; EAP-TLS deferred) |
| 3 | Wi-Fi core | multi-radio scan, IE decoding, channel/interference analysis, connection test (PSK + EAP), roaming, client discovery (monitor), locate | done (uConsole: scan on both radios, PSK/SAE connect + DHCP vs a lab AP, monitor + locate on the MT7610U; hwsim netns test incl. roaming; EAP verified by config tests only) |
| 4 | Cloud sync v1 | Worker + D1 + migrations + Actions deploy, enroll, sync, config pull, Access JWT check, usage meter + back-off, retention cron, basic dashboard | in progress (all code + tests done; uConsole synced to a local Worker; remote HTTPS login verified on the device; **production deploy waits for the Cloudflare setup in docs/DEPLOY.md**) |
| 5 | Discovery | ARP/ICMP/mDNS/SSDP/NetBIOS/LLDP, SNMP v1/2c/3, OUI DB, classification, topology, problem detection | planned |
| 6 | Security | engagements + audit UI, scope guard, nmap + NSE + CVE enrichment, policy engine, rogue detection, wireless posture, segmentation, inventory export | planned |
| 7 | AirMapper | floor plans, walk-and-click survey (passive/active), heatmaps, survey sync + dashboard viewer | planned |
| 8 | RF & BLE | BLE discovery/locate, nRF24 2.4 GHz sweep + MouseJack detection, rtl_433 inventory, rtl_power sweeps | planned |
| 9 | Perf, capture, reports | iperf3 + reflector/peer mode, path analysis, packet capture, HTML/PDF reports (device + cloud share links) | planned |
| 10 | Future hardware hooks | probe + PoE driver interfaces finalized, USB CDC JSON-lines protocol spec, firmware-side reference in `hardware/` | planned |

## Feature parity checklist

### Wired
| Feature | Src | Module | Hardware | Phase | Status |
|---|---|---|---|---|---|
| AutoTest, profiles, pass/warn/fail thresholds | E | `modules.autotest` | — | 2 | done (live view + results screen) |
| Link: speed/duplex, adv. vs negotiated, link-up time, flap counter | E | `wired.link` | wired NIC | 2 | done (AX88179 verified) |
| LLDP / CDP / EDP incl. VLAN, voice VLAN, LLDP-MED PoE | E | `wired.switchinfo` | wired NIC | 2 | done (LLDP+CDP verified on a real switch; EDP in netns tests) |
| 802.1Q VLAN tests, multiple VLAN profiles | E | `wired.vlan` | wired NIC | 2 | done (netns-tested) |
| 802.1X wired (PEAP/TLS) | E | `wired.dot1x` | wired NIC | 2 / 3 | done: PEAP/TTLS/MD5 (MD5 netns-tested vs hostapd), EAP-TLS with the local cert store (Phase 3) |
| DHCP timing, lease details, multiple/rogue server detection | E/C | `wired.dhcp` | wired NIC | 2 | done |
| IPv6: RA/SLAAC, DHCPv6, gateway | E | `wired.ipv6` | wired NIC | 2 | done (RA + DHCPv6 probe, rogue-RA by default-router count; observe only, no SLAAC config) |
| DNS timing, multiple servers; gateway reachability | E | `net.dns`, `net.gateway` | any test iface | 2 | done |
| Ping / TCP / HTTP(S) / FTP targets with thresholds | E | `net.targets` | any test iface | 2 | done |
| iperf3 client/server + netcaliper↔netcaliper reflector/peer | E | `perf.iperf`, `perf.reflector` | wired NIC (CM4: USB 2.0 caps it at ~300 Mb/s) | 9 | planned |
| Path analysis: traceroute + SNMP along path | E | `perf.path` | — (SNMP needs engagement) | 9 | planned |
| Packet capture with filters → pcap (local, downloadable) | E | `tools.capture` | any test iface | 9 | planned |
| Port blink | E | `wired.blink` | wired NIC | 2 | done (Wired screen) |
| Cable test via `ethtool --cable-test` when PHY supports | E | `wired.cable` | PHY w/ cable diag (AX88179: no) | 2 | done (skips cleanly when unsupported) |
| Wiremap, remote IDs, length, tone | E | `probe.*` | netcaliper probe | 10 | stub |
| PoE / TruePower class, voltage, power under load | E | `poe.truepower` | PoE module | 10 | stub |
| Multi-gig (2.5 GbE) link tests | E | `wired.link` | RTL8156B | 2 | stub (auto-detect) |

### Discovery
| Feature | Src | Module | Hardware | Phase | Status |
|---|---|---|---|---|---|
| ARP sweep, ICMP, mDNS, SSDP, NetBIOS, LLDP/CDP neighbors | E/C | `discovery.*` | any test iface | 5 | planned |
| SNMP v1/v2c/v3: sysinfo, ifaces, errors, util, neighbors, VLANs | E/C | `discovery.snmp` | — (engagement) | 5 | planned |
| Classification + offline OUI DB (updatable) | E/C | `discovery.classify` | — | 5 | planned |
| Topology map (LLDP/CDP/SNMP) | E | `discovery.topology` | — | 5 | planned |
| Problem detection (dup IP, errors, util, duplex mismatch…) | E | `discovery.problems` | — | 5 | planned |

### Wi-Fi
| Feature | Src | Module | Hardware | Phase | Status |
|---|---|---|---|---|---|
| Scan: SSID/BSSID, chan/width, RSSI, noise, security, PMF, WPS, standards, QBSS, hidden | E | `wifi.scan` | any radio (5 GHz: MT7610U/CYW43455) | 3 | done (own nl80211 + IE decoder; multi-radio merge; tested on RTL8188CUS + MT7610U) |
| Channel maps, co-/adjacent-channel analysis | E | `wifi.channels` | any radio | 3 | done (co/adjacent/overlap, 1/6/11 + 80 MHz recommendation, survey busy time where the driver reports it) |
| Connection test: assoc/auth/DHCP timing, PSK + EAP | E | `wifi.connect` | test-wifi radio | 3 | done (PSK/SAE/OWE/open/EAP-PEAP/TTLS/TLS; PSK + SAE verified on hardware; then `wifi.dhcp`/`net.*`) |
| Roaming test between BSSIDs | E | `wifi.roam` | test-wifi radio | 3 | done (hwsim-verified; needs ≥ 2 APs of one SSID) |
| Client discovery, AP↔client association | E | `wifi.clients` | monitor radio (MT7610U) | 3 | done (headers only; deauth-flood finding) |
| Locate (Geiger counter + tone): AP / client / BLE | E | `wifi.locate`, `ble.locate` | radio / BLE | 3 / 8 | Wi-Fi done (AP + client, meter + Web Audio clicks); BLE Phase 8 |
| 6 GHz / 802.11ax scanning | E | `wifi.scan` | MT7921AU | 3 | stub (auto-detect) |
| AirMapper: floor plan, walk-and-click, heatmaps (RSSI/SNR/co-chan/per-AP/rate) | E | `survey.*` | any radio | 7 | planned |
| AirMapper active mode | E | `survey.active` | test-wifi radio | 7 | planned |
| GPS outdoor survey | E | `survey.gps` | GPS | 7+ | stub |
| 2.4 GHz spectrum (activity only, nRF24 RPD — not calibrated dBm) | E | `rf.spectrum24` | nRF24LU1+ | 8 | planned |
| 5/6 GHz spectrum | E | `rf.wideband` | HackRF or similar | — | stub (driver slot) |

### Bluetooth / BLE
| Feature | Src | Module | Hardware | Phase | Status |
|---|---|---|---|---|---|
| BLE/BT discovery, RSSI, class, vendor | E/C | `ble.scan` | hci0 | 8 | planned |
| BLE locate | E | `ble.locate` | hci0 | 8 | planned |

### Security
| Feature | Src | Module | Hardware | Phase | Status |
|---|---|---|---|---|---|
| Engagements, scope guard, confirmation, hash-chained audit log | C | `core.engagement`, `core.audit` | — | 6 (guard + audit chain done in 0; UI in 6) | in progress |
| nmap host/port/service/OS + NSE | C | `security.nmap` | any test iface | 6 | planned |
| Vulnerability assessment (NSE + CPE→CVE enrichment) | C | `security.vuln` | — | 6 | planned |
| Greenbone/OpenVAS on device | C | — | — | — | won't do (too heavy for CM4; GVM report import maybe later) |
| Policy engine → findings | C | `security.policy` | — | 6 | planned |
| Rogue detection: APs, evil twins, DHCP, unknown switches | C | `security.rogue` | radio / wired | 6 | planned |
| Wireless security posture report | C | `security.wifiposture` | any radio | 6 | planned |
| Segmentation testing (per VLAN/SSID allow/deny matrix) | C | `security.segmentation` | test iface | 6 | planned |
| Edge inventory export CSV/JSON | C | `security.inventory` | — | 6 | planned |
| MouseJack-vulnerable HID detection (detect only) | X | `rf.mousejack` | nRF24LU1+ (RFStorm fw) | 8 | planned |
| Sub-GHz IoT inventory (rtl_433) | X | `rf.ism433` | RTL-SDR | 8 | planned |
| RF interference sweep (rtl_power) | X | `rf.sweep` | RTL-SDR (E4000: ~52–2200 MHz, gap ~1100–1250) | 8 | planned |

### Platform, reporting, cloud
| Feature | Src | Module | Hardware | Phase | Status |
|---|---|---|---|---|---|
| `netcaliper doctor` | X | `cli.doctor` | — | 0 | done |
| Kiosk boot, rotation, uConsole tweaks | X | installer | uConsole | 1 | done |
| Remote view + control (VNC) | E | installer (`--vnc`) | — | 1 | done |
| Test plane: auto-placement of test interfaces in `ncal-test`, hotplug | X | `core.testplane`, helper, agent | — | 1 | done |
| Power saving: dim 9 min → backlight off 10 min (configurable, optional shorter on battery), wake on any key/trackball/VNC input with the waking input swallowed, status polling paused while dark | X | installer (`kiosk-display`, swayidle), `web` | backlight | 1 | done |
| Keep screen awake during long jobs (surveys, long tests) | X | UI wake lock / idle inhibit | — | 7 | planned |
| Boot splash | X | installer | uConsole | 2 | done (Plymouth theme, verified on the uConsole boot) |
| Remote browser access (login + TLS on mgmt) | E | `web` | — | 4 | done (HTTPS :8443, scrypt password, sessions, throttling; verified on the uConsole) |
| HTML + PDF per-run and per-site reports | E/C | `reports` | — | 9 | planned |
| Cloud: enroll, sync, config pull, dashboard | E/C (Link-Live) | `cloud/` | — | 4 | done in code (Worker tests + device e2e vs local Worker); deploy pending |
| Cloud: survey viewer, findings, audit, editors, share links | E/C | `cloud/` | — | 4–9 | planned |

## Known hardware limits (summary — details in HARDWARE.md)
- CM4 has **USB 2.0 only** → AX88179 tops out around 300 Mb/s; true GbE iperf needs a CM5 or Pi 5.
- No 6 GHz / ax until an MT7921AU is attached; no calibrated 2.4/5 GHz spectrum without a wideband SDR.
- No cable diagnostics on AX88179; wiremap/length need the netcaliper probe.
- CYW43455: no monitor mode (stock firmware); used for mgmt + BLE only.
