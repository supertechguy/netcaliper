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

## Phases

| # | Phase | Exit criteria | Status |
|---|---|---|---|
| 0 | Foundation | scaffold, docs, config, SQLite + outbox, capability layer + mocks + fixtures, `netcaliper doctor` detects all current hardware, FastAPI UI shell with home tiles + keyboard nav, CI green | done (CI runs on first push) |
| 1 | Installer + kiosk | fresh Pi OS → boots into UI on uConsole; `--dev` on x86; `ncal-test` netns + agent + helper; nftables; idempotent re-run; uninstall | planned |
| 2 | Wired AutoTest | link, LLDP/CDP/EDP, DHCP (+rogue), DNS, gateway, IPv6, ping/TCP/HTTP/FTP, VLAN, 802.1X wired, profiles + thresholds, port blink, cable-test probe, results screen; netns integration tests | planned |
| 3 | Wi-Fi core | multi-radio scan, IE decoding, channel/interference analysis, connection test (PSK + EAP), roaming, client discovery (monitor), locate | planned |
| 4 | Cloud sync v1 | Worker + D1 + migrations + Actions deploy, enroll, sync, config pull, Access JWT check, usage meter + back-off, retention cron, basic dashboard | planned |
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
| AutoTest, profiles, pass/warn/fail thresholds | E | `core.autotest` | — | 2 | planned |
| Link: speed/duplex, adv. vs negotiated, link-up time, flap counter | E | `wired.link` | wired NIC | 2 | planned |
| LLDP / CDP / EDP incl. VLAN, voice VLAN, LLDP-MED PoE | E | `wired.switchinfo` | wired NIC | 2 | planned |
| 802.1Q VLAN tests, multiple VLAN profiles | E | `wired.vlan` | wired NIC | 2 | planned |
| 802.1X wired (PEAP/TLS) | E | `wired.dot1x` | wired NIC | 2 | planned |
| DHCP timing, lease details, multiple/rogue server detection | E/C | `wired.dhcp` | wired NIC | 2 | planned |
| IPv6: RA/SLAAC, DHCPv6, gateway | E | `wired.ipv6` | wired NIC | 2 | planned |
| DNS timing, multiple servers; gateway reachability | E | `net.dns`, `net.gateway` | any test iface | 2 | planned |
| Ping / TCP / HTTP(S) / FTP targets with thresholds | E | `net.targets` | any test iface | 2 | planned |
| iperf3 client/server + netcaliper↔netcaliper reflector/peer | E | `perf.iperf`, `perf.reflector` | wired NIC (CM4: USB 2.0 caps it at ~300 Mb/s) | 9 | planned |
| Path analysis: traceroute + SNMP along path | E | `perf.path` | — (SNMP needs engagement) | 9 | planned |
| Packet capture with filters → pcap (local, downloadable) | E | `tools.capture` | any test iface | 9 | planned |
| Port blink | E | `wired.blink` | wired NIC | 2 | planned |
| Cable test via `ethtool --cable-test` when PHY supports | E | `wired.cable` | PHY w/ cable diag (AX88179: no) | 2 | planned |
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
| Scan: SSID/BSSID, chan/width, RSSI, noise, security, PMF, WPS, standards, QBSS, hidden | E | `wifi.scan` | any radio (5 GHz: MT7610U/CYW43455) | 3 | planned |
| Channel maps, co-/adjacent-channel analysis | E | `wifi.channels` | any radio | 3 | planned |
| Connection test: assoc/auth/DHCP timing, PSK + EAP | E | `wifi.connect` | test-wifi radio | 3 | planned |
| Roaming test between BSSIDs | E | `wifi.roam` | test-wifi radio | 3 | planned |
| Client discovery, AP↔client association | E | `wifi.clients` | monitor radio (MT7610U) | 3 | planned |
| Locate (Geiger counter + tone): AP / client / BLE | E | `wifi.locate`, `ble.locate` | radio / BLE | 3 / 8 | planned |
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
| Kiosk boot, splash, blanking control, uConsole tweaks | X | installer | uConsole | 1 | planned |
| HTML + PDF per-run and per-site reports | E/C | `reports` | — | 9 | planned |
| Cloud: enroll, sync, config pull, dashboard | E/C (Link-Live) | `cloud/` | — | 4 | planned |
| Cloud: survey viewer, findings, audit, editors, share links | E/C | `cloud/` | — | 4–9 | planned |

## Known hardware limits (summary — details in HARDWARE.md)
- CM4 has **USB 2.0 only** → AX88179 tops out around 300 Mb/s; true GbE iperf needs a CM5 or Pi 5.
- No 6 GHz / ax until an MT7921AU is attached; no calibrated 2.4/5 GHz spectrum without a wideband SDR.
- No cable diagnostics on AX88179; wiremap/length need the netcaliper probe.
- CYW43455: no monitor mode (stock firmware); used for mgmt + BLE only.
