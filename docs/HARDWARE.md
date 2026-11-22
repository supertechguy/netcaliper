# Hardware

Detection is capability-based (see ARCHITECTURE §3); this page documents what each device is used
for, its limits, and how it is recognized. Run `netcaliper doctor` to see what is detected.

## Current devices

| Device | USB ID / driver | Role / capabilities | Limits & quirks |
|---|---|---|---|
| ASIX AX88179 USB 3.0 GbE | `0b95:1790`, `ax88179_178a` | `test-wired` · wired.test | 1 GbE max; no phylib PHY → no `ethtool --cable-test`; on CM4 (USB 2.0) ~300 Mb/s |
| MediaTek MT7610U 802.11ac 1x1 | `0e8d:7610`, `mt76x0u` | `monitor` · scan/connect/monitor, 2.4+5 GHz, ac | no 6 GHz / ax |
| Realtek RTL8188CUS / RTL8192CU | `0bda:8176`/`8178`, `rtl8192cu` | `test-wifi` · scan/connect, 2.4 GHz | monitor mode reported **degraded** (unreliable in-kernel driver) |
| RTL-SDR RTL2832U (+E4000 tuner) | `0bda:2838`/`2832` | sdr.subghz (`rtl_433`, `rtl_power`) | E4000 ≈ 52–2200 MHz with a gap ≈ 1100–1250 MHz; cannot see Wi-Fi bands. Kernel DVB drivers must be blacklisted (`dvb_usb_rtl28xxu`, `rtl2832`, `rtl2832_sdr`) — doctor flags it. Several SDRs: give each a unique serial (`rtl_eeprom -s`) so roles stay stable. |
| nRF24LU1+ RFStorm research fw | `1915:0102` | spectrum.2g4 (activity), hid_rf.detect | RPD is a single ~-64 dBm threshold → channel *activity*, not dBm. Detection only; payloads discarded. Stock Crazyradio firmware (`1915:7777`) is reported degraded with a reflash hint. |
| CM4 CYW43455 (internal) | `brcmfmac` (SDIO), `hci_uart_bcm` | `mgmt` · scan/connect; BLE | no monitor mode on stock firmware (reported absent) |

## Future devices (auto-detected when present)

| Device | Recognized by | Adds |
|---|---|---|
| MediaTek MT7921AU | `0e8d:7961` + nl80211 | wifi.band.6, wifi.ax — preferred `monitor` radio |
| Realtek RTL8156/B 2.5 GbE | `0bda:8156` + 2500baseT link modes | wired.multigig — preferred `test-wired` |
| netcaliper probe | USB product string `netcaliper-probe` (CDC, JSON lines) | probe.wiremap/tone/length |
| netcaliper PoE module | USB product string `netcaliper-poe` | poe.measure |
| HackRF-class SDR | `1d50:6089` | spectrum.wideband (5/6 GHz) |

## Platform notes
- **CM4 is USB 2.0 only.** All USB devices share 480 Mb/s; GbE throughput tests need CM5/Pi 5.
  Several dongles on battery need a powered hub.
- uConsole is detected by its keyboard MCU (`1eaf:0024`), with CM + DSI panel + AXP PMIC as fallback.
  Fixture `uconsole-cm4` is an anonymized recording of the real unit.
- The uConsole has **no Ethernet jack**: the CM4's `eth0` (bcmgenet) exists in the kernel but is
  forced `unused`. Wired testing needs a USB NIC.
- USB: one internal Genesys hub (`05e3:0608`) shared by the keyboard and the external ports.
- Reference OS image: ClockworkPi `uConsole_CM4_v3.1_64bit` (Debian 13 Trixie, Python 3.13).
