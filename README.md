# netcaliper

Open, DIY handheld network tester for Raspberry Pi — aiming at EtherScope nXG + CyberScope feature
parity, prototyped on a ClockworkPi uConsole (CM4). Wired, Wi-Fi, discovery, security, site survey,
RF/BLE; local-first with optional sync to a self-hosted Cloudflare Workers + D1 dashboard.

**Status:** Phase 0 (foundation). See [docs/ROADMAP.md](docs/ROADMAP.md).

## Quick start (dev, any x86 Linux box — no special hardware needed)

```sh
make dev            # venv + editable install
make test           # pytest on mock hardware
make serve          # UI on http://127.0.0.1:8080 with the uConsole mock fixture
device/.venv/bin/netcaliper doctor                      # inspect the real machine
device/.venv/bin/netcaliper doctor --fixture devbox-jer # or a recorded fixture
```

Mock hardware: `NETCALIPER_HW=mock:<fixture>` (`uconsole-cm4-full`, `uconsole-cm4-future`,
`devbox-jer`, `empty`, or a path). Record your own: `netcaliper doctor --record mybox.yaml --anonymize`.

## Docs
[Architecture](docs/ARCHITECTURE.md) · [Roadmap & parity table](docs/ROADMAP.md) ·
[Hardware](docs/HARDWARE.md) · [Security](docs/SECURITY.md)

netcaliper measures networks; it does not attack them. Active scanning requires an authorized,
time-boxed Engagement and is audit-logged. See [docs/SECURITY.md](docs/SECURITY.md).

## License
GPL-3.0-only — see [LICENSE](LICENSE).
