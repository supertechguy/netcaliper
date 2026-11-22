# CLAUDE.md — netcaliper conventions

netcaliper is an open EtherScope nXG / CyberScope-class network tester for Raspberry Pi
(prototype: ClockworkPi uConsole CM4). Read `docs/ARCHITECTURE.md` before structural changes;
keep `docs/ROADMAP.md` status current in the same commit as the work.

## Non-negotiables
- **Measure, never interfere.** Do not build credential brute-forcing, deauth/disassoc, attack
  packet injection, keystroke injection, jamming. MouseJack = detection only; discard sniffed payloads.
- **ACTIVE modules** (nmap beyond host discovery, NSE, vuln, SNMP of other devices, segmentation)
  must declare `activity = Activity.ACTIVE` and go through `ctx.guard.authorize(...)`. The runner
  enforces the guard; never add a bypass. Every active action → audit log.
- **No hard-coded interface names**, ever (not in code, tests or fixtures logic). Resolve devices by
  capability via the driver registry.
- **Every hardware-touching feature has a mock**; the full app and test suite run on x86 without hardware.
- Raw artifacts (pcaps, raw scan output) never go to the cloud — only metadata.
- Privileged helper: allowlisted, schema-validated actions only. No shell, no generic exec.

## Licensing
- GPL-3.0. **Do not add scapy** (GPL-2.0-only) or any GPL-3.0-incompatible dependency; check the
  license of every new dependency. External tools invoked as subprocesses are fine.

## Layout
`device/` Python package `netcaliper` · `schemas/` generated JSON Schema · `installer/` bash + units ·
`cloud/` TS Worker (Hono) + D1 · `hardware/` specs · `docs/`.

## Python (device/)
- Python ≥ 3.11 (Bookworm floor), tested on 3.11/3.13/3.14. asyncio throughout; no blocking calls in
  the event loop (use `asyncio.to_thread` or subprocess).
- Tooling: venv + pip (uv optional), `ruff` (lint + format), `mypy --strict` on `core/`, `drivers/`, `helper/`.
- Pydantic v2 for config, module configs, records. Records changes → regenerate `schemas/`
  (`make schemas`) and the cloud TS types; CI fails if they drift.
- Subprocesses: `asyncio.create_subprocess_exec` with argument lists — never `shell=True`.
  Parse machine output (`-oX`, `-F json`, `iw` raw) not human output where possible.
- IDs are UUIDv7. Timestamps UTC, ISO-8601 in JSON. Include `clock_synced`.
- Syncable writes go through the repository layer, which writes the outbox row in the same transaction.

## Tests
- `pytest` (+ `pytest-asyncio`). Default env `NETCALIPER_HW=mock:uconsole-cm4-full`.
- `@pytest.mark.hw` — real hardware; must auto-skip when the capability is absent.
- `@pytest.mark.netns` — needs root; veth/netns integration tests (dnsmasq, our frame emitters).
- Cloud: `vitest` with the Workers pool + local D1; keep the "≤ 40 D1 statements per sync request" test green.

## Cloud (cloud/)
- TypeScript strict, Hono, D1. Free tier only — check `docs/ARCHITECTURE.md §7.2` before adding any
  query path: index the WHERE columns, but remember indexes cost written rows; no unbounded scans.
- Migrations are numbered SQL files in `cloud/migrations/`, applied by `wrangler d1 migrations apply`
  in CI. Never edit an applied migration.
- Re-verify Cloudflare limits in the docs before relying on a number; update §7.2 with the date.

## UI
- Dark phosphor-green theme (shared tokens with netlog/netdash in `web/static/css/theme.css`).
- 1280×720, keyboard-first: every action reachable by keyboard, visible focus, min target 48 px.
- All JS/CSS vendored (`web/static/vendor/`, recorded in `VENDORED.md` with version + sha256). No CDNs.

## Git
- Commit at the end of each phase (and at sensible checkpoints) with a short summary; update ROADMAP.
- Never commit secrets, device tokens, `.dev.vars`, or real enrollment codes.
