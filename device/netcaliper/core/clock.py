# SPDX-License-Identifier: GPL-3.0-only
"""Is the system clock NTP-synchronised? Recorded as `clock_synced` on every run (the uConsole has
an RTC only with the optional battery; a run stamped before sync must be flagged, not trusted)."""

from __future__ import annotations

from pathlib import Path

# systemd-timesyncd touches this once synchronised; chrony users get the same via `chronyc waitsync`
# hooks — absent marker means "unknown", reported as not synced.
MARKERS = (Path("/run/systemd/timesync/synchronized"), Path("/run/netcaliper/clock-synced"))


def clock_synced(markers: tuple[Path, ...] = MARKERS) -> bool:
    return any(m.exists() for m in markers)
