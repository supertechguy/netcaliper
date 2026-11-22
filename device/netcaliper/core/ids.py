# SPDX-License-Identifier: GPL-3.0-only
"""UUIDv7 identifiers (time-sortable). Python < 3.14 lacks uuid.uuid7, so we build it."""

from __future__ import annotations

import os
import time
import uuid
from datetime import UTC, datetime


def uuid7() -> uuid.UUID:
    ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")
    value = (ms & 0xFFFF_FFFF_FFFF) << 80
    value |= 0x7 << 76  # version
    value |= ((rand >> 62) & 0x0FFF) << 64  # rand_a (12 bits)
    value |= 0b10 << 62  # variant
    value |= rand & 0x3FFF_FFFF_FFFF_FFFF  # rand_b (62 bits)
    return uuid.UUID(int=value)


def new_id() -> str:
    return str(uuid7())


def utcnow() -> datetime:
    return datetime.now(UTC)


def utcnow_iso() -> str:
    return utcnow().isoformat(timespec="milliseconds").replace("+00:00", "Z")
