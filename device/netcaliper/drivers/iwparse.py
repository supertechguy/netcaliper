# SPDX-License-Identifier: GPL-3.0-only
"""Parser for `iw phy <phy> info` output (nl80211 wiphy dump, human format)."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

_FREQ = re.compile(r"^\s*\*\s*(\d+(?:\.\d+)?)\s*MHz\s*\[(\d+)\](.*)$")


class WiphyInfo(BaseModel):
    iftypes: list[str] = Field(default_factory=list)
    freqs_mhz: list[float] = Field(default_factory=list)  # enabled only
    ht: bool = False
    vht: bool = False
    he: bool = False
    eht: bool = False

    @property
    def bands(self) -> set[str]:
        out: set[str] = set()
        for f in self.freqs_mhz:
            if 2400 <= f < 2500:
                out.add("2g4")
            elif 5150 <= f < 5925:
                out.add("5")
            elif 5925 <= f <= 7125:
                out.add("6")
        return out


def parse_iw_phy_info(text: str) -> WiphyInfo:
    info = WiphyInfo()
    section: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        depth = len(line) - len(line.lstrip("\t"))
        if depth == 1:
            section = None
            if stripped.startswith("Supported interface modes"):
                section = "iftypes"
                continue
        if depth == 2 and stripped.startswith("Frequencies"):
            section = "freqs"
            continue
        if depth == 2 and section == "freqs" and not stripped.startswith("*"):
            section = None
        if section == "iftypes" and stripped.startswith("*"):
            info.iftypes.append(stripped.lstrip("* ").strip())
            continue
        if section == "freqs":
            m = _FREQ.match(stripped)
            if m and "disabled" not in m.group(3):
                info.freqs_mhz.append(float(m.group(1)))
            continue
        if stripped.startswith("HT20") or stripped.startswith("HT Max RX") or "HT TX/RX MCS" in stripped:
            info.ht = True
        elif stripped.startswith("VHT Capabilities"):
            info.vht = True
        elif stripped.startswith("HE Iftypes") or stripped.startswith("HE PHY Capabilities"):
            info.he = True
        elif stripped.startswith("EHT Iftypes") or stripped.startswith("EHT PHY Capabilities"):
            info.eht = True
    return info
