# SPDX-License-Identifier: GPL-3.0-only
"""The complete set of things the root helper will do. Adding an action = security review.

Every action is a strict Pydantic model: unknown fields are rejected, every string is pattern-bound,
nothing is a path or a command. Interfaces are named by MAC address and resolved by the helper
itself at call time, so a caller can't smuggle an arbitrary name through.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

MacAddr = Annotated[str, StringConstraints(to_lower=True, pattern=r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")]
CountryCode = Annotated[str, StringConstraints(to_upper=True, pattern=r"^([A-Za-z]{2}|00)$")]


class _Action(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Ping(_Action):
    action: Literal["ping"] = "ping"


class SetNmUnmanaged(_Action):
    """Replace the set of MACs NetworkManager must leave alone (test-plane interfaces)."""

    action: Literal["nm.set_unmanaged"] = "nm.set_unmanaged"
    macs: list[MacAddr] = Field(max_length=32)


class MoveToTestNs(_Action):
    """Move a wired link, or a Wi-Fi radio's whole phy, from the root namespace into the test netns."""

    action: Literal["plane.move_in"] = "plane.move_in"
    mac: MacAddr


class ReleaseFromTestNs(_Action):
    """Move a link/phy from the test netns back to the root namespace."""

    action: Literal["plane.move_out"] = "plane.move_out"
    mac: MacAddr


class SetRegdomain(_Action):
    action: Literal["wifi.set_regdomain"] = "wifi.set_regdomain"
    country: CountryCode


Action = Annotated[
    Ping | SetNmUnmanaged | MoveToTestNs | ReleaseFromTestNs | SetRegdomain,
    Field(discriminator="action"),
]
ACTIONS: tuple[type[_Action], ...] = (Ping, SetNmUnmanaged, MoveToTestNs, ReleaseFromTestNs, SetRegdomain)
