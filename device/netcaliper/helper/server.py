# SPDX-License-Identifier: GPL-3.0-only
"""Helper daemon: validate → dispatch to Ops → log. Runs as root under netcaliper-helper.service."""

from __future__ import annotations

import logging
import pwd
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter, ValidationError

from ..core.rpc import Handler, Peer, RpcError, RpcServer
from .actions import (
    ACTIONS,
    Action,
    MoveToTestNs,
    Ping,
    ReleaseFromTestNs,
    SetNmUnmanaged,
    SetRegdomain,
)
from .ops import OpError, Ops

log = logging.getLogger("netcaliper.helper")
_adapter: TypeAdapter[Action] = TypeAdapter(Action)


async def execute(ops: Ops, action: Action) -> Any:
    match action:
        case Ping():
            return await ops.ping()
        case SetNmUnmanaged(macs=macs):
            return await ops.set_nm_unmanaged(list(macs))
        case MoveToTestNs(mac=mac):
            return await ops.move_in(mac)
        case ReleaseFromTestNs(mac=mac):
            return await ops.move_out(mac)
        case SetRegdomain(country=cc):
            return await ops.set_regdomain(cc)
    raise RpcError("unknown_action", type(action).__name__)  # pragma: no cover - exhaustive


def make_handlers(ops: Ops) -> dict[str, Handler]:
    def handler_for(name: str) -> Handler:
        async def handle(params: dict[str, Any], peer: Peer) -> Any:
            try:
                action = _adapter.validate_python({**params, "action": name})
            except ValidationError as e:
                log.warning("invalid %s from %r: %s", name, peer, e.errors(include_url=False))
                raise RpcError("invalid", "; ".join(str(err["msg"]) for err in e.errors())) from e
            log.info("%s by %r: %s", name, peer, action.model_dump(exclude={"action"}))
            try:
                result = await execute(ops, action)
            except OpError as e:
                log.warning("%s failed: %s", name, e)
                raise RpcError(e.code, e.message) from e
            log.info("%s ok: %s", name, result)
            return result

        return handle

    return {
        str(a.model_fields["action"].default): handler_for(str(a.model_fields["action"].default))
        for a in ACTIONS
    }


def allowed_uids(service_user: str) -> set[int]:
    uids = {0}
    try:
        uids.add(pwd.getpwnam(service_user).pw_uid)
    except KeyError:
        log.warning("service user %r not found; only root may call the helper", service_user)
    return uids


def build_server(ops: Ops, socket_path: Path, service_user: str = "netcaliper") -> RpcServer:
    gid = None
    try:
        gid = pwd.getpwnam(service_user).pw_gid
    except KeyError:
        pass
    return RpcServer(
        socket_path,
        make_handlers(ops),
        allowed_uids(service_user),
        mode=0o660,
        gid=gid,
        public_methods=frozenset({"ping"}),
    )
