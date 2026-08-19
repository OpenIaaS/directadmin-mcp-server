"""CloudLinux (LVE / CageFS / PHP Selector) via the DirectAdmin plugin.

CloudLinux is not part of the DirectAdmin New API. The admin UI is the
LVE Manager / CloudLinux Manager plugin. These tools talk to that plugin
the same way CSF tools talk to ConfigServer — they never spawn a shell
and they never use /api/execute.

Writes (set limits, enable/disable CageFS) require confirm=true.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from config import settings
from da import DirectAdminError, client
from mcp_instance import mcp
from security import validate_username
from tools.common import format_error, format_response, guard_confirm, log_tool_call

PLUGIN_PATHS = (
    "/CMD_PLUGINS_ADMIN/lve-manager/index.raw",
    "/CMD_PLUGINS_ADMIN/lve-manager/index.html",
    "/CMD_PLUGINS_ADMIN/cloudlinux/index.raw",
    "/CMD_PLUGINS_ADMIN/lvemanager/index.raw",
    "/CMD_PLUGINS/lve-manager/index.raw",
)

_LIMIT = re.compile(r"^(unlimited|\d+%?)$", re.IGNORECASE)


def _require() -> Optional[Dict[str, Any]]:
    if not settings.ENABLE_CLOUDLINUX:
        return format_error(
            "CloudLinux tools are disabled (ENABLE_CLOUDLINUX=false). "
            "Turn them on only on CloudLinux hosts with LVE Manager installed."
        )
    return None


def _as_text(payload: Any) -> str:
    if payload is None:
        return ""
    if isinstance(payload, (bytes, bytearray)):
        return payload.decode("utf-8", errors="replace")
    if isinstance(payload, str):
        return payload
    return str(payload)


def _limit(name: str, value: str) -> Optional[str]:
    if value is None or value == "":
        return None
    cleaned = str(value).strip()
    if not _LIMIT.fullmatch(cleaned):
        raise ValueError(f"Invalid {name} limit (use a number, percent, or 'unlimited')")
    return cleaned


async def _plugin(action: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"action": action, "json": "yes"}
    if extra:
        payload.update({k: v for k, v in extra.items() if v is not None})

    last_error: Optional[Exception] = None
    for path in PLUGIN_PATHS:
        try:
            result = await client.call_plugin(path, data=payload, method="POST")
            text = _as_text(result).lower()
            if isinstance(result, dict) and result:
                return {"path": path, "action": action, "result": result}
            if "lve" in text or "cagefs" in text or "cloudlinux" in text:
                return {"path": path, "action": action, "result": result}
        except DirectAdminError as exc:
            last_error = exc
            continue
    raise DirectAdminError(
        "CloudLinux LVE Manager plugin did not respond. "
        "Install `lvemanager` and open Admin → Extra Features → CloudLinux Manager once.",
        response_data=str(last_error) if last_error else None,
    )


@mcp.tool()
@log_tool_call
async def cl_status() -> Dict[str, Any]:
    """Detect CloudLinux / LVE Manager on this box.

    Reads the plugin list and pings LVE Manager. Does not change anything.
    """
    blocked = _require()
    if blocked:
        return blocked
    plugins = None
    try:
        from da import call_da_api

        plugins = await call_da_api("/api/plugins/list")
    except DirectAdminError:
        plugins = None
    try:
        ping = await _plugin("users")
        available = True
    except DirectAdminError as exc:
        ping = {"error": str(exc)}
        available = False
    return format_response(
        {
            "cloudlinux_tools": True,
            "plugin_reachable": available,
            "plugins": plugins,
            "probe": ping if available else ping,
        }
    )


@mcp.tool()
@log_tool_call
async def cl_lve_users() -> Dict[str, Any]:
    """List LVE users / current limits (LVE Manager `action=users`)."""
    blocked = _require()
    if blocked:
        return blocked
    return format_response(await _plugin("users"))


@mcp.tool()
@log_tool_call
async def cl_lve_get(username: str) -> Dict[str, Any]:
    """LVE limits for one user.

    Args:
        username: DirectAdmin account.
    """
    blocked = _require()
    if blocked:
        return blocked
    username = validate_username(username)
    return format_response(await _plugin("user", {"username": username, "user": username}))


@mcp.tool()
@log_tool_call
async def cl_lve_set(
    username: str,
    speed: str = "",
    pmem: str = "",
    io: str = "",
    nproc: str = "",
    ep: str = "",
    iops: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Set LVE limits for one user (CPU/RAM/IO/processes).

    Only numeric values, percents, or 'unlimited'. This is the CloudLinux
    equivalent of Pro Pack cgroups throttle.

    Args:
        username: Account.
        speed: CPU (e.g. 100% or 200).
        pmem: Physical memory (e.g. 1024 or 1G-style numbers the plugin accepts as digits).
        io: Disk IO.
        nproc: Max processes.
        ep: Entry processes.
        iops: IOPS.
        confirm: Required.
    """
    blocked = _require()
    if blocked:
        return blocked
    rejected = guard_confirm("cl_lve_set", confirm)
    if rejected:
        return rejected
    username = validate_username(username)
    try:
        extra = {
            "username": username,
            "user": username,
            "SPEED": _limit("speed", speed),
            "PMEM": _limit("pmem", pmem),
            "IO": _limit("io", io),
            "NPROC": _limit("nproc", nproc),
            "EP": _limit("ep", ep),
            "IOPS": _limit("iops", iops),
        }
    except ValueError as exc:
        return format_error(str(exc))
    extra = {k: v for k, v in extra.items() if v is not None}
    return format_response(await _plugin("setlimits", extra))


@mcp.tool()
@log_tool_call
async def cl_cagefs_enable(username: str, confirm: bool = False) -> Dict[str, Any]:
    """Enable CageFS for one user.

    Args:
        username: Account.
        confirm: Required.
    """
    blocked = _require()
    if blocked:
        return blocked
    rejected = guard_confirm("cl_cagefs_enable", confirm)
    if rejected:
        return rejected
    username = validate_username(username)
    return format_response(
        await _plugin("cagefs", {"username": username, "user": username, "cagefs": "enable"})
    )


@mcp.tool()
@log_tool_call
async def cl_cagefs_disable(username: str, confirm: bool = False) -> Dict[str, Any]:
    """Disable CageFS for one user. The account leaves the cage.

    Args:
        username: Account.
        confirm: Required.
    """
    blocked = _require()
    if blocked:
        return blocked
    rejected = guard_confirm("cl_cagefs_disable", confirm)
    if rejected:
        return rejected
    username = validate_username(username)
    return format_response(
        await _plugin("cagefs", {"username": username, "user": username, "cagefs": "disable"})
    )


@mcp.tool()
@log_tool_call
async def cl_php_selector_get(username: str) -> Dict[str, Any]:
    """Read CloudLinux PHP Selector for a user (plugin).

    On non-CL boxes use domains_set_php (DirectAdmin PHP selector) instead.

    Args:
        username: Account.
    """
    blocked = _require()
    if blocked:
        return blocked
    username = validate_username(username)
    return format_response(
        await _plugin("phpselector", {"username": username, "user": username})
    )


@mcp.tool()
@log_tool_call
async def cl_php_selector_set(
    username: str,
    version: str,
    confirm: bool = False,
) -> Dict[str, Any]:
    """Set CloudLinux PHP Selector version for a user.

    Args:
        username: Account.
        version: alt-php version the plugin understands (e.g. 8.2, 8.3, native).
        confirm: Required.
    """
    blocked = _require()
    if blocked:
        return blocked
    rejected = guard_confirm("cl_php_selector_set", confirm)
    if rejected:
        return rejected
    username = validate_username(username)
    cleaned = version.strip()
    if not re.fullmatch(r"(native|[0-9]{1,2}(\.[0-9]{1,2})?)", cleaned):
        return format_error("PHP version must look like 8.2, 8.3 or native")
    return format_response(
        await _plugin(
            "phpselector",
            {"username": username, "user": username, "version": cleaned, "phpversion": cleaned},
        )
    )
