"""CustomBuild 2 — software, options, compile, logs, updates."""

from __future__ import annotations

from typing import Any, Dict, Optional

from da import call_da_api
from mcp_instance import mcp
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def cb_state() -> Dict[str, Any]:
    """CustomBuild current state."""
    return format_response(await call_da_api("/api/custombuild/state"))


@mcp.tool()
@log_tool_call
async def cb_software() -> Dict[str, Any]:
    """Installed / available software."""
    return format_response(await call_da_api("/api/custombuild/software"))


@mcp.tool()
@log_tool_call
async def cb_versions() -> Dict[str, Any]:
    """Component versions."""
    return format_response(await call_da_api("/api/custombuild/versions"))


@mcp.tool()
@log_tool_call
async def cb_updates() -> Dict[str, Any]:
    """Available CustomBuild updates."""
    return format_response(await call_da_api("/api/custombuild/updates"))


@mcp.tool()
@log_tool_call
async def cb_options() -> Dict[str, Any]:
    """CustomBuild options (options.conf)."""
    return format_response(await call_da_api("/api/custombuild/options"))


@mcp.tool()
@log_tool_call
async def cb_options_update(values: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Patch CustomBuild options.

    Args:
        values: Options object.
        confirm: Required.
    """
    rejected = guard_confirm("cb_options_update", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/custombuild/options", method="PATCH", data=values))


@mcp.tool()
@log_tool_call
async def cb_run(payload: Optional[Dict[str, Any]] = None, confirm: bool = False) -> Dict[str, Any]:
    """Start a CustomBuild run (build / update / rewrite).

    Args:
        payload: Run arguments (action, software, …).
        confirm: Required.
    """
    rejected = guard_confirm("cb_run", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/custombuild/run", method="POST", data=payload or {}))


@mcp.tool()
@log_tool_call
async def cb_kill(confirm: bool = False) -> Dict[str, Any]:
    """Kill a running CustomBuild job.

    Args:
        confirm: Required.
    """
    rejected = guard_confirm("cb_kill", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/custombuild/kill", method="POST"))


@mcp.tool()
@log_tool_call
async def cb_logs() -> Dict[str, Any]:
    """CustomBuild log names."""
    return format_response(await call_da_api("/api/custombuild/logs"))


@mcp.tool()
@log_tool_call
async def cb_actions() -> Dict[str, Any]:
    """Available CustomBuild actions."""
    return format_response(await call_da_api("/api/custombuild/actions"))


@mcp.tool()
@log_tool_call
async def cb_removals() -> Dict[str, Any]:
    """Software CustomBuild can remove."""
    return format_response(await call_da_api("/api/custombuild/removals"))
