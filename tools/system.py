"""Version, license, system info, package updates, restart."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from da import call_da_api
from mcp_instance import mcp
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def system_info() -> Dict[str, Any]:
    """High-level panel info (/api/info)."""
    return format_response(await call_da_api("/api/info"))


@mcp.tool()
@log_tool_call
async def system_version() -> Dict[str, Any]:
    """DirectAdmin version and update channel."""
    return format_response(await call_da_api("/api/version"))


@mcp.tool()
@log_tool_call
async def system_set_update_channel(channel: str, confirm: bool = False) -> Dict[str, Any]:
    """Change the DirectAdmin update channel.

    Args:
        channel: current | stable | beta | alpha (panel-dependent).
        confirm: Required.
    """
    rejected = guard_confirm("system_set_update_channel", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/version", method="PATCH", data={"channel": channel}))


@mcp.tool()
@log_tool_call
async def system_update_directadmin(confirm: bool = False) -> Dict[str, Any]:
    """Update DirectAdmin itself to the latest build on the current channel.

    Args:
        confirm: Required.
    """
    rejected = guard_confirm("system_update_directadmin", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/version/update", method="POST"))


@mcp.tool()
@log_tool_call
async def system_restart_directadmin(confirm: bool = False) -> Dict[str, Any]:
    """Restart the DirectAdmin service.

    Args:
        confirm: Required.
    """
    rejected = guard_confirm("system_restart_directadmin", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/restart", method="POST"))


@mcp.tool()
@log_tool_call
async def system_cpu() -> Dict[str, Any]:
    """CPU information."""
    return format_response(await call_da_api("/api/system-info/cpu"))


@mcp.tool()
@log_tool_call
async def system_memory() -> Dict[str, Any]:
    """Memory information."""
    return format_response(await call_da_api("/api/system-info/memory"))


@mcp.tool()
@log_tool_call
async def system_load() -> Dict[str, Any]:
    """1/5/10 minute load averages."""
    return format_response(await call_da_api("/api/system-info/load"))


@mcp.tool()
@log_tool_call
async def system_disk() -> Dict[str, Any]:
    """Filesystem usage."""
    return format_response(await call_da_api("/api/system-info/fs"))


@mcp.tool()
@log_tool_call
async def system_uptime() -> Dict[str, Any]:
    """Host uptime."""
    return format_response(await call_da_api("/api/system-info/uptime"))


@mcp.tool()
@log_tool_call
async def system_services_overview() -> Dict[str, Any]:
    """Services occupancy snapshot (not the systemd list)."""
    return format_response(await call_da_api("/api/system-info/services"))


@mcp.tool()
@log_tool_call
async def system_resource_usage_latest() -> Dict[str, Any]:
    """Latest per-user resource usage snapshot."""
    return format_response(await call_da_api("/api/resource-usage/latest"))


@mcp.tool()
@log_tool_call
async def system_resource_usage_history() -> Dict[str, Any]:
    """Historical resource usage."""
    return format_response(await call_da_api("/api/resource-usage/history"))


@mcp.tool()
@log_tool_call
async def system_global_usage_latest() -> Dict[str, Any]:
    """Latest global resource usage."""
    return format_response(await call_da_api("/api/global-resource-usage/latest"))


@mcp.tool()
@log_tool_call
async def system_global_usage_history(user: str) -> Dict[str, Any]:
    """Global resource usage history for one user.

    Args:
        user: Username.
    """
    return format_response(await call_da_api(f"/api/global-resource-usage/history/{user}"))


@mcp.tool()
@log_tool_call
async def system_packages_updates() -> Dict[str, Any]:
    """Available OS package upgrades."""
    return format_response(await call_da_api("/api/system-packages/updates"))


@mcp.tool()
@log_tool_call
async def system_packages_update_test(packages: Optional[List[str]] = None) -> Dict[str, Any]:
    """Dry-run OS package upgrade.

    Args:
        packages: Optional package name list. Empty = all pending.
    """
    return format_response(
        await call_da_api(
            "/api/system-packages/update-test",
            method="POST",
            data={"packages": packages or []},
        )
    )


@mcp.tool()
@log_tool_call
async def system_packages_update_run(
    packages: Optional[List[str]] = None, confirm: bool = False
) -> Dict[str, Any]:
    """Apply OS package upgrades.

    Args:
        packages: Optional package name list. Empty = all pending.
        confirm: Required.
    """
    rejected = guard_confirm("system_packages_update_run", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(
            "/api/system-packages/update-run",
            method="POST",
            data={"packages": packages or []},
        )
    )


@mcp.tool()
@log_tool_call
async def system_packages_history() -> Dict[str, Any]:
    """History of OS package upgrade tasks."""
    return format_response(await call_da_api("/api/system-packages/history"))


@mcp.tool()
@log_tool_call
async def license_get() -> Dict[str, Any]:
    """DirectAdmin license details."""
    return format_response(await call_da_api("/api/license"))


@mcp.tool()
@log_tool_call
async def license_proof() -> Dict[str, Any]:
    """License proof document."""
    return format_response(await call_da_api("/api/license/proof"))


@mcp.tool()
@log_tool_call
async def license_update_key(key: str, confirm: bool = False) -> Dict[str, Any]:
    """Install a new license key.

    Args:
        key: License key.
        confirm: Required.
    """
    rejected = guard_confirm("license_update_key", confirm, extra=True)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/license/update-key", method="POST", data={"key": key}))


@mcp.tool()
@log_tool_call
async def maintenance_list() -> Dict[str, Any]:
    """Maintenance tasks / health checks the panel exposes."""
    return format_response(await call_da_api("/api/maintenance"))


@mcp.tool()
@log_tool_call
async def maintenance_check(task: str) -> Dict[str, Any]:
    """Run a maintenance check.

    Args:
        task: Task id from maintenance_list.
    """
    return format_response(await call_da_api(f"/api/maintenance/{task}/check", method="POST"))


@mcp.tool()
@log_tool_call
async def maintenance_fix(task: str, confirm: bool = False) -> Dict[str, Any]:
    """Apply a maintenance fix.

    Args:
        task: Task id.
        confirm: Required.
    """
    rejected = guard_confirm("maintenance_fix", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api(f"/api/maintenance/{task}/fix", method="POST"))
