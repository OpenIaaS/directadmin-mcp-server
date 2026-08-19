"""Systemd-style service control through DirectAdmin."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_api, client
from mcp_instance import mcp
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def services_list() -> Dict[str, Any]:
    """List managed services (httpd, exim, dovecot, named, …)."""
    return format_response(await call_da_api("/api/system-services/list"))


@mcp.tool()
@log_tool_call
async def services_get(service: str) -> Dict[str, Any]:
    """Details for one service.

    Args:
        service: Service name (e.g. httpd, exim, dovecot, named, proftpd).
    """
    return format_response(await call_da_api(f"/api/system-services/service/{service}"))


@mcp.tool()
@log_tool_call
async def services_logs(
    service: str,
    cursor: str = "",
    limit: int = 200,
    level: str = "",
) -> Dict[str, Any]:
    """Read a service log.

    Args:
        service: Service name.
        cursor: Pagination cursor from a previous response.
        limit: Max lines.
        level: Optional log level filter.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    if level:
        params["level"] = level
    data = await client.request(
        f"/api/system-services/service/{service}/log", method="GET", params=params
    )
    return format_response(data)


@mcp.tool()
@log_tool_call
async def services_start(service: str, confirm: bool = False) -> Dict[str, Any]:
    """Start a service.

    Args:
        service: Service name.
        confirm: Required.
    """
    rejected = guard_confirm("services_start", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(f"/api/system-services-actions/service/{service}/start", method="POST")
    )


@mcp.tool()
@log_tool_call
async def services_stop(service: str, confirm: bool = False) -> Dict[str, Any]:
    """Stop a service.

    Args:
        service: Service name.
        confirm: Required.
    """
    rejected = guard_confirm("services_stop", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(f"/api/system-services-actions/service/{service}/stop", method="POST")
    )


@mcp.tool()
@log_tool_call
async def services_restart(service: str, confirm: bool = False) -> Dict[str, Any]:
    """Restart a service.

    Args:
        service: Service name.
        confirm: Required.
    """
    rejected = guard_confirm("services_restart", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(f"/api/system-services-actions/service/{service}/restart", method="POST")
    )


@mcp.tool()
@log_tool_call
async def services_reload(service: str, confirm: bool = False) -> Dict[str, Any]:
    """Reload a service configuration.

    Args:
        service: Service name.
        confirm: Required.
    """
    rejected = guard_confirm("services_reload", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(f"/api/system-services-actions/service/{service}/reload", method="POST")
    )


@mcp.tool()
@log_tool_call
async def services_watchdog(service: str, enabled: bool, confirm: bool = False) -> Dict[str, Any]:
    """Toggle the service watchdog.

    Args:
        service: Service name.
        enabled: True to watch, False to stop watching.
        confirm: Required.
    """
    rejected = guard_confirm("services_watchdog", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(
            f"/api/system-services-actions/service/{service}/watchdog",
            method="PUT",
            data={"enabled": enabled},
        )
    )
