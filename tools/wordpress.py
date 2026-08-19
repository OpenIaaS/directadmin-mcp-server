"""WordPress manager."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_api
from mcp_instance import mcp
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def wp_locations() -> Dict[str, Any]:
    """List WordPress installations."""
    return format_response(await call_da_api("/api/wordpress/locations"))


@mcp.tool()
@log_tool_call
async def wp_install(payload: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Install WordPress.

    Args:
        payload: Install body (domain, path, title, admin user, …).
        confirm: Required.
    """
    rejected = guard_confirm("wp_install", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/wordpress/install", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def wp_install_quick(payload: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Quick WordPress install.

    Args:
        payload: Quick-install body.
        confirm: Required.
    """
    rejected = guard_confirm("wp_install_quick", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api("/api/wordpress/install-quick", method="POST", data=payload)
    )


@mcp.tool()
@log_tool_call
async def wp_get(location_id: str) -> Dict[str, Any]:
    """WordPress instance details.

    Args:
        location_id: Location id.
    """
    return format_response(await call_da_api(f"/api/wordpress/locations/{location_id}/wordpress"))


@mcp.tool()
@log_tool_call
async def wp_delete(location_id: str, confirm: bool = False) -> Dict[str, Any]:
    """Remove a WordPress location from the manager.

    Args:
        location_id: Location id.
        confirm: Required.
    """
    rejected = guard_confirm("wp_delete", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api(f"/api/wordpress/locations/{location_id}", method="DELETE"))
