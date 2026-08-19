"""Plugin manager + plugin list."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_api
from mcp_instance import mcp
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def plugins_list() -> Dict[str, Any]:
    """Installed plugins (user-facing list)."""
    return format_response(await call_da_api("/api/plugins/list"))


@mcp.tool()
@log_tool_call
async def plugins_manager_list() -> Dict[str, Any]:
    """Plugin manager inventory (admin)."""
    return format_response(await call_da_api("/api/plugin-manager/plugins"))


@mcp.tool()
@log_tool_call
async def plugins_install_url(url: str, confirm: bool = False) -> Dict[str, Any]:
    """Install a plugin from a URL.

    Args:
        url: https URL to a .tar.gz plugin.
        confirm: Required.
    """
    rejected = guard_confirm("plugins_install_url", confirm)
    if rejected:
        return rejected
    if not url.startswith("https://"):
        from tools.common import format_error

        return format_error("Plugin URLs must be https://")
    return format_response(
        await call_da_api("/api/plugin-manager/plugins/install-url", method="POST", data={"url": url})
    )


@mcp.tool()
@log_tool_call
async def plugins_activate(plugin_id: str, confirm: bool = False) -> Dict[str, Any]:
    """Activate a plugin.

    Args:
        plugin_id: Plugin id.
        confirm: Required.
    """
    rejected = guard_confirm("plugins_activate", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(f"/api/plugin-manager/plugins/{plugin_id}/activate", method="POST", data={})
    )


@mcp.tool()
@log_tool_call
async def plugins_deactivate(plugin_id: str, confirm: bool = False) -> Dict[str, Any]:
    """Deactivate a plugin.

    Args:
        plugin_id: Plugin id.
        confirm: Required.
    """
    rejected = guard_confirm("plugins_deactivate", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(f"/api/plugin-manager/plugins/{plugin_id}/deactivate", method="POST", data={})
    )


@mcp.tool()
@log_tool_call
async def plugins_update(plugin_id: str, confirm: bool = False) -> Dict[str, Any]:
    """Update a plugin from its update_url.

    Args:
        plugin_id: Plugin id.
        confirm: Required.
    """
    rejected = guard_confirm("plugins_update", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(f"/api/plugin-manager/plugins/{plugin_id}/update", method="POST", data={})
    )


@mcp.tool()
@log_tool_call
async def plugins_delete(plugin_id: str, confirm: bool = False) -> Dict[str, Any]:
    """Uninstall a plugin.

    Args:
        plugin_id: Plugin id.
        confirm: Required.
    """
    rejected = guard_confirm("plugins_delete", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(f"/api/plugin-manager/plugins/{plugin_id}/delete", method="POST", data={})
    )
