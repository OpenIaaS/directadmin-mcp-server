"""Hostname, directadmin.conf, timezone, email server settings, DB config."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_api
from mcp_instance import mcp
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def hostname_change(hostname: str, confirm: bool = False) -> Dict[str, Any]:
    """Change the server hostname.

    Args:
        hostname: New FQDN.
        confirm: Required. Reissue the hostname SSL afterwards with ssl_reissue_server.
    """
    rejected = guard_confirm("hostname_change", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(
            "/api/server-settings/change-hostname", method="POST", data={"hostname": hostname}
        )
    )


@mcp.tool()
@log_tool_call
async def da_config_active() -> Dict[str, Any]:
    """Currently applied directadmin.conf (merged)."""
    return format_response(await call_da_api("/api/server-settings/directadmin-conf/active"))


@mcp.tool()
@log_tool_call
async def da_config_default() -> Dict[str, Any]:
    """Default directadmin.conf values."""
    return format_response(await call_da_api("/api/server-settings/directadmin-conf/default"))


@mcp.tool()
@log_tool_call
async def da_config_local() -> Dict[str, Any]:
    """Local overrides in directadmin.conf."""
    return format_response(await call_da_api("/api/server-settings/directadmin-conf/local"))


@mcp.tool()
@log_tool_call
async def da_config_local_update(values: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Replace local directadmin.conf overrides (PUT).

    Args:
        values: Full local config object as the panel expects.
        confirm: Required.
    """
    rejected = guard_confirm("da_config_local_update", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api("/api/server-settings/directadmin-conf/local", method="PUT", data=values)
    )


@mcp.tool()
@log_tool_call
async def da_config_local_patch(values: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Patch selected directadmin.conf keys.

    Args:
        values: Partial local config.
        confirm: Required.
    """
    rejected = guard_confirm("da_config_local_patch", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api("/api/server-settings/directadmin-conf/local", method="PATCH", data=values)
    )


@mcp.tool()
@log_tool_call
async def timezone_current() -> Dict[str, Any]:
    """Current server timezone."""
    return format_response(await call_da_api("/api/server-settings/timezone/current"))


@mcp.tool()
@log_tool_call
async def timezone_list() -> Dict[str, Any]:
    """Available timezones."""
    return format_response(await call_da_api("/api/server-settings/timezone/list"))


@mcp.tool()
@log_tool_call
async def timezone_set(timezone: str, confirm: bool = False) -> Dict[str, Any]:
    """Set server timezone.

    Args:
        timezone: IANA name, e.g. Europe/Sofia.
        confirm: Required.
    """
    rejected = guard_confirm("timezone_set", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api("/api/server-settings/timezone/set", method="POST", data={"timezone": timezone})
    )


@mcp.tool()
@log_tool_call
async def email_server_config() -> Dict[str, Any]:
    """Global email / exim configuration."""
    return format_response(await call_da_api("/api/server-settings/email/config"))


@mcp.tool()
@log_tool_call
async def email_server_config_update(values: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Update global email configuration.

    Args:
        values: Config object.
        confirm: Required.
    """
    rejected = guard_confirm("email_server_config_update", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api("/api/server-settings/email/config", method="PUT", data=values)
    )


@mcp.tool()
@log_tool_call
async def email_outbound_filter() -> Dict[str, Any]:
    """Outbound email filter settings."""
    return format_response(await call_da_api("/api/server-settings/email/outbound-filter"))


@mcp.tool()
@log_tool_call
async def email_outbound_filter_update(
    values: Dict[str, Any], confirm: bool = False
) -> Dict[str, Any]:
    """Update outbound email filter.

    Args:
        values: Filter object.
        confirm: Required.
    """
    rejected = guard_confirm("email_outbound_filter_update", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api("/api/server-settings/email/outbound-filter", method="PUT", data=values)
    )


@mcp.tool()
@log_tool_call
async def db_server_config() -> Dict[str, Any]:
    """SQL server connection settings used by the panel."""
    return format_response(await call_da_api("/api/server-settings/db-config"))


@mcp.tool()
@log_tool_call
async def db_server_config_update(values: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Update SQL server settings.

    Args:
        values: Config object.
        confirm: Required.
    """
    rejected = guard_confirm("db_server_config_update", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api("/api/server-settings/db-config", method="PUT", data=values)
    )


@mcp.tool()
@log_tool_call
async def db_server_config_test() -> Dict[str, Any]:
    """Test the configured SQL connection."""
    return format_response(await call_da_api("/api/server-settings/db-config-test", method="POST"))
