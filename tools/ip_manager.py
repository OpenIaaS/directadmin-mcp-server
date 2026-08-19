"""IP manager via legacy admin API."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_legacy
from mcp_instance import mcp
from security import validate_ip, validate_username
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def ips_list() -> Dict[str, Any]:
    """List IPs visible to this reseller/admin."""
    return format_response(await call_da_legacy("CMD_API_SHOW_RESELLER_IPS", method="GET"))


@mcp.tool()
@log_tool_call
async def ips_get(ip: str) -> Dict[str, Any]:
    """Details for one IP.

    Args:
        ip: Address.
    """
    address = validate_ip(ip)
    return format_response(
        await call_da_legacy("CMD_API_SHOW_RESELLER_IPS", method="GET", data={"ip": address})
    )


@mcp.tool()
@log_tool_call
async def ips_admin_list() -> Dict[str, Any]:
    """Admin-level IP list (CMD_API_IP_MANAGER)."""
    return format_response(await call_da_legacy("CMD_API_IP_MANAGER", method="GET"))


@mcp.tool()
@log_tool_call
async def ips_add(ip: str, netmask: str = "255.255.255.0", confirm: bool = False) -> Dict[str, Any]:
    """Add an IP to the admin IP manager.

    Args:
        ip: Address to add.
        netmask: Netmask (IPv4) or prefix hint.
        confirm: Required.
    """
    rejected = guard_confirm("ips_add", confirm)
    if rejected:
        return rejected
    address = validate_ip(ip)
    payload = {"action": "add", "ip": address, "netmask": netmask}
    return format_response(await call_da_legacy("CMD_API_IP_MANAGER", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def ips_remove(ip: str, confirm: bool = False) -> Dict[str, Any]:
    """Remove an IP from the admin IP manager.

    Args:
        ip: Address to remove.
        confirm: Required.
    """
    rejected = guard_confirm("ips_remove", confirm)
    if rejected:
        return rejected
    address = validate_ip(ip)
    payload = {"action": "select", "delete": "yes", "select0": address}
    return format_response(await call_da_legacy("CMD_API_IP_MANAGER", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def ips_assign(ip: str, username: str, confirm: bool = False) -> Dict[str, Any]:
    """Assign an IP to a reseller/user.

    Args:
        ip: Address.
        username: Destination account.
        confirm: Required.
    """
    rejected = guard_confirm("ips_assign", confirm)
    if rejected:
        return rejected
    address = validate_ip(ip)
    payload = {"action": "assign", "ip": address, "user": validate_username(username)}
    return format_response(await call_da_legacy("CMD_API_IP_MANAGER", method="POST", data=payload))
