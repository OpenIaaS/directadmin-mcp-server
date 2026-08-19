"""DirectAdmin Brute Force Monitor — native panel IP blocks (not CSF)."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_legacy
from mcp_instance import mcp
from security import validate_ip
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def bfm_list(blocked_only: bool = True) -> Dict[str, Any]:
    """List Brute Force Monitor state (blocked IPs, failed logins).

    Args:
        blocked_only: Hint for the client; the panel still returns the full JSON.
    """
    data = await call_da_legacy(
        "CMD_API_BRUTE_FORCE_MONITOR", method="GET", data={"json": "yes"}
    )
    return format_response({"blocked_only": blocked_only, "result": data})


@mcp.tool()
@log_tool_call
async def bfm_unblock_ip(ip: str, confirm: bool = False) -> Dict[str, Any]:
    """Remove an IP from DirectAdmin Brute Force Monitor blocks.

    Use together with csf_unblock_ip — an IP is often listed in BOTH places.

    Args:
        ip: IPv4 or IPv6 to unblock.
        confirm: Required.
    """
    rejected = guard_confirm("bfm_unblock_ip", confirm)
    if rejected:
        return rejected
    address = validate_ip(ip)
    attempts = []
    # Newer JSON-ish shape
    for payload in (
        {"action": "unblock", "ip": address, "json": "yes"},
        {"action": "remove", "ip": address, "json": "yes"},
        {"unblock": "yes", "select0": address, "json": "yes"},
    ):
        try:
            result = await call_da_legacy(
                "CMD_API_BRUTE_FORCE_MONITOR", method="POST", data=payload
            )
            attempts.append({"payload": {k: v for k, v in payload.items() if k != "json"}, "result": result})
            break
        except Exception as exc:  # try the next encoding
            attempts.append({"payload": payload, "error": str(exc)})
    return format_response({"ip": address, "attempts": attempts})


@mcp.tool()
@log_tool_call
async def bfm_skip_ip(ip: str, confirm: bool = False) -> Dict[str, Any]:
    """Add an IP to the BFM skip / never-block list.

    Args:
        ip: Address to skip.
        confirm: Required.
    """
    rejected = guard_confirm("bfm_skip_ip", confirm)
    if rejected:
        return rejected
    address = validate_ip(ip)
    data = await call_da_legacy(
        "CMD_API_BRUTE_FORCE_MONITOR",
        method="POST",
        data={"action": "skip", "ip": address, "json": "yes"},
    )
    return format_response(data)


@mcp.tool()
@log_tool_call
async def firewall_unblock_everywhere(
    ip: str,
    also_allow: bool = False,
    confirm: bool = False,
) -> Dict[str, Any]:
    """Unblock an IP in CSF *and* DirectAdmin Brute Force Monitor.

    This is the 'customer is locked out' button. It does not disable the firewall.

    Args:
        ip: IPv4 or IPv6.
        also_allow: Also add a temporary CSF allow (1 hour).
        confirm: Required.
    """
    rejected = guard_confirm("firewall_unblock_everywhere", confirm)
    if rejected:
        return rejected
    from tools.csf_firewall import csf_unblock_ip

    csf = await csf_unblock_ip(
        ip=ip, also_allow=also_allow, confirm=True  # already confirmed here
    )
    bfm = await bfm_unblock_ip(ip=ip, confirm=True)
    return format_response({"ip": ip, "csf": csf, "bfm": bfm})
