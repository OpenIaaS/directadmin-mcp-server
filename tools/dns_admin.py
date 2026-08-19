"""DNS admin via legacy CMD_API_DNS_ADMIN / CMD_API_DNS_CONTROL."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_legacy
from mcp_instance import mcp
from security import validate_domain
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def dns_admin_list() -> Dict[str, Any]:
    """List DNS zones (admin)."""
    return format_response(await call_da_legacy("CMD_API_DNS_ADMIN", method="GET"))


@mcp.tool()
@log_tool_call
async def dns_zone_get(domain: str) -> Dict[str, Any]:
    """Get records for a zone.

    Args:
        domain: Zone name.
    """
    domain = validate_domain(domain)
    return format_response(
        await call_da_legacy("CMD_API_DNS_CONTROL", method="GET", data={"domain": domain})
    )


@mcp.tool()
@log_tool_call
async def dns_record_add(
    domain: str,
    record_type: str,
    name: str,
    value: str,
    ttl: int = 14400,
    confirm: bool = False,
) -> Dict[str, Any]:
    """Add a DNS record.

    Args:
        domain: Zone.
        record_type: A | AAAA | CNAME | MX | TXT | NS | SRV | CAA …
        name: Record name (use @ or the domain for the apex).
        value: Record value.
        ttl: TTL seconds.
        confirm: Required.
    """
    rejected = guard_confirm("dns_record_add", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    payload = {
        "domain": domain,
        "action": "add",
        "type": record_type.upper(),
        "name": name,
        "value": value,
        "ttl": str(ttl),
    }
    return format_response(await call_da_legacy("CMD_API_DNS_CONTROL", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def dns_record_delete(
    domain: str,
    record_type: str,
    name: str,
    value: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Delete a DNS record.

    Args:
        domain: Zone.
        record_type: Type.
        name: Name.
        value: Value (required by most DA versions).
        confirm: Required.
    """
    rejected = guard_confirm("dns_record_delete", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    payload = {
        "domain": domain,
        "action": "select",
        f"{record_type.lower()}recs0": f"name={name}&value={value}",
        "delete": "yes",
    }
    return format_response(await call_da_legacy("CMD_API_DNS_CONTROL", method="POST", data=payload))
