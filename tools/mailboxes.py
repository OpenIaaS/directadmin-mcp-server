"""POP/IMAP mailboxes, forwarders and autoresponders (legacy email admin)."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_legacy
from mcp_instance import mcp
from security import validate_domain, validate_email_local
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def email_pop_list(domain: str, full: bool = True, impersonate: str = "") -> Dict[str, Any]:
    """List POP/IMAP accounts on a domain.

    Args:
        domain: Domain.
        full: Use action=full_list (quota + usage) when true.
        impersonate: Owning user.
    """
    domain = validate_domain(domain)
    payload = {"domain": domain, "action": "full_list" if full else "list"}
    return format_response(
        await call_da_legacy(
            "CMD_API_POP", method="GET", data=payload, impersonate=impersonate or None
        )
    )


@mcp.tool()
@log_tool_call
async def email_pop_create(
    domain: str,
    user: str,
    password: str,
    quota_mb: int = 0,
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Create a mailbox (user@domain).

    Args:
        domain: Domain.
        user: Local part only (before @).
        password: Mailbox password.
        quota_mb: 0 = unlimited.
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("email_pop_create", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    user = validate_email_local(user)
    payload = {
        "action": "create",
        "domain": domain,
        "user": user,
        "passwd": password,
        "passwd2": password,
        "quota": str(quota_mb),
    }
    return format_response(
        await call_da_legacy(
            "CMD_API_POP", method="POST", data=payload, impersonate=impersonate or None
        )
    )


@mcp.tool()
@log_tool_call
async def email_pop_delete(
    domain: str, user: str, impersonate: str = "", confirm: bool = False
) -> Dict[str, Any]:
    """Delete a mailbox.

    Args:
        domain: Domain.
        user: Local part.
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("email_pop_delete", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    user = validate_email_local(user)
    payload = {"action": "delete", "domain": domain, "user": user, "select0": user}
    return format_response(
        await call_da_legacy(
            "CMD_API_POP", method="POST", data=payload, impersonate=impersonate or None
        )
    )


@mcp.tool()
@log_tool_call
async def email_pop_modify(
    domain: str,
    user: str,
    password: str = "",
    quota_mb: int = -1,
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Change mailbox password and/or quota.

    Args:
        domain: Domain.
        user: Local part.
        password: New password (empty = leave unchanged).
        quota_mb: New quota; -1 = leave unchanged, 0 = unlimited.
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("email_pop_modify", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    user = validate_email_local(user)
    payload: Dict[str, Any] = {"action": "modify", "domain": domain, "user": user}
    if password:
        payload["passwd"] = password
        payload["passwd2"] = password
    if quota_mb >= 0:
        payload["quota"] = str(quota_mb)
    return format_response(
        await call_da_legacy(
            "CMD_API_POP", method="POST", data=payload, impersonate=impersonate or None
        )
    )


@mcp.tool()
@log_tool_call
async def email_forwarders_list(domain: str, impersonate: str = "") -> Dict[str, Any]:
    """List forwarders on a domain.

    Args:
        domain: Domain.
        impersonate: Owning user.
    """
    domain = validate_domain(domain)
    return format_response(
        await call_da_legacy(
            "CMD_API_EMAIL_FORWARDERS",
            method="GET",
            data={"domain": domain},
            impersonate=impersonate or None,
        )
    )


@mcp.tool()
@log_tool_call
async def email_forwarder_create(
    domain: str,
    user: str,
    destination: str,
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Create an email forwarder.

    Args:
        domain: Domain.
        user: Local part (source).
        destination: Destination address or comma-separated list.
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("email_forwarder_create", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    user = validate_email_local(user)
    payload = {"action": "create", "domain": domain, "user": user, "email": destination}
    return format_response(
        await call_da_legacy(
            "CMD_API_EMAIL_FORWARDERS",
            method="POST",
            data=payload,
            impersonate=impersonate or None,
        )
    )


@mcp.tool()
@log_tool_call
async def email_forwarder_delete(
    domain: str, user: str, impersonate: str = "", confirm: bool = False
) -> Dict[str, Any]:
    """Delete a forwarder.

    Args:
        domain: Domain.
        user: Local part.
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("email_forwarder_delete", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    user = validate_email_local(user)
    payload = {"action": "delete", "domain": domain, "select0": user}
    return format_response(
        await call_da_legacy(
            "CMD_API_EMAIL_FORWARDERS",
            method="POST",
            data=payload,
            impersonate=impersonate or None,
        )
    )


@mcp.tool()
@log_tool_call
async def email_autoresponders_list(domain: str, impersonate: str = "") -> Dict[str, Any]:
    """List autoresponders on a domain.

    Args:
        domain: Domain.
        impersonate: Owning user.
    """
    domain = validate_domain(domain)
    return format_response(
        await call_da_legacy(
            "CMD_API_EMAIL_AUTORESPONDER",
            method="GET",
            data={"domain": domain},
            impersonate=impersonate or None,
        )
    )
