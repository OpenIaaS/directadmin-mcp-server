"""Email logs, vacation messages, IMAP sync, mobileconfig."""

from __future__ import annotations

import re
from typing import Any, Dict

from da import call_da_api
from mcp_instance import mcp
from security import validate_domain
from tools.common import format_error, format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def email_logs() -> Dict[str, Any]:
    """Global email logs (admin)."""
    return format_response(await call_da_api("/api/email-logs"))


@mcp.tool()
@log_tool_call
async def email_logs_summary() -> Dict[str, Any]:
    """Email log summary."""
    return format_response(await call_da_api("/api/email-logs-summary"))


@mcp.tool()
@log_tool_call
async def email_logs_user() -> Dict[str, Any]:
    """Current/impersonated user email logs."""
    return format_response(await call_da_api("/api/email-logs/user"))


@mcp.tool()
@log_tool_call
async def email_vacation_list(domain: str) -> Dict[str, Any]:
    """Vacation / autoresponder list for a domain.

    Args:
        domain: Domain.
    """
    domain = validate_domain(domain)
    return format_response(await call_da_api(f"/api/emailvacation/{domain}"))


@mcp.tool()
@log_tool_call
async def email_vacation_get(domain: str, user: str) -> Dict[str, Any]:
    """One vacation message.

    Args:
        domain: Domain.
        user: Local part.
    """
    domain = validate_domain(domain)
    return format_response(await call_da_api(f"/api/emailvacation/{domain}/{user}"))


@mcp.tool()
@log_tool_call
async def email_vacation_set(
    domain: str, user: str, values: Dict[str, Any], confirm: bool = False
) -> Dict[str, Any]:
    """Create/update a vacation message.

    Args:
        domain: Domain.
        user: Local part.
        values: Vacation body.
        confirm: Required.
    """
    rejected = guard_confirm("email_vacation_set", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    return format_response(
        await call_da_api(f"/api/emailvacation/{domain}/{user}", method="PUT", data=values)
    )


@mcp.tool()
@log_tool_call
async def email_vacation_delete(domain: str, user: str, confirm: bool = False) -> Dict[str, Any]:
    """Delete a vacation message.

    Args:
        domain: Domain.
        user: Local part.
        confirm: Required.
    """
    rejected = guard_confirm("email_vacation_delete", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    return format_response(
        await call_da_api(f"/api/emailvacation/{domain}/{user}", method="DELETE")
    )


@mcp.tool()
@log_tool_call
async def email_mobileconfig() -> Dict[str, Any]:
    """Apple mobileconfig for the current email account."""
    return format_response(await call_da_api("/api/email-config/mobileconfig"))


@mcp.tool()
@log_tool_call
async def imapsync_migrations() -> Dict[str, Any]:
    """IMAP migration tasks."""
    return format_response(await call_da_api("/api/imapsync/migrations"))


@mcp.tool()
@log_tool_call
async def imapsync_import(payload: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Import mail from a remote IMAP server into this box.

    Args:
        payload: Panel imapsync import body (host, user, password, dest).
        confirm: Required. Passwords in the payload are redacted in logs.
    """
    rejected = guard_confirm("imapsync_import", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/imapsync/import", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def imapsync_export(payload: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Export mail from this box to a remote IMAP server.

    Args:
        payload: Panel imapsync export body.
        confirm: Required.
    """
    rejected = guard_confirm("imapsync_export", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/imapsync/export", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def imapsync_cancel(migration_id: str, confirm: bool = False) -> Dict[str, Any]:
    """Cancel a running IMAP migration.

    Args:
        migration_id: Id from imapsync_migrations.
        confirm: Required.
    """
    rejected = guard_confirm("imapsync_cancel", confirm)
    if rejected:
        return rejected
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", migration_id):
        return format_error("Invalid migration id")
    return format_response(
        await call_da_api(f"/api/imapsync/migrations/{migration_id}", method="DELETE")
    )
