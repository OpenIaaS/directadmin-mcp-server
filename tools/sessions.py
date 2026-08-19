"""Session, login-as, profile, messages, tickets."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_api
from mcp_instance import mcp
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def session_get() -> Dict[str, Any]:
    """Current session (who am I, level, selected domain)."""
    return format_response(await call_da_api("/api/session"))


@mcp.tool()
@log_tool_call
async def session_state() -> Dict[str, Any]:
    """Session UI state."""
    return format_response(await call_da_api("/api/session/state"))


@mcp.tool()
@log_tool_call
async def session_user_config() -> Dict[str, Any]:
    """Current account user.conf."""
    return format_response(await call_da_api("/api/session/user-config"))


@mcp.tool()
@log_tool_call
async def session_user_usage() -> Dict[str, Any]:
    """Current account usage."""
    return format_response(await call_da_api("/api/session/user-usage"))


@mcp.tool()
@log_tool_call
async def session_reseller_config() -> Dict[str, Any]:
    """Current reseller config (when logged in as reseller/admin)."""
    return format_response(await call_da_api("/api/session/reseller-config"))


@mcp.tool()
@log_tool_call
async def session_switch_domain(domain: str) -> Dict[str, Any]:
    """Switch the active domain in the session.

    Args:
        domain: Domain to select.
    """
    return format_response(
        await call_da_api(
            "/api/session/switch-active-domain", method="POST", data={"domain": domain}
        )
    )


@mcp.tool()
@log_tool_call
async def session_login_as(username: str, confirm: bool = False) -> Dict[str, Any]:
    """Switch the session into another account (login-as).

    Prefer the impersonate= argument on individual tools — it does not mutate
    the long-lived session.

    Args:
        username: Account to impersonate.
        confirm: Required.
    """
    rejected = guard_confirm("session_login_as", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(
            "/api/session/login-as/switch", method="POST", data={"username": username}
        )
    )


@mcp.tool()
@log_tool_call
async def session_login_as_return() -> Dict[str, Any]:
    """Leave a login-as session and return to the admin."""
    return format_response(await call_da_api("/api/session/login-as/return", method="POST"))


@mcp.tool()
@log_tool_call
async def session_login_as_users(q: str = "", limit: int = 20) -> Dict[str, Any]:
    """Search users available for login-as.

    Args:
        q: Query.
        limit: Max rows.
    """
    return format_response(
        await call_da_api("/api/session/login-as/user-list", method="GET", data={"q": q, "limit": limit})
    )


@mcp.tool()
@log_tool_call
async def sessions_list() -> Dict[str, Any]:
    """List active sessions for this account."""
    return format_response(await call_da_api("/api/sessions"))


@mcp.tool()
@log_tool_call
async def sessions_destroy(public_id: str, confirm: bool = False) -> Dict[str, Any]:
    """Destroy one other session.

    Args:
        public_id: Session public id.
        confirm: Required.
    """
    rejected = guard_confirm("sessions_destroy", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(f"/api/sessions/destroy/{public_id}", method="POST")
    )


@mcp.tool()
@log_tool_call
async def sessions_destroy_all_other(confirm: bool = False) -> Dict[str, Any]:
    """Destroy every other session (force logout everywhere else).

    Args:
        confirm: Required.
    """
    rejected = guard_confirm("sessions_destroy_all_other", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/sessions/destroy-all-other", method="POST"))


@mcp.tool()
@log_tool_call
async def login_history() -> Dict[str, Any]:
    """Current account login history."""
    return format_response(await call_da_api("/api/login-history"))


@mcp.tool()
@log_tool_call
async def profile_settings() -> Dict[str, Any]:
    """Current profile settings."""
    return format_response(await call_da_api("/api/profile/settings"))


@mcp.tool()
@log_tool_call
async def profile_settings_update(values: Dict[str, Any]) -> Dict[str, Any]:
    """Patch profile settings.

    Args:
        values: Partial settings object.
    """
    return format_response(await call_da_api("/api/profile/settings", method="PATCH", data=values))


@mcp.tool()
@log_tool_call
async def messages_list() -> Dict[str, Any]:
    """Message center list."""
    return format_response(await call_da_api("/api/messages/list"))


@mcp.tool()
@log_tool_call
async def messages_get(message_id: str) -> Dict[str, Any]:
    """Read one message.

    Args:
        message_id: Message id.
    """
    return format_response(await call_da_api(f"/api/messages/id/{message_id}"))


@mcp.tool()
@log_tool_call
async def tickets_list() -> Dict[str, Any]:
    """Support tickets."""
    return format_response(await call_da_api("/api/tickets"))


@mcp.tool()
@log_tool_call
async def ticket_requests() -> Dict[str, Any]:
    """Ticket requests queue."""
    return format_response(await call_da_api("/api/ticket-requests"))
