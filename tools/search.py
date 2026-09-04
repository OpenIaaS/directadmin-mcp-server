"""Global search + widgets + cPanel import + misc admin."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_api
from mcp_instance import mcp
from security import (
    SecurityError,
    validate_path_segment,
    validate_query,
    validate_remote_host,
)
from tools.common import format_error, format_response, log_tool_call


@mcp.tool()
@log_tool_call
async def search_resources(q: str) -> Dict[str, Any]:
    """Search panel resources (domains, dbs, emails, …).

    Args:
        q: Query.
    """
    q = validate_query(q)
    return format_response(await call_da_api("/api/search/resources", method="GET", data={"q": q}))


@mcp.tool()
@log_tool_call
async def widgets_list() -> Dict[str, Any]:
    """Dashboard widgets."""
    return format_response(await call_da_api("/api/widgets/list"))


@mcp.tool()
@log_tool_call
async def cpanel_import_tasks() -> Dict[str, Any]:
    """cPanel import tasks."""
    return format_response(await call_da_api("/api/cpanel-import/tasks"))


# Payload keys that name the host the panel will dial (case-insensitive).
_REMOTE_HOST_KEYS = ("host", "hostname", "server", "url", "address")


@mcp.tool()
@log_tool_call
async def cpanel_import_check_remote(payload: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Check a remote cPanel server before import.

    Panel-side request forgery surface: the panel dials whatever host the
    payload names, with the credentials the payload carries. Host-like fields
    (host/hostname/server/url/address) must therefore be https (when a scheme
    is given), carry no embedded user:pass@ credentials, and point at public
    IP literals. Hostnames are not resolved here — the panel resolves them —
    so a hostname that maps to a private address remains a panel-side risk.

    Args:
        payload: Host / credentials body.
        confirm: Required — the panel dials an arbitrary host.
    """
    if not isinstance(payload, dict) or not payload:
        return format_error("payload with the remote host is required")
    for key, value in payload.items():
        if str(key).lower() in _REMOTE_HOST_KEYS and isinstance(value, str):
            try:
                validate_remote_host(value, what=f"cpanel-import {key}")
            except SecurityError as exc:
                return format_error(str(exc))
    return format_response(
        await call_da_api("/api/cpanel-import/check-remote", method="POST", data=payload)
    )


@mcp.tool()
@log_tool_call
async def phpmyadmin_sso(database: str = "", confirm: bool = False) -> Dict[str, Any]:
    """Create a phpMyAdmin SSO session.

    Args:
        database: Optional database name for database-scoped SSO.
        confirm: Required — mints a database SSO session.
    """
    if database:
        database = validate_path_segment(database, "database name", max_len=64)
        return format_response(
            await call_da_api(f"/api/phpmyadmin-sso/database-access/{database}", method="POST")
        )
    return format_response(await call_da_api("/api/phpmyadmin-sso/account-access", method="POST"))
