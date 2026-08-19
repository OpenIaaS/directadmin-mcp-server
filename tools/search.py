"""Global search + widgets + cPanel import + misc admin."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_api
from mcp_instance import mcp
from tools.common import format_response, log_tool_call


@mcp.tool()
@log_tool_call
async def search_resources(q: str) -> Dict[str, Any]:
    """Search panel resources (domains, dbs, emails, …).

    Args:
        q: Query.
    """
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


@mcp.tool()
@log_tool_call
async def cpanel_import_check_remote(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Check a remote cPanel server before import.

    Args:
        payload: Host / credentials body.
    """
    return format_response(
        await call_da_api("/api/cpanel-import/check-remote", method="POST", data=payload)
    )


@mcp.tool()
@log_tool_call
async def phpmyadmin_sso(database: str = "") -> Dict[str, Any]:
    """Create a phpMyAdmin SSO session.

    Args:
        database: Optional database name for database-scoped SSO.
    """
    if database:
        return format_response(
            await call_da_api(f"/api/phpmyadmin-sso/database-access/{database}", method="POST")
        )
    return format_response(await call_da_api("/api/phpmyadmin-sso/account-access", method="POST"))
