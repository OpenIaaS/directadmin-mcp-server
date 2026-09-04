"""Global search + widgets + cPanel import + misc admin."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_api
from mcp_instance import mcp
from security import validate_path_segment, validate_query
from tools.common import format_response, log_tool_call


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


@mcp.tool()
@log_tool_call
async def cpanel_import_check_remote(payload: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Check a remote cPanel server before import.

    Args:
        payload: Host / credentials body.
        confirm: Required — the panel dials an arbitrary host.
    """
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
