"""MySQL/MariaDB show + manage + monitor."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_api
from mcp_instance import mcp
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def db_info() -> Dict[str, Any]:
    """Database server info."""
    return format_response(await call_da_api("/api/db-show/info"))


@mcp.tool()
@log_tool_call
async def db_list() -> Dict[str, Any]:
    """List databases visible to the current/impersonated account."""
    return format_response(await call_da_api("/api/db-show/databases"))


@mcp.tool()
@log_tool_call
async def db_get(database: str) -> Dict[str, Any]:
    """Details for one database.

    Args:
        database: Database name.
    """
    return format_response(await call_da_api(f"/api/db-show/databases/{database}"))


@mcp.tool()
@log_tool_call
async def db_users() -> Dict[str, Any]:
    """List database users."""
    return format_response(await call_da_api("/api/db-show/users"))


@mcp.tool()
@log_tool_call
async def db_user_get(dbuser: str) -> Dict[str, Any]:
    """One database user.

    Args:
        dbuser: DB username.
    """
    return format_response(await call_da_api(f"/api/db-show/users/{dbuser}"))


@mcp.tool()
@log_tool_call
async def db_create(payload: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Create a database.

    Args:
        payload: Create body (name, charset, …).
        confirm: Required.
    """
    rejected = guard_confirm("db_create", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/db-manage/create-db", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def db_create_with_user(payload: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Create a database and a user in one call.

    Args:
        payload: Combined create body.
        confirm: Required.
    """
    rejected = guard_confirm("db_create_with_user", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api("/api/db-manage/create-db-with-user", method="POST", data=payload)
    )


@mcp.tool()
@log_tool_call
async def db_create_user(payload: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Create a database user.

    Args:
        payload: User body.
        confirm: Required.
    """
    rejected = guard_confirm("db_create_user", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/db-manage/create-user", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def db_delete(database: str, confirm: bool = False) -> Dict[str, Any]:
    """Drop a database.

    Args:
        database: Name.
        confirm: Required.
    """
    rejected = guard_confirm("db_delete", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api(f"/api/db-manage/databases/{database}", method="DELETE"))


@mcp.tool()
@log_tool_call
async def db_delete_user(dbuser: str, confirm: bool = False) -> Dict[str, Any]:
    """Drop a database user.

    Args:
        dbuser: Name.
        confirm: Required.
    """
    rejected = guard_confirm("db_delete_user", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api(f"/api/db-manage/users/{dbuser}", method="DELETE"))


@mcp.tool()
@log_tool_call
async def db_change_user_password(
    dbuser: str, password: str, confirm: bool = False
) -> Dict[str, Any]:
    """Change a database user password.

    Args:
        dbuser: Name.
        password: New password.
        confirm: Required.
    """
    rejected = guard_confirm("db_change_user_password", confirm, extra=True)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(
            f"/api/db-manage/users/{dbuser}/change-password",
            method="POST",
            data={"password": password},
        )
    )


@mcp.tool()
@log_tool_call
async def db_repair(database: str, confirm: bool = False) -> Dict[str, Any]:
    """Repair a database.

    Args:
        database: Name.
        confirm: Required.
    """
    rejected = guard_confirm("db_repair", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(f"/api/db-manage/databases/{database}/repair", method="POST")
    )


@mcp.tool()
@log_tool_call
async def db_optimize(database: str, confirm: bool = False) -> Dict[str, Any]:
    """Optimize a database.

    Args:
        database: Name.
        confirm: Required.
    """
    rejected = guard_confirm("db_optimize", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(f"/api/db-manage/databases/{database}/optimize", method="POST")
    )


@mcp.tool()
@log_tool_call
async def db_check(database: str) -> Dict[str, Any]:
    """Check a database.

    Args:
        database: Name.
    """
    return format_response(
        await call_da_api(f"/api/db-manage/databases/{database}/check", method="POST")
    )


@mcp.tool()
@log_tool_call
async def db_processes() -> Dict[str, Any]:
    """Show process list (admin)."""
    return format_response(await call_da_api("/api/db-monitor/processes"))


@mcp.tool()
@log_tool_call
async def db_kill_process(process_id: str, confirm: bool = False) -> Dict[str, Any]:
    """Kill a database process.

    Args:
        process_id: Process id.
        confirm: Required.
    """
    rejected = guard_confirm("db_kill_process", confirm)
    if rejected:
        return rejected
    if not process_id or "/" in process_id or ".." in process_id:
        from tools.common import format_error

        return format_error("Invalid process id")
    return format_response(
        await call_da_api(f"/api/db-monitor/processes/{process_id}/kill", method="POST")
    )
