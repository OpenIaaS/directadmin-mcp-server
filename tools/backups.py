"""Admin backups via legacy CMD_API_ADMIN_BACKUP / CMD_API_USER_BACKUP."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_legacy
from mcp_instance import mcp
from security import validate_username
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def backups_admin_list() -> Dict[str, Any]:
    """List admin-level backups / backup settings."""
    return format_response(await call_da_legacy("CMD_API_ADMIN_BACKUP", method="GET"))


@mcp.tool()
@log_tool_call
async def backups_create(
    username: str,
    where: str = "local",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Create a backup for one user.

    Args:
        username: Account to back up.
        where: Backup destination the panel understands (local / ftp / …).
        confirm: Required.
    """
    rejected = guard_confirm("backups_create", confirm)
    if rejected:
        return rejected
    username = validate_username(username)
    payload = {
        "action": "backup",
        "select0": username,
        "who": username,
        "when": "now",
        "where": where,
    }
    return format_response(await call_da_legacy("CMD_API_USER_BACKUP", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def backups_restore(
    username: str,
    file: str,
    confirm: bool = False,
) -> Dict[str, Any]:
    """Restore a user from a local backup file.

    Args:
        username: Account to restore into.
        file: Backup filename as listed by the panel.
        confirm: Required.
    """
    rejected = guard_confirm("backups_restore", confirm, extra=True)
    if rejected:
        return rejected
    username = validate_username(username)
    payload = {
        "action": "restore",
        "select0": file,
        "username": username,
        "ip_choice": "file",
    }
    return format_response(await call_da_legacy("CMD_API_USER_BACKUP", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def backups_admin_now(
    who: str = "all",
    where: str = "local",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Kick an admin-level backup now.

    Args:
        who: all | or a username.
        where: Destination the panel understands (local / ftp).
        confirm: Required.
    """
    rejected = guard_confirm("backups_admin_now", confirm)
    if rejected:
        return rejected
    if who != "all":
        who = validate_username(who)
    payload = {"action": "backup", "who": who, "when": "now", "where": where}
    return format_response(await call_da_legacy("CMD_API_ADMIN_BACKUP", method="POST", data=payload))
