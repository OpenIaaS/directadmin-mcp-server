"""Admin account lifecycle — New API where it exists, legacy CMD_API_* otherwise."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_api, call_da_legacy
from mcp_instance import mcp
from security import validate_query, validate_username
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def users_list_all() -> Dict[str, Any]:
    """List every user on the server (admin)."""
    return format_response(await call_da_legacy("CMD_API_SHOW_ALL_USERS", method="GET"))


@mcp.tool()
@log_tool_call
async def users_list(reseller: str = "") -> Dict[str, Any]:
    """List users owned by the current reseller, or by `reseller` if given.

    Args:
        reseller: Optional reseller username.
    """
    data = {"reseller": reseller} if reseller else {}
    if reseller:
        validate_username(reseller)
    return format_response(await call_da_legacy("CMD_API_SHOW_USERS", method="GET", data=data))


@mcp.tool()
@log_tool_call
async def resellers_list() -> Dict[str, Any]:
    """List all reseller accounts."""
    return format_response(await call_da_legacy("CMD_API_SHOW_RESELLERS", method="GET"))


@mcp.tool()
@log_tool_call
async def admins_list() -> Dict[str, Any]:
    """List all admin accounts."""
    return format_response(await call_da_legacy("CMD_API_SHOW_ADMINS", method="GET"))


@mcp.tool()
@log_tool_call
async def users_search(q: str, extended: bool = False) -> Dict[str, Any]:
    """Search users via the New API.

    Args:
        q: Query string (username / domain / email fragment).
        extended: Use /api/search/users-extended.
    """
    q = validate_query(q)
    path = "/api/search/users-extended" if extended else "/api/search/users"
    return format_response(await call_da_api(path, method="GET", data={"q": q}))


@mcp.tool()
@log_tool_call
async def users_get_config(username: str) -> Dict[str, Any]:
    """Get user.conf style configuration (limits, domains, suspended flag).

    Args:
        username: Account name.
    """
    username = validate_username(username)
    return format_response(await call_da_api(f"/api/users/{username}/config"))


@mcp.tool()
@log_tool_call
async def users_get_usage(username: str) -> Dict[str, Any]:
    """Get live usage + limits for a user.

    Args:
        username: Account name.
    """
    username = validate_username(username)
    return format_response(await call_da_api(f"/api/users/{username}/usage"))


@mcp.tool()
@log_tool_call
async def users_login_history(username: str) -> Dict[str, Any]:
    """Login history for a specific user.

    Args:
        username: Account name.
    """
    username = validate_username(username)
    return format_response(await call_da_api(f"/api/users/{username}/login-history"))


@mcp.tool()
@log_tool_call
async def resellers_get_config(username: str) -> Dict[str, Any]:
    """Reseller configuration.

    Args:
        username: Reseller name.
    """
    username = validate_username(username)
    return format_response(await call_da_api(f"/api/resellers/{username}/config"))


@mcp.tool()
@log_tool_call
async def resellers_get_usage(username: str) -> Dict[str, Any]:
    """Combined reseller + owned-users usage.

    Args:
        username: Reseller name.
    """
    username = validate_username(username)
    return format_response(await call_da_api(f"/api/resellers/{username}/usage"))


@mcp.tool()
@log_tool_call
async def users_create(
    username: str,
    email: str,
    password: str,
    domain: str,
    package: str,
    ip: str = "shared",
    notify: bool = False,
    confirm: bool = False,
) -> Dict[str, Any]:
    """Create a user from a package (legacy CMD_API_ACCOUNT_USER).

    Args:
        username: New username (usually 3–16 alphanumeric).
        email: Contact email.
        password: Initial password (prefer sending a login-key later).
        domain: Primary domain.
        package: Existing user package name.
        ip: shared | sharedreseller | a free IP.
        notify: Email the welcome message.
        confirm: Required.
    """
    rejected = guard_confirm("users_create", confirm)
    if rejected:
        return rejected
    username = validate_username(username)
    payload = {
        "action": "create",
        "add": "Submit",
        "username": username,
        "email": email,
        "passwd": password,
        "passwd2": password,
        "domain": domain,
        "package": package,
        "ip": ip,
        "notify": "yes" if notify else "no",
    }
    return format_response(await call_da_legacy("CMD_API_ACCOUNT_USER", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def resellers_create(
    username: str,
    email: str,
    password: str,
    domain: str,
    package: str,
    ip: str = "shared",
    notify: bool = False,
    confirm: bool = False,
) -> Dict[str, Any]:
    """Create a reseller from a reseller package.

    Args:
        username: New reseller.
        email: Contact email.
        password: Initial password.
        domain: Primary domain.
        package: Reseller package name.
        ip: shared | sharedreseller | assign.
        notify: Send welcome email.
        confirm: Required.
    """
    rejected = guard_confirm("resellers_create", confirm)
    if rejected:
        return rejected
    username = validate_username(username)
    payload = {
        "action": "create",
        "add": "Submit",
        "username": username,
        "email": email,
        "passwd": password,
        "passwd2": password,
        "domain": domain,
        "package": package,
        "ip": ip,
        "notify": "yes" if notify else "no",
    }
    return format_response(
        await call_da_legacy("CMD_API_ACCOUNT_RESELLER", method="POST", data=payload)
    )


@mcp.tool()
@log_tool_call
async def users_delete(username: str, confirm: bool = False) -> Dict[str, Any]:
    """Permanently delete a user/reseller/admin account.

    Args:
        username: Account to delete.
        confirm: Required.
    """
    rejected = guard_confirm("users_delete", confirm)
    if rejected:
        return rejected
    username = validate_username(username)
    payload = {"confirmed": "Confirm", "delete": "yes", "select0": username}
    return format_response(await call_da_legacy("CMD_API_SELECT_USERS", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def users_suspend(username: str, confirm: bool = False) -> Dict[str, Any]:
    """Toggle suspend/unsuspend for an account (DirectAdmin toggle).

    Args:
        username: Account.
        confirm: Required.
    """
    rejected = guard_confirm("users_suspend", confirm)
    if rejected:
        return rejected
    username = validate_username(username)
    payload = {
        "location": "CMD_SELECT_USERS",
        "suspend": "Suspend/Unsuspend",
        "select0": username,
    }
    return format_response(await call_da_legacy("CMD_API_SELECT_USERS", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def users_change_password(
    username: str, new_password: str, confirm: bool = False
) -> Dict[str, Any]:
    """Change another account's password (admin).

    Args:
        username: Target account. Empty / current user uses /api/change-password.
        new_password: New password.
        confirm: Required.
    """
    rejected = guard_confirm("users_change_password", confirm, extra=True)
    if rejected:
        return rejected
    username = validate_username(username)
    # Impersonate then change-password is the New API path
    data = await call_da_api(
        "/api/change-password",
        method="POST",
        data={"password": new_password},
        impersonate=username,
    )
    return format_response(data)


@mcp.tool()
@log_tool_call
async def users_change_creator(
    username: str, new_creator: str, confirm: bool = False
) -> Dict[str, Any]:
    """Move a user to a different reseller/creator.

    Args:
        username: User to move.
        new_creator: Destination reseller/admin.
        confirm: Required.
    """
    rejected = guard_confirm("users_change_creator", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(
            "/api/change-user-creator",
            method="POST",
            data={"username": validate_username(username), "creator": validate_username(new_creator)},
        )
    )


@mcp.tool()
@log_tool_call
async def users_convert_to_reseller(username: str, confirm: bool = False) -> Dict[str, Any]:
    """Promote a user account to reseller.

    Args:
        username: User to promote.
        confirm: Required.
    """
    rejected = guard_confirm("users_convert_to_reseller", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(
            "/api/convert-user-to-reseller",
            method="POST",
            data={"username": validate_username(username)},
        )
    )


@mcp.tool()
@log_tool_call
async def resellers_convert_to_user(username: str, confirm: bool = False) -> Dict[str, Any]:
    """Demote a reseller to a regular user.

    Args:
        username: Reseller to demote.
        confirm: Required.
    """
    rejected = guard_confirm("resellers_convert_to_user", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(
            "/api/convert-reseller-to-user",
            method="POST",
            data={"username": validate_username(username)},
        )
    )


@mcp.tool()
@log_tool_call
async def admin_usage() -> Dict[str, Any]:
    """Current admin's resource usage."""
    return format_response(await call_da_api("/api/admin-usage"))


@mcp.tool()
@log_tool_call
async def users_exists(username: str) -> Dict[str, Any]:
    """Check whether an account name already exists (admin).

    Args:
        username: Candidate username.
    """
    username = validate_username(username)
    return format_response(
        await call_da_legacy("CMD_API_USER_EXISTS", method="GET", data={"user": username})
    )


@mcp.tool()
@log_tool_call
async def users_unsuspend(username: str, confirm: bool = False) -> Dict[str, Any]:
    """Unsuspend an account (same toggle endpoint as users_suspend).

    Args:
        username: Account.
        confirm: Required.
    """
    rejected = guard_confirm("users_unsuspend", confirm)
    if rejected:
        return rejected
    username = validate_username(username)
    payload = {
        "location": "CMD_SELECT_USERS",
        "suspend": "Suspend/Unsuspend",
        "select0": username,
    }
    return format_response(await call_da_legacy("CMD_API_SELECT_USERS", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def users_modify(
    username: str,
    bandwidth: str = "",
    quota: str = "",
    vdomains: str = "",
    nemails: str = "",
    mysql: str = "",
    php: str = "",
    ssl: str = "",
    ssh: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Customize limits on an existing user (CMD_API_MODIFY_USER).

    Empty strings leave that field unchanged. Use 'unlimited' or a number.

    Args:
        username: Account.
        bandwidth: Bandwidth MB or unlimited.
        quota: Disk MB or unlimited.
        vdomains: Domain limit or unlimited.
        nemails: Mailbox limit or unlimited.
        mysql: Database limit or unlimited.
        php: ON | OFF
        ssl: ON | OFF
        ssh: ON | OFF
        confirm: Required.
    """
    rejected = guard_confirm("users_modify", confirm)
    if rejected:
        return rejected
    username = validate_username(username)
    payload: Dict[str, Any] = {"action": "customize", "user": username}
    mapping = {
        "bandwidth": bandwidth,
        "quota": quota,
        "vdomains": vdomains,
        "nemails": nemails,
        "mysql": mysql,
        "php": php,
        "ssl": ssl,
        "ssh": ssh,
    }
    for key, value in mapping.items():
        if not value:
            continue
        if value == "unlimited" and key in {"bandwidth", "quota", "vdomains", "nemails", "mysql"}:
            payload[f"u{key}"] = "yes"
            payload[key] = "0"
        else:
            payload[key] = value
    return format_response(await call_da_legacy("CMD_API_MODIFY_USER", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def admins_create(
    username: str,
    email: str,
    password: str,
    notify: bool = False,
    confirm: bool = False,
) -> Dict[str, Any]:
    """Create another admin account.

    Args:
        username: New admin.
        email: Contact email.
        password: Initial password.
        notify: Send welcome email.
        confirm: Required.
    """
    rejected = guard_confirm("admins_create", confirm, extra=True)
    if rejected:
        return rejected
    from security import validate_email

    username = validate_username(username)
    email = validate_email(email)
    payload = {
        "action": "create",
        "username": username,
        "email": email,
        "passwd": password,
        "passwd2": password,
        "notify": "yes" if notify else "no",
    }
    return format_response(await call_da_legacy("CMD_API_ACCOUNT_ADMIN", method="POST", data=payload))
