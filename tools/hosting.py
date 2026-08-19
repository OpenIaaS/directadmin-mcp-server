"""FTP accounts, cron jobs and per-domain PHP version (legacy hosting admin)."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_legacy
from mcp_instance import mcp
from security import validate_cron_field, validate_domain, validate_username
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def ftp_list(domain: str, impersonate: str = "") -> Dict[str, Any]:
    """List FTP accounts for a domain.

    Args:
        domain: Domain.
        impersonate: Owning user.
    """
    domain = validate_domain(domain)
    return format_response(
        await call_da_legacy(
            "CMD_API_FTP",
            method="GET",
            data={"domain": domain},
            impersonate=impersonate or None,
        )
    )


@mcp.tool()
@log_tool_call
async def ftp_create(
    domain: str,
    user: str,
    password: str,
    path_type: str = "domain",
    custom_path: str = "",
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Create an FTP account.

    Args:
        domain: Domain.
        user: FTP username (local part).
        password: FTP password.
        path_type: domain | ftp | user | custom
        custom_path: Required when path_type=custom.
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("ftp_create", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    user = validate_username(user)
    payload = {
        "action": "create",
        "domain": domain,
        "user": user,
        "passwd": password,
        "passwd2": password,
        "type": path_type,
    }
    if path_type == "custom" and custom_path:
        payload["custom_val"] = custom_path
    return format_response(
        await call_da_legacy(
            "CMD_API_FTP", method="POST", data=payload, impersonate=impersonate or None
        )
    )


@mcp.tool()
@log_tool_call
async def ftp_delete(
    domain: str, user: str, impersonate: str = "", confirm: bool = False
) -> Dict[str, Any]:
    """Delete an FTP account.

    Args:
        domain: Domain.
        user: FTP username.
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("ftp_delete", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    user = validate_username(user)
    payload = {"action": "delete", "domain": domain, "select0": user}
    return format_response(
        await call_da_legacy(
            "CMD_API_FTP", method="POST", data=payload, impersonate=impersonate or None
        )
    )


@mcp.tool()
@log_tool_call
async def cron_list(impersonate: str = "") -> Dict[str, Any]:
    """List cron jobs for the current (or impersonated) user.

    Args:
        impersonate: Owning user.
    """
    return format_response(
        await call_da_legacy("CMD_API_CRON_JOBS", method="GET", impersonate=impersonate or None)
    )


@mcp.tool()
@log_tool_call
async def cron_create(
    minute: str,
    hour: str,
    day_of_month: str,
    month: str,
    day_of_week: str,
    command: str,
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Create a cron job.

    Args:
        minute: Cron minute (0-59 or *).
        hour: Cron hour.
        day_of_month: Day of month.
        month: Month.
        day_of_week: Day of week.
        command: Command to run (no shell metachar redirection from untrusted input).
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("cron_create", confirm)
    if rejected:
        return rejected
    payload = {
        "action": "create",
        "minute": validate_cron_field(minute),
        "hour": validate_cron_field(hour),
        "dayofmonth": validate_cron_field(day_of_month),
        "month": validate_cron_field(month),
        "dayofweek": validate_cron_field(day_of_week),
        "command": command,
    }
    return format_response(
        await call_da_legacy(
            "CMD_API_CRON_JOBS", method="POST", data=payload, impersonate=impersonate or None
        )
    )


@mcp.tool()
@log_tool_call
async def cron_delete(job_id: str, impersonate: str = "", confirm: bool = False) -> Dict[str, Any]:
    """Delete a cron job by its panel id / select key.

    Args:
        job_id: Id from cron_list (select0 value).
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("cron_delete", confirm)
    if rejected:
        return rejected
    payload = {"action": "delete", "select0": job_id}
    return format_response(
        await call_da_legacy(
            "CMD_API_CRON_JOBS", method="POST", data=payload, impersonate=impersonate or None
        )
    )


@mcp.tool()
@log_tool_call
async def domains_set_php(
    domain: str,
    php1_select: str,
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Set the PHP version selector for a domain.

    Args:
        domain: Domain.
        php1_select: Selector index from the panel (often '1', '2', … mapping to php versions).
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("domains_set_php", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    payload = {"action": "php_selector", "domain": domain, "php1_select": php1_select}
    return format_response(
        await call_da_legacy(
            "CMD_API_DOMAIN", method="POST", data=payload, impersonate=impersonate or None
        )
    )
