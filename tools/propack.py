"""Pro Pack admin surfaces that are not (fully) in the New JSON API.

Modern DirectAdmin licenses include the old Pro Pack. Most of it already has
New API tools (Redis, WP, Git, ClamAV, Admin SSL, email logs, cgroups
metrics). This module covers the leftovers:

  * Nginx Unit (CMD_UNIT) — Node/Python/Ruby/Java/Perl apps
  * Nginx CMS templates (CMD_API_DOMAIN nginx_template)
  * A read-only inventory so the agent knows what is already curated
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from da import DirectAdminError, call_da_legacy
from mcp_instance import mcp
from security import validate_domain
from tools.common import format_error, format_response, guard_confirm, log_tool_call

_APP_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_TEMPLATES = {
    "",
    "none",
    "default",
    "wordpress",
    "wordpress_cache",
    "wordpress-fastcgi",
    "drupal",
    "joomla",
    "magento",
    "laravel",
    "custom",
}

INVENTORY = [
    {"feature": "Admin SSL", "tools": "ssl_admin_list, ssl_admin_reissue", "api": "CMD_ADMIN_SSL"},
    {"feature": "Per-user Redis", "tools": "redis_status, redis_enable, redis_disable", "api": "/api/redis/*"},
    {"feature": "WordPress manager", "tools": "wp_*", "api": "/api/wordpress/*"},
    {"feature": "GIT manager", "tools": "git_list, git_deploy, git_fetch, git_webhook", "api": "/api/git/*"},
    {"feature": "ClamAV scans", "tools": "clamav_status, clamav_scan, clamav_kill", "api": "/api/clamav"},
    {"feature": "Email Track & Trace", "tools": "email_logs, email_logs_summary, email_logs_user", "api": "/api/email-logs*"},
    {"feature": "IMAP sync", "tools": "imapsync_migrations, imapsync_import, imapsync_export, imapsync_cancel", "api": "/api/imapsync/*"},
    {"feature": "Mail autoconfig", "tools": "email_mobileconfig", "api": "/api/email-config/mobileconfig"},
    {"feature": "CGroups / resource metrics", "tools": "system_resource_usage_*, system_global_usage_*", "api": "/api/resource-usage/*, /api/global-resource-usage/*"},
    {"feature": "DB Monitor", "tools": "db_processes, db_kill_process", "api": "/api/db-monitor/*"},
    {"feature": "security.txt", "tools": "security_txt_status", "api": "/api/security-txt/status"},
    {"feature": "System Packages", "tools": "system_packages_*", "api": "/api/system-packages/*"},
    {"feature": "Nginx Unit", "tools": "unit_list, unit_create, unit_delete", "api": "CMD_UNIT"},
    {"feature": "Nginx CMS templates", "tools": "nginx_set_template", "api": "CMD_API_DOMAIN nginx_template"},
    {"feature": "Web Terminal", "tools": "(blocked)", "api": "/api/terminal — never exposed"},
]


def _app_name(value: str) -> str:
    if not value or not _APP_NAME.fullmatch(value):
        raise ValueError("Invalid Unit application name")
    return value


@mcp.tool()
@log_tool_call
async def propack_inventory() -> Dict[str, Any]:
    """Map every Pro Pack feature to the curated tool that covers it.

    Modern licenses include Pro Pack. Web Terminal is intentionally not wrapped.
    """
    return format_response({"features": INVENTORY, "web_terminal": "blocked"})


@mcp.tool()
@log_tool_call
async def unit_list(domain: str, impersonate: str = "") -> Dict[str, Any]:
    """List Nginx Unit applications and routes for a domain (CMD_UNIT).

    Args:
        domain: Domain that owns the Unit apps.
        impersonate: Owning user.
    """
    domain = validate_domain(domain)
    try:
        data = await call_da_legacy(
            "CMD_UNIT",
            method="GET",
            data={"domain": domain},
            impersonate=impersonate or None,
        )
    except DirectAdminError as exc:
        return format_error(
            "Nginx Unit is not available (CMD_UNIT). Enable it with CustomBuild "
            "`da build set unit yes && da build unit`.",
            status_code=exc.status_code,
        )
    return format_response(data)


@mcp.tool()
@log_tool_call
async def unit_create(
    domain: str,
    name: str,
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Create an empty Nginx Unit application stub (then edit JSON in the panel).

    Args:
        domain: Domain.
        name: Application name (saved as domain_name).
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("unit_create", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    try:
        name = _app_name(name)
    except ValueError as exc:
        return format_error(str(exc))
    data = await call_da_legacy(
        "CMD_UNIT",
        method="POST",
        data={"domain": domain, "action": "create", "name": name},
        impersonate=impersonate or None,
    )
    return format_response(data)


@mcp.tool()
@log_tool_call
async def unit_delete(
    domain: str,
    names: List[str],
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Delete one or more Nginx Unit applications.

    Args:
        domain: Domain.
        names: Application names.
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("unit_delete", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    if not names:
        return format_error("Provide at least one application name")
    payload: Dict[str, Any] = {"domain": domain, "action": "select"}
    for index, raw in enumerate(names):
        try:
            payload[f"select{index}"] = _app_name(raw)
        except ValueError as exc:
            return format_error(str(exc))
    data = await call_da_legacy(
        "CMD_UNIT", method="POST", data=payload, impersonate=impersonate or None
    )
    return format_response(data)


@mcp.tool()
@log_tool_call
async def nginx_set_template(
    domain: str,
    template: str,
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Apply a Pro Pack Nginx CMS template (WordPress, Drupal, FastCGI cache, …).

    Args:
        domain: Domain.
        template: wordpress | wordpress_cache | drupal | joomla | magento |
            laravel | default | none
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("nginx_set_template", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    cleaned = (template or "default").strip().lower()
    if cleaned not in _TEMPLATES:
        return format_error(
            "Unknown nginx template. Allowed: " + ", ".join(sorted(t for t in _TEMPLATES if t))
        )
    payload = {
        "action": "modify",
        "domain": domain,
        "nginx_template": cleaned,
    }
    data = await call_da_legacy(
        "CMD_API_DOMAIN", method="POST", data=payload, impersonate=impersonate or None
    )
    return format_response(data)
