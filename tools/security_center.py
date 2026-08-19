"""MFA, security.txt, ModSecurity, ClamAV, Redis, web-protect."""

from __future__ import annotations

from typing import Any, Dict, Optional

from da import call_da_api, client
from mcp_instance import mcp
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def mfa_enable(payload: Optional[Dict[str, Any]] = None, confirm: bool = False) -> Dict[str, Any]:
    """Enable multi-factor authentication on the current account.

    Args:
        payload: Panel-specific body (otp, password, …).
        confirm: Required.
    """
    rejected = guard_confirm("mfa_enable", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api("/api/multi-factor-auth/enable", method="POST", data=payload or {})
    )


@mcp.tool()
@log_tool_call
async def mfa_disable(payload: Optional[Dict[str, Any]] = None, confirm: bool = False) -> Dict[str, Any]:
    """Disable MFA.

    Args:
        payload: Usually includes the current password / OTP.
        confirm: Required.
    """
    rejected = guard_confirm("mfa_disable", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api("/api/multi-factor-auth/disable", method="POST", data=payload or {})
    )


@mcp.tool()
@log_tool_call
async def mfa_generate_secret() -> Dict[str, Any]:
    """Generate a new TOTP secret (enrolment)."""
    return format_response(
        await call_da_api("/api/multi-factor-auth/otp/generate-secret", method="POST")
    )


@mcp.tool()
@log_tool_call
async def mfa_recovery_codes() -> Dict[str, Any]:
    """List MFA recovery codes."""
    return format_response(await call_da_api("/api/multi-factor-auth/recovery-codes"))


@mcp.tool()
@log_tool_call
async def security_txt_status() -> Dict[str, Any]:
    """security.txt status."""
    return format_response(await call_da_api("/api/security-txt/status"))


@mcp.tool()
@log_tool_call
async def modsecurity_global() -> Dict[str, Any]:
    """Global ModSecurity configuration."""
    return format_response(await call_da_api("/api/modsecurity/global-config"))


@mcp.tool()
@log_tool_call
async def modsecurity_global_update(
    values: Dict[str, Any], confirm: bool = False
) -> Dict[str, Any]:
    """Update global ModSecurity configuration.

    Args:
        values: Config object.
        confirm: Required.
    """
    rejected = guard_confirm("modsecurity_global_update", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api("/api/modsecurity/global-config", method="PUT", data=values)
    )


@mcp.tool()
@log_tool_call
async def modsecurity_all_configs() -> Dict[str, Any]:
    """All ModSecurity per-host configs."""
    return format_response(await call_da_api("/api/modsecurity/all-configs"))


@mcp.tool()
@log_tool_call
async def modsecurity_user_configs() -> Dict[str, Any]:
    """Current user's ModSecurity configs."""
    return format_response(await call_da_api("/api/modsecurity/user-configs"))


@mcp.tool()
@log_tool_call
async def modsecurity_host_config(hostname: str) -> Dict[str, Any]:
    """ModSecurity config for one hostname.

    Args:
        hostname: vhost name.
    """
    return format_response(await call_da_api(f"/api/modsecurity/configs/{hostname}"))


@mcp.tool()
@log_tool_call
async def modsecurity_audit_summary() -> Dict[str, Any]:
    """ModSecurity audit log summary."""
    return format_response(await call_da_api("/api/modsecurity-audit-log/summary"))


@mcp.tool()
@log_tool_call
async def modsecurity_audit_entry(entry_id: str = "") -> Dict[str, Any]:
    """One ModSecurity audit entry.

    Args:
        entry_id: Optional entry identifier (query).
    """
    params = {"id": entry_id} if entry_id else None
    data = await client.request("/api/modsecurity-audit-log/entry", method="GET", params=params)
    return format_response(data)


@mcp.tool()
@log_tool_call
async def clamav_status() -> Dict[str, Any]:
    """ClamAV status / start a scan (GET)."""
    return format_response(await call_da_api("/api/clamav"))


@mcp.tool()
@log_tool_call
async def clamav_scan(payload: Optional[Dict[str, Any]] = None, confirm: bool = False) -> Dict[str, Any]:
    """Start a ClamAV scan.

    Args:
        payload: Scan options as the panel expects.
        confirm: Required.
    """
    rejected = guard_confirm("clamav_scan", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/clamav", method="POST", data=payload or {}))


@mcp.tool()
@log_tool_call
async def clamav_kill(pid: str, confirm: bool = False) -> Dict[str, Any]:
    """Kill a running ClamAV scan.

    Args:
        pid: Process id from clamav_status.
        confirm: Required.
    """
    rejected = guard_confirm("clamav_kill", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api(f"/api/clamav/{pid}", method="DELETE"))


@mcp.tool()
@log_tool_call
async def redis_status() -> Dict[str, Any]:
    """Per-user Redis status."""
    return format_response(await call_da_api("/api/redis/status"))


@mcp.tool()
@log_tool_call
async def redis_enable(confirm: bool = False) -> Dict[str, Any]:
    """Enable Redis for the current/impersonated user.

    Args:
        confirm: Required.
    """
    rejected = guard_confirm("redis_enable", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/redis/enable", method="POST"))


@mcp.tool()
@log_tool_call
async def redis_disable(confirm: bool = False) -> Dict[str, Any]:
    """Disable Redis.

    Args:
        confirm: Required.
    """
    rejected = guard_confirm("redis_disable", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/redis/disable", method="POST"))


@mcp.tool()
@log_tool_call
async def web_protect_list() -> Dict[str, Any]:
    """Directory password-protection list."""
    return format_response(await call_da_api("/api/web-protect/list"))
