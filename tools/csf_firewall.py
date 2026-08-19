"""ConfigServer Security & Firewall (CSF/LFD) via the DirectAdmin plugin.

CSF is not part of the New JSON API. These tools talk to
`/CMD_PLUGINS_ADMIN/csf/` (admin plugin). The plugin must be installed.

Primary tool: csf_unblock_ip — removes permanent + temporary blocks and
optionally adds a temporary allow so the client can reconnect.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from config import settings
from da import DirectAdminError, client
from mcp_instance import mcp
from security import sanitize_comment, validate_ip
from tools.common import format_error, format_response, guard_confirm, log_tool_call
from tools.csf_reason import parse_csf_grep

CSF_PATHS = (
    "/CMD_PLUGINS_ADMIN/csf/index.raw",
    "/CMD_PLUGINS_ADMIN/csf/index.html",
    "/CMD_PLUGINS/csf/index.raw",
)


def _require_csf() -> Optional[Dict[str, Any]]:
    if not settings.ENABLE_CSF:
        return format_error(
            "CSF tools are disabled (ENABLE_CSF=false). Enable them only on boxes that run CSF."
        )
    return None


def _require_csf_disable() -> Optional[Dict[str, Any]]:
    blocked = _require_csf()
    if blocked:
        return blocked
    if not settings.ENABLE_CSF_DISABLE:
        return format_error(
            "csf_disable is blocked (ENABLE_CSF_DISABLE=false). "
            "Turning CSF off leaves the host unprotected."
        )
    return None


def _as_text(payload: Any) -> str:
    if payload is None:
        return ""
    if isinstance(payload, (bytes, bytearray)):
        return payload.decode("utf-8", errors="replace")
    if isinstance(payload, str):
        return payload
    return str(payload)


async def _csf_plugin(action: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload = {"action": action}
    if extra:
        payload.update({k: v for k, v in extra.items() if v is not None})

    last_error: Optional[Exception] = None
    for path in CSF_PATHS:
        try:
            result = await client.call_plugin(path, data=payload, method="POST")
            text = _as_text(result)
            lowered = text.lower() if isinstance(text, str) else ""
            if "configserver" not in lowered and "csf" not in lowered and "lfd" not in lowered:
                if isinstance(result, dict) and result:
                    return {"path": path, "action": action, "result": result}
            return {"path": path, "action": action, "result": result}
        except DirectAdminError as exc:
            last_error = exc
            continue
    raise DirectAdminError(
        "CSF plugin did not respond on any known path. "
        "Install ConfigServer Security & Firewall for DirectAdmin.",
        response_data=str(last_error) if last_error else None,
    )


@mcp.tool()
@log_tool_call
async def csf_search_ip(ip: str) -> Dict[str, Any]:
    """Search CSF/iptables/LFD for an IP (csf -g). Shows why it is blocked.

    Args:
        ip: IPv4 or IPv6 address.
    """
    blocked = _require_csf()
    if blocked:
        return blocked
    address = validate_ip(ip)
    data = await _csf_plugin("grep", {"ip": address})
    parsed = parse_csf_grep(data.get("result", data), address)
    return format_response({"ip": address, "reason": parsed["reason"], "parsed": parsed, "plugin": data})


@mcp.tool()
@log_tool_call
async def csf_ip_reason(ip: str) -> Dict[str, Any]:
    """Why CSF/LFD listed this IP (list + LFD comment). Safe to show an operator.

    Parses `csf -g` via the plugin. Typical comment:
    `lfd: (sshd) Failed SSH login … 8 in the last 3600 secs`.
    Pair with bfm_ip_reason or use ip_block_reason for both + a customer text.

    Args:
        ip: IPv4 or IPv6.
    """
    blocked = _require_csf()
    if blocked:
        return blocked
    address = validate_ip(ip)
    data = await _csf_plugin("grep", {"ip": address})
    parsed = parse_csf_grep(data.get("result", data), address)
    from tools.csf_reason import customer_messages

    return format_response(
        {
            "ip": address,
            "listed": parsed["listed"],
            "reason": parsed["reason"]
            or ("Not listed in CSF/LFD grep." if not parsed["listed"] else "Listed, no LFD comment."),
            "hits": parsed["hits"],
            "customer_message": customer_messages(address, csf=parsed),
        }
    )


@mcp.tool()
@log_tool_call
async def csf_unblock_ip(
    ip: str,
    also_allow: bool = False,
    allow_ttl_seconds: int = 3600,
    comment: str = "unblocked-via-directadmin-mcp",
    confirm: bool = False,
    reason: str = "",
    idempotency_key: str = "",
) -> Dict[str, Any]:
    """Unblock an IP in CSF/LFD (permanent deny + temporary ban).

    This is the primary 'unlock from firewall' action. It:
      1. Runs the plugin Quick Unblock (`action=kill`) — csf -dr + csf -tr + drop states
      2. Also sends `qrm` when the plugin supports it
      3. Optionally adds a temporary allow so the next connection is not re-banned

    Pair with bfm_unblock_ip if DirectAdmin Brute Force Monitor also listed the IP.

    Args:
        ip: IPv4 or IPv6 to unblock.
        also_allow: After unblock, temporarily whitelist the IP.
        allow_ttl_seconds: TTL for the optional temporary allow (default 1h).
        comment: Note stored next to the allow rule.
        confirm: Required.
    """
    blocked = _require_csf()
    if blocked:
        return blocked
    rejected = guard_confirm("csf_unblock_ip", confirm)
    if rejected:
        return rejected
    address = validate_ip(ip)
    if "/" in address:
        return format_error("Unblock accepts a single IP, not a CIDR")
    note = sanitize_comment(comment)

    steps: List[Dict[str, Any]] = []
    for action in ("kill", "qrm"):
        try:
            steps.append(await _csf_plugin(action, {"ip": address, "comment": note}))
        except DirectAdminError as exc:
            steps.append({"action": action, "error": str(exc), "status_code": exc.status_code})

    allow_result = None
    if also_allow:
        allow_result = await _csf_plugin(
            "temp",
            {
                "ip": address,
                "do": "allow",
                "timeout": str(max(60, min(allow_ttl_seconds, 86400))),
                "comment": note,
            },
        )

    return format_response(
        {
            "ip": address,
            "steps": steps,
            "temporary_allow": allow_result,
            "hint": "Also run bfm_unblock_ip if the panel Brute Force Monitor still lists this address.",
        }
    )


@mcp.tool()
@log_tool_call
async def csf_allow_ip(
    ip: str,
    comment: str = "allowed-via-directadmin-mcp",
    temporary: bool = False,
    ttl_seconds: int = 3600,
    confirm: bool = False,
) -> Dict[str, Any]:
    """Whitelist an IP in CSF (csf -a / temporary allow).

    Allowed IPs bypass closed ports but LFD can still block them unless ignored.

    Args:
        ip: IPv4, IPv6, or CIDR.
        comment: Note stored with the rule.
        temporary: Use a TTL instead of a permanent allow.
        ttl_seconds: Lifetime when temporary=true.
        confirm: Required.
    """
    blocked = _require_csf()
    if blocked:
        return blocked
    rejected = guard_confirm("csf_allow_ip", confirm)
    if rejected:
        return rejected
    address = validate_ip(ip)
    note = sanitize_comment(comment)
    if temporary:
        data = await _csf_plugin(
            "temp",
            {
                "ip": address,
                "do": "allow",
                "timeout": str(max(60, min(ttl_seconds, 86400))),
                "comment": note,
            },
        )
    else:
        data = await _csf_plugin("qallow", {"ip": address, "comment": note})
    return format_response(data)


@mcp.tool()
@log_tool_call
async def csf_deny_ip(
    ip: str,
    comment: str = "denied-via-directadmin-mcp",
    temporary: bool = False,
    ttl_seconds: int = 3600,
    confirm: bool = False,
) -> Dict[str, Any]:
    """Block an IP in CSF (csf -d / temporary deny).

    Args:
        ip: IPv4, IPv6, or CIDR.
        comment: Note stored with the rule.
        temporary: Use a TTL instead of a permanent deny.
        ttl_seconds: Lifetime when temporary=true.
        confirm: Required.
    """
    blocked = _require_csf()
    if blocked:
        return blocked
    rejected = guard_confirm("csf_deny_ip", confirm)
    if rejected:
        return rejected
    address = validate_ip(ip)
    note = sanitize_comment(comment)
    if temporary:
        data = await _csf_plugin(
            "temp",
            {
                "ip": address,
                "do": "deny",
                "timeout": str(max(60, min(ttl_seconds, 86400))),
                "comment": note,
            },
        )
    else:
        data = await _csf_plugin("qdeny", {"ip": address, "comment": note})
    return format_response(data)


@mcp.tool()
@log_tool_call
async def csf_ignore_ip(
    ip: str, comment: str = "ignored-via-directadmin-mcp", confirm: bool = False
) -> Dict[str, Any]:
    """Add an IP to csf.ignore so LFD never blocks it.

    Args:
        ip: IPv4, IPv6, or CIDR.
        comment: Note.
        confirm: Required.
    """
    blocked = _require_csf()
    if blocked:
        return blocked
    rejected = guard_confirm("csf_ignore_ip", confirm)
    if rejected:
        return rejected
    address = validate_ip(ip)
    return format_response(
        await _csf_plugin("qignore", {"ip": address, "comment": sanitize_comment(comment)})
    )


@mcp.tool()
@log_tool_call
async def csf_remove_allow(ip: str, confirm: bool = False) -> Dict[str, Any]:
    """Remove an IP from the CSF allow list (csf -ar).

    Args:
        ip: Address to remove.
        confirm: Required.
    """
    blocked = _require_csf()
    if blocked:
        return blocked
    rejected = guard_confirm("csf_remove_allow", confirm)
    if rejected:
        return rejected
    address = validate_ip(ip)
    return format_response(await _csf_plugin("qrmallow", {"ip": address}))


@mcp.tool()
@log_tool_call
async def csf_flush_temp(confirm: bool = False) -> Dict[str, Any]:
    """Flush all CSF temporary allow/deny rules (csf -tf).

    Args:
        confirm: Required.
    """
    blocked = _require_csf()
    if blocked:
        return blocked
    rejected = guard_confirm("csf_flush_temp", confirm)
    if rejected:
        return rejected
    return format_response(await _csf_plugin("flush"))


@mcp.tool()
@log_tool_call
async def csf_restart(also_lfd: bool = True, confirm: bool = False) -> Dict[str, Any]:
    """Restart CSF, and optionally LFD.

    Args:
        also_lfd: Restart both csf and lfd (csf -ra).
        confirm: Required.
    """
    blocked = _require_csf()
    if blocked:
        return blocked
    rejected = guard_confirm("csf_restart", confirm)
    if rejected:
        return rejected
    results = [await _csf_plugin("restart")]
    if also_lfd:
        try:
            results.append(await _csf_plugin("lfdrestart"))
        except DirectAdminError as exc:
            results.append({"action": "lfdrestart", "error": str(exc)})
    return format_response(results)


@mcp.tool()
@log_tool_call
async def csf_enable(confirm: bool = False) -> Dict[str, Any]:
    """Enable CSF (csf -e).

    Args:
        confirm: Required.
    """
    blocked = _require_csf()
    if blocked:
        return blocked
    rejected = guard_confirm("csf_enable", confirm)
    if rejected:
        return rejected
    return format_response(await _csf_plugin("enable"))


@mcp.tool()
@log_tool_call
async def csf_disable(confirm: bool = False) -> Dict[str, Any]:
    """Disable CSF (csf -x). Dangerous — the host is unprotected until re-enabled.

    Blocked unless ENABLE_CSF_DISABLE=true. Prefer csf_unblock_ip instead.

    Args:
        confirm: Required.
    """
    blocked = _require_csf_disable()
    if blocked:
        return blocked
    rejected = guard_confirm("csf_disable", confirm, extra=True)
    if rejected:
        return rejected
    return format_response(await _csf_plugin("disable"))


@mcp.tool()
@log_tool_call
async def csf_status() -> Dict[str, Any]:
    """Best-effort CSF plugin landing / status page (HTML or structured)."""
    blocked = _require_csf()
    if blocked:
        return blocked
    try:
        data = await _csf_plugin("")
    except DirectAdminError:
        data = await client.call_plugin(CSF_PATHS[1], data=None, method="GET")
    text = _as_text(data)
    snippet = text[:4000] if isinstance(text, str) else data
    running = (
        bool(re.search(r"csf.+running|Firewall.+Enabled|lfd.+running", text, re.I))
        if isinstance(text, str)
        else None
    )
    return format_response({"running_hint": running, "body": snippet})
