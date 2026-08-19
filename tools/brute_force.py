"""DirectAdmin Brute Force Monitor — native panel IP blocks (not CSF)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote_plus

from da import call_da_legacy
from mcp_instance import mcp
from security import validate_ip
from tools.common import format_response, guard_confirm, log_tool_call

# Evolution / Enhanced expose these tables via show= (DA 1.52+).
_BFM_TABLES = ("LOGINFAILURES", "IPS", "USERS", "BLOCKEDIPS", "SKIPLIST")
_REASON_KEYS = (
    "info",
    "log",
    "log_line",
    "text",
    "reason",
    "details",
    "message",
    "filter",
    "type",
    "service",
    "user",
    "username",
    "attempts",
    "count",
    "dateblocked",
    "date",
    "when",
)


def _norm_ip(value: Any) -> str:
    return str(value or "").strip().split("/")[0]


def _ip_matches(candidate: Any, address: str) -> bool:
    left = _norm_ip(candidate)
    return bool(left) and left == address


def _row_reason(row: Dict[str, Any]) -> Dict[str, Any]:
    slim = {key: row[key] for key in _REASON_KEYS if row.get(key) not in (None, "")}
    service = slim.get("service") or slim.get("type") or slim.get("filter")
    user = slim.get("user") or slim.get("username")
    attempts = slim.get("attempts") or slim.get("count")
    evidence = slim.get("log") or slim.get("log_line") or slim.get("info") or slim.get("text")
    summary_bits = []
    if attempts:
        summary_bits.append(f"{attempts} attempts")
    if service:
        summary_bits.append(f"via {service}")
    if user:
        summary_bits.append(f"as {user}")
    if evidence and evidence not in summary_bits:
        summary_bits.append(str(evidence))
    return {
        "service": service,
        "user": user,
        "attempts": attempts,
        "evidence": evidence,
        "dateblocked": slim.get("dateblocked") or slim.get("date") or slim.get("when"),
        "summary": " ".join(str(bit) for bit in summary_bits) if summary_bits else None,
        "raw": slim,
    }


def _parse_blocked_blob(value: str, address: str) -> Optional[Dict[str, Any]]:
    """1.2.3.4=dateblocked=123&info=dovecot%20bruteforce  (legacy blocked-ips.sh)."""
    text = unquote_plus(str(value))
    if address not in text:
        return None
    if text.startswith(address + "="):
        text = text[len(address) + 1 :]
    parsed = {k: v[-1] if v else "" for k, v in parse_qs(text, keep_blank_values=True).items()}
    if not parsed and text:
        parsed = {"info": text}
    parsed.setdefault("ip", address)
    return parsed


def records_for_ip(payload: Any, address: str, source: str = "bfm") -> List[Dict[str, Any]]:
    """Pull every BFM row that mentions this IP, from any JSON/legacy shape."""
    found: List[Dict[str, Any]] = []

    def walk(node: Any, table: str) -> None:
        if isinstance(node, dict):
            ip_val = node.get("ip") or node.get("IP") or node.get("rip") or node.get("source")
            keyed = any(_ip_matches(key, address) for key in node)
            valued = _ip_matches(ip_val, address)
            if keyed or valued:
                if keyed and len(node) <= 8 and not valued:
                    for key, item in node.items():
                        if _ip_matches(key, address):
                            if isinstance(item, dict):
                                row = {"ip": address, **item}
                            elif isinstance(item, str) and ("=" in item or "&" in item):
                                row = _parse_blocked_blob(f"{address}={item}", address) or {"ip": address, "info": item}
                            else:
                                row = {"ip": address, "info": item}
                            found.append({**_row_reason(row), "table": table, "source": source})
                    return
                row = dict(node)
                if not valued:
                    row["ip"] = address
                found.append({**_row_reason(row), "table": table, "source": source})
            for key, item in node.items():
                next_table = str(key) if str(key).isupper() else table
                if _ip_matches(key, address) and not isinstance(item, (dict, list)):
                    blob = _parse_blocked_blob(f"{address}={item}", address) if isinstance(item, str) else {"ip": address, "info": item}
                    if blob:
                        found.append({**_row_reason(blob), "table": next_table, "source": source})
                    continue
                walk(item, next_table)
        elif isinstance(node, list):
            for item in node:
                walk(item, table)
        elif isinstance(node, str) and address in node:
            blob = _parse_blocked_blob(node, address)
            if blob:
                found.append({**_row_reason(blob), "table": table, "source": source})

    walk(payload, source)
    return found


def _dedupe(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for row in rows:
        key = (row.get("table"), row.get("summary"), row.get("evidence"), row.get("service"), row.get("user"))
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


async def _bfm_get(extra: Optional[Dict[str, Any]] = None) -> Any:
    data = {"json": "yes"}
    if extra:
        data.update(extra)
    return await call_da_legacy("CMD_API_BRUTE_FORCE_MONITOR", method="GET", data=data)


@mcp.tool()
@log_tool_call
async def bfm_list(blocked_only: bool = True) -> Dict[str, Any]:
    """List Brute Force Monitor state (blocked IPs, failed logins).

    For one IP use bfm_ip_reason — that is the 'why was this blocked' view.

    Args:
        blocked_only: Hint for the client; the panel still returns the full JSON.
    """
    data = await _bfm_get()
    return format_response({"blocked_only": blocked_only, "result": data})


@mcp.tool()
@log_tool_call
async def bfm_ip_reason(ip: str) -> Dict[str, Any]:
    """Why Brute Force Monitor listed this IP (service, user, attempts, log line).

    Not in the New JSON API — uses CMD_API_BRUTE_FORCE_MONITOR (same data as
    Admin → Brute Force Monitor). Typical reasons: failed DA logins, Dovecot /
    Exim / SSH / FTP / WordPress wp-login, or 'Your IP is blacklisted'.

    Also run csf_search_ip — LFD often blocked the same address for a
    different reason.

    Args:
        ip: IPv4 or IPv6 to explain.
    """
    address = validate_ip(ip)
    rows: List[Dict[str, Any]] = []
    errors: List[str] = []

    try:
        rows.extend(records_for_ip(await _bfm_get(), address, "all"))
    except Exception as exc:
        errors.append(f"list: {exc}")

    for table in ("LOGINFAILURES", "BLOCKEDIPS"):
        try:
            payload = await _bfm_get({"show": table, "value": address})
            rows.extend(records_for_ip(payload, address, table))
        except Exception as exc:
            errors.append(f"{table}: {exc}")

    rows = _dedupe(rows)
    summaries = [row["summary"] for row in rows if row.get("summary")]
    blocked = any(
        (row.get("table") or "").upper() in {"BLOCKEDIPS", "BLOCKED_IPS"}
        or row.get("dateblocked")
        or (row.get("raw") or {}).get("dateblocked")
        for row in rows
    )
    return format_response(
        {
            "ip": address,
            "listed": bool(rows),
            "blocked": blocked,
            "reason": summaries[0] if summaries else (
                "No BFM evidence for this IP. Check csf_search_ip — CSF/LFD may hold the block."
            ),
            "events": rows,
            "tables": _BFM_TABLES,
            "errors": errors,
            "hint": (
                "Unblock with firewall_unblock_everywhere (CSF + BFM). "
                "Skip-list with bfm_skip_ip if it is a known-good customer."
            ),
        }
    )


@mcp.tool()
@log_tool_call
async def bfm_unblock_ip(ip: str, confirm: bool = False) -> Dict[str, Any]:
    """Remove an IP from DirectAdmin Brute Force Monitor blocks.

    Use together with csf_unblock_ip — an IP is often listed in BOTH places.

    Args:
        ip: IPv4 or IPv6 to unblock.
        confirm: Required.
    """
    rejected = guard_confirm("bfm_unblock_ip", confirm)
    if rejected:
        return rejected
    address = validate_ip(ip)
    attempts = []
    # Newer JSON-ish shape
    for payload in (
        {"action": "unblock", "ip": address, "json": "yes"},
        {"action": "remove", "ip": address, "json": "yes"},
        {"unblock": "yes", "select0": address, "json": "yes"},
    ):
        try:
            result = await call_da_legacy(
                "CMD_API_BRUTE_FORCE_MONITOR", method="POST", data=payload
            )
            attempts.append({"payload": {k: v for k, v in payload.items() if k != "json"}, "result": result})
            break
        except Exception as exc:  # try the next encoding
            attempts.append({"payload": payload, "error": str(exc)})
    return format_response({"ip": address, "attempts": attempts})


@mcp.tool()
@log_tool_call
async def bfm_skip_ip(ip: str, confirm: bool = False) -> Dict[str, Any]:
    """Add an IP to the BFM skip / never-block list.

    Args:
        ip: Address to skip.
        confirm: Required.
    """
    rejected = guard_confirm("bfm_skip_ip", confirm)
    if rejected:
        return rejected
    address = validate_ip(ip)
    data = await call_da_legacy(
        "CMD_API_BRUTE_FORCE_MONITOR",
        method="POST",
        data={"action": "skip", "ip": address, "json": "yes"},
    )
    return format_response(data)


@mcp.tool()
@log_tool_call
async def firewall_unblock_everywhere(
    ip: str,
    also_allow: bool = False,
    confirm: bool = False,
) -> Dict[str, Any]:
    """Unblock an IP in CSF *and* DirectAdmin Brute Force Monitor.

    This is the 'customer is locked out' button. It does not disable the firewall.

    Args:
        ip: IPv4 or IPv6.
        also_allow: Also add a temporary CSF allow (1 hour).
        confirm: Required.
    """
    rejected = guard_confirm("firewall_unblock_everywhere", confirm)
    if rejected:
        return rejected
    from tools.csf_firewall import csf_unblock_ip

    csf = await csf_unblock_ip(
        ip=ip, also_allow=also_allow, confirm=True  # already confirmed here
    )
    bfm = await bfm_unblock_ip(ip=ip, confirm=True)
    return format_response({"ip": ip, "csf": csf, "bfm": bfm})
