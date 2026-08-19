"""Read the structured MCP audit log. Answers 'who did what when'."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from config import settings
from mcp_instance import mcp
from security import validate_query, window_status
from tools.common import format_error, format_response, log_tool_call

_MAX = 200


def _parse_ts(value: str) -> Optional[datetime]:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def read_audit_records(limit: int = 5000) -> List[Dict[str, Any]]:
    path = settings.AUDIT_LOG
    if not path:
        return []
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        return []
    except OSError:
        return []
    records: List[Dict[str, Any]] = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


@mcp.tool()
@log_tool_call
async def audit_search(
    tool: str = "",
    actor: str = "",
    event: str = "",
    query: str = "",
    since: str = "",
    until: str = "",
    limit: int = 50,
) -> Dict[str, Any]:
    """Search the structured MCP audit log.

    Answers: which agent restarted which service, who triggered an update,
    whether a call was denied by policy or outside the maintenance window.

    Args:
        tool: Tool name or prefix (services_restart, ssl_).
        actor: Agent id (X-Agent-Id / MCP_ACTOR).
        event: tool_call, tool_ok, tool_denied, tool_window_denied, …
        query: Substring match on the redacted JSON line.
        since: ISO timestamp (inclusive).
        until: ISO timestamp (inclusive).
        limit: Max rows (1–200).
    """
    cap = max(1, min(int(limit or 50), _MAX))
    start = _parse_ts(since) if since else None
    end = _parse_ts(until) if until else None
    if since and start is None:
        return format_error("since must be an ISO timestamp")
    if until and end is None:
        return format_error("until must be an ISO timestamp")
    needle = validate_query(query, max_len=128) if query else ""
    tool_f = tool.strip()
    actor_f = actor.strip()
    event_f = event.strip()

    hits: List[Dict[str, Any]] = []
    for record in reversed(read_audit_records()):
        if tool_f and not str(record.get("tool", "")).startswith(tool_f):
            if tool_f not in json.dumps(record.get("args") or {}, default=str):
                continue
        if actor_f and record.get("actor") != actor_f:
            continue
        if event_f and record.get("event") != event_f:
            continue
        stamp = _parse_ts(str(record.get("ts") or ""))
        if start and stamp and stamp < start:
            continue
        if end and stamp and stamp > end:
            continue
        if needle and needle.lower() not in json.dumps(record, default=str).lower():
            continue
        hits.append(record)
        if len(hits) >= cap:
            break
    return format_response(
        {
            "count": len(hits),
            "events": hits,
            "window": window_status(),
            "hint": "Events are redacted. This is not SSH history — each line is one tool call.",
        }
    )


@mcp.tool()
@log_tool_call
async def audit_recent(limit: int = 20) -> Dict[str, Any]:
    """Last N audit events (newest first). Same log as audit_search."""
    return await audit_search(limit=limit)


@mcp.tool()
@log_tool_call
async def window_now() -> Dict[str, Any]:
    """Is the maintenance window open right now? Reads still work when it is closed."""
    return format_response(window_status())
