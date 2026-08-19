"""Read-only hops inventory — which DA box this process talks to, and the fleet."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from config import settings
from mcp_instance import mcp
from tools.common import format_error, format_response, log_tool_call

try:
    import yaml  # type: ignore
except ImportError:  # stdlib-only fallback
    yaml = None


def _parse(text: str) -> Dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        data = json.loads(stripped)
        return data if isinstance(data, dict) else {"servers": data}
    if yaml is not None:
        data = yaml.safe_load(stripped) or {}
        return data if isinstance(data, dict) else {"servers": data}
    # Minimal YAML: key: value lines and a servers list of id: maps is not worth
    # a parser. Require JSON if PyYAML is missing.
    raise RuntimeError("Install pyyaml or use inventory.json")


def load_inventory() -> Dict[str, Any]:
    path = Path(settings.INVENTORY_FILE or "inventory.yaml")
    if not path.is_file():
        return {
            "hops": "local",
            "this": settings.MCP_SERVER_ID or "",
            "servers": [
                {
                    "id": settings.MCP_SERVER_ID or "this",
                    "da_url": settings.DA_URL,
                    "cloudlinux": settings.ENABLE_CLOUDLINUX,
                    "profile": settings.MCP_PROFILE,
                }
            ],
        }
    data = _parse(path.read_text(encoding="utf-8"))
    data.setdefault("this", settings.MCP_SERVER_ID or data.get("this") or "")
    return data


@mcp.tool()
@log_tool_call
async def inventory_list() -> Dict[str, Any]:
    """Fleet catalog on the hops host (no secrets). Who has CloudLinux, which profile."""
    return format_response(load_inventory())


@mcp.tool()
@log_tool_call
async def inventory_this() -> Dict[str, Any]:
    """The DirectAdmin box this MCP process is wired to."""
    data = load_inventory()
    this_id = data.get("this") or settings.MCP_SERVER_ID
    servers: List[Dict[str, Any]] = list(data.get("servers") or [])
    match = next((row for row in servers if str(row.get("id")) == str(this_id)), None)
    if match is None:
        match = {
            "id": this_id or "this",
            "da_url": settings.DA_URL,
            "cloudlinux": settings.ENABLE_CLOUDLINUX,
            "profile": settings.MCP_PROFILE,
        }
    return format_response(match)


@mcp.tool()
@log_tool_call
async def inventory_get(server_id: str) -> Dict[str, Any]:
    """Look up one server in the hops inventory.

    Args:
        server_id: id from inventory_list.
    """
    data = load_inventory()
    for row in data.get("servers") or []:
        if str(row.get("id")) == server_id.strip():
            return format_response(row)
    return format_error(f"No inventory entry '{server_id}'")
