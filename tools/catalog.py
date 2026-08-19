"""Full New API coverage — list, describe, and call any documented /api endpoint."""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from typing import Any, Dict, Optional

from config import settings
from da import client
from mcp_instance import mcp
from security import SecurityError
from tools.common import format_error, format_response, guard_confirm, log_tool_call

_SPEC_PATH = os.path.join(os.path.dirname(__file__), "api_spec.json")
_PATH_PARAM = re.compile(r"\{([^}]+)\}")

# Paths the generic caller must never hit unless an explicit feature flag is on
_BLOCKED_PATHS = {
    "/api/execute",
    "/api/login",
    "/api/logout",
    "/api/lost-password/request",
    "/api/lost-password/confirm",
    "/api/terminal",
}


@lru_cache(maxsize=1)
def _spec() -> Dict[str, Any]:
    with open(_SPEC_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def _fill_path(template: str, path_params: Optional[Dict[str, str]]) -> str:
    params = path_params or {}

    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in params:
            raise SecurityError(f"Missing path parameter '{key}' for {template}")
        value = str(params[key])
        if "/" in value or ".." in value or value.startswith("."):
            raise SecurityError(f"Illegal path parameter '{key}'")
        return value

    return _PATH_PARAM.sub(repl, template)


def _lookup(method: str, path: str) -> Optional[Dict[str, Any]]:
    method = method.upper()
    for op in _spec()["operations"]:
        if op["method"] == method and op["path"] == path:
            return op
    return None


@mcp.tool()
@log_tool_call
async def da_list_endpoints(prefix: str = "/api/", method: str = "") -> Dict[str, Any]:
    """List New API operations bundled with this server (from official swagger).

    Args:
        prefix: Path prefix filter, e.g. /api/domain-tls or /api/users.
        method: Optional HTTP method filter (GET/POST/…).
    """
    method = method.upper()
    rows = []
    for op in _spec()["operations"]:
        if not op["path"].startswith(prefix):
            continue
        if method and op["method"] != method:
            continue
        rows.append(
            {
                "method": op["method"],
                "path": op["path"],
                "summary": op.get("summary") or "",
            }
        )
    return format_response({"count": len(rows), "endpoints": rows})


@mcp.tool()
@log_tool_call
async def da_describe_endpoint(method: str, path: str) -> Dict[str, Any]:
    """Show parameters for one New API operation.

    Args:
        method: HTTP method.
        path: Path template, e.g. /api/domain-tls/{domain}/provision-certs
    """
    op = _lookup(method, path)
    if not op:
        return format_error(f"Unknown operation {method.upper()} {path}")
    return format_response(op)


@mcp.tool()
@log_tool_call
async def da_api(
    method: str,
    path: str,
    path_params: Optional[Dict[str, str]] = None,
    query: Optional[Dict[str, Any]] = None,
    body: Optional[Dict[str, Any]] = None,
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Call any documented DirectAdmin New API endpoint.

    Use this for operations that do not yet have a dedicated curated tool.
    The path must exist in the bundled swagger. /api/execute is blocked unless
    ENABLE_EXECUTE=true.

    Args:
        method: GET POST PUT PATCH DELETE
        path: Template from da_list_endpoints (keep {placeholders}).
        path_params: Values for {placeholders}.
        query: Query string parameters.
        body: JSON body for non-GET requests.
        impersonate: Optional user to act as.
        confirm: Required for destructive methods / paths.
    """
    method = method.upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        return format_error("Unsupported method")
    if not path.startswith("/api/"):
        return format_error("Only /api/* New API paths are allowed")
    op = _lookup(method, path)
    if not op:
        return format_error(
            f"{method} {path} is not in the bundled DirectAdmin swagger. "
            "Check da_list_endpoints."
        )
    filled = _fill_path(path, path_params)
    if filled.rstrip("/") in _BLOCKED_PATHS or path.rstrip("/") in _BLOCKED_PATHS:
        if filled.rstrip("/") == "/api/execute" and settings.ENABLE_EXECUTE:
            rejected = guard_confirm("da_api", confirm, extra=True)
            if rejected:
                return rejected
        else:
            return format_error(
                f"{filled} is blocked. Set ENABLE_EXECUTE=true for /api/execute, "
                "or use a dedicated tool."
            )
    destructive = method in {"DELETE", "PUT", "PATCH"} or any(
        hint in path.lower()
        for hint in (
            "delete",
            "restart",
            "kill",
            "remove",
            "update-run",
            "obtain",
            "provision-certs",
        )
    )
    if destructive:
        rejected = guard_confirm("da_api", confirm, extra=True)
        if rejected:
            return rejected
    data = await client.request(
        filled,
        method=method,
        data=body if method != "GET" else None,
        params=query,
        impersonate=impersonate or None,
    )
    return format_response({"method": method, "path": filled, "result": data})


@mcp.tool()
@log_tool_call
async def da_legacy(
    command: str,
    method: str = "POST",
    data: Optional[Dict[str, Any]] = None,
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Call a legacy CMD_API_* / CMD_* endpoint.

    Only commands that start with CMD_API_ or CMD_ are accepted.

    Args:
        command: e.g. CMD_API_SHOW_ALL_USERS or /CMD_API_SSL
        method: GET or POST
        data: Form fields. json=yes is added automatically.
        impersonate: Optional user.
        confirm: Required for POST.
    """
    name = command.strip().lstrip("/")
    if not (name.startswith("CMD_API_") or name.startswith("CMD_")):
        return format_error("Only CMD_* / CMD_API_* commands are allowed")
    if any(bad in name.upper() for bad in ("CMD_API_LOGIN", "CMD_LOGIN", "CMD_LOGOUT")):
        return format_error("Login/logout commands are not allowed through the MCP")
    if method.upper() != "GET":
        rejected = guard_confirm("da_legacy", confirm, extra=True)
        if rejected:
            return rejected
    from da import call_da_legacy

    result = await call_da_legacy(
        name, method=method.upper(), data=data or {}, impersonate=impersonate or None
    )
    return format_response(result)


@mcp.tool()
@log_tool_call
async def da_ping() -> Dict[str, Any]:
    """Connectivity check — hits /api/version."""
    from da import call_da_api

    version = await call_da_api("/api/version")
    return format_response({"connected": True, "version": version})
