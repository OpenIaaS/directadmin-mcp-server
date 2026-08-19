"""Login keys and one-time login URLs — the recommended way to grant API access."""

from __future__ import annotations

from typing import Any, Dict, Optional

from da import call_da_api
from mcp_instance import mcp
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def login_keys_list() -> Dict[str, Any]:
    """List login keys on the current account."""
    return format_response(await call_da_api("/api/login-keys/keys"))


@mcp.tool()
@log_tool_call
async def login_keys_commands() -> Dict[str, Any]:
    """Commands a login key can be restricted to."""
    return format_response(await call_da_api("/api/login-keys/commands"))


@mcp.tool()
@log_tool_call
async def login_keys_get(key_id: str) -> Dict[str, Any]:
    """Get one login key.

    Args:
        key_id: Key id.
    """
    return format_response(await call_da_api(f"/api/login-keys/keys/{key_id}"))


@mcp.tool()
@log_tool_call
async def login_keys_history(key_id: str) -> Dict[str, Any]:
    """Usage history for a login key.

    Args:
        key_id: Key id.
    """
    return format_response(await call_da_api(f"/api/login-keys/keys/{key_id}/history"))


@mcp.tool()
@log_tool_call
async def login_keys_create(payload: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Create a login key. Prefer IP-restricted, command-restricted keys.

    Args:
        payload: Create body as documented by /api/login-keys/keys (name, expires, ips, commands, …).
        confirm: Required.
    """
    rejected = guard_confirm("login_keys_create", confirm, extra=True)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/login-keys/keys", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def login_keys_update(
    key_id: str, payload: Dict[str, Any], confirm: bool = False
) -> Dict[str, Any]:
    """Update a login key.

    Args:
        key_id: Key id.
        payload: Patch body.
        confirm: Required.
    """
    rejected = guard_confirm("login_keys_update", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(f"/api/login-keys/keys/{key_id}", method="PATCH", data=payload)
    )


@mcp.tool()
@log_tool_call
async def login_keys_delete(key_id: str, confirm: bool = False) -> Dict[str, Any]:
    """Delete a login key.

    Args:
        key_id: Key id.
        confirm: Required.
    """
    rejected = guard_confirm("login_keys_delete", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api(f"/api/login-keys/keys/{key_id}", method="DELETE"))


@mcp.tool()
@log_tool_call
async def login_urls_list() -> Dict[str, Any]:
    """List one-time / login-as URLs."""
    return format_response(await call_da_api("/api/login-keys/urls"))


@mcp.tool()
@log_tool_call
async def login_urls_create(payload: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Create a login URL.

    Args:
        payload: Create body.
        confirm: Required.
    """
    rejected = guard_confirm("login_urls_create", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/login-keys/urls", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def login_urls_delete(url_id: str, confirm: bool = False) -> Dict[str, Any]:
    """Delete a login URL.

    Args:
        url_id: URL id.
        confirm: Required.
    """
    rejected = guard_confirm("login_urls_delete", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api(f"/api/login-keys/urls/{url_id}", method="DELETE"))


@mcp.tool()
@log_tool_call
async def login_url_one_shot(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Create a one-shot panel login URL (POST /api/login/url).

    Args:
        payload: Optional body the panel expects.
    """
    return format_response(await call_da_api("/api/login/url", method="POST", data=payload or {}))
