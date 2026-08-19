"""Git deploy applications."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_api
from mcp_instance import mcp
from security import validate_domain
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def git_list(domain: str) -> Dict[str, Any]:
    """List git applications on a domain.

    Args:
        domain: Domain.
    """
    domain = validate_domain(domain)
    return format_response(await call_da_api(f"/api/git/domain/{domain}"))


@mcp.tool()
@log_tool_call
async def git_get(uuid: str) -> Dict[str, Any]:
    """One git application.

    Args:
        uuid: Application uuid.
    """
    return format_response(await call_da_api(f"/api/git/uuid/{uuid}"))


@mcp.tool()
@log_tool_call
async def git_deploy(uuid: str, confirm: bool = False) -> Dict[str, Any]:
    """Trigger a git deploy.

    Args:
        uuid: Application uuid.
        confirm: Required.
    """
    rejected = guard_confirm("git_deploy", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api(f"/api/git/uuid/{uuid}/deploy", method="POST"))


@mcp.tool()
@log_tool_call
async def git_fetch(uuid: str) -> Dict[str, Any]:
    """Fetch remotes for a git application.

    Args:
        uuid: Application uuid.
    """
    return format_response(await call_da_api(f"/api/git/uuid/{uuid}/fetch", method="POST"))
