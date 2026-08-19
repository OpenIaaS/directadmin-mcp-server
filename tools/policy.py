"""Read-only view of capability flags — so the agent can explain a denial."""

from __future__ import annotations

from typing import Any, Dict

from config import settings
from mcp_instance import mcp
from security import capability_enabled, current_actor, current_profile, window_status
from tokens import load_tokens
from tools.common import format_response, log_tool_call

_FLAGS = (
    "ENABLE_DELETE",
    "ENABLE_ACCOUNT_WRITE",
    "ENABLE_FILEMANAGER_WRITE",
    "ENABLE_CUSTOMBUILD",
    "ENABLE_OS_UPDATES",
    "ENABLE_PLUGIN_WRITE",
    "ENABLE_BACKUP_RESTORE",
    "ENABLE_SERVICE_CONTROL",
    "ENABLE_CONFIG_WRITE",
    "ENABLE_DA_WRITE",
    "ENABLE_CLOUDLINUX",
    "ENABLE_CSF",
    "ENABLE_CSF_DISABLE",
    "ENABLE_EXECUTE",
    "REQUIRE_CONFIRM",
)


@mcp.tool()
@log_tool_call
async def policy_status() -> Dict[str, Any]:
    """Show which optional capabilities are on.

    A denied tool means the matching ENABLE_* flag is false. Do not try to
    bypass it. Ask the operator to flip the flag on the host if they want
    that class of action.
    """
    flags = {name: capability_enabled(name) for name in _FLAGS}
    token_set = bool(settings.APPROVAL_TOKEN.get_secret_value())
    return format_response(
        {
            "flags": flags,
            "approval_token_required": token_set,
            "actor": current_actor.get() or settings.MCP_ACTOR,
            "profile": current_profile.get() or settings.MCP_PROFILE,
            "tokens_loaded": [row.public() for row in load_tokens()],
            "require_reason": settings.REQUIRE_REASON,
            "require_backup_before": settings.REQUIRE_BACKUP_BEFORE,
            "window": window_status(),
            "default_profile": "helpdesk — SSL + CSF unblock + reads",
            "hint": (
                "Deletes, account writes, filemanager writes, CustomBuild, "
                "OS updates, plugin installs, backup restore, service control, "
                "config writes and generic da_api writes are off until enabled. "
                "Mutating families honour MAINTENANCE_WINDOW when set."
            ),
        }
    )
