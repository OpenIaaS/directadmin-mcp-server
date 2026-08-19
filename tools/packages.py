"""User and reseller packages."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_api, call_da_legacy
from mcp_instance import mcp
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def packages_user_list(package: str = "") -> Dict[str, Any]:
    """List user packages, or show one package.

    Args:
        package: Optional package name.
    """
    data = {"package": package} if package else {}
    return format_response(await call_da_legacy("CMD_API_PACKAGES_USER", method="GET", data=data))


@mcp.tool()
@log_tool_call
async def packages_reseller_list(package: str = "") -> Dict[str, Any]:
    """List reseller packages (legacy), or one package.

    Args:
        package: Optional package name.
    """
    data = {"package": package} if package else {}
    return format_response(
        await call_da_legacy("CMD_API_PACKAGES_RESELLER", method="GET", data=data)
    )


@mcp.tool()
@log_tool_call
async def packages_reseller_new_api(package: str = "") -> Dict[str, Any]:
    """Reseller packages via the New API.

    Args:
        package: Optional package name for /api/reseller-packages/{package}.
    """
    path = f"/api/reseller-packages/{package}" if package else "/api/reseller-packages"
    return format_response(await call_da_api(path))


@mcp.tool()
@log_tool_call
async def packages_user_delete(package: str, confirm: bool = False) -> Dict[str, Any]:
    """Delete a user package.

    Args:
        package: Package name.
        confirm: Required.
    """
    rejected = guard_confirm("packages_user_delete", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_legacy(
            "CMD_API_PACKAGES_USER",
            method="POST",
            data={"delete": "yes", "delete0": package},
        )
    )


@mcp.tool()
@log_tool_call
async def packages_user_save(
    name: str,
    bandwidth: str = "unlimited",
    quota: str = "unlimited",
    vdomains: str = "unlimited",
    nemails: str = "unlimited",
    mysql: str = "unlimited",
    php: str = "ON",
    ssl: str = "ON",
    cgi: str = "ON",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Create or overwrite a user package.

    Args:
        name: Package name.
        bandwidth: MB or unlimited.
        quota: MB or unlimited.
        vdomains: Domain limit or unlimited.
        nemails: Mailbox limit or unlimited.
        mysql: Database limit or unlimited.
        php: ON | OFF
        ssl: ON | OFF
        cgi: ON | OFF
        confirm: Required.
    """
    rejected = guard_confirm("packages_user_save", confirm)
    if rejected:
        return rejected
    payload = {
        "add": "Save",
        "packagename": name,
        "bandwidth": "0" if bandwidth == "unlimited" else bandwidth,
        "ubandwidth": "yes" if bandwidth == "unlimited" else "no",
        "quota": "0" if quota == "unlimited" else quota,
        "uquota": "yes" if quota == "unlimited" else "no",
        "vdomains": "0" if vdomains == "unlimited" else vdomains,
        "uvdomains": "yes" if vdomains == "unlimited" else "no",
        "nemails": "0" if nemails == "unlimited" else nemails,
        "unemails": "yes" if nemails == "unlimited" else "no",
        "mysql": "0" if mysql == "unlimited" else mysql,
        "umysql": "yes" if mysql == "unlimited" else "no",
        "php": php,
        "ssl": ssl,
        "cgi": cgi,
    }
    return format_response(await call_da_legacy("CMD_API_PACKAGES_USER", method="POST", data=payload))
