"""Domain, subdomain, pointer and redirect admin (legacy CMD_API_*)."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_legacy
from mcp_instance import mcp
from security import validate_domain, validate_username
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def domains_list_user(username: str = "") -> Dict[str, Any]:
    """List domains owned by a user (admin) or the current account.

    Args:
        username: Optional account. Empty = current session (CMD_API_SHOW_DOMAINS).
    """
    if username:
        username = validate_username(username)
        return format_response(
            await call_da_legacy(
                "CMD_API_SHOW_USER_DOMAINS", method="GET", data={"user": username}
            )
        )
    return format_response(await call_da_legacy("CMD_API_SHOW_DOMAINS", method="GET"))


@mcp.tool()
@log_tool_call
async def domains_create(
    domain: str,
    bandwidth: str = "unlimited",
    quota: str = "unlimited",
    ssl: bool = True,
    cgi: bool = True,
    php: bool = True,
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Create an additional domain on the current (or impersonated) user.

    Args:
        domain: FQDN to add.
        bandwidth: MB or 'unlimited'.
        quota: MB or 'unlimited'.
        ssl: Enable SSL for the domain.
        cgi: Enable CGI.
        php: Enable PHP.
        impersonate: Owning user (admin should set this).
        confirm: Required.
    """
    rejected = guard_confirm("domains_create", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    payload = {
        "action": "create",
        "domain": domain,
        "ubandwidth": "yes" if bandwidth == "unlimited" else "no",
        "bandwidth": "0" if bandwidth == "unlimited" else str(bandwidth),
        "uquota": "yes" if quota == "unlimited" else "no",
        "quota": "0" if quota == "unlimited" else str(quota),
        "ssl": "ON" if ssl else "OFF",
        "cgi": "ON" if cgi else "OFF",
        "php": "ON" if php else "OFF",
    }
    return format_response(
        await call_da_legacy(
            "CMD_API_DOMAIN",
            method="POST",
            data=payload,
            impersonate=impersonate or None,
        )
    )


@mcp.tool()
@log_tool_call
async def domains_delete(
    domain: str, impersonate: str = "", confirm: bool = False
) -> Dict[str, Any]:
    """Delete a domain from an account.

    Args:
        domain: Domain to remove.
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("domains_delete", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    payload = {"delete": "yes", "confirmed": "Confirm", "select0": domain}
    return format_response(
        await call_da_legacy(
            "CMD_API_DOMAIN",
            method="POST",
            data=payload,
            impersonate=impersonate or None,
        )
    )


@mcp.tool()
@log_tool_call
async def subdomains_list(domain: str, impersonate: str = "") -> Dict[str, Any]:
    """List subdomains of a domain.

    Args:
        domain: Parent domain.
        impersonate: Owning user.
    """
    domain = validate_domain(domain)
    return format_response(
        await call_da_legacy(
            "CMD_API_SUBDOMAINS",
            method="GET",
            data={"domain": domain},
            impersonate=impersonate or None,
        )
    )


@mcp.tool()
@log_tool_call
async def subdomains_create(
    domain: str, subdomain: str, impersonate: str = "", confirm: bool = False
) -> Dict[str, Any]:
    """Create a subdomain.

    Args:
        domain: Parent domain.
        subdomain: Left-most label only (e.g. 'shop', not shop.example.com).
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("subdomains_create", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    payload = {"action": "create", "domain": domain, "subdomain": subdomain.strip().lower()}
    return format_response(
        await call_da_legacy(
            "CMD_API_SUBDOMAINS",
            method="POST",
            data=payload,
            impersonate=impersonate or None,
        )
    )


@mcp.tool()
@log_tool_call
async def subdomains_delete(
    domain: str,
    subdomain: str,
    contents: bool = False,
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Delete a subdomain.

    Args:
        domain: Parent domain.
        subdomain: Label to remove.
        contents: Also delete files under the subdomain document root.
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("subdomains_delete", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    payload = {
        "action": "delete",
        "domain": domain,
        "select0": subdomain.strip().lower(),
        "contents": "yes" if contents else "no",
    }
    return format_response(
        await call_da_legacy(
            "CMD_API_SUBDOMAINS",
            method="POST",
            data=payload,
            impersonate=impersonate or None,
        )
    )


@mcp.tool()
@log_tool_call
async def domain_pointers_list(domain: str, impersonate: str = "") -> Dict[str, Any]:
    """List domain pointers (aliases) for a domain.

    Args:
        domain: Parent domain.
        impersonate: Owning user.
    """
    domain = validate_domain(domain)
    return format_response(
        await call_da_legacy(
            "CMD_API_DOMAIN_POINTER",
            method="GET",
            data={"domain": domain},
            impersonate=impersonate or None,
        )
    )


@mcp.tool()
@log_tool_call
async def domain_pointers_create(
    domain: str,
    from_domain: str,
    alias: bool = True,
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Add a domain pointer / alias.

    Args:
        domain: Existing parent domain.
        from_domain: New hostname that should point at the parent.
        alias: True = alias (same site), False = pointer (redirect).
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("domain_pointers_create", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    from_domain = validate_domain(from_domain)
    payload = {
        "action": "add",
        "domain": domain,
        "from": from_domain,
        "alias": "yes" if alias else "no",
    }
    return format_response(
        await call_da_legacy(
            "CMD_API_DOMAIN_POINTER",
            method="POST",
            data=payload,
            impersonate=impersonate or None,
        )
    )


@mcp.tool()
@log_tool_call
async def domain_pointers_delete(
    domain: str, pointer: str, impersonate: str = "", confirm: bool = False
) -> Dict[str, Any]:
    """Remove a domain pointer.

    Args:
        domain: Parent domain.
        pointer: Pointer hostname.
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("domain_pointers_delete", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    pointer = validate_domain(pointer)
    payload = {"delete": "yes", "domain": domain, "select0": pointer}
    return format_response(
        await call_da_legacy(
            "CMD_API_DOMAIN_POINTER",
            method="POST",
            data=payload,
            impersonate=impersonate or None,
        )
    )


@mcp.tool()
@log_tool_call
async def redirects_list(domain: str, impersonate: str = "") -> Dict[str, Any]:
    """List site redirects for a domain.

    Args:
        domain: Domain.
        impersonate: Owning user.
    """
    domain = validate_domain(domain)
    return format_response(
        await call_da_legacy(
            "CMD_API_REDIRECT",
            method="GET",
            data={"domain": domain},
            impersonate=impersonate or None,
        )
    )


@mcp.tool()
@log_tool_call
async def redirects_create(
    domain: str,
    path: str,
    destination: str,
    redirect_type: str = "301",
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Create a site redirect.

    Args:
        domain: Domain.
        path: Source path (e.g. /old).
        destination: Target URL.
        redirect_type: 301 | 302 | 303.
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("redirects_create", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    payload = {
        "action": "add",
        "domain": domain,
        "path": path,
        "url": destination,
        "type": redirect_type,
    }
    return format_response(
        await call_da_legacy(
            "CMD_API_REDIRECT",
            method="POST",
            data=payload,
            impersonate=impersonate or None,
        )
    )
