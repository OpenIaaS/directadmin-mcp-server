"""Domain + hostname TLS: list, issue, reissue, ACME, upload, self-signed.

Priority tools:
  ssl_reissue_domain     — Let's Encrypt / ZeroSSL re-provision for a domain
  ssl_reissue_server     — force-obtain the hostname (DirectAdmin) certificate
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from da import call_da_api, call_da_legacy
from mcp_instance import mcp
from security import validate_domain
from tools.common import format_error, format_response, guard_confirm, log_tool_call


def _imp(user: Optional[str]) -> Optional[str]:
    return user or None


@mcp.tool()
@log_tool_call
async def ssl_list_domain_certs(domain: str, impersonate: str = "") -> Dict[str, Any]:
    """List TLS certificates installed on a user domain.

    Args:
        domain: Fully-qualified domain (example.com).
        impersonate: Optional user to act as (admin login-as).
    """
    domain = validate_domain(domain)
    data = await call_da_api(
        f"/api/domain-tls/{domain}/certs",
        method="GET",
        impersonate=_imp(impersonate),
    )
    return format_response(data)


@mcp.tool()
@log_tool_call
async def ssl_get_domain_acme_config(domain: str, impersonate: str = "") -> Dict[str, Any]:
    """Read ACME (Let's Encrypt / ZeroSSL) configuration for a domain.

    Args:
        domain: Fully-qualified domain.
        impersonate: Optional user to act as.
    """
    domain = validate_domain(domain)
    data = await call_da_api(
        f"/api/domain-tls/{domain}/acme-config",
        method="GET",
        impersonate=_imp(impersonate),
    )
    return format_response(data)


@mcp.tool()
@log_tool_call
async def ssl_set_domain_acme_config(
    domain: str,
    enabled: bool = True,
    provider: str = "letsencrypt",
    key_type: str = "ec256",
    prefer_wildcard: bool = False,
    dns_provider: str = "",
    skip_dns_names: Optional[List[str]] = None,
    dns_environment: Optional[Dict[str, str]] = None,
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Update ACME settings for a domain before issuing or reissuing a cert.

    Args:
        domain: Fully-qualified domain.
        enabled: Whether ACME auto-management is on.
        provider: '' | letsencrypt | letsencrypt-staging | zerossl
        key_type: rsa2048 | rsa4096 | ec256 | ec384
        prefer_wildcard: Request *.domain when DNS challenge is available.
        dns_provider: Optional DNS plugin name (cloudflare, …) for DNS-01.
        skip_dns_names: Names that ACME should ignore.
        dns_environment: Provider env vars (tokens are redacted in logs).
        impersonate: Optional user to act as.
        confirm: Must be true — writes ACME secrets.
    """
    rejected = guard_confirm("ssl_set_domain_acme_config", confirm, extra=True)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    if provider not in {"", "letsencrypt", "letsencrypt-staging", "zerossl"}:
        return format_error("provider must be '', letsencrypt, letsencrypt-staging or zerossl")
    body = {
        "enabled": enabled,
        "provider": provider,
        "keyType": key_type,
        "preferWildcard": prefer_wildcard,
        "dnsProvider": dns_provider,
        "skipDNSNames": skip_dns_names or [],
        "dnsEnvironment": dns_environment or {},
    }
    data = await call_da_api(
        f"/api/domain-tls/{domain}/acme-config",
        method="PUT",
        data=body,
        impersonate=_imp(impersonate),
    )
    return format_response(data)


@mcp.tool()
@log_tool_call
async def ssl_reissue_domain(
    domain: str,
    impersonate: str = "",
    dry_run: bool = False,
    confirm: bool = False,
) -> Dict[str, Any]:
    """Reissue / provision the Let's Encrypt (or configured ACME) certificate for a domain.

    This is the primary 'renew/reissue SSL' action. It calls
    POST /api/domain-tls/{domain}/provision-certs (or the dry-run sibling).
    DirectAdmin must have ACME enabled for the domain — use ssl_get_domain_acme_config
    first if you are unsure. For hostname/server certs use ssl_reissue_server.

    Args:
        domain: Fully-qualified domain to reissue.
        impersonate: User that owns the domain (recommended for admin).
        dry_run: If true, validate only — do not hit the CA.
        confirm: Required unless dry_run is true.
    """
    if not dry_run:
        rejected = guard_confirm("ssl_reissue_domain", confirm)
        if rejected:
            return rejected
    domain = validate_domain(domain)
    path = (
        f"/api/domain-tls/{domain}/provision-certs-dry-run"
        if dry_run
        else f"/api/domain-tls/{domain}/provision-certs"
    )
    data = await call_da_api(path, method="POST", impersonate=_imp(impersonate))
    return format_response({"domain": domain, "dry_run": dry_run, "result": data})


@mcp.tool()
@log_tool_call
async def ssl_reissue_domain_legacy(
    domain: str,
    wildcard: bool = False,
    entries: Optional[List[str]] = None,
    keysize: str = "secp384r1",
    encryption: str = "sha256",
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Fallback Let's Encrypt request via legacy CMD_API_SSL (older DirectAdmin).

    Use ssl_reissue_domain first. This exists for panels that predate /api/domain-tls.

    Args:
        domain: Domain to issue.
        wildcard: Include *.domain (needs DNS challenge).
        entries: Extra hostnames (www, mail, …). Defaults to domain + www.domain.
        keysize: secp384r1 | ecdsa | 4096 | 2048
        encryption: sha256
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("ssl_reissue_domain_legacy", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    names = entries or [domain, f"www.{domain}"]
    if wildcard and f"*.{domain}" not in names:
        names.append(f"*.{domain}")
    payload = {
        "domain": domain,
        "action": "save",
        "type": "create",
        "request": "letsencrypt",
        "name": domain,
        "wildcard": "yes" if wildcard else "no",
        "keysize": keysize,
        "encryption": encryption,
        "background": "auto",
    }
    for index, name in enumerate(names):
        payload[f"le_select{index}"] = name
    data = await call_da_legacy(
        "CMD_API_SSL", method="POST", data=payload, impersonate=_imp(impersonate)
    )
    return format_response(data)


@mcp.tool()
@log_tool_call
async def ssl_delete_domain_cert(
    domain: str,
    cert_id: str,
    update_acme_skiplist: bool = False,
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Delete one certificate from a domain.

    Args:
        domain: Domain.
        cert_id: Certificate id from ssl_list_domain_certs.
        update_acme_skiplist: Let ACME manage this name again after delete.
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("ssl_delete_domain_cert", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    path = f"/api/domain-tls/{domain}/certs/{cert_id}"
    params = {"update-acme-skiplist": "true"} if update_acme_skiplist else None
    from da import client

    data = await client.request(
        path, method="DELETE", params=params, impersonate=_imp(impersonate)
    )
    return format_response(data)


@mcp.tool()
@log_tool_call
async def ssl_get_cert_files(
    domain: str, cert_id: str, impersonate: str = ""
) -> Dict[str, Any]:
    """Download certificate + chain + key files for a domain cert id.

    The private key is returned by DirectAdmin — treat the response as secret.

    Args:
        domain: Domain.
        cert_id: Certificate id.
        impersonate: Owning user.
    """
    domain = validate_domain(domain)
    data = await call_da_api(
        f"/api/domain-tls/{domain}/certs/{cert_id}/files",
        method="GET",
        impersonate=_imp(impersonate),
    )
    return format_response(data)


@mcp.tool()
@log_tool_call
async def ssl_upload_cert_files(
    domain: str,
    cert_id: str,
    certificate: str,
    key: str,
    chain: Optional[List[str]] = None,
    force: bool = False,
    dry_run: bool = False,
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Replace a domain certificate with uploaded PEM files.

    Args:
        domain: Domain.
        cert_id: Certificate id.
        certificate: PEM certificate body.
        key: PEM private key.
        chain: Optional intermediate PEM list.
        force: Allow a certificate that fails validation.
        dry_run: Validate only.
        impersonate: Owning user.
        confirm: Required unless dry_run.
    """
    if not dry_run:
        rejected = guard_confirm("ssl_upload_cert_files", confirm)
        if rejected:
            return rejected
    domain = validate_domain(domain)
    from da import client

    data = await client.request(
        f"/api/domain-tls/{domain}/certs/{cert_id}/files",
        method="PUT",
        data={"cert": certificate, "key": key, "chain": chain or []},
        params={
            "force": str(force).lower(),
            "dry-run": str(dry_run).lower(),
        },
        impersonate=_imp(impersonate),
    )
    return format_response(data)


@mcp.tool()
@log_tool_call
async def ssl_create_csr(
    domain: str, cert_id: str, common_name: str = "", impersonate: str = ""
) -> Dict[str, Any]:
    """Create a CSR for a domain certificate slot (commercial CA flow).

    Args:
        domain: Domain.
        cert_id: Certificate id.
        common_name: CN, defaults to the domain.
        impersonate: Owning user.
    """
    domain = validate_domain(domain)
    data = await call_da_api(
        f"/api/domain-tls/{domain}/certs/{cert_id}/create-csr",
        method="POST",
        data={"commonName": common_name or domain},
        impersonate=_imp(impersonate),
    )
    return format_response(data)


@mcp.tool()
@log_tool_call
async def ssl_install_self_signed(
    domain: str,
    cert_id: str,
    dns_names: Optional[List[str]] = None,
    key_type: str = "ec256",
    overwrite: bool = False,
    impersonate: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Install a self-signed certificate on a domain (lab / placeholder only).

    Args:
        domain: Domain.
        cert_id: Certificate id.
        dns_names: SANs. Defaults to [domain].
        key_type: rsa2048 | rsa4096 | ec256 | ec384
        overwrite: Replace existing material.
        impersonate: Owning user.
        confirm: Required.
    """
    rejected = guard_confirm("ssl_install_self_signed", confirm)
    if rejected:
        return rejected
    domain = validate_domain(domain)
    from da import client

    data = await client.request(
        f"/api/domain-tls/{domain}/certs/{cert_id}/install-self-signed",
        method="POST",
        data={"dnsNames": dns_names or [domain], "keyType": key_type},
        params={"overwrite": str(overwrite).lower()},
        impersonate=_imp(impersonate),
    )
    return format_response(data)


@mcp.tool()
@log_tool_call
async def ssl_server_status() -> Dict[str, Any]:
    """Hostname / DirectAdmin service TLS status (not a user domain)."""
    return format_response(await call_da_api("/api/server-tls/status"))


@mcp.tool()
@log_tool_call
async def ssl_server_certificate() -> Dict[str, Any]:
    """Read the current hostname certificate metadata."""
    return format_response(await call_da_api("/api/server-tls/certificate"))


@mcp.tool()
@log_tool_call
async def ssl_server_acme_config() -> Dict[str, Any]:
    """Read ACME configuration used for the server hostname certificate."""
    return format_response(await call_da_api("/api/server-tls/acme-config"))


@mcp.tool()
@log_tool_call
async def ssl_set_server_acme_config(
    account: str,
    enabled: bool = True,
    provider: str = "letsencrypt",
    key_type: str = "ec256",
    additional_domains: Optional[List[str]] = None,
    dns_provider: str = "",
    dns_environment: Optional[Dict[str, str]] = None,
    confirm: bool = False,
) -> Dict[str, Any]:
    """Update ACME settings for the DirectAdmin hostname certificate.

    Args:
        account: ACME account email.
        enabled: Enable ACME for the hostname.
        provider: '' | letsencrypt | letsencrypt-staging | zerossl
        key_type: rsa2048 | rsa4096 | ec256 | ec384
        additional_domains: Extra names on the hostname cert.
        dns_provider: Optional DNS-01 provider.
        dns_environment: Provider secrets.
        confirm: Required.
    """
    rejected = guard_confirm("ssl_set_server_acme_config", confirm, extra=True)
    if rejected:
        return rejected
    body = {
        "account": account,
        "enabled": enabled,
        "provider": provider,
        "keyType": key_type,
        "additionalDomains": additional_domains or [],
        "dnsProvider": dns_provider,
        "dnsEnvironment": dns_environment or {},
    }
    return format_response(await call_da_api("/api/server-tls/acme-config", method="PUT", data=body))


@mcp.tool()
@log_tool_call
async def ssl_reissue_server(confirm: bool = False) -> Dict[str, Any]:
    """Force-obtain / reissue the DirectAdmin hostname TLS certificate.

    Calls POST /api/server-tls/obtain. Use this when the panel hostname cert
    is expired or the hostname changed.

    Args:
        confirm: Required.
    """
    rejected = guard_confirm("ssl_reissue_server", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/server-tls/obtain", method="POST"))


@mcp.tool()
@log_tool_call
async def ssl_server_enable(force: bool = False, confirm: bool = False) -> Dict[str, Any]:
    """Enable TLS on the DirectAdmin service itself.

    Args:
        force: Force the switch even if a cert looks incomplete.
        confirm: Required.
    """
    rejected = guard_confirm("ssl_server_enable", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api("/api/server-tls/enable", method="POST", data={"force": force})
    )


@mcp.tool()
@log_tool_call
async def ssl_server_files() -> Dict[str, Any]:
    """Download the hostname certificate and key (secret)."""
    return format_response(await call_da_api("/api/server-tls/files"))


@mcp.tool()
@log_tool_call
async def ssl_server_upload_files(
    certificate: str, key: str, force: bool = False, confirm: bool = False
) -> Dict[str, Any]:
    """Replace the hostname certificate with uploaded PEM files.

    Args:
        certificate: PEM cert (+ optional chain).
        key: PEM private key.
        force: Allow an invalid cert.
        confirm: Required.
    """
    rejected = guard_confirm("ssl_server_upload_files", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api(
            "/api/server-tls/files",
            method="PUT",
            data={"data": {"certificate": certificate, "key": key}, "force": force},
        )
    )


@mcp.tool()
@log_tool_call
async def ssl_acme_dns_providers() -> Dict[str, Any]:
    """List ACME DNS-01 providers the panel knows about (Cloudflare, …)."""
    return format_response(await call_da_api("/api/session/acme-dns-providers"))


# ---------------------------------------------------------------------------
# Admin SSL (Pro Pack) — the Admin Level icon that reissues customer certs
# ---------------------------------------------------------------------------

_ADMIN_SSL_CMDS = ("CMD_API_ADMIN_SSL", "CMD_ADMIN_SSL")
_ADMIN_SSL_MAX_DOMAINS = 50


async def _admin_ssl(method: str, data: Optional[Dict[str, Any]] = None) -> Any:
    """Admin SSL is not in the New JSON API. Talk to CMD_(API_)ADMIN_SSL."""
    from da import DirectAdminError

    last: Optional[DirectAdminError] = None
    for command in _ADMIN_SSL_CMDS:
        try:
            return await call_da_legacy(command, method=method, data=data or {})
        except DirectAdminError as exc:
            last = exc
            if exc.status_code in {404, 405}:
                continue
            if exc.status_code in {301, 302}:
                raise DirectAdminError(
                    "Admin SSL redirected — Pro Pack missing or login-key cannot "
                    "call CMD_ADMIN_SSL. Grant the key that command.",
                    status_code=exc.status_code,
                ) from exc
            raise
    raise last or DirectAdminError(
        "Admin SSL is not available (CMD_ADMIN_SSL / CMD_API_ADMIN_SSL). "
        "This is a Pro Pack feature: Admin Level → Admin SSL."
    )


@mcp.tool()
@log_tool_call
async def ssl_admin_list() -> Dict[str, Any]:
    """List every user/domain certificate the Admin SSL page shows.

    This is the Admin Level → Admin SSL overview (CMD_ADMIN_SSL?json=yes).
    It is not in the New JSON API. Requires Pro Pack and a login key that
    is allowed to run CMD_ADMIN_SSL.

    Use this to see which customer domains are missing, expired, or valid
    before calling ssl_admin_reissue.
    """
    data = await _admin_ssl("GET")
    return format_response(data)


@mcp.tool()
@log_tool_call
async def ssl_admin_reissue(
    domains: List[str],
    wildcard: bool = False,
    confirm: bool = False,
) -> Dict[str, Any]:
    """Request Let's Encrypt certificates for selected customer domains.

    This is the Admin SSL icon action: POST CMD_ADMIN_SSL action=multiple.
    The panel queues ACME in the background (dataskq) — no impersonation.
    Prefer this when an operator says “reissue SSL for these clients”
    from the Admin SSL page.

    For a single domain on a modern panel, ssl_reissue_domain (New API,
    impersonate the owner) is more precise.

    Args:
        domains: Customer domain names as listed by ssl_admin_list (max 50).
        wildcard: Request *.domain (dns-01). Default is http-01 / per-host.
        confirm: Required.
    """
    rejected = guard_confirm("ssl_admin_reissue", confirm)
    if rejected:
        return rejected
    if not domains:
        return format_error("Provide at least one domain")
    if len(domains) > _ADMIN_SSL_MAX_DOMAINS:
        return format_error(
            f"Refusing more than {_ADMIN_SSL_MAX_DOMAINS} domains in one call "
            "(Let's Encrypt rate limits). Split the batch."
        )
    clean = [validate_domain(item) for item in domains]
    payload: Dict[str, Any] = {
        "action": "multiple",
        "request": "yourdomain",
        "wildcard": "yes" if wildcard else "no",
    }
    for index, name in enumerate(clean):
        payload[f"select{index}"] = name
    data = await _admin_ssl("POST", payload)
    return format_response(
        {
            "domains": clean,
            "wildcard": wildcard,
            "queued": True,
            "result": data,
            "hint": "Admin SSL writes a task; poll ssl_admin_list until the certs show as valid.",
        }
    )


@mcp.tool()
@log_tool_call
async def ssl_admin_flags() -> Dict[str, Any]:
    """Read admin_ssl_* and letsencrypt_* flags from directadmin.conf.

    These control the automatic Admin SSL poller (install-to-missing,
    replace-expired, cert-on-create). Change them with da_config_local_patch.
    """
    cfg = await call_da_api("/api/server-settings/directadmin-conf/active")
    if not isinstance(cfg, dict):
        return format_response(cfg)
    keys = (
        "admin_ssl_install_to_missing",
        "admin_ssl_replace_all_expired_invalid",
        "admin_ssl_check_retries",
        "admin_ssl_cert_on_create",
        "admin_ssl_cert_per_vh",
        "admin_ssl_default_wildcard",
        "admin_ssl_poll_frequency",
        "letsencrypt",
        "letsencrypt_max_requests_per_week",
    )
    picked = {key: cfg.get(key) for key in keys if key in cfg}
    if not picked:
        nested = cfg.get("data") or cfg.get("values") or {}
        if isinstance(nested, dict):
            picked = {key: nested.get(key) for key in keys if key in nested}
    return format_response({"flags": picked, "source": "directadmin.conf active"})

