"""Security helpers: URL validation, IP checks, auth, rate limit, audit, policy."""

from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import os
import re
import threading
import time
from collections import defaultdict, deque
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

from config import settings

logger = logging.getLogger(__name__)

_SENSITIVE_KEY = re.compile(
    r"(pass(word|wd)?|secret|token|key|authorization|cookie|login_key|certificate|private)$",
    re.IGNORECASE,
)

IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
)
IPV6_CANDIDATE = re.compile(r"^[0-9a-fA-F:]+$")

DESTRUCTIVE_HINTS = (
    "unblock",
    "allow",
    "ignore",
    "create",
    "upload",
    "change",
    "delete",
    "remove",
    "destroy",
    "restart",
    "stop",
    "kill",
    "deny",
    "flush",
    "disable",
    "uninstall",
    "drop",
    "convert",
    "suspend",
    "execute",
    "update-run",
    "obtain",
    "provision",
    "reissue",
    "modify",
    "assign",
    "restore",
)

_EMAIL_LOCAL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}$")
_CRON_FIELD = re.compile(r"^[\d*/,\-]+$")
_SERVICE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class SecurityError(Exception):
    """Raised when a request is rejected on security grounds."""


def redact(value: Any) -> Any:
    """Recursively hide secret-looking fields."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if _SENSITIVE_KEY.search(str(key)):
                out[key] = "********"
            else:
                out[key] = redact(item)
        return out
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def validate_da_url(url: str, allow_insecure_http: bool = False) -> str:
    """Reject anything that is not a remote DirectAdmin HTTP(S) origin."""
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"https", "http"}:
        raise SecurityError("DA_URL must use http or https")
    if parsed.scheme == "http" and not allow_insecure_http:
        raise SecurityError(
            "DA_URL must be https:// (set DA_ALLOW_INSECURE_HTTP=true only for labs)"
        )
    if not parsed.hostname:
        raise SecurityError("DA_URL is missing a hostname")
    if parsed.username or parsed.password:
        raise SecurityError("Do not embed credentials in DA_URL")
    host = parsed.hostname
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_unspecified:
            raise SecurityError("DA_URL host cannot be 0.0.0.0 / ::")
    except ValueError:
        pass
    return url.rstrip("/")


def validate_ip(value: str) -> str:
    """Accept a single IPv4/IPv6 address or CIDR. Reject anything else."""
    if not value or not isinstance(value, str):
        raise SecurityError("IP address is required")
    candidate = value.strip()
    if "/" in candidate:
        network = ipaddress.ip_network(candidate, strict=False)
        if network.prefixlen < 8:
            raise SecurityError("CIDR prefix is too broad (minimum /8)")
        return str(network)
    return str(ipaddress.ip_address(candidate))


def validate_username(value: str) -> str:
    if not value or not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", value):
        raise SecurityError("Invalid username")
    return value


def validate_impersonate(value: Optional[str]) -> str:
    """Empty is fine (admin context). Otherwise a DirectAdmin username."""
    if not value:
        return ""
    return validate_username(value)


def validate_domain(value: str) -> str:
    if not value or len(value) > 253:
        raise SecurityError("Invalid domain")
    if not re.fullmatch(r"[A-Za-z0-9.*-]+(\.[A-Za-z0-9.*-]+)+", value):
        raise SecurityError("Invalid domain")
    return value.lower()


def validate_email_local(value: str) -> str:
    """Local-part of an email address (before @)."""
    if not value or not _EMAIL_LOCAL.fullmatch(value):
        raise SecurityError("Invalid mailbox local-part")
    if ".." in value:
        raise SecurityError("Invalid mailbox local-part")
    return value


def validate_email(value: str) -> str:
    if not value or "@" not in value or len(value) > 254:
        raise SecurityError("Invalid email")
    local, _, domain = value.partition("@")
    validate_email_local(local)
    validate_domain(domain)
    return f"{local}@{domain.lower()}"


def validate_fs_path(value: str) -> str:
    """Reject path traversal and NUL bytes. DirectAdmin paths are POSIX-style."""
    if not value or not isinstance(value, str):
        raise SecurityError("Path is required")
    if "\x00" in value:
        raise SecurityError("Invalid path")
    if any(part == ".." for part in value.replace("\\", "/").split("/")):
        raise SecurityError("Path traversal is not allowed")
    return value


def validate_service(value: str) -> str:
    """systemd / DirectAdmin service name (httpd, php-fpm83, named, …)."""
    if not value or not _SERVICE.fullmatch(value):
        raise SecurityError("Invalid service name")
    return value


def validate_backup_file(value: str) -> str:
    """Backup filename as listed by the panel. No traversal."""
    if not value or not isinstance(value, str) or len(value) > 255:
        raise SecurityError("Invalid backup file")
    if "\x00" in value:
        raise SecurityError("Invalid backup file")
    if any(part == ".." for part in value.replace("\\", "/").split("/")):
        raise SecurityError("Path traversal is not allowed")
    return value


def validate_query(value: str, max_len: int = 128) -> str:
    if value is None:
        raise SecurityError("Query is required")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > max_len:
        raise SecurityError("Invalid query")
    if "\x00" in cleaned:
        raise SecurityError("Invalid query")
    return cleaned


def sanitize_comment(value: str, max_len: int = 80) -> str:
    """Strip shell-ish characters from CSF comments."""
    cleaned = re.sub(r"[^A-Za-z0-9._\-\s]", "", value or "")
    cleaned = " ".join(cleaned.split())[:max_len]
    return cleaned or "directadmin-mcp"


def validate_cron_field(value: str) -> str:
    if not value or not _CRON_FIELD.fullmatch(value) or len(value) > 32:
        raise SecurityError("Invalid cron field")
    return value


def ip_in_cidrs(client_ip: str, cidrs: Iterable[str]) -> bool:
    if not cidrs:
        return True
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def tool_permitted(name: str) -> bool:
    denylist = settings.tool_denylist
    allowlist = settings.tool_allowlist
    for rule in denylist:
        if name == rule or name.startswith(rule):
            return False
    if not allowlist:
        return True
    return any(name == rule or name.startswith(rule) for rule in allowlist)


# First matching rule wins. Reads, SSL reissue, and CSF unblock stay ungated.
_CAPABILITY_EXACT: dict[str, str] = {
    "users_create": "ENABLE_ACCOUNT_WRITE",
    "users_delete": "ENABLE_ACCOUNT_WRITE",
    "users_suspend": "ENABLE_ACCOUNT_WRITE",
    "users_unsuspend": "ENABLE_ACCOUNT_WRITE",
    "users_modify": "ENABLE_ACCOUNT_WRITE",
    "users_change_password": "ENABLE_ACCOUNT_WRITE",
    "users_change_creator": "ENABLE_ACCOUNT_WRITE",
    "users_convert_to_reseller": "ENABLE_ACCOUNT_WRITE",
    "resellers_create": "ENABLE_ACCOUNT_WRITE",
    "resellers_convert_to_user": "ENABLE_ACCOUNT_WRITE",
    "admins_create": "ENABLE_ACCOUNT_WRITE",
    "login_keys_create": "ENABLE_ACCOUNT_WRITE",
    "login_keys_update": "ENABLE_ACCOUNT_WRITE",
    "login_keys_delete": "ENABLE_ACCOUNT_WRITE",
    "login_urls_create": "ENABLE_ACCOUNT_WRITE",
    "login_urls_delete": "ENABLE_ACCOUNT_WRITE",
    "cb_run": "ENABLE_CUSTOMBUILD",
    "cb_options_update": "ENABLE_CUSTOMBUILD",
    "cb_kill": "ENABLE_CUSTOMBUILD",
    "system_packages_update_run": "ENABLE_OS_UPDATES",
    "system_update_directadmin": "ENABLE_OS_UPDATES",
    "system_set_update_channel": "ENABLE_OS_UPDATES",
    "system_restart_directadmin": "ENABLE_SERVICE_CONTROL",
    "plugins_install_url": "ENABLE_PLUGIN_WRITE",
    "plugins_activate": "ENABLE_PLUGIN_WRITE",
    "plugins_deactivate": "ENABLE_PLUGIN_WRITE",
    "plugins_update": "ENABLE_PLUGIN_WRITE",
    "plugins_delete": "ENABLE_PLUGIN_WRITE",
    "backups_restore": "ENABLE_BACKUP_RESTORE",
    "da_config_local_update": "ENABLE_CONFIG_WRITE",
    "da_config_local_patch": "ENABLE_CONFIG_WRITE",
    "hostname_change": "ENABLE_CONFIG_WRITE",
    "timezone_set": "ENABLE_CONFIG_WRITE",
    "email_server_config_update": "ENABLE_CONFIG_WRITE",
    "email_outbound_filter_update": "ENABLE_CONFIG_WRITE",
    "db_server_config_update": "ENABLE_CONFIG_WRITE",
    "license_update_key": "ENABLE_CONFIG_WRITE",
    "csf_disable": "ENABLE_CSF_DISABLE",
    "da_execute": "ENABLE_EXECUTE",
}

_DELETE_MARKERS = ("_delete", "_remove", "_destroy", "_drop", "_trash", "uninstall")
_SERVICE_MARKERS = ("_restart", "_stop", "_start", "_reload", "_kill")
_FM_WRITE_PREFIXES = ("fm_", "filemanager_")


def capability_for(tool_name: str) -> Optional[str]:
    """Which ENABLE_* flag must be on, or None if the tool is always allowed."""
    if tool_name in _CAPABILITY_EXACT:
        return _CAPABILITY_EXACT[tool_name]
    if tool_name.startswith("cl_"):
        return "ENABLE_CLOUDLINUX"
    if tool_name.startswith(("csf_", "bfm_", "firewall_")):
        if tool_name == "csf_disable":
            return "ENABLE_CSF_DISABLE"
        return None if settings.ENABLE_CSF else "ENABLE_CSF"
    if any(tool_name.startswith(prefix) for prefix in _FM_WRITE_PREFIXES):
        if tool_name in {
            "fm_list",
            "fm_tree",
            "fm_disk_usage",
            "fm_search_files",
            "fm_search_text",
            "fm_trash",
        }:
            return None
        return "ENABLE_FILEMANAGER_WRITE"
    if tool_name.startswith("services_") and any(marker in tool_name for marker in _SERVICE_MARKERS):
        return "ENABLE_SERVICE_CONTROL"
    if any(marker in tool_name for marker in _DELETE_MARKERS):
        return "ENABLE_DELETE"
    if tool_name.endswith("_kill") or "_kill_" in tool_name:
        return "ENABLE_DELETE"
    return None


def capability_enabled(flag: str) -> bool:
    return bool(getattr(settings, flag, False))


def capability_denied(tool_name: str) -> Optional[dict]:
    flag = capability_for(tool_name)
    if not flag or capability_enabled(flag):
        return None
    return {
        "success": False,
        "error": True,
        "denied_by": flag,
        "message": (
            f"'{tool_name}' is disabled ({flag}=false). "
            "This is the default so a rogue agent cannot delete or rewrite "
            "the box. Set the flag in .env if you really want this class of action."
        ),
    }


def _approval_token() -> str:
    token = settings.APPROVAL_TOKEN
    return token.get_secret_value() if hasattr(token, "get_secret_value") else str(token or "")


def confirm_accepted(confirm: Any) -> tuple[bool, str]:
    """confirm=true is enough only when APPROVAL_TOKEN is unset."""
    token = _approval_token()
    if token:
        if confirm is True or confirm is False or confirm is None:
            return False, (
                "APPROVAL_TOKEN is set. confirm=true is not enough — ask the "
                "human to paste the token into confirm=."
            )
        if constant_time_token_match(str(confirm).strip(), token):
            return True, ""
        return False, "Approval token does not match. Do not retry with a guess."
    if confirm is True:
        return True, ""
    return False, ""


def needs_confirm(tool_name: str, extra_flag: bool = False) -> bool:
    if not settings.REQUIRE_CONFIRM:
        return False
    lowered = tool_name.lower()
    if extra_flag:
        return True
    return any(hint in lowered for hint in DESTRUCTIVE_HINTS)


def confirm_or_reject(tool_name: str, confirm: Any, extra_flag: bool = False) -> Optional[dict]:
    if not needs_confirm(tool_name, extra_flag=extra_flag):
        return None
    ok, detail = confirm_accepted(confirm)
    if ok:
        return None
    if detail:
        return {
            "success": False,
            "error": True,
            "needs_confirm": True,
            "needs_approval_token": bool(_approval_token()),
            "message": f"'{tool_name}' is a destructive action. {detail}",
        }
    return {
        "success": False,
        "error": True,
        "needs_confirm": True,
        "message": (
            f"'{tool_name}' is a destructive action. "
            "Re-run with confirm=true after the operator has approved it. "
            "Do not set confirm=true yourself."
        ),
    }


class RateLimiter:
    """Simple sliding-window limiter (per-process). Evicts idle identities."""

    def __init__(self, per_minute: int) -> None:
        self.per_minute = per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, identity: str) -> bool:
        if self.per_minute <= 0:
            return True
        now = time.time()
        window = 60.0
        with self._lock:
            if len(self._hits) > 2048:
                stale = [
                    key
                    for key, bucket in self._hits.items()
                    if not bucket or now - bucket[-1] > window
                ]
                for key in stale:
                    del self._hits[key]
            bucket = self._hits[identity]
            while bucket and now - bucket[0] > window:
                bucket.popleft()
            if len(bucket) >= self.per_minute:
                return False
            bucket.append(now)
            return True


rate_limiter = RateLimiter(settings.RATE_LIMIT_PER_MINUTE)


def write_audit(event: str, **fields: Any) -> None:
    """Append one JSON line. Never write secrets."""
    path = settings.AUDIT_LOG
    if not path:
        return
    os.makedirs(os.path.dirname(path) or "logs", exist_ok=True)
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event,
        **redact(fields),
    }
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str) + "\n")
    except OSError as exc:
        logger.warning("audit log write failed: %s", exc)


def constant_time_token_match(provided: Optional[str], expected: str) -> bool:
    if not expected:
        return False
    if not provided:
        return False
    token = provided.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if len(token) != len(expected):
        return hmac.compare_digest(token[:64].ljust(64), expected[:64].ljust(64)) and False
    return hmac.compare_digest(token, expected)
