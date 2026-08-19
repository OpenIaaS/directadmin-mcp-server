"""Named, hashed bearer tokens. The token name is the actor — not a spoofable header."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from config import settings

logger = logging.getLogger(__name__)

PROFILES = ("readonly", "helpdesk", "operator", "break-glass")

# Writes a helpdesk token may perform. Everything else stays read-only for them.
HELPDESK_WRITES = (
    "ssl_reissue",
    "ssl_admin_reissue",
    "ssl_set_",
    "ssl_server_enable",
    "ssl_create_csr",
    "ssl_install_self_signed",
    "ssl_upload",
    "csf_unblock",
    "csf_allow",
    "csf_ignore",
    "bfm_unblock",
    "bfm_skip",
    "firewall_unblock",
)

# Always allowed regardless of profile (investigation + policy).
ALWAYS_READ = (
    "policy_status",
    "audit_search",
    "audit_recent",
    "window_now",
    "inventory_list",
    "inventory_get",
    "inventory_this",
    "ip_block_reason",
    "bfm_ip_reason",
    "csf_ip_reason",
    "csf_search_ip",
    "csf_status",
    "da_ping",
    "da_list_endpoints",
    "da_describe_endpoint",
    "session_get",
    "propack_inventory",
    "cl_status",
)


@dataclass
class TokenRecord:
    name: str
    hash: str
    profile: str = "helpdesk"
    capabilities: List[str] = field(default_factory=list)

    def public(self) -> Dict[str, Any]:
        return {"name": self.name, "profile": self.profile, "hash": "sha256:********"}


def hash_secret(raw: str) -> str:
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _digest(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def hashes_equal(raw: str, stored: str) -> bool:
    expected = stored.split(":", 1)[1] if stored.startswith("sha256:") else stored
    return hmac.compare_digest(_digest(raw), expected)


def _load_file(path: str) -> List[TokenRecord]:
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    rows = payload.get("tokens", payload) if isinstance(payload, dict) else payload
    out: List[TokenRecord] = []
    for row in rows or []:
        name = str(row.get("name") or "").strip()
        digest = str(row.get("hash") or "").strip()
        profile = str(row.get("profile") or "helpdesk").strip()
        if not name or not digest:
            continue
        if profile not in PROFILES:
            profile = "helpdesk"
        out.append(
            TokenRecord(
                name=name,
                hash=digest,
                profile=profile,
                capabilities=list(row.get("capabilities") or []),
            )
        )
    return out


_cached: Optional[List[TokenRecord]] = None


def load_tokens() -> List[TokenRecord]:
    global _cached
    if _cached is not None:
        return _cached
    records: List[TokenRecord] = []
    path = (settings.MCP_TOKENS_FILE or "").strip()
    if path and os.path.isfile(path):
        try:
            records.extend(_load_file(path))
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            logger.error("MCP_TOKENS_FILE unreadable: %s", exc)
    legacy = settings.MCP_AUTH_TOKEN.get_secret_value()
    if legacy:
        records.append(
            TokenRecord(
                name=settings.MCP_ACTOR if settings.MCP_ACTOR != "unknown" else "legacy",
                hash=hash_secret(legacy),
                profile=settings.MCP_PROFILE,
            )
        )
    _cached = records
    return records


def reset_token_cache() -> None:
    global _cached
    _cached = None


def authenticate_bearer(provided: Optional[str]) -> Optional[TokenRecord]:
    if not provided:
        return None
    token = provided.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if not token:
        return None
    found: Optional[TokenRecord] = None
    for record in load_tokens():
        if hashes_equal(token, record.hash):
            found = record
            # keep scanning so timing does not leak the slot
    return found


def helpdesk_write(tool_name: str) -> bool:
    return any(tool_name == prefix or tool_name.startswith(prefix) for prefix in HELPDESK_WRITES)


def profile_denied(tool_name: str, profile: str) -> Optional[dict]:
    """Narrower than process ENABLE_*. A helpdesk token cannot grow into break-glass."""
    from security import capability_for, needs_confirm

    if tool_name in ALWAYS_READ or tool_name.startswith(("audit_", "inventory_")):
        return None
    profile = profile if profile in PROFILES else settings.MCP_PROFILE
    if profile == "break-glass":
        return None
    mutating = bool(capability_for(tool_name) or needs_confirm(tool_name) or helpdesk_write(tool_name))
    if profile == "readonly":
        if mutating:
            return _deny(tool_name, profile, "readonly token: reads + ip_block_reason only")
        return None
    if profile == "helpdesk":
        if not mutating:
            return None
        if helpdesk_write(tool_name):
            return None
        return _deny(tool_name, profile, "helpdesk token: SSL reissue + CSF/BFM unblock only")
    if profile == "operator":
        # Operator still cannot delete / execute unless process flags allow (checked earlier).
        if tool_name.startswith(("users_delete", "admins_create", "da_execute", "csf_disable")):
            return _deny(tool_name, profile, "operator token cannot delete accounts or disable CSF")
        return None
    return None


def _deny(tool_name: str, profile: str, message: str) -> dict:
    return {
        "success": False,
        "error": True,
        "denied_by": f"profile:{profile}",
        "message": f"'{tool_name}' is not allowed for this token ({message}).",
    }


def has_auth_configured() -> bool:
    return bool(load_tokens()) or settings.MCP_ALLOW_ANONYMOUS


if __name__ == "__main__":
    import secrets
    import sys

    raw = sys.argv[1] if len(sys.argv) > 1 else secrets.token_urlsafe(32)
    print(raw)
    print(hash_secret(raw))
