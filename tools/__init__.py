"""Auto-load every tool module so @mcp.tool registrations run."""

from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import List

logger = logging.getLogger(__name__)

# Load order: curated first, generic catalog last
_PREFERRED = [
    "common",
    "ssl_certs",
    "csf_firewall",
    "brute_force",
    "accounts",
    "packages",
    "ip_manager",
    "dns_admin",
    "domains",
    "mailboxes",
    "email",
    "hosting",
    "backups",
    "system",
    "services",
    "server_settings",
    "login_keys",
    "sessions",
    "security_center",
    "databases",
    "filemanager",
    "custombuild",
    "plugins",
    "wordpress",
    "git_deploy",
    "search",
    "catalog",
]


def load_all_tools() -> List[str]:
    loaded: List[str] = []
    seen = set()

    for name in _PREFERRED:
        if _import(f"tools.{name}"):
            loaded.append(name)
            seen.add(name)

    import tools as pkg

    for module in pkgutil.iter_modules(pkg.__path__):
        if module.name in seen or module.name.startswith("_"):
            continue
        if _import(f"tools.{module.name}"):
            loaded.append(module.name)
            seen.add(module.name)
    return loaded


def _import(dotted: str) -> bool:
    try:
        importlib.import_module(dotted)
        logger.info("Loaded %s", dotted)
        return True
    except Exception as exc:  # pragma: no cover - surfaced in logs
        logger.error("Failed to load %s: %s", dotted, exc, exc_info=True)
        return False
