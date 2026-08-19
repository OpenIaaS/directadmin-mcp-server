"""Short-lived idempotency keys so a retried SSL reissue / unblock is a no-op."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any, Dict, Optional, Tuple

from config import settings

_lock = threading.Lock()
_store: Dict[str, Dict[str, Any]] = {}


def _fingerprint(tool: str, args: Dict[str, Any]) -> str:
    skip = {"confirm", "reason", "idempotency_key", "approval"}
    material = {k: v for k, v in args.items() if k not in skip}
    blob = json.dumps({"tool": tool, "args": material}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _purge(now: float) -> None:
    ttl = settings.IDEMPOTENCY_TTL_SECONDS
    stale = [key for key, row in _store.items() if now - float(row.get("ts") or 0) > ttl]
    for key in stale:
        del _store[key]


def check_idempotency(key: str, tool: str, args: Dict[str, Any]) -> Tuple[Optional[dict], Optional[dict]]:
    """Return (cached_response, error). Both None means proceed."""
    token = (key or "").strip()
    if not token:
        return None, None
    if len(token) > 128:
        return None, {
            "success": False,
            "error": True,
            "message": "idempotency_key is too long",
        }
    now = time.time()
    digest = _fingerprint(tool, args)
    slot = f"{tool}:{token}"
    with _lock:
        _purge(now)
        row = _store.get(slot)
        if not row:
            _store[slot] = {"ts": now, "fingerprint": digest, "result": None}
            return None, None
        if row.get("fingerprint") != digest:
            return None, {
                "success": False,
                "error": True,
                "message": "idempotency_key reused with different arguments",
            }
        if row.get("result") is not None:
            cached = dict(row["result"])
            cached["idempotent_replay"] = True
            return cached, None
        return None, None


def store_idempotency(key: str, tool: str, args: Dict[str, Any], result: Any) -> None:
    token = (key or "").strip()
    if not token:
        return
    slot = f"{tool}:{token}"
    digest = _fingerprint(tool, args)
    with _lock:
        _store[slot] = {"ts": time.time(), "fingerprint": digest, "result": result}


def reset_idempotency() -> None:
    with _lock:
        _store.clear()
