"""Shared tool helpers."""

from __future__ import annotations

import functools
import inspect
import logging
from typing import Any, Callable, Dict, Optional, TypeVar, cast

from da import DirectAdminError
from idempotency import check_idempotency, store_idempotency
from security import (
    backup_denied,
    capability_denied,
    confirm_or_reject,
    current_idem,
    current_reason,
    reason_denied,
    redact,
    sanitize_reason,
    tool_permitted,
    window_denied,
    write_audit,
)
from truncate import cap_payload

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=Callable)


def format_response(data: Any) -> Dict[str, Any]:
    if isinstance(data, dict) and data.get("error") is True:
        return data
    capped, truncated = cap_payload(data)
    payload: Dict[str, Any] = {"success": True, "data": capped}
    if truncated:
        payload["truncated"] = True
        payload["message"] = "Response truncated for the model. Full event is in the audit log."
    return payload


def format_error(message: str, **extra: Any) -> Dict[str, Any]:
    payload = {"success": False, "error": True, "message": message}
    payload.update(extra)
    return payload


def log_tool_call(func: T) -> T:
    if "confirm" in getattr(func, "__annotations__", {}):
        func.__annotations__["confirm"] = Any

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any):
        name = func.__name__
        reason = kwargs.pop("reason", "") or current_reason.get()
        idem_key = kwargs.pop("idempotency_key", "") or current_idem.get()
        backup_confirmed = kwargs.pop("backup_confirmed", False)

        if not tool_permitted(name):
            write_audit("tool_denied", tool=name)
            return format_error(f"Tool '{name}' is blocked by TOOL_ALLOWLIST/TOOL_DENYLIST")

        gated = capability_denied(name)
        if gated:
            write_audit("tool_capability_denied", tool=name, flag=gated.get("denied_by"))
            return gated

        closed = window_denied(name)
        if closed:
            write_audit("tool_window_denied", tool=name)
            return closed

        needed = reason_denied(name, reason)
        if needed:
            write_audit("tool_reason_denied", tool=name)
            return needed

        backed = backup_denied(name, backup_confirmed)
        if backed:
            write_audit("tool_backup_denied", tool=name)
            return backed

        sig = inspect.signature(func)
        try:
            bound = sig.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            safe = redact(dict(bound.arguments))
            if isinstance(safe.get("confirm"), str) and len(str(safe["confirm"])) > 8:
                safe["confirm"] = "********"
        except Exception:
            safe = {"_": "unbound"}
        if reason:
            safe["reason"] = sanitize_reason(reason)

        cached, idem_err = check_idempotency(str(idem_key or ""), name, safe)
        if idem_err:
            return idem_err
        if cached is not None:
            write_audit("tool_idempotent", tool=name, reason=safe.get("reason", ""))
            return cached

        write_audit("tool_call", tool=name, args=safe, reason=safe.get("reason", ""))
        logger.info("tool %s args=%s", name, safe)
        try:
            result = await func(*args, **kwargs)
            if isinstance(result, dict) and result.get("success") is True:
                capped, truncated = cap_payload(result.get("data"))
                result = dict(result)
                result["data"] = capped
                if truncated:
                    result["truncated"] = True
                    result.setdefault(
                        "message",
                        "Response truncated for the model. Full event is in the audit log.",
                    )
                    write_audit("tool_truncated", tool=name)
            write_audit("tool_ok", tool=name)
            store_idempotency(str(idem_key or ""), name, safe, result)
            return result
        except DirectAdminError as exc:
            logger.error("DirectAdmin error in %s: %s", name, exc)
            write_audit("tool_da_error", tool=name, message=str(exc), status=exc.status_code)
            return exc.as_dict()
        except Exception as exc:
            logger.exception("Unhandled error in %s", name)
            write_audit("tool_error", tool=name, type=type(exc).__name__)
            return format_error(str(exc), type=type(exc).__name__)

    return cast(T, wrapper)


def guard_confirm(tool_name: str, confirm: Any, extra: bool = False) -> Optional[Dict[str, Any]]:
    return confirm_or_reject(tool_name, confirm, extra_flag=extra)
