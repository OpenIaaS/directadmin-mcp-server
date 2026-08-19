"""Cap tool results so a BFM dump cannot flood the model (or inject from logs)."""

from __future__ import annotations

import json
from typing import Any, Dict, Tuple

from config import settings


def _size(value: Any) -> int:
    try:
        return len(json.dumps(value, default=str))
    except (TypeError, ValueError):
        return len(str(value))


def cap_payload(value: Any, budget: int | None = None) -> Tuple[Any, bool]:
    limit = budget if budget is not None else settings.MAX_RESPONSE_CHARS
    if _size(value) <= limit:
        return value, False
    return _trim(value, limit), True


def _trim(value: Any, budget: int) -> Any:
    if isinstance(value, str):
        if len(value) <= budget:
            return value
        return value[: max(0, budget - 32)] + "…[truncated]"
    if isinstance(value, list):
        kept = []
        used = 2
        for item in value:
            piece, _ = cap_payload(item, max(200, budget // 4))
            extra = _size(piece) + 1
            if used + extra > budget and kept:
                break
            kept.append(piece)
            used += extra
        if len(kept) < len(value):
            kept.append(f"…[{len(value) - len(kept)} more items truncated]")
        return kept
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        used = 2
        for key, item in value.items():
            piece, _ = cap_payload(item, max(200, budget // 3))
            extra = _size({key: piece})
            if used + extra > budget and out:
                out["_truncated"] = True
                break
            out[key] = piece
            used += extra
        return out
    return value
