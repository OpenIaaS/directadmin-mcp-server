"""Fire-and-forget webhook for dangerous audit events."""

from __future__ import annotations

import json
import logging
import threading
from typing import Any, Dict
from urllib.error import URLError
from urllib.request import Request, urlopen

from config import VERSION, settings

logger = logging.getLogger(__name__)


def should_alert(event: str, tool: str = "") -> bool:
    configured = set(settings.alert_events)
    if event in configured:
        return True
    if tool and tool in configured:
        return True
    return False


def fire_alert(event: str, **fields: Any) -> None:
    url = (settings.ALERT_WEBHOOK_URL or "").strip()
    if not url or not should_alert(event, str(fields.get("tool") or "")):
        return
    payload: Dict[str, Any] = {
        "source": "directadmin-mcp",
        "version": VERSION,
        "event": event,
        **{k: v for k, v in fields.items() if k not in {"args", "result"}},
    }

    def _post() -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        req = Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=3) as resp:  # noqa: S310 — operator-configured webhook
                resp.read(256)
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            logger.warning("alert webhook failed: %s", exc)

    threading.Thread(target=_post, name="mcp-alert", daemon=True).start()
