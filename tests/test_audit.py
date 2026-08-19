import json
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from security import (
    bind_request_context,
    parse_maintenance_window,
    sanitize_actor,
    window_denied,
    window_status,
    write_audit,
)


def test_sanitize_actor():
    assert sanitize_actor("helpdesk-bot") == "helpdesk-bot"
    assert sanitize_actor("claude@ops") == "claude@ops"
    assert sanitize_actor("rm -rf /") == "unknown"
    assert sanitize_actor("", "stdio-agent") == "stdio-agent"


def test_window_parser_weekday_hours():
    parsed = parse_maintenance_window("Mon-Fri 01:00-05:00 Europe/Sofia")
    assert parsed is not None
    assert parsed["days"] == [0, 1, 2, 3, 4]
    assert parsed["tz"] == "Europe/Sofia"


def test_window_open_and_closed(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "MAINTENANCE_WINDOW", "Tue 01:00-05:00 Europe/Sofia")
    monkeypatch.setattr(settings, "WINDOW_ENFORCE", True)
    inside = datetime(2026, 8, 18, 2, 30, tzinfo=ZoneInfo("Europe/Sofia"))
    outside = datetime(2026, 8, 18, 12, 0, tzinfo=ZoneInfo("Europe/Sofia"))
    assert window_status(inside)["open"] is True
    assert window_status(outside)["open"] is False
    assert window_denied("ssl_reissue_domain", now=outside) is None
    denied = window_denied("services_restart", now=outside)
    assert denied and denied["denied_by"] == "MAINTENANCE_WINDOW"
    assert window_denied("services_restart", now=inside) is None


def test_audit_line_includes_actor(tmp_path, monkeypatch):
    from config import settings

    log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(settings, "AUDIT_LOG", str(log))
    bind_request_context(actor="cursor-helpdesk", ip="127.0.0.1", request_id="abc123")
    write_audit("tool_call", tool="services_restart", args={"service": "httpd"})
    row = json.loads(log.read_text().splitlines()[-1])
    assert row["actor"] == "cursor-helpdesk"
    assert row["ip"] == "127.0.0.1"
    assert row["tool"] == "services_restart"
    assert row["args"]["service"] == "httpd"
    assert "password" not in json.dumps(row)


def test_audit_search_finds_restart(tmp_path, monkeypatch):
    from config import settings
    from tools.audit import read_audit_records

    log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(settings, "AUDIT_LOG", str(log))
    bind_request_context(actor="ops-bot", ip="10.0.0.2", request_id="r1")
    write_audit("tool_call", tool="services_restart", args={"service": "httpd"})
    write_audit("tool_ok", tool="services_restart")
    rows = [r for r in read_audit_records() if r.get("tool") == "services_restart"]
    assert rows
    assert rows[0]["actor"] == "ops-bot"


def test_audit_module_exists():
    src = (Path(__file__).resolve().parents[1] / "tools" / "audit.py").read_text()
    assert "audit_search" in src
    assert "window_now" in src
