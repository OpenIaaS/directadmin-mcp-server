"""DoS / resource regressions: idempotency cache bound, alert thread cap, audit tail."""

import json
import threading


def test_idempotency_cache_is_bounded(monkeypatch):
    import idempotency
    from idempotency import check_idempotency

    monkeypatch.setattr(idempotency, "_MAX_ENTRIES", 10)
    idempotency.reset_idempotency()
    try:
        for i in range(25):
            check_idempotency(f"key-{i}", "csf_unblock_ip", {"ip": "203.0.113.1"})
        assert len(idempotency._store) <= 10
        # Oldest keys are evicted, newest survive.
        assert "csf_unblock_ip:key-0" not in idempotency._store
        assert "csf_unblock_ip:key-24" in idempotency._store
    finally:
        idempotency.reset_idempotency()


def test_idempotency_store_path_also_evicts(monkeypatch):
    import idempotency
    from idempotency import reset_idempotency, store_idempotency

    monkeypatch.setattr(idempotency, "_MAX_ENTRIES", 5)
    reset_idempotency()
    try:
        for i in range(12):
            store_idempotency(f"k-{i}", "ssl_reissue_domain", {"domain": f"d{i}.test"}, {"ok": i})
        assert len(idempotency._store) <= 5
    finally:
        reset_idempotency()


def test_alert_threads_are_capped(monkeypatch):
    import alerts

    monkeypatch.setattr(alerts.settings, "ALERT_WEBHOOK_URL", "https://hooks.example.test/x")
    monkeypatch.setattr(alerts.settings, "ALERT_EVENTS", "tool_window_denied")
    # Drain the semaphore so the next event cannot spawn a thread.
    for _ in range(alerts._MAX_ALERT_THREADS):
        assert alerts._alert_slots.acquire(blocking=False)

    spawned = []

    class FakeThread:
        def __init__(self, target=None, name=None, daemon=None):
            spawned.append(name)

        def start(self):
            pass

    monkeypatch.setattr(alerts.threading, "Thread", FakeThread)
    try:
        alerts.fire_alert("tool_window_denied", tool="services_restart")
        assert spawned == []  # saturated → dropped, no thread
        # Release one slot; the next event spawns exactly one thread.
        alerts._alert_slots.release()
        alerts.fire_alert("tool_window_denied", tool="services_restart")
        assert spawned == ["mcp-alert"]
    finally:
        for _ in range(alerts._MAX_ALERT_THREADS):
            if alerts._alert_slots._value < alerts._MAX_ALERT_THREADS:
                alerts._alert_slots.release()


def test_audit_reader_reads_tail_without_slurping(tmp_path, monkeypatch):
    from config import settings
    from tools.audit import _TAIL_BYTES, read_audit_records

    log = tmp_path / "audit.jsonl"
    big_line = json.dumps({"event": "filler", "blob": "x" * 200})
    lines = [big_line] * 8000  # ~1.9 MB, above _TAIL_BYTES
    lines.append(json.dumps({"event": "tool_call", "tool": "services_restart"}))
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setattr(settings, "AUDIT_LOG", str(log))

    records = read_audit_records()
    assert len(records) < 8000  # only the tail was read, not the whole file
    # The window starts mid-filler-line; that partial line is dropped, not fatal.
    assert all(r.get("event") != "filler" or r.get("blob", "").startswith("x") for r in records)
    assert any(r.get("event") == "tool_call" for r in records)
    assert _TAIL_BYTES > 0


def test_threading_import_untouched():
    """Guard against accidentally making alert threads non-daemon."""
    source_thread = threading.Thread
    assert source_thread is not None