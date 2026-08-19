from idempotency import check_idempotency, reset_idempotency, store_idempotency
from security import backup_denied, reason_denied
from truncate import cap_payload


def test_reason_required_for_unblock(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "REQUIRE_REASON", True)
    assert reason_denied("csf_unblock_ip", "") is not None
    assert reason_denied("csf_unblock_ip", "DA-1234 client locked out") is None
    assert reason_denied("users_list", "") is None
    assert reason_denied("csf_unblock_ip", "клиент е заключен от CSF") is None


def test_backup_before_account_write(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "REQUIRE_BACKUP_BEFORE", True)
    assert backup_denied("users_delete", False) is not None
    assert backup_denied("users_delete", True) is None
    assert backup_denied("csf_unblock_ip", False) is None


def test_idempotency_replays_same_args():
    reset_idempotency()
    args = {"ip": "203.0.113.44"}
    miss, err = check_idempotency("k1", "csf_unblock_ip", args)
    assert miss is None and err is None
    store_idempotency("k1", "csf_unblock_ip", args, {"success": True, "data": {"ok": 1}})
    hit, err = check_idempotency("k1", "csf_unblock_ip", args)
    assert err is None
    assert hit and hit.get("idempotent_replay") is True
    _, clash = check_idempotency("k1", "csf_unblock_ip", {"ip": "203.0.113.99"})
    assert clash and clash["error"] is True
    reset_idempotency()


def test_cap_payload_truncates_long_list():
    huge = {"rows": ["x" * 400 for _ in range(80)]}
    out, truncated = cap_payload(huge, budget=2000)
    assert truncated is True
    assert _small(out) <= 4000


def _small(value):
    import json

    return len(json.dumps(value, default=str))
