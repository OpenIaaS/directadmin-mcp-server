from pathlib import Path

from security import validate_ip
from tools.brute_force import records_for_ip


def test_unblock_rejects_non_ip():
    try:
        validate_ip("*; csf -x")
        raised = False
    except Exception:
        raised = True
    assert raised


def test_csf_module_documents_plugin_paths():
    src = (Path(__file__).resolve().parents[1] / "tools" / "csf_firewall.py").read_text()
    assert "/CMD_PLUGINS_ADMIN/csf/" in src
    assert "action=kill" in src or '"kill"' in src
    assert "csf_unblock_ip" in src


def test_bfm_records_from_login_failures():
    payload = {
        "LOGINFAILURES": {
            "data": {
                "0": {
                    "ip": "203.0.113.44",
                    "user": "alice",
                    "service": "dovecot",
                    "attempts": "18",
                    "log": "imap-login: Aborted login (auth failed): user=<alice>, rip=203.0.113.44",
                },
                "1": {
                    "ip": "198.51.100.9",
                    "user": "bob",
                    "service": "sshd",
                    "attempts": "40",
                },
            }
        }
    }
    rows = records_for_ip(payload, "203.0.113.44")
    assert rows
    assert rows[0]["service"] == "dovecot"
    assert rows[0]["user"] == "alice"
    assert "18 attempts" in rows[0]["summary"]
    assert "imap-login" in rows[0]["evidence"]
    assert records_for_ip(payload, "192.0.2.1") == []


def test_bfm_records_from_legacy_blocked_blob():
    payload = {
        "BLOCKEDIPS": {
            "203.0.113.44": "dateblocked=1710000000&info=dovecot%20bruteforce"
        }
    }
    rows = records_for_ip(payload, "203.0.113.44")
    assert rows
    assert rows[0]["dateblocked"] == "1710000000"
    assert "dovecot" in (rows[0]["evidence"] or "") or "dovecot" in (rows[0]["summary"] or "")
