from pathlib import Path

from security import validate_ip
from tools.brute_force import records_for_ip
from tools.csf_reason import customer_messages, parse_csf_grep


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


def test_csf_grep_parses_lfd_comment():
    html = """
    <pre>
    csf.tempban:
    203.0.113.44 # lfd: (sshd) Failed SSH login from 203.0.113.44 (BG/Bulgaria/-): 8 in the last 3600 secs - Wed Aug 19 22:00:00 2026
    DENYIN  203.0.113.44
    </pre>
    """
    parsed = parse_csf_grep(html, "203.0.113.44")
    assert parsed["listed"] is True
    assert parsed["hits"]
    assert parsed["hits"][0]["service"] == "sshd"
    assert parsed["hits"][0]["attempts"] == "8"
    assert "Failed SSH login" in (parsed["reason"] or "")
    assert parse_csf_grep(html, "192.0.2.1")["listed"] is False


def test_customer_message_has_bg_and_does_not_invent():
    empty = customer_messages("203.0.113.10")
    assert "не фигурира" in empty["bg"]
    assert "not listed" in empty["en"]

    csf = {
        "listed": True,
        "hits": [{"list": "temporary deny (LFD)", "service": "sshd", "attempts": "8", "comment": "lfd: (sshd)"}],
    }
    msg = customer_messages("203.0.113.10", csf=csf)
    assert "SSH" in msg["en"]
    assert "SSH" in msg["bg"]
    assert "/usr/local" not in msg["bg"]
    assert "временно" in msg["bg"]
