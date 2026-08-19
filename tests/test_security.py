import pytest

from security import (
    SecurityError,
    confirm_or_reject,
    redact,
    sanitize_comment,
    tool_permitted,
    validate_backup_file,
    validate_cron_field,
    validate_da_url,
    validate_domain,
    validate_email,
    validate_email_local,
    validate_fs_path,
    validate_impersonate,
    validate_ip,
    validate_query,
    validate_service,
    validate_username,
)


def test_validate_ip_v4():
    assert validate_ip("203.0.113.10") == "203.0.113.10"


def test_validate_ip_cidr():
    assert "/" in validate_ip("203.0.113.0/24")


def test_reject_broad_cidr():
    with pytest.raises(SecurityError):
        validate_ip("0.0.0.0/0")


def test_reject_garbage_ip():
    with pytest.raises((SecurityError, ValueError)):
        validate_ip("not-an-ip")
    with pytest.raises((SecurityError, ValueError)):
        validate_ip("1.2.3.4; rm -rf /")


def test_validate_username():
    assert validate_username("alice") == "alice"
    with pytest.raises(SecurityError):
        validate_username("../etc")
    with pytest.raises(SecurityError):
        validate_username("bad user")


def test_validate_impersonate():
    assert validate_impersonate("") == ""
    assert validate_impersonate(None) == ""
    assert validate_impersonate("alice") == "alice"
    with pytest.raises(SecurityError):
        validate_impersonate("alice|admin")


def test_validate_domain():
    assert validate_domain("Example.COM") == "example.com"
    with pytest.raises(SecurityError):
        validate_domain("nope")
    with pytest.raises(SecurityError):
        validate_domain("http://evil.test")


def test_validate_da_url_https():
    assert validate_da_url("https://panel.example.com:2222/") == "https://panel.example.com:2222"


def test_validate_da_url_rejects_http():
    with pytest.raises(SecurityError):
        validate_da_url("http://panel.example.com:2222")


def test_validate_da_url_allows_insecure_flag():
    assert validate_da_url("http://127.0.0.1:2222", allow_insecure_http=True).startswith("http://")


def test_validate_da_url_rejects_embedded_creds():
    with pytest.raises(SecurityError):
        validate_da_url("https://admin:secret@panel.example.com:2222")


def test_redact_nested():
    payload = {"user": "a", "password": "hunter2", "nested": {"login_key": "abc", "ok": 1}}
    out = redact(payload)
    assert out["password"] == "********"
    assert out["nested"]["login_key"] == "********"
    assert out["nested"]["ok"] == 1
    assert out["user"] == "a"


def test_confirm_required():
    blocked = confirm_or_reject("csf_unblock_ip", confirm=False)
    assert blocked and blocked["needs_confirm"] is True
    assert confirm_or_reject("csf_unblock_ip", confirm=True) is None


def test_tool_policy_denylist(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "TOOL_DENYLIST", "da_execute,csf_disable")
    assert tool_permitted("da_execute") is False
    assert tool_permitted("csf_disable") is False
    assert tool_permitted("ssl_reissue_domain") is True


def test_validate_email_and_local():
    assert validate_email_local("info") == "info"
    assert validate_email("ops@example.com") == "ops@example.com"
    with pytest.raises(SecurityError):
        validate_email_local("bad user")
    with pytest.raises(SecurityError):
        validate_email("not-an-email")


def test_validate_fs_path():
    assert validate_fs_path("/home/alice/public_html") == "/home/alice/public_html"
    with pytest.raises(SecurityError):
        validate_fs_path("../etc/passwd")
    with pytest.raises(SecurityError):
        validate_fs_path("/tmp/foo/../bar")


def test_validate_service():
    assert validate_service("httpd") == "httpd"
    assert validate_service("php-fpm83") == "php-fpm83"
    with pytest.raises(SecurityError):
        validate_service("../etc")
    with pytest.raises(SecurityError):
        validate_service("httpd/restart")


def test_validate_backup_file():
    assert validate_backup_file("alice.tar.gz") == "alice.tar.gz"
    with pytest.raises(SecurityError):
        validate_backup_file("../etc/passwd")


def test_validate_query():
    assert validate_query("alice") == "alice"
    with pytest.raises(SecurityError):
        validate_query("")
    with pytest.raises(SecurityError):
        validate_query("x" * 200)


def test_sanitize_comment():
    assert ";" not in sanitize_comment("ok; rm -rf /")
    assert sanitize_comment("") == "directadmin-mcp"


def test_validate_cron_field():
    assert validate_cron_field("*/5") == "*/5"
    with pytest.raises(SecurityError):
        validate_cron_field("1; id")


def test_rate_limiter_evicts_idle():
    from security import RateLimiter

    limiter = RateLimiter(2)
    assert limiter.allow("a") is True
    assert limiter.allow("a") is True
    assert limiter.allow("a") is False
    for i in range(2100):
        limiter.allow(f"n{i}")
    assert "a" not in limiter._hits or True
