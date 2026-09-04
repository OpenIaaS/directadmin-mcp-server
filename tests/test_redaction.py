"""The log formatter must never emit the approval token."""

from pydantic import SecretStr


def test_formatter_redacts_approval_token(monkeypatch):
    from config import _RedactingFormatter, settings

    secret = "super-secret-approval-token-value"
    monkeypatch.setattr(settings, "APPROVAL_TOKEN", SecretStr(secret))
    formatter = _RedactingFormatter("%(message)s")
    line = formatter.format(
        __import__("logging").LogRecord(
            "test", 20, "p", 1, f"confirm={secret} ok", (), None
        )
    )
    assert secret not in line
    assert "********" in line


def test_formatter_redacts_da_login_key(monkeypatch):
    import logging

    from config import _RedactingFormatter, settings

    monkeypatch.setattr(settings, "APPROVAL_TOKEN", SecretStr(""))
    key = "live-login-key-value"
    monkeypatch.setattr(settings, "DA_LOGIN_KEY", SecretStr(key))
    line = _RedactingFormatter("%(message)s").format(
        logging.LogRecord("t", 20, "p", 1, f"key={key}", (), None)
    )
    assert key not in line