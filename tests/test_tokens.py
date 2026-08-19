from tokens import (
    authenticate_bearer,
    hash_secret,
    helpdesk_write,
    profile_denied,
    reset_token_cache,
)


def test_hash_roundtrip():
    raw = "a" * 32
    digest = hash_secret(raw)
    assert digest.startswith("sha256:")
    assert authenticate_bearer("nope") is None


def test_named_token_is_the_actor(tmp_path, monkeypatch):
    from config import settings

    raw = "helpdesk-secret-token-value-32b"
    path = tmp_path / "tokens.json"
    path.write_text(
        '{"tokens":[{"name":"helpdesk","profile":"helpdesk","hash":"%s"}]}' % hash_secret(raw)
    )
    monkeypatch.setattr(settings, "MCP_TOKENS_FILE", str(path))
    monkeypatch.setattr(settings, "MCP_AUTH_TOKEN", type(settings.MCP_AUTH_TOKEN)(""))
    reset_token_cache()
    record = authenticate_bearer("Bearer " + raw)
    assert record is not None
    assert record.name == "helpdesk"
    assert record.profile == "helpdesk"
    reset_token_cache()


def test_helpdesk_profile_allows_ssl_and_blocks_delete():
    assert helpdesk_write("ssl_reissue_domain") is True
    assert profile_denied("ssl_reissue_domain", "helpdesk") is None
    assert profile_denied("ip_block_reason", "readonly") is None
    denied = profile_denied("ssl_reissue_domain", "readonly")
    assert denied and denied["denied_by"].startswith("profile:")
    assert profile_denied("users_delete", "helpdesk") is not None
    assert profile_denied("csf_disable", "operator") is not None
    assert profile_denied("ssl_reissue_domain", "break-glass") is None
