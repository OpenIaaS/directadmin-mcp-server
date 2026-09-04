"""Regression tests: path-component injection into DirectAdmin API paths.

Curated tools interpolate ids (cert_id, key_id, message_id, uuid, task…) into
f-string paths. Before 2.7.0 those ids were unvalidated, so a value like
"../../api/server-settings/directadmin-conf/local" was normalized by httpx
into a request against a completely different endpoint — bypassing the
ENABLE_DA_WRITE gate that curated paths are meant to enforce.
"""

import pytest

from security import SecurityError, validate_label, validate_path_segment


def test_validate_path_segment_accepts_panel_ids():
    assert validate_path_segment("1234") == "1234"
    assert validate_path_segment("9b2f5c1e-77") == "9b2f5c1e-77"
    assert validate_path_segment("user@example.com") == "user@example.com"


@pytest.mark.parametrize(
    "bad",
    [
        "../api/server-settings/directadmin-conf/local",
        "../../x",
        "a/b",
        "a\\b",
        "id?next=/api/x",
        "id#frag",
        "id&x=1",
        "id%2F..",
        "id x",
        "",
        ".",
        "..",
        None,
        "x" * 129,
    ],
)
def test_validate_path_segment_rejects_injection(bad):
    with pytest.raises(SecurityError):
        validate_path_segment(bad)


def test_validate_label_accepts_one_label():
    assert validate_label("shop") == "shop"
    assert validate_label("My-Shop") == "my-shop"


@pytest.mark.parametrize("bad", ["", "a_b", "a.b", "-lead", "trail-", "a b", "a/b", "x" * 64])
def test_validate_label_rejects(bad):
    with pytest.raises(SecurityError):
        validate_label(bad)


@pytest.mark.asyncio
async def test_vacation_set_rejects_path_traversal_in_user(tmp_path, monkeypatch):
    from config import settings
    from security import bind_request_context
    from tools.email import email_vacation_set

    monkeypatch.setattr(settings, "AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(settings, "REQUIRE_REASON", False)
    bind_request_context(profile="operator")
    result = await email_vacation_set(
        "example.com", "ops/../../api/server-settings/directadmin-conf/local", {}, confirm=True
    )
    assert result["success"] is False
    assert "mailbox local-part" in result["message"]


@pytest.mark.asyncio
async def test_wp_get_rejects_path_traversal(tmp_path, monkeypatch):
    from config import settings
    from tools.wordpress import wp_get

    monkeypatch.setattr(settings, "AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    result = await wp_get("../../../api/plugin-manager/plugins")
    assert result["success"] is False
    assert "WordPress location" in result["message"]


@pytest.mark.asyncio
async def test_sessions_destroy_rejects_path_injection(tmp_path, monkeypatch):
    from config import settings
    from security import bind_request_context
    from tools.sessions import sessions_destroy

    monkeypatch.setattr(settings, "AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(settings, "REQUIRE_REASON", False)
    monkeypatch.setattr(settings, "ENABLE_DELETE", True)
    bind_request_context(profile="operator")
    result = await sessions_destroy("x/../api/system-services-actions/service/httpd/stop", confirm=True)
    assert result["success"] is False
    assert "session id" in result["message"]


@pytest.mark.asyncio
async def test_maintenance_fix_rejects_path_traversal(tmp_path, monkeypatch):
    from config import settings
    from security import bind_request_context
    from tools.system import maintenance_fix

    monkeypatch.setattr(settings, "AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(settings, "REQUIRE_REASON", False)
    bind_request_context(profile="operator")
    result = await maintenance_fix("../../api/system-packages/update-run", confirm=True)
    assert result["success"] is False
    assert "maintenance task" in result["message"]


@pytest.mark.asyncio
async def test_db_repair_rejects_traversal(tmp_path, monkeypatch):
    from config import settings
    from security import bind_request_context
    from tools.databases import db_repair

    monkeypatch.setattr(settings, "AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(settings, "REQUIRE_REASON", False)
    bind_request_context(profile="operator")
    result = await db_repair("../../api/users/admin/config", confirm=True)
    assert result["success"] is False


@pytest.mark.asyncio
async def test_phpmyadmin_sso_rejects_traversal(tmp_path, monkeypatch):
    from config import settings
    from security import bind_request_context
    from tools.search import phpmyadmin_sso

    monkeypatch.setattr(settings, "AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    bind_request_context(profile="operator")
    # confirm=true: since the central gate (round 2) the confirm check fires
    # before the body, so the traversal path needs a confirmed call to reach it.
    result = await phpmyadmin_sso(
        "../../api/session/login-as/switch", confirm=True, reason="audit-regression-test"
    )
    assert result["success"] is False
    assert "database name" in result["message"]


@pytest.mark.asyncio
async def test_ssl_cert_files_rejects_traversal(tmp_path, monkeypatch):
    from config import settings
    from tools.ssl_certs import ssl_get_cert_files

    monkeypatch.setattr(settings, "AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    result = await ssl_get_cert_files("example.com", "../../api/server-tls/files")
    assert result["success"] is False


@pytest.mark.asyncio
async def test_da_legacy_rejects_dot_segments(tmp_path, monkeypatch):
    from config import settings
    from tools.catalog import da_legacy

    monkeypatch.setattr(settings, "AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    result = await da_legacy("CMD_API_../../CMD_API_SHOW_ALL_USERS", method="GET")
    assert result["success"] is False
    assert "traversal" in result["message"]


@pytest.mark.asyncio
async def test_subdomain_label_rejected(tmp_path, monkeypatch):
    from config import settings
    from security import bind_request_context
    from tools.domains import subdomains_create

    monkeypatch.setattr(settings, "AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(settings, "REQUIRE_REASON", False)
    bind_request_context(profile="operator")
    result = await subdomains_create("example.com", "../evil", confirm=True)
    assert result["success"] is False
    assert "subdomain label" in result["message"]


@pytest.mark.asyncio
async def test_call_plugin_never_retries_mutating_post():
    """A failed POST must not be resent raw: the first attempt may have applied."""
    from da import DirectAdminClient, DirectAdminError

    http = DirectAdminClient()
    calls = []

    async def fake_request(path, method="GET", **kwargs):
        calls.append((path, method))
        if len(calls) == 1:
            raise DirectAdminError("html skin returned garbage", status_code=500)
        return "raw text ok"

    http.request = fake_request  # type: ignore[method-assign]
    with pytest.raises(DirectAdminError):
        await http.call_plugin("/CMD_PLUGINS_ADMIN/csf/index.raw", data={"action": "kill"}, method="POST")
    assert calls == [("/CMD_PLUGINS_ADMIN/csf/index.raw", "POST")]

    calls.clear()
    result = await http.call_plugin("/CMD_PLUGINS_ADMIN/csf/index.raw", data=None, method="GET")
    assert result == "raw text ok"
    assert calls == [
        ("/CMD_PLUGINS_ADMIN/csf/index.raw", "GET"),
        ("/CMD_PLUGINS_ADMIN/csf/index.raw", "GET"),
    ]
    await http.aclose()