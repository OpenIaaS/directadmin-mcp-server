import ast
import json
from pathlib import Path

import pytest

from security import SecurityError
from tools.catalog import _fill_path

_SPEC_PATH = Path(__file__).resolve().parents[1] / "tools" / "api_spec.json"


def _spec():
    return json.loads(_SPEC_PATH.read_text())


def _lookup(method: str, path: str):
    method = method.upper()
    for op in _spec()["operations"]:
        if op["method"] == method and op["path"] == path:
            return op
    return None


def test_spec_has_domain_tls_and_server_tls():
    ops = _spec()["operations"]
    paths = {o["path"] for o in ops}
    assert "/api/domain-tls/{domain}/provision-certs" in paths
    assert "/api/server-tls/obtain" in paths
    assert len(ops) >= 300


def test_lookup():
    op = _lookup("POST", "/api/domain-tls/{domain}/provision-certs")
    assert op is not None
    assert op["method"] == "POST"


def test_fill_path():
    assert (
        _fill_path("/api/domain-tls/{domain}/certs/{id}", {"domain": "ex.com", "id": "1"})
        == "/api/domain-tls/ex.com/certs/1"
    )


def test_fill_path_rejects_traversal():
    with pytest.raises(SecurityError):
        _fill_path("/api/users/{username}/config", {"username": "../admin"})
    with pytest.raises(SecurityError):
        _fill_path("/api/users/{username}/config", {"username": "a/b"})


def test_fill_path_encodes_url_meta_characters():
    """A path parameter must not be able to split the URL with ? # & or spaces."""
    filled = _fill_path(
        "/api/users/{username}/config", {"username": "ad?min&x=1#frag ment"}
    )
    assert filled == "/api/users/ad%3Fmin%26x%3D1%23frag%20ment/config"
    assert "?" not in filled and "#" not in filled and "&" not in filled


def test_fill_path_keeps_ascii_identifiers_readable():
    filled = _fill_path("/api/users/{username}/config", {"username": "alice-01"})
    assert filled == "/api/users/alice-01/config"


def test_tools_json_in_sync_with_registry():
    """docs/tools.json must list exactly the registered tools (no drift)."""
    doc = json.loads((_SPEC_PATH.parent.parent / "docs" / "tools.json").read_text())
    assert doc["count"] == sum(len(rows) for rows in doc["modules"].values())

    live = {
        node.name
        for path in _SPEC_PATH.parent.glob("*.py")
        if not path.name.startswith("_")
        for node in ast.parse(path.read_text()).body
        if isinstance(node, ast.AsyncFunctionDef)
        and any("tool()" in ast.unparse(d) for d in node.decorator_list)
    }
    listed = {row["name"] for rows in doc["modules"].values() for row in rows}
    assert listed == live, (sorted(listed - live), sorted(live - listed))


def test_destructive_flags_match_policy():
    from security import needs_confirm

    doc = json.loads((_SPEC_PATH.parent.parent / "docs" / "tools.json").read_text())
    for rows in doc["modules"].values():
        for row in rows:
            assert row["destructive"] == bool(needs_confirm(row["name"])), row["name"]


def _run_da_legacy(monkeypatch, command, method, confirm=False, enable_write=False):
    """Drive da_legacy through the decorator with a mocked transport."""
    import asyncio

    import da
    from config import settings
    from security import current_profile
    from tools.catalog import da_legacy

    monkeypatch.setattr(settings, "AUDIT_LOG", "")
    monkeypatch.setattr(settings, "ENABLE_DA_WRITE", enable_write)
    token = current_profile.set("break-glass")
    calls = []

    async def fake_request(*args, **kwargs):
        calls.append((args, kwargs))
        return {"ok": True}

    monkeypatch.setattr(da.client, "request", fake_request)
    try:
        result = asyncio.run(
            da_legacy(command, method=method, confirm=confirm, reason="DA-9 test")
        )
    finally:
        current_profile.reset(token)
    return result, calls


def test_da_legacy_allowlisted_get_is_read(monkeypatch):
    result, calls = _run_da_legacy(monkeypatch, "CMD_API_SHOW_ALL_USERS", "GET")
    assert result.get("success") is True, result
    assert len(calls) == 1


def test_da_legacy_non_allowlisted_get_is_treated_as_write(monkeypatch):
    """K-06: legacy CMD_API_* historically act on GET, so GET proves nothing."""
    result, calls = _run_da_legacy(monkeypatch, "CMD_API_ACCOUNT_USER", "GET")
    assert result.get("error") is True and "ENABLE_DA_WRITE" in result["message"]
    assert calls == []
    # Flag on but not confirmed -> confirm gate.
    result, calls = _run_da_legacy(
        monkeypatch, "CMD_API_ACCOUNT_USER", "GET", enable_write=True
    )
    assert result.get("needs_confirm") is True, result
    assert calls == []
    # Flag on + confirmed -> reaches the panel.
    result, calls = _run_da_legacy(
        monkeypatch, "CMD_API_ACCOUNT_USER", "GET", confirm=True, enable_write=True
    )
    assert result.get("success") is True, result
    assert len(calls) == 1


def test_da_legacy_post_always_needs_write_flag(monkeypatch):
    """An allowlisted read command via POST is still a write."""
    result, calls = _run_da_legacy(monkeypatch, "CMD_API_SHOW_ALL_USERS", "POST")
    assert result.get("error") is True and "ENABLE_DA_WRITE" in result["message"]
    assert calls == []