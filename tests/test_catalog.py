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