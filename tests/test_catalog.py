import json
import re
from pathlib import Path

import pytest

from security import SecurityError

_SPEC_PATH = Path(__file__).resolve().parents[1] / "tools" / "api_spec.json"
_PATH_PARAM = re.compile(r"\{([^}]+)\}")


def _spec():
    return json.loads(_SPEC_PATH.read_text())


def _fill_path(template: str, path_params):
    params = path_params or {}

    def repl(match):
        key = match.group(1)
        if key not in params:
            raise SecurityError(f"Missing path parameter '{key}' for {template}")
        value = str(params[key])
        if "/" in value or ".." in value or value.startswith("."):
            raise SecurityError(f"Illegal path parameter '{key}'")
        return value

    return _PATH_PARAM.sub(repl, template)


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
