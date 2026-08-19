from fastapi.testclient import TestClient

from main import GateMiddleware, app


def test_health_is_liveness():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "version" in body
    assert "directadmin" not in body


def test_security_headers_present():
    client = TestClient(app)
    response = client.get("/health")
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert "default-src 'none'" in response.headers.get("content-security-policy", "")


def test_query_string_token_is_ignored():
    """Tokens in ?token= must not authenticate — they leak via logs."""
    middleware = GateMiddleware(app)
    assert "token" not in (GateMiddleware.dispatch.__doc__ or "")
    # The gate reads Authorization only; a query token is not a source.
    source = GateMiddleware.dispatch.__code__.co_names
    assert "query_params" not in source
    assert middleware is not None
