"""Registry coverage: the central confirm gate rejects every write-shaped tool.

Round-2 audit findings K-01..K-03: confirm enforcement was per-tool opt-in
(each body had to remember ``guard_confirm``), so 7 confirm-classified tools —
cpanel_import_check_remote, git_fetch, login_url_one_shot, phpmyadmin_sso,
profile_settings_update, session_switch_domain, ssl_create_csr — executed
ungated for operator/break-glass tokens. The gate now lives in
``log_tool_call`` itself. The first audit only ever asserted the policy
*function* (``confirm_or_reject``); these tests drive every registered tool
through the decorator path with a mocked transport, so a future mutator that
forgets gating fails here instead of silently shipping.
"""

import asyncio
import inspect

import pytest

import da
import tools as tools_pkg
from config import settings
from mcp_instance import mcp
from security import (
    confirm_or_reject,
    current_idem,
    current_profile,
    current_reason,
    needs_confirm,
)

tools_pkg.load_all_tools()
REGISTRY = dict(mcp._tool_manager._tools)

# The 7 tools the round-2 audit caught executing with no confirm.
ROUND2_SEVEN = (
    "cpanel_import_check_remote",
    "git_fetch",
    "login_url_one_shot",
    "phpmyadmin_sso",
    "profile_settings_update",
    "session_switch_domain",
    "ssl_create_csr",
)


class _Recorder:
    """Stands in for the panel: records calls, never touches the network."""

    def __init__(self):
        self.calls = []

    async def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return {"ok": True}


@pytest.fixture()
def open_gates(monkeypatch):
    """Open every gate except the confirm gate under test."""
    monkeypatch.setattr(settings, "REQUIRE_CONFIRM", True)
    monkeypatch.setattr(settings, "REQUIRE_REASON", False)
    monkeypatch.setattr(settings, "TOOL_DENYLIST", "")
    monkeypatch.setattr(settings, "MCP_PROFILE", "break-glass")
    monkeypatch.setattr(settings, "AUDIT_LOG", "")
    for field in type(settings).model_fields:
        if field.startswith("ENABLE_"):
            monkeypatch.setattr(settings, field, True)
    # Request-context ContextVars leak across tests (test_audit.py sets them via
    # bind_request_context); pin them here instead of inheriting anyone's.
    tokens = [
        current_profile.set("break-glass"),
        current_reason.set(""),
        current_idem.set(""),
    ]
    recorder = _Recorder()
    monkeypatch.setattr(da.client, "request", recorder)
    yield recorder
    for var, token in zip((current_profile, current_reason, current_idem), tokens, strict=True):
        var.reset(token)


def test_every_confirm_classified_tool_rejects_without_confirm(open_gates):
    checked = 0
    for name, tool in sorted(REGISTRY.items()):
        if not needs_confirm(name):
            continue
        checked += 1
        result = asyncio.run(tool.fn(confirm=False))
        assert isinstance(result, dict), name
        assert result.get("error") is True, name
        assert result.get("needs_confirm") is True, name
    # Sanity: the sweep really covered the registry, not an empty set.
    assert checked >= 100
    assert open_gates.calls == []


def test_every_confirm_classified_tool_accepts_a_confirm_argument():
    """A gated tool the operator cannot confirm would be a permanent lockout."""
    for name, tool in sorted(REGISTRY.items()):
        if not needs_confirm(name):
            continue
        params = inspect.signature(tool.fn).parameters
        assert "confirm" in params, f"{name} is confirm-classified but takes no confirm="


def test_round2_seven_tools_now_reject_without_confirm(open_gates):
    for name in ROUND2_SEVEN:
        assert name in REGISTRY, name
        assert needs_confirm(name), name
        result = asyncio.run(REGISTRY[name].fn(confirm=False))
        assert result.get("error") is True and result.get("needs_confirm") is True, name
    assert open_gates.calls == []


def test_approved_calls_pass_the_central_gate(open_gates):
    """confirm=true still reaches the tool body (and the mocked panel)."""
    result = asyncio.run(REGISTRY["git_fetch"].fn(uuid="9f6b2c1a", confirm=True))
    assert result.get("success") is True, result
    result = asyncio.run(REGISTRY["phpmyadmin_sso"].fn(confirm=True))
    assert result.get("success") is True, result
    assert len(open_gates.calls) == 2
    paths = [call[1].get("path") or call[0][0] for call in open_gates.calls]
    assert any("/api/git/uuid/9f6b2c1a/fetch" in str(p) for p in paths)
    assert any("/api/phpmyadmin-sso/account-access" in str(p) for p in paths)


def test_central_gate_matches_guard_confirm_message_shape(open_gates):
    """Tools that also call guard_confirm are rejected once, with the same dict."""
    name = "ssl_install_self_signed"  # body-guarded long before round 2
    via_gate = asyncio.run(REGISTRY[name].fn(domain="ex.com", cert_id="c1", confirm=False))
    via_policy = confirm_or_reject(name, False)
    assert via_gate == via_policy
    assert open_gates.calls == []


def test_cpanel_import_check_remote_validates_the_dialed_host(open_gates):
    """K-01: the panel-side request forgery is gated AND the payload checked."""
    fn = REGISTRY["cpanel_import_check_remote"].fn
    bad_payloads = (
        {"hostname": "http://cpanel.example.com"},  # plaintext creds
        {"hostname": "https://root:hunter2@cpanel.example.com"},  # creds in URL
        {"hostname": "192.168.1.10"},  # RFC1918
        {"host": "169.254.169.254"},  # link-local metadata endpoint
        {"host": "127.0.0.1:2222"},  # loopback
    )
    for payload in bad_payloads:
        result = asyncio.run(fn(payload=payload, confirm=True))
        assert result.get("error") is True, payload
        assert result.get("needs_confirm") is not True, payload  # gate passed, validation spoke
    assert open_gates.calls == []
    ok = asyncio.run(
        fn(
            payload={"hostname": "https://cpanel.example.com", "user": "root", "password": "x"},
            confirm=True,
        )
    )
    assert ok.get("success") is True, ok
    assert len(open_gates.calls) == 1
