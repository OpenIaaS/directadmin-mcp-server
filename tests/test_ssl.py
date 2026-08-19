from pathlib import Path


def test_ssl_module_has_reissue_tools():
    src = (Path(__file__).resolve().parents[1] / "tools" / "ssl_certs.py").read_text()
    assert "ssl_reissue_domain" in src
    assert "ssl_reissue_server" in src
    assert "/api/domain-tls/{domain}/provision-certs" in src
    assert "/api/server-tls/obtain" in src
    assert "ssl_reissue_domain_legacy" in src
    assert "CMD_API_SSL" in src
    assert "ssl_admin_list" in src
    assert "ssl_admin_reissue" in src
    assert "CMD_ADMIN_SSL" in src
    assert "ssl_admin_flags" in src


def test_firewall_combo_tool_exists():
    src = (Path(__file__).resolve().parents[1] / "tools" / "brute_force.py").read_text()
    assert "firewall_unblock_everywhere" in src
    assert "csf_unblock_ip" in src
    assert "bfm_unblock_ip" in src
