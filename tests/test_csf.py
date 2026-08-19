from pathlib import Path

from security import validate_ip


def test_unblock_rejects_non_ip():
    try:
        validate_ip("*; csf -x")
        raised = False
    except Exception:
        raised = True
    assert raised


def test_csf_module_documents_plugin_paths():
    src = (Path(__file__).resolve().parents[1] / "tools" / "csf_firewall.py").read_text()
    assert "/CMD_PLUGINS_ADMIN/csf/" in src
    assert "action=kill" in src or '"kill"' in src
    assert "csf_unblock_ip" in src
