from pathlib import Path

from tools.propack import _TEMPLATES, INVENTORY


def test_inventory_covers_core_propack():
    names = " ".join(row["feature"] for row in INVENTORY)
    for feature in (
        "Admin SSL",
        "Per-user Redis",
        "WordPress manager",
        "GIT manager",
        "Nginx Unit",
        "Web Terminal",
    ):
        assert feature in names, feature


def test_web_terminal_is_blocked():
    row = next(item for item in INVENTORY if item["feature"] == "Web Terminal")
    assert "blocked" in row["tools"]


def test_nginx_templates_are_closed():
    assert "wordpress" in _TEMPLATES
    assert "../etc" not in _TEMPLATES


def test_cloudlinux_module_exists():
    src = (Path(__file__).resolve().parents[1] / "tools" / "cloudlinux.py").read_text()
    for name in (
        "cl_status",
        "cl_lve_set",
        "cl_cagefs_enable",
        "cl_php_selector_set",
        "ENABLE_CLOUDLINUX",
    ):
        assert name in src, name
    assert "subprocess" not in src
    assert "call_da_api(\"/api/execute\"" not in src


def test_unit_and_terminal_blocked_in_catalog():
    src = (Path(__file__).resolve().parents[1] / "tools" / "catalog.py").read_text()
    assert "/api/terminal" in src
    assert "/api/execute" in src


def test_cloudlinux_is_opt_in():
    from config import Settings

    assert Settings.model_fields["ENABLE_CLOUDLINUX"].default is False
