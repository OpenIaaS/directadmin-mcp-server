import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "tools"


def _modules_on_disk():
    return {p.stem for p in ROOT.glob("*.py") if not p.name.startswith("_")}


def test_preferred_modules_exist():
    names = _modules_on_disk()
    for name in (
        "ssl_certs",
        "csf_firewall",
        "brute_force",
        "accounts",
        "domains",
        "mailboxes",
        "hosting",
        "catalog",
    ):
        assert name in names, name


def test_curated_tools_parse():
    count = 0
    for path in ROOT.glob("*.py"):
        if path.name.startswith("_"):
            continue
        tree = ast.parse(path.read_text())
        for node in tree.body:
            if not isinstance(node, ast.AsyncFunctionDef):
                continue
            for deco in node.decorator_list:
                if isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute):
                    if deco.func.attr == "tool":
                        count += 1
    assert count >= 200, count
