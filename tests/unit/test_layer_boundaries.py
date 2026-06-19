import ast
from pathlib import Path


FLOW_LAYERS = {
    "filesystem",
    "relations",
    "detection",
    "analysis",
    "extraction",
    "verification",
    "repair",
    "postprocess",
}


def test_flow_layers_do_not_depend_on_each_other_or_coordinator():
    root = Path(__file__).parents[2] / "sunpack"
    violations: list[str] = []
    for owner in sorted(FLOW_LAYERS):
        for path in (root / owner).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                modules: list[str] = []
                if isinstance(node, ast.ImportFrom) and node.module:
                    modules.append(node.module)
                elif isinstance(node, ast.Import):
                    modules.extend(alias.name for alias in node.names)
                for module in modules:
                    parts = module.split(".")
                    if len(parts) < 2 or parts[0] != "sunpack":
                        continue
                    target = parts[1]
                    if target == "coordinator" or target in FLOW_LAYERS and target != owner:
                        violations.append(f"{path.relative_to(root.parent)}:{node.lineno} imports {module}")
    assert not violations, "Flow-layer dependency violations:\n" + "\n".join(violations)


def test_cross_layer_results_are_owned_by_contracts_only():
    root = Path(__file__).parents[2] / "sunpack"
    assert not (root / "extraction" / "result.py").exists()
    assert not (root / "verification" / "result.py").exists()
    assert (root / "contracts" / "extraction.py").is_file()
    assert (root / "contracts" / "verification.py").is_file()
