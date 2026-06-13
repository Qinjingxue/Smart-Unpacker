from __future__ import annotations

import re
from pathlib import Path


RUNTIME_ROOTS = [
    "sunpack/coordinator",
    "sunpack/analysis",
    "sunpack/extraction",
    "sunpack/verification",
    "sunpack/repair",
    "sunpack/passwords",
]

FORBIDDEN_PREFIXES = (
    "analysis.",
    "extraction.",
    "verification.",
    "repair.",
    "resource.",
    "archive.input",
    "candidate.",
    "relation.",
    "file.",
)

ALLOWED_FILES: set[Path] = {
    Path("sunpack/passwords/resolver.py"),
}

FACT_GET_RE = re.compile(r"(?:\b|\.)fact_bag\.get\(\s*[\"']([^\"']+)[\"']")


def test_runtime_layers_do_not_read_legacy_cross_layer_fact_keys() -> None:
    root = Path(__file__).resolve().parents[2]
    violations: list[str] = []
    for rel_root in RUNTIME_ROOTS:
        for path in (root / rel_root).rglob("*.py"):
            rel_path = path.relative_to(root)
            if rel_path in ALLOWED_FILES:
                continue
            text = path.read_text(encoding="utf-8")
            for line_number, line in enumerate(text.splitlines(), start=1):
                match = FACT_GET_RE.search(line)
                if not match:
                    continue
                key = match.group(1)
                if key == "archive.knowledge":
                    continue
                if key.startswith(FORBIDDEN_PREFIXES):
                    violations.append(f"{rel_path}:{line_number}: {key}")
    assert not violations, "legacy cross-layer fact_bag reads found:\n" + "\n".join(violations)
