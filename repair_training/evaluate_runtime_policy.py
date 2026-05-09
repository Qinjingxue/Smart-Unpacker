from __future__ import annotations

import argparse
import runpy
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_RUNTIME_AB = ROOT / ".private" / "tools" / "evaluate_runtime_policy_ab.py"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the production ExtractionBatchRunner runtime policy evaluation."
    )
    parser.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="Arguments passed through to .private/tools/evaluate_runtime_policy_ab.py.",
    )
    parsed = parser.parse_args(argv)
    if not PRIVATE_RUNTIME_AB.is_file():
        raise SystemExit(
            "runtime A/B evaluator is private and was not found. "
            f"Expected: {PRIVATE_RUNTIME_AB}"
        )
    old_argv = sys.argv
    try:
        sys.argv = [str(PRIVATE_RUNTIME_AB), *list(parsed.args or [])]
        runpy.run_path(str(PRIVATE_RUNTIME_AB), run_name="__main__")
    finally:
        sys.argv = old_argv
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
