from __future__ import annotations

import argparse
from pathlib import Path

from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from sunpack.model_runtime.policy.schema import transition_sample_from_dict
from repair_training.core.repair_policy_transformer.world_rows import build_policy_world_samples


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    transitions = [transition_sample_from_dict(row) for row in read_jsonl(args.input)]
    rows = build_policy_world_samples(transitions)
    output = Path(args.output)
    write_jsonl(output, [row.to_dict() for row in rows])
    summary = {
        "transition_rows": len(transitions),
        "world_rows": len(rows),
        "task_counts": _task_counts(rows),
        "formats": sorted({row.format for row in rows}),
    }
    write_json(Path(args.summary_output) if args.summary_output else output.with_name("policy_world_rows_summary.json"), summary)
    return 0


def _task_counts(rows) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.task] = counts.get(row.task, 0) + 1
    return dict(sorted(counts.items()))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build RepairGraph world-model rows from transition rows.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", default="")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
