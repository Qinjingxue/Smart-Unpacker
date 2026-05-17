from __future__ import annotations

import argparse
import json
from pathlib import Path

from repair_training.core.datasets import read_jsonl
from repair_training.core.features import build_feature_datasets, normalize_model_type
from repair_training.core.plugin import load_training_format_plugin, normalize_format_name


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    plugin = load_training_format_plugin(fmt)
    run_dir = Path(args.run_dir).resolve()
    model_type = normalize_model_type(args.model)
    default_input = {
        "normal_structure": "normal_structure_queries.jsonl",
        "damage_location": "damage_rows.jsonl",
        "graph_action": "action_policy_rows.jsonl",
        "graph_state_value": "state_value_rows.jsonl",
    }.get(model_type, "")
    input_path = Path(args.input) if args.input else run_dir / "datasets" / default_input
    if model_type == "normal_structure" and not input_path.is_file() and not args.input:
        input_path = run_dir / "datasets" / "normal_structure_rows.jsonl"
    output_name = args.model if args.model == "damage_analysis" else model_type
    output_dir = Path(args.output_dir) if args.output_dir else run_dir / "features" / output_name
    rows = read_jsonl(input_path)
    summary = build_feature_datasets(rows, plugin=plugin, model_type=model_type, output_dir=output_dir)
    print(json.dumps({"format": fmt, "model": model_type, "input": str(input_path), "output_dir": str(output_dir), **summary}, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build dual-model LightGBM feature matrices.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--model", choices=["damage_analysis", "damage_location", "normal_structure", "graph_action", "graph_state_value"], required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--input", default="")
    parser.add_argument("--output-dir", default="")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
