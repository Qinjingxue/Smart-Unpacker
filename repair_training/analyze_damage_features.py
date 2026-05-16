from __future__ import annotations

import argparse
import json
from pathlib import Path

from repair_training.core.damage_feature_analysis import analyze_damage_features
from repair_training.core.plugin import load_training_format_plugin, normalize_format_name


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    plugin = load_training_format_plugin(fmt)
    summary = analyze_damage_features(
        rows_path=args.rows,
        predictions_path=args.predictions,
        output_dir=args.output,
        plugin=plugin,
    )
    print(json.dumps({"output": str(Path(args.output).resolve()), "summary": summary}, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze DamageAnalysis feature/label/profile correspondence.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--rows", required=True, help="Path to damage_rows.jsonl or eval_damage_rows.jsonl.")
    parser.add_argument("--predictions", default=None, help="Optional predictions.jsonl from evaluate_damage_model.")
    parser.add_argument("--output", required=True, help="Directory for feature analysis reports.")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
