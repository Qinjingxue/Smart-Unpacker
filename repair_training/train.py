from __future__ import annotations

import argparse
import json
from pathlib import Path

from repair_training.core.features import normalize_model_type
from repair_training.core.lightgbm_training import train_lightgbm_model
from repair_training.core.plugin import load_training_format_plugin, normalize_format_name


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    plugin = load_training_format_plugin(fmt)
    model_type = normalize_model_type(args.model)
    run_dir = Path(args.run_dir).resolve()
    output_name = args.model if args.model == "damage_analysis" else model_type
    features_dir = Path(args.features_dir) if args.features_dir else run_dir / "features" / output_name
    model_dir = Path(args.model_dir) if args.model_dir else run_dir / "models" / output_name
    metrics = train_lightgbm_model(
        plugin=plugin,
        model_type=model_type,
        features_dir=features_dir,
        model_dir=model_dir,
        run_id=args.run_id or run_dir.name,
    )
    print(json.dumps({"format": fmt, "model": model_type, "model_dir": str(model_dir), "metrics": metrics}, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train format-specific dual LightGBM policy models.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--model", choices=["damage_analysis", "damage_location", "normal_structure", "step_action", "step_value"], required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--features-dir", default="")
    parser.add_argument("--model-dir", default="")
    parser.add_argument("--run-id", default="")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
