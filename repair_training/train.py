from __future__ import annotations

import argparse
import json
from pathlib import Path

from repair_training.core.features import normalize_model_type
from repair_training.core.diagnosis_gnn.training import train_diagnosis_gnn_model
from repair_training.core.lightgbm_training import train_lightgbm_model
from repair_training.core.plugin import load_training_format_plugin, normalize_format_name


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    plugin = load_training_format_plugin(fmt)
    model_type = normalize_model_type(args.model)
    run_dir = Path(args.run_dir).resolve()
    output_name = args.model if args.model == "damage_analysis" else model_type
    if model_type == "diagnosis_gnn":
        input_path = Path(args.input) if args.input else run_dir / "datasets" / "diagnosis_graph_train_single_field_rows.jsonl"
        if not input_path.is_file() and not args.input:
            input_path = run_dir / "datasets" / "diagnosis_graph_train_rows.jsonl"
        if not input_path.is_file() and not args.input:
            input_path = run_dir / "datasets" / "diagnosis_graph_rows.jsonl"
        model_dir = Path(args.model_dir) if args.model_dir else run_dir / "models" / ("diagnosis_gnn_single_field_v1" if "single_field" in input_path.name else output_name)
        gnn_config = {
            key: value
            for key, value in {
                "hidden_dim": args.hidden_dim,
                "layers": args.layers,
                "dropout": args.dropout,
                "batch_size": args.batch_size,
                "epochs": args.epochs,
                "lr": args.lr,
                "weight_decay": args.weight_decay,
                "early_stopping_patience": args.early_stopping_patience,
                "edge_loss_weight": args.edge_loss_weight,
            }.items()
            if value is not None
        }
        metrics = train_diagnosis_gnn_model(
            input_path=input_path,
            model_dir=model_dir,
            run_id=args.run_id or run_dir.name,
            format_name=fmt,
            config=gnn_config,
            device=args.device,
        )
    else:
        model_dir = Path(args.model_dir) if args.model_dir else run_dir / "models" / output_name
        features_dir = Path(args.features_dir) if args.features_dir else run_dir / "features" / output_name
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
    parser = argparse.ArgumentParser(description="Train format-specific repair training models.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--model", choices=["damage_analysis", "damage_location", "normal_structure", "step_action", "step_value", "diagnosis_gnn"], required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--features-dir", default="")
    parser.add_argument("--input", default="")
    parser.add_argument("--model-dir", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    parser.add_argument("--hidden-dim", type=int, default=None)
    parser.add_argument("--layers", type=int, default=None)
    parser.add_argument("--dropout", type=float, default=None)
    parser.add_argument("--batch-size", type=int, default=None)
    parser.add_argument("--epochs", type=int, default=None)
    parser.add_argument("--lr", type=float, default=None)
    parser.add_argument("--weight-decay", type=float, default=None)
    parser.add_argument("--early-stopping-patience", type=int, default=None)
    parser.add_argument("--edge-loss-weight", type=float, default=None)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
