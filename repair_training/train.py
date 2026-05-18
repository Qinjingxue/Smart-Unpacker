from __future__ import annotations

import argparse
import json
from pathlib import Path

from repair_training.core.diagnosis_gnn.training import train_diagnosis_gnn_model
from repair_training.core.repair_policy_transformer.training import train_repair_policy_transformer
from repair_training.core.plugin import load_training_format_plugin, normalize_format_name


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    load_training_format_plugin(fmt)
    model_type = str(args.model)
    run_dir = Path(args.run_dir).resolve()
    if model_type == "diagnosis_gnn":
        input_path = Path(args.input) if args.input else run_dir / "datasets" / "diagnosis_graph_train_single_field_rows.jsonl"
        if not input_path.is_file() and not args.input:
            input_path = run_dir / "datasets" / "diagnosis_graph_train_rows.jsonl"
        if not input_path.is_file() and not args.input:
            input_path = run_dir / "datasets" / "diagnosis_graph_rows.jsonl"
        model_dir = Path(args.model_dir) if args.model_dir else run_dir / "models" / ("diagnosis_gnn_single_field_v1" if "single_field" in input_path.name else "diagnosis_gnn")
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
                "arch": args.arch,
                "heads": args.heads,
                "num_bases": args.num_bases,
                "residual": args.residual,
                "layernorm": args.layernorm,
                "amp": args.amp,
                "loss": args.loss,
                "focal_gamma": args.focal_gamma,
                "asym_gamma_pos": args.asym_gamma_pos,
                "asym_gamma_neg": args.asym_gamma_neg,
                "rank_loss_weight": args.rank_loss_weight,
                "rank_loss_top_negatives": args.rank_loss_top_negatives,
                "pos_weight_max": args.pos_weight_max,
                "sample_weighting": args.sample_weighting,
                "score_normalization": args.score_normalization,
                "tensor_cache_dir": args.tensor_cache_dir,
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
    elif model_type == "repair_policy_transformer":
        input_path = Path(args.input) if args.input else run_dir / "datasets" / "policy_world_rows.jsonl"
        if not input_path.is_file() and not args.input:
            input_path = run_dir / "datasets" / "policy_teacher_rows.jsonl"
        if not input_path.is_file() and not args.input:
            input_path = run_dir / "datasets" / "policy_graph_rows.jsonl"
        model_dir = Path(args.model_dir) if args.model_dir else run_dir / "models" / "repair_policy_transformer"
        policy_config = {
            key: value
            for key, value in {
                "hidden_dim": args.hidden_dim,
                "layers": args.layers,
                "dropout": args.dropout,
                "batch_size": args.batch_size,
                "epochs": args.epochs,
                "lr": args.lr,
                "weight_decay": args.weight_decay,
                "heads": args.heads,
                "rank_loss_weight": args.rank_loss_weight,
                "softmax_loss_weight": args.softmax_loss_weight,
                "q_regression_weight": args.q_regression_weight,
                "q_temperature": args.q_temperature,
                "best_tie_margin": args.best_tie_margin,
                "rank_q_gap_min": args.rank_q_gap_min,
                "premature_stop_loss_weight": args.premature_stop_loss_weight,
                "undo_loss_weight": args.undo_loss_weight,
                "undo_margin": args.undo_margin,
                "promising_loss_weight": args.promising_loss_weight,
                "stop_margin": args.stop_margin,
                "transition_loss_weight": args.transition_loss_weight,
                "masked_graph_loss_weight": args.masked_graph_loss_weight,
                "repeat_action_loss_weight": args.repeat_action_loss_weight,
                "repeat_action_margin": args.repeat_action_margin,
                "training_task": args.training_task,
            }.items()
            if value is not None
        }
        metrics = train_repair_policy_transformer(
            input_path=input_path,
            model_dir=model_dir,
            run_id=args.run_id or run_dir.name,
            format_name=fmt,
            config=policy_config,
            device=args.device,
        )
    else:
        raise SystemExit(f"unsupported model: {args.model}")
    print(json.dumps({"format": fmt, "model": model_type, "model_dir": str(model_dir), "metrics": metrics}, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train format-specific repair training models.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--model", choices=["diagnosis_gnn", "repair_policy_transformer"], required=True)
    parser.add_argument("--run-dir", required=True)
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
    parser.add_argument("--arch", choices=["hetero_graphsage", "rgcn", "hgt"], default=None)
    parser.add_argument("--heads", type=int, default=None)
    parser.add_argument("--num-bases", type=int, default=None)
    parser.add_argument("--residual", type=_bool_arg, default=None)
    parser.add_argument("--layernorm", type=_bool_arg, default=None)
    parser.add_argument("--amp", action="store_true")
    parser.add_argument("--loss", choices=["bce", "weighted_bce", "focal", "asymmetric_focal"], default=None)
    parser.add_argument("--focal-gamma", type=float, default=None)
    parser.add_argument("--asym-gamma-pos", type=float, default=None)
    parser.add_argument("--asym-gamma-neg", type=float, default=None)
    parser.add_argument("--rank-loss-weight", type=float, default=None)
    parser.add_argument("--softmax-loss-weight", type=float, default=None)
    parser.add_argument("--q-regression-weight", type=float, default=None)
    parser.add_argument("--q-temperature", type=float, default=None)
    parser.add_argument("--best-tie-margin", type=float, default=None)
    parser.add_argument("--rank-q-gap-min", type=float, default=None)
    parser.add_argument("--premature-stop-loss-weight", type=float, default=None)
    parser.add_argument("--undo-loss-weight", type=float, default=None)
    parser.add_argument("--undo-margin", type=float, default=None)
    parser.add_argument("--promising-loss-weight", type=float, default=None)
    parser.add_argument("--stop-margin", type=float, default=None)
    parser.add_argument("--transition-loss-weight", type=float, default=None)
    parser.add_argument("--masked-graph-loss-weight", type=float, default=None)
    parser.add_argument("--repeat-action-loss-weight", type=float, default=None)
    parser.add_argument("--repeat-action-margin", type=float, default=None)
    parser.add_argument("--training-task", choices=["world_pretrain", "policy_finetune", "joint"], default=None)
    parser.add_argument("--rank-loss-top-negatives", type=int, default=None)
    parser.add_argument("--pos-weight-max", type=float, default=None)
    parser.add_argument("--sample-weighting", choices=["multi_field_root_count", "none"], default=None)
    parser.add_argument("--score-normalization", choices=["raw", "zone_aware"], default=None)
    parser.add_argument("--tensor-cache-dir", default="")
    return parser


def _bool_arg(value: str) -> bool:
    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    raise argparse.ArgumentTypeError(f"expected boolean value, got {value!r}")


if __name__ == "__main__":
    raise SystemExit(main())
