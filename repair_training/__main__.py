from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

from repair_training.diagnosis.training import train_diagnosis_gnn_model
from repair_training.formats.base import load_training_format_plugin, normalize_format_name
from repair_training.policy.training import train_repair_policy_transformer
from repair_training.run_store.layout import create_or_resolve_run_dir, ensure_run_layout, write_latest_run


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help"}:
        _root_parser().print_help()
        return 0
    command, command_args = args[0], args[1:]
    if command == "train":
        return train_main(command_args)
    if command == "pipeline":
        return pipeline_main(command_args)
    raise SystemExit(f"unknown repair_training command: {command}")


def _root_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Repair model training tools.")
    parser.add_argument("command", nargs="?", choices=("train", "pipeline"))
    return parser


def train_main(argv: list[str] | None = None) -> int:
    args = _train_parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    model_type = str(args.model)
    if model_type == "diagnosis_gnn" or fmt not in {"shared", "mixed", "all"}:
        load_training_format_plugin(fmt)
    elif model_type != "repair_policy_transformer":
        raise SystemExit(f"shared format training is only supported for the repair meta-policy: {model_type}")
    if fmt in {"mixed", "all"}:
        fmt = "shared"
    run_dir = Path(args.run_dir).resolve()
    if model_type == "diagnosis_gnn":
        input_path = Path(args.input) if args.input else run_dir / "datasets" / "diagnosis_graph_rows.jsonl"
        model_dir = Path(args.model_dir) if args.model_dir else run_dir / "models" / "diagnosis_gnn"
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
                "heads": args.heads,
                "residual": args.residual,
                "layernorm": args.layernorm,
                "amp": args.amp,
                "loss": args.loss,
                "focal_gamma": args.focal_gamma,
                "asym_gamma_pos": args.asym_gamma_pos,
                "asym_gamma_neg": args.asym_gamma_neg,
                "rank_loss_weight": args.rank_loss_weight,
                "rank_loss_top_negatives": args.rank_loss_top_negatives,
                "root_softmax_loss_weight": args.root_softmax_loss_weight,
                "root_evidence_loss_weight": args.root_evidence_loss_weight,
                "root_transition_gain_loss_weight": args.root_transition_gain_loss_weight,
                "root_probe_viability_loss_weight": args.root_probe_viability_loss_weight,
                "probe_pairwise_loss_weight": args.probe_pairwise_loss_weight,
                "probe_viability_pairwise_loss_weight": args.probe_viability_pairwise_loss_weight,
                "same_state_gain_rank_loss_weight": args.same_state_gain_rank_loss_weight,
                "hard_negative_suppression_loss_weight": args.hard_negative_suppression_loss_weight,
                "priority_direct_weight": args.priority_direct_weight,
                "priority_evidence_weight": args.priority_evidence_weight,
                "priority_transition_gain_weight": args.priority_transition_gain_weight,
                "priority_viability_weight": args.priority_viability_weight,
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
                "continuation_loss_weight": args.continuation_loss_weight,
                "action_continuation_loss_weight": args.action_continuation_loss_weight,
                "continuation_rank_loss_weight": args.continuation_rank_loss_weight,
                "continuation_rank_margin": args.continuation_rank_margin,
                "post_undo_switch_loss_weight": args.post_undo_switch_loss_weight,
                "post_module_deepen_loss_weight": args.post_module_deepen_loss_weight,
                "branch_context_margin": args.branch_context_margin,
                "continuation_score_fusion_weight": args.continuation_score_fusion_weight,
                "stop_margin": args.stop_margin,
                "transition_loss_weight": args.transition_loss_weight,
                "masked_graph_loss_weight": args.masked_graph_loss_weight,
                "repeat_action_loss_weight": args.repeat_action_loss_weight,
                "repeat_action_margin": args.repeat_action_margin,
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


def _train_parser() -> argparse.ArgumentParser:
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
    parser.add_argument("--heads", type=int, default=None)
    parser.add_argument("--residual", type=_bool_arg, default=None)
    parser.add_argument("--layernorm", type=_bool_arg, default=None)
    parser.add_argument("--amp", action="store_true")
    parser.add_argument("--loss", choices=["bce", "weighted_bce", "focal", "asymmetric_focal"], default=None)
    parser.add_argument("--focal-gamma", type=float, default=None)
    parser.add_argument("--asym-gamma-pos", type=float, default=None)
    parser.add_argument("--asym-gamma-neg", type=float, default=None)
    parser.add_argument("--rank-loss-weight", type=float, default=None)
    parser.add_argument("--root-softmax-loss-weight", type=float, default=None)
    parser.add_argument("--root-evidence-loss-weight", type=float, default=None)
    parser.add_argument("--root-transition-gain-loss-weight", type=float, default=None)
    parser.add_argument("--root-probe-viability-loss-weight", type=float, default=None)
    parser.add_argument("--probe-pairwise-loss-weight", type=float, default=None)
    parser.add_argument("--probe-viability-pairwise-loss-weight", type=float, default=None)
    parser.add_argument("--same-state-gain-rank-loss-weight", type=float, default=None)
    parser.add_argument("--hard-negative-suppression-loss-weight", type=float, default=None)
    parser.add_argument("--priority-direct-weight", type=float, default=None)
    parser.add_argument("--priority-evidence-weight", type=float, default=None)
    parser.add_argument("--priority-transition-gain-weight", type=float, default=None)
    parser.add_argument("--priority-viability-weight", type=float, default=None)
    parser.add_argument("--softmax-loss-weight", type=float, default=None)
    parser.add_argument("--q-regression-weight", type=float, default=None)
    parser.add_argument("--q-temperature", type=float, default=None)
    parser.add_argument("--best-tie-margin", type=float, default=None)
    parser.add_argument("--rank-q-gap-min", type=float, default=None)
    parser.add_argument("--premature-stop-loss-weight", type=float, default=None)
    parser.add_argument("--undo-loss-weight", type=float, default=None)
    parser.add_argument("--undo-margin", type=float, default=None)
    parser.add_argument("--promising-loss-weight", type=float, default=None)
    parser.add_argument("--continuation-loss-weight", type=float, default=None)
    parser.add_argument("--action-continuation-loss-weight", type=float, default=None)
    parser.add_argument("--continuation-rank-loss-weight", type=float, default=None)
    parser.add_argument("--continuation-rank-margin", type=float, default=None)
    parser.add_argument("--post-undo-switch-loss-weight", type=float, default=None)
    parser.add_argument("--post-module-deepen-loss-weight", type=float, default=None)
    parser.add_argument("--branch-context-margin", type=float, default=None)
    parser.add_argument("--continuation-score-fusion-weight", type=float, default=None)
    parser.add_argument("--stop-margin", type=float, default=None)
    parser.add_argument("--transition-loss-weight", type=float, default=None)
    parser.add_argument("--masked-graph-loss-weight", type=float, default=None)
    parser.add_argument("--repeat-action-loss-weight", type=float, default=None)
    parser.add_argument("--repeat-action-margin", type=float, default=None)
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


def pipeline_main(argv: list[str] | None = None) -> int:
    args = _pipeline_parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    plugin = load_training_format_plugin(fmt)
    run_dir = create_or_resolve_run_dir(format_name=fmt, run_name=args.run_name or plugin.default_run_name, run_dir=args.run_dir)
    ensure_run_layout(run_dir)
    stages = [item.strip() for item in args.stage.split(",") if item.strip()]
    for stage in stages:
        if stage == "collect":
            command = [
                sys.executable, "-m", "repair_training.data.collection",
                "--format", fmt,
                "--material-root", str(Path(args.material_root)),
                "--output", str(run_dir / "datasets" / "damage_rows.jsonl"),
                "--failure-output", str(run_dir / "reports" / "collection_failures.jsonl"),
                "--summary-output", str(run_dir / "reports" / "collection_summary.json"),
                "--workspace", str(run_dir / "workspace" / "collection"),
                "--workers", str(args.workers),
                "--limit", str(args.limit),
                "--per-source", str(args.per_source),
                "--seed", str(args.seed),
            ]
            _run_pipeline_command(command)
        elif stage in {"graphs", "graphs:diagnosis_gnn"}:
            input_path = Path(args.input) if args.input else run_dir / "datasets" / "damage_rows.jsonl"
            _run_pipeline_command([
                sys.executable, "-m", "repair_training.diagnosis.graph_rows",
                "--format", "auto",
                "--input", str(input_path),
                "--output", str(run_dir / "datasets" / "diagnosis_graph_rows.jsonl"),
                "--summary-output", str(run_dir / "reports" / "diagnosis_graph_summary.json"),
            ])
        elif stage == "transitions:policy_transformer":
            input_path = Path(args.input) if args.input else run_dir / "datasets" / "damage_rows.jsonl"
            _run_pipeline_command([
                sys.executable, "-m", "repair_training.policy.transitions",
                "--format", fmt,
                "--input", str(input_path),
                "--output", str(run_dir / "datasets" / "policy_transition_rows.jsonl"),
                "--summary-output", str(run_dir / "reports" / "policy_transition_rows_summary.json"),
            ])
        elif stage == "world_rows:policy_transformer":
            input_path = Path(args.input) if args.input else run_dir / "datasets" / "policy_transition_rows.jsonl"
            _run_pipeline_command([
                sys.executable, "-m", "repair_training.policy.build_world_rows",
                "--format", fmt,
                "--input", str(input_path),
                "--output", str(run_dir / "datasets" / "policy_world_rows.jsonl"),
                "--summary-output", str(run_dir / "reports" / "policy_world_rows_summary.json"),
            ])
        elif stage in {"train", "train:diagnosis_gnn"}:
            model = args.model if args.model else "diagnosis_gnn"
            _run_pipeline_command([sys.executable, "-m", "repair_training", "train", "--format", fmt, "--model", model, "--run-dir", str(run_dir)])
        elif stage == "train:policy_transformer":
            _run_pipeline_command([sys.executable, "-m", "repair_training", "train", "--format", fmt, "--model", "repair_policy_transformer", "--run-dir", str(run_dir)])
        elif stage in {"eval", "eval:diagnosis_gnn"}:
            _run_pipeline_command([
                sys.executable, "-m", "repair_training.diagnosis.evaluation",
                "--format", fmt,
                "--input", str(run_dir / "datasets" / "diagnosis_graph_rows.jsonl"),
                "--model-dir", str(run_dir / "models" / "diagnosis_gnn"),
                "--output", str(run_dir / "reports" / "diagnosis_gnn_eval"),
            ])
        elif stage == "eval:policy_transformer":
            input_path = run_dir / "datasets" / "policy_world_rows.jsonl"
            _run_pipeline_command([
                sys.executable, "-m", "repair_training.policy.evaluation",
                "--format", fmt,
                "--input", str(input_path),
                "--model-dir", str(run_dir / "models" / "repair_policy_transformer"),
                "--output", str(run_dir / "reports" / "repair_policy_transformer_eval"),
            ])
        else:
            raise SystemExit(f"unknown pipeline stage: {stage}")
    write_latest_run(fmt, run_dir)
    print(json.dumps({"format": fmt, "run_dir": str(run_dir), "stages": stages}, ensure_ascii=False, sort_keys=True))
    return 0


def _pipeline_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the repair diagnosis and policy model training pipeline.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--run-dir", default="")
    parser.add_argument("--run-name", default="")
    parser.add_argument("--model", choices=["", "diagnosis_gnn", "repair_policy_transformer"], default="")
    parser.add_argument(
        "--stage",
        default="collect,graphs:diagnosis_gnn,train:diagnosis_gnn,transitions:policy_transformer,world_rows:policy_transformer,train:policy_transformer",
    )
    parser.add_argument("--input", default="")
    parser.add_argument("--material-root", default=str(Path("repair_training") / "material"))
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--per-source", type=int, default=0)
    parser.add_argument("--seed", default="20260515")
    return parser


def _run_pipeline_command(command: list[str]) -> None:
    subprocess.run(command, check=True)


if __name__ == "__main__":
    raise SystemExit(main())
