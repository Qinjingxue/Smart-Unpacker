from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from repair_training.core.plugin import load_training_format_plugin, normalize_format_name
from repair_training.core.run_layout import create_or_resolve_run_dir, ensure_run_layout, write_latest_run


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    plugin = load_training_format_plugin(fmt)
    run_dir = create_or_resolve_run_dir(format_name=fmt, run_name=args.run_name or plugin.default_run_name, run_dir=args.run_dir)
    ensure_run_layout(run_dir)
    stages = [item.strip() for item in args.stage.split(",") if item.strip()]
    for stage in stages:
        if stage in {"graphs", "graphs:diagnosis_gnn"}:
            input_path = Path(args.input) if args.input else run_dir / "datasets" / "damage_rows.jsonl"
            _run([
                sys.executable, "-m", "repair_training.build_diagnosis_graphs",
                "--format", "auto",
                "--input", str(input_path),
                "--output", str(run_dir / "datasets" / "diagnosis_graph_rows.jsonl"),
                "--summary-output", str(run_dir / "reports" / "diagnosis_graph_summary.json"),
            ])
        elif stage in {"graphs:policy_transformer", "policy_graphs"}:
            input_path = Path(args.input) if args.input else run_dir / "datasets" / "policy_runtime_logs.jsonl"
            _run([
                sys.executable, "-m", "repair_training.build_policy_graph_rows",
                "--format", fmt,
                "--input", str(input_path),
                "--output", str(run_dir / "datasets" / "policy_graph_rows.jsonl"),
                "--summary-output", str(run_dir / "reports" / "policy_graph_rows_summary.json"),
            ])
        elif stage in {"train", "train:diagnosis_gnn"}:
            model = args.model if args.model else "diagnosis_gnn"
            _run([sys.executable, "-m", "repair_training.train", "--format", fmt, "--model", model, "--run-dir", str(run_dir)])
        elif stage == "train:policy_transformer":
            _run([sys.executable, "-m", "repair_training.train", "--format", fmt, "--model", "repair_policy_transformer", "--run-dir", str(run_dir)])
        elif stage in {"eval", "eval:diagnosis_gnn"}:
            _run([
                sys.executable, "-m", "repair_training.evaluate_diagnosis_gnn",
                "--format", fmt,
                "--input", str(run_dir / "datasets" / "diagnosis_graph_rows.jsonl"),
                "--model-dir", str(run_dir / "models" / "diagnosis_gnn"),
                "--output", str(run_dir / "reports" / "diagnosis_gnn_eval"),
            ])
        elif stage == "eval:policy_transformer":
            _run([
                sys.executable, "-m", "repair_training.evaluate_policy_transformer",
                "--format", fmt,
                "--input", str(run_dir / "datasets" / "policy_graph_rows.jsonl"),
                "--model-dir", str(run_dir / "models" / "repair_policy_transformer"),
                "--output", str(run_dir / "reports" / "repair_policy_transformer_eval"),
            ])
        else:
            raise SystemExit(f"unknown pipeline stage: {stage}")
    write_latest_run(fmt, run_dir)
    print(json.dumps({"format": fmt, "run_dir": str(run_dir), "stages": stages}, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run DiagnosisHGT and RepairGraph policy transformer training pipeline.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--run-dir", default="")
    parser.add_argument("--run-name", default="")
    parser.add_argument("--model", choices=["", "diagnosis_gnn", "repair_policy_transformer"], default="")
    parser.add_argument("--stage", default="graphs:diagnosis_gnn,train:diagnosis_gnn")
    parser.add_argument("--input", default="")
    return parser


def _run(command: list[str]) -> None:
    subprocess.run(command, check=True)


if __name__ == "__main__":
    raise SystemExit(main())
