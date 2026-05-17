from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from repair_training.core.plugin import load_training_format_plugin, normalize_format_name
from repair_training.core.run_layout import create_or_resolve_run_dir, ensure_run_layout, write_latest_run
from repair_training.core.features import normalize_model_type


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    plugin = load_training_format_plugin(fmt)
    run_dir = create_or_resolve_run_dir(format_name=fmt, run_name=args.run_name or plugin.default_run_name, run_dir=args.run_dir)
    ensure_run_layout(run_dir)
    stages = [item.strip() for item in args.stage.split(",") if item.strip()]
    if args.model == "damage_analysis" and stages == ["collect_damage", "features", "train"]:
        _run_damage_analysis_pipeline(args, fmt=fmt, run_dir=run_dir)
        write_latest_run(fmt, run_dir)
        print(json.dumps({"format": fmt, "run_dir": str(run_dir), "stages": [
            "collect_normal",
            "collect_damage",
            "features:normal_structure",
            "train:normal_structure",
            "features:damage_location",
            "train:damage_location",
        ]}, ensure_ascii=False, sort_keys=True))
        return 0
    for stage in stages:
        if stage == "collect_normal":
            if args.model not in {"", "damage_analysis", "normal_structure"}:
                raise SystemExit("collect_normal is only valid for --model damage_analysis or normal_structure")
            _run([
                sys.executable, "-m", "repair_training.collect_normal_structure_rows",
                "--format", fmt,
                "--material-root", args.material_root,
                "--output", str(run_dir / "datasets" / "normal_structure_rows.jsonl"),
                "--seed", args.seed,
            ] + (["--limit", str(args.limit)] if args.limit else []))
        elif stage == "apply_normal":
            _run([
                sys.executable, "-m", "repair_training.apply_normal_structure_model",
                "--format", fmt,
                "--input", str(run_dir / "datasets" / "damage_rows_raw.jsonl"),
                "--normal-model-dir", str(run_dir / "models" / "normal_structure"),
                "--output", str(run_dir / "datasets" / "damage_rows.jsonl"),
            ])
        elif stage == "collect_damage":
            if args.model not in {"", "damage_analysis", "damage_location"}:
                raise SystemExit("collect_damage is only valid for --model damage_analysis or damage_location")
            damage_output = run_dir / "datasets" / "damage_rows.jsonl"
            _run([
                sys.executable, "-m", "repair_training.collect_damage_rows",
                "--format", fmt,
                "--material-root", args.material_root,
                "--output", str(damage_output),
                "--seed", args.seed,
                "--per-source", str(args.per_source),
                "--workers", str(args.workers),
            ] + (["--manifest", args.manifest] if args.manifest else []) + (["--limit", str(args.limit)] if args.limit else []))
        elif stage == "collect":
            _run([
                sys.executable, "-m", "repair_training.collect_episodes",
                "--format", fmt,
                "--material-root", args.material_root,
                "--output", str(run_dir / "datasets" / "episodes.jsonl"),
            ] + (["--manifest", args.manifest] if args.manifest else []))
        elif stage == "label":
            _run([
                sys.executable, "-m", "repair_training.value_labeler",
                "--episodes", str(run_dir / "datasets" / "episodes.jsonl"),
                "--output-dir", str(run_dir / "datasets"),
                "--damage-output", str(run_dir / "datasets" / "damage_rows.jsonl"),
                "--report-output", str(run_dir / "reports" / "oracle_recovery_report.json"),
            ])
        elif stage == "features":
            for model in _models(args.model):
                _run([sys.executable, "-m", "repair_training.build_features", "--format", fmt, "--model", model, "--run-dir", str(run_dir)])
        elif stage == "analyze":
            _run([sys.executable, "-m", "repair_training.analyze_run", "--run-dir", str(run_dir)])
        elif stage == "train":
            for model in _models(args.model):
                _run([sys.executable, "-m", "repair_training.train", "--format", fmt, "--model", model, "--run-dir", str(run_dir)])
        else:
            raise SystemExit(f"unknown pipeline stage: {stage}")
    write_latest_run(fmt, run_dir)
    print(json.dumps({"format": fmt, "run_dir": str(run_dir), "stages": stages}, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run format-specific dual-model training pipeline.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--run-dir", default="")
    parser.add_argument("--run-name", default="")
    parser.add_argument("--model", choices=["", "damage_analysis", "damage_location", "normal_structure", "step_value", "step_action"], default="")
    parser.add_argument("--stage", default="features,train")
    parser.add_argument("--material-root", default=str(Path("repair_training") / "material"))
    parser.add_argument("--manifest", default="")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--seed", default="20260515")
    parser.add_argument("--per-source", type=int, default=1)
    return parser


def _run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def _run_damage_analysis_pipeline(args: argparse.Namespace, *, fmt: str, run_dir: Path) -> None:
    _run([
        sys.executable, "-m", "repair_training.collect_normal_structure_rows",
        "--format", fmt,
        "--material-root", args.material_root,
        "--output", str(run_dir / "datasets" / "normal_structure_rows.jsonl"),
        "--seed", args.seed,
    ] + (["--limit", str(args.limit)] if args.limit else []))
    _run([
        sys.executable, "-m", "repair_training.collect_damage_rows",
        "--format", fmt,
        "--material-root", args.material_root,
        "--output", str(run_dir / "datasets" / "damage_rows.jsonl"),
        "--seed", args.seed,
        "--per-source", str(args.per_source),
        "--workers", str(args.workers),
    ] + (["--manifest", args.manifest] if args.manifest else []) + (["--limit", str(args.limit)] if args.limit else []))
    _run([sys.executable, "-m", "repair_training.build_features", "--format", fmt, "--model", "normal_structure", "--run-dir", str(run_dir)])
    _run([sys.executable, "-m", "repair_training.train", "--format", fmt, "--model", "normal_structure", "--run-dir", str(run_dir)])
    _run([sys.executable, "-m", "repair_training.build_features", "--format", fmt, "--model", "damage_location", "--run-dir", str(run_dir)])
    _run([sys.executable, "-m", "repair_training.train", "--format", fmt, "--model", "damage_location", "--run-dir", str(run_dir)])


def _models(model: str) -> tuple[str, ...]:
    if model == "damage_analysis":
        return ("normal_structure", "damage_location")
    if model:
        return (normalize_model_type(model),)
    return ("normal_structure", "damage_location", "step_value", "step_action")


if __name__ == "__main__":
    raise SystemExit(main())
