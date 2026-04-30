from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


DEFAULT_INPUTS = [
    Path("repair_training") / "datasets" / "repair_plan_ltr_success_pipeline.jsonl",
    Path("repair_training") / "datasets" / "repair_plan_ltr_failure_pipeline.jsonl",
]
DEFAULT_OUTPUT_DIR = Path("repair_training") / "models" / "by_format"
FORMATS = ("zip", "tar", "tar_gz", "tar_bz2", "tar_xz", "gzip", "bzip2", "xz", "zstd", "7z", "rar")
FEATURE_VIEWS = ("runtime_only", "runtime_plus_repair_prior", "teacher_only_baseline")
LABEL_TARGETS = {"immediate", "future", "discounted", "blended", "terminal_recovery_ratio", "discounted_terminal_recovery_ratio"}


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    inputs = _input_paths(args.input)
    output_root = Path(args.output_dir)
    output_root.mkdir(parents=True, exist_ok=True)
    formats = _csv(args.formats) or list(FORMATS)
    views = _csv(args.feature_views) or list(FEATURE_VIEWS)
    registry: dict[str, Any] = {
        "schema_version": 1,
        "input_files": [str(path) for path in inputs],
        "output_dir": str(output_root),
        "formats": {},
    }
    for fmt in formats:
        fmt_record: dict[str, Any] = {"format": fmt, "feature_views": {}}
        registry["formats"][fmt] = fmt_record
        for view in views:
            view_dir = output_root / fmt / view
            command = [
                sys.executable,
                str(REPO_ROOT / "repair_training" / "train_ltr.py"),
                "--feature-view",
                view,
                "--format-scope",
                fmt,
                "--label-target",
                args.label_target,
                "--split-by",
                args.split_by,
                "--output-dir",
                str(view_dir),
                "--seed",
                str(args.seed),
                "--min-trainable-queries",
                str(args.min_trainable_queries),
                "--min-candidates-per-query",
                str(args.min_candidates_per_query),
            ]
            if args.include_single_candidate_queries:
                command.append("--include-single-candidate-queries")
            for path in inputs:
                command.extend(["--input", str(path)])
            print(f"==> Training {fmt}/{view}", flush=True)
            completed = subprocess.run(command, cwd=REPO_ROOT)
            if completed.returncode != 0:
                fmt_record["feature_views"][view] = {
                    "status": "failed",
                    "exit_code": completed.returncode,
                    "output_dir": str(view_dir),
                }
                continue
            fmt_record["feature_views"][view] = _view_status(view_dir)
    registry["summary"] = _registry_summary(registry)
    (output_root / "model_registry.json").write_text(json.dumps(registry, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(registry["summary"], ensure_ascii=False, sort_keys=True))
    return 1 if registry["summary"]["failed_views"] else 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train one LTR ranker set per material format.")
    parser.add_argument("--input", action="append", default=[], help="Input JSONL file. Repeatable; defaults to pipeline success/failure outputs.")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--formats", default="", help="Comma-separated material formats. Defaults to all supported training formats.")
    parser.add_argument("--feature-views", default="", help="Comma-separated feature views. Defaults to all views.")
    parser.add_argument("--label-target", choices=sorted(LABEL_TARGETS), default="terminal_recovery_ratio")
    parser.add_argument("--split-by", choices=("query", "episode", "source_sample", "source_profile", "profile_holdout"), default="source_sample")
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--min-trainable-queries", type=int, default=30)
    parser.add_argument("--min-candidates-per-query", type=int, default=2)
    parser.add_argument("--include-single-candidate-queries", action="store_true")
    return parser


def _input_paths(inputs: list[str]) -> list[Path]:
    paths = [Path(item) for item in inputs] if inputs else list(DEFAULT_INPUTS)
    return [path for path in paths if path.is_file()]


def _csv(raw: str) -> list[str]:
    return [part.strip() for part in str(raw or "").split(",") if part.strip()]


def _view_status(view_dir: Path) -> dict[str, Any]:
    training_summary = view_dir / "training_summary.json"
    skip_summary = view_dir / "skip_summary.json"
    if training_summary.is_file():
        summary = json.loads(training_summary.read_text(encoding="utf-8"))
        return {
            "status": "trained",
            "output_dir": str(view_dir),
            "row_count": summary.get("row_count"),
            "query_count": summary.get("query_count"),
            "feature_count": summary.get("feature_count"),
            "label_target": summary.get("label_target"),
            "raw_label_counts": summary.get("raw_label_counts", {}),
            "label_target": summary.get("label_target"),
            "metrics": summary.get("metrics", {}),
        }
    if skip_summary.is_file():
        summary = json.loads(skip_summary.read_text(encoding="utf-8"))
        return {
            "status": "skipped",
            "skip_reason": summary.get("skip_reason"),
            "output_dir": str(view_dir),
            "row_count": summary.get("row_count"),
            "query_count": summary.get("query_count"),
            "raw_label_counts": summary.get("raw_label_counts", {}),
        }
    return {"status": "missing", "output_dir": str(view_dir)}


def _registry_summary(registry: dict[str, Any]) -> dict[str, int]:
    trained = skipped = failed = missing = 0
    for fmt in registry.get("formats", {}).values():
        for view in fmt.get("feature_views", {}).values():
            status = view.get("status")
            if status == "trained":
                trained += 1
            elif status == "skipped":
                skipped += 1
            elif status == "failed":
                failed += 1
            else:
                missing += 1
    return {
        "trained_views": trained,
        "skipped_views": skipped,
        "failed_views": failed,
        "missing_views": missing,
    }


if __name__ == "__main__":
    raise SystemExit(main())
