from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from repair_training.collect_damage_rows import collect_damage_rows
from repair_training.core.cleanup import remove_tree_fast
from repair_training.core.damage_eval import (
    evaluate_predictions,
    hard_cases,
    leakage_report,
    per_label_metrics,
    profile_summary,
)
from repair_training.core.damage_model_inference import DamageAnalysisModel, select_labels
from repair_training.core.datasets import write_json, write_jsonl
from repair_training.core.plugin import load_training_format_plugin, normalize_format_name


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    plugin = load_training_format_plugin(fmt)
    if plugin.damage_eval_profile_plan is None or plugin.generate_damage_eval_records is None:
        raise SystemExit(f"format plugin does not implement damage eval hooks: {fmt}")
    output = Path(args.output).resolve()
    datasets = output / "datasets"
    predictions_dir = output / "predictions"
    reports = output / "reports"
    tmp = output / "tmp"
    for path in (datasets, predictions_dir, reports, tmp):
        path.mkdir(parents=True, exist_ok=True)

    started = time.perf_counter()
    seed = int(args.seed or 0)
    samples = max(0, int(args.samples or 0))
    profile_plan = plugin.damage_eval_profile_plan(samples, seed)
    records = plugin.generate_damage_eval_records(
        args.material_root,
        tmp / "generated",
        seed,
        samples,
        profile_plan,
    )
    rows, failures = collect_damage_rows(
        records,
        workspace=tmp / "observed",
        workers=max(1, int(args.workers or 1)),
    )
    write_jsonl(datasets / "eval_damage_rows.jsonl", rows)
    write_jsonl(datasets / "eval_failures.jsonl", failures)

    leak = leakage_report(rows)
    write_json(reports / "leakage_report.json", leak)
    if not leak.get("ok"):
        raise SystemExit(f"damage eval leakage check failed: {reports / 'leakage_report.json'}")

    model = DamageAnalysisModel(model_dir=args.model_dir, plugin=plugin)
    score_rows = model.predict_rows(rows)
    predictions = [
        _prediction_row(row, scores, threshold=float(args.threshold or 0.5))
        for row, scores in zip(rows, score_rows)
    ]
    write_jsonl(predictions_dir / "predictions.jsonl", predictions)
    metrics = evaluate_predictions(predictions, threshold=float(args.threshold or 0.5))
    metrics.update({
        "format": fmt,
        "seed": seed,
        "samples_requested": samples,
        "rows": len(rows),
        "failures": len(failures),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "acceptance": _acceptance(metrics),
        "plugin_metadata": plugin.damage_eval_metadata() if plugin.damage_eval_metadata else {},
    })
    write_json(reports / "metrics.json", metrics)
    write_json(reports / "per_label_metrics.json", per_label_metrics(predictions))
    write_json(reports / "profile_summary.json", profile_summary(predictions))
    write_jsonl(reports / "hard_cases.jsonl", hard_cases(predictions))

    cleanup: dict[str, Any] = {"enabled": not bool(args.keep_generated), "removed": []}
    if not args.keep_generated:
        cleanup["removed"].append({"path": str(tmp), "ok": remove_tree_fast(tmp, root=output)})
    write_json(reports / "cleanup_report.json", cleanup)
    print(json.dumps({"output": str(output), "model_dir": str(args.model_dir), "metrics": metrics}, ensure_ascii=False, sort_keys=True))
    return 0


def _prediction_row(row: dict[str, Any], scores: dict[str, float], *, threshold: float) -> dict[str, Any]:
    target = row.get("damage_analysis_target") if isinstance(row.get("damage_analysis_target"), dict) else {}
    runtime = ((row.get("damage_analysis_input") or {}).get("runtime_context") or {})
    extraction = runtime.get("extraction_summary") if isinstance(runtime.get("extraction_summary"), dict) else {}
    analysis = runtime.get("analysis_summary") if isinstance(runtime.get("analysis_summary"), dict) else {}
    true_labels = sorted(str(label) for label in target.get("damage_labels") or [])
    predicted = select_labels(scores, threshold=threshold)
    return {
        "sample_id": row.get("sample_id"),
        "damage_profile": (row.get("metadata") or {}).get("damage_profile"),
        "true_labels": true_labels,
        "predicted_labels": predicted,
        "scores": scores,
        "threshold": float(threshold),
        "runtime_summary": {
            "analysis_format": analysis.get("format"),
            "extraction_failure_kind": extraction.get("failure_kind"),
            "extraction_failure_stage": extraction.get("failure_stage"),
        },
    }


def _acceptance(metrics: dict[str, Any]) -> dict[str, Any]:
    checks = {
        "zone_macro_f1": float(metrics.get("zone_macro_f1") or 0.0) >= 0.85,
        "compound_zone_recall": float(metrics.get("compound_zone_recall") or 0.0) >= 0.85,
        "field_macro_f1": float(metrics.get("field_macro_f1") or 0.0) >= 0.65,
    }
    return {"ok": all(checks.values()), "checks": checks}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate a format-specific DamageAnalysis model on fresh corruptions.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--material-root", default=str(Path("repair_training") / "material"))
    parser.add_argument("--output", required=True)
    parser.add_argument("--seed", type=int, default=20260516)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--keep-generated", action="store_true")
    parser.add_argument("--threshold", type=float, default=0.5)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
