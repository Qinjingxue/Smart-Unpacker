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
from repair_training.core.damage_model_inference import DamageAnalysisModel
from repair_training.core.normal_structure_inference import NormalStructureModel
from repair_training.core.datasets import write_json, write_jsonl
from repair_training.core.features import damage_labels_for_row, oracle_damage_labels_for_row, uncertain_labels_for_row
from repair_training.core.plugin import load_training_format_plugin, normalize_format_name
from sunpack.repair.policy.adapters.damage import get_damage_analysis_adapter


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
    cleanup: dict[str, Any] = {"enabled": not bool(args.keep_generated), "removed": []}
    try:
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

        model_root = Path(args.model_dir)
        normal_dir = model_root / "normal_structure"
        location_dir = model_root / "damage_location"
        if normal_dir.is_dir() and location_dir.is_dir():
            normal_model = NormalStructureModel(model_dir=normal_dir, plugin=plugin)
            world_rows: list[dict[str, Any]] = []
            for row in rows:
                payload = row.get("knowledge_payload") if isinstance(row.get("knowledge_payload"), dict) else {}
                normal_scores = normal_model.predict_rows([{"knowledge_payload": payload}])
                world_score = float(normal_scores[0]) if normal_scores else 0.0
                out = dict(row)
                out["world_model"] = {
                    "world_scores": {"normal": world_score, "anomaly": 1.0 - world_score},
                    "structure_anomaly": {"summary": {"world_score": world_score, "max_anomaly": 1.0 - world_score}},
                }
                world_rows.append(out)
            write_jsonl(datasets / "eval_world_model_outputs.jsonl", world_rows)
            damage_model_dir = location_dir
        else:
            damage_model_dir = model_root
        model = DamageAnalysisModel(model_dir=damage_model_dir, plugin=plugin)
        adapter = get_damage_analysis_adapter(fmt)
        if adapter is None:
            raise SystemExit(f"damage analysis adapter is not available for format: {fmt}")
        score_rows = model.predict_rows(rows)
        uncertain_score_rows = model.predict_uncertain_rows(rows)
        threshold_override = args.threshold if args.threshold is not None else None
        predictions = [
            _prediction_row(row, scores, uncertain_scores, model=model, adapter=adapter, threshold=threshold_override)
            for row, scores, uncertain_scores in zip(rows, score_rows, uncertain_score_rows)
        ]
        write_jsonl(predictions_dir / "predictions.jsonl", predictions)
        metrics = evaluate_predictions(
            predictions,
            threshold=float(threshold_override) if threshold_override is not None else float(model.thresholds.get("default_threshold", 0.5) or 0.5),
        )
        metrics["uncertain"] = evaluate_predictions(_uncertain_prediction_view(predictions), threshold=0.5)
        metrics["oracle_reconstructed"] = evaluate_predictions(_oracle_reconstructed_view(predictions), threshold=0.5)
        metrics.update({
            "format": fmt,
            "seed": seed,
            "samples_requested": samples,
            "rows": len(rows),
            "failures": len(failures),
            "threshold_mode": "override" if threshold_override is not None else "model",
            "thresholds_path": str(Path(damage_model_dir) / "thresholds.json") if threshold_override is None else "",
            "elapsed_seconds": round(time.perf_counter() - started, 3),
            "acceptance": _acceptance(metrics),
            "plugin_metadata": plugin.damage_eval_metadata() if plugin.damage_eval_metadata else {},
        })
        write_json(reports / "metrics.json", metrics)
        write_json(reports / "per_label_metrics.json", per_label_metrics(predictions))
        write_json(reports / "profile_summary.json", profile_summary(predictions))
        write_jsonl(reports / "hard_cases.jsonl", hard_cases(predictions))
        print(json.dumps({"output": str(output), "model_dir": str(args.model_dir), "metrics": metrics}, ensure_ascii=False, sort_keys=True))
        return 0
    finally:
        if not args.keep_generated:
            cleanup["removed"].append({"path": str(tmp), "ok": remove_tree_fast(tmp, root=output)})
        write_json(reports / "cleanup_report.json", cleanup)


def _prediction_row(
    row: dict[str, Any],
    scores: dict[str, float],
    uncertain_scores: dict[str, float],
    *,
    model: DamageAnalysisModel,
    adapter: Any,
    threshold: float | None,
) -> dict[str, Any]:
    target = row.get("damage_analysis_target") if isinstance(row.get("damage_analysis_target"), dict) else {}
    knowledge = row.get("knowledge_payload") if isinstance(row.get("knowledge_payload"), dict) else {}
    extraction = _nested(knowledge, "extraction", "failure") or _nested(knowledge, "extraction", "diagnostics") or {}
    analysis = _nested(knowledge, "analysis", "summary") or _nested(knowledge, "analysis") or {}
    true_labels = damage_labels_for_row({"damage_analysis_target": target})
    true_uncertain_labels = uncertain_labels_for_row({"damage_analysis_target": target})
    oracle_labels = oracle_damage_labels_for_row({"damage_analysis_target": target})
    result = adapter.postprocess_scores(
        scores,
        model.thresholds,
        threshold_override=threshold,
        uncertainty_scores=uncertain_scores,
        uncertainty_thresholds=model.uncertain_thresholds,
    )
    predicted = result.damage_labels
    predicted_uncertain = list((result.metadata or {}).get("uncertain_labels") or [])
    return {
        "sample_id": row.get("sample_id"),
        "damage_profile": (row.get("metadata") or {}).get("damage_profile"),
        "true_labels": true_labels,
        "true_uncertain_labels": true_uncertain_labels,
        "oracle_labels": oracle_labels,
        "predicted_labels": predicted,
        "predicted_uncertain_labels": predicted_uncertain,
        "scores": scores,
        "uncertain_scores": uncertain_scores,
        "threshold": float(threshold) if threshold is not None else "model",
        "runtime_summary": {
            "analysis_format": analysis.get("format"),
            "extraction_failure_kind": extraction.get("failure_kind"),
            "extraction_failure_stage": extraction.get("failure_stage"),
        },
    }


def _uncertain_prediction_view(predictions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            **row,
            "true_labels": list(row.get("true_uncertain_labels") or []),
            "predicted_labels": list(row.get("predicted_uncertain_labels") or []),
            "scores": dict(row.get("uncertain_scores") or {}),
        }
        for row in predictions
    ]


def _oracle_reconstructed_view(predictions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            **row,
            "true_labels": list(row.get("oracle_labels") or []),
            "predicted_labels": sorted(set(row.get("predicted_labels") or []) | set(row.get("predicted_uncertain_labels") or [])),
        }
        for row in predictions
    ]


def _acceptance(metrics: dict[str, Any]) -> dict[str, Any]:
    checks = {
        "zone_macro_f1": float(metrics.get("zone_macro_f1") or 0.0) >= 0.85,
        "compound_zone_recall": float(metrics.get("compound_zone_recall") or 0.0) >= 0.85,
        "field_macro_f1": float(metrics.get("field_macro_f1") or 0.0) >= 0.65,
    }
    return {"ok": all(checks.values()), "checks": checks}


def _nested(payload: dict[str, Any], *path: str) -> dict[str, Any]:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict):
            return {}
        current = current.get(key)
    return current if isinstance(current, dict) else {}


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
    parser.add_argument("--threshold", type=float, default=None)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
