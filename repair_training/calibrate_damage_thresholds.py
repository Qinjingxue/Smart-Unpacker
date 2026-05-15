from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from repair_training.core.damage_eval import evaluate_predictions, per_label_metrics
from sunpack.repair.policy.adapters.damage import get_damage_analysis_adapter


DEFAULT_GRID = tuple(round(value / 100, 2) for value in range(5, 96, 2))


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    rows = _read_jsonl(args.predictions)
    model_dir = Path(args.model_dir).resolve()
    output_model_dir = Path(args.output_model_dir).resolve()
    if output_model_dir != model_dir:
        if output_model_dir.exists():
            shutil.rmtree(output_model_dir)
        shutil.copytree(model_dir, output_model_dir)
    base_thresholds = _read_json(model_dir / "thresholds.json")
    labels = sorted({label for row in rows for label in (row.get("scores") or {}).keys() if str(label).startswith(("zone:", "field:"))})
    thresholds, history = calibrate_thresholds(
        rows,
        fmt=args.format,
        labels=labels,
        base_thresholds=base_thresholds,
        passes=max(1, int(args.passes or 1)),
        grid=_grid(args.grid),
    )
    summary = _summary(rows, fmt=args.format, thresholds=thresholds)
    thresholds.update({
        "schema_version": 1,
        "selection_metric": "coordinate_search_exact_macro_compound",
        "calibration": {
            "source_predictions": str(Path(args.predictions).resolve()),
            "rows": len(rows),
            "passes": max(1, int(args.passes or 1)),
            "objective": "0.30*exact + 0.20*field_macro + 0.20*zone_macro + 0.15*field_exact + 0.10*zone_exact + 0.05*compound_zone_recall",
            "history": history,
            "metrics": summary["metrics"],
            "per_label_metrics": summary["per_label"],
        },
    })
    (output_model_dir / "thresholds.json").write_text(json.dumps(thresholds, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    report_dir = output_model_dir / "calibration"
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "calibration_metrics.json").write_text(json.dumps(summary["metrics"], ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    (report_dir / "per_label_metrics.json").write_text(json.dumps(summary["per_label"], ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"output_model_dir": str(output_model_dir), "metrics": summary["metrics"]}, ensure_ascii=False, sort_keys=True))
    return 0


def calibrate_thresholds(
    rows: list[dict[str, Any]],
    *,
    fmt: str,
    labels: list[str],
    base_thresholds: dict[str, Any],
    passes: int,
    grid: tuple[float, ...],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    current = {
        label: float((base_thresholds.get("thresholds") or {}).get(label, base_thresholds.get("default_threshold", 0.5)) or 0.5)
        for label in labels
    }
    history: list[dict[str, Any]] = []
    best_score = _objective(_predict(rows, fmt=fmt, thresholds=_payload(base_thresholds, current)))
    for pass_index in range(passes):
        changed = 0
        for label in labels:
            original = current[label]
            label_best_threshold = original
            label_best_score = best_score
            for threshold in grid:
                current[label] = float(threshold)
                score = _objective(_predict(rows, fmt=fmt, thresholds=_payload(base_thresholds, current)))
                if score > label_best_score + 1e-12 or (abs(score - label_best_score) <= 1e-12 and abs(threshold - 0.5) < abs(label_best_threshold - 0.5)):
                    label_best_score = score
                    label_best_threshold = float(threshold)
            current[label] = label_best_threshold
            if abs(label_best_threshold - original) > 1e-9:
                changed += 1
                best_score = label_best_score
        history.append({"pass": pass_index + 1, "changed_labels": changed, "objective": best_score})
        if changed == 0:
            break
    return _payload(base_thresholds, current), history


def _payload(base: dict[str, Any], thresholds: dict[str, float]) -> dict[str, Any]:
    return {
        "default_threshold": float(base.get("default_threshold", 0.5) or 0.5),
        "thresholds": {label: float(value) for label, value in sorted(thresholds.items())},
    }


def _predict(rows: list[dict[str, Any]], *, fmt: str, thresholds: dict[str, Any]) -> list[dict[str, Any]]:
    adapter = get_damage_analysis_adapter(fmt)
    if adapter is None:
        raise SystemExit(f"missing damage adapter for format: {fmt}")
    output = []
    for row in rows:
        scores = {str(label): float(score or 0.0) for label, score in (row.get("scores") or {}).items()}
        result = adapter.postprocess_scores(scores, thresholds)
        output.append({**row, "predicted_labels": list(result.damage_labels), "threshold": "calibrated"})
    return output


def _objective(predictions: list[dict[str, Any]]) -> float:
    metrics = evaluate_predictions(predictions)
    return (
        0.30 * float(metrics.get("exact_match") or 0.0)
        + 0.20 * float(metrics.get("field_macro_f1") or 0.0)
        + 0.20 * float(metrics.get("zone_macro_f1") or 0.0)
        + 0.15 * float(metrics.get("field_exact_match") or 0.0)
        + 0.10 * float(metrics.get("zone_exact_match") or 0.0)
        + 0.05 * float(metrics.get("compound_zone_recall") or 0.0)
    )


def _summary(rows: list[dict[str, Any]], *, fmt: str, thresholds: dict[str, Any]) -> dict[str, Any]:
    predictions = _predict(rows, fmt=fmt, thresholds=thresholds)
    return {"metrics": evaluate_predictions(predictions), "per_label": per_label_metrics(predictions)}


def _grid(raw: str) -> tuple[float, ...]:
    if not raw:
        return DEFAULT_GRID
    return tuple(sorted({float(item) for item in raw.split(",") if item.strip()}))


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def _read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Calibrate DamageAnalysis per-label thresholds from prediction rows.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--output-model-dir", required=True)
    parser.add_argument("--passes", type=int, default=3)
    parser.add_argument("--grid", default="")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
