from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from repair_training.core.datasets import write_json, write_jsonl
from repair_training.core.diagnosis_gnn.actionable_roots import ACTIONABLE_ROOT_SEMANTICS, modules_for_root
from repair_training.core.diagnosis_gnn.dataset import read_diagnosis_graph_samples
from repair_training.core.diagnosis_gnn.inference import DiagnosisGNNModel
from repair_training.core.diagnosis_gnn.root_cases import ROOT_CASES


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    model = DiagnosisGNNModel(model_dir=args.model_dir, device=args.device)
    if model.model_card.get("diagnosis_semantics") != ACTIONABLE_ROOT_SEMANTICS:
        raise SystemExit(f"model is not actionable-root semantics: {model.model_card.get('diagnosis_semantics')!r}")
    samples = read_diagnosis_graph_samples(args.input)
    predictions = []
    rows = []
    for sample, pred in zip(samples, model.predict_samples(samples)):
        root = pred.get("root_case") if isinstance(pred.get("root_case"), dict) else {}
        ranked = list(root.get("ranked") or [])
        scores = dict(root.get("scores") or {})
        truth = set(sample.labels.root_case_labels)
        top_roots = [str(item.get("root_case") or "") for item in ranked if str(item.get("root_case") or "")]
        source = sample.source if isinstance(sample.source, dict) else {}
        expected_module = str(source.get("expected_module") or (sample.labels.auxiliary or {}).get("expected_module") or "")
        row = {
            "sample_id": sample.sample_id,
            "true_actionable_roots": sorted(truth),
            "ranked_roots": ranked,
            "actionable_top1_hit": _hit(top_roots, truth, 1),
            "actionable_top3_hit": _hit(top_roots, truth, 3),
            "actionable_top5_hit": _hit(top_roots, truth, 5),
            "first_step_module_hit": _module_hit(top_roots[:5], expected_module),
            "expected_module": expected_module,
        }
        rows.append(row)
        predictions.append({"sample_id": sample.sample_id, "root_case": {"scores": scores, "ranked": ranked}, **row})
    metrics = _metrics(rows)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    write_jsonl(output / "actionable_diagnosis_predictions.jsonl", predictions)
    write_json(output / "actionable_diagnosis_metrics.json", metrics)
    print(json.dumps({"output": str(output), "model_dir": str(args.model_dir), "metrics": metrics}, ensure_ascii=False, sort_keys=True))
    return 0


def _metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {"rows": 0}
    per_label: dict[str, dict[str, Any]] = {}
    for label in ROOT_CASES:
        label_rows = [row for row in rows if label in set(row.get("true_actionable_roots") or [])]
        if not label_rows:
            continue
        per_label[label] = {
            "rows": len(label_rows),
            "top1_hit": sum(1 for row in label_rows if row["actionable_top1_hit"]) / len(label_rows),
            "top3_hit": sum(1 for row in label_rows if row["actionable_top3_hit"]) / len(label_rows),
            "top5_hit": sum(1 for row in label_rows if row["actionable_top5_hit"]) / len(label_rows),
        }
    module_rows = [row for row in rows if row.get("expected_module")]
    return {
        "rows": len(rows),
        "actionable_top1": sum(1 for row in rows if row["actionable_top1_hit"]) / len(rows),
        "actionable_top3": sum(1 for row in rows if row["actionable_top3_hit"]) / len(rows),
        "actionable_top5": sum(1 for row in rows if row["actionable_top5_hit"]) / len(rows),
        "first_step_module_hit_top5": (
            sum(1 for row in module_rows if row["first_step_module_hit"]) / len(module_rows)
            if module_rows else 0.0
        ),
        "per_label": per_label,
    }


def _hit(ranked_roots: list[str], truth: set[str], k: int) -> bool:
    return bool(truth and set(ranked_roots[:k]) & truth)


def _module_hit(top_roots: list[str], expected_module: str) -> bool:
    if not expected_module:
        return False
    modules = set()
    for root in top_roots:
        modules.update(modules_for_root(root))
    return expected_module in modules


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate DiagnosisGNN actionable-root repair-priority predictions.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
