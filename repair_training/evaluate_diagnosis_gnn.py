from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from repair_training.core.datasets import write_json, write_jsonl
from repair_training.core.diagnosis_gnn.dataset import read_diagnosis_graph_samples
from repair_training.core.diagnosis_gnn.inference import DiagnosisGNNModel
from repair_training.core.diagnosis_gnn.metrics import binary_multilabel_metrics, clean_false_positive_rate, multilabel_set_metrics
from repair_training.core.diagnosis_gnn.root_cases import ROOT_CASES, ROOT_CASE_INDEX
from repair_training.core.diagnosis_gnn.tensorize import metadata_for_sample
from repair_training.core.plugin import normalize_format_name


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    samples = read_diagnosis_graph_samples(args.input)
    model = DiagnosisGNNModel(model_dir=args.model_dir, device=args.device)
    thresholds = _thresholds_for_model(model, override=args.threshold)
    predictions = []
    score_rows: list[list[float]] = []
    label_rows: list[list[float]] = []
    theory_edge_scores: list[list[float]] = []
    theory_edge_labels: list[list[float]] = []
    for sample, pred in zip(samples, model.predict_samples(samples)):
        root = pred.get("root_case") if isinstance(pred.get("root_case"), dict) else {}
        scores = dict(root.get("scores") or {})
        score_rows.append([float(scores.get(label, 0.0)) for label in ROOT_CASES])
        truth = set(sample.labels.root_case_labels)
        label_rows.append([1.0 if label in truth else 0.0 for label in ROOT_CASES])
        metadata = metadata_for_sample(sample)
        edge_scores_by_id = dict((pred.get("diagnostics") or {}).get("theory_edge_scores") or {})
        theory_edge_scores.append([float(edge_scores_by_id.get(edge_id, 0.0)) for edge_id in metadata.theory_edge_ids])
        edge_label_set = set(sample.labels.theory_edge_ids)
        theory_edge_labels.append([1.0 if edge_id in edge_label_set else 0.0 for edge_id in metadata.theory_edge_ids])
        predictions.append({
            "sample_id": sample.sample_id,
            "format": sample.format,
            "true_root_cases": sorted(truth),
            **pred,
        })
    threshold = float(thresholds["root_case_threshold"])
    metrics = {
        "format": fmt,
        "rows": len(samples),
        "thresholds": thresholds,
        "root_case": binary_multilabel_metrics(score_rows, label_rows, threshold=threshold),
        "root_case_set": multilabel_set_metrics(score_rows, label_rows),
        "root_case_per_label": _per_label_topk(score_rows, label_rows),
        "clean_false_positive_rate": clean_false_positive_rate(score_rows, label_rows, threshold=threshold),
        "theory_edge": binary_multilabel_metrics(
            theory_edge_scores,
            theory_edge_labels,
            threshold=float(thresholds["theory_edge_threshold"]),
        ),
    }
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    write_jsonl(output / "diagnosis_gnn_predictions.jsonl", predictions)
    write_json(output / "diagnosis_gnn_metrics.json", metrics)
    print(json.dumps({"output": str(output), "model_dir": str(args.model_dir), "metrics": metrics}, ensure_ascii=False, sort_keys=True))
    return 0


def _per_label_topk(score_rows: list[list[float]], label_rows: list[list[float]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for index, label in enumerate(ROOT_CASES):
        rows = [row_index for row_index, truth in enumerate(label_rows) if index < len(truth) and truth[index] >= 0.5]
        if not rows:
            continue
        top1 = top3 = top5 = 0
        for row_index in rows:
            ranked = sorted(range(len(score_rows[row_index])), key=lambda item: float(score_rows[row_index][item]), reverse=True)
            top1 += int(index in ranked[:1])
            top3 += int(index in ranked[:3])
            top5 += int(index in ranked[:5])
        output[label] = {
            "rows": len(rows),
            "top1_hit": top1 / len(rows),
            "top3_hit": top3 / len(rows),
            "top5_hit": top5 / len(rows),
        }
    if output:
        output["_macro"] = {
            "rows": sum(int(item["rows"]) for item in output.values()),
            "top1_hit": sum(float(item["top1_hit"]) for item in output.values()) / len(output),
            "top3_hit": sum(float(item["top3_hit"]) for item in output.values()) / len(output),
            "top5_hit": sum(float(item["top5_hit"]) for item in output.values()) / len(output),
        }
    return output


def _thresholds_for_model(model: DiagnosisGNNModel, *, override: float | None) -> dict[str, Any]:
    raw = dict(model.thresholds or {})
    root = raw.get("root_case") if isinstance(raw.get("root_case"), dict) else {}
    root_threshold = float(root.get("threshold", raw.get("root_case_threshold", raw.get("default_threshold", 0.5))))
    if override is not None:
        root_threshold = float(override)
    theory_edge = raw.get("theory_edge_alignment") if isinstance(raw.get("theory_edge_alignment"), dict) else {}
    return {
        "source": "override" if override is not None else "model",
        "root_case_threshold": root_threshold,
        "root_case_label_thresholds": dict(raw.get("root_case_label_thresholds") or {}),
        "theory_edge_threshold": float(theory_edge.get("threshold", 0.5)),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate DiagnosisGNN root-case-direct predictions.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--input", required=True)
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    parser.add_argument("--threshold", type=float, default=None)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
