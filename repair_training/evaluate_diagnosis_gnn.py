from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from repair_training.core.datasets import write_json, write_jsonl
from repair_training.core.diagnosis_gnn.dataset import read_diagnosis_graph_samples
from repair_training.core.diagnosis_gnn.inference import DiagnosisGNNModel
from repair_training.core.diagnosis_gnn.metrics import (
    binary_multilabel_metrics,
    calibrate_global_threshold,
    clean_false_positive_rate,
    multilabel_set_metrics,
)
from repair_training.core.diagnosis_gnn.tensorize import metadata_for_sample
from repair_training.core.plugin import normalize_format_name


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    samples = read_diagnosis_graph_samples(args.input)
    model = DiagnosisGNNModel(model_dir=args.model_dir, device=args.device)
    thresholds = _thresholds_for_model(model, override=args.threshold)
    predictions = []
    cause_scores_rows: list[list[float]] = []
    cause_label_rows: list[list[float]] = []
    field_scores: list[dict[str, float]] = []
    field_labels: list[list[str]] = []
    zone_scores: list[dict[str, float]] = []
    zone_labels: list[list[str]] = []
    theory_edge_scores: list[list[float]] = []
    theory_edge_labels: list[list[float]] = []
    for sample, pred in zip(samples, model.predict_samples(samples)):
        metadata = metadata_for_sample(sample)
        scores_by_node = dict((pred.get("root_cause") or {}).get("cause_scores") or {})
        score_row = [float(scores_by_node.get(node_id, 0.0)) for node_id in metadata.cause_node_ids]
        label_set = set(sample.labels.cause_node_ids)
        label_row = [1.0 if node_id in label_set else 0.0 for node_id in metadata.cause_node_ids]
        cause_scores_rows.append(score_row)
        cause_label_rows.append(label_row)
        root = pred.get("root_cause") if isinstance(pred.get("root_cause"), dict) else {}
        field_scores.append(dict(root.get("field_scores") or {}))
        field_labels.append(list(sample.labels.field_labels))
        zone_scores.append(dict(root.get("zone_scores") or {}))
        zone_labels.append([label.split(":", 1)[1] for label in sample.labels.zone_labels if ":" in label])
        edge_scores_by_id = dict((pred.get("diagnostics") or {}).get("theory_edge_scores") or {})
        theory_edge_scores.append([float(edge_scores_by_id.get(edge_id, 0.0)) for edge_id in metadata.theory_edge_ids])
        edge_label_set = set(sample.labels.theory_edge_ids)
        theory_edge_labels.append([1.0 if edge_id in edge_label_set else 0.0 for edge_id in metadata.theory_edge_ids])
        predictions.append({
            "sample_id": sample.sample_id,
            "format": sample.format,
            "true_field_labels": list(sample.labels.field_labels),
            "true_zone_labels": list(sample.labels.zone_labels),
            **pred,
        })
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    metrics = {
        "format": fmt,
        "rows": len(samples),
        "thresholds": thresholds,
        "cause": binary_multilabel_metrics(cause_scores_rows, cause_label_rows, threshold=float(thresholds["cause_threshold"])),
        "cause_set": multilabel_set_metrics(cause_scores_rows, cause_label_rows),
        "clean_false_positive_rate": clean_false_positive_rate(cause_scores_rows, cause_label_rows, threshold=float(thresholds["cause_threshold"])),
        "field": _label_score_metrics(field_scores, field_labels, threshold=float(thresholds["field_threshold"])),
        "field_per_label": _per_label_topk(field_scores, field_labels),
        "zone": _label_score_metrics(zone_scores, zone_labels, threshold=float(thresholds["zone_threshold"])),
        "theory_edge": binary_multilabel_metrics(
            theory_edge_scores,
            theory_edge_labels,
            threshold=float(thresholds["theory_edge_threshold"]),
        ),
    }
    write_jsonl(output / "diagnosis_gnn_predictions.jsonl", predictions)
    write_json(output / "diagnosis_gnn_metrics.json", metrics)
    print(json.dumps({"output": str(output), "model_dir": str(args.model_dir), "metrics": metrics}, ensure_ascii=False, sort_keys=True))
    return 0


def _label_score_metrics(score_rows: list[dict[str, float]], label_rows: list[list[str]], *, threshold: float = 0.5) -> dict[str, Any]:
    labels = sorted({label for row in label_rows for label in row} | {label for scores in score_rows for label in scores})
    if not labels:
        return {"micro_f1": 0.0, "macro_f1": 0.0, "top1_hit": 0.0, "top3_hit": 0.0, "top5_hit": 0.0}
    score_matrix = [[float(scores.get(label, 0.0)) for label in labels] for scores in score_rows]
    label_matrix = [[1.0 if label in set(row) else 0.0 for label in labels] for row in label_rows]
    base = binary_multilabel_metrics(score_matrix, label_matrix, threshold=threshold)
    per_label_f1 = []
    for index, _label in enumerate(labels):
        tp = fp = fn = 0
        for scores, truth in zip(score_matrix, label_matrix):
            predicted = scores[index] >= threshold
            actual = truth[index] >= 0.5
            tp += int(predicted and actual)
            fp += int(predicted and not actual)
            fn += int((not predicted) and actual)
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        per_label_f1.append(2 * precision * recall / max(1e-9, precision + recall))
    return {
        "threshold": threshold,
        "micro_f1": base["micro_f1"],
        "macro_f1": sum(per_label_f1) / max(1, len(per_label_f1)),
        "top1_hit": base["top1_hit"],
        "top3_hit": base["top3_hit"],
        "top5_hit": base["top5_hit"],
    }


def _per_label_topk(score_rows: list[dict[str, float]], label_rows: list[list[str]]) -> dict[str, Any]:
    counts: dict[str, dict[str, float]] = {}
    labels = sorted({label for row in label_rows for label in row})
    for label in labels:
        rows = [index for index, truth in enumerate(label_rows) if label in set(truth)]
        if not rows:
            continue
        top1 = top3 = top5 = 0
        for index in rows:
            ranked = [
                item
                for item, _score in sorted(score_rows[index].items(), key=lambda pair: pair[1], reverse=True)
            ]
            top1 += int(label in ranked[:1])
            top3 += int(label in ranked[:3])
            top5 += int(label in ranked[:5])
        counts[label] = {
            "rows": len(rows),
            "top1_hit": top1 / len(rows),
            "top3_hit": top3 / len(rows),
            "top5_hit": top5 / len(rows),
        }
    if counts:
        counts["_macro"] = {
            "rows": sum(int(value["rows"]) for value in counts.values()),
            "top1_hit": sum(float(value["top1_hit"]) for value in counts.values()) / len(counts),
            "top3_hit": sum(float(value["top3_hit"]) for value in counts.values()) / len(counts),
            "top5_hit": sum(float(value["top5_hit"]) for value in counts.values()) / len(counts),
        }
    return counts


def _thresholds_for_model(model: DiagnosisGNNModel, *, override: float | None) -> dict[str, float]:
    if override is not None:
        return {
            "cause_threshold": float(override),
            "field_threshold": float(override),
            "zone_threshold": float(override),
            "theory_edge_threshold": float(override),
            "source": "override",
        }
    raw = model.thresholds if isinstance(model.thresholds, dict) else {}
    cause = raw.get("cause") if isinstance(raw.get("cause"), dict) else {}
    return {
        "cause_threshold": float(cause.get("threshold", raw.get("default_threshold", 0.5))),
        "field_threshold": float(raw.get("field_threshold", cause.get("threshold", 0.5))),
        "zone_threshold": float(raw.get("zone_threshold", cause.get("threshold", 0.5))),
        "theory_edge_threshold": float(((raw.get("theory_edge_alignment") or {}).get("threshold", 0.5))),
        "source": "model",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate a DiagnosisGNN root-cause model.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--input", required=True)
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    parser.add_argument("--threshold", type=float, default=None)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
