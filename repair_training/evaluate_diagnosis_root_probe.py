from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from repair_training.core.diagnosis_gnn.actionable_roots import ACTIONABLE_ROOT_SEMANTICS
from repair_training.core.diagnosis_gnn.dataset import read_diagnosis_graph_samples
from repair_training.core.diagnosis_gnn.inference import DiagnosisGNNModel


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    model = DiagnosisGNNModel(model_dir=args.model_dir, device=args.device)
    if model.model_card.get("diagnosis_semantics") != ACTIONABLE_ROOT_SEMANTICS:
        raise SystemExit(f"model is not root-hypothesis semantics: {model.model_card.get('diagnosis_semantics')!r}")
    samples = read_diagnosis_graph_samples(args.input)
    predictions = model.predict_samples(samples)
    probe_rows = read_jsonl(args.probes) if args.probes else []
    pred_rows = []
    for sample, pred in zip(samples, predictions):
        diagnostics = pred.get("diagnostics") if isinstance(pred.get("diagnostics"), dict) else {}
        root = pred.get("root_case") if isinstance(pred.get("root_case"), dict) else {}
        auxiliary = sample.labels.auxiliary if isinstance(sample.labels.auxiliary, dict) else {}
        pred_rows.append({
            "sample_id": sample.sample_id,
            "root_case": root,
            "root_evidence_scores": diagnostics.get("root_evidence_scores") or {},
            "root_evidence_targets": auxiliary.get("root_evidence_targets") if isinstance(auxiliary.get("root_evidence_targets"), dict) else {},
            "root_transition_gain": diagnostics.get("root_transition_gain") or {},
            "true_roots": sample.labels.root_case_labels,
        })
    metrics = _metrics(pred_rows, probe_rows)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    write_jsonl(output / "diagnosis_root_probe_predictions.jsonl", pred_rows)
    write_json(output / "diagnosis_root_probe_metrics.json", metrics)
    print(json.dumps({"output": str(output), "metrics": metrics}, ensure_ascii=False, sort_keys=True))
    return 0


def _metrics(predictions: list[dict[str, Any]], probes: list[dict[str, Any]]) -> dict[str, Any]:
    by_sample = {str(row.get("sample_id") or ""): row for row in predictions}
    pair_correct = pair_total = 0
    gain_errors = []
    evidence_tp = evidence_fp = evidence_fn = 0
    grouped: dict[str, list[dict[str, Any]]] = {}
    for probe in probes:
        key = str(probe.get("graph_sample_id") or probe.get("sample_id") or probe.get("source_sample_id") or "")
        if key:
            grouped.setdefault(key, []).append(probe)
    for sample_id, rows in grouped.items():
        pred = by_sample.get(sample_id)
        if not pred:
            continue
        scores = (pred.get("root_case") or {}).get("scores") or {}
        gains = pred.get("root_transition_gain") or {}
        for row in rows:
            root = str(row.get("candidate_root") or row.get("root_case") or "")
            target = _probe_score(row)
            if root in gains:
                gain_errors.append(abs(float(gains[root]) - target))
        for left in rows:
            left_root = str(left.get("candidate_root") or left.get("root_case") or "")
            left_score = _probe_score(left)
            for right in rows:
                right_root = str(right.get("candidate_root") or right.get("root_case") or "")
                right_score = _probe_score(right)
                if left_root == right_root or left_score <= right_score + 0.03:
                    continue
                pair_total += 1
                pair_correct += int(float(scores.get(left_root, 0.0)) > float(scores.get(right_root, 0.0)))
    first_unlock_hits = {1: 0, 3: 0, 5: 0}
    labeled = 0
    for pred in predictions:
        evidence_scores = pred.get("root_evidence_scores") or {}
        evidence_targets = pred.get("root_evidence_targets") or {}
        if evidence_targets:
            for root, score in evidence_scores.items():
                predicted = float(score) >= 0.5
                truth = _float(evidence_targets.get(root)) >= 0.5
                evidence_tp += int(predicted and truth)
                evidence_fp += int(predicted and not truth)
                evidence_fn += int((not predicted) and truth)
        truth = set(pred.get("true_roots") or [])
        ranked = [str(item.get("root_case") or "") for item in ((pred.get("root_case") or {}).get("ranked") or [])]
        if not truth:
            continue
        labeled += 1
        for k in first_unlock_hits:
            first_unlock_hits[k] += int(bool(set(ranked[:k]) & truth))
    evidence_precision = evidence_tp / max(1, evidence_tp + evidence_fp)
    evidence_recall = evidence_tp / max(1, evidence_tp + evidence_fn)
    evidence_f1 = 0.0 if evidence_precision + evidence_recall <= 0.0 else 2 * evidence_precision * evidence_recall / (evidence_precision + evidence_recall)
    return {
        "rows": len(predictions),
        "probe_rows": len(probes),
        "probe_pairwise_accuracy": pair_correct / max(1, pair_total),
        "root_transition_gain_mae": sum(gain_errors) / max(1, len(gain_errors)),
        "evidence_explanation_f1": evidence_f1,
        "first_unlock_top1": first_unlock_hits[1] / max(1, labeled),
        "first_unlock_top3": first_unlock_hits[3] / max(1, labeled),
        "first_unlock_top5": first_unlock_hits[5] / max(1, labeled),
        "multi_step_progression_hit": first_unlock_hits[3] / max(1, labeled),
    }


def _probe_score(row: dict[str, Any]) -> float:
    values = [
        _float(row.get("recovery_delta")),
        _float(row.get("ak_consistency_delta")),
        _float(row.get("evidence_delta")),
    ]
    return max(0.0, min(1.0, sum(max(0.0, value) for value in values) / max(1, len(values))))


def _float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate DiagnosisGNN root-hypothesis probe metrics.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--probes", default="")
    parser.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
