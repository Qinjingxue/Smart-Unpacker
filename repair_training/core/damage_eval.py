from __future__ import annotations

import json
from collections import Counter
from typing import Any


FORBIDDEN_INPUT_TOKENS = (
    "corruption_plan",
    "damage_profile",
    "damage_analysis_target",
    "oracle_damage",
    "candidate_payload",
    "candidate_snapshot",
    "selected_module",
    "action_value",
    "long_term_value",
)


def leakage_report(rows: list[dict[str, Any]]) -> dict[str, Any]:
    leaked: list[dict[str, Any]] = []
    bad_patch_depth = 0
    bad_patch_stack = 0
    structure_counts: Counter[str] = Counter()
    for index, row in enumerate(rows):
        payload = row.get("knowledge_payload") if isinstance(row.get("knowledge_payload"), dict) else {}
        text = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).lower()
        tokens = [token for token in FORBIDDEN_INPUT_TOKENS if token in text]
        runtime = payload
        if tokens:
            leaked.append({"index": index, "sample_id": row.get("sample_id"), "tokens": tokens})
        _add_structure_coverage(runtime, structure_counts)
    structure_coverage = _structure_coverage_payload(structure_counts, len(rows))
    return {
        "row_count": len(rows),
        "leak_count": len(leaked),
        "leaks": leaked[:100],
        "bad_patch_depth": bad_patch_depth,
        "bad_patch_stack": bad_patch_stack,
        "structure_coverage": structure_coverage,
        "ok": not leaked and bad_patch_depth == 0 and bad_patch_stack == 0,
    }


def _add_structure_coverage(runtime: dict[str, Any], counts: Counter[str]) -> None:
    fmt = runtime.get("format") if isinstance(runtime.get("format"), dict) else {}
    zip_payload = fmt.get("zip") if isinstance(fmt.get("zip"), dict) else {}
    structure = zip_payload.get("structure") if isinstance(zip_payload.get("structure"), dict) else {}
    raw_structure = {}
    if structure or raw_structure:
        counts["analysis_native_probe_structure_present"] += 1
    merged = structure or raw_structure
    if isinstance(merged.get("eocd"), dict) or any(str(key).startswith("eocd.") for key in merged):
        counts["zip_eocd_structure_present"] += 1
    if isinstance(merged.get("local_header"), dict) or any(str(key).startswith("local_header.") for key in merged):
        counts["zip_local_header_present"] += 1
    if isinstance(merged.get("directory_consistency"), dict) or any(
        str(key).startswith("directory_consistency.") for key in merged
    ):
        counts["zip_directory_consistency_present"] += 1
    if isinstance(merged.get("zip64_consistency"), dict) or any(str(key).startswith("zip64_consistency.") for key in merged):
        counts["zip64_consistency_present"] += 1


def _structure_coverage_payload(counts: Counter[str], total: int) -> dict[str, Any]:
    return {
        name: {"count": int(counts.get(name, 0)), "ratio": float(counts.get(name, 0) / total) if total else 0.0}
        for name in (
            "zip_eocd_structure_present",
            "zip_local_header_present",
            "zip_directory_consistency_present",
            "zip64_consistency_present",
            "analysis_native_probe_structure_present",
        )
    }


def evaluate_predictions(predictions: list[dict[str, Any]], *, threshold: float = 0.5) -> dict[str, Any]:
    labels = sorted({
        label
        for row in predictions
        for label in [*(row.get("true_labels") or []), *(row.get("predicted_labels") or [])]
    })
    per_label = {label: _label_metrics(predictions, label) for label in labels}
    zone_labels = [label for label in labels if label.startswith("zone:")]
    field_labels = [label for label in labels if label.startswith("field:")]
    compound = [row for row in predictions if _is_compound(row)]
    return {
        "threshold": float(threshold),
        "rows": len(predictions),
        "label_count": len(labels),
        "zone_macro_f1": _macro(per_label, zone_labels, "f1"),
        "zone_micro_f1": _micro(predictions, prefix="zone:")["f1"],
        "zone_precision": _micro(predictions, prefix="zone:")["precision"],
        "zone_recall": _micro(predictions, prefix="zone:")["recall"],
        "field_macro_f1": _macro(per_label, field_labels, "f1"),
        "field_micro_f1": _micro(predictions, prefix="field:")["f1"],
        "field_precision": _micro(predictions, prefix="field:")["precision"],
        "field_recall": _micro(predictions, prefix="field:")["recall"],
        "exact_match": _exact_match(predictions),
        "zone_exact_match": _exact_match(predictions, prefix="zone:"),
        "field_exact_match": _exact_match(predictions, prefix="field:"),
        "top3_zone_recall": _topk_recall(predictions, prefix="zone:", k=3),
        "compound_count": len(compound),
        "compound_zone_recall": _micro(compound, prefix="zone:")["recall"] if compound else 0.0,
        "compound_field_f1": _micro(compound, prefix="field:")["f1"] if compound else 0.0,
        "hard_case_count": len(hard_cases(predictions)),
        "low_performing_labels": [
            {"label": label, **metrics}
            for label, metrics in per_label.items()
            if metrics["support"] > 0 and metrics["f1"] < 0.65
        ],
    }


def per_label_metrics(predictions: list[dict[str, Any]]) -> dict[str, Any]:
    labels = sorted({
        label
        for row in predictions
        for label in [*(row.get("true_labels") or []), *(row.get("predicted_labels") or [])]
    })
    return {label: _label_metrics(predictions, label) for label in labels}


def hard_cases(predictions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for row in predictions:
        truth = set(row.get("true_labels") or [])
        pred = set(row.get("predicted_labels") or [])
        if truth != pred:
            output.append({
                "sample_id": row.get("sample_id"),
                "damage_profile": row.get("damage_profile"),
                "missing": sorted(truth - pred),
                "extra": sorted(pred - truth),
                "true_labels": sorted(truth),
                "predicted_labels": sorted(pred),
            })
    return output


def profile_summary(predictions: list[dict[str, Any]]) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    exact: Counter[str] = Counter()
    for row in predictions:
        profile = str(row.get("damage_profile") or "")
        counts[profile] += 1
        if set(row.get("true_labels") or []) == set(row.get("predicted_labels") or []):
            exact[profile] += 1
    return {
        profile: {
            "count": int(count),
            "exact_match": float(exact.get(profile, 0) / count) if count else 0.0,
        }
        for profile, count in sorted(counts.items())
    }


def _label_metrics(predictions: list[dict[str, Any]], label: str) -> dict[str, float]:
    tp = fp = fn = 0
    for row in predictions:
        truth = label in set(row.get("true_labels") or [])
        pred = label in set(row.get("predicted_labels") or [])
        tp += int(truth and pred)
        fp += int((not truth) and pred)
        fn += int(truth and not pred)
    return _prf(tp, fp, fn) | {"support": float(tp + fn)}


def _micro(predictions: list[dict[str, Any]], *, prefix: str) -> dict[str, float]:
    tp = fp = fn = 0
    for row in predictions:
        truth = {label for label in row.get("true_labels") or [] if label.startswith(prefix)}
        pred = {label for label in row.get("predicted_labels") or [] if label.startswith(prefix)}
        tp += len(truth & pred)
        fp += len(pred - truth)
        fn += len(truth - pred)
    return _prf(tp, fp, fn)


def _prf(tp: int, fp: int, fn: int) -> dict[str, float]:
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    return {"precision": precision, "recall": recall, "f1": f1}


def _macro(per_label: dict[str, dict[str, float]], labels: list[str], key: str) -> float:
    values = [per_label[label].get(key, 0.0) for label in labels if label in per_label and per_label[label].get("support", 0.0) > 0]
    return sum(values) / max(1, len(values))


def _exact_match(predictions: list[dict[str, Any]], *, prefix: str = "") -> float:
    if not predictions:
        return 0.0
    correct = 0
    for row in predictions:
        truth = set(row.get("true_labels") or [])
        pred = set(row.get("predicted_labels") or [])
        if prefix:
            truth = {label for label in truth if label.startswith(prefix)}
            pred = {label for label in pred if label.startswith(prefix)}
        correct += int(truth == pred)
    return correct / len(predictions)


def _topk_recall(predictions: list[dict[str, Any]], *, prefix: str, k: int) -> float:
    recalls = []
    for row in predictions:
        truth = {label for label in row.get("true_labels") or [] if label.startswith(prefix)}
        if not truth:
            continue
        scores = row.get("scores") if isinstance(row.get("scores"), dict) else {}
        top = {
            label
            for label, _score in sorted(
                [(label, float(score or 0.0)) for label, score in scores.items() if label.startswith(prefix)],
                key=lambda item: item[1],
                reverse=True,
            )[:k]
        }
        recalls.append(len(truth & top) / len(truth))
    return sum(recalls) / max(1, len(recalls))


def _is_compound(row: dict[str, Any]) -> bool:
    profile = str(row.get("damage_profile") or "").lower()
    return profile.startswith("compound_") or len(row.get("true_labels") or []) >= 4
