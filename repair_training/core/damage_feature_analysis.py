from __future__ import annotations

import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from repair_training.core.features import damage_labels_for_row, feature_spec, flatten
from repair_training.core.plugin import TrainingFeatureSpec, TrainingFormatPlugin


MAX_REPORT_FEATURES = 30


def analyze_damage_features(
    *,
    rows_path: str | Path,
    output_dir: str | Path,
    plugin: TrainingFormatPlugin,
    predictions_path: str | Path | None = None,
) -> dict[str, Any]:
    rows = read_jsonl(rows_path)
    predictions = read_jsonl(predictions_path) if predictions_path else []
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    spec = feature_spec(plugin, "damage_location")
    prepared = [_prepared_row(row, spec) for row in rows]
    prediction_by_id = _prediction_index(predictions)
    labels = _focus_or_all_labels(plugin, prepared)
    profiles = sorted({item["damage_profile"] for item in prepared if item["damage_profile"]})

    label_report = {
        label: _label_feature_report(label, prepared)
        for label in labels
    }
    profile_report = {
        profile: _profile_signature(profile, prepared)
        for profile in profiles
    }
    pair_report = [
        _profile_pair_diff(left, right, prepared)
        for left, right in _profile_pairs(plugin, prepared)
    ]
    hard_cases = _hard_case_rows(prepared, prediction_by_id)
    summary = _summary(
        prepared=prepared,
        label_report=label_report,
        profile_report=profile_report,
        pair_report=pair_report,
        hard_cases=hard_cases,
        plugin=plugin,
    )

    write_json(output / "label_feature_correlation.json", label_report)
    write_json(output / "profile_feature_signature.json", profile_report)
    write_json(output / "profile_pair_diffs.json", pair_report)
    write_jsonl(output / "hard_case_feature_report.jsonl", hard_cases)
    write_json(output / "summary.json", summary)
    (output / "summary.md").write_text(_summary_markdown(summary), encoding="utf-8")
    return summary


def _prepared_row(row: dict[str, Any], spec: TrainingFeatureSpec) -> dict[str, Any]:
    payload = row.get("knowledge_payload") if isinstance(row.get("knowledge_payload"), dict) else row
    flat = flatten(payload)
    filtered = {key: value for key, value in flat.items() if _allowed_feature(key, spec)}
    sample_id = str(row.get("sample_id") or (row.get("metadata") or {}).get("sample_id") or "")
    profile = str((row.get("metadata") or {}).get("damage_profile") or row.get("damage_profile") or row.get("eval_profile") or "")
    labels = damage_labels_for_row(row)
    return {
        "row": row,
        "sample_id": sample_id,
        "damage_profile": profile,
        "labels": labels,
        "features": filtered,
    }


def _label_feature_report(label: str, prepared: list[dict[str, Any]]) -> dict[str, Any]:
    positives = [row for row in prepared if label in row["labels"]]
    negatives = [row for row in prepared if label not in row["labels"]]
    keys = _feature_keys(positives + negatives)
    stats = [_feature_stat(key, positives, negatives) for key in keys]
    stats = [item for item in stats if item["support"] > 0]
    top_positive = sorted(stats, key=lambda item: item["positive_score"], reverse=True)[:MAX_REPORT_FEATURES]
    top_negative = sorted(stats, key=lambda item: item["negative_score"], reverse=True)[:MAX_REPORT_FEATURES]
    low = [
        item for item in sorted(stats, key=lambda item: item["separability"])
        if item["support"] >= max(2, int(len(prepared) * 0.05))
    ][:MAX_REPORT_FEATURES]
    constant = [item for item in stats if item.get("constant_or_missing")][:MAX_REPORT_FEATURES]
    return {
        "positive_count": len(positives),
        "negative_count": len(negatives),
        "top_positive_features": top_positive,
        "top_negative_features": top_negative,
        "low_separability_features": low,
        "missing_or_constant_features": constant,
        "diagnosis": _label_diagnosis(label, positives, negatives, stats),
    }


def _profile_signature(profile: str, prepared: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [row for row in prepared if row["damage_profile"] == profile]
    others = [row for row in prepared if row["damage_profile"] != profile]
    stats = [_feature_stat(key, rows, others) for key in _feature_keys(rows + others)]
    stats = [item for item in stats if item["support"] > 0]
    labels = Counter(label for row in rows for label in row["labels"])
    return {
        "profile": profile,
        "row_count": len(rows),
        "top_labels": labels.most_common(20),
        "signature_features": sorted(stats, key=lambda item: item["positive_score"], reverse=True)[:MAX_REPORT_FEATURES],
        "absent_features": sorted(stats, key=lambda item: item["negative_score"], reverse=True)[:MAX_REPORT_FEATURES],
    }


def _profile_pair_diff(left: str, right: str, prepared: list[dict[str, Any]]) -> dict[str, Any]:
    left_rows = [row for row in prepared if row["damage_profile"] == left]
    right_rows = [row for row in prepared if row["damage_profile"] == right]
    stats = [_feature_stat(key, left_rows, right_rows) for key in _feature_keys(left_rows + right_rows)]
    stats = [item for item in stats if item["support"] > 0]
    ranked = sorted(stats, key=lambda item: item["separability"], reverse=True)
    label_left = Counter(label for row in left_rows for label in row["labels"])
    label_right = Counter(label for row in right_rows for label in row["labels"])
    return {
        "left": left,
        "right": right,
        "left_count": len(left_rows),
        "right_count": len(right_rows),
        "separability_score": round(_mean([item["separability"] for item in ranked[:50]]), 6),
        "top_left_features": sorted(stats, key=lambda item: item["positive_score"], reverse=True)[:MAX_REPORT_FEATURES],
        "top_right_features": sorted(stats, key=lambda item: item["negative_score"], reverse=True)[:MAX_REPORT_FEATURES],
        "overlapping_features": [
            item for item in sorted(stats, key=lambda item: item["separability"])
            if item["support"] >= 2
        ][:MAX_REPORT_FEATURES],
        "left_top_labels": label_left.most_common(12),
        "right_top_labels": label_right.most_common(12),
    }


def _hard_case_rows(prepared: list[dict[str, Any]], prediction_by_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in prepared:
        pred = prediction_by_id.get(item["sample_id"])
        if not pred:
            continue
        true_labels = set(str(label) for label in pred.get("true_labels") or item["labels"])
        predicted_labels = set(str(label) for label in pred.get("predicted_labels") or [])
        missing = sorted(true_labels - predicted_labels)
        extra = sorted(predicted_labels - true_labels)
        if not missing and not extra:
            continue
        output.append({
            "sample_id": item["sample_id"],
            "damage_profile": item["damage_profile"],
            "missing_labels": missing,
            "extra_labels": extra,
            "label_margins": _label_margins(missing + extra, pred),
            "top_features": _top_sample_features(item["features"]),
            "top_anomaly_attribution": _top_anomaly_attribution(item["row"]),
        })
    return output


def _feature_stat(key: str, positives: list[dict[str, Any]], negatives: list[dict[str, Any]]) -> dict[str, Any]:
    pos_values = [row["features"].get(key) for row in positives]
    neg_values = [row["features"].get(key) for row in negatives]
    values = [value for value in pos_values + neg_values if value not in (None, "")]
    kind = _feature_kind(values)
    support = len(values)
    base: dict[str, Any] = {"feature": key, "kind": kind, "support": support}
    if not values:
        base.update({"separability": 0.0, "positive_score": 0.0, "negative_score": 0.0, "constant_or_missing": True})
        return base
    if kind in {"numeric", "boolean"}:
        pos_nums = [_to_float(value) for value in pos_values if value not in (None, "")]
        neg_nums = [_to_float(value) for value in neg_values if value not in (None, "")]
        pos_mean = _mean(pos_nums)
        neg_mean = _mean(neg_nums)
        diff = pos_mean - neg_mean
        auc = _threshold_auc(pos_nums, neg_nums)
        separability = max(abs(diff), abs(auc - 0.5) * 2.0)
        base.update({
            "positive_mean": round(pos_mean, 6),
            "negative_mean": round(neg_mean, 6),
            "mean_diff": round(diff, 6),
            "threshold_auc": round(auc, 6),
            "positive_score": round(max(0.0, diff) + max(0.0, auc - 0.5), 6),
            "negative_score": round(max(0.0, -diff) + max(0.0, 0.5 - auc), 6),
            "separability": round(separability, 6),
            "positive_missing_rate": _missing_rate(pos_values),
            "negative_missing_rate": _missing_rate(neg_values),
            "constant_or_missing": len(set(round(_to_float(value), 8) for value in values)) <= 1,
        })
        if kind == "boolean":
            base["lift"] = round((pos_mean + 1e-9) / (neg_mean + 1e-9), 6)
        return base
    pos_dist = _distribution(pos_values)
    neg_dist = _distribution(neg_values)
    tv = _total_variation(pos_dist, neg_dist)
    pos_top = pos_dist.most_common(1)[0][0] if pos_dist else ""
    neg_top = neg_dist.most_common(1)[0][0] if neg_dist else ""
    base.update({
        "positive_top": pos_top,
        "negative_top": neg_top,
        "positive_distribution": dict(pos_dist.most_common(8)),
        "negative_distribution": dict(neg_dist.most_common(8)),
        "total_variation": round(tv, 6),
        "positive_score": round(tv if pos_top != neg_top else tv * 0.5, 6),
        "negative_score": round(tv if pos_top != neg_top else tv * 0.5, 6),
        "separability": round(tv, 6),
        "positive_missing_rate": _missing_rate(pos_values),
        "negative_missing_rate": _missing_rate(neg_values),
        "constant_or_missing": len(set(str(value) for value in values)) <= 1,
    })
    return base


def _label_diagnosis(
    label: str,
    positives: list[dict[str, Any]],
    negatives: list[dict[str, Any]],
    stats: list[dict[str, Any]],
) -> dict[str, Any]:
    if len(positives) < 5:
        return {"class": "too_few_samples", "reason": f"only {len(positives)} positive samples"}
    if not stats:
        return {"class": "missing_or_constant_features", "reason": "no training-visible features"}
    top_sep = max(float(item.get("separability") or 0.0) for item in stats)
    constant_ratio = sum(1 for item in stats if item.get("constant_or_missing")) / float(max(1, len(stats)))
    if top_sep >= 0.35:
        return {"class": "separable", "reason": "high-separability features exist", "top_separability": round(top_sep, 6)}
    if constant_ratio >= 0.8:
        return {"class": "missing_or_constant_features", "reason": "most visible features are constant/missing", "constant_ratio": round(constant_ratio, 6)}
    if negatives and len(positives) / float(len(positives) + len(negatives)) < 0.03:
        return {"class": "too_few_samples", "reason": "very rare positive label", "positive_count": len(positives)}
    return {"class": "overlapping_distributions", "reason": "positive and negative feature distributions overlap", "top_separability": round(top_sep, 6)}


def _summary(
    *,
    prepared: list[dict[str, Any]],
    label_report: dict[str, Any],
    profile_report: dict[str, Any],
    pair_report: list[dict[str, Any]],
    hard_cases: list[dict[str, Any]],
    plugin: TrainingFormatPlugin,
) -> dict[str, Any]:
    diagnosis_counts = Counter((item.get("diagnosis") or {}).get("class") for item in label_report.values())
    weak_labels = sorted(
        (
            {
                "label": label,
                "positive_count": report.get("positive_count"),
                "diagnosis": report.get("diagnosis"),
                "top_feature": (report.get("top_positive_features") or [{}])[0].get("feature"),
            }
            for label, report in label_report.items()
        ),
        key=lambda item: (str((item["diagnosis"] or {}).get("class")), int(item.get("positive_count") or 0)),
    )[:30]
    return {
        "format": plugin.format_name,
        "row_count": len(prepared),
        "feature_count": len(_feature_keys(prepared)),
        "feature_groups": _feature_group_summary(prepared, plugin),
        "profile_count": len(profile_report),
        "label_count": len(label_report),
        "hard_case_count": len(hard_cases),
        "diagnosis_counts": dict(diagnosis_counts),
        "weak_labels": weak_labels,
        "least_separable_profile_pairs": sorted(pair_report, key=lambda item: item.get("separability_score") or 0.0)[:20],
    }


def _summary_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Damage Feature Analysis",
        "",
        f"- format: `{summary.get('format')}`",
        f"- rows: `{summary.get('row_count')}`",
        f"- training-visible features: `{summary.get('feature_count')}`",
        f"- labels: `{summary.get('label_count')}`",
        f"- hard cases: `{summary.get('hard_case_count')}`",
        "",
        "## Diagnosis Counts",
    ]
    for key, value in sorted((summary.get("diagnosis_counts") or {}).items()):
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Feature Groups"])
    for key, value in sorted((summary.get("feature_groups") or {}).items()):
        lines.append(f"- `{key}`: {value.get('feature_count', 0)} features")
    lines.extend(["", "## Weak Labels"])
    for item in summary.get("weak_labels") or []:
        diagnosis = item.get("diagnosis") or {}
        lines.append(f"- `{item.get('label')}`: {diagnosis.get('class')} ({diagnosis.get('reason')})")
    lines.extend(["", "## Least Separable Profile Pairs"])
    for item in summary.get("least_separable_profile_pairs") or []:
        lines.append(f"- `{item.get('left')}` vs `{item.get('right')}`: {item.get('separability_score')}")
    lines.append("")
    return "\n".join(lines)


def _feature_group_summary(prepared: list[dict[str, Any]], plugin: TrainingFormatPlugin) -> dict[str, Any]:
    if plugin.diagnostic_feature_groups is None:
        return {}
    keys = _feature_keys(prepared)
    output: dict[str, Any] = {}
    for group, prefixes in plugin.diagnostic_feature_groups().items():
        matched = [key for key in keys if any(key.startswith(prefix) for prefix in prefixes)]
        output[group] = {
            "feature_count": len(matched),
            "examples": matched[:20],
        }
    return output


def _prediction_index(predictions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for row in predictions:
        sample_id = str(row.get("sample_id") or "")
        if sample_id:
            output[sample_id] = row
    return output


def _focus_or_all_labels(plugin: TrainingFormatPlugin, prepared: list[dict[str, Any]]) -> list[str]:
    labels = sorted({label for row in prepared for label in row["labels"]})
    if plugin.diagnostic_focus_labels:
        focus = [label for label in plugin.diagnostic_focus_labels() if label in labels]
        return focus or labels
    return labels


def _profile_pairs(plugin: TrainingFormatPlugin, prepared: list[dict[str, Any]]) -> list[tuple[str, str]]:
    profiles = sorted({row["damage_profile"] for row in prepared if row["damage_profile"]})
    output: list[tuple[str, str]] = []
    if plugin.diagnostic_profile_pairs:
        output.extend((left, right) for left, right in plugin.diagnostic_profile_pairs() if left in profiles and right in profiles)
    if output:
        return output
    label_sets = {profile: set(label for row in prepared if row["damage_profile"] == profile for label in row["labels"]) for profile in profiles}
    scored: list[tuple[float, str, str]] = []
    for index, left in enumerate(profiles):
        for right in profiles[index + 1:]:
            union = label_sets[left] | label_sets[right]
            overlap = len(label_sets[left] & label_sets[right]) / float(max(1, len(union)))
            scored.append((overlap, left, right))
    return [(left, right) for _, left, right in sorted(scored, reverse=True)[:30]]


def _feature_keys(rows: list[dict[str, Any]]) -> list[str]:
    return sorted({key for row in rows for key in row["features"]})


def _allowed_feature(key: str, spec: TrainingFeatureSpec) -> bool:
    if key in spec.ignore_paths:
        return False
    if any(key.startswith(prefix) for prefix in spec.ignore_prefixes):
        return False
    if spec.include_prefixes and not any(key == prefix or key.startswith(prefix) for prefix in spec.include_prefixes):
        return False
    return True


def _feature_kind(values: list[Any]) -> str:
    if not values:
        return "numeric"
    if all(_is_bool_like(value) for value in values):
        return "boolean"
    if all(_is_number(value) for value in values):
        return "numeric"
    return "categorical"


def _threshold_auc(pos: list[float], neg: list[float]) -> float:
    if not pos or not neg:
        return 0.5
    wins = 0.0
    total = 0
    for left in pos:
        for right in neg:
            total += 1
            if left > right:
                wins += 1.0
            elif left == right:
                wins += 0.5
    return wins / float(max(1, total))


def _distribution(values: list[Any]) -> Counter[str]:
    return Counter(str(value if value not in (None, "") else "<MISSING>") for value in values)


def _total_variation(left: Counter[str], right: Counter[str]) -> float:
    left_total = float(max(1, sum(left.values())))
    right_total = float(max(1, sum(right.values())))
    keys = set(left) | set(right)
    return 0.5 * sum(abs(left.get(key, 0) / left_total - right.get(key, 0) / right_total) for key in keys)


def _missing_rate(values: list[Any]) -> float:
    if not values:
        return 1.0
    return round(sum(1 for value in values if value in (None, "")) / float(len(values)), 6)


def _label_margins(labels: list[str], prediction: dict[str, Any]) -> dict[str, Any]:
    scores = prediction.get("scores") if isinstance(prediction.get("scores"), dict) else {}
    threshold = prediction.get("threshold")
    output: dict[str, Any] = {}
    for label in labels:
        score = _to_float(scores.get(label))
        if isinstance(threshold, dict):
            limit = _to_float(threshold.get(label, threshold.get("default_threshold", 0.5)))
        else:
            limit = 0.5 if threshold in (None, "model") else _to_float(threshold, 0.5)
        output[label] = {"score": round(score, 6), "threshold": round(limit, 6), "margin": round(score - limit, 6)}
    return output


def _top_sample_features(features: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key, value in features.items():
        if value in (None, "", 0, 0.0, False):
            continue
        rows.append({"feature": key, "value": value})
    return rows[:MAX_REPORT_FEATURES]


def _top_anomaly_attribution(row: dict[str, Any]) -> dict[str, Any]:
    payload = row.get("knowledge_payload") if isinstance(row.get("knowledge_payload"), dict) else {}
    structure = (((payload.get("runtime_context") or {}).get("analysis_native_probe") or {}).get("structure") or {})
    anomaly = structure.get("anomaly") if isinstance(structure.get("anomaly"), dict) else {}
    compact = anomaly.get("compact_attribution") if isinstance(anomaly.get("compact_attribution"), dict) else {}
    return {
        "top_queries": compact.get("top_queries") or [],
        "by_field": compact.get("by_field") or {},
        "by_relation": compact.get("by_relation") or {},
    }


def _mean(values: list[float]) -> float:
    return sum(values) / float(len(values)) if values else 0.0


def _to_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    try:
        result = float(value)
        if math.isnan(result) or math.isinf(result):
            return default
        return result
    except (TypeError, ValueError):
        return default


def _is_number(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    try:
        float(value)
        return True
    except (TypeError, ValueError):
        return False


def _is_bool_like(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        return float(value) in (0.0, 1.0)
    text = str(value).lower()
    return text in {"true", "false", "0", "1"}
