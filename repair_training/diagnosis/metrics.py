from __future__ import annotations

from typing import Any


def binary_multilabel_metrics(scores: list[list[float]], labels: list[list[float]], *, threshold: float = 0.5) -> dict[str, Any]:
    tp = fp = fn = 0
    total = 0
    top1_hit = top3_hit = top5_hit = 0
    positive_rows = 0
    for score_row, label_row in zip(scores, labels):
        positives = {index for index, value in enumerate(label_row) if float(value or 0.0) >= 0.5}
        if positives:
            positive_rows += 1
        predicted = {index for index, score in enumerate(score_row) if float(score or 0.0) >= threshold}
        tp += len(predicted & positives)
        fp += len(predicted - positives)
        fn += len(positives - predicted)
        ranked = sorted(range(len(score_row)), key=lambda index: float(score_row[index]), reverse=True)
        top1_hit += int(bool(positives & set(ranked[:1])))
        top3_hit += int(bool(positives & set(ranked[:3])))
        top5_hit += int(bool(positives & set(ranked[:5])))
        total += 1
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    return {
        "micro_precision": precision,
        "micro_recall": recall,
        "micro_f1": f1,
        "top1_hit": top1_hit / max(1, positive_rows),
        "top3_hit": top3_hit / max(1, positive_rows),
        "top5_hit": top5_hit / max(1, positive_rows),
        "rows": total,
        "positive_rows": positive_rows,
    }


def multilabel_set_metrics(scores: list[list[float]], labels: list[list[float]]) -> dict[str, Any]:
    rows = 0
    positive_rows = 0
    recall_top5 = 0.0
    recall_topn = 0.0
    exact_top5 = 0
    exact_topn = 0
    buckets: dict[str, dict[str, float]] = {}
    for score_row, label_row in zip(scores, labels):
        rows += 1
        positives = {index for index, value in enumerate(label_row) if float(value or 0.0) >= 0.5}
        if not positives:
            continue
        positive_rows += 1
        ranked = sorted(range(len(score_row)), key=lambda index: float(score_row[index]), reverse=True)
        root_count = len(positives)
        top5 = set(ranked[:5])
        topn = set(ranked[:root_count])
        recall_top5 += len(positives & top5) / max(1, root_count)
        recall_topn += len(positives & topn) / max(1, root_count)
        exact_top5 += int(positives <= top5)
        exact_topn += int(positives == topn)
        bucket = buckets.setdefault(str(root_count), {
            "rows": 0.0,
            "recall_top5": 0.0,
            "recall_topN": 0.0,
            "exact_top5": 0.0,
            "exact_topN": 0.0,
        })
        bucket["rows"] += 1.0
        bucket["recall_top5"] += len(positives & top5) / max(1, root_count)
        bucket["recall_topN"] += len(positives & topn) / max(1, root_count)
        bucket["exact_top5"] += float(positives <= top5)
        bucket["exact_topN"] += float(positives == topn)
    for bucket in buckets.values():
        count = max(1.0, float(bucket["rows"]))
        for key in ("recall_top5", "recall_topN", "exact_top5", "exact_topN"):
            bucket[key] = bucket[key] / count
    return {
        "rows": rows,
        "positive_rows": positive_rows,
        "recall_top5": recall_top5 / max(1, positive_rows),
        "recall_topN": recall_topn / max(1, positive_rows),
        "exact_top5": exact_top5 / max(1, positive_rows),
        "exact_topN": exact_topn / max(1, positive_rows),
        "by_root_count": buckets,
    }


def clean_false_positive_rate(scores: list[list[float]], labels: list[list[float]], *, threshold: float = 0.5) -> float:
    clean_rows = 0
    false_positive = 0
    for score_row, label_row in zip(scores, labels):
        if any(float(value or 0.0) >= 0.5 for value in label_row):
            continue
        clean_rows += 1
        false_positive += int(any(float(score or 0.0) >= threshold for score in score_row))
    return false_positive / max(1, clean_rows)


def calibrate_global_threshold(
    scores: list[list[float]],
    labels: list[list[float]],
    *,
    max_clean_false_positive_rate: float | None = 0.05,
) -> dict[str, Any]:
    candidates = {0.5, 0.0, 1.0}
    for row in scores:
        for score in row:
            value = max(0.0, min(1.0, float(score or 0.0)))
            candidates.add(value)
            candidates.add(max(0.0, value - 1e-6))
            candidates.add(min(1.0, value + 1e-6))
    best: dict[str, Any] | None = None
    for threshold in sorted(candidates):
        metrics = binary_multilabel_metrics(scores, labels, threshold=threshold)
        clean_fp = clean_false_positive_rate(scores, labels, threshold=threshold)
        if max_clean_false_positive_rate is not None and clean_fp > float(max_clean_false_positive_rate):
            continue
        item = {
            "threshold": float(threshold),
            "micro_f1": float(metrics["micro_f1"]),
            "micro_precision": float(metrics["micro_precision"]),
            "micro_recall": float(metrics["micro_recall"]),
            "clean_false_positive_rate": float(clean_fp),
        }
        if best is None or _better_threshold(item, best):
            best = item
    if best is None:
        metrics = binary_multilabel_metrics(scores, labels, threshold=0.5)
        best = {
            "threshold": 0.5,
            "micro_f1": float(metrics["micro_f1"]),
            "micro_precision": float(metrics["micro_precision"]),
            "micro_recall": float(metrics["micro_recall"]),
            "clean_false_positive_rate": float(clean_false_positive_rate(scores, labels, threshold=0.5)),
            "fallback_reason": "no_threshold_satisfied_clean_fp_constraint",
        }
    return best


def _better_threshold(candidate: dict[str, Any], incumbent: dict[str, Any]) -> bool:
    key = (
        float(candidate.get("micro_f1", 0.0)),
        -float(candidate.get("clean_false_positive_rate", 0.0)),
        float(candidate.get("micro_precision", 0.0)),
        -abs(float(candidate.get("threshold", 0.5)) - 0.5),
    )
    incumbent_key = (
        float(incumbent.get("micro_f1", 0.0)),
        -float(incumbent.get("clean_false_positive_rate", 0.0)),
        float(incumbent.get("micro_precision", 0.0)),
        -abs(float(incumbent.get("threshold", 0.5)) - 0.5),
    )
    return key > incumbent_key
