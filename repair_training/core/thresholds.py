from __future__ import annotations

from typing import Any

import numpy as np


DEFAULT_THRESHOLD = 0.5


def calibrate_binary_thresholds(
    scores: np.ndarray,
    y: np.ndarray,
    labels: list[str],
    *,
    default_threshold: float = DEFAULT_THRESHOLD,
) -> dict[str, Any]:
    thresholds: dict[str, float] = {}
    per_label: dict[str, dict[str, float]] = {}
    grid = [round(value, 2) for value in np.arange(0.05, 0.951, 0.01)]
    for index, label in enumerate(labels):
        truth = _label_column(y, index) >= 0.5
        label_scores = _label_column(scores, index)
        if len(truth) == 0 or truth.sum() == 0:
            threshold = float(default_threshold)
            metrics = _metrics(label_scores >= threshold, truth)
        else:
            threshold, metrics = _best_threshold(label_scores, truth, grid, default_threshold=default_threshold)
        thresholds[label] = float(threshold)
        per_label[label] = {"threshold": float(threshold), **metrics}
    return {
        "schema_version": 1,
        "default_threshold": float(default_threshold),
        "selection_metric": "f1_then_precision_then_threshold_closeness",
        "thresholds": thresholds,
        "per_label": per_label,
    }


def select_labels_with_thresholds(
    scores: dict[str, float],
    thresholds: dict[str, Any] | None = None,
    *,
    default_threshold: float = DEFAULT_THRESHOLD,
) -> list[str]:
    payload = thresholds if isinstance(thresholds, dict) else {}
    per_label = payload.get("thresholds") if isinstance(payload.get("thresholds"), dict) else {}
    default = float(payload.get("default_threshold", default_threshold) or default_threshold)
    selected: list[str] = []
    for label, score in scores.items():
        threshold = float(per_label.get(label, default) or default)
        if float(score or 0.0) >= threshold:
            selected.append(label)
    return sorted(selected)


def _best_threshold(
    scores: np.ndarray,
    truth: np.ndarray,
    grid: list[float],
    *,
    default_threshold: float,
) -> tuple[float, dict[str, float]]:
    best_threshold = float(default_threshold)
    best_metrics = _metrics(scores >= best_threshold, truth)
    best_key = _rank_key(best_metrics, best_threshold, default_threshold)
    for threshold in grid:
        metrics = _metrics(scores >= threshold, truth)
        key = _rank_key(metrics, threshold, default_threshold)
        if key > best_key:
            best_threshold = float(threshold)
            best_metrics = metrics
            best_key = key
    return best_threshold, best_metrics


def _rank_key(metrics: dict[str, float], threshold: float, default_threshold: float) -> tuple[float, float, float, float]:
    return (
        float(metrics.get("f1", 0.0)),
        float(metrics.get("precision", 0.0)),
        float(metrics.get("recall", 0.0)),
        -abs(float(threshold) - float(default_threshold)),
    )


def _metrics(pred: np.ndarray, truth: np.ndarray) -> dict[str, float]:
    tp = float(np.sum(pred & truth))
    fp = float(np.sum(pred & ~truth))
    fn = float(np.sum(~pred & truth))
    precision = tp / max(1.0, tp + fp)
    recall = tp / max(1.0, tp + fn)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "support": float(tp + fn),
    }


def _label_column(values: np.ndarray, index: int) -> np.ndarray:
    if values.ndim == 1:
        return values
    if values.shape[1] <= index:
        return np.zeros((values.shape[0],), dtype=np.float32)
    return values[:, index]
