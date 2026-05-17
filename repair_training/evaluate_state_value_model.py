from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np

from repair_training.core.datasets import read_jsonl, write_json
from repair_training.core.features import transform_rows
from repair_training.core.plugin import load_training_format_plugin, normalize_format_name


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    plugin = load_training_format_plugin(fmt)
    model_dir = Path(args.model_dir).resolve()
    rows = read_jsonl(args.state_value_rows)
    if args.limit and args.limit > 0:
        rows = rows[: args.limit]
    schema = _read_json(model_dir / "feature_schema.json")
    x, y = transform_rows(rows, schema=schema, plugin=plugin, model_type="graph_state_value")
    scores = _predict(model_dir, x)
    report = _metrics(scores, y)
    report.update({
        "format": fmt,
        "rows": len(rows),
        "model_dir": str(model_dir),
        "state_value_rows": str(Path(args.state_value_rows).resolve()),
    })
    write_json(args.output, report)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


def _predict(model_dir: Path, x: np.ndarray) -> np.ndarray:
    model_path = model_dir / "model.txt"
    if not model_path.is_file():
        raise SystemExit(f"missing state value model: {model_path}")
    try:
        import lightgbm as lgb
    except Exception as exc:  # pragma: no cover
        raise SystemExit("LightGBM is required for state value evaluation.") from exc
    booster = lgb.Booster(model_file=str(model_path))
    return np.asarray(booster.predict(x) if len(x) else [], dtype=np.float32)


def _metrics(scores: np.ndarray, y: np.ndarray) -> dict[str, Any]:
    y1 = y[:, 0] if getattr(y, "ndim", 1) > 1 else y
    if len(y1) == 0:
        return {"mae": 0.0, "rmse": 0.0, "r2": 0.0, "bucket_accuracy": 0.0}
    clipped = np.clip(scores, 0.0, 1.0)
    err = clipped - y1
    variance = float(np.sum((y1 - np.mean(y1)) ** 2))
    high_truth = y1 >= 0.8
    high_pred = clipped >= 0.8
    truth_bucket = np.floor(np.clip(y1, 0.0, 0.999999) * 5.0).astype(int)
    pred_bucket = np.floor(np.clip(clipped, 0.0, 0.999999) * 5.0).astype(int)
    return {
        "mae": float(np.mean(np.abs(err))),
        "rmse": float(np.sqrt(np.mean(err * err))),
        "r2": 1.0 - float(np.sum(err * err)) / variance if variance > 1e-9 else 0.0,
        "bucket_accuracy": float(np.mean(truth_bucket == pred_bucket)),
        "bias": float(np.mean(err)),
        "overestimation_mean": float(np.mean(np.maximum(err, 0.0))),
        "underestimation_mean": float(np.mean(np.maximum(-err, 0.0))),
        "high_value_recall": float(np.sum(high_truth & high_pred) / max(1.0, np.sum(high_truth))),
        "high_value_precision": float(np.sum(high_truth & high_pred) / max(1.0, np.sum(high_pred))),
    }


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate a trained StateValue LightGBM model on state_value_rows.jsonl.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--state-value-rows", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--limit", type=int, default=0)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
