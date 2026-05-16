from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Any

from repair_training.core.datasets import sha256_file


MODEL_ARTIFACT_SCHEMA_VERSION = 1


def write_model_artifacts(
    model_dir: str | Path,
    *,
    format_name: str,
    model_type: str,
    training_config: dict[str, Any],
    metrics: dict[str, Any],
    feature_schema: dict[str, Any],
    label_schema: dict[str, Any],
    input_files: dict[str, str | Path],
    extra: dict[str, Any] | None = None,
) -> None:
    model_dir = Path(model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    _write_json(model_dir / "training_config.json", training_config)
    _write_json(model_dir / "metrics.json", metrics)
    _write_json(model_dir / "feature_schema.json", feature_schema)
    _write_json(model_dir / ("action_schema.json" if model_type == "repair_action" else "label_schema.json"), label_schema)
    thresholds_path = model_dir / "thresholds.json"
    if not thresholds_path.is_file():
        _write_json(thresholds_path, {"default_threshold": 0.5, "thresholds": {}})
    input_payload = {
        key: {"path": str(path), "sha256": sha256_file(path) if Path(path).is_file() else ""}
        for key, path in input_files.items()
    }
    model_card = {
        "schema_version": MODEL_ARTIFACT_SCHEMA_VERSION,
        "format": format_name,
        "model_type": model_type,
        "algorithm": "lightgbm",
        "created_at": _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "training_run_id": str(training_config.get("run_id") or ""),
        "taxonomy_version": int(training_config.get("taxonomy_version", 1) or 1),
        "input_files": input_payload,
        "metrics": metrics,
        **dict(extra or {}),
    }
    _write_json(model_dir / "model_card.json", model_card)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")
