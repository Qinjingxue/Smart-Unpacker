from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np

from repair_training.core.features import transform_rows
from repair_training.core.plugin import TrainingFormatPlugin
from sunpack.repair.policy.adapters.damage import select_labels_with_thresholds


class DamageAnalysisModel:
    def __init__(self, *, model_dir: str | Path, plugin: TrainingFormatPlugin):
        self.model_dir = Path(model_dir)
        self.plugin = plugin
        self.feature_schema = _read_json(self.model_dir / "feature_schema.json")
        self.label_schema = _read_json(self.model_dir / "label_schema.json")
        self.thresholds = _read_json(self.model_dir / "thresholds.json")
        self.labels = list(self.label_schema.get("labels") or [])
        self.model_index = _read_json(self.model_dir / "models.json")
        self._models: dict[str, Any] = {}

    def predict_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, float]]:
        if not rows:
            return []
        model_type = str(self.feature_schema.get("model_type") or "damage_location")
        x, _ = transform_rows(rows, schema=self.feature_schema, plugin=self.plugin, model_type=model_type)
        return [self._predict_one(x[index]) for index in range(x.shape[0])]

    def _predict_one(self, vector: np.ndarray) -> dict[str, float]:
        output: dict[str, float] = {}
        matrix = vector.reshape(1, -1)
        for label in self.labels:
            model = self._model_for_label(label)
            if isinstance(model, dict) and "constant_probability" in model:
                output[label] = float(model.get("constant_probability") or 0.0)
            else:
                output[label] = float(model.predict(matrix)[0])
        return output

    def _model_for_label(self, label: str) -> Any:
        if label in self._models:
            return self._models[label]
        rel = str(self.model_index.get(label) or "")
        if not rel:
            model = {"constant_probability": 0.0}
        elif rel.endswith(".constant.json"):
            model = _read_json(self.model_dir / rel)
        else:
            try:
                import lightgbm as lgb
            except Exception as exc:  # pragma: no cover
                raise SystemExit("LightGBM is required for damage model evaluation") from exc
            model = lgb.Booster(model_file=str(self.model_dir / rel))
        self._models[label] = model
        return model


def select_labels(scores: dict[str, float], *, threshold: float = 0.5) -> list[str]:
    return select_labels_with_thresholds(
        scores,
        {"default_threshold": float(threshold), "thresholds": {}},
        default_threshold=float(threshold),
    )


def select_labels_from_model(scores: dict[str, float], model: DamageAnalysisModel, *, threshold: float | None = None) -> list[str]:
    if threshold is not None:
        return select_labels(scores, threshold=float(threshold))
    return select_labels_with_thresholds(scores, model.thresholds)


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
