from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np

from repair_training.core.features import transform_rows
from repair_training.core.plugin import TrainingFormatPlugin


class NormalStructureModel:
    def __init__(self, *, model_dir: str | Path, plugin: TrainingFormatPlugin):
        self.model_dir = Path(model_dir)
        self.plugin = plugin
        self.feature_schema = _read_json(self.model_dir / "feature_schema.json")
        self.constant = _read_json(self.model_dir / "model.constant.json")
        self._model: Any = None

    def predict_rows(self, rows: list[dict[str, Any]]) -> list[float]:
        if not rows:
            return []
        if "constant_probability" in self.constant:
            return [float(self.constant.get("constant_probability") or 0.0) for _ in rows]
        x, _ = transform_rows(rows, schema=self.feature_schema, plugin=self.plugin, model_type="normal_structure")
        model = self._load_model()
        scores = model.predict(x) if len(x) else np.array([], dtype=np.float32)
        return [float(item) for item in scores]

    def _load_model(self) -> Any:
        if self._model is not None:
            return self._model
        try:
            import lightgbm as lgb
        except Exception as exc:  # pragma: no cover
            raise SystemExit("LightGBM is required for normal structure inference") from exc
        self._model = lgb.Booster(model_file=str(self.model_dir / "model.txt"))
        return self._model


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
