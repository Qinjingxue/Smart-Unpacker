from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np

from repair_training.core.features import transform_rows
from repair_training.core.plugin import TrainingFormatPlugin
from repair_training.core.world_field import (
    WORLD_SEMANTICS,
    flatten_world_payload,
    load_world_index,
    row_for_flat_world_payload,
    row_for_inference,
    world_summary,
)


class NormalStructureModel:
    def __init__(self, *, model_dir: str | Path, plugin: TrainingFormatPlugin):
        self.model_dir = Path(model_dir)
        self.plugin = plugin
        self.feature_schema = _read_json(self.model_dir / "feature_schema.json")
        self.model_card = _read_json(self.model_dir / "model_card.json")
        self.index = load_world_index(self.model_dir)
        if self.model_card and self.model_card.get("world_semantics") != WORLD_SEMANTICS:
            raise RuntimeError(f"unsupported World model semantics: {self.model_card.get('world_semantics')!r}")
        if not self.index or self.index.get("world_semantics") != WORLD_SEMANTICS:
            raise RuntimeError("normal_structure model is not a masked ArchiveKnowledge world field model")
        self._models: dict[str, Any] = {}
        self._constants: dict[str, dict[str, Any]] = {}

    def analyze_knowledge(self, knowledge_payload: dict[str, Any]) -> dict[str, Any]:
        return self.analyze_knowledge_batch([knowledge_payload])[0]

    def analyze_knowledge_batch(self, knowledge_payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
        outputs = [
            {
                "world_field_scores": {},
                "world_field_predictions": {},
                "world_summary": {},
                "structure_anomaly": {"summary": {}},
            }
            for _ in knowledge_payloads
        ]
        if not knowledge_payloads:
            return outputs
        heads = self.index.get("heads") if isinstance(self.index.get("heads"), dict) else {}
        flat_payloads = [
            flatten_world_payload(payload if isinstance(payload, dict) else {})
            for payload in knowledge_payloads
        ]
        for field_path, head in sorted(heads.items()):
            if not isinstance(head, dict):
                continue
            indexed_rows: list[tuple[int, dict[str, Any]]] = []
            for row_index, flat in enumerate(flat_payloads):
                row = row_for_flat_world_payload(flat, field_path)
                if row is not None:
                    indexed_rows.append((row_index, row))
            if not indexed_rows:
                continue
            predictions = self._predict_field_batch([row for _index, row in indexed_rows], head)
            for (row_index, _row), prediction in zip(indexed_rows, predictions):
                if not prediction:
                    continue
                outputs[row_index]["world_field_predictions"][field_path] = prediction
                outputs[row_index]["world_field_scores"][field_path] = float(prediction.get("score") or 0.0)
        for output in outputs:
            summary = world_summary(output["world_field_scores"])
            output["world_summary"] = summary
            output["structure_anomaly"] = {"summary": summary}
        return outputs

    def analyze_knowledge_slow(self, knowledge_payload: dict[str, Any]) -> dict[str, Any]:
        predictions: dict[str, dict[str, Any]] = {}
        scores: dict[str, float] = {}
        heads = self.index.get("heads") if isinstance(self.index.get("heads"), dict) else {}
        for field_path, head in sorted(heads.items()):
            if not isinstance(head, dict):
                continue
            row = row_for_inference(knowledge_payload, field_path)
            if row is None:
                continue
            prediction = self._predict_field(row, head)
            if not prediction:
                continue
            predictions[field_path] = prediction
            scores[field_path] = float(prediction.get("score") or 0.0)
        summary = world_summary(scores)
        return {
            "world_field_scores": scores,
            "world_field_predictions": predictions,
            "world_summary": summary,
            "structure_anomaly": {"summary": summary},
        }

    def predict_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return self.analyze_knowledge_batch([_knowledge_payload(row) for row in rows])

    def _predict_field(self, row: dict[str, Any], head: dict[str, Any]) -> dict[str, Any]:
        predictions = self._predict_field_batch([row], head)
        return predictions[0] if predictions else {}

    def _predict_field_batch(self, rows: list[dict[str, Any]], head: dict[str, Any]) -> list[dict[str, Any]]:
        kind = str(head.get("kind") or "")
        value_type = str(head.get("value_type") or (rows[0].get("value_type") if rows else "") or "")
        if not rows:
            return []
        if kind.startswith("constant"):
            payload = self._load_constant(head)
            output = []
            if value_type == "numeric":
                predicted = float(payload.get("constant", head.get("constant", 0.0)) or 0.0)
                for row in rows:
                    actual = row.get("target_value")
                    residual = abs(float(row.get("target_numeric") or 0.0) - predicted)
                    score = _calibrated_score(residual, head) * _rank_weight(head)
                    output.append(_prediction(actual, predicted, residual, score, value_type, "constant_numeric", raw_score=residual, rank_weight=_rank_weight(head)))
                return output
            predicted = str(payload.get("constant", head.get("constant", "")) or "")
            for row in rows:
                actual = row.get("target_value")
                probability = 1.0 if str(row.get("target_category") or "") == predicted else 0.0
                error = 1.0 - probability
                score = _calibrated_score(error, head) * _rank_weight(head)
                output.append(_prediction(actual, predicted, error, score, value_type, "constant_categorical", probability=probability, raw_score=error, rank_weight=_rank_weight(head)))
            return output
        x, _ = transform_rows(rows, schema=self.feature_schema, plugin=self.plugin, model_type="normal_structure")
        model = self._load_model(head)
        if value_type == "numeric":
            raw_predictions = self._model_predict(model, x) if len(x) else np.zeros((0,), dtype=np.float32)
            output = []
            for row, raw_pred in zip(rows, raw_predictions):
                actual = row.get("target_value")
                predicted = float(raw_pred)
                residual = abs(float(row.get("target_numeric") or 0.0) - predicted)
                score = _calibrated_score(residual, head) * _rank_weight(head)
                output.append(_prediction(actual, predicted, residual, score, value_type, "numeric_regressor", raw_score=residual, rank_weight=_rank_weight(head)))
            return output
        raw = self._model_predict(model, x) if len(x) else np.array([[1.0]], dtype=np.float32)
        classes = [str(item) for item in head.get("classes") or []]
        output = []
        for index, row in enumerate(rows):
            actual = row.get("target_value")
            actual_category = str(row.get("target_category") or "")
            raw_one = raw[index:index + 1] if getattr(raw, "ndim", 1) > 1 else np.asarray([raw[index]])
            probability = _class_probability(raw_one, classes, actual_category)
            predicted = (
                classes[int(np.argmax(raw_one[0]))]
                if classes and getattr(raw_one, "ndim", 1) > 1
                else (classes[1] if classes and float(raw_one[0]) >= 0.5 and len(classes) > 1 else classes[0] if classes else "")
            )
            error = 1.0 - probability
            score = _calibrated_score(error, head) * _rank_weight(head)
            output.append(_prediction(actual, predicted, error, score, value_type, "categorical_classifier", probability=probability, raw_score=error, rank_weight=_rank_weight(head)))
        return output

    def _load_model(self, head: dict[str, Any]) -> Any:
        path = str(head.get("path") or "")
        if path in self._models:
            return self._models[path]
        try:
            import lightgbm as lgb
        except Exception as exc:  # pragma: no cover
            raise SystemExit("LightGBM is required for normal structure inference") from exc
        model = lgb.Booster(model_file=str(self.model_dir / path))
        self._models[path] = model
        return model

    @staticmethod
    def _model_predict(model: Any, x: Any) -> Any:
        try:
            return model.predict(x, num_threads=1)
        except TypeError:
            return model.predict(x)

    def _load_constant(self, head: dict[str, Any]) -> dict[str, Any]:
        path = str(head.get("path") or "")
        if path in self._constants:
            return self._constants[path]
        payload = _read_json(self.model_dir / path)
        self._constants[path] = payload
        return payload


def _prediction(
    actual: Any,
    predicted: Any,
    residual: float,
    score: float,
    value_type: str,
    method: str,
    *,
    probability: float | None = None,
    raw_score: float | None = None,
    rank_weight: float | None = None,
) -> dict[str, Any]:
    output = {
        "actual": actual,
        "predicted": predicted,
        "residual": float(residual),
        "score": max(0.0, min(1.0, float(score))),
        "value_type": value_type,
        "method": method,
    }
    if raw_score is not None:
        output["raw_score"] = max(0.0, float(raw_score))
    if rank_weight is not None:
        output["rank_weight"] = max(0.0, float(rank_weight))
    if probability is not None:
        output["probability"] = max(0.0, min(1.0, float(probability)))
    return output


def _rank_weight(head: dict[str, Any]) -> float:
    return max(0.0, min(1.0, float(head.get("rank_weight", 1.0))))


def _calibrated_score(error: float, head: dict[str, Any]) -> float:
    calibration = head.get("calibration") if isinstance(head.get("calibration"), dict) else {}
    p95 = max(0.0, float(calibration.get("p95", head.get("residual_scale", 0.0)) or 0.0))
    p99 = max(p95, float(calibration.get("p99", p95) or p95))
    value = max(0.0, float(error or 0.0))
    if value <= p95:
        return 0.0
    span = max(1e-6, p99 - p95, p95 * 3.0, 1.0)
    return max(0.0, min(1.0, (value - p95) / span))


def _class_probability(raw: Any, classes: list[str], actual: str) -> float:
    if not classes:
        return 0.0
    arr = np.asarray(raw)
    if arr.ndim == 1:
        prob = float(arr[0]) if len(arr) else 0.0
        if len(classes) == 1:
            return 1.0 if actual == classes[0] else 0.0
        return prob if actual == classes[1] else 1.0 - prob if actual == classes[0] else 0.0
    idx = classes.index(actual) if actual in classes else -1
    if idx < 0 or idx >= arr.shape[1]:
        return 0.0
    return float(arr[0, idx])


def _knowledge_payload(row: dict[str, Any]) -> dict[str, Any]:
    payload = row.get("knowledge_payload") if isinstance(row.get("knowledge_payload"), dict) else row
    return payload if isinstance(payload, dict) else {}


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
