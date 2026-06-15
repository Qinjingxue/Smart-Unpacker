from __future__ import annotations

import os
from typing import Any

from sunpack.contracts.archive_state import ArchiveState
from sunpack.repair.job import RepairJob
from sunpack.repair.model.assets import ModelAssetRegistry, get_model_asset_registry
from sunpack.repair.model.diagnosis.graph_dispatcher import build_diagnosis_graph_sample
from sunpack.repair.model.diagnosis.inference import DiagnosisGNNModel
from sunpack.repair.model.policy.inference import RepairPolicyTransformerModel
from sunpack.repair.model.policy.schema import PolicyAction, PolicyGraphTrainingSample
from sunpack.repair.search.types import PolicyExplorationGraph, PolicyGraphAction


class RepairModelRuntime:
    """Owns the paired diagnosis and repair-policy models used by repair."""

    def __init__(self, config: dict[str, Any] | None = None, *, assets: ModelAssetRegistry | None = None):
        self.config = config or {}
        policy_config = self.config.get("policy") if isinstance(self.config.get("policy"), dict) else {}
        self.enabled = bool(policy_config.get("enabled", True))
        self.strict_errors = bool(policy_config.get("strict_model_errors", False))
        self.assets = assets or get_model_asset_registry()
        self._diagnosis_models: dict[str, Any] = {}
        self._policy_models: dict[str, Any] = {}
        self.last_load_error = ""

    def active_for_job(self, job: RepairJob) -> bool:
        return self.status_for_job(job).get("decision_status") == "available"

    def status_for_job(self, job: RepairJob) -> dict[str, Any]:
        base = {"enabled": self.enabled}
        if not self.enabled:
            return {**base, "decision_status": "disabled", "fallback_reason": "policy_disabled"}
        fmt = _normalize_format(job.format)
        if not fmt or fmt not in self.assets.supported_formats():
            return {**base, "decision_status": "unavailable", "fallback_reason": "unsupported_format"}
        diagnosis = self.assets.asset(fmt, "diagnosis")
        if diagnosis is None or not diagnosis.available:
            return {**base, "decision_status": "unavailable", "fallback_reason": "diagnosis_hgt_unavailable"}
        policy = self.assets.asset(fmt, "policy")
        if policy is None or not policy.available:
            return {**base, "decision_status": "unavailable", "fallback_reason": "policy_transformer_unavailable"}
        return {**base, "decision_status": "available"}

    def diagnose_state(
        self,
        *,
        job: RepairJob,
        archive_state: ArchiveState | None,
        graph: PolicyExplorationGraph,
        recovery: dict[str, Any] | None = None,
        round_index: int = 0,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        del archive_state, graph, recovery
        fmt = _normalize_format(job.format)
        try:
            model = self._diagnosis_model(fmt)
            sample = build_diagnosis_graph_sample(
                {
                    "format": fmt,
                    "sample_id": f"{job.archive_key}:{round_index}",
                    "knowledge_payload": dict(job.knowledge or {}),
                }
            )
            result = _normalize_diagnosis(model.predict_sample(sample), fmt=fmt)
            return result, {"enabled": self.enabled, "decision_status": "diagnosed", "model_id": "diagnosis_hgt"}
        except Exception as exc:
            if self.strict_errors:
                raise
            self.last_load_error = str(exc)
            return {}, {
                "enabled": self.enabled,
                "decision_status": "unavailable",
                "fallback_reason": "diagnosis_hgt_unavailable",
                "model_errors": [str(exc)],
                "load_error": self.last_load_error,
            }

    def score_graph_actions(
        self,
        *,
        job: RepairJob,
        archive_state: ArchiveState | None,
        graph: PolicyExplorationGraph,
        available_actions: list[dict[str, Any]],
        diagnosis_hgt: dict[str, Any],
        current_recovery: dict[str, Any] | None = None,
        best_seen_recovery: dict[str, Any] | None = None,
        round_index: int = 0,
    ) -> tuple[list[PolicyGraphAction], dict[str, Any]]:
        del archive_state
        fmt = _normalize_format(job.format)
        try:
            model = self._policy_model(fmt)
            actions = [
                PolicyAction(
                    action_type=str(action.get("action_type") or "module"),  # type: ignore[arg-type]
                    action_id=str(action.get("action_id") or action.get("candidate_id") or action.get("action_type") or ""),
                    module_name=str(action.get("module_name") or action.get("module") or ""),
                    features=dict(action),
                )
                for action in available_actions
                if str(action.get("action_type") or "") in {"stop", "undo", "module"}
            ]
            sample = PolicyGraphTrainingSample(
                sample_id=f"{job.archive_key}:{round_index}",
                format=fmt,
                graph=graph.to_dict(),
                current_node_id=graph.current_node_id,
                best_node_id=graph.best_node_id,
                actions=actions,
                diagnosis_hgt=dict(diagnosis_hgt or {}),
                current_recovery=dict(current_recovery or {}),
                best_recovery=dict(best_seen_recovery or {}),
            )
            raw = model.predict_sample(sample)
            if not _has_action_predictions(raw):
                raise RuntimeError("policy_prediction_unavailable")
            scores = _valid_actions(_normalize_actions(raw), available_actions)
            if not scores:
                raise RuntimeError("policy_action_scores_invalid")
            return scores, {
                "enabled": self.enabled,
                "decision_status": "scored",
                "model_id": "repair_policy_transformer",
                "action_scores": [score.to_dict() for score in scores],
            }
        except Exception as exc:
            if self.strict_errors:
                raise
            self.last_load_error = str(exc)
            return [], {
                "enabled": self.enabled,
                "decision_status": "unavailable",
                "fallback_reason": "policy_graph_scorer_unavailable_or_invalid",
                "model_errors": [str(exc)],
                "load_error": self.last_load_error,
            }

    def _diagnosis_model(self, fmt: str) -> Any:
        if fmt not in self._diagnosis_models:
            asset = self.assets.asset(fmt, "diagnosis")
            if asset is None or not asset.available:
                raise RuntimeError("diagnosis model asset is unavailable")
            self._diagnosis_models[fmt] = DiagnosisGNNModel(
                model_dir=asset.model_dir,
                device=os.environ.get("SUNPACK_MODEL_DEVICE", "auto"),
            )
        return self._diagnosis_models[fmt]

    def _policy_model(self, fmt: str) -> Any:
        if fmt not in self._policy_models:
            asset = self.assets.asset(fmt, "policy")
            if asset is None or not asset.available:
                raise RuntimeError("policy model asset is unavailable")
            self._policy_models[fmt] = RepairPolicyTransformerModel(
                model_dir=asset.model_dir,
                device=os.environ.get("SUNPACK_MODEL_DEVICE", "auto"),
            )
        return self._policy_models[fmt]


def _normalize_diagnosis(value: Any, *, fmt: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError("diagnosis model returned an invalid payload")
    root = value.get("root_case") if isinstance(value.get("root_case"), dict) else {}
    scores = root.get("scores") if isinstance(root.get("scores"), dict) else {}
    ranked = root.get("ranked") if isinstance(root.get("ranked"), list) else []
    selected = root.get("selected") if isinstance(root.get("selected"), list) else []
    return {
        "format": str(value.get("format") or fmt),
        "root_case": {
            "scores": {str(key): float(score or 0.0) for key, score in scores.items()},
            "ranked": [dict(item) for item in ranked if isinstance(item, dict)],
            "selected": [str(item) for item in selected if str(item)],
        },
        "diagnostics": {**dict(value.get("diagnostics") or {}), "model_id": "diagnosis_hgt"},
    }


def _normalize_actions(value: Any) -> list[PolicyGraphAction]:
    raw = value.get("action_scores") if isinstance(value, dict) else None
    if not isinstance(raw, list):
        return []
    predictions = value.get("action_predictions") if isinstance(value.get("action_predictions"), dict) else {}
    output: list[PolicyGraphAction] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        action_type = str(item.get("action_type") or item.get("action") or "")
        if action_type not in {"module", "undo", "stop"}:
            continue
        action_id = str(item.get("action_id") or item.get("candidate_id") or "")
        module_name = str(item.get("module_name") or item.get("module") or "")
        metadata = dict(item.get("metadata") or {})
        prediction = metadata.get("predicted_next_state")
        if prediction is None:
            prediction = predictions.get(action_id) or predictions.get(module_name)
        if isinstance(prediction, dict):
            metadata["predicted_next_state"] = prediction
        metadata["model_id"] = "repair_policy_transformer"
        output.append(
            PolicyGraphAction(
                action_type=action_type,  # type: ignore[arg-type]
                module_name=module_name,
                action_id=action_id,
                score=float(item.get("score", item.get("logic_score", 0.0)) or 0.0),
                confidence=_optional_float(item.get("confidence")),
                reason=str(item.get("reason") or ""),
                metadata=metadata,
            )
        )
    return output


def _has_action_predictions(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    if isinstance(value.get("action_predictions"), dict) and value["action_predictions"]:
        return True
    return any(
        isinstance(item, dict)
        and isinstance(item.get("metadata"), dict)
        and isinstance(item["metadata"].get("predicted_next_state"), dict)
        for item in value.get("action_scores") or []
    )


def _valid_actions(scores: list[PolicyGraphAction], available_actions: list[dict[str, Any]]) -> list[PolicyGraphAction]:
    module_ids = {
        str(item.get("action_id") or item.get("candidate_id") or "")
        for item in available_actions
        if item.get("action_type") == "module"
    }
    module_names = {
        str(item.get("module_name") or item.get("module") or "")
        for item in available_actions
        if item.get("action_type") == "module"
    }
    return [
        score
        for score in scores
        if score.action_type != "module" or score.action_id in module_ids or score.module_name in module_names
    ]


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalize_format(value: Any) -> str:
    text = str(value or "").lower().lstrip(".")
    return {"gz": "gzip", "bz2": "bzip2", "seven_zip": "7z"}.get(text, text)
