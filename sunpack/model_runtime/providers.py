from __future__ import annotations

import os
from typing import Any

from sunpack.model_runtime.diagnosis.graph_dispatcher import build_diagnosis_graph_sample
from sunpack.model_runtime.diagnosis.inference import DiagnosisGNNModel
from sunpack.model_runtime.policy.inference import RepairPolicyTransformerModel
from sunpack.model_runtime.policy.schema import PolicyAction, PolicyGraphTrainingSample
from sunpack.model_runtime.registry import ModelAsset, get_model_asset_registry


class DiagnosisHGTProvider:
    provider_id = "diagnosis_hgt"

    def __init__(self, asset: ModelAsset):
        self.asset = asset
        self.supported_formats = [asset.format]
        self._model: DiagnosisGNNModel | None = None

    def available(self) -> bool:
        return self.asset.available

    def diagnose_state(self, request: Any) -> dict[str, Any]:
        if self._model is None:
            self._model = DiagnosisGNNModel(
                model_dir=self.asset.model_dir,
                device=os.environ.get("SUNPACK_MODEL_DEVICE", "auto"),
            )
        sample = build_diagnosis_graph_sample(
            {
                "format": request.format,
                "sample_id": f"{getattr(request.job, 'archive_key', '')}:{request.round_index}",
                "knowledge_payload": dict(request.knowledge_payload or {}),
            }
        )
        return self._model.predict_sample(sample)


class RepairPolicyTransformerProvider:
    provider_id = "repair_policy_transformer"

    def __init__(self, asset: ModelAsset):
        self.asset = asset
        self.supported_formats = [asset.format]
        self._model: RepairPolicyTransformerModel | None = None

    def available(self) -> bool:
        return self.asset.available

    def score_actions(self, request: Any) -> dict[str, Any]:
        if self._model is None:
            self._model = RepairPolicyTransformerModel(
                model_dir=self.asset.model_dir,
                device=os.environ.get("SUNPACK_MODEL_DEVICE", "auto"),
            )
        actions = [
            PolicyAction(
                action_type=str(action.get("action_type") or "module"),  # type: ignore[arg-type]
                action_id=str(action.get("action_id") or action.get("candidate_id") or action.get("action_type") or ""),
                module_name=str(action.get("module_name") or action.get("module") or ""),
                features=dict(action),
            )
            for action in request.available_actions
            if str(action.get("action_type") or "") in {"stop", "undo", "module"}
        ]
        sample = PolicyGraphTrainingSample(
            sample_id=f"{getattr(request.job, 'archive_key', '')}:{request.round_index}",
            format=request.format,
            graph=dict(request.graph or {}),
            current_node_id=request.current_node_id,
            best_node_id=request.best_node_id,
            actions=actions,
            diagnosis_hgt=dict(request.diagnosis_hgt or {}),
            current_recovery=dict(request.current_recovery or {}),
            best_recovery=dict(request.best_seen_recovery or {}),
        )
        return self._model.predict_sample(sample)


def create_model_providers() -> list[Any]:
    registry = get_model_asset_registry()
    providers: list[Any] = []
    for format_name in registry.supported_formats():
        diagnosis = registry.asset(format_name, "diagnosis")
        if diagnosis is not None:
            providers.append(DiagnosisHGTProvider(diagnosis))
        policy = registry.asset(format_name, "policy")
        if policy is not None:
            providers.append(RepairPolicyTransformerProvider(policy))
    return providers
