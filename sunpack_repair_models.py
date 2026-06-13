from __future__ import annotations

import os
from typing import Any

from sunpack.model_runtime import get_model_asset_registry


class DiagnosisHGTProvider:
    provider_id = "diagnosis_hgt"

    def __init__(self, format_name: str, model_dir: str = ""):
        self.format_name = str(format_name or "").lower()
        self.supported_formats = [self.format_name]
        asset = get_model_asset_registry().asset(self.format_name, "diagnosis")
        self.model_dir = model_dir or (str(asset.model_dir) if asset is not None else "")
        self._model = None

    def available(self) -> bool:
        return bool(self.model_dir)

    def diagnose_state(self, request):
        if self._model is None:
            from repair_training.core.diagnosis_gnn.inference import DiagnosisGNNModel

            self._model = DiagnosisGNNModel(model_dir=self.model_dir, device=os.environ.get("SUNPACK_MODEL_DEVICE", "auto"))
        from repair_training.core.diagnosis_graph.dispatcher import build_diagnosis_graph_sample

        sample = build_diagnosis_graph_sample({
            "format": request.format,
            "sample_id": f"{getattr(request.job, 'archive_key', '')}:{request.round_index}",
            "knowledge_payload": dict(request.knowledge_payload or {}),
        })
        return self._model.predict_sample(sample)


class RepairPolicyTransformerProvider:
    provider_id = "repair_policy_transformer"

    def __init__(self, format_name: str, model_dir: str = ""):
        self.format_name = str(format_name or "").lower()
        self.supported_formats = [self.format_name]
        asset = get_model_asset_registry().asset(self.format_name, "policy")
        self.model_dir = model_dir or (str(asset.model_dir) if asset is not None else "")
        self._model = None

    def available(self) -> bool:
        return bool(self.model_dir)

    def score_actions(self, request):
        if self._model is None:
            from repair_training.core.repair_policy_transformer.inference import RepairPolicyTransformerModel

            self._model = RepairPolicyTransformerModel(model_dir=self.model_dir, device=os.environ.get("SUNPACK_MODEL_DEVICE", "auto"))
        from repair_training.core.repair_policy_transformer.schema import PolicyAction, PolicyGraphTrainingSample

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


def get_diagnosis_hgt_models() -> list[Any]:
    registry = get_model_asset_registry()
    return [
        DiagnosisHGTProvider(format_name)
        for format_name in registry.supported_formats()
        if registry.asset(format_name, "diagnosis") is not None
    ]


def get_policy_graph_scorers() -> list[Any]:
    registry = get_model_asset_registry()
    return [
        RepairPolicyTransformerProvider(format_name)
        for format_name in registry.supported_formats()
        if registry.asset(format_name, "policy") is not None
    ]
