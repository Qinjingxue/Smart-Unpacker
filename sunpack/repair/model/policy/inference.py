from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sunpack.repair.model.policy import POLICY_TRANSFORMER_SEMANTICS
from sunpack.repair.model.policy.model import build_repair_policy_transformer
from sunpack.repair.model.policy.schema import PolicyGraphTrainingSample, PolicyWorldTrainingSample
from sunpack.repair.model.policy.tensorize import WORLD_BASE_TARGET_DIM, ROOT_CASES, tensorize_sample, tensorize_world_sample


class RepairPolicyTransformerModel:
    def __init__(self, *, model_dir: str | Path, device: str = "auto"):
        try:
            import torch
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                f"RepairPolicyTransformer inference requires torch. Install the project runtime dependencies. Import error: {exc}"
            ) from exc
        self.torch = torch
        self.model_dir = Path(model_dir)
        self.model_card = _read_json(self.model_dir / "model_card.json")
        if self.model_card.get("policy_semantics") != POLICY_TRANSFORMER_SEMANTICS:
            raise RuntimeError(f"unsupported repair policy semantics: {self.model_card.get('policy_semantics')!r}")
        checkpoint = torch.load(self.model_dir / "model.pt", map_location="cpu")
        self.config = dict(checkpoint.get("config") or {})
        self.device = _resolve_device(device, torch)
        self.model = build_repair_policy_transformer(self.config).to(self.device)
        self.model.load_state_dict(checkpoint["state_dict"])
        self.model.eval()

    def predict_sample(self, sample: PolicyGraphTrainingSample) -> dict[str, Any]:
        item = tensorize_sample(sample)
        with self.torch.no_grad():
            outputs = self.model.forward_all(
                item["node_x"].to(self.device),
                item["memory_x"].to(self.device),
                item["action_x"].to(self.device),
                item["edge_x"].to(self.device),
            )
            logits = outputs["action_logits"]
            scores = self.torch.softmax(logits, dim=0).detach().cpu().tolist()
            transition = self.torch.sigmoid(outputs["transition"]).detach().cpu().tolist()
            uncertainty = self.torch.sigmoid(outputs["uncertainty"]).detach().cpu().tolist()
        actions = []
        predictions: dict[str, Any] = {}
        for index, (action, score) in enumerate(zip(item["actions"], scores)):
            prediction = _decode_predicted_next_state(transition[index] if transition and isinstance(transition[0], list) else transition)
            predicted_uncertainty = _decode_predicted_uncertainty(uncertainty[index] if uncertainty and isinstance(uncertainty[0], list) else uncertainty)
            action_id = str(action.get("action_id") or action.get("candidate_id") or action.get("action_type") or "")
            actions.append({
                "action_type": action.get("action_type"),
                "action_id": action_id,
                "module_name": action.get("module_name", ""),
                "score": float(score),
                "metadata": {"predicted_next_state": prediction, "predicted_uncertainty": predicted_uncertainty},
            })
            if action_id:
                predictions[action_id] = prediction
        actions.sort(key=lambda row: row["score"], reverse=True)
        return {
            "action_scores": actions,
            "action_predictions": predictions,
            "diagnostics": {"model_type": "repair_policy_transformer", "policy_semantics": POLICY_TRANSFORMER_SEMANTICS},
        }

    def predict_world_sample(self, sample: PolicyWorldTrainingSample) -> dict[str, Any]:
        item = tensorize_world_sample(sample)
        with self.torch.no_grad():
            outputs = self.model.forward_all(
                item["node_x"].to(self.device),
                item["memory_x"].to(self.device),
                item["action_x"].to(self.device),
                item["edge_x"].to(self.device),
            )
            scores = self.torch.softmax(outputs["action_logits"], dim=0).detach().cpu().tolist()
            transition_raw = self.torch.sigmoid(outputs["transition"]).detach().cpu().tolist()
            uncertainty_raw = self.torch.sigmoid(outputs["uncertainty"]).detach().cpu().tolist()
            chosen_index = int(item.get("chosen_action_index", -1))
            if transition_raw and isinstance(transition_raw[0], list):
                transition = transition_raw[chosen_index if 0 <= chosen_index < len(transition_raw) else 0]
            else:
                transition = transition_raw
            if uncertainty_raw and isinstance(uncertainty_raw[0], list):
                uncertainty = uncertainty_raw[chosen_index if 0 <= chosen_index < len(uncertainty_raw) else 0]
            else:
                uncertainty = uncertainty_raw
            masked = self.torch.sigmoid(outputs["masked"]).detach().cpu().tolist()
        actions = []
        for action, score in zip(item["actions"], scores):
            actions.append({
                "action_type": action.get("action_type"),
                "action_id": action.get("action_id"),
                "module_name": action.get("module_name", ""),
                "score": float(score),
                "action_q_value": action.get("action_q_value", 0.0),
                "best_action_set_member": action.get("best_action_set_member", False),
            })
        actions.sort(key=lambda row: row["score"], reverse=True)
        return {
            "sample_id": sample.sample_id,
            "task": sample.task,
            "action_scores": actions,
            "transition_prediction": transition,
            "predicted_next_state": _decode_predicted_next_state(transition),
            "predicted_uncertainty": _decode_predicted_uncertainty(uncertainty),
            "masked_prediction": masked,
            "diagnostics": {"model_type": "repair_policy_transformer", "policy_semantics": POLICY_TRANSFORMER_SEMANTICS},
        }


def _decode_predicted_next_state(values: list[float]) -> dict[str, Any]:
    padded = [float(value or 0.0) for value in list(values or [])]
    if len(padded) < WORLD_BASE_TARGET_DIM + len(ROOT_CASES):
        padded.extend([0.0] * (WORLD_BASE_TARGET_DIM + len(ROOT_CASES) - len(padded)))
    root_offset = WORLD_BASE_TARGET_DIM
    recovery_offset = WORLD_BASE_TARGET_DIM + len(ROOT_CASES)
    root_scores = {
        root_case: _clamp01(padded[root_offset + index])
        for index, root_case in enumerate(ROOT_CASES)
        if root_offset + index < len(padded)
    }
    recovery = {
        "score": _at(padded, recovery_offset),
        "completeness": _at(padded, recovery_offset + 1),
        "recovered_bytes_scaled": _at(padded, recovery_offset + 2),
        "complete_files_scaled": _at(padded, recovery_offset + 3),
        "failed_files_scaled": _at(padded, recovery_offset + 4),
        "missing_files_scaled": _at(padded, recovery_offset + 5),
        "partial_files_scaled": _at(padded, recovery_offset + 6),
    }
    return {
        "predicted_recovery": recovery,
        "predicted_recovery_delta": _at(padded, 1),
        "predicted_patch_status_hash": _at(padded, 2),
        "predicted_best_updated": _at(padded, 3) >= 0.5,
        "predicted_branch_stale_delta": _at(padded, 4),
        "predicted_diagnosis_root_scores": root_scores,
        "predicted_verification_summary": {
            "completeness": recovery["completeness"],
            "complete_files_scaled": recovery["complete_files_scaled"],
            "failed_files_scaled": recovery["failed_files_scaled"],
            "missing_files_scaled": recovery["missing_files_scaled"],
            "partial_files_scaled": recovery["partial_files_scaled"],
        },
        "prediction_vector": [float(value) for value in padded],
    }


def _decode_predicted_uncertainty(values: list[float]) -> dict[str, float]:
    padded = [float(value or 0.0) for value in list(values or [])]
    value = _at(padded, 0)
    return {
        "predicted_uncertainty": value,
        "overall_uncertainty": value,
    }


def _at(values: list[float], index: int) -> float:
    if index < 0 or index >= len(values):
        return 0.0
    return _clamp01(values[index])


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _resolve_device(device: str, torch_module) -> str:
    requested = str(device or "auto").lower()
    if requested == "auto":
        return "cuda" if torch_module.cuda.is_available() else "cpu"
    if requested == "cuda" and not torch_module.cuda.is_available():
        raise SystemExit("RepairPolicyTransformer requested --device cuda but CUDA is not available")
    return requested


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
