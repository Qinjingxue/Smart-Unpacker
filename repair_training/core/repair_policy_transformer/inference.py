from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from repair_training.core.repair_policy_transformer import POLICY_TRANSFORMER_SEMANTICS
from repair_training.core.repair_policy_transformer.model import build_repair_policy_transformer
from repair_training.core.repair_policy_transformer.schema import PolicyGraphTrainingSample
from repair_training.core.repair_policy_transformer.tensorize import tensorize_sample


class RepairPolicyTransformerModel:
    def __init__(self, *, model_dir: str | Path, device: str = "auto"):
        try:
            import torch
        except Exception as exc:  # pragma: no cover
            raise SystemExit("RepairPolicyTransformer inference requires torch.") from exc
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
            scores = self.torch.sigmoid(self.model(
                item["node_x"].to(self.device),
                item["memory_x"].to(self.device),
                item["action_x"].to(self.device),
            )).detach().cpu().tolist()
        actions = []
        for action, score in zip(item["actions"], scores):
            actions.append({
                "action_type": action.get("action_type"),
                "action_id": action.get("action_id"),
                "module_name": action.get("module_name", ""),
                "score": float(score),
            })
        actions.sort(key=lambda row: row["score"], reverse=True)
        return {"action_scores": actions, "diagnostics": {"model_type": "repair_policy_transformer", "policy_semantics": POLICY_TRANSFORMER_SEMANTICS}}


def _resolve_device(device: str, torch_module) -> str:
    requested = str(device or "auto").lower()
    if requested == "auto":
        return "cuda" if torch_module.cuda.is_available() else "cpu"
    if requested == "cuda" and not torch_module.cuda.is_available():
        raise SystemExit("RepairPolicyTransformer requested --device cuda but CUDA is not available")
    return requested


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}

