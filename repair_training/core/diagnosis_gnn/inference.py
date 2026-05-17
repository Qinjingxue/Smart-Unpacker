from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from repair_training.core.diagnosis_graph.schema import DIAGNOSIS_GRAPH_SCHEMA_VERSION, DiagnosisGraphSample
from repair_training.core.diagnosis_gnn import DIAGNOSIS_GNN_SEMANTICS
from repair_training.core.diagnosis_gnn.model import build_diagnosis_gnn_model
from repair_training.core.diagnosis_gnn.tensorize import metadata_for_sample, tensorize_sample


class DiagnosisGNNModel:
    def __init__(self, *, model_dir: str | Path, device: str = "auto"):
        try:
            import torch
        except Exception as exc:  # pragma: no cover
            raise SystemExit(
                "DiagnosisGNN inference requires torch and torch-geometric. "
                "Install repair_training/requirements-training.txt."
            ) from exc
        self.torch = torch
        self.model_dir = Path(model_dir)
        self.model_card = _read_json(self.model_dir / "model_card.json")
        self.thresholds = _read_json(self.model_dir / "thresholds.json")
        if self.model_card.get("diagnosis_semantics") != DIAGNOSIS_GNN_SEMANTICS:
            raise RuntimeError(f"unsupported DiagnosisGNN semantics: {self.model_card.get('diagnosis_semantics')!r}")
        if self.model_card.get("graph_schema") != DIAGNOSIS_GRAPH_SCHEMA_VERSION:
            raise RuntimeError(f"unsupported DiagnosisGNN graph schema: {self.model_card.get('graph_schema')!r}")
        checkpoint = torch.load(self.model_dir / "model.pt", map_location="cpu")
        self.metadata = (list(checkpoint.get("metadata", ([], []))[0]), [tuple(item) for item in checkpoint.get("metadata", ([], []))[1]])
        self.config = dict(checkpoint.get("config") or {})
        self.device = _resolve_device(device, torch)
        self.model = build_diagnosis_gnn_model(metadata=self.metadata, config=self.config).to(self.device)
        self.model.load_state_dict(checkpoint["state_dict"])
        self.model.eval()

    def predict_sample(self, sample: DiagnosisGraphSample) -> dict[str, Any]:
        data = tensorize_sample(sample).to(self.device)
        metadata = metadata_for_sample(sample)
        with self.torch.no_grad():
            out = self.model(data.x_dict, data.edge_index_dict)
            scores = self.torch.sigmoid(out["cause"]).detach().cpu().tolist()
            edge_scores_raw = self.torch.sigmoid(out.get("theory_edge", self.torch.empty(0, device=self.device))).detach().cpu().tolist()
        cause_scores = {
            node_id: float(score)
            for node_id, score in zip(metadata.cause_node_ids, scores)
        }
        field_scores: dict[str, float] = {}
        zone_scores: dict[str, float] = {}
        for label, score in zip(metadata.cause_labels, scores):
            if not label:
                continue
            if label.startswith("field:"):
                field_scores[label] = max(float(score), field_scores.get(label, 0.0))
            if label.startswith("zone:"):
                zone = label.split(":", 1)[1]
                zone_scores[zone] = max(float(score), zone_scores.get(zone, 0.0))
        return {
            "root_cause": {
                "cause_scores": dict(sorted(cause_scores.items())),
                "field_scores": dict(sorted(field_scores.items())),
                "zone_scores": dict(sorted(zone_scores.items())),
                "top_evidence": [],
            },
            "diagnostics": {
                "model_type": "diagnosis_gnn",
                "graph_schema": DIAGNOSIS_GRAPH_SCHEMA_VERSION,
                "thresholds": dict(self.thresholds),
                "node_count": len(sample.graph.nodes),
                "edge_count": len(sample.graph.edges),
                "theory_edge_scores": dict(sorted({
                    edge_id: float(score)
                    for edge_id, score in zip(metadata.theory_edge_ids, edge_scores_raw)
                }.items())),
                "top_theory_edges": [
                    {"edge_id": edge_id, "score": float(score)}
                    for edge_id, score in sorted(
                        zip(metadata.theory_edge_ids, edge_scores_raw),
                        key=lambda item: item[1],
                        reverse=True,
                    )[:10]
                ],
            },
        }

    def predict_samples(self, samples: list[DiagnosisGraphSample]) -> list[dict[str, Any]]:
        return [self.predict_sample(sample) for sample in samples]


def _resolve_device(device: str, torch_module) -> str:
    requested = str(device or "auto").lower()
    if requested == "auto":
        return "cuda" if torch_module.cuda.is_available() else "cpu"
    if requested == "cuda" and not torch_module.cuda.is_available():
        raise SystemExit("DiagnosisGNN requested --device cuda but CUDA is not available")
    return requested


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
