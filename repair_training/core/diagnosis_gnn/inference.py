from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from repair_training.core.diagnosis_graph.schema import DIAGNOSIS_GRAPH_SCHEMA_VERSION, DiagnosisGraphSample
from repair_training.core.diagnosis_gnn import DIAGNOSIS_GNN_SEMANTICS
from repair_training.core.diagnosis_gnn.model import build_diagnosis_gnn_model
from repair_training.core.diagnosis_gnn.root_cases import ROOT_CASES
from repair_training.core.diagnosis_gnn.tensorize import THEORY_DEPENDS_EDGE_TYPE, metadata_for_sample, tensorize_sample


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
        self.edge_types = {tuple(item) for item in self.metadata[1]}
        self.config = dict(checkpoint.get("config") or {})
        self.config = _normalize_checkpoint_config(self.config, checkpoint.get("state_dict") or {})
        self.device = _resolve_device(device, torch)
        self.model = build_diagnosis_gnn_model(metadata=self.metadata, config=self.config).to(self.device)
        self.model.load_state_dict(checkpoint["state_dict"])
        self.model.eval()

    def predict_sample(self, sample: DiagnosisGraphSample) -> dict[str, Any]:
        return self.predict_samples([sample])[0]

    def predict_samples(self, samples: list[DiagnosisGraphSample]) -> list[dict[str, Any]]:
        if not samples:
            return []
        from torch_geometric.loader import DataLoader

        data_items = []
        for index, sample in enumerate(samples):
            data = tensorize_sample(sample)
            data.sample_index = self.torch.tensor([index], dtype=self.torch.long)
            data_items.append(data)
        metadatas = [metadata_for_sample(sample) for sample in samples]
        outputs: list[dict[str, Any] | None] = [None] * len(samples)
        loader = DataLoader(data_items, batch_size=16)
        with self.torch.no_grad():
            for batch in loader:
                indices = [int(item) for item in batch.sample_index.detach().cpu().view(-1).tolist()]
                batch = batch.to(self.device)
                runtime_edge_types = {tuple(edge_type) for edge_type in batch.edge_index_dict}
                unknown_edge_types = sorted(runtime_edge_types - self.edge_types)
                if unknown_edge_types:
                    raise RuntimeError(
                        "DiagnosisGNN runtime graph has edge types that were not present in training metadata: "
                        f"{unknown_edge_types}. Rebuild diagnosis graph rows and retrain the model."
                    )
                out = self.model(batch.x_dict, batch.edge_index_dict, _batch_dict(batch))
                root_scores_all = self.torch.sigmoid(out["root_case"]).detach().cpu()
                edge_scores_all = self.torch.sigmoid(out.get("theory_edge", self.torch.empty(0, device=self.device))).detach().cpu()
                edge_batch = _edge_batch_for_theory_depends(batch)
                for local_index, sample_index in enumerate(indices):
                    metadata = metadatas[sample_index]
                    sample = samples[sample_index]
                    root_scores = root_scores_all[local_index].tolist()
                    edge_scores_raw = edge_scores_all[edge_batch == local_index].tolist() if edge_batch is not None else []
                    outputs[sample_index] = self._format_prediction(sample, metadata, root_scores, edge_scores_raw)
        return [item for item in outputs if item is not None]

    def _format_prediction(self, sample: DiagnosisGraphSample, metadata, scores: list[float], edge_scores_raw: list[float]) -> dict[str, Any]:
        root_scores = {label: float(score) for label, score in zip(ROOT_CASES, scores)}
        ranked = [
            {"root_case": label, "score": float(score)}
            for label, score in sorted(root_scores.items(), key=lambda item: item[1], reverse=True)
        ]
        threshold = float((self.thresholds.get("root_case") or {}).get("threshold", self.thresholds.get("root_case_threshold", 0.5)))
        return {
            "root_case": {
                "scores": dict(sorted(root_scores.items())),
                "ranked": ranked,
                "selected": [item["root_case"] for item in ranked if float(item["score"]) >= threshold],
            },
            "diagnostics": {
                "model_type": "diagnosis_gnn",
                "graph_schema": DIAGNOSIS_GRAPH_SCHEMA_VERSION,
                "thresholds": dict(self.thresholds),
                "root_case_score_summary": _root_case_score_summary(ranked, threshold),
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


def _root_case_score_summary(ranked: list[dict[str, Any]], threshold: float) -> dict[str, Any]:
    if not ranked:
        return {"top_score": 0.0, "top_margin": 0.0, "threshold_excess": 0.0}
    top_score = _clamp01(float(ranked[0].get("score") or 0.0))
    second_score = _clamp01(float(ranked[1].get("score") or 0.0)) if len(ranked) > 1 else 0.0
    top_margin = _clamp01(top_score - second_score)
    threshold = _clamp01(float(threshold or 0.0))
    threshold_excess = 0.0
    if threshold < 1.0:
        threshold_excess = _clamp01((top_score - threshold) / max(1.0 - threshold, 1e-6))
    return {
        "top_score": top_score,
        "second_score": second_score,
        "top_margin": top_margin,
        "threshold": threshold,
        "threshold_excess": threshold_excess,
    }


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _edge_batch_for_theory_depends(batch):
    try:
        edge_index = batch[THEORY_DEPENDS_EDGE_TYPE].edge_index
        theory_batch = batch["theory"].batch.detach().cpu()
    except Exception:
        return None
    if edge_index.numel() == 0:
        return None
    return theory_batch[edge_index[0].detach().cpu()]


def _batch_dict(batch) -> dict[str, Any]:
    output = {}
    for node_type in batch.x_dict:
        try:
            output[node_type] = batch[node_type].batch
        except Exception:
            pass
    return output


def _normalize_checkpoint_config(config: dict[str, Any], state_dict: dict[str, Any]) -> dict[str, Any]:
    output = dict(config)
    arch = str(output.get("arch") or output.get("algorithm") or "").lower().replace("-", "_")
    if arch == "hgt":
        has_layernorm_weights = any(str(key).startswith("norms.") for key in state_dict)
        if "layernorm" not in output:
            output["layernorm"] = has_layernorm_weights
        if "residual" not in output:
            output["residual"] = has_layernorm_weights
    return output


def _resolve_device(device: str, torch_module) -> str:
    requested = str(device or "auto").lower()
    if requested == "auto":
        return "cuda" if torch_module.cuda.is_available() else "cpu"
    if requested == "cuda" and not torch_module.cuda.is_available():
        raise SystemExit("DiagnosisGNN requested --device cuda but CUDA is not available")
    return requested


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
