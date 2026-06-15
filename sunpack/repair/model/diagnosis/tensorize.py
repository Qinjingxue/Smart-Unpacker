from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from sunpack.repair.model.diagnosis.graph_schema import DiagnosisGraphSample
from sunpack.repair.model.diagnosis.root_cases import ROOT_CASES, ROOT_CASE_INDEX


NODE_TYPES = ("observation", "theory", "cause")
NODE_FEATURE_DIM = 10
THEORY_DEPENDS_EDGE_TYPE = ("theory", "theory_depends_on", "theory")


@dataclass(frozen=True)
class TensorizedGraphMetadata:
    cause_node_ids: list[str]
    cause_labels: list[str]
    theory_node_ids: list[str]
    theory_edge_ids: list[str]
    root_cases: list[str]


def require_pyg():
    try:
        import torch  # noqa: F401
        from torch_geometric.data import HeteroData  # noqa: F401
    except Exception as exc:  # pragma: no cover - depends on optional training environment
        raise RuntimeError(
            "DiagnosisGNN requires torch and torch-geometric. "
            f"Install the project runtime dependencies. Import error: {exc}"
        ) from exc


def tensorize_sample(sample: DiagnosisGraphSample):
    require_pyg()
    import torch
    from torch_geometric.data import HeteroData

    data = HeteroData()
    nodes_by_type = {node_type: [] for node_type in NODE_TYPES}
    for node in sample.graph.nodes:
        nodes_by_type.setdefault(node.node_layer, []).append(node)
    node_index: dict[str, tuple[str, int]] = {}
    for node_type in NODE_TYPES:
        nodes = sorted(nodes_by_type.get(node_type, []), key=lambda item: item.node_id)
        for index, node in enumerate(nodes):
            node_index[node.node_id] = (node_type, index)
        features = [_node_features(node, layer_index=NODE_TYPES.index(node_type)) for node in nodes]
        if not features:
            features = [[0.0] * NODE_FEATURE_DIM]
        data[node_type].x = torch.tensor(features, dtype=torch.float32)
        if node_type == "cause":
            labels = {item for item in sample.labels.cause_node_ids}
            y = [1.0 if node.node_id in labels else 0.0 for node in nodes]
            if not y:
                y = [0.0]
            data[node_type].y = torch.tensor(y, dtype=torch.float32)
        if node_type == "theory":
            labels = {item for item in sample.labels.theory_node_ids}
            y = [1.0 if node.node_id in labels else 0.0 for node in nodes]
            if not y:
                y = [0.0]
            data[node_type].y_alignment = torch.tensor(y, dtype=torch.float32)
    root_y = [0.0] * len(ROOT_CASES)
    for label in sample.labels.root_case_labels:
        index = ROOT_CASE_INDEX.get(str(label))
        if index is not None:
            root_y[index] = 1.0
    data.root_case_y = torch.tensor(root_y, dtype=torch.float32)
    evidence_y, evidence_mask = _root_target_vector(sample, "root_evidence_targets")
    transition_y, transition_mask = _root_target_vector(sample, "root_transition_gain_targets")
    viability_y, viability_mask = _root_target_vector(sample, "root_probe_viability_targets")
    positive_y, positive_mask = _root_target_vector(sample, "root_positive_probe_targets")
    hard_negative_y, hard_negative_mask = _root_target_vector(sample, "root_hard_negative_targets")
    data.root_evidence_y = torch.tensor(evidence_y, dtype=torch.float32)
    data.root_evidence_mask = torch.tensor(evidence_mask, dtype=torch.float32)
    data.root_transition_gain_y = torch.tensor(transition_y, dtype=torch.float32)
    data.root_transition_gain_mask = torch.tensor(transition_mask, dtype=torch.float32)
    data.root_probe_viability_y = torch.tensor(viability_y, dtype=torch.float32)
    data.root_probe_viability_mask = torch.tensor(viability_mask, dtype=torch.float32)
    data.root_positive_probe_y = torch.tensor(positive_y, dtype=torch.float32)
    data.root_positive_probe_mask = torch.tensor(positive_mask, dtype=torch.float32)
    data.root_hard_negative_y = torch.tensor(hard_negative_y, dtype=torch.float32)
    data.root_hard_negative_mask = torch.tensor(hard_negative_mask, dtype=torch.float32)

    edge_groups: dict[tuple[str, str, str], list[tuple[int, int]]] = {}
    edge_ids_by_type: dict[tuple[str, str, str], list[str]] = {}
    for edge in sample.graph.edges:
        if edge.source not in node_index or edge.target not in node_index:
            continue
        source_type, source_index = node_index[edge.source]
        target_type, target_index = node_index[edge.target]
        edge_key = (source_type, edge.edge_type, target_type)
        edge_groups.setdefault(edge_key, []).append((source_index, target_index))
        edge_ids_by_type.setdefault(edge_key, []).append(edge.edge_id)
    for edge_type, pairs in edge_groups.items():
        source = [item[0] for item in pairs]
        target = [item[1] for item in pairs]
        data[edge_type].edge_index = torch.tensor([source, target], dtype=torch.long)
        if edge_type == THEORY_DEPENDS_EDGE_TYPE:
            labels = set(sample.labels.theory_edge_ids)
            y = [1.0 if edge_id in labels else 0.0 for edge_id in edge_ids_by_type.get(edge_type, [])]
            data[edge_type].edge_label = torch.tensor(y, dtype=torch.float32)
    return data


def metadata_for_sample(sample: DiagnosisGraphSample) -> TensorizedGraphMetadata:
    cause_nodes = sorted((node for node in sample.graph.nodes if node.node_layer == "cause"), key=lambda item: item.node_id)
    theory_nodes = sorted((node for node in sample.graph.nodes if node.node_layer == "theory"), key=lambda item: item.node_id)
    theory_edges = sorted(
        (
            edge for edge in sample.graph.edges
            if edge.edge_type == "theory_depends_on"
            and any(node.node_id == edge.source and node.node_layer == "theory" for node in sample.graph.nodes)
            and any(node.node_id == edge.target and node.node_layer == "theory" for node in sample.graph.nodes)
        ),
        key=lambda item: (item.edge_type, item.source, item.target, item.edge_id),
    )
    return TensorizedGraphMetadata(
        cause_node_ids=[node.node_id for node in cause_nodes],
        cause_labels=[node.label for node in cause_nodes],
        theory_node_ids=[node.node_id for node in theory_nodes],
        theory_edge_ids=[edge.edge_id for edge in theory_edges],
        root_cases=list(ROOT_CASES),
    )


def metadata_from_samples(samples: list[DiagnosisGraphSample]) -> tuple[list[str], list[tuple[str, str, str]]]:
    node_types = list(NODE_TYPES)
    edge_types: set[tuple[str, str, str]] = set()
    for sample in samples:
        layer_by_node = {node.node_id: node.node_layer for node in sample.graph.nodes}
        for edge in sample.graph.edges:
            source = layer_by_node.get(edge.source)
            target = layer_by_node.get(edge.target)
            if source and target:
                edge_types.add((source, edge.edge_type, target))
    return node_types, sorted(edge_types)


def _node_features(node: Any, *, layer_index: int) -> list[float]:
    features = node.features if isinstance(node.features, dict) else {}
    value_numeric = _float(features.get("value_numeric"))
    delta = _float(features.get("delta"))
    confidence = _float(features.get("confidence"))
    return [
        float(layer_index) / max(1.0, len(NODE_TYPES) - 1),
        _hash_unit(node.node_type),
        _hash_unit(node.zone),
        _hash_unit(node.field_path),
        _hash_unit(node.label),
        1.0 if features.get("present", True) else 0.0,
        _clamp(value_numeric / 1000.0),
        1.0 if features.get("value_bool") is True else 0.0,
        _clamp(confidence),
        _clamp(delta / 1000.0),
    ]


def _hash_unit(value: Any, *, buckets: int = 1024) -> float:
    text = str(value or "")
    if not text:
        return 0.0
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return (int(digest[:8], 16) % buckets) / float(buckets - 1)


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _clamp(value: float) -> float:
    return max(-1.0, min(1.0, float(value or 0.0)))


def _root_target_vector(sample: DiagnosisGraphSample, key: str) -> tuple[list[float], list[float]]:
    auxiliary = sample.labels.auxiliary if isinstance(sample.labels.auxiliary, dict) else {}
    raw = auxiliary.get(key) if isinstance(auxiliary.get(key), dict) else {}
    values = [0.0] * len(ROOT_CASES)
    mask = [0.0] * len(ROOT_CASES)
    for label, value in raw.items():
        index = ROOT_CASE_INDEX.get(str(label))
        if index is None:
            continue
        values[index] = max(0.0, min(1.0, _float(value)))
        mask[index] = 1.0
    return values, mask
