from __future__ import annotations

from typing import Any

from repair_training.core.diagnosis_graph.schema import (
    DiagnosisEdge,
    DiagnosisGraph,
    DiagnosisGraphPlugin,
    DiagnosisGraphSample,
    DiagnosisNode,
    GraphFragment,
)
from repair_training.core.diagnosis_graph.validate import validate_diagnosis_graph_sample


def build_sample_with_plugin(row: dict[str, Any], *, plugin: DiagnosisGraphPlugin) -> DiagnosisGraphSample:
    knowledge_payload = row.get("knowledge_payload") if isinstance(row.get("knowledge_payload"), dict) else row
    observation = plugin.build_observation_graph(knowledge_payload)
    theory = plugin.build_theory_graph()
    cause = plugin.build_cause_graph()
    mapping_edges = plugin.build_mapping_edges(knowledge_payload)
    graph = merge_fragments(observation, theory, cause, GraphFragment(edges=mapping_edges))
    labels = plugin.build_labels(row)
    sample = DiagnosisGraphSample(
        format=plugin.format_name,
        sample_id=str(row.get("sample_id") or row.get("episode_id") or ""),
        source={
            "state_digest": str(row.get("state_digest") or ""),
            "patch_depth": int(row.get("patch_depth") or 0),
        },
        graph=graph,
        labels=labels,
    )
    validate_diagnosis_graph_sample(sample)
    return sample


def merge_fragments(*fragments: GraphFragment) -> DiagnosisGraph:
    nodes: dict[str, DiagnosisNode] = {}
    edges: dict[str, DiagnosisEdge] = {}
    graph_features: dict[str, Any] = {}
    for fragment in fragments:
        graph_features.update(fragment.graph_features)
        for node in fragment.nodes:
            nodes.setdefault(node.node_id, node)
        for edge in fragment.edges:
            edges.setdefault(edge.edge_id, edge)
    return DiagnosisGraph(
        nodes=sorted(nodes.values(), key=lambda item: (item.node_layer, item.node_id)),
        edges=sorted(edges.values(), key=lambda item: (item.edge_type, item.source, item.target, item.edge_id)),
        graph_features=dict(sorted(graph_features.items())),
    )
