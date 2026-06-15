from __future__ import annotations

from sunpack.repair.model.diagnosis.graph_schema import (
    DIAGNOSIS_GRAPH_SCHEMA_VERSION,
    EDGE_TYPES,
    NODE_LAYERS,
    DiagnosisGraphSample,
)


class DiagnosisGraphValidationError(ValueError):
    pass


def validate_diagnosis_graph_sample(sample: DiagnosisGraphSample) -> None:
    if sample.schema_version != DIAGNOSIS_GRAPH_SCHEMA_VERSION:
        raise DiagnosisGraphValidationError(f"unsupported diagnosis graph schema: {sample.schema_version}")
    node_ids: set[str] = set()
    edge_ids: set[str] = set()
    for node in sample.graph.nodes:
        if not node.node_id:
            raise DiagnosisGraphValidationError("diagnosis graph node is missing node_id")
        if node.node_id in node_ids:
            raise DiagnosisGraphValidationError(f"duplicate diagnosis graph node_id: {node.node_id}")
        if node.node_layer not in NODE_LAYERS:
            raise DiagnosisGraphValidationError(f"invalid diagnosis graph node_layer: {node.node_layer}")
        node_ids.add(node.node_id)
    for edge in sample.graph.edges:
        if not edge.edge_id:
            raise DiagnosisGraphValidationError("diagnosis graph edge is missing edge_id")
        if edge.edge_id in edge_ids:
            raise DiagnosisGraphValidationError(f"duplicate diagnosis graph edge_id: {edge.edge_id}")
        if edge.edge_type not in EDGE_TYPES:
            raise DiagnosisGraphValidationError(f"invalid diagnosis graph edge_type: {edge.edge_type}")
        if edge.source not in node_ids:
            raise DiagnosisGraphValidationError(f"diagnosis graph edge source is missing: {edge.source}")
        if edge.target not in node_ids:
            raise DiagnosisGraphValidationError(f"diagnosis graph edge target is missing: {edge.target}")
        edge_ids.add(edge.edge_id)
    for node_id in sample.labels.cause_node_ids:
        if node_id not in node_ids:
            raise DiagnosisGraphValidationError(f"root cause label references missing node: {node_id}")
    for node_id in sample.labels.theory_node_ids:
        if node_id not in node_ids:
            raise DiagnosisGraphValidationError(f"theory alignment label references missing node: {node_id}")
    for edge_id in sample.labels.theory_edge_ids:
        if edge_id not in edge_ids:
            raise DiagnosisGraphValidationError(f"theory alignment label references missing edge: {edge_id}")
    for node_id in sample.labels.symptom_theory_node_ids:
        if node_id not in node_ids:
            raise DiagnosisGraphValidationError(f"symptom theory label references missing node: {node_id}")
    for edge_id in sample.labels.symptom_theory_edge_ids:
        if edge_id not in edge_ids:
            raise DiagnosisGraphValidationError(f"symptom theory label references missing edge: {edge_id}")
