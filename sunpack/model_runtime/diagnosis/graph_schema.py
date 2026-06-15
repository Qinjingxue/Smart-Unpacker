from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


DIAGNOSIS_GRAPH_SCHEMA_VERSION = "diagnosis_graph_v1"

NODE_LAYERS = frozenset({"observation", "theory", "cause"})
EDGE_TYPES = frozenset({
    "observes_theory",
    "observes_root_direction",
    "theory_depends_on",
    "theory_explains_obs",
    "root_direction_explains_obs",
    "cause_affects_theory",
    "theory_supports_cause",
    "same_zone",
    "same_entry",
    "propagates_to",
})


@dataclass(frozen=True)
class DiagnosisNode:
    node_id: str
    node_layer: str
    node_type: str
    format: str = ""
    zone: str = ""
    field_path: str = ""
    label: str = ""
    features: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_layer": self.node_layer,
            "node_type": self.node_type,
            "format": self.format,
            "zone": self.zone,
            "field_path": self.field_path,
            "label": self.label,
            "features": dict(self.features),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "DiagnosisNode":
        return cls(
            node_id=str(payload.get("node_id") or ""),
            node_layer=str(payload.get("node_layer") or ""),
            node_type=str(payload.get("node_type") or ""),
            format=str(payload.get("format") or ""),
            zone=str(payload.get("zone") or ""),
            field_path=str(payload.get("field_path") or ""),
            label=str(payload.get("label") or ""),
            features=dict(payload.get("features") or {}),
        )


@dataclass(frozen=True)
class DiagnosisEdge:
    edge_id: str
    edge_type: str
    source: str
    target: str
    features: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "edge_type": self.edge_type,
            "source": self.source,
            "target": self.target,
            "features": dict(self.features),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "DiagnosisEdge":
        return cls(
            edge_id=str(payload.get("edge_id") or ""),
            edge_type=str(payload.get("edge_type") or ""),
            source=str(payload.get("source") or ""),
            target=str(payload.get("target") or ""),
            features=dict(payload.get("features") or {}),
        )


@dataclass(frozen=True)
class GraphFragment:
    nodes: list[DiagnosisNode] = field(default_factory=list)
    edges: list[DiagnosisEdge] = field(default_factory=list)
    graph_features: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DiagnosisGraph:
    nodes: list[DiagnosisNode] = field(default_factory=list)
    edges: list[DiagnosisEdge] = field(default_factory=list)
    graph_features: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        nodes = sorted((node.to_dict() for node in self.nodes), key=lambda item: (item["node_layer"], item["node_id"]))
        edges = sorted((edge.to_dict() for edge in self.edges), key=lambda item: (item["edge_type"], item["source"], item["target"], item["edge_id"]))
        return {"nodes": nodes, "edges": edges, "graph_features": dict(sorted(self.graph_features.items()))}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "DiagnosisGraph":
        return cls(
            nodes=[DiagnosisNode.from_dict(item) for item in payload.get("nodes") or [] if isinstance(item, dict)],
            edges=[DiagnosisEdge.from_dict(item) for item in payload.get("edges") or [] if isinstance(item, dict)],
            graph_features=dict(payload.get("graph_features") or {}),
        )


@dataclass(frozen=True)
class DiagnosisLabels:
    root_case_labels: list[str] = field(default_factory=list)
    cause_node_ids: list[str] = field(default_factory=list)
    field_labels: list[str] = field(default_factory=list)
    zone_labels: list[str] = field(default_factory=list)
    theory_node_ids: list[str] = field(default_factory=list)
    theory_edge_ids: list[str] = field(default_factory=list)
    symptom_field_labels: list[str] = field(default_factory=list)
    symptom_zone_labels: list[str] = field(default_factory=list)
    symptom_theory_node_ids: list[str] = field(default_factory=list)
    symptom_theory_edge_ids: list[str] = field(default_factory=list)
    auxiliary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_case": {
                "labels": sorted(set(self.root_case_labels)),
            },
            "root_cause": {
                "cause_node_ids": sorted(set(self.cause_node_ids)),
                "field_labels": sorted(set(self.field_labels)),
                "zone_labels": sorted(set(self.zone_labels)),
            },
            "theory_alignment": {
                "theory_node_ids": sorted(set(self.theory_node_ids)),
                "theory_edge_ids": sorted(set(self.theory_edge_ids)),
            },
            "propagated_symptoms": {
                "field_labels": sorted(set(self.symptom_field_labels)),
                "zone_labels": sorted(set(self.symptom_zone_labels)),
                "theory_node_ids": sorted(set(self.symptom_theory_node_ids)),
                "theory_edge_ids": sorted(set(self.symptom_theory_edge_ids)),
            },
            "auxiliary": dict(sorted(self.auxiliary.items())),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "DiagnosisLabels":
        root = payload.get("root_cause") if isinstance(payload.get("root_cause"), dict) else {}
        root_case = payload.get("root_case") if isinstance(payload.get("root_case"), dict) else {}
        theory = payload.get("theory_alignment") if isinstance(payload.get("theory_alignment"), dict) else {}
        symptoms = payload.get("propagated_symptoms") if isinstance(payload.get("propagated_symptoms"), dict) else {}
        return cls(
            root_case_labels=[str(item) for item in root_case.get("labels") or []],
            cause_node_ids=[str(item) for item in root.get("cause_node_ids") or []],
            field_labels=[str(item) for item in root.get("field_labels") or []],
            zone_labels=[str(item) for item in root.get("zone_labels") or []],
            theory_node_ids=[str(item) for item in theory.get("theory_node_ids") or []],
            theory_edge_ids=[str(item) for item in theory.get("theory_edge_ids") or []],
            symptom_field_labels=[str(item) for item in symptoms.get("field_labels") or []],
            symptom_zone_labels=[str(item) for item in symptoms.get("zone_labels") or []],
            symptom_theory_node_ids=[str(item) for item in symptoms.get("theory_node_ids") or []],
            symptom_theory_edge_ids=[str(item) for item in symptoms.get("theory_edge_ids") or []],
            auxiliary=dict(payload.get("auxiliary") or {}),
        )


@dataclass(frozen=True)
class DiagnosisGraphSample:
    format: str
    sample_id: str
    source: dict[str, Any]
    graph: DiagnosisGraph
    labels: DiagnosisLabels
    schema_version: str = DIAGNOSIS_GRAPH_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "format": self.format,
            "sample_id": self.sample_id,
            "source": dict(self.source),
            "graph": self.graph.to_dict(),
            "labels": self.labels.to_dict(),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "DiagnosisGraphSample":
        return cls(
            schema_version=str(payload.get("schema_version") or ""),
            format=str(payload.get("format") or ""),
            sample_id=str(payload.get("sample_id") or ""),
            source=dict(payload.get("source") or {}),
            graph=DiagnosisGraph.from_dict(payload.get("graph") if isinstance(payload.get("graph"), dict) else {}),
            labels=DiagnosisLabels.from_dict(payload.get("labels") if isinstance(payload.get("labels"), dict) else {}),
        )


class DiagnosisGraphPlugin(Protocol):
    format_name: str

    def build_theory_graph(self) -> GraphFragment:
        ...

    def build_observation_graph(self, knowledge_payload: dict[str, Any]) -> GraphFragment:
        ...

    def build_mapping_edges(self, knowledge_payload: dict[str, Any]) -> list[DiagnosisEdge]:
        ...

    def build_cause_graph(self) -> GraphFragment:
        ...

    def build_labels(self, row: dict[str, Any]) -> DiagnosisLabels:
        ...
