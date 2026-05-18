from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from sunpack.contracts.archive_state import ArchiveState
from sunpack.repair.job import RepairJob


PolicyGraphActionKind = Literal["module", "undo", "stop"]


@dataclass(frozen=True)
class DiagnosisHGTRequest:
    job: RepairJob
    format: str
    archive_state: ArchiveState | None = None
    knowledge_payload: dict[str, Any] = field(default_factory=dict)
    graph: dict[str, Any] = field(default_factory=dict)
    current_node_id: str = ""
    recovery: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    round_index: int = 0


@dataclass(frozen=True)
class DiagnosisHGTResult:
    format: str = ""
    root_case_scores: dict[str, float] = field(default_factory=dict)
    selected_root_cases: list[str] = field(default_factory=list)
    ranked_root_cases: list[dict[str, Any]] = field(default_factory=list)
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ranked = list(self.ranked_root_cases)
        if not ranked and self.root_case_scores:
            ranked = [
                {"root_case": key, "score": value}
                for key, value in sorted(self.root_case_scores.items(), key=lambda item: float(item[1] or 0.0), reverse=True)
            ]
        return {
            "format": self.format,
            "root_case": {
                "scores": dict(self.root_case_scores),
                "ranked": ranked,
                "selected": list(self.selected_root_cases),
            },
            "diagnostics": dict(self.diagnostics or {}),
        }


@dataclass(frozen=True)
class PolicyGraphAction:
    action_type: PolicyGraphActionKind = "stop"
    module_name: str = ""
    action_id: str = ""
    score: float = 0.0
    confidence: float | None = None
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "module_name": self.module_name,
            "action_id": self.action_id,
            "score": float(self.score or 0.0),
            "confidence": self.confidence,
            "reason": self.reason,
            "metadata": dict(self.metadata or {}),
        }


@dataclass(frozen=True)
class PolicyGraphActionRequest:
    job: RepairJob
    format: str
    graph: dict[str, Any]
    current_node_id: str
    best_node_id: str
    archive_state: ArchiveState | None
    available_actions: list[dict[str, Any]] = field(default_factory=list)
    diagnosis_hgt: dict[str, Any] = field(default_factory=dict)
    current_recovery: dict[str, Any] = field(default_factory=dict)
    best_seen_recovery: dict[str, Any] = field(default_factory=dict)
    graph_summary: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    round_index: int = 0


@dataclass
class PolicyGraphNode:
    node_id: str
    parent_id: str = ""
    patch_digest: str = ""
    archive_state: ArchiveState | None = None
    recovery: dict[str, Any] = field(default_factory=dict)
    status: str = "active"
    created_round: int = 0
    expanded_candidate_ids: set[str] = field(default_factory=set)
    exploration: dict[str, Any] = field(default_factory=dict)
    module_name: str = ""
    patch_status: str = "root"
    failure_reason: str = ""
    created_step: int = 0
    diagnosis_hgt: dict[str, Any] = field(default_factory=dict)
    verification: dict[str, Any] = field(default_factory=dict)
    prediction_error_from_parent: dict[str, Any] = field(default_factory=dict)
    uncertainty: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "parent_id": self.parent_id,
            "patch_digest": self.patch_digest,
            "patch_depth": self.archive_state.patch_depth() if self.archive_state is not None else 0,
            "recovery": dict(self.recovery or {}),
            "status": self.status,
            "created_round": int(self.created_round or 0),
            "expanded_candidate_ids": sorted(self.expanded_candidate_ids),
            "exploration": dict(self.exploration or {}),
            "archive_state": self.archive_state.to_dict() if self.archive_state is not None else {},
            "module_name": self.module_name,
            "patch_status": self.patch_status,
            "failure_reason": self.failure_reason,
            "created_step": int(self.created_step or self.created_round or 0),
            "diagnosis_hgt": dict(self.diagnosis_hgt or {}),
            "verification": dict(self.verification or {}),
            "prediction_error_from_parent": dict(self.prediction_error_from_parent or {}),
            "uncertainty": dict(self.uncertainty or {}),
        }


@dataclass
class PolicyGraphEdge:
    edge_id: str
    from_node_id: str
    to_node_id: str = ""
    candidate_id: str = ""
    module_name: str = ""
    module_family: str = ""
    action_score: dict[str, Any] = field(default_factory=dict)
    status: str = "frontier"
    created_round: int = 0
    predicted_next_state: dict[str, Any] = field(default_factory=dict)
    prediction_error: dict[str, Any] = field(default_factory=dict)
    prediction_model_version: str = ""
    predicted_at_step: int = 0
    exploration: dict[str, Any] = field(default_factory=dict)
    uncertainty: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "from_node_id": self.from_node_id,
            "to_node_id": self.to_node_id,
            "candidate_id": self.candidate_id,
            "module_name": self.module_name,
            "module_family": self.module_family,
            "action_score": dict(self.action_score or {}),
            "status": self.status,
            "created_round": int(self.created_round or 0),
            "predicted_next_state": dict(self.predicted_next_state or {}),
            "prediction_error": dict(self.prediction_error or {}),
            "prediction_model_version": self.prediction_model_version,
            "predicted_at_step": int(self.predicted_at_step or 0),
            "exploration": dict(self.exploration or {}),
            "uncertainty": dict(self.uncertainty or {}),
        }


@dataclass
class PolicyExplorationGraph:
    nodes: dict[str, PolicyGraphNode] = field(default_factory=dict)
    edges: dict[str, PolicyGraphEdge] = field(default_factory=dict)
    current_node_id: str = ""
    best_node_id: str = ""
    frontier: list[str] = field(default_factory=list)
    expansion_count: int = 0
    stale_expansion_count: int = 0

    def current_node(self) -> PolicyGraphNode | None:
        return self.nodes.get(self.current_node_id)

    def best_node(self) -> PolicyGraphNode | None:
        return self.nodes.get(self.best_node_id)

    def active_frontier_edges(self) -> list[PolicyGraphEdge]:
        return [
            self.edges[edge_id]
            for edge_id in self.frontier
            if edge_id in self.edges and self.edges[edge_id].status == "frontier"
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "current_node_id": self.current_node_id,
            "best_node_id": self.best_node_id,
            "frontier": list(self.frontier),
            "expansion_count": int(self.expansion_count or 0),
            "stale_expansion_count": int(self.stale_expansion_count or 0),
            "nodes": {key: value.to_dict() for key, value in self.nodes.items()},
            "edges": {key: value.to_dict() for key, value in self.edges.items()},
        }

    def summary(self) -> dict[str, Any]:
        current = self.current_node()
        best = self.best_node()
        current_exploration = current.exploration if current is not None and isinstance(current.exploration, dict) else {}
        best_exploration = best.exploration if best is not None and isinstance(best.exploration, dict) else {}
        current_uncertainty = current.uncertainty if current is not None and isinstance(current.uncertainty, dict) else {}
        best_uncertainty = best.uncertainty if best is not None and isinstance(best.uncertainty, dict) else {}
        attempted = sum(1 for edge in self.edges.values() if int((edge.exploration or {}).get("attempt_count") or 0) > 0)
        total_edges = max(1, len(self.edges))
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "frontier_count": len(self.active_frontier_edges()),
            "current_node_id": self.current_node_id,
            "best_node_id": self.best_node_id,
            "expansion_count": int(self.expansion_count or 0),
            "stale_expansion_count": int(self.stale_expansion_count or 0),
            "current_node_visit_count": int(current_exploration.get("visit_count") or 0),
            "current_node_exhaustion_ratio": float(current_exploration.get("exhaustion_ratio") or 0.0),
            "best_node_visit_count": int(best_exploration.get("visit_count") or 0),
            "untried_action_count": int(current_exploration.get("fresh_action_count") or 0),
            "revisit_available": bool(current_exploration.get("fresh_action_count") == 0 and int(current_exploration.get("expanded_action_count") or 0) > 0),
            "graph_exploration_coverage": attempted / total_edges,
            "steps_since_global_best_update": int(self.stale_expansion_count or 0),
            "current_node_uncertainty": float(current_uncertainty.get("overall_uncertainty") or 0.0),
            "best_node_uncertainty": float(best_uncertainty.get("overall_uncertainty") or 0.0),
            "node_status_counts": _count_statuses(node.status for node in self.nodes.values()),
            "edge_status_counts": _count_statuses(edge.status for edge in self.edges.values()),
        }


def _count_statuses(values) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "")
        counts[key] = counts.get(key, 0) + 1
    return counts
