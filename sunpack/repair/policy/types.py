from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

from sunpack.contracts.archive_state import ArchiveState
from sunpack.repair.candidate import RepairCandidate
from sunpack.repair.job import RepairJob


PolicyCandidatePayload = dict[str, Any]
GraphPolicyActionKind = Literal["expand_edge", "checkout_node", "stop_signal"]
PolicyGraphActionKind = Literal["expand", "checkout", "finish"]


@dataclass(frozen=True)
class DamageAnalysisRequest:
    job: RepairJob
    format: str
    archive_state: ArchiveState | None = None
    runtime_context: dict[str, Any] = field(default_factory=dict)
    diagnosis: dict[str, Any] = field(default_factory=dict)
    knowledge_projection: dict[str, Any] = field(default_factory=dict)
    repair_history: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    round_index: int = 0


@dataclass(frozen=True)
class DamageAnalysisResult:
    format: str = ""
    damage_labels: list[str] = field(default_factory=list)
    damage_zones: list[dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0
    route_hints: list[str] = field(default_factory=list)
    blocking_reasons: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "damage_labels": list(self.damage_labels),
            "damage_zones": [dict(item) for item in self.damage_zones],
            "confidence": float(self.confidence or 0.0),
            "route_hints": list(self.route_hints),
            "blocking_reasons": list(self.blocking_reasons),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class GraphActionRequest:
    job: RepairJob
    format: str
    graph: dict[str, Any]
    current_node_id: str
    best_node_id: str
    archive_state: ArchiveState | None
    frontier: list[dict[str, Any]] = field(default_factory=list)
    candidate_payloads: list[PolicyCandidatePayload] = field(default_factory=list)
    damage_analysis: dict[str, Any] = field(default_factory=dict)
    current_recovery: dict[str, Any] = field(default_factory=dict)
    best_seen_recovery: dict[str, Any] = field(default_factory=dict)
    parent_recovery: dict[str, Any] = field(default_factory=dict)
    state_value: dict[str, Any] = field(default_factory=dict)
    parent_state_value: dict[str, Any] = field(default_factory=dict)
    graph_summary: dict[str, Any] = field(default_factory=dict)
    diagnosis: dict[str, Any] = field(default_factory=dict)
    repair_history: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    round_index: int = 0


@dataclass(frozen=True)
class GraphActionPrior:
    action_type: GraphPolicyActionKind = "stop_signal"
    edge_id: str = ""
    candidate_id: str = ""
    node_id: str = ""
    prior_score: float = 0.0
    confidence: float | None = None
    provider_id: str = ""
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "edge_id": self.edge_id,
            "candidate_id": self.candidate_id,
            "node_id": self.node_id,
            "prior_score": float(self.prior_score or 0.0),
            "confidence": self.confidence,
            "provider_id": self.provider_id,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }


@dataclass
class PolicyGraphNode:
    node_id: str
    parent_id: str = ""
    patch_digest: str = ""
    archive_state: ArchiveState | None = None
    recovery: dict[str, Any] = field(default_factory=dict)
    state_value: dict[str, Any] = field(default_factory=dict)
    status: str = "active"
    created_round: int = 0
    expanded_candidate_ids: set[str] = field(default_factory=set)
    module_name: str = ""
    patch_status: str = "root"
    failure_reason: str = ""
    created_step: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "parent_id": self.parent_id,
            "patch_digest": self.patch_digest,
            "patch_depth": self.archive_state.patch_depth() if self.archive_state is not None else 0,
            "recovery": dict(self.recovery or {}),
            "state_value": dict(self.state_value or {}),
            "status": self.status,
            "created_round": int(self.created_round or 0),
            "expanded_candidate_ids": sorted(self.expanded_candidate_ids),
            "archive_state": self.archive_state.to_dict() if self.archive_state is not None else {},
            "module_name": self.module_name,
            "patch_status": self.patch_status,
            "failure_reason": self.failure_reason,
            "created_step": int(self.created_step or self.created_round or 0),
        }


@dataclass
class PolicyGraphEdge:
    edge_id: str
    from_node_id: str
    to_node_id: str = ""
    candidate_id: str = ""
    module_name: str = ""
    action_prior: dict[str, Any] = field(default_factory=dict)
    status: str = "frontier"
    created_round: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "from_node_id": self.from_node_id,
            "to_node_id": self.to_node_id,
            "candidate_id": self.candidate_id,
            "module_name": self.module_name,
            "action_prior": dict(self.action_prior or {}),
            "status": self.status,
            "created_round": int(self.created_round or 0),
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
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "frontier_count": len(self.active_frontier_edges()),
            "current_node_id": self.current_node_id,
            "best_node_id": self.best_node_id,
            "expansion_count": int(self.expansion_count or 0),
            "stale_expansion_count": int(self.stale_expansion_count or 0),
            "node_status_counts": _count_statuses(node.status for node in self.nodes.values()),
            "edge_status_counts": _count_statuses(edge.status for edge in self.edges.values()),
        }


@dataclass(frozen=True)
class PolicyGraphAction:
    action: PolicyGraphActionKind = "finish"
    candidate_id: str = ""
    node_id: str = ""
    reason: str = ""
    terminal_action: str = ""
    final_node_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "candidate_id": self.candidate_id,
            "node_id": self.node_id,
            "reason": self.reason,
            "terminal_action": self.terminal_action,
            "final_node_id": self.final_node_id,
            "metadata": dict(self.metadata or {}),
        }


def _count_statuses(values) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "")
        counts[key] = counts.get(key, 0) + 1
    return counts


@dataclass(frozen=True)
class StateValueRequest:
    job: RepairJob
    format: str
    archive_state: ArchiveState | None = None
    damage_analysis: dict[str, Any] = field(default_factory=dict)
    current_recovery: dict[str, Any] = field(default_factory=dict)
    best_seen_recovery: dict[str, Any] = field(default_factory=dict)
    parent_recovery: dict[str, Any] = field(default_factory=dict)
    candidate_summaries: list[PolicyCandidatePayload] = field(default_factory=list)
    repair_history: dict[str, Any] = field(default_factory=dict)
    diagnosis: dict[str, Any] = field(default_factory=dict)
    graph_summary: dict[str, Any] = field(default_factory=dict)
    frontier_summary: dict[str, Any] = field(default_factory=dict)
    branch_status: str = ""
    config: dict[str, Any] = field(default_factory=dict)
    round_index: int = 0


@dataclass(frozen=True)
class StateValueResult:
    reachable_recovery_value: float = 0.0
    confidence: float | None = None
    provider_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reachable_recovery_value": float(self.reachable_recovery_value or 0.0),
            "confidence": self.confidence,
            "provider_id": self.provider_id,
            "metadata": dict(self.metadata),
        }


@runtime_checkable
class DamageAnalysisModel(Protocol):
    provider_id: str
    supported_formats: tuple[str, ...] | list[str]

    def available(self) -> bool:
        ...

    def analyze(self, request: DamageAnalysisRequest) -> DamageAnalysisResult | dict[str, Any] | None:
        ...


@runtime_checkable
class GraphActionModel(Protocol):
    provider_id: str
    supported_formats: tuple[str, ...] | list[str]

    def available(self) -> bool:
        ...

    def choose_graph_action(self, request: GraphActionRequest) -> dict[str, Any] | list[dict[str, Any]] | None:
        ...


@runtime_checkable
class GraphStateValueModel(Protocol):
    provider_id: str
    supported_formats: tuple[str, ...] | list[str]

    def available(self) -> bool:
        ...

    def estimate(self, request: StateValueRequest) -> StateValueResult | dict[str, Any] | float | None:
        ...
