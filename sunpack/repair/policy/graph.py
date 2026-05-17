from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from sunpack.contracts.archive_state import ArchiveState, PatchPlan
from sunpack.repair.candidate import RepairCandidate
from sunpack.repair.job import RepairJob
from sunpack.repair.policy.recovery_evaluator import PolicyRecoverySnapshot
from sunpack.repair.policy.types import PolicyExplorationGraph, PolicyGraphEdge, PolicyGraphNode


GraphOperationKind = Literal["init", "forward", "undo", "stop"]


@dataclass(frozen=True)
class GraphOperationResult:
    action: GraphOperationKind
    node_id: str
    edge_id: str = ""
    archive_state: ArchiveState | None = None
    stop_signal: bool = False
    module_name: str = ""
    patch_status: str = "applied"
    diagnostics: dict[str, Any] = field(default_factory=dict)


class PolicyRepairGraph:
    def __init__(self, graph: PolicyExplorationGraph):
        self.graph = graph

    @classmethod
    def initialize(cls, job: RepairJob, recovery: PolicyRecoverySnapshot | dict[str, Any] | None = None) -> "PolicyRepairGraph":
        state = _job_archive_state(job)
        digest = state.effective_patch_digest() if state is not None else ""
        node_id = policy_graph_node_id(digest, 0)
        recovery_payload = recovery.to_dict() if hasattr(recovery, "to_dict") else dict(recovery or {})
        graph = PolicyExplorationGraph(
            nodes={
                node_id: PolicyGraphNode(
                    node_id=node_id,
                    patch_digest=digest,
                    archive_state=state,
                    recovery=recovery_payload,
                    patch_status="root",
                    created_round=0,
                    created_step=0,
                )
            },
            current_node_id=node_id,
            best_node_id=node_id,
        )
        return cls(graph)

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "PolicyRepairGraph":
        graph = PolicyExplorationGraph(
            current_node_id=str(payload.get("current_node_id") or ""),
            best_node_id=str(payload.get("best_node_id") or ""),
            frontier=[str(item) for item in payload.get("frontier") or [] if str(item)],
            expansion_count=int(payload.get("expansion_count") or 0),
            stale_expansion_count=int(payload.get("stale_expansion_count") or 0),
        )
        nodes = payload.get("nodes") if isinstance(payload.get("nodes"), dict) else {}
        for node_id, raw in nodes.items():
            if not isinstance(raw, dict):
                continue
            archive_state = archive_state_from_payload(raw.get("archive_state"))
            graph.nodes[str(node_id)] = PolicyGraphNode(
                node_id=str(raw.get("node_id") or node_id),
                parent_id=str(raw.get("parent_id") or ""),
                patch_digest=str(raw.get("patch_digest") or ""),
                archive_state=archive_state,
                recovery=dict(raw.get("recovery") or {}),
                state_value=dict(raw.get("state_value") or {}),
                status=str(raw.get("status") or "active"),
                created_round=int(raw.get("created_round") or raw.get("created_step") or 0),
                expanded_candidate_ids={str(item) for item in raw.get("expanded_candidate_ids") or [] if str(item)},
                module_name=str(raw.get("module_name") or ""),
                patch_status=str(raw.get("patch_status") or ("root" if not raw.get("parent_id") else "applied")),
                failure_reason=str(raw.get("failure_reason") or ""),
                created_step=int(raw.get("created_step") or raw.get("created_round") or 0),
            )
        edges = payload.get("edges") if isinstance(payload.get("edges"), dict) else {}
        for edge_id, raw in edges.items():
            if not isinstance(raw, dict):
                continue
            graph.edges[str(edge_id)] = PolicyGraphEdge(
                edge_id=str(raw.get("edge_id") or edge_id),
                from_node_id=str(raw.get("from_node_id") or ""),
                to_node_id=str(raw.get("to_node_id") or ""),
                candidate_id=str(raw.get("candidate_id") or ""),
                module_name=str(raw.get("module_name") or ""),
                action_prior=dict(raw.get("action_prior") or {}),
                status=str(raw.get("status") or "frontier"),
                created_round=int(raw.get("created_round") or 0),
            )
        graph.frontier = [edge_id for edge_id in graph.frontier if edge_id in graph.edges and graph.edges[edge_id].status == "frontier"]
        if not graph.current_node_id or graph.current_node_id not in graph.nodes:
            graph.current_node_id = next(iter(graph.nodes), "")
        if not graph.best_node_id or graph.best_node_id not in graph.nodes:
            graph.best_node_id = graph.current_node_id
        return cls(graph)

    def to_payload(self) -> dict[str, Any]:
        return self.graph.to_dict()

    def current_node(self) -> PolicyGraphNode | None:
        return self.graph.current_node()

    def observe_current_recovery(self, recovery: PolicyRecoverySnapshot | dict[str, Any] | None, *, min_improvement: float = 0.0) -> dict[str, Any]:
        current = self.graph.current_node()
        if current is None:
            return self.stop_readiness()
        previous_best_id = self.graph.best_node_id if self.graph.best_node_id in self.graph.nodes else ""
        previous_best = self.graph.nodes.get(previous_best_id)
        previous_score = _recovery_score(previous_best.recovery if previous_best is not None else {})
        payload = recovery.to_dict() if hasattr(recovery, "to_dict") else dict(recovery or {})
        current.recovery = payload
        candidate_best_id = best_node_id(self.graph)
        candidate = self.graph.nodes.get(candidate_best_id)
        candidate_score = _recovery_score(candidate.recovery if candidate is not None else {})
        improved = not previous_best_id or candidate_score > previous_score + max(0.0, float(min_improvement or 0.0))
        if improved:
            self.graph.best_node_id = candidate_best_id
            self.graph.stale_expansion_count = 0
        else:
            self.graph.best_node_id = previous_best_id or candidate_best_id
            if self.graph.expansion_count > 0 or current.node_id != self.graph.best_node_id:
                self.graph.stale_expansion_count += 1
        return self.stop_readiness()

    def stop_readiness(self, *, stale_patience: int = 0) -> dict[str, Any]:
        best_id = best_node_id(self.graph)
        if best_id:
            self.graph.best_node_id = best_id
        best = self.graph.nodes.get(self.graph.best_node_id)
        recovery = best.recovery if best is not None and isinstance(best.recovery, dict) else {}
        best_score = _recovery_score(recovery)
        stale_steps = int(self.graph.stale_expansion_count or 0)
        plateau = bool(stale_patience and stale_steps >= int(stale_patience or 0))
        reason = "graph_stale_best" if plateau else ""
        return {
            "best_node_id": self.graph.best_node_id,
            "best_recovery": best_score,
            "steps_since_best_update": stale_steps,
            "stale_patience": int(stale_patience or 0),
            "plateau": plateau,
            "should_force_stop": bool(plateau),
            "force_stop_reason": reason,
        }

    def register_proposals(self, proposals: list[dict[str, Any]], *, step: int) -> list[PolicyGraphEdge]:
        current = self.graph.current_node()
        if current is None:
            return []
        output: list[PolicyGraphEdge] = []
        for payload in proposals:
            candidate_id = str(payload.get("candidate_id") or "")
            if not candidate_id or candidate_id in current.expanded_candidate_ids:
                continue
            edge_id = policy_graph_edge_id(current.node_id, candidate_id)
            if edge_id in self.graph.edges:
                edge = self.graph.edges[edge_id]
                if edge.status == "frontier" and edge_id not in self.graph.frontier:
                    self.graph.frontier.append(edge_id)
                output.append(edge)
                continue
            edge = PolicyGraphEdge(
                edge_id=edge_id,
                from_node_id=current.node_id,
                candidate_id=candidate_id,
                module_name=str(payload.get("module_name") or payload.get("module") or ""),
                status="frontier",
                created_round=int(step or 0),
            )
            self.graph.edges[edge_id] = edge
            self.graph.frontier.append(edge_id)
            output.append(edge)
        return output

    def forward(
        self,
        *,
        candidate_id: str,
        module_name: str,
        materialized_candidate: RepairCandidate | None,
        failure: dict[str, Any] | None = None,
        step: int,
    ) -> GraphOperationResult:
        current = self.graph.current_node()
        if current is None or current.archive_state is None:
            return GraphOperationResult(action="forward", node_id="", module_name=module_name, patch_status="empty_failed", diagnostics={"failure_reason": "current_node_missing"})
        edge_id = policy_graph_edge_id(current.node_id, candidate_id)
        edge = self.graph.edges.get(edge_id)
        if edge is None:
            edge = PolicyGraphEdge(edge_id=edge_id, from_node_id=current.node_id, candidate_id=candidate_id, module_name=module_name, status="frontier", created_round=int(step or 0))
            self.graph.edges[edge_id] = edge
            self.graph.frontier.append(edge_id)
        failure_payload = dict(failure or {})
        next_state = materialized_candidate.repaired_state if materialized_candidate is not None else None
        patch_status = "applied"
        if next_state is None:
            patch_status = "empty_failed"
            next_state = current.archive_state.push_patch(empty_policy_patch(
                base_state=current.archive_state,
                module_name=module_name or edge.module_name or "unknown_policy_module",
                reason=str(failure_payload.get("failure_reason") or failure_payload.get("message") or "materialization_failed"),
                diagnostics=failure_payload,
            ))
        next_digest = next_state.effective_patch_digest()
        repeated = find_node_by_digest(self.graph, next_digest)
        current.expanded_candidate_ids.add(edge.candidate_id)
        remove_frontier(self.graph, edge.edge_id)
        if repeated:
            edge.to_node_id = repeated
            edge.status = "repeated"
            self.graph.current_node_id = repeated
            return GraphOperationResult(action="forward", node_id=repeated, edge_id=edge.edge_id, archive_state=self.graph.nodes[repeated].archive_state, module_name=module_name, patch_status="repeated", diagnostics=failure_payload)
        node_id = policy_graph_node_id(next_digest, len(self.graph.nodes))
        edge.to_node_id = node_id
        edge.status = "expanded" if patch_status == "applied" else "expanded_failed"
        node = PolicyGraphNode(
            node_id=node_id,
            parent_id=current.node_id,
            patch_digest=next_digest,
            archive_state=next_state,
            recovery={},
            status="active",
            created_round=int(step or 0),
            created_step=int(step or 0),
            module_name=module_name or edge.module_name,
            patch_status=patch_status,
            failure_reason=str(failure_payload.get("failure_reason") or failure_payload.get("message") or "") if patch_status != "applied" else "",
        )
        self.graph.nodes[node_id] = node
        self.graph.current_node_id = node_id
        self.graph.expansion_count += 1
        return GraphOperationResult(action="forward", node_id=node_id, edge_id=edge.edge_id, archive_state=next_state, module_name=node.module_name, patch_status=patch_status, diagnostics=failure_payload)

    def undo(self, *, step: int) -> GraphOperationResult:
        current = self.graph.current_node()
        if current is None:
            return GraphOperationResult(action="undo", node_id="", patch_status="empty_noop", diagnostics={"failure_reason": "current_node_missing"})
        if not current.parent_id or current.parent_id not in self.graph.nodes:
            return GraphOperationResult(action="undo", node_id=current.node_id, archive_state=current.archive_state, patch_status="empty_noop", diagnostics={"reason": "root_undo_noop"})
        self.graph.current_node_id = current.parent_id
        parent = self.graph.nodes[current.parent_id]
        return GraphOperationResult(action="undo", node_id=parent.node_id, archive_state=parent.archive_state, patch_status=parent.patch_status, diagnostics={"from_node_id": current.node_id, "step": int(step or 0)})

    def stop_best(self) -> GraphOperationResult:
        best_id = best_node_id(self.graph)
        self.graph.best_node_id = best_id
        node = self.graph.nodes.get(best_id)
        return GraphOperationResult(action="stop", node_id=best_id, archive_state=node.archive_state if node is not None else None, stop_signal=True, module_name=node.module_name if node is not None else "", patch_status=node.patch_status if node is not None else "", diagnostics={"best_node_id": best_id})


def empty_policy_patch(*, base_state: ArchiveState, module_name: str, reason: str, diagnostics: dict[str, Any] | None = None) -> PatchPlan:
    return PatchPlan(
        module=str(module_name or "unknown_policy_module"),
        format=base_state.format_hint or base_state.source.format_hint,
        action_type="policy_empty_patch",
        operations=[],
        provenance={
            "module": str(module_name or "unknown_policy_module"),
            "policy_patch_status": "empty_failed",
            "failure_reason": str(reason or "materialization_failed"),
            "diagnostics": dict(diagnostics or {}),
        },
        confidence=0.0,
    )


def policy_graph_node_id(patch_digest: str, index: int) -> str:
    digest = str(patch_digest or "root")
    return f"node_{int(index):04d}_{digest[:16]}"


def policy_graph_edge_id(node_id: str, candidate_id: str) -> str:
    return f"{node_id}::{candidate_id}"


def find_node_by_digest(graph: PolicyExplorationGraph, patch_digest: str) -> str:
    digest = str(patch_digest or "")
    for node_id, node in graph.nodes.items():
        if node.patch_digest == digest:
            return node_id
    return ""


def remove_frontier(graph: PolicyExplorationGraph, edge_id: str) -> None:
    graph.frontier = [item for item in graph.frontier if item != edge_id]


def archive_state_from_payload(payload: Any) -> ArchiveState | None:
    if not isinstance(payload, dict) or not payload:
        return None
    try:
        return ArchiveState.from_dict(payload)
    except Exception:
        return None


def best_node_id(graph: PolicyExplorationGraph) -> str:
    best_id = graph.best_node_id if graph.best_node_id in graph.nodes else graph.current_node_id
    best_key = None
    for node_id, node in graph.nodes.items():
        recovery = node.recovery if isinstance(node.recovery, dict) else {}
        score = _float(recovery.get("score"))
        depth = node.archive_state.patch_depth() if node.archive_state is not None else 0
        non_failed = 0 if node.patch_status == "empty_failed" else 1
        key = (score, -depth, non_failed)
        if best_key is None or key > best_key:
            best_key = key
            best_id = node_id
    return best_id


def _recovery_score(payload: dict[str, Any]) -> float:
    return _float((payload or {}).get("score"))


def _job_archive_state(job: RepairJob) -> ArchiveState | None:
    if job.archive_state is not None:
        return job.archive_state
    try:
        from sunpack.repair.policy.training_runtime import archive_state_for_job

        return archive_state_for_job(job)
    except Exception:
        return None


def _float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
