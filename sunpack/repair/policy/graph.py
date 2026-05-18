from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
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
    stop_requested: bool = False
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
                    exploration={"visit_count": 1, "last_visited_step": 0, "exhaustion_ratio": 0.0},
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
                status=str(raw.get("status") or "active"),
                created_round=int(raw.get("created_round") or raw.get("created_step") or 0),
                expanded_candidate_ids={str(item) for item in raw.get("expanded_candidate_ids") or [] if str(item)},
                exploration=dict(raw.get("exploration") or {}),
                module_name=str(raw.get("module_name") or ""),
                patch_status=str(raw.get("patch_status") or ("root" if not raw.get("parent_id") else "applied")),
                failure_reason=str(raw.get("failure_reason") or ""),
                created_step=int(raw.get("created_step") or raw.get("created_round") or 0),
                diagnosis_hgt=dict(raw.get("diagnosis_hgt") or {}),
                verification=dict(raw.get("verification") or {}),
                prediction_error_from_parent=dict(raw.get("prediction_error_from_parent") or {}),
                uncertainty=dict(raw.get("uncertainty") or {}),
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
                module_family=str(raw.get("module_family") or raw.get("route_family") or ""),
                action_score=dict(raw.get("action_score") or {}),
                status=str(raw.get("status") or "frontier"),
                created_round=int(raw.get("created_round") or 0),
                predicted_next_state=dict(raw.get("predicted_next_state") or {}),
                prediction_error=dict(raw.get("prediction_error") or {}),
                prediction_model_version=str(raw.get("prediction_model_version") or ""),
                predicted_at_step=int(raw.get("predicted_at_step") or 0),
                exploration=dict(raw.get("exploration") or {}),
                uncertainty=dict(raw.get("uncertainty") or {}),
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

    def observe_current_state(
        self,
        *,
        recovery: PolicyRecoverySnapshot | dict[str, Any] | None = None,
        diagnosis_hgt: dict[str, Any] | None = None,
        verification: dict[str, Any] | None = None,
        min_improvement: float = 0.0,
    ) -> dict[str, Any]:
        current = self.graph.current_node()
        if current is not None:
            if diagnosis_hgt is not None:
                current.diagnosis_hgt = dict(diagnosis_hgt or {})
            if verification is not None:
                current.verification = dict(verification or {})
        readiness = self.observe_current_recovery(recovery, min_improvement=min_improvement)
        current = self.graph.current_node()
        if current is not None:
            self._update_prediction_error_for_node(current)
        self.refresh_exploration(step=int((current.created_step if current is not None else 0) or 0))
        return readiness

    def _update_prediction_error_for_node(self, node: PolicyGraphNode) -> None:
        edge = _incoming_edge(self.graph, node.node_id)
        if edge is None or not edge.predicted_next_state:
            return
        parent = self.graph.nodes.get(node.parent_id)
        error = compute_prediction_error(edge.predicted_next_state, node, parent)
        edge.prediction_error = error
        edge.exploration["prediction_error_after_attempt"] = float(error.get("overall_prediction_error") or 0.0)
        node.prediction_error_from_parent = error
        edge.uncertainty = compute_edge_uncertainty(edge)

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
        module_proposals = [payload for payload in proposals if str(payload.get("action_type") or "module") == "module"]
        visible_edges: list[PolicyGraphEdge] = []
        for payload in proposals:
            if str(payload.get("action_type") or "module") != "module":
                continue
            candidate_id = str(payload.get("candidate_id") or "")
            if not candidate_id:
                continue
            edge_id = policy_graph_edge_id(current.node_id, candidate_id)
            if edge_id in self.graph.edges:
                edge = self.graph.edges[edge_id]
                edge.module_name = edge.module_name or str(payload.get("module_name") or payload.get("module") or "")
                edge.module_family = edge.module_family or str(payload.get("module_family") or payload.get("route_family") or payload.get("atomic_action_group") or payload.get("module_name") or payload.get("module") or "")
                visible_edges.append(edge)
                continue
            edge = PolicyGraphEdge(
                edge_id=edge_id,
                from_node_id=current.node_id,
                candidate_id=candidate_id,
                module_name=str(payload.get("module_name") or payload.get("module") or ""),
                module_family=str(payload.get("module_family") or payload.get("route_family") or payload.get("atomic_action_group") or payload.get("module_name") or payload.get("module") or ""),
                status="frontier",
                created_round=int(step or 0),
            )
            self.graph.edges[edge_id] = edge
            visible_edges.append(edge)
        attempted = [edge for edge in visible_edges if _edge_attempt_count(edge) > 0 or edge.candidate_id in current.expanded_candidate_ids]
        fresh = [edge for edge in visible_edges if edge not in attempted]
        exposed = fresh if fresh else attempted
        for edge in fresh:
            edge.status = "frontier"
            edge.exploration["reopened_after_exhaustion"] = False
            if edge.edge_id not in self.graph.frontier:
                self.graph.frontier.append(edge.edge_id)
        for edge in attempted:
            if edge not in exposed:
                remove_frontier(self.graph, edge.edge_id)
        if not fresh:
            for edge in exposed:
                edge.status = "frontier"
                edge.exploration["reopened_after_exhaustion"] = True
                if edge.edge_id not in self.graph.frontier:
                    self.graph.frontier.append(edge.edge_id)
        self._update_node_exploration_from_edges(current, visible_edges, exposed=exposed, step=step)
        self.refresh_exploration(step=step)
        return exposed

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
            edge = PolicyGraphEdge(edge_id=edge_id, from_node_id=current.node_id, candidate_id=candidate_id, module_name=module_name, module_family=module_name, status="frontier", created_round=int(step or 0))
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
        edge.exploration["attempt_count"] = int(edge.exploration.get("attempt_count") or 0) + 1
        edge.exploration["last_attempt_step"] = int(step or 0)
        edge.exploration["result_patch_status"] = patch_status
        if repeated:
            edge.to_node_id = repeated
            edge.status = "repeated"
            self.graph.current_node_id = repeated
            repeated_node = self.graph.nodes[repeated]
            repeated_node.exploration["visit_count"] = int(repeated_node.exploration.get("visit_count") or 0) + 1
            repeated_node.exploration["last_visited_step"] = int(step or 0)
            self.refresh_exploration(step=step)
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
            exploration={"visit_count": 1, "last_visited_step": int(step or 0), "exhaustion_ratio": 0.0},
        )
        self.graph.nodes[node_id] = node
        self.graph.current_node_id = node_id
        self.graph.expansion_count += 1
        self.refresh_exploration(step=step)
        return GraphOperationResult(action="forward", node_id=node_id, edge_id=edge.edge_id, archive_state=next_state, module_name=node.module_name, patch_status=patch_status, diagnostics=failure_payload)

    def undo(self, *, step: int) -> GraphOperationResult:
        current = self.graph.current_node()
        if current is None:
            return GraphOperationResult(action="undo", node_id="", patch_status="empty_noop", diagnostics={"failure_reason": "current_node_missing"})
        if not current.parent_id or current.parent_id not in self.graph.nodes:
            return GraphOperationResult(action="undo", node_id=current.node_id, archive_state=current.archive_state, patch_status="empty_noop", diagnostics={"reason": "root_undo_noop"})
        self.graph.current_node_id = current.parent_id
        parent = self.graph.nodes[current.parent_id]
        edge = _incoming_edge(self.graph, current.node_id)
        if edge is not None:
            edge.exploration["undo_count_after_attempt"] = int(edge.exploration.get("undo_count_after_attempt") or 0) + 1
            edge.exploration["result_patch_status"] = current.patch_status
            edge.exploration["prediction_error_after_attempt"] = float((current.prediction_error_from_parent or {}).get("overall_prediction_error") or edge.exploration.get("prediction_error_after_attempt") or 0.0)
        parent.exploration["visit_count"] = int(parent.exploration.get("visit_count") or 0) + 1
        parent.exploration["last_visited_step"] = int(step or 0)
        diagnostics = {
            "from_node_id": current.node_id,
            "edge_id": edge.edge_id if edge is not None else "",
            "candidate_id": edge.candidate_id if edge is not None else "",
            "module_name": (edge.module_name if edge is not None else "") or current.module_name,
            "module_family": (edge.module_family if edge is not None else "") or current.module_name,
            "patch_status": current.patch_status,
            "recovery": dict(current.recovery or {}),
            "prediction_error": dict(current.prediction_error_from_parent or {}),
            "step": int(step or 0),
        }
        self.refresh_exploration(step=step)
        return GraphOperationResult(action="undo", node_id=parent.node_id, archive_state=parent.archive_state, patch_status=parent.patch_status, diagnostics=diagnostics)

    def refresh_exploration(self, *, step: int = 0) -> None:
        children: dict[str, list[str]] = {}
        incoming: dict[str, PolicyGraphEdge] = {}
        for edge in self.graph.edges.values():
            if edge.to_node_id:
                children.setdefault(edge.from_node_id, []).append(edge.to_node_id)
                incoming[edge.to_node_id] = edge
            if edge.to_node_id in self.graph.nodes:
                node = self.graph.nodes[edge.to_node_id]
                parent = self.graph.nodes.get(edge.from_node_id)
                edge.exploration["result_recovery_delta"] = _recovery_score(node.recovery) - _recovery_score(parent.recovery if parent is not None else {})
                edge.exploration["result_patch_status"] = node.patch_status
                edge.uncertainty = compute_edge_uncertainty(edge)
        for node_id, node in self.graph.nodes.items():
            subtree_ids = _subtree_node_ids(children, node_id)
            subtree_scores = [_recovery_score(self.graph.nodes[item].recovery) for item in subtree_ids if item in self.graph.nodes]
            own_score = _recovery_score(node.recovery)
            subtree_best = max([own_score, *subtree_scores])
            outgoing = [edge for edge in self.graph.edges.values() if edge.from_node_id == node_id]
            attempted = [edge for edge in outgoing if _edge_attempt_count(edge) > 0 or edge.candidate_id in node.expanded_candidate_ids]
            failed = [edge for edge in outgoing if edge.status == "expanded_failed" or str(edge.exploration.get("result_patch_status") or "") == "empty_failed"]
            reopened = [edge for edge in outgoing if edge.exploration.get("reopened_after_exhaustion")]
            outgoing_count = int(node.exploration.get("outgoing_action_count") or len(outgoing))
            fresh_count = max(0, outgoing_count - len(attempted))
            node.exploration.update({
                "visit_count": int(node.exploration.get("visit_count") or (1 if node_id == self.graph.current_node_id else 0)),
                "last_visited_step": int(node.exploration.get("last_visited_step") or 0),
                "outgoing_action_count": outgoing_count,
                "expanded_action_count": len(attempted),
                "failed_action_count": len(failed),
                "reopened_action_count": len(reopened),
                "fresh_action_count": fresh_count,
                "exhaustion_ratio": (len(attempted) / outgoing_count) if outgoing_count else 0.0,
                "subtree_node_count": len(subtree_ids),
                "subtree_best_recovery": subtree_best,
                "subtree_best_delta": subtree_best - own_score,
                "steps_since_subtree_best_update": int(self.graph.stale_expansion_count or 0),
            })
            node.uncertainty = compute_node_uncertainty(node)

    def _update_node_exploration_from_edges(self, node: PolicyGraphNode, visible_edges: list[PolicyGraphEdge], *, exposed: list[PolicyGraphEdge], step: int) -> None:
        attempted = [edge for edge in visible_edges if _edge_attempt_count(edge) > 0 or edge.candidate_id in node.expanded_candidate_ids]
        fresh = [edge for edge in visible_edges if edge not in attempted]
        node.exploration.update({
            "outgoing_action_count": len(visible_edges),
            "expanded_action_count": len(attempted),
            "fresh_action_count": len(fresh),
            "reopened_action_count": 0 if fresh else len(exposed),
            "exhaustion_ratio": (len(attempted) / len(visible_edges)) if visible_edges else 0.0,
            "last_visited_step": int(step or node.exploration.get("last_visited_step") or 0),
            "visit_count": int(node.exploration.get("visit_count") or 1),
        })

    def stop_best(self) -> GraphOperationResult:
        best_id = best_node_id(self.graph)
        self.graph.best_node_id = best_id
        node = self.graph.nodes.get(best_id)
        return GraphOperationResult(action="stop", node_id=best_id, archive_state=node.archive_state if node is not None else None, stop_requested=True, module_name=node.module_name if node is not None else "", patch_status=node.patch_status if node is not None else "", diagnostics={"best_node_id": best_id})


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
    return f"node_{digest[:32]}"


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


def _edge_attempt_count(edge: PolicyGraphEdge) -> int:
    return int((edge.exploration or {}).get("attempt_count") or 0)


def _subtree_node_ids(children: dict[str, list[str]], node_id: str) -> list[str]:
    output: list[str] = []
    stack = list(children.get(node_id, []))
    while stack:
        current = stack.pop()
        output.append(current)
        stack.extend(children.get(current, []))
    return output


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


def compute_prediction_error(predicted: dict[str, Any], actual_node: PolicyGraphNode, parent_node: PolicyGraphNode | None = None) -> dict[str, Any]:
    predicted_recovery = predicted.get("predicted_recovery") if isinstance(predicted.get("predicted_recovery"), dict) else {}
    predicted_verification = predicted.get("predicted_verification_summary") if isinstance(predicted.get("predicted_verification_summary"), dict) else {}
    actual_recovery = actual_node.recovery if isinstance(actual_node.recovery, dict) else {}
    actual_verification = _verification_summary(actual_node.verification)
    actual_score = _clamp01(_float(actual_recovery.get("score", actual_recovery.get("completeness"))))
    parent_score = _clamp01(_float((parent_node.recovery if parent_node is not None and isinstance(parent_node.recovery, dict) else {}).get("score")))
    predicted_score = _clamp01(_float(predicted_recovery.get("score")))
    predicted_delta = _float(predicted.get("predicted_recovery_delta", predicted.get("recovery_delta", predicted_score - parent_score)))
    actual_delta = actual_score - parent_score
    diagnosis_l1 = _diagnosis_l1(
        predicted.get("predicted_diagnosis_root_scores") if isinstance(predicted.get("predicted_diagnosis_root_scores"), dict) else {},
        actual_node.diagnosis_hgt if isinstance(actual_node.diagnosis_hgt, dict) else {},
    )
    predicted_top = _top_root(predicted.get("predicted_diagnosis_root_scores") if isinstance(predicted.get("predicted_diagnosis_root_scores"), dict) else {})
    actual_top = _top_root((_root_scores(actual_node.diagnosis_hgt if isinstance(actual_node.diagnosis_hgt, dict) else {})))
    predicted_patch_hash = _float(predicted.get("predicted_patch_status_hash"))
    actual_patch_hash = _hash_unit(actual_node.patch_status)
    patch_mismatch = abs(predicted_patch_hash - actual_patch_hash)
    completeness_error = abs(_clamp01(_float(predicted_verification.get("completeness", predicted_recovery.get("completeness")))) - _clamp01(_float(actual_verification.get("completeness", actual_recovery.get("completeness")))))
    recovery_abs_error = abs(predicted_score - actual_score)
    recovery_delta_error = abs(predicted_delta - actual_delta)
    diagnosis_top1_changed = bool(predicted_top and actual_top and predicted_top != actual_top)
    overall = _clamp01(
        0.35 * recovery_abs_error
        + 0.20 * min(1.0, recovery_delta_error)
        + 0.25 * diagnosis_l1
        + 0.10 * completeness_error
        + 0.10 * min(1.0, patch_mismatch * 2.0)
    )
    return {
        "recovery_abs_error": recovery_abs_error,
        "recovery_delta_error": recovery_delta_error,
        "diagnosis_root_l1": diagnosis_l1,
        "diagnosis_top1_changed": diagnosis_top1_changed,
        "verification_completeness_error": completeness_error,
        "patch_status_mismatch": patch_mismatch,
        "overall_prediction_error": overall,
        "predicted_top_root": predicted_top,
        "actual_top_root": actual_top,
    }


def compute_node_uncertainty(node: PolicyGraphNode) -> dict[str, Any]:
    scores = [_clamp01(_float(value)) for value in _root_scores(node.diagnosis_hgt if isinstance(node.diagnosis_hgt, dict) else {}).values()]
    scores.sort(reverse=True)
    diagnosis_entropy = _normalized_entropy(scores)
    top_margin = scores[0] - scores[1] if len(scores) > 1 else (scores[0] if scores else 0.0)
    root = node.diagnosis_hgt.get("root_case") if isinstance(node.diagnosis_hgt.get("root_case"), dict) else {}
    selected_count = len(root.get("selected") or []) if isinstance(root.get("selected"), list) else 0
    verification = _verification_summary(node.verification)
    completeness = _clamp01(_float(verification.get("completeness", (node.recovery or {}).get("completeness", (node.recovery or {}).get("score")))))
    status = str(verification.get("assessment_status") or (node.recovery or {}).get("status") or "")
    hint = str(verification.get("decision_hint") or (node.recovery or {}).get("decision_hint") or "")
    verification_ambiguity = _clamp01(
        (1.0 - abs(completeness - 0.5) * 2.0) * 0.45
        + (0.25 if status in {"partial", "unusable", "unknown", ""} else 0.0)
        + (0.20 if hint in {"repair", "unknown", ""} else 0.0)
        + (0.10 if "archive_coverage" not in verification else 0.0)
    )
    exploration = node.exploration if isinstance(node.exploration, dict) else {}
    exploration_uncertainty = _clamp01(
        0.45 * (1.0 - _clamp01(_float(exploration.get("exhaustion_ratio"))))
        + 0.30 * min(1.0, _float(exploration.get("fresh_action_count")) / 8.0)
        + 0.25 * _clamp01(_float(exploration.get("subtree_best_delta")))
    )
    prediction_error = node.prediction_error_from_parent if isinstance(node.prediction_error_from_parent, dict) else {}
    prediction_uncertainty = _clamp01(_float(prediction_error.get("overall_prediction_error")))
    overall = _clamp01(
        0.30 * diagnosis_entropy
        + 0.20 * (1.0 - _clamp01(top_margin))
        + 0.20 * verification_ambiguity
        + 0.15 * exploration_uncertainty
        + 0.15 * prediction_uncertainty
    )
    return {
        "overall_uncertainty": overall,
        "diagnosis_entropy": diagnosis_entropy,
        "diagnosis_top_margin": _clamp01(top_margin),
        "diagnosis_selected_count": selected_count,
        "verification_ambiguity": verification_ambiguity,
        "exploration_uncertainty": exploration_uncertainty,
        "prediction_uncertainty": prediction_uncertainty,
    }


def compute_edge_uncertainty(edge: PolicyGraphEdge) -> dict[str, Any]:
    existing = edge.uncertainty if isinstance(edge.uncertainty, dict) else {}
    predicted = edge.predicted_next_state if isinstance(edge.predicted_next_state, dict) else {}
    predicted_scores = predicted.get("predicted_diagnosis_root_scores") if isinstance(predicted.get("predicted_diagnosis_root_scores"), dict) else {}
    scores = [_clamp01(_float(value)) for value in predicted_scores.values()]
    scores.sort(reverse=True)
    predicted_entropy = _normalized_entropy(scores)
    predicted_margin = scores[0] - scores[1] if len(scores) > 1 else (scores[0] if scores else 0.0)
    prediction_error = edge.prediction_error if isinstance(edge.prediction_error, dict) else {}
    exploration = edge.exploration if isinstance(edge.exploration, dict) else {}
    historical_error = _clamp01(_float(prediction_error.get("overall_prediction_error", exploration.get("prediction_error_after_attempt"))))
    predicted_uncertainty = _clamp01(_float(existing.get("predicted_uncertainty", existing.get("overall_uncertainty"))))
    result_ambiguity = _clamp01(
        0.35 * (1.0 if str(exploration.get("result_patch_status") or edge.status) in {"empty_failed", "expanded_failed", "repeated"} else 0.0)
        + 0.30 * (1.0 if exploration.get("reopened_after_exhaustion") else 0.0)
        + 0.20 * min(1.0, _float(exploration.get("undo_count_after_attempt")) / 4.0)
        + 0.15 * (1.0 - abs(_clamp01(_float(exploration.get("result_recovery_delta"))) - 0.5) * 2.0)
    )
    overall = _clamp01(
        0.25 * predicted_entropy
        + 0.15 * (1.0 - _clamp01(predicted_margin))
        + 0.25 * historical_error
        + 0.20 * result_ambiguity
        + 0.15 * predicted_uncertainty
    )
    return {
        "overall_uncertainty": overall,
        "predicted_uncertainty": predicted_uncertainty,
        "transition_prediction_entropy": predicted_entropy,
        "transition_prediction_margin": _clamp01(predicted_margin),
        "prediction_error_uncertainty": historical_error,
        "result_ambiguity": result_ambiguity,
    }


def _incoming_edge(graph: PolicyExplorationGraph, node_id: str) -> PolicyGraphEdge | None:
    for edge in graph.edges.values():
        if edge.to_node_id == node_id:
            return edge
    return None


def _verification_summary(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else payload
    return dict(summary or {})


def _diagnosis_l1(predicted_scores: dict[str, Any], actual_diagnosis: dict[str, Any]) -> float:
    actual_scores = _root_scores(actual_diagnosis)
    labels = set(predicted_scores) | set(actual_scores)
    if not labels:
        return 0.0
    total = 0.0
    for label in labels:
        total += abs(_clamp01(_float(predicted_scores.get(label))) - _clamp01(_float(actual_scores.get(label))))
    return _clamp01(total / max(1, len(labels)))


def _root_scores(diagnosis: dict[str, Any]) -> dict[str, Any]:
    root = diagnosis.get("root_case") if isinstance(diagnosis.get("root_case"), dict) else {}
    scores = root.get("scores") if isinstance(root.get("scores"), dict) else diagnosis.get("root_case_scores")
    return dict(scores or {}) if isinstance(scores, dict) else {}


def _top_root(scores: dict[str, Any]) -> str:
    if not scores:
        return ""
    return max(scores.items(), key=lambda item: _float(item[1]))[0]


def _hash_unit(value: Any, *, buckets: int = 2048) -> float:
    text = str(value or "")
    if not text:
        return 0.0
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return (int(digest[:8], 16) % buckets) / float(buckets - 1)


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _normalized_entropy(values: list[float]) -> float:
    if not values:
        return 0.0
    total = sum(max(0.0, float(value)) for value in values)
    if total <= 0.0:
        return 0.0
    import math
    entropy = 0.0
    for value in values:
        p = max(0.0, float(value)) / total
        if p > 0.0:
            entropy -= p * math.log(p)
    return _clamp01(entropy / math.log(max(2, len(values))))


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
