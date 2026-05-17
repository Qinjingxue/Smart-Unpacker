from __future__ import annotations

import importlib
from typing import Any

from sunpack.contracts.archive_state import ArchiveState
from sunpack.repair.candidate import RepairCandidate
from sunpack.repair.job import RepairJob
from sunpack.repair.policy.adapters import get_damage_analysis_adapter
from sunpack.repair.policy.types import (
    DamageAnalysisRequest,
    DamageAnalysisResult,
    StepActionScore,
    StepActionRequest,
    PolicyCandidatePayload,
    PolicyExplorationGraph,
    PolicyStepDecision,
    PolicyGraphEdge,
    StepValueRequest,
    StepValueResult,
)


class RepairPolicyManager:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.policy_config = self.config.get("policy") if isinstance(self.config.get("policy"), dict) else {}
        self.enabled = bool(self.policy_config.get("enabled", True))
        self.fallback_to_selector = bool(self.policy_config.get("fallback_to_selector", True))
        self.strict_provider_errors = bool(self.policy_config.get("strict_provider_errors", False))
        self.provider_package = str(self.policy_config.get("provider_package") or "sunpack_repair_models")
        self._providers: list[Any] | None = None
        self.last_load_error: str = ""

    def dual_model_active_for_job(self, job: RepairJob) -> bool:
        if not self.enabled:
            return False
        fmt = _normalize_format(job.format)
        return bool(fmt and self._damage_models(fmt) and self._step_action_models(fmt) and self._step_value_models(fmt))

    def active_for_job(self, job: RepairJob) -> bool:
        return self.dual_model_active_for_job(job)

    def status_for_job(self, job: RepairJob) -> dict[str, Any]:
        base = {
            "enabled": self.enabled,
            "provider_package": self.provider_package,
            "fallback_to_selector": self.fallback_to_selector,
        }
        if not self.enabled:
            return {**base, "decision_status": "disabled", "fallback_reason": "policy_disabled"}
        fmt = _normalize_format(job.format)
        providers = self.providers()
        if not providers:
            return {
                **base,
                "decision_status": "unavailable",
                "fallback_reason": "policy_unavailable",
                "load_error": self.last_load_error,
            }
        if not any(self._provider_supports_format(provider, fmt) for provider in providers):
            return {**base, "decision_status": "unavailable", "fallback_reason": "unsupported_format"}
        return {**base, "decision_status": "available"}

    def analyze_damage(
        self,
        *,
        job: RepairJob,
        archive_state: ArchiveState | None = None,
        runtime_context: dict[str, Any] | None = None,
        diagnosis: dict[str, Any] | None = None,
        round_index: int = 0,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        base = {"enabled": self.enabled, "provider_package": self.provider_package}
        fmt = _normalize_format(job.format)
        request = DamageAnalysisRequest(
            job=job,
            format=fmt,
            archive_state=archive_state,
            runtime_context=dict(runtime_context or {}),
            diagnosis=dict(diagnosis or {}),
            knowledge_projection=dict(getattr(job, "knowledge", {}) or {}),
            repair_history=dict(getattr(job, "repair_history", {}) or {}),
            config=dict(self.config),
            round_index=int(round_index or 0),
        )
        errors: list[str] = []
        for provider in self._damage_models(fmt):
            provider_id = self._provider_id(provider)
            try:
                result = _coerce_damage_analysis(provider.analyze(request), provider_id=provider_id, fmt=fmt)
            except Exception as exc:
                if self.strict_provider_errors:
                    raise
                errors.append(f"{provider_id}: {exc}")
                continue
            return result.to_dict(), {
                **base,
                "decision_status": "analyzed",
                "provider_id": provider_id,
                "confidence": result.confidence,
                "metadata": _public_metadata(result.metadata),
                "provider_errors": errors,
            }
        result = DamageAnalysisResult(
            format=fmt,
            damage_labels=[str(item) for item in getattr(job, "damage_flags", []) if str(item)],
            confidence=float(getattr(job, "confidence", 0.0) or 0.0),
            metadata={"decision_reason": "damage_analysis_unavailable"},
        )
        return result.to_dict(), {
            **base,
            "decision_status": "fallback",
            "fallback_reason": "damage_analysis_unavailable",
            "provider_errors": errors,
            "load_error": self.last_load_error,
        }

    def score_step_actions(
        self,
        *,
        job: RepairJob,
        archive_state: ArchiveState | None,
        candidate_payloads: list[PolicyCandidatePayload],
        graph: PolicyExplorationGraph,
        damage_analysis: dict[str, Any],
        current_recovery: dict[str, Any] | None = None,
        best_seen_recovery: dict[str, Any] | None = None,
        parent_recovery: dict[str, Any] | None = None,
        state_value: dict[str, Any] | None = None,
        parent_state_value: dict[str, Any] | None = None,
        diagnosis: dict[str, Any] | None = None,
        round_index: int = 0,
    ) -> tuple[list[StepActionScore], dict[str, Any]]:
        base = {
            "enabled": self.enabled,
            "provider_package": self.provider_package,
            "fallback_to_selector": self.fallback_to_selector,
        }
        fmt = _normalize_format(job.format)
        _candidate_by_id, duplicate_candidate_ids = _candidate_id_index(candidate_payloads)
        if duplicate_candidate_ids:
            return [], {
                **base,
                "decision_status": "fallback",
                "fallback_reason": "duplicate_candidate_id",
                "duplicate_candidate_id_count": len(duplicate_candidate_ids),
                "duplicate_candidate_ids": duplicate_candidate_ids,
            }
        request = StepActionRequest(
            job=job,
            format=fmt,
            graph=graph.to_dict(),
            graph_summary=graph.summary(),
            current_node_id=graph.current_node_id,
            best_node_id=graph.best_node_id,
            archive_state=archive_state,
            frontier=[edge.to_dict() for edge in graph.active_frontier_edges()],
            candidate_payloads=list(candidate_payloads),
            damage_analysis=dict(damage_analysis or {}),
            current_recovery=dict(current_recovery or {}),
            best_seen_recovery=dict(best_seen_recovery or {}),
            parent_recovery=dict(parent_recovery or {}),
            state_value=dict(state_value or {}),
            parent_state_value=dict(parent_state_value or {}),
            diagnosis=dict(diagnosis or {}),
            repair_history=dict(getattr(job, "repair_history", {}) or {}),
            config=dict(self.config),
            round_index=int(round_index or 0),
        )
        errors: list[str] = []
        for provider in self._step_action_models(fmt):
            provider_id = self._provider_id(provider)
            try:
                raw = provider.score_step_actions(request)
            except Exception as exc:
                if self.strict_provider_errors:
                    raise
                errors.append(f"{provider_id}: {exc}")
                continue
            scores = _coerce_step_action_scores(raw, provider_id=provider_id)
            if scores:
                valid, invalid_count = _valid_graph_step_scores(scores, graph)
                if valid:
                    return valid, {
                        **base,
                        "decision_status": "selected",
                        "provider_id": provider_id,
                        "invalid_score_count": invalid_count,
                        "frontier_count": len(graph.active_frontier_edges()),
                        "raw_step_action_scores": [score.to_dict() for score in scores],
                        "step_action_scores": [score.to_dict() for score in valid],
                    }
                errors.append(f"{provider_id}: step_action_scores_invalid")
                continue
            errors.append(f"{provider_id}: step_action_score_list_required")
        return [], {
            **base,
            "decision_status": "fallback",
            "fallback_reason": "step_action_model_unavailable_or_invalid",
            "provider_errors": errors,
            "load_error": self.last_load_error,
        }

    def decide_step_action(
        self,
        *,
        graph: PolicyExplorationGraph,
        step_action_scores: list[StepActionScore],
        step_action_selection: dict[str, Any],
        events: dict[str, Any] | None = None,
        current_recovery: dict[str, Any] | None = None,
        best_seen_recovery: dict[str, Any] | None = None,
        state_value: dict[str, Any] | None = None,
        round_index: int = 0,
        max_expansions: int = 0,
    ) -> tuple[PolicyStepDecision, dict[str, Any]]:
        events = dict(events or {})
        current_score = _optional_float((current_recovery or {}).get("score")) or 0.0
        best_score = _optional_float((best_seen_recovery or {}).get("score")) or 0.0
        policy = self.policy_config if isinstance(self.policy_config, dict) else {}
        stale_patience = max(0, int(policy.get("graph_stale_expansion_patience", policy.get("stop_plateau_min_rounds", 2)) or 0))
        frontier = graph.active_frontier_edges()
        selected_score = _best_graph_step_score(step_action_scores, graph)
        best_edge = _best_graph_frontier_edge(frontier)
        final_node_id = graph.best_node_id or graph.current_node_id
        stop_controller = {
            "best_score": best_score,
            "current_score": current_score,
            "frontier_count": len(frontier),
            "events": events,
            "selected_score": selected_score.to_dict() if selected_score is not None else {},
        }
        if stale_patience and graph.stale_expansion_count >= stale_patience:
            return PolicyStepDecision(action="finish", reason="graph_stale_expansions", terminal_action="stop", final_node_id=final_node_id), {
                "stop_controller": {**stop_controller, "finish_reason": "graph_stale_expansions"},
                "step_action_selection": step_action_selection,
            }
        stop_dominance = _graph_stop_absolute_advantage(step_action_scores, state_value=state_value or {}, best_seen_recovery=best_seen_recovery or {}, policy=policy)
        if stop_dominance.get("stop_dominates"):
            stop_score_payload = stop_dominance.get("stop_action_score") if isinstance(stop_dominance.get("stop_action_score"), dict) else {}
            return PolicyStepDecision(action="finish", reason=str(stop_score_payload.get("reason") or "model_stop_absolute_advantage"), terminal_action="stop", final_node_id=final_node_id), {
                "stop_controller": {**stop_controller, "finish_reason": "model_stop_absolute_advantage", "stop_dominance": stop_dominance},
                "step_action_selection": step_action_selection,
            }
        if selected_score is not None and selected_score.action_type == "module":
            edge = _graph_edge_for_step_score(graph, selected_score)
            if edge is not None:
                if edge.from_node_id == graph.current_node_id:
                    return PolicyStepDecision(action="expand", candidate_id=edge.candidate_id, reason=selected_score.reason, metadata={"edge_id": edge.edge_id, "step_action_score": selected_score.to_dict()}), {
                        "stop_controller": {**stop_controller, "finish_reason": ""},
                        "step_action_selection": step_action_selection,
                    }
                return PolicyStepDecision(action="checkout", node_id=edge.from_node_id, reason="checkout_frontier_source", metadata={"edge_id": edge.edge_id, "candidate_id": edge.candidate_id, "step_action_score": selected_score.to_dict()}), {
                    "stop_controller": {**stop_controller, "finish_reason": ""},
                    "step_action_selection": step_action_selection,
                }
        if selected_score is not None and selected_score.action_type == "undo":
            return PolicyStepDecision(action="checkout", node_id="", reason=selected_score.reason or "model_undo", metadata={"step_action_score": selected_score.to_dict()}), {
                "stop_controller": {**stop_controller, "finish_reason": ""},
                "step_action_selection": step_action_selection,
            }
        if best_edge is not None:
            if best_edge.from_node_id == graph.current_node_id:
                return PolicyStepDecision(action="expand", candidate_id=best_edge.candidate_id, reason="continue_best_frontier", metadata={"edge_id": best_edge.edge_id}), {
                    "stop_controller": {**stop_controller, "finish_reason": ""},
                    "step_action_selection": step_action_selection,
                }
            return PolicyStepDecision(action="checkout", node_id=best_edge.from_node_id, reason="checkout_best_frontier", metadata={"edge_id": best_edge.edge_id, "candidate_id": best_edge.candidate_id}), {
                "stop_controller": {**stop_controller, "finish_reason": ""},
                "step_action_selection": step_action_selection,
            }
        return PolicyStepDecision(action="checkout", reason="no_executable_step_action", metadata={"checkout_semantics": "undo_parent", "stop_dominance": stop_dominance}), {
            "stop_controller": {**stop_controller, "finish_reason": "", "no_executable_step_action": True, "stop_dominance": stop_dominance},
            "step_action_selection": step_action_selection,
        }

    def estimate_state_value(
        self,
        *,
        job: RepairJob,
        archive_state: ArchiveState | None,
        damage_analysis: dict[str, Any],
        current_recovery: dict[str, Any] | None = None,
        best_seen_recovery: dict[str, Any] | None = None,
        parent_recovery: dict[str, Any] | None = None,
        candidate_payloads: list[PolicyCandidatePayload] | None = None,
        graph_summary: dict[str, Any] | None = None,
        frontier_summary: dict[str, Any] | None = None,
        branch_status: str = "",
        diagnosis: dict[str, Any] | None = None,
        round_index: int = 0,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        fmt = _normalize_format(job.format)
        current_score = _optional_float((current_recovery or {}).get("score")) or 0.0
        base = {"enabled": self.enabled, "provider_package": self.provider_package}
        request = StepValueRequest(
            job=job,
            format=fmt,
            archive_state=archive_state,
            damage_analysis=dict(damage_analysis or {}),
            current_recovery=dict(current_recovery or {}),
            best_seen_recovery=dict(best_seen_recovery or {}),
            parent_recovery=dict(parent_recovery or {}),
            candidate_summaries=list(candidate_payloads or []),
            repair_history=dict(getattr(job, "repair_history", {}) or {}),
            diagnosis=dict(diagnosis or {}),
            graph_summary=dict(graph_summary or {}),
            frontier_summary=dict(frontier_summary or {}),
            branch_status=str(branch_status or ""),
            config=dict(self.config),
            round_index=int(round_index or 0),
        )
        errors: list[str] = []
        for provider in self._step_value_models(fmt):
            provider_id = self._provider_id(provider)
            try:
                result = _coerce_state_value(provider.estimate(request), provider_id=provider_id, fallback=current_score)
            except Exception as exc:
                if self.strict_provider_errors:
                    raise
                errors.append(f"{provider_id}: {exc}")
                continue
            return result.to_dict(), {
                **base,
                "decision_status": "estimated",
                "provider_id": provider_id,
                "confidence": result.confidence,
                "metadata": _public_metadata(result.metadata),
                "provider_errors": errors,
            }
        result = StepValueResult(
            reachable_recovery_value=current_score,
            confidence=0.0,
            metadata={"decision_reason": "state_value_unavailable", "fallback": True},
        )
        return result.to_dict(), {
            **base,
            "decision_status": "fallback",
            "fallback_reason": "state_value_unavailable",
            "provider_errors": errors,
            "load_error": self.last_load_error,
        }

    def providers(self) -> list[Any]:
        if self._providers is None:
            self._providers = self._load_providers()
        return list(self._providers)

    def _load_providers(self) -> list[Any]:
        if not self.enabled:
            return []
        try:
            package = importlib.import_module(self.provider_package)
        except Exception as exc:
            self.last_load_error = str(exc)
            return []

        providers: list[Any] = []
        if hasattr(package, "get_damage_analysis_models"):
            providers.extend(list(package.get_damage_analysis_models() or []))
        if hasattr(package, "get_step_action_models"):
            providers.extend(list(package.get_step_action_models() or []))
        if hasattr(package, "get_step_value_models"):
            providers.extend(list(package.get_step_value_models() or []))
        return [provider for provider in providers if provider is not None]

    def register(self, provider: Any) -> None:
        if self._providers is None:
            self._providers = []
        self._providers.append(provider)

    @staticmethod
    def _provider_supports_format(provider: Any, fmt: str) -> bool:
        supported = getattr(provider, "supported_formats", ())
        values = {_normalize_format(item) for item in supported or []}
        return "*" in values or fmt in values

    @staticmethod
    def _provider_id(provider: Any) -> str:
        return str(getattr(provider, "provider_id", "") or provider.__class__.__name__ or "repair_policy")

    def _damage_models(self, fmt: str) -> list[Any]:
        output: list[Any] = []
        for provider in self.providers():
            if not self._provider_supports_format(provider, fmt):
                continue
            available = getattr(provider, "available", None)
            if callable(available) and not bool(available()):
                continue
            if callable(getattr(provider, "analyze", None)):
                output.append(provider)
        return output

    def _step_action_models(self, fmt: str) -> list[Any]:
        output: list[Any] = []
        for provider in self.providers():
            if not self._provider_supports_format(provider, fmt):
                continue
            available = getattr(provider, "available", None)
            if callable(available) and not bool(available()):
                continue
            if callable(getattr(provider, "score_step_actions", None)):
                output.append(provider)
        return output

    def _step_value_models(self, fmt: str) -> list[Any]:
        output: list[Any] = []
        for provider in self.providers():
            if not self._provider_supports_format(provider, fmt):
                continue
            available = getattr(provider, "available", None)
            if callable(available) and not bool(available()):
                continue
            if callable(getattr(provider, "estimate", None)):
                output.append(provider)
        return output


def _coerce_damage_analysis(value: DamageAnalysisResult | dict[str, Any] | None, *, provider_id: str, fmt: str) -> DamageAnalysisResult:
    if isinstance(value, DamageAnalysisResult):
        return value
    if isinstance(value, dict):
        scores = value.get("damage_location_scores")
        if not isinstance(scores, dict):
            scores = value.get("scores")
        if isinstance(scores, dict) and not value.get("damage_labels"):
            adapter = get_damage_analysis_adapter(fmt)
            if adapter is None:
                return DamageAnalysisResult(
                    format=fmt,
                    metadata={
                        **dict(value.get("metadata") or {}),
                        "provider_id": provider_id,
                        "decision_reason": "damage_analysis_adapter_unavailable",
                    },
                )
            metadata = {**dict(value.get("metadata") or {}), "provider_id": provider_id}
            if isinstance(value.get("world_field_scores"), dict):
                metadata["world_field_scores"] = dict(value.get("world_field_scores") or {})
            if isinstance(value.get("world_field_predictions"), dict):
                metadata["world_field_predictions"] = dict(value.get("world_field_predictions") or {})
            if isinstance(value.get("world_summary"), dict):
                metadata["world_summary"] = dict(value.get("world_summary") or {})
            if isinstance(value.get("normal_structure_metadata"), dict):
                metadata["normal_structure_metadata"] = dict(value.get("normal_structure_metadata") or {})
            if isinstance(value.get("structure_anomaly"), dict):
                metadata["structure_anomaly"] = dict(value.get("structure_anomaly") or {})
            result = adapter.postprocess_scores(
                {str(label): _optional_float(score) or 0.0 for label, score in scores.items()},
                (
                    value.get("thresholds_observed")
                    if isinstance(value.get("thresholds_observed"), dict)
                    else value.get("thresholds") if isinstance(value.get("thresholds"), dict) else None
                ),
                metadata=metadata,
                uncertainty_scores={
                    str(label): _optional_float(score) or 0.0
                    for label, score in (value.get("damage_uncertainty_scores") or {}).items()
                } if isinstance(value.get("damage_uncertainty_scores"), dict) else None,
                uncertainty_thresholds=value.get("thresholds_uncertain") if isinstance(value.get("thresholds_uncertain"), dict) else None,
            )
            return result
        return DamageAnalysisResult(
            format=str(value.get("format") or fmt),
            damage_labels=[str(item) for item in value.get("damage_labels") or [] if str(item)],
            damage_zones=[dict(item) for item in value.get("damage_zones") or [] if isinstance(item, dict)],
            confidence=float(value.get("confidence") or 0.0),
            route_hints=[str(item) for item in value.get("route_hints") or [] if str(item)],
            blocking_reasons=[str(item) for item in value.get("blocking_reasons") or [] if str(item)],
            metadata={**dict(value.get("metadata") or {}), "provider_id": provider_id},
        )
    return DamageAnalysisResult(format=fmt, metadata={"provider_id": provider_id, "decision_reason": "empty_damage_analysis"})


def _best_graph_frontier_edge(edges: list[PolicyGraphEdge]) -> PolicyGraphEdge | None:
    if not edges:
        return None
    return max(edges, key=_graph_edge_score)


def _graph_edge_for_step_score(graph: PolicyExplorationGraph, score: StepActionScore) -> PolicyGraphEdge | None:
    edge_id = str(score.edge_id or "")
    if edge_id and edge_id in graph.edges:
        edge = graph.edges[edge_id]
        return edge if edge.status == "frontier" else None
    wanted = str(score.candidate_id or "")
    if not wanted:
        return None
    for edge in graph.edges.values():
        if edge.candidate_id == wanted and edge.status == "frontier":
            return edge
    return None


def _frontier_has_high_value(edges: list[PolicyGraphEdge], best_score: float, *, margin: float) -> bool:
    for edge in edges:
        value = _optional_float((edge.step_action_score or {}).get("logic_score")) or best_score
        if value >= float(best_score or 0.0) + float(margin or 0.0):
            return True
    return False


def _graph_stop_absolute_advantage(
    scores: list[StepActionScore],
    *,
    state_value: dict[str, Any],
    best_seen_recovery: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    stop_scores = [score for score in scores if score.action_type == "stop"]
    if not stop_scores:
        return {"stop_dominates": False, "reason": "no_stop_score"}
    stop_action_score = max(stop_scores, key=lambda item: float(item.logic_score or 0.0))
    other_scores = [score for score in scores if score.action_type in {"module", "undo"}]
    best_other_score = max((float(score.logic_score or 0.0) for score in other_scores), default=float("-inf"))
    stop_score = float(stop_action_score.logic_score or 0.0)
    confidence = 1.0 if stop_action_score.confidence is None else float(stop_action_score.confidence or 0.0)
    action_margin = float(policy.get("stop_absolute_action_margin", 0.25) or 0.25)
    min_stop_score = float(policy.get("stop_absolute_min_score", 0.75) or 0.75)
    min_confidence = float(policy.get("stop_absolute_min_confidence", 0.65) or 0.65)
    value_margin = float(policy.get("stop_absolute_value_margin", 0.01) or 0.01)
    best_score = _optional_float((best_seen_recovery or {}).get("score")) or 0.0
    reachable_value = _optional_float((state_value or {}).get("reachable_recovery_value", (state_value or {}).get("value")))
    if reachable_value is None:
        reachable_value = best_score
    action_dominates = stop_score >= min_stop_score and confidence >= min_confidence and (not other_scores or stop_score >= best_other_score + action_margin)
    value_allows_stop = float(reachable_value) <= float(best_score) + value_margin
    return {
        "stop_dominates": bool(action_dominates and value_allows_stop),
        "action_dominates": bool(action_dominates),
        "value_allows_stop": bool(value_allows_stop),
        "stop_score": stop_score,
        "best_non_stop_score": None if best_other_score == float("-inf") else best_other_score,
        "action_margin": action_margin,
        "min_stop_score": min_stop_score,
        "confidence": confidence,
        "min_confidence": min_confidence,
        "best_recovery": float(best_score),
        "reachable_recovery_value": float(reachable_value),
        "value_margin": value_margin,
        "stop_action_score": stop_action_score.to_dict(),
    }


def _graph_edge_score(edge: PolicyGraphEdge) -> float:
    score = _optional_float((edge.step_action_score or {}).get("logic_score"))
    if score is None:
        score = _optional_float((edge.step_action_score or {}).get("final_score"))
    return float(score or 0.0)


def _best_graph_step_score(scores: list[StepActionScore], graph: PolicyExplorationGraph) -> StepActionScore | None:
    valid, _invalid = _valid_graph_step_scores(scores, graph)
    if not valid:
        return None
    return max(valid, key=lambda item: float(item.logic_score or 0.0))


def _valid_graph_step_scores(scores: list[StepActionScore], graph: PolicyExplorationGraph) -> tuple[list[StepActionScore], int]:
    valid: list[StepActionScore] = []
    invalid = 0
    for score in scores:
        if score.action_type == "module":
            if _graph_edge_for_step_score(graph, score) is None:
                invalid += 1
                continue
        elif score.action_type == "undo":
            pass
        valid.append(score)
    return valid, invalid


def _coerce_step_action_scores(value: Any, *, provider_id: str) -> list[StepActionScore]:
    if isinstance(value, dict):
        raw = value.get("step_action_scores")
        if raw is None:
            raw = value.get("action_scores")
        if isinstance(raw, list):
            return [_coerce_step_action_score(item, provider_id=provider_id) for item in raw if isinstance(item, dict)]
    if isinstance(value, list):
        return [_coerce_step_action_score(item, provider_id=provider_id) for item in value if isinstance(item, dict)]
    return []


def _coerce_step_action_score(value: dict[str, Any], *, provider_id: str) -> StepActionScore:
    action = str(value.get("operation") or value.get("action_type") or value.get("action") or "module")
    if action not in {"module", "undo", "stop"}:
        raise ValueError(f"unsupported step operation score: {action}")
    return StepActionScore(
        action_type=action,  # type: ignore[arg-type]
        edge_id=str(value.get("edge_id") or ""),
        candidate_id=str(value.get("candidate_id") or ""),
        node_id=str(value.get("node_id") or ""),
        logic_score=float(_optional_float(value.get("logic_score", value.get("score", value.get("confidence", 0.0)))) or 0.0),
        confidence=_optional_float(value.get("confidence")),
        provider_id=str(value.get("provider_id") or provider_id),
        reason=str(value.get("reason") or ""),
        metadata=dict(value.get("metadata") or {}),
    )


def _coerce_state_value(value: StepValueResult | dict[str, Any] | float | int | None, *, provider_id: str, fallback: float) -> StepValueResult:
    if isinstance(value, StepValueResult):
        if value.provider_id:
            return value
        return StepValueResult(**{**value.to_dict(), "provider_id": provider_id})
    if isinstance(value, (float, int)):
        return StepValueResult(reachable_recovery_value=_clamp01(float(value)), provider_id=provider_id)
    if isinstance(value, dict):
        parsed = _optional_float(value.get("reachable_recovery_value", value.get("value", value.get("score", fallback))))
        raw_scores = value.get("step_value_scores")
        if raw_scores is None:
            raw_scores = value.get("action_values")
        action_values = [_coerce_step_action_score(item, provider_id=provider_id) for item in raw_scores or [] if isinstance(item, dict)] if isinstance(raw_scores, list) else []
        return StepValueResult(
            reachable_recovery_value=_clamp01(parsed if parsed is not None else fallback),
            action_values=action_values,
            confidence=_optional_float(value.get("confidence")),
            provider_id=str(value.get("provider_id") or provider_id),
            metadata=dict(value.get("metadata") or {}),
        )
    return StepValueResult(
        reachable_recovery_value=_clamp01(fallback),
        provider_id=provider_id,
        metadata={"decision_reason": "empty_state_value"},
    )


def _candidate_id_index(candidate_payloads: list[PolicyCandidatePayload]) -> tuple[dict[str, int], list[str]]:
    candidate_by_id: dict[str, int] = {}
    duplicate_ids: set[str] = set()
    for index, payload in enumerate(candidate_payloads):
        if not isinstance(payload, dict):
            continue
        candidate_id = str(payload.get("candidate_id") or "")
        if not candidate_id:
            continue
        if candidate_id in candidate_by_id:
            duplicate_ids.add(candidate_id)
            continue
        candidate_by_id[candidate_id] = index
    return candidate_by_id, sorted(duplicate_ids)


def _first_invalid_reason(errors: list[str]) -> str:
    for error in errors:
        text = str(error)
        if ": " in text:
            return text.split(": ", 1)[1]
        if text:
            return text
    return ""


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value or 0.0)))


def _state_value_score(value: dict[str, Any] | None, *, default: float = 0.0) -> float:
    parsed = _optional_float((value or {}).get("reachable_recovery_value"))
    return _clamp01(parsed if parsed is not None else default)


def _normalize_format(value: Any) -> str:
    text = str(value or "").lower().lstrip(".")
    return {"gz": "gzip", "bz2": "bzip2", "seven_zip": "7z"}.get(text, text)


def _public_metadata(value: dict[str, Any]) -> dict[str, Any]:
    allowed = {"model_id", "model_version", "format", "decision_reason", "provider_id"}
    return {key: value[key] for key in allowed if key in value}
