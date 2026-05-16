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
    PolicyCandidatePayload,
    RepairActionDecision,
    RepairActionPrior,
    RepairActionRequest,
    StateValueRequest,
    StateValueResult,
)


DEFAULT_ARBITER_CONFIG = {
    "stop_epsilon": 0.035,
    "low_value_threshold": 0.06,
    "continue_margin": 0.12,
    "apply_margin": 0.06,
    "undo_margin": 0.08,
    "value_weight": 1.0,
    "recovery_weight": 0.4,
    "step_cost": 0.01,
    "undo_cost": 0.005,
    "loop_penalty": 0.20,
    "invalid_candidate_penalty": 2.0,
    "hard_guard_penalty": 2.0,
}


class PolicyDecisionArbiter:
    def __init__(self, config: dict[str, Any] | None = None):
        payload = {**DEFAULT_ARBITER_CONFIG, **dict(config or {})}
        self.stop_epsilon = float(payload["stop_epsilon"])
        self.low_value_threshold = float(payload["low_value_threshold"])
        self.continue_margin = float(payload["continue_margin"])
        self.apply_margin = float(payload["apply_margin"])
        self.undo_margin = float(payload["undo_margin"])
        self.value_weight = float(payload["value_weight"])
        self.recovery_weight = float(payload["recovery_weight"])
        self.step_cost = float(payload["step_cost"])
        self.undo_cost = float(payload["undo_cost"])
        self.loop_penalty = float(payload["loop_penalty"])
        self.invalid_candidate_penalty = float(payload["invalid_candidate_penalty"])
        self.hard_guard_penalty = float(payload["hard_guard_penalty"])

    def decide(
        self,
        *,
        priors: list[RepairActionPrior],
        candidate_payloads: list[PolicyCandidatePayload],
        candidate_state_values: dict[str, dict[str, Any]] | None,
        current_recovery: dict[str, Any] | None,
        state_value: dict[str, Any] | None,
        parent_state_value: dict[str, Any] | None,
        parent_recovery: dict[str, Any] | None,
    ) -> tuple[RepairActionDecision, dict[str, Any]]:
        current_score = _optional_float((current_recovery or {}).get("score")) or 0.0
        current_value = _state_value_score(state_value, default=current_score)
        parent_score = _optional_float((parent_recovery or {}).get("score")) or 0.0
        parent_value = _state_value_score(parent_state_value, default=parent_score)
        candidate_by_id = {str(item.get("candidate_id") or ""): dict(item) for item in candidate_payloads if isinstance(item, dict)}
        value_by_id = candidate_state_values or {}
        scored: list[tuple[float, RepairActionPrior, dict[str, Any]]] = []
        max_apply_prior = max((prior.prior_score for prior in priors if prior.action == "apply_patch"), default=0.0)
        best_candidate_value_delta = max(
            (_state_value_score(value_by_id.get(candidate_id), default=current_value) - current_value for candidate_id in candidate_by_id),
            default=0.0,
        )
        parent_value_delta = parent_value - current_value
        parent_recovery_delta = parent_score - current_score
        value_gap = current_value - current_score
        has_apply = any(prior.action == "apply_patch" for prior in priors)
        has_undo = any(prior.action == "undo_patch" for prior in priors)
        for prior in priors:
            candidate_id = str(prior.candidate_id or "")
            details: dict[str, Any] = {
                "prior_score": float(prior.prior_score or 0.0),
                "action": prior.action,
                "candidate_id": candidate_id,
                "hard_guard": "",
                "selected_reason": prior.reason or prior.action,
            }
            score = float(prior.prior_score or 0.0)
            if prior.action == "apply_patch":
                payload = candidate_by_id.get(candidate_id, {})
                recovery_delta = _optional_float(payload.get("recovery_delta")) or 0.0
                next_value = _state_value_score(value_by_id.get(candidate_id), default=current_value)
                value_delta = next_value - current_value
                score += self.value_weight * value_delta + self.recovery_weight * recovery_delta - self.step_cost
                if not payload:
                    score -= self.invalid_candidate_penalty
                    details["hard_guard"] = "missing_candidate_payload"
                if bool(payload.get("repeated_digest")):
                    score -= self.loop_penalty
                    details["hard_guard"] = "repeated_digest"
                if bool(payload.get("noop")) or bool((payload.get("metadata") or {}).get("noop")):
                    score -= self.invalid_candidate_penalty
                    details["hard_guard"] = "noop_candidate"
                validation = payload.get("validation_summary") if isinstance(payload.get("validation_summary"), dict) else {}
                if validation and not bool(validation.get("accepted", True)):
                    score -= self.invalid_candidate_penalty
                    details["hard_guard"] = "validation_rejected"
                if value_delta >= self.apply_margin:
                    score += self.apply_margin
                    details["selected_reason"] = "candidate_value_improves"
                details.update({"next_value": next_value, "value_delta": value_delta, "recovery_delta": recovery_delta})
            elif prior.action == "undo_patch":
                value_delta = parent_value_delta
                recovery_delta = parent_recovery_delta
                score += self.value_weight * value_delta + self.recovery_weight * recovery_delta - self.undo_cost
                if value_delta >= self.undo_margin:
                    score += self.undo_margin
                    details["selected_reason"] = "parent_value_improves"
                elif parent_value <= 0.0 and parent_score <= 0.0:
                    score -= self.hard_guard_penalty
                    details["hard_guard"] = "missing_parent_value"
                details.update({"parent_value": parent_value, "value_delta": value_delta, "recovery_delta": recovery_delta})
            elif prior.action == "stop":
                gap = value_gap
                if current_score >= 0.95 or (gap <= self.stop_epsilon and current_value > self.low_value_threshold):
                    score += 1.0
                    details["selected_reason"] = "value_gap_satisfied"
                else:
                    score -= max(0.0, gap)
                if gap > self.continue_margin and (best_candidate_value_delta >= self.apply_margin or parent_value_delta >= self.undo_margin or has_apply or has_undo):
                    score -= self.hard_guard_penalty
                    details["hard_guard"] = "stop_blocked_high_value_gap"
                details.update({
                    "value_gap": gap,
                    "stop_epsilon": self.stop_epsilon,
                    "continue_margin": self.continue_margin,
                    "best_candidate_value_delta": best_candidate_value_delta,
                    "parent_value_delta": parent_value_delta,
                })
            elif prior.action == "give_up":
                if current_value <= self.low_value_threshold and max_apply_prior <= 0.0 and not has_undo:
                    score += 1.0
                    details["selected_reason"] = "low_value_no_actions"
                else:
                    score -= max(0.0, current_value)
                    if has_apply or has_undo:
                        score -= self.hard_guard_penalty
                        details["hard_guard"] = "give_up_blocked_actions_available"
                details.update({"current_value": current_value, "low_value_threshold": self.low_value_threshold})
            details["final_score"] = score
            details["arbiter_score"] = score
            scored.append((score, prior, details))
        if not scored:
            return RepairActionDecision(action="give_up", reason="no_action_priors"), {"scores": [], "selected_by": "arbiter"}
        scored.sort(key=lambda item: item[0], reverse=True)
        score, prior, details = scored[0]
        return RepairActionDecision(
            action=prior.action,
            selected_candidate_id=prior.candidate_id if prior.action == "apply_patch" else "",
            confidence=prior.confidence,
            provider_id=prior.provider_id,
            reason=f"arbiter:{prior.reason or prior.action}",
            metadata={"arbiter_score": score, "prior_score": prior.prior_score, **dict(prior.metadata or {})},
        ), {
            "selected_by": "arbiter",
            "scores": [item[2] for item in scored],
            "config": {
                **dict(DEFAULT_ARBITER_CONFIG),
                "stop_epsilon": self.stop_epsilon,
                "low_value_threshold": self.low_value_threshold,
                "continue_margin": self.continue_margin,
                "apply_margin": self.apply_margin,
                "undo_margin": self.undo_margin,
                "value_weight": self.value_weight,
                "recovery_weight": self.recovery_weight,
                "step_cost": self.step_cost,
                "undo_cost": self.undo_cost,
                "loop_penalty": self.loop_penalty,
            },
            "current_value": current_value,
            "current_recovery": current_score,
            "value_gap": value_gap,
            "best_candidate_value_delta": best_candidate_value_delta,
            "parent_value_delta": parent_value_delta,
        }


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
        return bool(fmt and self._damage_models(fmt) and self._action_models(fmt))

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

    def choose_action(
        self,
        *,
        job: RepairJob,
        archive_state: ArchiveState | None,
        candidates: list[RepairCandidate],
        candidate_payloads: list[PolicyCandidatePayload],
        damage_analysis: dict[str, Any],
        current_recovery: dict[str, Any] | None = None,
        best_seen_recovery: dict[str, Any] | None = None,
        parent_recovery: dict[str, Any] | None = None,
        state_value: dict[str, Any] | None = None,
        parent_state_value: dict[str, Any] | None = None,
        candidate_state_values: dict[str, dict[str, Any]] | None = None,
        diagnosis: dict[str, Any] | None = None,
        round_index: int = 0,
    ) -> tuple[RepairActionDecision, dict[str, Any]]:
        base = {
            "enabled": self.enabled,
            "provider_package": self.provider_package,
            "fallback_to_selector": self.fallback_to_selector,
        }
        fmt = _normalize_format(job.format)
        candidate_by_id, duplicate_candidate_ids = _candidate_id_index(candidate_payloads)
        if duplicate_candidate_ids:
            return RepairActionDecision(action="give_up", reason="duplicate_candidate_id"), {
                **base,
                "decision_status": "fallback",
                "fallback_reason": "duplicate_candidate_id",
                "duplicate_candidate_id_count": len(duplicate_candidate_ids),
                "duplicate_candidate_ids": duplicate_candidate_ids,
            }
        request = RepairActionRequest(
            job=job,
            format=fmt,
            archive_state=archive_state,
            candidates=list(candidates),
            candidate_payloads=list(candidate_payloads),
            damage_analysis=dict(damage_analysis or {}),
            current_recovery=dict(current_recovery or {}),
            best_seen_recovery=dict(best_seen_recovery or {}),
            parent_recovery=dict(parent_recovery or {}),
            diagnosis=dict(diagnosis or {}),
            repair_history=dict(getattr(job, "repair_history", {}) or {}),
            config=dict(self.config),
            round_index=int(round_index or 0),
        )
        errors: list[str] = []
        for provider in self._action_models(fmt):
            provider_id = self._provider_id(provider)
            try:
                raw = provider.choose(request)
            except Exception as exc:
                if self.strict_provider_errors:
                    raise
                errors.append(f"{provider_id}: {exc}")
                continue
            priors = _coerce_action_priors(raw, provider_id=provider_id)
            if priors:
                decision, arbiter_payload = PolicyDecisionArbiter(self.policy_config.get("arbiter") if isinstance(self.policy_config.get("arbiter"), dict) else {}).decide(
                    priors=priors,
                    candidate_payloads=candidate_payloads,
                    candidate_state_values=candidate_state_values,
                    current_recovery=current_recovery,
                    state_value=state_value,
                    parent_state_value=parent_state_value,
                    parent_recovery=parent_recovery,
                )
                invalid = _invalid_action_decision_reason(decision, candidate_by_id)
                if invalid:
                    errors.append(f"{provider_id}: {invalid}")
                    continue
                selected_index = candidate_by_id.get(decision.selected_candidate_id) if decision.selected_candidate_id else None
                selected = candidates[selected_index] if selected_index is not None and selected_index < len(candidates) else None
                return decision, {
                    **base,
                    "decision_status": "selected",
                    "provider_id": provider_id,
                    "action": decision.action,
                    "confidence": decision.confidence,
                    "reason": decision.reason,
                    "selected_candidate_id": decision.selected_candidate_id,
                    "selected_candidate_id_valid": bool(decision.selected_candidate_id) if decision.action == "apply_patch" else True,
                    "selected_module": selected.module_name if selected is not None else "",
                    "selected_format": selected.format if selected is not None else fmt,
                    "candidate_count": len(candidates),
                    "action_priors": [prior.to_dict() for prior in priors],
                    "arbiter": arbiter_payload,
                    "metadata": _public_metadata(decision.metadata),
                }
            errors.append(f"{provider_id}: action_prior_list_required")
        return RepairActionDecision(action="give_up", reason="action_model_unavailable_or_invalid"), {
            **base,
            "decision_status": "fallback",
            "fallback_reason": "action_model_unavailable_or_invalid",
            "provider_errors": errors,
            "load_error": self.last_load_error,
        }

    def estimate_state_value(
        self,
        *,
        job: RepairJob,
        archive_state: ArchiveState | None,
        damage_analysis: dict[str, Any],
        candidate_summaries: list[PolicyCandidatePayload] | None = None,
        current_recovery: dict[str, Any] | None = None,
        best_seen_recovery: dict[str, Any] | None = None,
        parent_recovery: dict[str, Any] | None = None,
        diagnosis: dict[str, Any] | None = None,
        round_index: int = 0,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        fmt = _normalize_format(job.format)
        current_score = _optional_float((current_recovery or {}).get("score")) or 0.0
        base = {"enabled": self.enabled, "provider_package": self.provider_package}
        request = StateValueRequest(
            job=job,
            format=fmt,
            archive_state=archive_state,
            damage_analysis=dict(damage_analysis or {}),
            current_recovery=dict(current_recovery or {}),
            best_seen_recovery=dict(best_seen_recovery or {}),
            parent_recovery=dict(parent_recovery or {}),
            candidate_summaries=[dict(item) for item in candidate_summaries or []],
            repair_history=dict(getattr(job, "repair_history", {}) or {}),
            diagnosis=dict(diagnosis or {}),
            config=dict(self.config),
            round_index=int(round_index or 0),
        )
        errors: list[str] = []
        for provider in self._state_value_models(fmt):
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
        result = StateValueResult(
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
        if hasattr(package, "get_repair_action_models"):
            providers.extend(list(package.get_repair_action_models() or []))
        if hasattr(package, "get_state_value_models"):
            providers.extend(list(package.get_state_value_models() or []))
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

    def _action_models(self, fmt: str) -> list[Any]:
        output: list[Any] = []
        for provider in self.providers():
            if not self._provider_supports_format(provider, fmt):
                continue
            available = getattr(provider, "available", None)
            if callable(available) and not bool(available()):
                continue
            if callable(getattr(provider, "choose", None)) and callable(getattr(provider, "analyze", None)):
                output.append(provider)
        return output

    def _state_value_models(self, fmt: str) -> list[Any]:
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
            if isinstance(value.get("normal_structure_scores"), dict):
                metadata["normal_structure_scores"] = dict(value.get("normal_structure_scores") or {})
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


def _coerce_action_priors(value: Any, *, provider_id: str) -> list[RepairActionPrior]:
    if isinstance(value, dict):
        raw = value.get("action_priors")
        if raw is None:
            raw = value.get("scores")
        if isinstance(raw, list):
            return [_coerce_action_prior(item, provider_id=provider_id) for item in raw if isinstance(item, dict)]
    if isinstance(value, list):
        return [_coerce_action_prior(item, provider_id=provider_id) for item in value if isinstance(item, dict)]
    return []


def _coerce_action_prior(value: dict[str, Any], *, provider_id: str) -> RepairActionPrior:
    action = str(value.get("action") or value.get("action_type") or "apply_patch")
    if action not in {"apply_patch", "undo_patch", "stop", "give_up"}:
        action = "give_up"
    return RepairActionPrior(
        action=action,  # type: ignore[arg-type]
        candidate_id=str(value.get("candidate_id") or value.get("selected_candidate_id") or ""),
        prior_score=float(_optional_float(value.get("prior_score", value.get("score", value.get("confidence", 0.0)))) or 0.0),
        confidence=_optional_float(value.get("confidence")),
        provider_id=str(value.get("provider_id") or provider_id),
        reason=str(value.get("reason") or ""),
        metadata=dict(value.get("metadata") or {}),
    )


def _coerce_state_value(value: StateValueResult | dict[str, Any] | float | int | None, *, provider_id: str, fallback: float) -> StateValueResult:
    if isinstance(value, StateValueResult):
        if value.provider_id:
            return value
        return StateValueResult(**{**value.to_dict(), "provider_id": provider_id})
    if isinstance(value, (float, int)):
        return StateValueResult(reachable_recovery_value=_clamp01(float(value)), provider_id=provider_id)
    if isinstance(value, dict):
        parsed = _optional_float(value.get("reachable_recovery_value", value.get("value", value.get("score", fallback))))
        return StateValueResult(
            reachable_recovery_value=_clamp01(parsed if parsed is not None else fallback),
            confidence=_optional_float(value.get("confidence")),
            provider_id=str(value.get("provider_id") or provider_id),
            metadata=dict(value.get("metadata") or {}),
        )
    return StateValueResult(
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


def _invalid_action_decision_reason(decision: RepairActionDecision, candidate_by_id: dict[str, int]) -> str:
    if decision.action not in {"apply_patch", "undo_patch", "stop", "give_up"}:
        return "invalid_action"
    if decision.action == "apply_patch":
        if not decision.selected_candidate_id:
            return "invalid_action_missing_candidate_id"
        if str(decision.selected_candidate_id) not in candidate_by_id:
            return "invalid_action_candidate_id"
    return ""


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
