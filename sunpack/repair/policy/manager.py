from __future__ import annotations

import importlib
from dataclasses import asdict
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
    RepairActionRequest,
    RepairPolicyDecision,
    RepairPolicyRequest,
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
        return bool(fmt and self._damage_models(fmt) and self._action_models(fmt))

    def active_for_job(self, job: RepairJob) -> bool:
        if not self.enabled:
            return False
        fmt = _normalize_format(job.format)
        if not fmt:
            return False
        for provider in self.providers():
            available = getattr(provider, "available", None)
            if callable(available) and not bool(available()):
                continue
            if self._provider_supports_format(provider, fmt):
                return True
        return False

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
                decision = _coerce_action_decision(provider.choose(request), provider_id=provider_id)
            except Exception as exc:
                if self.strict_provider_errors:
                    raise
                errors.append(f"{provider_id}: {exc}")
                continue
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
                "metadata": _public_metadata(decision.metadata),
            }
        return RepairActionDecision(action="give_up", reason="action_model_unavailable_or_invalid"), {
            **base,
            "decision_status": "fallback",
            "fallback_reason": "action_model_unavailable_or_invalid",
            "provider_errors": errors,
            "load_error": self.last_load_error,
        }

    def choose(
        self,
        *,
        job: RepairJob,
        candidates: list[RepairCandidate],
        candidate_payloads: list[PolicyCandidatePayload],
        diagnosis: dict[str, Any] | None = None,
    ) -> tuple[RepairCandidate | None, dict[str, Any]]:
        base = {
            "enabled": self.enabled,
            "provider_package": self.provider_package,
            "fallback_to_selector": self.fallback_to_selector,
        }
        if not self.enabled:
            return None, {**base, "decision_status": "disabled", "fallback_reason": "policy_disabled"}
        if not candidates:
            return None, {**base, "decision_status": "no_candidates", "fallback_reason": "no_candidates"}
        request = RepairPolicyRequest(
            job=job,
            format=_normalize_format(job.format),
            candidates=list(candidates),
            candidate_payloads=list(candidate_payloads),
            diagnosis=dict(diagnosis or {}),
            config=dict(self.config),
        )
        providers = [provider for provider in self.providers() if self._provider_can_handle(provider, request)]
        if not providers:
            reason = "policy_unavailable" if not self.providers() else "unsupported_format"
            return None, {
                **base,
                "decision_status": "unavailable",
                "fallback_reason": reason,
                "load_error": self.last_load_error,
            }

        candidate_by_id, duplicate_candidate_ids = _candidate_id_index(candidate_payloads)
        if duplicate_candidate_ids:
            return None, {
                **base,
                "decision_status": "fallback",
                "fallback_reason": "duplicate_candidate_id",
                "duplicate_candidate_id_count": len(duplicate_candidate_ids),
                "duplicate_candidate_ids": duplicate_candidate_ids,
            }
        errors: list[str] = []
        for provider in providers:
            provider_id = self._provider_id(provider)
            try:
                decision = _coerce_decision(provider.choose(request), provider_id=provider_id)
            except Exception as exc:
                if self.strict_provider_errors:
                    raise
                errors.append(f"{provider_id}: {exc}")
                continue
            selected_candidate_index = self._selected_candidate_index(decision, candidate_by_id)
            if selected_candidate_index is None:
                errors.append(f"{provider_id}: {_invalid_decision_reason(decision, candidate_by_id)}")
                continue
            selected = candidates[selected_candidate_index]
            selected_payload = (
                candidate_payloads[selected_candidate_index]
                if selected_candidate_index < len(candidate_payloads)
                else {}
            )
            selected_candidate_id = str(selected_payload.get("candidate_id") or "")
            return selected, {
                **base,
                "decision_status": "selected",
                "provider_id": provider_id,
                "confidence": decision.confidence,
                "reason": decision.reason,
                "selected_candidate_id": selected_candidate_id,
                "selected_candidate_id_valid": bool(selected_candidate_id),
                "selected_module": selected.module_name,
                "selected_format": selected.format,
                "candidate_count": len(candidates),
                "duplicate_candidate_id_count": 0,
                "candidates": list(candidate_payloads),
                "metadata": _public_metadata(decision.metadata),
            }
        return None, {
            **base,
            "decision_status": "fallback",
            "fallback_reason": "provider_error_or_invalid_decision",
            "provider_errors": errors,
            "invalid_candidate_id_reason": _first_invalid_reason(errors),
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
        if hasattr(package, "get_repair_policy_providers"):
            loaded = package.get_repair_policy_providers()
            providers.extend(list(loaded or []))
        if hasattr(package, "get_damage_analysis_models"):
            providers.extend(list(package.get_damage_analysis_models() or []))
        if hasattr(package, "get_repair_action_models"):
            providers.extend(list(package.get_repair_action_models() or []))
        if hasattr(package, "register_repair_policies"):
            self._providers = []
            package.register_repair_policies(self)
            providers.extend(self._providers)
        if hasattr(package, "PROVIDERS"):
            providers.extend(list(getattr(package, "PROVIDERS") or []))
        return [provider for provider in providers if provider is not None]

    def register(self, provider: Any) -> None:
        if self._providers is None:
            self._providers = []
        self._providers.append(provider)

    def _provider_can_handle(self, provider: Any, request: RepairPolicyRequest) -> bool:
        if callable(getattr(provider, "analyze", None)):
            return False
        if not self._provider_supports_format(provider, request.format):
            return False
        available = getattr(provider, "available", None)
        if callable(available) and not bool(available()):
            return False
        can_handle = getattr(provider, "can_handle", None)
        if callable(can_handle):
            return bool(can_handle(request))
        return True

    @staticmethod
    def _provider_supports_format(provider: Any, fmt: str) -> bool:
        supported = getattr(provider, "supported_formats", ())
        values = {_normalize_format(item) for item in supported or []}
        return "*" in values or fmt in values

    @staticmethod
    def _provider_id(provider: Any) -> str:
        return str(getattr(provider, "provider_id", "") or provider.__class__.__name__ or "repair_policy")

    @staticmethod
    def _selected_candidate_index(decision: RepairPolicyDecision, candidate_by_id: dict[str, int]) -> int | None:
        if not decision.selected_candidate_id:
            return None
        return candidate_by_id.get(str(decision.selected_candidate_id))

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


def _coerce_decision(value: RepairPolicyDecision | dict[str, Any] | str | None, *, provider_id: str) -> RepairPolicyDecision:
    if isinstance(value, RepairPolicyDecision):
        if value.provider_id:
            return value
        return RepairPolicyDecision(**{**asdict(value), "provider_id": provider_id})
    if isinstance(value, str):
        return RepairPolicyDecision(selected_candidate_id=value, provider_id=provider_id)
    if isinstance(value, dict):
        return RepairPolicyDecision(
            selected_candidate_id=str(value.get("selected_candidate_id") or value.get("candidate_id") or ""),
            confidence=_optional_float(value.get("confidence")),
            provider_id=str(value.get("provider_id") or provider_id),
            reason=str(value.get("reason") or ""),
            metadata=dict(value.get("metadata") or {}),
        )
    return RepairPolicyDecision(provider_id=provider_id)


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
                value.get("thresholds") if isinstance(value.get("thresholds"), dict) else None,
                metadata=metadata,
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


def _coerce_action_decision(value: RepairActionDecision | dict[str, Any] | str | None, *, provider_id: str) -> RepairActionDecision:
    if isinstance(value, RepairActionDecision):
        if value.provider_id:
            return value
        return RepairActionDecision(**{**asdict(value), "provider_id": provider_id})
    if isinstance(value, str):
        action, _, candidate = value.partition(":")
        if action in {"apply_patch", "undo_patch", "stop", "give_up"}:
            return RepairActionDecision(action=action, selected_candidate_id=candidate, provider_id=provider_id)
        return RepairActionDecision(action="apply_patch", selected_candidate_id=value, provider_id=provider_id)
    if isinstance(value, dict):
        action = str(value.get("action") or value.get("action_type") or "apply_patch")
        if action not in {"apply_patch", "undo_patch", "stop", "give_up"}:
            action = "give_up"
        return RepairActionDecision(
            action=action,  # type: ignore[arg-type]
            selected_candidate_id=str(value.get("selected_candidate_id") or value.get("candidate_id") or ""),
            confidence=_optional_float(value.get("confidence")),
            provider_id=str(value.get("provider_id") or provider_id),
            reason=str(value.get("reason") or ""),
            metadata=dict(value.get("metadata") or {}),
        )
    return RepairActionDecision(provider_id=provider_id)


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


def _invalid_decision_reason(decision: RepairPolicyDecision, candidate_by_id: dict[str, int]) -> str:
    if decision.reason.startswith("abstain:"):
        return decision.reason
    if not decision.selected_candidate_id:
        return "invalid_policy_decision_missing_candidate_id"
    return "invalid_candidate_id" if str(decision.selected_candidate_id) not in candidate_by_id else "invalid_policy_decision"


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


def _normalize_format(value: Any) -> str:
    text = str(value or "").lower().lstrip(".")
    return {"gz": "gzip", "bz2": "bzip2", "seven_zip": "7z"}.get(text, text)


def _public_metadata(value: dict[str, Any]) -> dict[str, Any]:
    allowed = {"model_id", "model_version", "format", "decision_reason", "provider_id"}
    return {key: value[key] for key in allowed if key in value}
