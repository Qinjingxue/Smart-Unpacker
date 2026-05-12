from __future__ import annotations

import importlib
from dataclasses import asdict
from typing import Any

from sunpack.repair.candidate import RepairCandidate
from sunpack.repair.job import RepairJob
from sunpack.repair.policy.types import PolicyCandidatePayload, RepairPolicyDecision, RepairPolicyRequest


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
            contract_miss = _provider_contract_miss(provider, candidate_payloads)
            if contract_miss:
                errors.append(f"{provider_id}: feature_contract_miss:{','.join(contract_miss)}")
                continue
            try:
                decision = _coerce_decision(provider.choose(request), provider_id=provider_id)
            except Exception as exc:
                if self.strict_provider_errors:
                    raise
                errors.append(f"{provider_id}: {exc}")
                continue
            selected_index = self._selected_index(decision, candidate_by_id)
            if selected_index is None:
                errors.append(f"{provider_id}: {_invalid_decision_reason(decision, candidate_by_id)}")
                continue
            selected = candidates[selected_index]
            selected_payload = candidate_payloads[selected_index] if selected_index < len(candidate_payloads) else {}
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
        elif hasattr(package, "register_repair_policies"):
            self._providers = []
            package.register_repair_policies(self)
            providers.extend(self._providers)
        elif hasattr(package, "PROVIDERS"):
            providers.extend(list(getattr(package, "PROVIDERS") or []))
        return [provider for provider in providers if provider is not None]

    def register(self, provider: Any) -> None:
        if self._providers is None:
            self._providers = []
        self._providers.append(provider)

    def _provider_can_handle(self, provider: Any, request: RepairPolicyRequest) -> bool:
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
    def _selected_index(decision: RepairPolicyDecision, candidate_by_id: dict[str, int]) -> int | None:
        if not decision.selected_candidate_id:
            return None
        return candidate_by_id.get(str(decision.selected_candidate_id))


def _coerce_decision(value: RepairPolicyDecision | dict[str, Any] | str | int | None, *, provider_id: str) -> RepairPolicyDecision:
    if isinstance(value, RepairPolicyDecision):
        if value.provider_id:
            return value
        return RepairPolicyDecision(**{**asdict(value), "provider_id": provider_id})
    if isinstance(value, int):
        return RepairPolicyDecision(selected_index=value, provider_id=provider_id)
    if isinstance(value, str):
        return RepairPolicyDecision(selected_candidate_id=value, provider_id=provider_id)
    if isinstance(value, dict):
        return RepairPolicyDecision(
            selected_candidate_id=str(value.get("selected_candidate_id") or value.get("candidate_id") or ""),
            selected_index=value.get("selected_index"),
            confidence=_optional_float(value.get("confidence")),
            provider_id=str(value.get("provider_id") or provider_id),
            reason=str(value.get("reason") or ""),
            metadata=dict(value.get("metadata") or {}),
        )
    return RepairPolicyDecision(provider_id=provider_id)


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
        if decision.selected_index is not None:
            return "invalid_policy_decision_legacy_selected_index"
        return "invalid_policy_decision_missing_candidate_id"
    return "invalid_candidate_id" if str(decision.selected_candidate_id) not in candidate_by_id else "invalid_policy_decision"


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
    allowed = {"model_id", "model_version", "feature_contract_version", "decision_reason"}
    return {key: value[key] for key in allowed if key in value}


def _provider_contract_miss(provider: Any, candidate_payloads: list[PolicyCandidatePayload]) -> list[str]:
    misses: list[str] = []
    expected_version = getattr(provider, "supported_feature_contract_version", None)
    if expected_version is not None:
        for payload in candidate_payloads:
            if isinstance(payload, dict) and payload.get("feature_contract_version") != expected_version:
                misses.append("feature_contract_version")
                break
    required = getattr(provider, "required_payload_sections", None)
    if required:
        for section in required:
            name = str(section)
            if not name:
                continue
            if not all(isinstance(payload, dict) and _has_payload_path(payload, name) for payload in candidate_payloads):
                misses.append(name)
    return sorted(set(misses))


def _has_payload_path(payload: dict[str, Any], path: str) -> bool:
    current: Any = payload
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False
        current = current.get(part)
    return True
