from __future__ import annotations

import importlib
from typing import Any

from sunpack.contracts.archive_state import ArchiveState
from sunpack.repair.job import RepairJob
from sunpack.repair.policy.types import (
    DiagnosisHGTRequest,
    DiagnosisHGTResult,
    PolicyExplorationGraph,
    PolicyGraphAction,
    PolicyGraphActionRequest,
)


class RepairPolicyManager:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.policy_config = self.config.get("policy") if isinstance(self.config.get("policy"), dict) else {}
        self.enabled = bool(self.policy_config.get("enabled", True))
        self.strict_provider_errors = bool(self.policy_config.get("strict_provider_errors", False))
        self.provider_package = str(self.policy_config.get("provider_package") or "sunpack_repair_models")
        self._providers: list[Any] | None = None
        self.last_load_error: str = ""

    def dual_model_active_for_job(self, job: RepairJob) -> bool:
        if not self.enabled:
            return False
        fmt = _normalize_format(job.format)
        return bool(fmt and self._diagnosis_hgt_models(fmt) and self._policy_graph_scorers(fmt))

    def active_for_job(self, job: RepairJob) -> bool:
        return self.dual_model_active_for_job(job)

    def status_for_job(self, job: RepairJob) -> dict[str, Any]:
        base = {"enabled": self.enabled, "provider_package": self.provider_package}
        if not self.enabled:
            return {**base, "decision_status": "disabled", "fallback_reason": "policy_disabled"}
        fmt = _normalize_format(job.format)
        providers = self.providers()
        if not providers:
            return {**base, "decision_status": "unavailable", "fallback_reason": "policy_unavailable", "load_error": self.last_load_error}
        if not any(self._provider_supports_format(provider, fmt) for provider in providers):
            return {**base, "decision_status": "unavailable", "fallback_reason": "unsupported_format"}
        if not self._diagnosis_hgt_models(fmt):
            return {**base, "decision_status": "unavailable", "fallback_reason": "diagnosis_hgt_unavailable"}
        if not self._policy_graph_scorers(fmt):
            return {**base, "decision_status": "unavailable", "fallback_reason": "policy_transformer_unavailable"}
        return {**base, "decision_status": "available"}

    def diagnose_state(
        self,
        *,
        job: RepairJob,
        archive_state: ArchiveState | None,
        graph: PolicyExplorationGraph,
        recovery: dict[str, Any] | None = None,
        round_index: int = 0,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        base = {"enabled": self.enabled, "provider_package": self.provider_package}
        fmt = _normalize_format(job.format)
        request = DiagnosisHGTRequest(
            job=job,
            format=fmt,
            archive_state=archive_state,
            knowledge_payload=dict(getattr(job, "knowledge", {}) or {}),
            graph=graph.to_dict(),
            current_node_id=graph.current_node_id,
            recovery=dict(recovery or {}),
            config=dict(self.config),
            round_index=int(round_index or 0),
        )
        errors: list[str] = []
        for provider in self._diagnosis_hgt_models(fmt):
            provider_id = self._provider_id(provider)
            try:
                result = _coerce_diagnosis_hgt(provider.diagnose_state(request), provider_id=provider_id, fmt=fmt)
            except Exception as exc:
                if self.strict_provider_errors:
                    raise
                errors.append(f"{provider_id}: {exc}")
                continue
            return result.to_dict(), {**base, "decision_status": "diagnosed", "provider_id": provider_id, "provider_errors": errors}
        return {}, {**base, "decision_status": "unavailable", "fallback_reason": "diagnosis_hgt_unavailable", "provider_errors": errors, "load_error": self.last_load_error}

    def score_graph_actions(
        self,
        *,
        job: RepairJob,
        archive_state: ArchiveState | None,
        graph: PolicyExplorationGraph,
        available_actions: list[dict[str, Any]],
        diagnosis_hgt: dict[str, Any],
        current_recovery: dict[str, Any] | None = None,
        best_seen_recovery: dict[str, Any] | None = None,
        round_index: int = 0,
    ) -> tuple[list[PolicyGraphAction], dict[str, Any]]:
        base = {"enabled": self.enabled, "provider_package": self.provider_package}
        fmt = _normalize_format(job.format)
        request = PolicyGraphActionRequest(
            job=job,
            format=fmt,
            graph=graph.to_dict(),
            current_node_id=graph.current_node_id,
            best_node_id=graph.best_node_id,
            archive_state=archive_state,
            available_actions=[dict(item) for item in available_actions],
            diagnosis_hgt=dict(diagnosis_hgt or {}),
            current_recovery=dict(current_recovery or {}),
            best_seen_recovery=dict(best_seen_recovery or {}),
            graph_summary=graph.summary(),
            config=dict(self.config),
            round_index=int(round_index or 0),
        )
        errors: list[str] = []
        for provider in self._policy_graph_scorers(fmt):
            provider_id = self._provider_id(provider)
            try:
                raw = provider.score_actions(request)
            except Exception as exc:
                if self.strict_provider_errors:
                    raise
                errors.append(f"{provider_id}: {exc}")
                continue
            if not _has_action_predictions(raw):
                errors.append(f"{provider_id}: policy_prediction_unavailable")
                continue
            scores = _coerce_policy_graph_actions(raw, provider_id=provider_id)
            valid = _valid_policy_graph_actions(scores, available_actions)
            if valid:
                return valid, {
                    **base,
                    "decision_status": "scored",
                    "provider_id": provider_id,
                    "action_scores": [score.to_dict() for score in valid],
                    "raw_action_scores": [score.to_dict() for score in scores],
                    "provider_errors": errors,
                }
            errors.append(f"{provider_id}: policy_action_scores_invalid")
        return [], {**base, "decision_status": "unavailable", "fallback_reason": "policy_graph_scorer_unavailable_or_invalid", "provider_errors": errors, "load_error": self.last_load_error}

    def providers(self) -> list[Any]:
        if self._providers is not None:
            return self._providers
        self._providers = []
        if not self.enabled:
            return self._providers
        try:
            package = importlib.import_module(self.provider_package)
        except Exception as exc:
            self.last_load_error = str(exc)
            return self._providers
        for getter in ("get_diagnosis_hgt_models", "get_policy_graph_scorers"):
            func = getattr(package, getter, None)
            if callable(func):
                self._providers.extend([provider for provider in list(func() or []) if provider is not None])
        return self._providers

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

    def _diagnosis_hgt_models(self, fmt: str) -> list[Any]:
        return [
            provider
            for provider in self.providers()
            if self._provider_supports_format(provider, fmt)
            and _provider_available(provider)
            and callable(getattr(provider, "diagnose_state", None))
        ]

    def _policy_graph_scorers(self, fmt: str) -> list[Any]:
        return [
            provider
            for provider in self.providers()
            if self._provider_supports_format(provider, fmt)
            and _provider_available(provider)
            and callable(getattr(provider, "score_actions", None))
        ]


def _coerce_diagnosis_hgt(value: DiagnosisHGTResult | dict[str, Any] | None, *, provider_id: str, fmt: str) -> DiagnosisHGTResult:
    if isinstance(value, DiagnosisHGTResult):
        return value
    if not isinstance(value, dict):
        return DiagnosisHGTResult(format=fmt, diagnostics={"provider_id": provider_id, "decision_reason": "empty_diagnosis_hgt"})
    root = value.get("root_case") if isinstance(value.get("root_case"), dict) else {}
    scores = root.get("scores") if isinstance(root.get("scores"), dict) else value.get("root_case_scores")
    scores = scores if isinstance(scores, dict) else {}
    ranked = root.get("ranked") if isinstance(root.get("ranked"), list) else value.get("ranked_root_cases")
    selected = root.get("selected") if isinstance(root.get("selected"), list) else value.get("selected_root_cases")
    return DiagnosisHGTResult(
        format=str(value.get("format") or fmt),
        root_case_scores={str(key): float(_optional_float(score) or 0.0) for key, score in scores.items()},
        selected_root_cases=[str(item) for item in selected or [] if str(item)],
        ranked_root_cases=[dict(item) for item in ranked or [] if isinstance(item, dict)],
        diagnostics={**dict(value.get("diagnostics") or {}), "provider_id": provider_id},
    )


def _coerce_policy_graph_actions(value: Any, *, provider_id: str) -> list[PolicyGraphAction]:
    raw = value.get("action_scores") if isinstance(value, dict) else value
    if not isinstance(raw, list):
        return []
    predictions = value.get("action_predictions") if isinstance(value, dict) and isinstance(value.get("action_predictions"), dict) else {}
    output: list[PolicyGraphAction] = []
    for item in raw:
        if isinstance(item, PolicyGraphAction):
            output.append(item)
            continue
        if not isinstance(item, dict):
            continue
        action = str(item.get("action_type") or item.get("action") or "module")
        if action not in {"module", "undo", "stop"}:
            continue
        action_id = str(item.get("action_id") or item.get("candidate_id") or "")
        module_name = str(item.get("module_name") or item.get("module") or "")
        metadata = dict(item.get("metadata") or {})
        prediction = metadata.get("predicted_next_state")
        if prediction is None:
            prediction = predictions.get(action_id) or predictions.get(f"module:{module_name}") or predictions.get(module_name)
        if isinstance(prediction, dict):
            metadata["predicted_next_state"] = prediction
        output.append(PolicyGraphAction(
            action_type=action,  # type: ignore[arg-type]
            module_name=module_name,
            action_id=action_id,
            score=float(_optional_float(item.get("score", item.get("logic_score", 0.0))) or 0.0),
            confidence=_optional_float(item.get("confidence")),
            reason=str(item.get("reason") or ""),
            metadata={**metadata, "provider_id": provider_id},
        ))
    return output


def _has_action_predictions(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    predictions = value.get("action_predictions")
    if isinstance(predictions, dict) and predictions:
        return True
    for item in value.get("action_scores") or []:
        if isinstance(item, dict):
            metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            if isinstance(metadata.get("predicted_next_state"), dict):
                return True
    return False


def _valid_policy_graph_actions(scores: list[PolicyGraphAction], available_actions: list[dict[str, Any]]) -> list[PolicyGraphAction]:
    module_ids = {str(item.get("action_id") or item.get("candidate_id") or "") for item in available_actions if str(item.get("action_type") or "") == "module"}
    module_names = {str(item.get("module_name") or item.get("module") or "") for item in available_actions if str(item.get("action_type") or "") == "module"}
    valid: list[PolicyGraphAction] = []
    for score in scores:
        if score.action_type == "module" and score.action_id not in module_ids and score.module_name not in module_names:
            continue
        valid.append(score)
    return valid


def _provider_available(provider: Any) -> bool:
    available = getattr(provider, "available", None)
    return not callable(available) or bool(available())


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
