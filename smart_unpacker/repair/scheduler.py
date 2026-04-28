from dataclasses import replace
from pathlib import Path
from typing import Any

from smart_unpacker.repair.candidate import CandidateSelector, CandidateValidation, RepairCandidate, RepairCandidateBatch
from smart_unpacker.repair.capability import ModuleCapabilityDecision, RepairCapabilityDecision
from smart_unpacker.repair.config import enabled_module_configs, repair_config
from smart_unpacker.repair.context import RepairContext, build_repair_context
from smart_unpacker.repair.diagnosis import RepairDiagnosis, diagnose_repair_job
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairRoute
from smart_unpacker.repair.pipeline.modules._common import job_source_size
from smart_unpacker.repair.pipeline.registry import discover_repair_modules, get_repair_module_registry
from smart_unpacker.repair.result import RepairResult


class RepairScheduler:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = repair_config(config or {})
        discover_repair_modules()

    def diagnose(self, job: RepairJob) -> RepairDiagnosis:
        return diagnose_repair_job(job)

    def repair(self, job: RepairJob) -> RepairResult:
        batch = self.generate_repair_candidates(job)
        if batch.terminal_result is not None:
            return batch.terminal_result
        selector = CandidateSelector(self.config)
        warnings = list(batch.warnings)
        if batch.candidates:
            selected, selection = selector.select(_with_job_password_candidates(batch.candidates, job))
            if selected is not None:
                return selected.to_result(selection=selection)
            warnings.extend(selection.get("warnings") or [])
            warnings.append("repair candidates were produced but none passed selection")
        diagnosis = batch.diagnosis
        return RepairResult(
            status="unrepairable",
            confidence=float(diagnosis.get("confidence", 0.0) or 0.0),
            format=str(diagnosis.get("format") or job.format),
            warnings=_dedupe(warnings),
            diagnosis=diagnosis,
            message=batch.message or "registered repair modules did not produce a candidate",
        )

    def generate_repair_candidates(self, job: RepairJob, *, lazy: bool = False) -> RepairCandidateBatch:
        diagnosis = self.diagnose(job)
        context = build_repair_context(job, diagnosis)
        if not self.config.get("enabled", True):
            return RepairCandidateBatch(
                terminal_result=self._result("skipped", job, diagnosis, "repair layer is disabled"),
                diagnosis=diagnosis.as_dict(),
                message="repair layer is disabled",
            )
        if not diagnosis.repairable:
            message = "; ".join(diagnosis.notes) or "repair is blocked"
            return RepairCandidateBatch(
                terminal_result=self._result("unrepairable", job, diagnosis, message),
                diagnosis=diagnosis.as_dict(),
                message=message,
            )

        modules, capability = self._select_modules(job, diagnosis, context)
        if not modules:
            status = "unrepairable" if capability.automatic_unrepairable else "unsupported"
            result = self._result(status, job, diagnosis, capability.message(), capability)
            return RepairCandidateBatch(
                terminal_result=result,
                diagnosis=result.diagnosis,
                message=result.message,
            )

        workspace = self._workspace_for(job)
        workspace.mkdir(parents=True, exist_ok=True)
        module_configs = enabled_module_configs(self.config)
        warnings = []
        repair_candidates: list[RepairCandidate] = []
        for score, module, route_score in modules:
            module_config = self._module_runtime_config(module.spec.name, module_configs)
            if lazy:
                repair_candidates.append(_lazy_module_candidate(
                    module,
                    job,
                    diagnosis,
                    str(workspace),
                    module_config,
                    score_hint=max(score, route_score),
                ))
                continue
            try:
                if hasattr(module, "generate_candidates"):
                    generated = module.generate_candidates(  # type: ignore[attr-defined]
                        job,
                        diagnosis,
                        str(workspace),
                        module_config,
                    )
                    if not generated:
                        capability = _record_module_feedback(
                            capability,
                            module.spec.name,
                            "no_candidates",
                            execution_status="no_candidates",
                            execution_message="module produced no repair candidates",
                        )
                        warnings.append(f"{module.spec.name}: produced no repair candidates")
                        continue
                    for candidate in generated:
                        candidate = _with_job_password_candidate(candidate, job)
                        repair_candidates.append(replace(
                            candidate,
                            score_hint=max(score, route_score, candidate.score_hint),
                            stage=candidate.stage or module.spec.stage,
                        ))
                    continue

                result = module.repair(job, diagnosis, str(workspace), module_config)
            except Exception as exc:
                capability = _record_module_feedback(
                    capability,
                    module.spec.name,
                    "module_exception",
                    execution_status="exception",
                    execution_message=str(exc),
                )
                warnings.append(f"{module.spec.name}: {exc}")
                continue
            if result.ok:
                candidate = RepairCandidate.from_result(
                    _with_job_password_result(result, job),
                    score_hint=max(score, route_score),
                    stage=module.spec.stage,
                )
                if candidate is not None:
                    repair_candidates.append(candidate)
                continue
            capability = _record_module_feedback(
                capability,
                module.spec.name,
                f"module_returned_{result.status}",
                execution_status=result.status,
                execution_message=result.message,
                execution_warnings=result.warnings,
            )
            warnings.extend(result.warnings)
        repair_candidates = [
            replace(candidate, diagnosis=_with_capability_diagnosis(candidate.diagnosis, capability))
            for candidate in repair_candidates
        ]
        return RepairCandidateBatch(
            candidates=repair_candidates,
            warnings=_dedupe(warnings),
            diagnosis=_with_capability_diagnosis(diagnosis.as_dict(), capability),
            message="registered repair modules did not produce a candidate",
        )

    def _select_modules(self, job: RepairJob, diagnosis: RepairDiagnosis, context: RepairContext):
        enabled = enabled_module_configs(self.config)
        registry = get_repair_module_registry()
        candidates = []
        decisions: list[ModuleCapabilityDecision] = []
        for name, module in registry.all().items():
            if name not in enabled:
                continue
            reasons: list[str] = []
            declarative_reasons: list[str] = []
            policy_reasons: list[str] = []
            dynamic_reasons: list[str] = []
            format_supported = _format_matches(diagnosis.format, module.spec.formats)
            route_score = self._route_score(module.spec.routes, context)
            route_reasons = self._route_reasons(module.spec.routes, context) if route_score <= 0 else []
            if route_score <= 0 and route_reasons:
                declarative_reasons.extend(route_reasons)
            if route_score <= 0 and not format_supported:
                reasons.append("format_not_supported")
                decisions.append(_module_decision(module, format_supported, reasons, declarative_reasons, policy_reasons, dynamic_reasons, route_score=route_score))
                continue
            if route_score <= 0 and module.spec.categories and not (set(module.spec.categories) & set(diagnosis.categories)):
                reasons.append("category_mismatch")
                declarative_reasons.append("category_mismatch")
                decisions.append(_module_decision(module, format_supported, reasons, declarative_reasons, policy_reasons, dynamic_reasons, route_score=route_score))
                continue
            stages = self.config.get("stages", {}) if isinstance(self.config.get("stages"), dict) else {}
            if not stages.get(module.spec.stage, True):
                reasons.append("stage_disabled")
                policy_reasons.append("stage_disabled")
                decisions.append(_module_decision(module, format_supported, reasons, declarative_reasons, policy_reasons, dynamic_reasons, route_score=route_score))
                continue
            module_config = self._module_runtime_config(name, enabled)
            safety_reasons = self._safety_reasons(module, module_config)
            if safety_reasons:
                reasons.extend(safety_reasons)
                policy_reasons.extend(safety_reasons)
                decisions.append(_module_decision(module, format_supported, reasons, declarative_reasons, policy_reasons, dynamic_reasons, route_score=route_score))
                continue
            if module.spec.stage == "deep" and not self._deep_input_allowed(job, module_config):
                reasons.append("deep_input_size_blocked")
                policy_reasons.append("deep_input_size_blocked")
                decisions.append(_module_decision(module, format_supported, reasons, declarative_reasons, policy_reasons, dynamic_reasons, route_score=route_score))
                continue
            fine_score = float(module.can_handle(job, diagnosis, module_config) or 0.0)
            score = max(fine_score, route_score)
            if score <= 0:
                if declarative_reasons:
                    reasons.extend(declarative_reasons)
                else:
                    reasons.append("can_handle_rejected")
                    dynamic_reasons.append("can_handle_rejected")
                decisions.append(_module_decision(
                    module,
                    format_supported,
                    reasons,
                    declarative_reasons,
                    policy_reasons,
                    dynamic_reasons,
                    route_score=route_score,
                    fine_score=fine_score,
                ))
                continue
            decisions.append(_module_decision(
                module,
                format_supported,
                ["selected"],
                declarative_reasons=[],
                policy_reasons=[],
                dynamic_reasons=[],
                selected=True,
                score=score,
                route_score=route_score,
                fine_score=fine_score,
            ))
            candidates.append((score, module, route_score))
        candidates.sort(key=lambda item: self._module_sort_key(item[0], item[1], item[2]))
        limit = max(1, int(self.config.get("max_modules_per_job", 4) or 4))
        selected_names = {module.spec.name for _, module, _ in candidates[:limit]}
        if selected_names:
            decisions = [
                replace(
                    item,
                    selected=item.name in selected_names,
                    reasons=["selected"] if item.name in selected_names else ["module_limit"],
                    policy_reasons=[] if item.name in selected_names else ["module_limit"],
                )
                if item.selected
                else item
                for item in decisions
            ]
        decision = RepairCapabilityDecision(
            format=context.format,
            categories=tuple(context.categories),
            damage_flags=tuple(context.damage_flags),
            failure_stage=context.failure_stage,
            failure_kind=context.failure_kind,
            modules=decisions,
        )
        return candidates[:limit], decision

    def _module_sort_key(self, score: float, module, route_score: float) -> tuple:
        return (
            -float(score or 0.0),
            -float(route_score or 0.0),
            -_route_specificity(module.spec.routes),
            -_stage_rank(module.spec.stage),
            0 if module.spec.safe else 1,
            1 if module.spec.lossy else 0,
            1 if module.spec.partial else 0,
            module.spec.name,
        )

    def _route_score(self, routes: tuple[RepairRoute, ...], context: RepairContext) -> float:
        best = 0.0
        for route in routes:
            score = self._single_route_score(route, context)
            if score > best:
                best = score
        return best

    def _single_route_score(self, route: RepairRoute, context: RepairContext) -> float:
        if route.formats and not _format_matches(context.format, route.formats):
            return 0.0
        if _intersects(route.reject_any_flags, context.damage_flags):
            return 0.0
        if context.failure_stage and _intersects(route.reject_any_failure_stages, (context.failure_stage,)):
            return 0.0
        if context.failure_kind and _intersects(route.reject_any_failure_kinds, (context.failure_kind,)):
            return 0.0

        score = float(route.base_score or 0.0)
        requirements = [
            (route.require_any_categories, context.categories, 0.08),
            (route.require_any_flags, context.damage_flags, 0.12),
            (route.require_any_fuzzy_hints, context.fuzzy_hints, 0.08),
            (route.require_any_failure_stages, (context.failure_stage,), 0.1),
            (route.require_any_failure_kinds, (context.failure_kind,), 0.14),
        ]
        active_requirements = [item for item in requirements if item[0]]
        if not active_requirements:
            return max(0.0, min(score, 1.0))
        matched = False
        for expected, actual, bonus in active_requirements:
            if _intersects(expected, actual):
                matched = True
                score += bonus
        if not matched:
            return 0.0
        return max(0.0, min(score, 1.0))

    def _route_reasons(self, routes: tuple[RepairRoute, ...], context: RepairContext) -> list[str]:
        if not routes:
            return []
        reasons: list[str] = []
        for route in routes:
            if route.formats and not _format_matches(context.format, route.formats):
                continue
            if _intersects(route.reject_any_flags, context.damage_flags):
                reasons.append("route_rejected_flags")
                continue
            if context.failure_stage and _intersects(route.reject_any_failure_stages, (context.failure_stage,)):
                reasons.append("route_rejected_failure_stage")
                continue
            if context.failure_kind and _intersects(route.reject_any_failure_kinds, (context.failure_kind,)):
                reasons.append("route_rejected_failure_kind")
                continue
            requirements = [
                (route.require_any_categories, context.categories),
                (route.require_any_flags, context.damage_flags),
                (route.require_any_fuzzy_hints, context.fuzzy_hints),
                (route.require_any_failure_stages, (context.failure_stage,)),
                (route.require_any_failure_kinds, (context.failure_kind,)),
            ]
            active_requirements = [item for item in requirements if item[0]]
            if active_requirements and not any(_intersects(expected, actual) for expected, actual in active_requirements):
                reasons.append("route_requirements_unmet")
        return _dedupe(reasons)

    def _safety_allows(self, module, module_config: dict[str, Any]) -> bool:
        return not self._safety_reasons(module, module_config)

    def _safety_reasons(self, module, module_config: dict[str, Any]) -> list[str]:
        safety = module_config.get("safety") if isinstance(module_config.get("safety"), dict) else {}
        reasons: list[str] = []
        if not bool(safety.get("allow_unsafe", False)) and not module.spec.safe:
            reasons.append("unsafe_module_blocked")
        if not bool(safety.get("allow_partial", True)) and module.spec.partial:
            reasons.append("partial_module_blocked")
        if not bool(safety.get("allow_lossy", False)) and module.spec.lossy:
            reasons.append("lossy_module_blocked")
        return reasons

    def _deep_input_allowed(self, job: RepairJob, module_config: dict[str, Any]) -> bool:
        deep = module_config.get("deep") if isinstance(module_config.get("deep"), dict) else {}
        max_mb = float(deep.get("max_input_size_mb", 0) or 0)
        if max_mb <= 0:
            return True
        size = job_source_size(job)
        if size is None:
            return True
        return size <= int(max_mb * 1024 * 1024)

    def _module_runtime_config(self, name: str, module_configs: dict[str, dict[str, Any]]) -> dict[str, Any]:
        config = dict(module_configs.get(name, {}))
        safety = dict(self.config.get("safety") or {})
        if isinstance(config.get("safety"), dict):
            safety.update(config["safety"])
        deep = dict(self.config.get("deep") or {})
        if isinstance(config.get("deep"), dict):
            deep.update(config["deep"])
        config["safety"] = safety
        config["deep"] = deep
        return config

    def _workspace_for(self, job: RepairJob) -> Path:
        base = Path(job.workspace or self.config.get("workspace") or ".smart_unpacker_repair")
        key = _safe_key(job.archive_key or str(job.source_input.get("path") or job.source_input.get("archive_path") or "archive"))
        return base / key

    def _result(
        self,
        status: str,
        job: RepairJob,
        diagnosis: RepairDiagnosis,
        message: str,
        capability: RepairCapabilityDecision | None = None,
    ) -> RepairResult:
        return RepairResult(
            status=status,
            confidence=diagnosis.confidence,
            format=diagnosis.format or job.format,
            damage_flags=list(job.damage_flags),
            diagnosis=_with_capability_diagnosis(diagnosis.as_dict(), capability),
            message=message,
        )


def _safe_key(value: str) -> str:
    text = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(value or "archive"))
    return text[-120:] or "archive"


def _module_decision(
    module,
    format_supported: bool,
    reasons: list[str],
    declarative_reasons: list[str],
    policy_reasons: list[str],
    dynamic_reasons: list[str],
    *,
    selected: bool = False,
    score: float = 0.0,
    route_score: float = 0.0,
    fine_score: float = 0.0,
) -> ModuleCapabilityDecision:
    return ModuleCapabilityDecision(
        name=module.spec.name,
        formats=tuple(module.spec.formats),
        stage=module.spec.stage,
        format_supported=format_supported,
        selected=selected,
        score=float(score or 0.0),
        route_score=float(route_score or 0.0),
        fine_score=float(fine_score or 0.0),
        reasons=_dedupe(reasons),
        declarative_reasons=_dedupe(declarative_reasons),
        policy_reasons=_dedupe(policy_reasons),
        dynamic_reasons=_dedupe(dynamic_reasons),
    )


def _with_capability_diagnosis(
    diagnosis: dict[str, Any] | None,
    capability: RepairCapabilityDecision | None,
) -> dict[str, Any]:
    payload = dict(diagnosis or {})
    if capability is not None:
        payload["capability_decision"] = capability.as_dict()
    return payload


def _record_module_feedback(
    capability: RepairCapabilityDecision,
    module_name: str,
    reason: str,
    *,
    execution_status: str,
    execution_message: str = "",
    execution_warnings: list[str] | None = None,
) -> RepairCapabilityDecision:
    modules = []
    for item in capability.modules:
        if item.name != module_name:
            modules.append(item)
            continue
        modules.append(replace(
            item,
            reasons=_dedupe([*item.reasons, reason]),
            dynamic_reasons=_dedupe([*item.dynamic_reasons, reason]),
            execution_status=execution_status,
            execution_message=execution_message,
            execution_warnings=_dedupe([*item.execution_warnings, *(execution_warnings or [])]),
        ))
    return replace(capability, modules=modules)


def _route_specificity(routes: tuple[RepairRoute, ...]) -> int:
    if not routes:
        return 0
    return max(
        len(route.formats)
        + len(route.require_any_categories)
        + len(route.require_any_flags)
        + len(route.require_any_fuzzy_hints)
        + len(route.require_any_failure_stages)
        + len(route.require_any_failure_kinds)
        + len(route.reject_any_flags)
        + len(route.reject_any_failure_stages)
        + len(route.reject_any_failure_kinds)
        for route in routes
    )


def _stage_rank(stage: str) -> int:
    ranks = {
        "targeted": 40,
        "safe_repair": 30,
        "deep": 20,
    }
    return ranks.get(str(stage or ""), 10)


def _dedupe(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _intersects(left, right) -> bool:
    return bool({str(item).lower() for item in left} & {str(item).lower() for item in right if str(item or "")})


def _format_matches(fmt: str, expected) -> bool:
    normalized = _normalize_format(fmt)
    formats = {_normalize_format(item) for item in expected}
    return normalized in formats or "archive" in formats


def _normalize_format(value: Any) -> str:
    text = str(value or "").lower().lstrip(".")
    aliases = {
        "seven_zip": "7z",
        "sevenzip": "7z",
        "gz": "gzip",
        "bz2": "bzip2",
        "zst": "zstd",
        "tgz": "tar.gz",
        "tbz2": "tar.bz2",
        "txz": "tar.xz",
    }
    return aliases.get(text, text or "unknown")


def _lazy_module_candidate(
    module,
    job: RepairJob,
    diagnosis: RepairDiagnosis,
    workspace: str,
    module_config: dict[str, Any],
    *,
    score_hint: float,
) -> RepairCandidate:
    module_name = module.spec.name

    def materialize():
        if hasattr(module, "generate_candidates"):
            return _with_job_password_candidates(list(module.generate_candidates(  # type: ignore[attr-defined]
                job,
                diagnosis,
                workspace,
                {**module_config, "virtual_patch_candidate": True},
            ) or []), job)
        result = module.repair(job, diagnosis, workspace, {**module_config, "virtual_patch_candidate": True})
        if result.ok:
            return RepairCandidate.from_result(
                _with_job_password_result(result, job),
                score_hint=score_hint,
                stage=module.spec.stage,
            )
        return None

    return RepairCandidate(
        module_name=module_name,
        format=diagnosis.format or job.format,
        repaired_input={},
        status="partial" if module.spec.partial else "repaired",
        stage=module.spec.stage,
        confidence=float(score_hint or 0.0),
        partial=bool(module.spec.partial),
        actions=["plan_repair", module_name],
        damage_flags=list(job.damage_flags),
        diagnosis=diagnosis.as_dict(),
        message="repair plan pending materialization",
        validations=[
            CandidateValidation(
                name="repair_plan",
                accepted=True,
                score=float(score_hint or 0.0),
                details={
                    "module": module_name,
                    "stage": module.spec.stage,
                    "lazy": True,
                },
            )
        ],
        score_hint=float(score_hint or 0.0),
        materializer=materialize,
        materialized=False,
        plan={
            "module": module_name,
            "stage": module.spec.stage,
            "workspace": workspace,
            "lazy": True,
        },
    )


def _with_job_password_result(result: RepairResult, job: RepairJob) -> RepairResult:
    if job.password is None or not isinstance(result.repaired_input, dict):
        return result
    repaired_input = _with_password(result.repaired_input, job.password)
    return replace(result, repaired_input=repaired_input)


def _with_job_password_candidates(candidates: list[RepairCandidate], job: RepairJob) -> list[RepairCandidate]:
    return [_with_job_password_candidate(candidate, job) for candidate in candidates]


def _with_job_password_candidate(candidate: RepairCandidate, job: RepairJob) -> RepairCandidate:
    if job.password is None or not isinstance(candidate.repaired_input, dict):
        return candidate
    repaired_input = _with_password(candidate.repaired_input, job.password)
    return replace(candidate, repaired_input=repaired_input)


def _with_password(payload: dict[str, Any], password: str | None) -> dict[str, Any]:
    output = dict(payload)
    if password is not None and "password" not in output:
        output["password"] = password
    return output
