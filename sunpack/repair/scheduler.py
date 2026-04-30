from dataclasses import replace
import json
from pathlib import Path
from typing import Any

from sunpack.repair.candidate import CandidateSelector, CandidateValidation, RepairCandidate, RepairCandidateBatch, candidate_feature_payload
from sunpack.repair.capability import ModuleCapabilityDecision, RepairCapabilityDecision
from sunpack.repair.config import enabled_module_configs, repair_config
from sunpack.repair.context import RepairContext, build_repair_context
from sunpack.repair.diagnosis import RepairDiagnosis, diagnose_repair_job
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairRoute
from sunpack.repair.pipeline.modules._common import job_source_size
from sunpack.repair.pipeline.registry import discover_repair_modules, get_repair_module_registry
from sunpack.repair.result import RepairResult


class RepairScheduler:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = repair_config(config or {})
        discover_repair_modules()

    def diagnose(self, job: RepairJob) -> RepairDiagnosis:
        return diagnose_repair_job(job)

    def repair(self, job: RepairJob) -> RepairResult:
        batch = self.generate_repair_candidates(job)
        if batch.terminal_result is not None:
            self._write_telemetry(job, batch, batch.terminal_result, {})
            return batch.terminal_result
        selector = CandidateSelector(self.config)
        warnings = list(batch.warnings)
        selection: dict[str, Any] = {}
        primary_selection: dict[str, Any] = {}
        if batch.candidates:
            selected, selection = selector.select(_with_job_password_candidates(batch.candidates, job))
            if selected is not None:
                result = selected.to_result(selection=selection)
                if warnings:
                    result = replace(result, warnings=_dedupe([*result.warnings, *warnings]))
                self._write_telemetry(job, batch, result, selection)
                return result
            warnings.extend(selection.get("warnings") or [])
            warnings.append("repair candidates were produced but none passed selection")
            primary_selection = dict(selection)
            if self._auto_deep_should_escalate(job) and not _batch_used_auto_deep(batch):
                auto_batch = self._generate_auto_deep_candidates(job)
                warnings.extend(auto_batch.warnings)
                batch = _merge_candidate_batches(batch, auto_batch)
                if auto_batch.candidates:
                    selected, selection = selector.select(_with_job_password_candidates(auto_batch.candidates, job))
                    if selected is not None:
                        result = selected.to_result(selection=_merge_candidate_selections(primary_selection, selection))
                        self._write_telemetry(job, batch, result, result.diagnosis.get("candidate_selection", {}))
                        return replace(result, warnings=_dedupe([*result.warnings, *warnings]))
                    warnings.extend(selection.get("warnings") or [])
                    warnings.append("auto_deep candidates were produced but none passed selection")
        diagnosis = _diagnosis_with_candidate_selection(batch.diagnosis, selection)
        result = RepairResult(
            status="unrepairable",
            confidence=float(diagnosis.get("confidence", 0.0) or 0.0),
            format=str(diagnosis.get("format") or job.format),
            warnings=_dedupe(warnings),
            diagnosis=diagnosis,
            message=batch.message or "registered repair modules did not produce a candidate",
        )
        self._write_telemetry(job, batch, result, selection)
        return result

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
        auto_deep_attempted = False
        if not modules:
            if self._auto_deep_should_escalate(job):
                auto_deep_attempted = True
                modules, capability = self._select_modules(job, diagnosis, context, auto_deep=True)
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
        repair_candidates, warnings, capability = self._run_modules(
            job,
            diagnosis,
            modules,
            capability,
            workspace,
            module_configs,
            lazy=lazy,
            auto_deep=auto_deep_attempted,
        )
        if not repair_candidates and not auto_deep_attempted and self._auto_deep_should_escalate(job):
            auto_modules, auto_capability = self._select_modules(job, diagnosis, context, auto_deep=True)
            if auto_modules:
                auto_candidates, auto_warnings, auto_capability = self._run_modules(
                    job,
                    diagnosis,
                    auto_modules,
                    auto_capability,
                    workspace,
                    module_configs,
                    lazy=lazy,
                    auto_deep=True,
                )
                repair_candidates.extend(auto_candidates)
                warnings.extend(auto_warnings)
                capability = auto_capability
                auto_deep_attempted = True
        repair_candidates = [
            _with_candidate_features(replace(candidate, diagnosis=_with_capability_diagnosis(candidate.diagnosis, capability)))
            for candidate in repair_candidates
        ]
        if auto_deep_attempted:
            warnings.append("auto_deep: escalated to limited deep repair after primary stages produced no candidates")
        return RepairCandidateBatch(
            candidates=repair_candidates,
            warnings=_dedupe(warnings),
            diagnosis=_with_generation_diagnosis(
                _with_capability_diagnosis(diagnosis.as_dict(), capability),
                repair_candidates,
                warnings,
                auto_deep_attempted=auto_deep_attempted,
            ),
            message="registered repair modules did not produce a candidate",
        )

    def _generate_auto_deep_candidates(self, job: RepairJob, *, lazy: bool = False) -> RepairCandidateBatch:
        diagnosis = self.diagnose(job)
        context = build_repair_context(job, diagnosis)
        modules, capability = self._select_modules(job, diagnosis, context, auto_deep=True)
        if not modules:
            return RepairCandidateBatch(
                diagnosis=_with_capability_diagnosis(diagnosis.as_dict(), capability),
                message=capability.message(),
                warnings=[],
            )
        workspace = self._workspace_for(job)
        workspace.mkdir(parents=True, exist_ok=True)
        module_configs = enabled_module_configs(self.config)
        repair_candidates, warnings, capability = self._run_modules(
            job,
            diagnosis,
            modules,
            capability,
            workspace,
            module_configs,
            lazy=lazy,
            auto_deep=True,
        )
        warnings.append("auto_deep: escalated to limited deep repair after primary stages produced no accepted candidates")
        return RepairCandidateBatch(
            candidates=[
                _with_candidate_features(replace(candidate, diagnosis=_with_capability_diagnosis(candidate.diagnosis, capability)))
                for candidate in repair_candidates
            ],
            warnings=_dedupe(warnings),
            diagnosis=_with_generation_diagnosis(
                _with_capability_diagnosis(diagnosis.as_dict(), capability),
                repair_candidates,
                warnings,
                auto_deep_attempted=True,
            ),
            message="registered repair modules did not produce a candidate",
        )

    def _run_modules(
        self,
        job: RepairJob,
        diagnosis: RepairDiagnosis,
        modules,
        capability: RepairCapabilityDecision,
        workspace: Path,
        module_configs: dict[str, dict[str, Any]],
        *,
        lazy: bool,
        auto_deep: bool = False,
    ) -> tuple[list[RepairCandidate], list[str], RepairCapabilityDecision]:
        warnings: list[str] = []
        repair_candidates: list[RepairCandidate] = []
        for score, module, route_score, fine_score in modules:
            module_config = self._module_runtime_config(module.spec.name, module_configs, auto_deep=auto_deep)
            score_hint = max(score, route_score, fine_score)
            if lazy:
                repair_candidates.append(_lazy_module_candidate(
                    module,
                    job,
                    diagnosis,
                    str(workspace),
                    module_config,
                    score_hint=score_hint,
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
                            score_hint=max(score_hint, candidate.score_hint),
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
                    score_hint=score_hint,
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
        return repair_candidates, warnings, capability

    def _select_modules(
        self,
        job: RepairJob,
        diagnosis: RepairDiagnosis,
        context: RepairContext,
        *,
        auto_deep: bool = False,
    ):
        enabled = enabled_module_configs(self.config)
        registry = get_repair_module_registry()
        candidates = []
        decisions: list[ModuleCapabilityDecision] = []
        for name, module in registry.all().items():
            if name not in enabled:
                continue
            if auto_deep and module.spec.stage != "deep":
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
            if not auto_deep and not stages.get(module.spec.stage, True):
                reasons.append("stage_disabled")
                policy_reasons.append("stage_disabled")
                decisions.append(_module_decision(module, format_supported, reasons, declarative_reasons, policy_reasons, dynamic_reasons, route_score=route_score))
                continue
            module_config = self._module_runtime_config(name, enabled, auto_deep=auto_deep)
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
            candidates.append((score, module, route_score, fine_score))
        candidates.sort(key=lambda item: self._module_sort_key(item[0], item[1], item[2], item[3], diagnosis.format))
        limit = self._module_limit(auto_deep=auto_deep)
        selected_names = {module.spec.name for _, module, _, _ in candidates[:limit]}
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

    def _module_sort_key(self, score: float, module, route_score: float, fine_score: float, diagnosis_format: str = "") -> tuple:
        return (
            -float(score or 0.0),
            -float(fine_score or 0.0),
            -float(route_score or 0.0),
            _format_specificity_penalty(diagnosis_format, module.spec.formats),
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

    def _auto_deep_should_escalate(self, job: RepairJob) -> bool:
        auto_deep = self.config.get("auto_deep") if isinstance(self.config.get("auto_deep"), dict) else {}
        if not bool(auto_deep.get("enabled", True)):
            return False
        stages = self.config.get("stages") if isinstance(self.config.get("stages"), dict) else {}
        if bool(stages.get("deep", True)):
            return False
        if bool(auto_deep.get("require_verification_repair", True)) and not _verification_requests_repair(job):
            return False
        return True

    def _module_limit(self, *, auto_deep: bool = False) -> int:
        if auto_deep:
            auto_config = self.config.get("auto_deep") if isinstance(self.config.get("auto_deep"), dict) else {}
            return max(1, int(auto_config.get("max_modules", 2) or 2))
        return max(1, int(self.config.get("max_modules_per_job", 4) or 4))

    def _module_runtime_config(
        self,
        name: str,
        module_configs: dict[str, dict[str, Any]],
        *,
        auto_deep: bool = False,
    ) -> dict[str, Any]:
        config = dict(module_configs.get(name, {}))
        safety = dict(self.config.get("safety") or {})
        if isinstance(config.get("safety"), dict):
            safety.update(config["safety"])
        deep = dict(self.config.get("deep") or {})
        if isinstance(config.get("deep"), dict):
            deep.update(config["deep"])
        if auto_deep:
            auto_config = self.config.get("auto_deep") if isinstance(self.config.get("auto_deep"), dict) else {}
            deep["auto_deep"] = True
            deep["max_candidates_per_module"] = _min_positive_int(
                deep.get("max_candidates_per_module"),
                auto_config.get("max_candidates_per_module"),
                default=1,
            )
            deep["max_input_size_mb"] = _min_positive_float(
                deep.get("max_input_size_mb"),
                auto_config.get("max_input_size_mb"),
            )
        config["safety"] = safety
        config["deep"] = deep
        return config

    def _workspace_for(self, job: RepairJob) -> Path:
        base = Path(job.workspace or self.config.get("workspace") or ".sunpack_repair")
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

    def _write_telemetry(
        self,
        job: RepairJob,
        batch: RepairCandidateBatch,
        result: RepairResult,
        selection: dict[str, Any],
    ) -> None:
        telemetry = self.config.get("telemetry") if isinstance(self.config.get("telemetry"), dict) else {}
        if not bool(telemetry.get("enabled", False)):
            return
        records = _telemetry_records(job, batch, result, selection)
        if not records:
            return
        target = _telemetry_target(result)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("a", encoding="utf-8") as handle:
                for record in records:
                    handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str) + "\n")
        except OSError:
            return


def _safe_key(value: str) -> str:
    text = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(value or "archive"))
    return text[-120:] or "archive"


def _telemetry_records(
    job: RepairJob,
    batch: RepairCandidateBatch,
    result: RepairResult,
    selection: dict[str, Any],
) -> list[dict[str, Any]]:
    features = _telemetry_candidate_features(batch, selection)
    if not features:
        return []
    selected_ids = _telemetry_selected_ids(features, result, selection)
    repair_success = bool(result.ok and result.status in {"repaired", "partial"})
    query_id = f"{job.archive_key or 'repair'}:{int(job.attempts or 0)}"
    records = []
    for index, item in enumerate(features):
        candidate_id = str(item.get("candidate_id") or "")
        selected = candidate_id in selected_ids
        records.append({
            "schema_version": 1,
            "source": "runtime.repair.telemetry",
            "query_id": query_id,
            "archive_key": job.archive_key,
            "candidate_id": candidate_id,
            "candidate_index": index,
            "label": 2 if selected and repair_success else 0,
            "label_source": "runtime_weak",
            "candidate_selected": selected,
            "candidate_is_expected_module": None,
            "expected_module": None,
            "actual_selected": result.module_name,
            "result_status": result.status,
            "repair_success": repair_success,
            "verified_by_test": False,
            "format": result.format or job.format,
            "damage_flags": list(job.damage_flags),
            "features": dict(item.get("ltr_features") or {}),
        })
    return records


def _telemetry_target(result: RepairResult) -> Path:
    suffix = "success" if result.ok and result.status in {"repaired", "partial"} else "failure"
    return Path(".sunpack") / "datasets" / f"repair_candidates_runtime_{suffix}.jsonl"


def _telemetry_candidate_features(batch: RepairCandidateBatch, selection: dict[str, Any]) -> list[dict[str, Any]]:
    selected_features = selection.get("candidates") if isinstance(selection.get("candidates"), list) else []
    output = [dict(item) for item in selected_features if isinstance(item, dict) and item.get("ltr_features")]
    if output:
        return output
    return [
        candidate_feature_payload(candidate)
        for candidate in batch.candidates
        if candidate.repaired_input or candidate.is_lazy
    ]


def _telemetry_selected_ids(
    features: list[dict[str, Any]],
    result: RepairResult,
    selection: dict[str, Any],
) -> set[str]:
    selected_module = str(selection.get("selected_module") or result.module_name or "")
    selected_priority = selection.get("generation_priority")
    selected = set()
    for item in features:
        if str(item.get("module") or "") != selected_module:
            continue
        if selected_priority is None or _float_equal(item.get("generation_priority"), selected_priority):
            candidate_id = str(item.get("candidate_id") or "")
            if candidate_id:
                selected.add(candidate_id)
    if selected:
        return selected
    return {
        str(item.get("candidate_id") or "")
        for item in features
        if str(item.get("module") or "") == selected_module and item.get("candidate_id")
    }


def _float_equal(left: Any, right: Any) -> bool:
    try:
        return abs(float(left) - float(right)) <= 1e-12
    except (TypeError, ValueError):
        return left == right


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


def _with_candidate_features(candidate: RepairCandidate) -> RepairCandidate:
    diagnosis = dict(candidate.diagnosis)
    diagnosis["candidate_features"] = candidate_feature_payload(candidate)
    return replace(candidate, diagnosis=diagnosis)


def _with_generation_diagnosis(
    diagnosis: dict[str, Any],
    candidates: list[RepairCandidate],
    warnings: list[str],
    *,
    auto_deep_attempted: bool,
) -> dict[str, Any]:
    payload = dict(diagnosis or {})
    payload["candidate_generation"] = {
        "candidate_count": len(candidates),
        "auto_deep_attempted": bool(auto_deep_attempted),
        "warnings": list(warnings),
        "candidates": [candidate_feature_payload(candidate) for candidate in candidates],
    }
    return payload


def _diagnosis_with_candidate_selection(diagnosis: dict[str, Any], selection: dict[str, Any]) -> dict[str, Any]:
    payload = dict(diagnosis or {})
    if selection:
        payload["candidate_selection"] = dict(selection)
    return payload


def _merge_candidate_batches(left: RepairCandidateBatch, right: RepairCandidateBatch) -> RepairCandidateBatch:
    warnings = _dedupe([*left.warnings, *right.warnings])
    diagnosis = dict(left.diagnosis or {})
    right_diagnosis = right.diagnosis if isinstance(right.diagnosis, dict) else {}
    if right_diagnosis:
        diagnosis["auto_deep_diagnosis"] = dict(right_diagnosis)
    return RepairCandidateBatch(
        candidates=[*left.candidates, *right.candidates],
        warnings=warnings,
        diagnosis=diagnosis,
        message=right.message or left.message,
        terminal_result=left.terminal_result or right.terminal_result,
    )


def _merge_candidate_selections(primary: dict[str, Any], secondary: dict[str, Any]) -> dict[str, Any]:
    if not primary:
        return dict(secondary or {})
    if not secondary:
        return dict(primary or {})
    merged = dict(secondary)
    primary_candidates = primary.get("candidates") if isinstance(primary.get("candidates"), list) else []
    secondary_candidates = secondary.get("candidates") if isinstance(secondary.get("candidates"), list) else []
    merged["candidates"] = [*primary_candidates, *secondary_candidates]
    merged["candidate_count"] = int(primary.get("candidate_count", 0) or 0) + int(secondary.get("candidate_count", 0) or 0)
    merged["accepted_count"] = int(primary.get("accepted_count", 0) or 0) + int(secondary.get("accepted_count", 0) or 0)
    merged["warnings"] = _dedupe([*(primary.get("warnings") or []), *(secondary.get("warnings") or [])])
    merged["auto_deep_selection"] = dict(secondary)
    return merged


def _batch_used_auto_deep(batch: RepairCandidateBatch) -> bool:
    if any("auto_deep" in str(warning) for warning in batch.warnings):
        return True
    for candidate in batch.candidates:
        deep = candidate.diagnosis.get("deep") if isinstance(candidate.diagnosis, dict) else {}
        if isinstance(deep, dict) and deep.get("auto_deep"):
            return True
        if candidate.stage == "deep" and any("auto_deep" in str(action) for action in candidate.actions):
            return True
    return False


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


def _format_specificity_penalty(fmt: str, expected) -> int:
    normalized = _normalize_format(fmt)
    formats = {_normalize_format(item) for item in expected}
    if normalized in formats:
        return 0
    if "archive" in formats:
        return 1
    return 2


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


def _verification_requests_repair(job: RepairJob) -> bool:
    payloads = []
    if isinstance(job.extraction_failure, dict):
        payloads.append(job.extraction_failure)
        nested = job.extraction_failure.get("verification")
        if isinstance(nested, dict):
            payloads.append(nested)
    if isinstance(job.extraction_diagnostics, dict):
        payloads.append(job.extraction_diagnostics)
        nested = job.extraction_diagnostics.get("verification")
        if isinstance(nested, dict):
            payloads.append(nested)
    for payload in payloads:
        if str(payload.get("decision_hint") or "").lower() == "repair":
            return True
    return False


def _min_positive_int(left: Any, right: Any, *, default: int) -> int:
    values = []
    for value in (left, right):
        try:
            number = int(value)
        except (TypeError, ValueError):
            continue
        if number > 0:
            values.append(number)
    if not values:
        return default
    return min(values)


def _min_positive_float(left: Any, right: Any) -> float:
    values = []
    for value in (left, right):
        try:
            number = float(value)
        except (TypeError, ValueError):
            continue
        if number > 0:
            values.append(number)
    if not values:
        return 0.0
    return min(values)


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
