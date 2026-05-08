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
from sunpack.repair.pipeline.modules._common import job_source_size, repair_operation_cache_key
from sunpack.repair.pipeline.registry import discover_repair_modules, get_repair_module_registry
from sunpack.repair.result import RepairResult
from sunpack.repair.runtime_cache import RepairRuntimeCache
from sunpack.support import repair_trace


class RepairScheduler:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = repair_config(config or {})
        cache_config = self.config.get("runtime_cache") if isinstance(self.config.get("runtime_cache"), dict) else {}
        self.repair_cache = RepairRuntimeCache(
            enabled=bool(cache_config.get("enabled", True)),
            max_entries=int(cache_config.get("max_entries", 512) or 512),
        )
        discover_repair_modules()

    def diagnose(self, job: RepairJob) -> RepairDiagnosis:
        return diagnose_repair_job(job)

    def repair(self, job: RepairJob) -> RepairResult:
        batch = self.generate_repair_candidates(job)
        if batch.terminal_result is not None:
            self._write_telemetry(job, batch, batch.terminal_result, {})
            repair_trace.write_event("repair_terminal_result", {
                "job": repair_trace.job_payload(job),
                "result": repair_trace.result_payload(batch.terminal_result),
                "diagnosis": batch.diagnosis,
                "warnings": list(batch.warnings),
            })
            return batch.terminal_result
        selector = CandidateSelector(self.config)
        warnings = list(batch.warnings)
        selection: dict[str, Any] = {}
        if batch.candidates:
            selected, selection = selector.select(_with_job_password_candidates(batch.candidates, job))
            if selected is not None:
                result = selected.to_result(selection=selection)
                if warnings:
                    result = replace(result, warnings=_dedupe([*result.warnings, *warnings]))
                self._write_telemetry(job, batch, result, selection)
                repair_trace.write_event("repair_selected_result", {
                    "job": repair_trace.job_payload(job),
                    "result": repair_trace.result_payload(result),
                    "selection": selection,
                    "candidate": candidate_feature_payload(selected),
                    "candidate_count": len(batch.candidates),
                })
                return result
            warnings.extend(selection.get("warnings") or [])
            warnings.append("repair candidates were produced but none passed selection")
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
        repair_trace.write_event("repair_unrepairable_result", {
            "job": repair_trace.job_payload(job),
            "result": repair_trace.result_payload(result),
            "selection": selection,
            "candidate_count": len(batch.candidates),
        })
        return result

    def generate_repair_candidates(self, job: RepairJob, *, lazy: bool = False) -> RepairCandidateBatch:
        diagnosis = self.diagnose(job)
        context = build_repair_context(job, diagnosis)
        effective_job = replace(job, damage_flags=list(context.damage_flags), repair_cache=job.repair_cache or self.repair_cache)
        if not self.config.get("enabled", True):
            result = self._result("skipped", job, diagnosis, "repair layer is disabled")
            repair_trace.write_event("repair_candidates_terminal", {
                "job": repair_trace.job_payload(job),
                "lazy": bool(lazy),
                "diagnosis": diagnosis.as_dict(),
                "result": repair_trace.result_payload(result),
                "message": "repair layer is disabled",
            })
            return RepairCandidateBatch(
                terminal_result=result,
                diagnosis=diagnosis.as_dict(),
                message="repair layer is disabled",
            )
        if not diagnosis.repairable:
            message = "; ".join(diagnosis.notes) or "repair is blocked"
            result = self._result("unrepairable", job, diagnosis, message)
            repair_trace.write_event("repair_candidates_terminal", {
                "job": repair_trace.job_payload(job),
                "lazy": bool(lazy),
                "diagnosis": diagnosis.as_dict(),
                "result": repair_trace.result_payload(result),
                "message": message,
            })
            return RepairCandidateBatch(
                terminal_result=result,
                diagnosis=diagnosis.as_dict(),
                message=message,
            )

        modules, capability = self._select_modules(effective_job, diagnosis, context)
        if not modules:
            status = "unrepairable" if capability.automatic_unrepairable else "unsupported"
            result = self._result(status, job, diagnosis, capability.message(), capability)
            repair_trace.write_event("repair_candidates_terminal", {
                "job": repair_trace.job_payload(job),
                "lazy": bool(lazy),
                "diagnosis": diagnosis.as_dict(),
                "capability_decision": capability.as_dict() if hasattr(capability, "as_dict") else {},
                "result": repair_trace.result_payload(result),
                "message": result.message,
            })
            return RepairCandidateBatch(
                terminal_result=result,
                diagnosis=result.diagnosis,
                message=result.message,
            )

        workspace = self._workspace_for(job)
        workspace.mkdir(parents=True, exist_ok=True)
        module_configs = enabled_module_configs(self.config)
        runtime_job = replace(effective_job, workspace=str(workspace))
        repair_candidates, warnings, capability = self._run_modules(
            runtime_job,
            diagnosis,
            modules,
            capability,
            workspace,
            module_configs,
            lazy=lazy,
        )
        repair_candidates = [
            _with_candidate_features(replace(candidate, diagnosis=_with_capability_diagnosis(candidate.diagnosis, capability)))
            for candidate in repair_candidates
        ]
        repair_trace.write_event("repair_candidates_generated", {
            "job": repair_trace.job_payload(job),
            "lazy": bool(lazy),
            "diagnosis": diagnosis.as_dict(),
            "capability_decision": capability.as_dict() if hasattr(capability, "as_dict") else {},
            "candidate_count": len(repair_candidates),
            "candidates": [candidate_feature_payload(candidate) for candidate in repair_candidates],
            "warnings": _dedupe(warnings),
        })
        return RepairCandidateBatch(
            candidates=repair_candidates,
            warnings=_dedupe(warnings),
            diagnosis=_with_generation_diagnosis(
            _with_capability_diagnosis(diagnosis.as_dict(), capability),
                repair_candidates,
                warnings,
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
    ) -> tuple[list[RepairCandidate], list[str], RepairCapabilityDecision]:
        warnings: list[str] = []
        repair_candidates: list[RepairCandidate] = []
        for score, module, route_score, fine_score in modules:
            module_config = self._module_runtime_config(module.spec.name, module_configs)
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
    ):
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
            atomic = bool(getattr(module.spec, "atomic", False))
            route_score = self._route_score(module.spec.routes, context, atomic=atomic)
            route_reasons = self._route_reasons(module.spec.routes, context, atomic=atomic) if route_score <= 0 else []
            if route_score <= 0 and route_reasons:
                declarative_reasons.extend(route_reasons)
            if atomic and not format_supported:
                reasons.append("format_not_supported")
                decisions.append(_module_decision(module, format_supported, reasons, declarative_reasons, policy_reasons, dynamic_reasons, route_score=route_score))
                continue
            if atomic and route_score <= 0:
                reasons.extend(declarative_reasons or ["atomic_route_rejected"])
                decisions.append(_module_decision(module, format_supported, reasons, declarative_reasons, policy_reasons, dynamic_reasons, route_score=route_score))
                continue
            if route_score <= 0 and not format_supported:
                reasons.append("format_not_supported")
                decisions.append(_module_decision(module, format_supported, reasons, declarative_reasons, policy_reasons, dynamic_reasons, route_score=route_score))
                continue
            if route_score <= 0 and module.spec.categories and not (set(module.spec.categories) & set(diagnosis.categories)):
                reasons.append("category_mismatch")
                declarative_reasons.append("category_mismatch")
                decisions.append(_module_decision(module, format_supported, reasons, declarative_reasons, policy_reasons, dynamic_reasons, route_score=route_score))
                continue
            module_config = self._module_runtime_config(name, enabled)
            safety_reasons = self._safety_reasons(module, module_config)
            if safety_reasons:
                reasons.extend(safety_reasons)
                policy_reasons.extend(safety_reasons)
                decisions.append(_module_decision(module, format_supported, reasons, declarative_reasons, policy_reasons, dynamic_reasons, route_score=route_score))
                continue
            if not self._module_input_allowed(job, module_config):
                reasons.append("module_input_size_blocked")
                policy_reasons.append("module_input_size_blocked")
                decisions.append(_module_decision(module, format_supported, reasons, declarative_reasons, policy_reasons, dynamic_reasons, route_score=route_score))
                continue
            fine_score = float(module.can_handle(job, diagnosis, module_config) or 0.0)
            score = min(fine_score, route_score) if atomic else max(fine_score, route_score)
            if score <= 0:
                if atomic and fine_score <= 0:
                    reasons.append("can_handle_rejected")
                    dynamic_reasons.append("can_handle_rejected")
                elif declarative_reasons:
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
        selected = list(candidates)
        selected_names = {module.spec.name for _, module, _, _ in selected}
        if selected_names:
            decisions = [
                replace(
                    item,
                    selected=item.name in selected_names,
                    reasons=["selected"] if item.name in selected_names else item.reasons,
                    policy_reasons=[] if item.name in selected_names else item.policy_reasons,
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
        return selected, decision

    def _module_sort_key(self, score: float, module, route_score: float, fine_score: float, diagnosis_format: str = "") -> tuple:
        return (
            -float(score or 0.0),
            -float(fine_score or 0.0),
            -float(route_score or 0.0),
            _format_specificity_penalty(diagnosis_format, module.spec.formats),
            -_route_specificity(module.spec.routes),
            0 if module.spec.safe else 1,
            1 if module.spec.lossy else 0,
            1 if module.spec.partial else 0,
            module.spec.name,
        )

    def _route_score(self, routes: tuple[RepairRoute, ...], context: RepairContext, *, atomic: bool = False) -> float:
        best = 0.0
        for route in routes:
            score = self._single_route_score(route, context, atomic=atomic)
            if score > best:
                best = score
        return best

    def _single_route_score(self, route: RepairRoute, context: RepairContext, *, atomic: bool = False) -> float:
        if route.formats and not _format_matches(context.format, route.formats):
            return 0.0
        if _intersects(route.reject_any_flags, context.damage_flags):
            return 0.0
        if context.failure_stage and _intersects(route.reject_any_failure_stages, (context.failure_stage,)):
            return 0.0
        if context.failure_kind and _intersects(route.reject_any_failure_kinds, (context.failure_kind,)):
            return 0.0

        score = float(route.base_score or 0.0)
        if not _contains_all(route.require_all_categories, context.categories):
            return 0.0
        if not _contains_all(route.require_all_flags, context.damage_flags):
            return 0.0
        if route.require_all_categories:
            score += 0.1
        if route.require_all_flags:
            score += 0.14
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

    def _route_reasons(self, routes: tuple[RepairRoute, ...], context: RepairContext, *, atomic: bool = False) -> list[str]:
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
            if not _contains_all(route.require_all_categories, context.categories):
                reasons.append("route_required_categories_unmet")
                continue
            if not _contains_all(route.require_all_flags, context.damage_flags):
                reasons.append("route_required_flags_unmet")
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
                reasons.append("route_required_flags_unmet" if atomic else "route_requirements_unmet")
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

    def _module_input_allowed(self, job: RepairJob, module_config: dict[str, Any]) -> bool:
        limits = module_config.get("module_limits") if isinstance(module_config.get("module_limits"), dict) else {}
        max_mb = float(limits.get("max_input_size_mb", 0) or 0)
        if max_mb <= 0:
            return True
        size = job_source_size(job)
        if size is None:
            return True
        return size <= int(max_mb * 1024 * 1024)

    def _module_runtime_config(
        self,
        name: str,
        module_configs: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        config = dict(module_configs.get(name, {}))
        safety = dict(self.config.get("safety") or {})
        if isinstance(config.get("safety"), dict):
            safety.update(config["safety"])
        limits = dict(self.config.get("module_limits") or {})
        if isinstance(config.get("module_limits"), dict):
            limits.update(config["module_limits"])
        config["safety"] = safety
        config["module_limits"] = limits
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
            _write_pretty_telemetry(_telemetry_pretty_target(target), records)
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


def _telemetry_pretty_target(path: Path) -> Path:
    suffix = "".join(path.suffixes)
    if suffix:
        return path.with_name(path.name.removesuffix(suffix) + ".pretty.json")
    return path.with_name(path.name + ".pretty.json")


def _write_pretty_telemetry(path: Path, records: list[dict[str, Any]]) -> None:
    existing: list[Any] = []
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            loaded = []
        if isinstance(loaded, list):
            existing = loaded
    path.write_text(
        json.dumps([*existing, *records], ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )


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
        atomic=bool(getattr(module.spec, "atomic", False)),
        route_family=str(getattr(module.spec, "route_family", "") or ""),
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
) -> dict[str, Any]:
    payload = dict(diagnosis or {})
    payload["candidate_generation"] = {
        "candidate_count": len(candidates),
        "warnings": list(warnings),
        "candidates": [candidate_feature_payload(candidate) for candidate in candidates],
    }
    return payload


def _diagnosis_with_candidate_selection(diagnosis: dict[str, Any], selection: dict[str, Any]) -> dict[str, Any]:
    payload = dict(diagnosis or {})
    if selection:
        payload["candidate_selection"] = dict(selection)
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
        + len(route.require_all_categories)
        + len(route.require_all_flags)
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


def _contains_all(expected, actual) -> bool:
    required = {str(item).lower() for item in expected if str(item or "")}
    if not required:
        return True
    present = {str(item).lower() for item in actual if str(item or "")}
    return required <= present


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
    route_family = str(getattr(module.spec, "route_family", "") or "")
    atomic_action_group = route_family or module_name
    route_required_flags = tuple(
        flag
        for route in getattr(module.spec, "routes", ()) or ()
        for flag in (*getattr(route, "require_all_flags", ()), *getattr(route, "require_any_flags", ()))
    )
    route_required_flags_matched = sorted({
        str(flag)
        for flag in route_required_flags
        if str(flag).lower() in {str(item).lower() for item in job.damage_flags}
    })

    def materialize():
        def compute():
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

        cache = getattr(job, "repair_cache", None)
        if cache is None:
            return compute()
        return cache.get_or_compute(
            "materialize_candidate",
            repair_operation_cache_key(
                job,
                module_name,
                {
                    "module_config": module_config,
                    "virtual_patch_candidate": True,
                    "score_hint": round(float(score_hint or 0.0), 8),
                },
            ),
            compute,
        )

    enriched = dict(diagnosis.as_dict())
    enriched.update({
        "repair_name": module_name,
        "native_key": "",
        "atomic_action_group": atomic_action_group,
        "route_family": route_family,
        "route_required_flags_matched": route_required_flags_matched,
        "route_reject_reason": "",
    })
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
        diagnosis=enriched,
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
                    "atomic": bool(getattr(module.spec, "atomic", False)),
                    "route_family": route_family,
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
            "plan_kind": "lazy_repair",
            "requires_materialization": True,
            "estimated_cost": 0.5,
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
