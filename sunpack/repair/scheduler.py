from dataclasses import replace
from contextlib import nullcontext
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.repair.candidate import CandidateSelector, CandidateValidation, RepairCandidate, RepairCandidateBatch, candidate_feature_payload, materialize_candidates
from sunpack.repair.capability import ModuleCapabilityDecision, RepairCapabilityDecision
from sunpack.repair.config import enabled_module_configs, repair_config
from sunpack.repair.context import RepairContext, build_repair_context
from sunpack.repair.control_candidates import is_accept_current_state_candidate, with_accept_current_state_candidate
from sunpack.repair.diagnosis import RepairDiagnosis, diagnose_repair_job
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairRoute
from sunpack.repair.pipeline.modules._common import job_source_size, repair_operation_cache_key
from sunpack.repair.pipeline.registry import discover_repair_modules, get_repair_module_registry
from sunpack.repair.policy import RepairPolicyManager
from sunpack.repair.policy.training_runtime import (
    archive_state_for_job,
    candidate_snapshot,
    recovery_score_from_job,
    runtime_context_from_job,
    state_source_input,
)
from sunpack.repair.policy.recovery_evaluator import PolicyRecoverySnapshot, RecoveryEvaluator
from sunpack.repair.result import RepairResult
from sunpack.repair.runtime_cache import RepairRuntimeCache
from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.support import archive_knowledge_projection as knowledge_view
from sunpack.support.archive_state_view import ArchiveStateByteView
from sunpack.support import repair_trace


class RepairScheduler:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = repair_config(config or {})
        self._module_selection_cache: dict[tuple[Any, ...], tuple[list[Any], RepairCapabilityDecision]] = {}
        cache_config = self.config.get("runtime_cache") if isinstance(self.config.get("runtime_cache"), dict) else {}
        self.repair_cache = RepairRuntimeCache(
            enabled=bool(cache_config.get("enabled", True)),
            max_entries=int(cache_config.get("max_entries", 512) or 512),
        )
        self.policy_manager = RepairPolicyManager(self.config)
        discover_repair_modules()

    def diagnose(self, job: RepairJob, *, knowledge: ArchiveKnowledge | None = None) -> RepairDiagnosis:
        return diagnose_repair_job(job, knowledge=knowledge)

    def repair(self, job: RepairJob) -> RepairResult:
        if self.policy_manager.dual_model_active_for_job(job):
            return self.repair_policy_loop(job)
        batch = self.generate_repair_candidates(job)
        terminal_policy_noop = (
            batch.terminal_result is not None
            and self.policy_manager.active_for_job(job)
            and _terminal_result_allows_policy_noop(batch.terminal_result)
        )
        if batch.terminal_result is not None and not terminal_policy_noop:
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
        if batch.candidates or terminal_policy_noop:
            selected = None
            if self.policy_manager.active_for_job(job):
                policy_candidates = _with_job_password_candidates(with_accept_current_state_candidate(batch.candidates, job), job)
                validated = self._validated_policy_candidates(selector, policy_candidates)
                selectable = [candidate for candidate in validated if selector._accepted(candidate)]
                policy_payloads = [
                    _policy_candidate_snapshot(job, candidate, index=index)
                    for index, candidate in enumerate(selectable)
                ]
                probe_query = _policy_probe_query(job)
                probe_payloads = [repair_trace.public_policy_payload(payload) for payload in policy_payloads]
                repair_trace.write_probe_event("policy_probe_request", {
                    **probe_query,
                    "job": repair_trace.job_payload(job),
                    "diagnosis": batch.diagnosis,
                    "route_evidence_flags": _probe_context_flags(probe_payloads, "route_evidence_flags"),
                    "repair_history_flags": _probe_context_flags(probe_payloads, "repair_history_flags"),
                    "residual_damage_flags": _probe_context_flags(probe_payloads, "residual_damage_flags"),
                    "candidate_count": len(validated),
                    "accepted_count": len(selectable),
                    "candidate_id_collision_count": _candidate_id_collision_count(probe_payloads),
                    "candidate_payloads": probe_payloads,
                    "runtime_context_hash": _runtime_context_hash(probe_payloads),
                    "candidate_payload_hashes": [repair_trace.canonical_hash(payload) for payload in probe_payloads],
                    "candidate_set_hash": repair_trace.canonical_hash(_candidate_set_hash_input(probe_payloads)),
                    "beam_disabled_by_policy": _policy_disables_beam(self.config),
                })
                selected, policy_selection = self.policy_manager.choose(
                    job=job,
                    candidates=selectable,
                    candidate_payloads=policy_payloads,
                    diagnosis=batch.diagnosis,
                )
                selection = {"policy": _policy_selection_public(policy_selection)}
                repair_trace.write_probe_event("policy_probe_decision", {
                    **probe_query,
                    "policy": _policy_selection_public(policy_selection),
                    "selected_candidate": _selected_policy_payload(probe_payloads, policy_selection),
                    "candidate_set_hash": repair_trace.canonical_hash(_candidate_set_hash_input(probe_payloads)),
                    "beam_disabled_by_policy": _policy_disables_beam(self.config),
                })
                if selected is not None:
                    selection.update({
                        "candidate_count": len(validated),
                        "accepted_count": len(selectable),
                        "selected_module": selected.module_name,
                        "selected_format": selected.format,
                        "candidates": policy_payloads,
                    })
                elif self.policy_manager.fallback_to_selector:
                    fallback_validated = [
                        candidate for candidate in validated
                        if not is_accept_current_state_candidate(candidate)
                    ]
                    fallback_selected, fallback_selection = selector.select_validated(fallback_validated)
                    selected = fallback_selected
                    fallback_candidate_payload = (
                        candidate_feature_payload(fallback_selected)
                        if fallback_selected is not None
                        else {}
                    )
                    selection = {
                        **fallback_selection,
                        "policy": _policy_selection_public(policy_selection),
                        "policy_fallback": True,
                        "fallback_selected_candidate_id": str(fallback_candidate_payload.get("candidate_id") or ""),
                        "fallback_selected_candidate": fallback_candidate_payload,
                        "fallback_candidate_in_request": _candidate_id_in_payloads(
                            str(fallback_candidate_payload.get("candidate_id") or ""),
                            policy_payloads,
                        ),
                    }
                else:
                    warnings.append("model repair policy did not select a candidate")
            else:
                selected, selection = selector.select(_with_job_password_candidates(batch.candidates, job))
                policy_status = self.policy_manager.status_for_job(job)
                if policy_status.get("decision_status") in {"unavailable", "disabled"}:
                    selection = {**selection, "policy": _policy_selection_public(policy_status), "policy_fallback": True}
            if selected is not None:
                result = selected.to_result(selection=selection)
                if warnings:
                    result = replace(result, warnings=_dedupe([*result.warnings, *warnings]))
                self._write_telemetry(job, batch, result, selection)
                selected_rank = _candidate_index(selectable if "selectable" in locals() else [], selected)
                trace_candidate = (
                    _policy_candidate_snapshot(job, selected, index=selected_rank)
                    if isinstance(selection.get("policy"), dict)
                    else candidate_feature_payload(selected)
                )
                repair_trace.write_event("repair_selected_result", {
                    "job": repair_trace.job_payload(job),
                    "result": repair_trace.result_payload(result),
                    "selection": selection,
                    "candidate": trace_candidate,
                    "candidate_count": len(batch.candidates),
                })
                repair_trace.write_probe_event("policy_probe_selected_result", {
                    **_policy_probe_query(job),
                    "job": repair_trace.job_payload(job),
                    "result": repair_trace.result_payload(result),
                    "selection": repair_trace.public_policy_payload(selection),
                    "candidate": repair_trace.public_policy_payload(trace_candidate if isinstance(trace_candidate, dict) else {}),
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

    def repair_policy_loop(self, job: RepairJob) -> RepairResult:
        selector = CandidateSelector(self.config)
        current_state = _job_archive_state(job)
        current_job = replace(
            job,
            archive_state=current_state,
            source_input=dict(job.source_input or {}),
            repair_cache=job.repair_cache or self.repair_cache,
        )
        max_rounds = max(1, int(self.config.get("max_repair_rounds_per_task", 5) or 5))
        max_attempts = max(1, int(self.config.get("max_attempts_per_task", max_rounds) or max_rounds))
        max_rounds = min(max_rounds, max_attempts)
        min_improvement = float(self.config.get("min_recovery_improvement", 0.0) or 0.0)
        patience = max(0, int(self.config.get("stagnation_patience_rounds", 3) or 0))
        history: list[dict[str, Any]] = []
        seen_digests = {current_state.effective_patch_digest()} if current_state is not None else set()
        recovery_evaluator = RecoveryEvaluator(self.config)
        recovery_cache: dict[str, PolicyRecoverySnapshot] = {}
        parent_by_digest: dict[str, str] = {}
        current_recovery = recovery_evaluator.evaluate_state(current_job, current_state, mode="policy_light", cache=recovery_cache)
        best_recovery_snapshot = current_recovery
        best_recovery = float(current_recovery.score or 0.0)
        stale_rounds = 0
        last_batch = RepairCandidateBatch()
        last_selection: dict[str, Any] = {}
        warnings: list[str] = []
        diagnosis_payload: dict[str, Any] = {"format": current_job.format, "confidence": current_job.confidence}

        for round_index in range(1, max_rounds + 1):
            current_job, current_state, observation_warning = _refresh_policy_loop_observation(
                current_job,
                current_state,
                self.config,
            )
            if observation_warning:
                warnings.append(observation_warning)
            runtime_context = runtime_context_from_job(current_job)
            current_recovery = recovery_evaluator.evaluate_state(current_job, current_state, mode="policy_light", cache=recovery_cache)
            current_digest = current_state.effective_patch_digest() if current_state is not None else ""
            parent_recovery = PolicyRecoverySnapshot()
            parent_digest = parent_by_digest.get(current_digest, "")
            if parent_digest:
                parent_recovery = recovery_cache.get(parent_digest, PolicyRecoverySnapshot(state_digest=parent_digest))
            damage_analysis, analysis_selection = self.policy_manager.analyze_damage(
                job=current_job,
                archive_state=current_state,
                runtime_context=runtime_context,
                diagnosis=diagnosis_payload,
                round_index=round_index,
            )
            analysis_route_flags = _route_flags_from_damage_analysis(damage_analysis)
            if analysis_route_flags:
                current_job = _job_with_policy_route_flags(current_job, analysis_route_flags)
            try:
                batch = self.generate_repair_candidates(current_job, lazy=True, phase_prefix=f"policy_loop_{round_index}")
            except TypeError:
                batch = self.generate_repair_candidates(current_job)
            last_batch = batch
            diagnosis_payload = dict(batch.diagnosis or diagnosis_payload)
            if batch.terminal_result is not None and not batch.candidates:
                warnings.extend(batch.warnings)
            materialized = materialize_candidates(batch.candidates)
            validated = [selector._with_native_validation(candidate) for candidate in materialized]
            selectable = [candidate for candidate in validated if selector._accepted(candidate)]
            candidate_recoveries = [
                recovery_evaluator.evaluate_candidate(current_job, candidate, mode="policy_light", cache=recovery_cache)
                for candidate in selectable
            ]
            candidate_payloads = [
                _policy_candidate_snapshot_with_damage(
                    current_job,
                    candidate,
                    damage_analysis,
                    index=index,
                    current_recovery=current_recovery.to_dict(),
                    recovery_snapshot=candidate_recoveries[index].to_dict(),
                )
                for index, candidate in enumerate(selectable)
            ]
            decision, action_selection = self.policy_manager.choose_action(
                job=current_job,
                archive_state=current_state,
                candidates=selectable,
                candidate_payloads=candidate_payloads,
                damage_analysis=damage_analysis,
                current_recovery=current_recovery.to_dict(),
                best_seen_recovery=best_recovery_snapshot.to_dict(),
                parent_recovery=parent_recovery.to_dict(),
                diagnosis=diagnosis_payload,
                round_index=round_index,
            )
            last_selection = {
                "policy_loop": True,
                "round": round_index,
                "analysis": analysis_selection,
                "action": action_selection,
                "damage_analysis": damage_analysis,
                "candidate_count": len(selectable),
                "candidates": candidate_payloads,
            }
            repair_trace.write_probe_event("policy_loop_decision", {
                **_policy_probe_query(current_job),
                "round": round_index,
                "patch_depth": current_state.patch_depth() if current_state is not None else 0,
                "patch_digest": current_state.effective_patch_digest() if current_state is not None else "",
                "damage_analysis": damage_analysis,
                "policy": _policy_selection_public(action_selection),
            })
            history.append({
                "round": round_index,
                "patch_digest": current_state.effective_patch_digest() if current_state is not None else "",
                "patch_depth": current_state.patch_depth() if current_state is not None else 0,
                "damage_analysis": damage_analysis,
                "analysis_route_flags": list(analysis_route_flags),
                "current_recovery": current_recovery.to_dict(),
                "best_seen_recovery": best_recovery_snapshot.to_dict(),
                "action": action_selection,
            })

            if decision.action == "apply_patch":
                selected = _candidate_by_id(selectable, candidate_payloads, decision.selected_candidate_id)
                if selected is None:
                    warnings.append("policy selected a missing repair candidate")
                    break
                next_state = selected.repaired_state
                if next_state is None:
                    result = selected.to_result(selection=last_selection)
                    next_state = result.repaired_state
                if next_state is None:
                    warnings.append("policy selected a candidate without repaired_state")
                    break
                next_digest = next_state.effective_patch_digest()
                if next_digest in seen_digests:
                    warnings.append("policy loop stopped because selected state was already visited")
                    return _loop_stop_result(current_job, current_state, diagnosis_payload, last_selection, history, warnings, reason="repeated_patch_digest", recovery=current_recovery)
                seen_digests.add(next_digest)
                parent_by_digest[next_digest] = current_state.effective_patch_digest() if current_state is not None else ""
                current_state = next_state
                current_job = replace(
                    current_job,
                    archive_state=current_state,
                    source_input=dict(current_job.source_input or {}),
                    attempts=round_index,
                    repair_history=_loop_history_payload(history),
                    damage_flags=[],
                )
                selected_index = selectable.index(selected) if selected in selectable else -1
                next_recovery = candidate_recoveries[selected_index] if selected_index >= 0 else recovery_evaluator.evaluate_state(current_job, current_state, mode="policy_light", cache=recovery_cache)
                recovery = float(next_recovery.score or 0.0)
                if recovery >= best_recovery + min_improvement:
                    best_recovery = recovery
                    best_recovery_snapshot = next_recovery
                    stale_rounds = 0
                else:
                    stale_rounds += 1
                if patience and stale_rounds >= patience:
                    return _loop_stop_result(current_job, current_state, diagnosis_payload, last_selection, history, warnings, reason="policy_loop_stagnation", recovery=next_recovery)
                continue

            if decision.action == "undo_patch":
                if current_state is None or current_state.patch_depth() <= 0:
                    warnings.append("policy requested undo on an empty patch stack")
                    return _loop_stop_result(current_job, current_state, diagnosis_payload, last_selection, history, warnings, reason="undo_empty_patch_stack", recovery=current_recovery)
                current_state = current_state.pop_patch()
                current_job = replace(
                    current_job,
                    archive_state=current_state,
                    source_input=dict(current_job.source_input or {}),
                    attempts=round_index,
                    repair_history=_loop_history_payload(history),
                    damage_flags=[],
                )
                current_recovery = recovery_evaluator.evaluate_state(current_job, current_state, mode="policy_light", cache=recovery_cache)
                seen_digests.add(current_state.effective_patch_digest())
                continue

            if decision.action == "stop":
                return _loop_stop_result(current_job, current_state, diagnosis_payload, last_selection, history, warnings, reason=decision.reason or "policy_stop", recovery=current_recovery)

            if decision.action == "give_up":
                return _loop_give_up_result(current_job, diagnosis_payload, last_selection, history, warnings, reason=decision.reason or "policy_give_up", recovery=current_recovery)

        return _loop_stop_result(current_job, current_state, diagnosis_payload, last_selection, history, warnings, reason="max_policy_loop_rounds_reached", batch=last_batch, recovery=current_recovery)

    def policy_active_for_job(self, job: RepairJob) -> bool:
        return self.policy_manager.active_for_job(job)

    def _validated_policy_candidates(
        self,
        selector: CandidateSelector,
        candidates: list[RepairCandidate],
    ) -> list[RepairCandidate]:
        materialized = materialize_candidates(candidates)
        return [selector._with_native_validation(candidate) for candidate in materialized]

    def generate_repair_candidates(self, job: RepairJob, *, lazy: bool = False, phase_timer: Any | None = None, phase_prefix: str = "generate_candidates") -> RepairCandidateBatch:
        with _phase(phase_timer, f"{phase_prefix}_knowledge"):
            knowledge = ArchiveKnowledge.from_any(job.knowledge)
        with _phase(phase_timer, f"{phase_prefix}_pre_route_scan"):
            job, knowledge = self._apply_pre_route_scan(job, knowledge)
        with _phase(phase_timer, f"{phase_prefix}_diagnose"):
            diagnosis = self.diagnose(job, knowledge=knowledge)
        with _phase(phase_timer, f"{phase_prefix}_build_context"):
            context = build_repair_context(job, diagnosis, knowledge=knowledge)
        with _phase(phase_timer, f"{phase_prefix}_effective_job"):
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

        with _phase(phase_timer, f"{phase_prefix}_select_modules"):
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

        with _phase(phase_timer, f"{phase_prefix}_workspace"):
            workspace = self._workspace_for(job)
            workspace.mkdir(parents=True, exist_ok=True)
        with _phase(phase_timer, f"{phase_prefix}_module_configs"):
            module_configs = enabled_module_configs(self.config)
            runtime_job = replace(effective_job, workspace=str(workspace))
        with _phase(phase_timer, f"{phase_prefix}_run_modules"):
            repair_candidates, warnings, capability = self._run_modules(
                runtime_job,
                diagnosis,
                modules,
                capability,
                workspace,
                module_configs,
                lazy=lazy,
                phase_timer=phase_timer,
                phase_prefix=phase_prefix,
            )
        with _phase(phase_timer, f"{phase_prefix}_candidate_features"):
            repair_candidates = [
                _with_candidate_features(replace(candidate, diagnosis=_with_capability_diagnosis(candidate.diagnosis, capability)))
                for candidate in repair_candidates
            ]
        with _phase(phase_timer, f"{phase_prefix}_trace_generated"):
            trace_candidates = [candidate_feature_payload(candidate) for candidate in repair_candidates]
        repair_trace.write_event("repair_candidates_generated", {
            "job": repair_trace.job_payload(job),
            "lazy": bool(lazy),
            "diagnosis": diagnosis.as_dict(),
            "capability_decision": capability.as_dict() if hasattr(capability, "as_dict") else {},
            "candidate_count": len(repair_candidates),
            "candidates": trace_candidates,
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

    def _apply_pre_route_scan(self, job: RepairJob, knowledge: ArchiveKnowledge) -> tuple[RepairJob, ArchiveKnowledge]:
        fmt = str(job.format or "").lower()
        if fmt not in {"7z", "seven_zip", "sevenzip"}:
            return job, knowledge
        before_flags = _route_flags(knowledge)
        try:
            from sunpack.repair.pipeline.modules.seven_zip._scan import cached_seven_zip_scan_artifact
            scan_job = replace(job, repair_cache=job.repair_cache or self.repair_cache)
            artifact = cached_seven_zip_scan_artifact(scan_job, self.config)
            refreshed = ArchiveKnowledge.from_any(scan_job.knowledge)
            after_flags = _route_flags(refreshed)
            added = sorted(after_flags - before_flags)
            repair_trace.write_event("repair_pre_route_scan", {
                "job": repair_trace.job_payload(scan_job),
                "pre_route_scan_applied": True,
                "pre_route_scan_digest": getattr(artifact, "digest", ""),
                "pre_route_scan_flags_added": added,
                "route_flags_before_scan": sorted(before_flags),
                "route_flags_after_scan": sorted(after_flags),
            })
            return scan_job, refreshed
        except Exception as exc:
            repair_trace.write_event("repair_pre_route_scan", {
                "job": repair_trace.job_payload(job),
                "pre_route_scan_applied": False,
                "pre_route_scan_error": str(exc),
                "route_flags_before_scan": sorted(before_flags),
            })
            return job, knowledge

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
        phase_timer: Any | None = None,
        phase_prefix: str = "generate_candidates",
    ) -> tuple[list[RepairCandidate], list[str], RepairCapabilityDecision]:
        warnings: list[str] = []
        repair_candidates: list[RepairCandidate] = []
        for score, module, route_score, fine_score in modules:
            module_phase = f"{phase_prefix}_run_module_{module.spec.name}"
            with _phase(phase_timer, module_phase):
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
        cache_key = _module_selection_cache_key(job, diagnosis, context, self.config) if self.config.get("training_module_selection_cache") else None
        if cache_key is not None and cache_key in self._module_selection_cache:
            selected, decision = self._module_selection_cache[cache_key]
            return list(selected), decision
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
        if cache_key is not None:
            self._module_selection_cache[cache_key] = (list(selected), decision)
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
        rejected_flags = {str(item) for item in route.reject_any_flags if str(item)} & {str(item) for item in context.damage_flags if str(item)}
        if rejected_flags and not _policy_route_rejects_are_soft(context.damage_flags, rejected_flags):
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
            rejected_flags = {str(item) for item in route.reject_any_flags if str(item)} & {str(item) for item in context.damage_flags if str(item)}
            if rejected_flags and not _policy_route_rejects_are_soft(context.damage_flags, rejected_flags):
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
    if isinstance(selection.get("policy"), dict) and selected_features:
        return [dict(item) for item in selected_features if isinstance(item, dict)]
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


def _policy_candidate_snapshot(job: RepairJob, candidate: RepairCandidate, *, index: int = 0) -> dict[str, Any]:
    return candidate_snapshot(candidate, index=index)


def _module_selection_cache_key(
    job: RepairJob,
    diagnosis: RepairDiagnosis,
    context: RepairContext,
    config: dict[str, Any],
) -> tuple[Any, ...]:
    try:
        size_mb = int(job_source_size(job) // (1024 * 1024))
    except Exception:
        size_mb = -1
    enabled = tuple(sorted(enabled_module_configs(config).keys()))
    limits = config.get("module_limits") if isinstance(config.get("module_limits"), dict) else {}
    safety = config.get("safety") if isinstance(config.get("safety"), dict) else {}
    return (
        str(job.format or ""),
        str(diagnosis.format or ""),
        tuple(sorted(str(item) for item in diagnosis.categories)),
        str(diagnosis.severity or ""),
        bool(diagnosis.repairable),
        tuple(sorted(str(item) for item in context.categories)),
        tuple(sorted(str(item) for item in context.damage_flags)),
        tuple(sorted(str(item) for item in context.route_evidence_flags)),
        tuple(sorted(str(item) for item in context.repair_history_flags)),
        tuple(sorted(str(item) for item in context.residual_damage_flags)),
        str(context.failure_stage or ""),
        str(context.failure_kind or ""),
        str(context.failure_status or ""),
        str(context.native_status or ""),
        bool(job.password),
        job.archive_state.patch_depth() if job.archive_state is not None else 0,
        size_mb,
        tuple(sorted((str(key), str(value)) for key, value in safety.items())),
        tuple(sorted((str(key), str(value)) for key, value in limits.items() if key in {"max_input_size_mb", "allow_partial", "allow_lossy"})),
        enabled,
    )


def _phase(timer: Any | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)


def _route_flags(knowledge: ArchiveKnowledge) -> set[str]:
    try:
        context = knowledge_view.repair_route_context(knowledge)
    except Exception:
        return set()
    flags = context.get("route_evidence_flags") or context.get("damage_flags") or []
    if not isinstance(flags, list):
        return set()
    return {str(flag) for flag in flags if str(flag)}


def _candidate_index(candidates: list[RepairCandidate], selected: RepairCandidate) -> int:
    for index, candidate in enumerate(candidates):
        if candidate is selected:
            return index
    return 0


def _policy_selection_public(selection: dict[str, Any]) -> dict[str, Any]:
    return {
        key: selection.get(key)
        for key in (
            "enabled",
            "provider_package",
            "fallback_to_selector",
            "decision_status",
            "action",
            "fallback_reason",
            "provider_id",
            "confidence",
            "reason",
            "selected_candidate_id",
            "selected_candidate_id_valid",
            "selected_module",
            "selected_format",
            "candidate_count",
            "duplicate_candidate_id_count",
            "duplicate_candidate_ids",
            "invalid_candidate_id_reason",
            "load_error",
            "provider_errors",
            "fallback_selected_candidate_id",
            "fallback_candidate_in_request",
            "metadata",
        )
        if key in selection
    }


def _policy_probe_query(job: RepairJob) -> dict[str, Any]:
    run_id = str(os.environ.get("SUNPACK_REPAIR_POLICY_PROBE_RUN_ID") or "")
    archive_key = str(getattr(job, "archive_key", "") or "")
    round_index = int(getattr(job, "attempts", 0) or 0)
    if not run_id:
        run_id = archive_key or repair_trace.canonical_hash(repair_trace.job_payload(job))[:16]
    return {
        "run_id": run_id,
        "query_id": f"{archive_key or run_id}:{round_index}",
        "archive_key": archive_key,
        "round": round_index,
        "format": str(getattr(job, "format", "") or ""),
    }


def _policy_disables_beam(config: dict[str, Any]) -> bool:
    policy = config.get("policy") if isinstance(config.get("policy"), dict) else {}
    return bool(policy.get("enabled", True)) and bool(policy.get("disable_beam_when_model_active", True))


def _runtime_context_hash(payloads: list[dict[str, Any]]) -> str:
    for payload in payloads:
        context = payload.get("runtime_context") if isinstance(payload, dict) else None
        if isinstance(context, dict):
            return repair_trace.canonical_hash(context)
    return ""


def _probe_context_flags(payloads: list[dict[str, Any]], key: str) -> list[str]:
    for payload in payloads:
        context = payload.get("runtime_context") if isinstance(payload, dict) else None
        summary = context.get("job_summary") if isinstance(context, dict) and isinstance(context.get("job_summary"), dict) else {}
        values = summary.get(key)
        if isinstance(values, list):
            return [str(item) for item in values if str(item)]
    return []


def _candidate_set_hash_input(payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        proposal = payload.get("candidate_proposal") if isinstance(payload.get("candidate_proposal"), dict) else {}
        output.append({
            "candidate_id": payload.get("candidate_id"),
            "module_name": payload.get("module_name") or payload.get("module"),
            "repair_name": payload.get("repair_name"),
            "native_key": payload.get("native_key"),
            "native_target": payload.get("native_target"),
            "candidate_status": payload.get("candidate_status"),
            "patch_facts": proposal.get("patch_facts") or payload.get("patch_facts"),
            "validation_details": proposal.get("validation_details") or payload.get("validation_details"),
        })
    return output


def _selected_policy_payload(payloads: list[dict[str, Any]], selection: dict[str, Any]) -> dict[str, Any]:
    selected_id = str(selection.get("selected_candidate_id") or "")
    for payload in payloads:
        if str(payload.get("candidate_id") or "") == selected_id:
            return payload
    return {}


def _candidate_id_in_payloads(candidate_id: str, payloads: list[dict[str, Any]]) -> bool:
    if not candidate_id:
        return False
    return any(str(payload.get("candidate_id") or "") == candidate_id for payload in payloads if isinstance(payload, dict))


def _candidate_id_collision_count(payloads: list[dict[str, Any]]) -> int:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for payload in payloads:
        candidate_id = str(payload.get("candidate_id") or "") if isinstance(payload, dict) else ""
        if not candidate_id:
            continue
        if candidate_id in seen:
            duplicates.add(candidate_id)
        seen.add(candidate_id)
    return len(duplicates)


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


def _job_archive_state(job: RepairJob) -> ArchiveState | None:
    return archive_state_for_job(job)


def _state_source_input(state: ArchiveState | None, job: RepairJob) -> dict[str, Any]:
    return state_source_input(state, job)


def _refresh_policy_loop_observation(
    job: RepairJob,
    state: ArchiveState | None,
    config: dict[str, Any],
) -> tuple[RepairJob, ArchiveState | None, str]:
    policy = config.get("policy") if isinstance(config.get("policy"), dict) else {}
    if not bool(policy.get("refresh_runtime_observation", True)):
        return job, state, ""
    if state is None:
        return job, state, ""
    try:
        from sunpack.coordinator.analysis_stage import ArchiveAnalysisStage
        from sunpack.extraction.knowledge import write_extraction_result
        from sunpack.extraction.scheduler import ExtractionScheduler
        from sunpack.verification.knowledge import write_verification_result
        from sunpack.verification.scheduler import VerificationScheduler

        task = _task_for_policy_observation(job, state)
        fmt = _normalize_format(state.format_hint or job.format or task.detected_ext)
        with tempfile.TemporaryDirectory(prefix="sunpack_policy_loop_obs_") as tmp:
            ArchiveAnalysisStage(config).refresh_task_analysis(task)
            if fmt == "zip":
                _ensure_zip_structure_facts_for_state(task, state, Path(tmp))
            extractor = ExtractionScheduler(
                process_config=dict(config.get("process") or {}),
                output_config=dict(config.get("output") or {}),
                extraction_config={**dict(config.get("extraction") or {}), "quiet": True},
            )
            try:
                extracted = extractor.extract(task, str(Path(tmp) / "extract"))
                write_extraction_result(task, extracted)
                verification = VerificationScheduler(config).verify(task, extracted)
                write_verification_result(task, verification)
            finally:
                extractor.close()
        observed_state = task.archive_state()
        knowledge = task.knowledge().to_dict()
        observed_job = replace(
            job,
            archive_state=observed_state,
            source_input=dict(job.source_input or {}),
            knowledge=knowledge,
            extraction_failure=_nested(knowledge, "extraction", "failure") or {},
            extraction_diagnostics=_nested(knowledge, "extraction", "diagnostics") or {},
        )
        return observed_job, observed_state, ""
    except Exception as exc:
        return job, state, f"policy loop observation refresh failed: {exc}"


def _task_for_policy_observation(job: RepairJob, state: ArchiveState) -> ArchiveTask:
    descriptor = state.to_archive_input_descriptor()
    main_path = descriptor.entry_path or str(job.source_input.get("path") or job.source_input.get("archive_path") or "")
    parts = descriptor.part_paths() or [main_path]
    bag = FactBag()
    fmt = state.format_hint or job.format or descriptor.format_hint
    source_payload = descriptor.to_dict()
    knowledge = ArchiveKnowledge.from_any(job.knowledge)
    if not knowledge.to_dict():
        knowledge.set("source.input", source_payload, source_layer="repair", source_module="policy_loop_observation")
    knowledge.set("repair.damage.flags", [], source_layer="repair", source_module="policy_loop_observation")
    if _normalize_format(fmt) == "zip":
        knowledge.set("format.zip.route_evidence_flags", [], source_layer="repair", source_module="policy_loop_observation")
    bag.set("analysis.selected_format", fmt)
    bag.set("archive.input", source_payload)
    bag.set("archive.knowledge", knowledge.to_dict())
    task = ArchiveTask(
        fact_bag=bag,
        score=10,
        key=job.archive_key or main_path,
        main_path=main_path,
        all_parts=parts,
        logical_name=state.logical_name or descriptor.logical_name or job.archive_key,
        detected_ext=fmt,
    )
    task.set_archive_state(state)
    return task


def _ensure_zip_structure_facts_for_state(task: ArchiveTask, state: ArchiveState, tmp_dir: Path) -> None:
    from sunpack.analysis.knowledge import write_zip_structure_facts
    from sunpack.detection.pipeline.processors.modules.format_structure.zip_directory_consistency import inspect_zip_directory_consistency
    from sunpack.detection.pipeline.processors.modules.format_structure.zip_eocd import inspect_zip_eocd_structure
    from sunpack.detection.pipeline.processors.modules.format_structure.zip_local_header import inspect_zip_local_header
    from sunpack.detection.pipeline.processors.modules.format_structure.zip_structure_graph import inspect_zip_structure_graph

    probe_path = str(task.main_path or "")
    if state.patch_depth() > 0:
        probe_path = str(ArchiveStateByteView(state).materialize(tmp_dir / "policy_loop_patched.zip"))
    if not probe_path:
        return
    fact_bag = task.fact_bag
    fact_bag.set("file.path", probe_path)
    try:
        fact_bag.set("zip.eocd_structure", inspect_zip_eocd_structure(probe_path))
    except Exception as exc:
        fact_bag.set("zip.eocd_structure", {"error": str(exc) or type(exc).__name__})
    try:
        fact_bag.set("zip.directory_consistency", inspect_zip_directory_consistency(probe_path))
    except Exception as exc:
        fact_bag.set("zip.directory_consistency", {"error": str(exc) or type(exc).__name__})
    try:
        fact_bag.set("zip.structure_graph", inspect_zip_structure_graph(probe_path))
    except Exception as exc:
        fact_bag.set("zip.structure_graph", {"error": str(exc) or type(exc).__name__})
    try:
        local = inspect_zip_local_header(probe_path, 0)
    except Exception as exc:
        local = {"error": str(exc) or type(exc).__name__}
    fact_bag.set("zip.local_header", local)
    if isinstance(local, dict):
        fact_bag.set("zip.local_header_plausible", bool(local.get("plausible")))
        fact_bag.set("zip.local_header_offset", int(local.get("offset") or 0))
        fact_bag.set("zip.local_header_error", str(local.get("error") or ""))
    write_zip_structure_facts(task)


def _nested(payload: dict[str, Any], *path: str) -> Any:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict):
            return {}
        current = current.get(key)
    return current if isinstance(current, dict) else {}


def _route_flags_from_damage_analysis(damage_analysis: dict[str, Any]) -> list[str]:
    labels = [str(item) for item in damage_analysis.get("damage_labels") or [] if str(item)]
    metadata = damage_analysis.get("metadata") if isinstance(damage_analysis.get("metadata"), dict) else {}
    labels.extend(str(item) for item in metadata.get("uncertain_labels") or [] if str(item))
    flags: list[str] = ["policy_damage_analysis_route"]
    for label in labels:
        name = label.split(":", 1)[1] if ":" in label else label
        flags.append(name.replace(".", "_"))
        if name.startswith("eocd."):
            flags.append("eocd_bad")
        if name in {"eocd.cd_offset", "central_directory.offset"}:
            flags.append("central_directory_offset_bad")
        if name in {"eocd.entry_count", "central_directory.entry_count"}:
            flags.append("central_directory_count_bad")
        if name == "eocd.comment_length":
            flags.extend(["zip_comment_length_bad", "comment_length_bad"])
        if name.startswith("central_directory."):
            flags.append("central_directory_bad")
        if name == "central_directory.local_header_offset":
            flags.extend(["central_directory_offset_bad", "local_header_conflict"])
        if name in {"central_directory.compressed_size", "local_header.compressed_size", "local_header.uncompressed_size"}:
            flags.extend(["compressed_size_bad", "local_header_size_bad"])
        if name in {"central_directory.crc", "central_directory.flags", "central_directory.filename"}:
            flags.append("local_header_conflict")
        if name.startswith("local_header."):
            flags.append("local_header_bad")
        if name in {"local_header.extra", "local_header.extra_length", "central_directory.extra", "central_directory.extra_length"}:
            flags.extend(["extra_field_bad", "extra_field_length_bad", "extra_length_bad"])
        if name.startswith("data_descriptor."):
            flags.extend(["data_descriptor", "bit3_data_descriptor"])
        if name == "data_descriptor.record":
            flags.extend(["spurious_data_descriptor_candidate", "compressed_size_bad"])
        if name.startswith("payload."):
            flags.extend(["entry_payload_bad", "payload_damaged", "checksum_error"])
        if name.startswith("split_volume."):
            flags.extend(["missing_volume", "input_truncated", "stream_truncated", "local_header_recovery"])
        if name.startswith("sfx_prefix."):
            flags.extend(["sfx", "carrier_prefix", "carrier_archive"])
        if name.startswith("zip64."):
            flags.append("zip64")
            if "locator" in name:
                flags.append("zip64_locator_bad")
            elif "extra" in name:
                flags.extend(["zip64_extra_bad", "zip64_extra_size_bad"])
            else:
                flags.append("zip64_eocd_bad")
        if name.startswith("tail.") or name == "trailing_junk":
            flags.extend(["trailing_junk", "boundary_unreliable"])
        if label == "zone:eocd":
            flags.append("eocd_bad")
        if label == "zone:central_directory":
            flags.append("central_directory_bad")
        if label == "zone:local_header":
            flags.append("local_header_bad")
        if label == "zone:data_descriptor":
            flags.append("data_descriptor")
        if label == "zone:payload":
            flags.append("entry_payload_bad")
        if label == "zone:split_volume":
            flags.extend(["missing_volume", "input_truncated", "stream_truncated"])
        if label == "zone:sfx_prefix":
            flags.extend(["sfx", "carrier_prefix"])
        if label == "zone:zip64":
            flags.append("zip64")
    return _dedupe(flags)


def _job_with_policy_route_flags(job: RepairJob, flags: list[str]) -> RepairJob:
    knowledge = ArchiveKnowledge.from_any(job.knowledge)
    normalized = _dedupe([str(flag) for flag in flags if str(flag)])
    knowledge.set("repair.damage.flags", normalized, source_layer="policy", source_module="damage_analysis_route_bridge")
    if _normalize_format(job.format) == "zip":
        knowledge.set("format.zip.route_evidence_flags", normalized, source_layer="policy", source_module="damage_analysis_route_bridge")
    return replace(job, damage_flags=normalized, knowledge=knowledge.to_dict())


def _policy_route_rejects_are_soft(context_flags, rejected_flags: set[str]) -> bool:
    flags = {str(item) for item in context_flags if str(item)}
    if "policy_damage_analysis_route" not in flags:
        return False
    soft = {
        "checksum_error",
        "crc_error",
        "entry_payload_bad",
        "payload_bad",
        "payload_damaged",
        "damaged",
        "content_integrity_bad_or_unknown",
        "data_error",
        "corrupted_data",
        "partial_entries_remaining",
        "partial_extract_available",
        "post_validate",
        "item_extract",
        "unknown",
    }
    return bool(rejected_flags) and rejected_flags <= soft


def _policy_candidate_snapshot_with_damage(
    job: RepairJob,
    candidate: RepairCandidate,
    damage_analysis: dict[str, Any],
    *,
    index: int,
    current_recovery: dict[str, Any] | None = None,
    recovery_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return candidate_snapshot(
        candidate,
        index=index,
        damage_analysis=damage_analysis,
        current_recovery=current_recovery,
        recovery_snapshot=recovery_snapshot,
    )


def _candidate_by_id(
    candidates: list[RepairCandidate],
    payloads: list[dict[str, Any]],
    candidate_id: str,
) -> RepairCandidate | None:
    for candidate, payload in zip(candidates, payloads):
        if str(payload.get("candidate_id") or "") == str(candidate_id or ""):
            return candidate
    return None


def _loop_history_payload(history: list[dict[str, Any]]) -> dict[str, Any]:
    modules = []
    actions = []
    for item in history:
        action = item.get("action") if isinstance(item.get("action"), dict) else {}
        module = str(action.get("selected_module") or "")
        if module:
            modules.append(module)
        action_name = str(action.get("action") or "")
        if action_name:
            actions.append(action_name)
    return {
        "policy_loop": list(history),
        "previous_modules": modules,
        "previous_actions": actions,
    }


def _loop_stop_result(
    job: RepairJob,
    state: ArchiveState | None,
    diagnosis: dict[str, Any],
    selection: dict[str, Any],
    history: list[dict[str, Any]],
    warnings: list[str],
    *,
    reason: str,
    batch: RepairCandidateBatch | None = None,
    recovery: PolicyRecoverySnapshot | None = None,
) -> RepairResult:
    patch_depth = state.patch_depth() if state is not None else 0
    recovery_score = float(recovery.score or 0.0) if recovery is not None else 0.0
    decision_hint = recovery.decision_hint if recovery is not None else ""
    if recovery_score >= 0.999 or decision_hint == "accept":
        status = "repaired"
    elif recovery_score > 0.0 or patch_depth > 0:
        status = "partial"
    else:
        status = "skipped"
    repaired_input = _state_source_input(state, job) if state is not None else dict(job.source_input or {})
    payload = _diagnosis_with_candidate_selection(diagnosis, selection)
    payload["policy_loop"] = {
        "terminal_action": "stop",
        "stop_reason": reason,
        "rounds": list(history),
        "patch_depth": patch_depth,
        "patch_digest": state.effective_patch_digest() if state is not None else "",
        "recovery": recovery.to_dict() if recovery is not None else {},
    }
    result = RepairResult(
        status=status,
        confidence=float(job.confidence or 0.0),
        format=job.format,
        repaired_input=repaired_input,
        repaired_state=state if status in {"repaired", "partial"} and state is not None else None,
        actions=["policy_stop"],
        damage_flags=list(job.damage_flags),
        warnings=_dedupe(warnings),
        partial=status == "partial",
        module_name="policy_stop",
        diagnosis=payload,
        message=reason,
    )
    if batch is not None:
        return replace(result, warnings=_dedupe([*result.warnings, *batch.warnings]))
    return result


def _loop_give_up_result(
    job: RepairJob,
    diagnosis: dict[str, Any],
    selection: dict[str, Any],
    history: list[dict[str, Any]],
    warnings: list[str],
    *,
    reason: str,
    recovery: PolicyRecoverySnapshot | None = None,
) -> RepairResult:
    payload = _diagnosis_with_candidate_selection(diagnosis, selection)
    payload["policy_loop"] = {
        "terminal_action": "give_up",
        "stop_reason": reason,
        "rounds": list(history),
        "recovery": recovery.to_dict() if recovery is not None else {},
    }
    return RepairResult(
        status="unrepairable",
        confidence=float(job.confidence or 0.0),
        format=job.format,
        actions=["policy_give_up"],
        damage_flags=list(job.damage_flags),
        warnings=_dedupe(warnings),
        module_name="policy_give_up",
        diagnosis=payload,
        message=reason,
    )


def _loop_recovery_score(job: RepairJob) -> float:
    return recovery_score_from_job(job)


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


def _terminal_result_allows_policy_noop(result: RepairResult | None) -> bool:
    if result is None:
        return False
    return str(getattr(result, "status", "") or "") in {"unrepairable", "unsupported"}


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
