from dataclasses import replace
from contextlib import nullcontext
import json
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.repair.candidate import CandidateSelector, CandidateValidation, RepairCandidate, RepairCandidateBatch, candidate_feature_payload, materialize_candidate, materialize_candidates
from sunpack.repair.capability import ModuleCapabilityDecision, RepairCapabilityDecision
from sunpack.repair.config import enabled_module_configs, repair_config
from sunpack.repair.context import RepairContext, build_repair_context
from sunpack.repair.control_candidates import is_accept_current_state_candidate, with_accept_current_state_candidate
from sunpack.repair.diagnosis import RepairDiagnosis, diagnose_repair_job
from sunpack.repair.formats import canonical_format as _normalize_format
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairRoute
from sunpack.repair.pipeline.modules._common import job_source_size, repair_operation_cache_key
from sunpack.repair.pipeline.registry import discover_repair_modules, get_repair_module_registry
from sunpack.repair.search.features import (
    archive_state_for_job,
    candidate_snapshot,
    recovery_score_from_job,
    runtime_context_from_job,
    state_source_input,
)
from sunpack.repair.search.recovery import PolicyRecoverySnapshot, RecoveryEvaluator
from sunpack.repair.search.graph import (
    PolicyRepairGraph,
    best_node_id as graph_best_node_id,
    find_node_by_digest as graph_find_node_by_digest,
    policy_graph_edge_id,
    policy_graph_node_id,
    remove_frontier as graph_remove_frontier,
)
from sunpack.repair.search.types import PolicyExplorationGraph, PolicyGraphEdge, PolicyGraphNode
from sunpack.repair.search.proposals import available_module_proposals, materialize_module_proposal
from sunpack.repair.result import RepairResult
from sunpack.repair.runtime_cache import RepairRuntimeCache
from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.support import archive_knowledge_projection as knowledge_view
from sunpack.support.archive_state_view import ArchiveStateByteView
from sunpack.support import repair_trace

if TYPE_CHECKING:
    from sunpack.repair.model.runtime import RepairModelRuntime


class RepairScheduler:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = repair_config(config or {})
        self._module_selection_cache: dict[tuple[Any, ...], tuple[list[Any], RepairCapabilityDecision]] = {}
        cache_config = self.config.get("runtime_cache") if isinstance(self.config.get("runtime_cache"), dict) else {}
        self.repair_cache = RepairRuntimeCache(
            enabled=bool(cache_config.get("enabled", True)),
            max_entries=int(cache_config.get("max_entries", 512) or 512),
        )
        self.model_runtime = self._build_model_runtime()
        discover_repair_modules()
        self._validate_configured_modules()

    def _build_model_runtime(self) -> "RepairModelRuntime":
        from sunpack.repair.model.runtime import RepairModelRuntime

        return RepairModelRuntime(self.config)

    def _validate_configured_modules(self) -> None:
        registry_names = set(get_repair_module_registry().all())
        if not registry_names:
            return
        configured = set(enabled_module_configs(self.config))
        unknown = sorted(configured - registry_names)
        if unknown:
            joined = ", ".join(unknown)
            raise ValueError(f"Unknown repair module configured: {joined}")

    def diagnose(self, job: RepairJob, *, knowledge: ArchiveKnowledge | None = None) -> RepairDiagnosis:
        return diagnose_repair_job(job, knowledge=knowledge)

    def repair(self, job: RepairJob) -> RepairResult:
        if self.model_runtime.active_for_job(job):
            return self.repair_policy_step(job)
        status = self.model_runtime.status_for_job(job)
        return RepairResult(
            status="unsupported",
            confidence=float(job.confidence or 0.0),
            format=job.format,
            repaired_input=dict(job.source_input or {}),
            actions=["policy_unavailable"],
            damage_flags=list(job.damage_flags),
            warnings=[str(status.get("fallback_reason") or "policy_unavailable")],
            module_name="policy_unavailable",
            diagnosis={"policy": status},
            message="repair policy graph runtime is unavailable",
        )

    def repair_policy_step(self, job: RepairJob) -> RepairResult:
        current_state = _job_archive_state(job)
        current_job = replace(
            job,
            archive_state=current_state,
            source_input=dict(job.source_input or {}),
            repair_cache=job.repair_cache or self.repair_cache,
        )
        recovery_evaluator = RecoveryEvaluator(self.config)
        current_recovery = recovery_evaluator.evaluate_state(current_job, current_state, mode="policy_light")
        repair_graph = _policy_repair_graph_from_job(current_job, current_state, current_recovery)
        graph = repair_graph.graph
        current_node = graph.current_node()
        if current_node is None:
            root_digest = current_state.effective_patch_digest() if current_state is not None else ""
            root_id = _policy_graph_node_id(root_digest, 0)
            current_node = PolicyGraphNode(
                node_id=root_id,
                patch_digest=root_digest,
                archive_state=current_state,
                recovery=current_recovery.to_dict(),
            )
            graph.nodes[root_id] = current_node
            graph.current_node_id = root_id
            graph.best_node_id = graph.best_node_id or root_id
        current_node.archive_state = current_state
        current_node.patch_digest = current_state.effective_patch_digest() if current_state is not None else current_node.patch_digest
        policy_config = self.config.get("policy") if isinstance(self.config.get("policy"), dict) else {}
        round_index = max(1, int(job.attempts or 0) + 1)
        diagnosis_payload: dict[str, Any] = {"format": current_job.format, "confidence": current_job.confidence}
        warnings: list[str] = []
        diagnosis_hgt, diagnosis_selection = self.model_runtime.diagnose_state(
            job=current_job,
            archive_state=current_state,
            graph=graph,
            recovery=current_recovery.to_dict(),
            round_index=round_index,
        )
        if not diagnosis_hgt:
            return RepairResult(
                status="unsupported",
                confidence=float(current_job.confidence or 0.0),
                format=current_job.format,
                repaired_input=dict(current_job.source_input or {}),
                actions=["diagnosis_hgt_unavailable"],
                damage_flags=list(current_job.damage_flags),
                warnings=[str(diagnosis_selection.get("fallback_reason") or "diagnosis_hgt_unavailable")],
                module_name="diagnosis_hgt_unavailable",
                diagnosis={"policy_loop": {"policy_step": True, "error": "diagnosis_hgt_unavailable", "graph": graph.to_dict(), "diagnosis_selection": diagnosis_selection}},
                message="diagnosis HGT runtime is unavailable",
            )
        repair_graph.observe_current_state(
            recovery=current_recovery,
            diagnosis_hgt=diagnosis_hgt,
            verification=_verification_from_job(current_job),
            min_improvement=float(policy_config.get("min_best_recovery_improvement", self.config.get("min_recovery_improvement", 0.0)) or 0.0),
        )
        stop_readiness = repair_graph.stop_readiness(
            stale_patience=int(policy_config.get("graph_stop_stale_patience", 0) or 0),
        )

        proposals = available_module_proposals(
            scheduler=self,
            job=current_job,
            diagnosis_hgt=diagnosis_hgt,
            graph=graph,
        )
        module_action_payloads = [proposal.to_action_payload() for proposal in proposals]
        exposed_edges = repair_graph.register_proposals(module_action_payloads, step=round_index)
        exposed_candidate_ids = {edge.candidate_id for edge in exposed_edges}
        proposals = [proposal for proposal in proposals if proposal.action_id in exposed_candidate_ids]
        proposal_by_action_id = {proposal.action_id: proposal for proposal in proposals}
        action_payloads = [proposal.to_action_payload() for proposal in proposals]
        suppress_repeat_undo = _latest_policy_action_type(current_job) == "undo" and bool(action_payloads)
        if current_node.parent_id and not suppress_repeat_undo:
            action_payloads.append({"action_type": "undo", "action_id": "undo", "module_name": ""})
        action_payloads.append({"action_type": "stop", "action_id": "stop", "module_name": ""})
        best_node = graph.best_node() or current_node
        if stop_readiness.get("should_force_stop"):
            action_scores = []
            action_selection = {"decision_status": "forced_stop", "reason": stop_readiness.get("force_stop_reason")}
            selected_action = None
        else:
            action_scores, action_selection = self.model_runtime.score_graph_actions(
                job=current_job,
                archive_state=current_state,
                graph=graph,
                available_actions=action_payloads,
                diagnosis_hgt=diagnosis_hgt,
                current_recovery=current_recovery.to_dict(),
                best_seen_recovery=dict((best_node.recovery if best_node is not None else {}) or {}),
                round_index=round_index,
            )
            selected_action = max(action_scores, key=lambda item: float(item.score or 0.0), default=None)
            if selected_action is None:
                return RepairResult(
                    status="unsupported",
                    confidence=float(current_job.confidence or 0.0),
                    format=current_job.format,
                    repaired_input=dict(current_job.source_input or {}),
                    actions=["policy_graph_scorer_unavailable"],
                    damage_flags=list(current_job.damage_flags),
                    warnings=[str(action_selection.get("fallback_reason") or "policy_graph_scorer_unavailable")],
                    module_name="policy_graph_scorer_unavailable",
                    diagnosis={"policy_loop": {"policy_step": True, "error": "policy_graph_scorer_unavailable", "graph": graph.to_dict(), "diagnosis_hgt": diagnosis_hgt, "action_selection": action_selection}},
                    message="policy graph scorer runtime is unavailable",
                )
        if selected_action is not None:
            _policy_graph_update_action_scores(graph, [score.to_dict() for score in action_scores])
        graph_action = (
            {"action_type": "stop", "reason": stop_readiness.get("force_stop_reason") or "graph_stale_best"}
            if stop_readiness.get("should_force_stop")
            else selected_action.to_dict() if selected_action is not None else {"action_type": "stop", "reason": "no_action"}
        )
        repair_trace.write_probe_event("policy_probe_action_scores", {
            "run_id": _policy_probe_run_id(),
            "query_id": f"{current_job.archive_key or current_job.source_path or ''}:policy_step:{round_index}",
            "format": current_job.format,
            "round": int(round_index),
            "current_node_id": graph.current_node_id,
            "best_node_id": graph.best_node_id,
            "proposal_count": len(proposals),
            "available_action_count": len(action_payloads),
            "diagnosis_root_ranked": _policy_probe_root_ranked(diagnosis_hgt),
            "selected_action": dict(graph_action),
            "top_action_scores": [
                score.to_dict()
                for score in sorted(action_scores, key=lambda item: float(item.score or 0.0), reverse=True)[:12]
            ],
            "graph_summary": graph.summary(),
            "stop_readiness": stop_readiness,
        })
        selection = {
            "policy_step": True,
            "diagnosis_hgt_model": diagnosis_selection,
            "policy_graph_scorer": action_selection,
            "graph_action": graph_action,
            "diagnosis_hgt": diagnosis_hgt,
            "candidate_count": len(proposals),
            "proposal_count": len(proposals),
            "actions": action_payloads,
            "graph_summary": graph.summary(),
            "stop_readiness": stop_readiness,
        }
        history = [{
            "round": round_index,
            "node_id": current_node.node_id,
            "patch_digest": current_state.effective_patch_digest() if current_state is not None else "",
            "patch_depth": current_state.patch_depth() if current_state is not None else 0,
            "diagnosis_hgt": diagnosis_hgt,
            "current_recovery": current_recovery.to_dict(),
            "best_seen_recovery": dict((best_node.recovery if best_node is not None else {}) or {}),
            "actions": action_payloads,
            "graph_action": graph_action,
            "graph_summary": graph.summary(),
            "policy_graph_scorer": action_selection,
            "stop_readiness": stop_readiness,
        }]
        action_type = str(graph_action.get("action_type") or "")
        if action_type == "stop":
            repair_graph.stop_best()
            return _loop_graph_finish_result(
                current_job,
                graph,
                diagnosis_payload,
                selection,
                history,
                warnings,
                reason=str(graph_action.get("reason") or "policy_step_stop"),
                terminal_action="stop",
                batch=None,
                recovery=PolicyRecoverySnapshot.from_dict((graph.best_node() or current_node).recovery) if (graph.best_node() or current_node).recovery else current_recovery,
                current_state=current_state,
                current_recovery=current_recovery,
            )
        if action_type == "undo":
            op = repair_graph.undo(step=round_index)
            if op.archive_state is None:
                return _policy_step_no_patch_result(current_job, graph, diagnosis_payload, selection, history, "checkout_target_missing", warnings)
            return _policy_step_state_result(current_job, graph, op.archive_state, diagnosis_payload, selection, history, "policy_undo", warnings, operation=op)
        if action_type != "module":
            return _policy_step_no_patch_result(current_job, graph, diagnosis_payload, selection, history, "policy_step_no_action", warnings)
        action_id = str(graph_action.get("action_id") or "")
        proposal = proposal_by_action_id.get(action_id)
        if proposal is None:
            module_name = str(graph_action.get("module_name") or "")
            proposal = next((item for item in proposals if item.module_name == module_name), None)
            if proposal is not None:
                action_id = proposal.action_id
        if proposal is None:
            return _policy_step_no_patch_result(current_job, graph, diagnosis_payload, selection, history, "selected_proposal_missing", warnings)
        edge_id = policy_graph_edge_id(current_node.node_id, action_id)
        materialized = materialize_module_proposal(
            scheduler=self,
            proposal=proposal,
            job=current_job,
        )
        op = repair_graph.forward(
            candidate_id=action_id,
            module_name=proposal.module_name,
            materialized_candidate=materialized.candidate,
            failure=materialized.failure,
            step=round_index,
        )
        _attach_selected_prediction(graph, op.edge_id or edge_id, selected_action.to_dict() if selected_action is not None else {}, round_index)
        if op.archive_state is None:
            return _policy_step_no_patch_result(current_job, graph, diagnosis_payload, selection, history, "proposal_missing_repaired_state", warnings)
        return _policy_step_state_result(
            current_job,
            graph,
            op.archive_state,
            diagnosis_payload,
            selection,
            history,
            op.module_name or proposal.module_name or "policy_module",
            warnings,
            candidate=materialized.candidate,
            operation=op,
        )

    def policy_active_for_job(self, job: RepairJob) -> bool:
        return self.model_runtime.active_for_job(job)

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
    selected_scoreity = selection.get("generation_priority")
    selected = set()
    for item in features:
        if str(item.get("module") or "") != selected_module:
            continue
        if selected_scoreity is None or _float_equal(item.get("generation_priority"), selected_scoreity):
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
) -> dict[str, Any]:
    return candidate_snapshot(
        candidate,
        index=index,
        damage_analysis=damage_analysis,
    )


def _policy_candidate_available(candidate: RepairCandidate) -> bool:
    if candidate.is_lazy:
        return True
    return candidate.repaired_state is not None


def _policy_select_materialized_candidate(candidates: list[RepairCandidate]) -> RepairCandidate | None:
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda candidate: (
            float(candidate.score_hint or 0.0),
            float(candidate.confidence or 0.0),
            0 if candidate.partial else 1,
        ),
    )


def _policy_materialization_errors(candidates: list[RepairCandidate]) -> list[str]:
    errors: list[str] = []
    for candidate in candidates:
        diagnosis = candidate.diagnosis if isinstance(candidate.diagnosis, dict) else {}
        error = str(diagnosis.get("materialization_error") or "")
        if error:
            errors.append(error)
            continue
        errors.extend(str(item) for item in candidate.warnings or [] if str(item))
    return _dedupe(errors)


def _policy_graph_from_job(job: RepairJob, current_state: ArchiveState | None, current_recovery: PolicyRecoverySnapshot) -> PolicyExplorationGraph:
    graph_payload = _latest_policy_graph_payload(job)
    graph = _policy_graph_from_payload(graph_payload)
    if graph.nodes:
        current_digest = current_state.effective_patch_digest() if current_state is not None else ""
        node_id = _policy_graph_find_node_by_digest(graph, current_digest)
        if node_id:
            graph.current_node_id = node_id
            node = graph.nodes[node_id]
            node.archive_state = current_state
            node.patch_digest = current_digest
            if not node.recovery:
                node.recovery = current_recovery.to_dict()
        graph.best_node_id = _policy_graph_best_node_id(graph, fallback=graph.current_node_id)
        return graph
    root_digest = current_state.effective_patch_digest() if current_state is not None else ""
    root_id = _policy_graph_node_id(root_digest, 0)
    return PolicyExplorationGraph(
        nodes={
            root_id: PolicyGraphNode(
                node_id=root_id,
                patch_digest=root_digest,
                archive_state=current_state,
                recovery=current_recovery.to_dict(),
                created_round=0,
            )
        },
        current_node_id=root_id,
        best_node_id=root_id,
    )


def _policy_repair_graph_from_job(job: RepairJob, current_state: ArchiveState | None, current_recovery: PolicyRecoverySnapshot) -> PolicyRepairGraph:
    graph_payload = _latest_policy_graph_payload(job)
    repair_graph = PolicyRepairGraph.from_payload(graph_payload) if graph_payload else PolicyRepairGraph.initialize(job, current_recovery)
    graph = repair_graph.graph
    current_digest = current_state.effective_patch_digest() if current_state is not None else ""
    if graph.nodes:
        node_id = graph_find_node_by_digest(graph, current_digest)
        if node_id:
            graph.current_node_id = node_id
            node = graph.nodes[node_id]
            node.archive_state = current_state
            node.patch_digest = current_digest
            node.recovery = current_recovery.to_dict()
        elif graph.current_node_id in graph.nodes:
            parent_id = graph.current_node_id
            node_id = _policy_graph_node_id(current_digest, len(graph.nodes))
            graph.nodes[node_id] = PolicyGraphNode(
                node_id=node_id,
                parent_id=parent_id,
                patch_digest=current_digest,
                archive_state=current_state,
                recovery=current_recovery.to_dict(),
                status="active",
                created_round=0,
                created_step=0,
                module_name="external_policy_state",
                patch_status="applied",
            )
            graph.current_node_id = node_id
        graph.best_node_id = graph_best_node_id(graph) or graph.current_node_id
        return repair_graph
    return PolicyRepairGraph.initialize(job, current_recovery)


def _latest_policy_graph_payload(job: RepairJob) -> dict[str, Any]:
    sources = []
    if isinstance(job.repair_history, dict):
        sources.append(job.repair_history)
    if isinstance(job.knowledge, dict):
        repair = job.knowledge.get("repair")
        if isinstance(repair, dict):
            history = repair.get("history")
            if isinstance(history, dict):
                sources.append(history)
    for source in sources:
        items = source.get("items") if isinstance(source.get("items"), list) else []
        for item in reversed(items):
            diagnosis = item.get("diagnosis") if isinstance(item, dict) and isinstance(item.get("diagnosis"), dict) else {}
            loop = diagnosis.get("policy_loop") if isinstance(diagnosis.get("policy_loop"), dict) else {}
            graph = loop.get("graph") if isinstance(loop.get("graph"), dict) else {}
            if graph:
                return graph
    return {}


def _latest_policy_action_type(job: RepairJob) -> str:
    sources = []
    if isinstance(job.repair_history, dict):
        sources.append(job.repair_history)
    if isinstance(job.knowledge, dict):
        repair = job.knowledge.get("repair")
        if isinstance(repair, dict):
            history = repair.get("history")
            if isinstance(history, dict):
                sources.append(history)
    for source in sources:
        items = source.get("items") if isinstance(source.get("items"), list) else []
        for item in reversed(items):
            diagnosis = item.get("diagnosis") if isinstance(item, dict) and isinstance(item.get("diagnosis"), dict) else {}
            loop = diagnosis.get("policy_loop") if isinstance(diagnosis.get("policy_loop"), dict) else {}
            rounds = loop.get("rounds") if isinstance(loop.get("rounds"), list) else []
            for round_payload in reversed(rounds):
                if not isinstance(round_payload, dict):
                    continue
                action = round_payload.get("graph_action") if isinstance(round_payload.get("graph_action"), dict) else {}
                action_type = str(action.get("action_type") or "")
                if action_type:
                    return action_type
            action = loop.get("graph_action") if isinstance(loop.get("graph_action"), dict) else {}
            action_type = str(action.get("action_type") or "")
            if action_type:
                return action_type
    return ""


def _policy_graph_from_payload(payload: dict[str, Any]) -> PolicyExplorationGraph:
    if not isinstance(payload, dict):
        return PolicyExplorationGraph()
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
        archive_state = None
        if isinstance(raw.get("archive_state"), dict) and raw.get("archive_state"):
            try:
                archive_state = ArchiveState.from_dict(raw["archive_state"])
            except Exception:
                archive_state = None
        graph.nodes[str(node_id)] = PolicyGraphNode(
            node_id=str(raw.get("node_id") or node_id),
            parent_id=str(raw.get("parent_id") or ""),
            patch_digest=str(raw.get("patch_digest") or ""),
            archive_state=archive_state,
            recovery=dict(raw.get("recovery") or {}),
            status=str(raw.get("status") or "active"),
            created_round=int(raw.get("created_round") or 0),
            expanded_candidate_ids={str(item) for item in raw.get("expanded_candidate_ids") or [] if str(item)},
            exploration=dict(raw.get("exploration") or {}),
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
            exploration=dict(raw.get("exploration") or {}),
        )
    graph.frontier = [edge_id for edge_id in graph.frontier if edge_id in graph.edges and graph.edges[edge_id].status == "frontier"]
    if not graph.current_node_id or graph.current_node_id not in graph.nodes:
        graph.current_node_id = next(iter(graph.nodes), "")
    if not graph.best_node_id or graph.best_node_id not in graph.nodes:
        graph.best_node_id = graph.current_node_id
    return graph


def _policy_graph_best_node_id(graph: PolicyExplorationGraph, *, fallback: str = "") -> str:
    best_id = graph.best_node_id if graph.best_node_id in graph.nodes else fallback
    best_score = -1.0
    for node_id, node in graph.nodes.items():
        try:
            score = float((node.recovery or {}).get("score") or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        if score > best_score:
            best_id = node_id
            best_score = score
    return best_id or fallback


def _policy_step_state_result(
    job: RepairJob,
    graph: PolicyExplorationGraph,
    state: ArchiveState,
    diagnosis: dict[str, Any],
    selection: dict[str, Any],
    history: list[dict[str, Any]],
    module_name: str,
    warnings: list[str],
    *,
    candidate: RepairCandidate | None = None,
    operation: Any | None = None,
) -> RepairResult:
    payload = _diagnosis_with_candidate_selection(diagnosis, selection)
    payload["policy_loop"] = {
        "policy_step": True,
        "terminal_action": "",
        "stop_reason": "",
        "rounds": list(history),
        "patch_depth": state.patch_depth(),
        "patch_digest": state.effective_patch_digest(),
        "graph_summary": graph.summary(),
        "graph": graph.to_dict(),
        "current_node_id": graph.current_node_id,
        "best_node_id": graph.best_node_id,
        "final_state_selection": "current_step_state",
    }
    if operation is not None:
        payload["policy_loop"]["graph_operation"] = {
            "action": getattr(operation, "action", ""),
            "node_id": getattr(operation, "node_id", ""),
            "edge_id": getattr(operation, "edge_id", ""),
            "module_name": getattr(operation, "module_name", ""),
            "patch_status": getattr(operation, "patch_status", ""),
            "diagnostics": dict(getattr(operation, "diagnostics", {}) or {}),
        }
    base = candidate.to_result(selection={"selected_module": candidate.module_name}) if candidate is not None else None
    patch_status = str(getattr(operation, "patch_status", "") or "")
    status = "partial"
    partial = True
    if patch_status in {"empty_failed", "empty_noop", "repeated"}:
        status = "partial"
        partial = True
    return RepairResult(
        status=status,
        confidence=float((base.confidence if base is not None else job.confidence) or 0.0),
        format=job.format,
        repaired_input=_state_source_input(state, job),
        repaired_state=state,
        actions=list(base.actions if base is not None else [module_name]),
        damage_flags=list(job.damage_flags),
        warnings=_dedupe([*warnings, *list(base.warnings if base is not None else [])]),
        partial=partial,
        module_name=module_name,
        diagnosis=payload,
        message=module_name,
    )


def _policy_step_no_patch_result(
    job: RepairJob,
    graph: PolicyExplorationGraph,
    diagnosis: dict[str, Any],
    selection: dict[str, Any],
    history: list[dict[str, Any]],
    reason: str,
    warnings: list[str],
) -> RepairResult:
    payload = _diagnosis_with_candidate_selection(diagnosis, selection)
    payload["policy_loop"] = {
        "policy_step": True,
        "terminal_action": "",
        "stop_reason": reason,
        "rounds": list(history),
        "graph_summary": graph.summary(),
        "graph": graph.to_dict(),
        "current_node_id": graph.current_node_id,
        "best_node_id": graph.best_node_id,
        "final_state_selection": "no_patch",
    }
    return RepairResult(
        status="skipped",
        confidence=float(job.confidence or 0.0),
        format=job.format,
        repaired_input=dict(job.source_input or {}),
        actions=["policy_no_patch"],
        damage_flags=list(job.damage_flags),
        warnings=_dedupe(warnings),
        module_name="policy_no_patch",
        diagnosis=payload,
        message=reason,
    )


def _policy_graph_node_id(patch_digest: str, index: int) -> str:
    digest = str(patch_digest or "root")
    return f"node_{digest[:32]}"


def _policy_graph_edge_id(node_id: str, candidate_id: str) -> str:
    return f"{node_id}::{candidate_id}"


def _policy_graph_find_node_by_digest(graph: PolicyExplorationGraph, patch_digest: str) -> str:
    digest = str(patch_digest or "")
    for node_id, node in graph.nodes.items():
        if node.patch_digest == digest:
            return node_id
    return ""


def _policy_graph_remove_frontier(graph: PolicyExplorationGraph, edge_id: str) -> None:
    graph.frontier = [item for item in graph.frontier if item != edge_id]


def _policy_graph_register_frontier(
    graph: PolicyExplorationGraph,
    *,
    current_node: PolicyGraphNode,
    candidate_payloads: list[dict[str, Any]],
    round_index: int,
) -> None:
    for payload in candidate_payloads:
        candidate_id = str(payload.get("candidate_id") or "")
        if not candidate_id or candidate_id in current_node.expanded_candidate_ids:
            continue
        edge_id = _policy_graph_edge_id(current_node.node_id, candidate_id)
        if edge_id in graph.edges:
            edge = graph.edges[edge_id]
            if edge.status == "frontier" and edge_id not in graph.frontier:
                graph.frontier.append(edge_id)
            continue
        edge = PolicyGraphEdge(
            edge_id=edge_id,
            from_node_id=current_node.node_id,
            candidate_id=candidate_id,
            module_name=str(payload.get("module_name") or payload.get("module") or ""),
            module_family=str(payload.get("module_family") or payload.get("route_family") or payload.get("atomic_action_group") or payload.get("module_name") or payload.get("module") or ""),
            status="frontier",
            created_round=round_index,
        )
        graph.edges[edge_id] = edge
        graph.frontier.append(edge_id)


def _policy_graph_update_edge_scores(graph: PolicyExplorationGraph, step_action_selection: dict[str, Any]) -> None:
    scores: list[dict[str, Any]] = []
    if isinstance(step_action_selection.get("action_scores"), list):
        scores.extend(item for item in step_action_selection.get("action_scores", []) if isinstance(item, dict))
    if isinstance(step_action_selection.get("raw_action_scores"), list):
        scores.extend(item for item in step_action_selection.get("raw_action_scores", []) if isinstance(item, dict))
    for score in scores:
        for edge in graph.edges.values():
            if str(score.get("edge_id") or "") == edge.edge_id or str(score.get("candidate_id") or "") == edge.candidate_id:
                merged = dict(edge.action_score or {})
                merged.update({key: value for key, value in score.items() if value is not None})
                edge.action_score = merged


def _policy_graph_update_action_scores(graph: PolicyExplorationGraph, scores: list[dict[str, Any]]) -> None:
    for score in scores:
        action_id = str(score.get("action_id") or score.get("candidate_id") or "")
        module_name = str(score.get("module_name") or score.get("module") or "")
        if not action_id and not module_name:
            continue
        for edge in graph.edges.values():
            if action_id and edge.candidate_id != action_id:
                continue
            if not action_id and module_name and edge.module_name != module_name:
                continue
            merged = dict(edge.action_score or {})
            merged.update({key: value for key, value in score.items() if value is not None})
            if "score" in merged and "logic_score" not in merged:
                merged["logic_score"] = merged["score"]
            edge.action_score = merged
            metadata = score.get("metadata") if isinstance(score.get("metadata"), dict) else {}
            prediction = metadata.get("predicted_next_state") if isinstance(metadata.get("predicted_next_state"), dict) else {}
            if prediction:
                edge.predicted_next_state = dict(prediction)
                edge.prediction_model_version = str(metadata.get("model_id") or "repair_policy_transformer")
            uncertainty = metadata.get("predicted_uncertainty") if isinstance(metadata.get("predicted_uncertainty"), dict) else {}
            if uncertainty:
                merged_uncertainty = dict(edge.uncertainty or {})
                merged_uncertainty.update(uncertainty)
                edge.uncertainty = merged_uncertainty


def _attach_selected_prediction(graph: PolicyExplorationGraph, edge_id: str, action: dict[str, Any], round_index: int) -> None:
    edge = graph.edges.get(str(edge_id or ""))
    if edge is None:
        return
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    prediction = metadata.get("predicted_next_state") if isinstance(metadata.get("predicted_next_state"), dict) else {}
    if not prediction:
        return
    edge.predicted_next_state = dict(prediction)
    edge.prediction_model_version = str(metadata.get("model_id") or "repair_policy_transformer")
    edge.predicted_at_step = int(round_index or 0)
    uncertainty = metadata.get("predicted_uncertainty") if isinstance(metadata.get("predicted_uncertainty"), dict) else {}
    if uncertainty:
        merged_uncertainty = dict(edge.uncertainty or {})
        merged_uncertainty.update(uncertainty)
        edge.uncertainty = merged_uncertainty


def _policy_probe_root_ranked(diagnosis_hgt: dict[str, Any], *, limit: int = 8) -> list[dict[str, Any]]:
    root = diagnosis_hgt.get("root_case") if isinstance(diagnosis_hgt.get("root_case"), dict) else {}
    ranked = root.get("ranked") if isinstance(root.get("ranked"), list) else []
    output: list[dict[str, Any]] = []
    for item in ranked[:limit]:
        if not isinstance(item, dict):
            continue
        try:
            score = float(item.get("score") or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        output.append({"root_case": str(item.get("root_case") or ""), "score": score})
    if output:
        return output
    scores = root.get("scores") if isinstance(root.get("scores"), dict) else {}
    pairs = []
    for key, value in scores.items():
        try:
            pairs.append((str(key), float(value or 0.0)))
        except (TypeError, ValueError):
            pairs.append((str(key), 0.0))
    return [{"root_case": key, "score": value} for key, value in sorted(pairs, key=lambda item: item[1], reverse=True)[:limit]]


def _policy_probe_run_id() -> str:
    import os

    return str(os.environ.get("SUNPACK_REPAIR_POLICY_PROBE_RUN_ID") or "")


def _verification_from_job(job: RepairJob) -> dict[str, Any]:
    knowledge = ArchiveKnowledge.from_any(getattr(job, "knowledge", {}))
    payload = knowledge.to_dict()
    verification = payload.get("verification") if isinstance(payload.get("verification"), dict) else {}
    summary = verification.get("summary") if isinstance(verification.get("summary"), dict) else {}
    coverage = verification.get("coverage_breakdown") if isinstance(verification.get("coverage_breakdown"), dict) else {}
    return {
        "summary": dict(summary),
        "coverage_breakdown": dict(coverage),
    }


def _policy_graph_frontier_top(graph: PolicyExplorationGraph, *, limit: int = 5) -> list[dict[str, Any]]:
    edges = sorted(graph.active_frontier_edges(), key=_policy_graph_edge_score, reverse=True)
    return [edge.to_dict() for edge in edges[: max(0, int(limit or 0))]]


def _policy_graph_edge_score(edge: PolicyGraphEdge) -> float:
    action_score = edge.action_score or {}
    for key in ("final_score", "arbiter_score", "logic_score"):
        try:
            value = action_score.get(key)
            if value is not None:
                return float(value)
        except (TypeError, ValueError):
            pass
    return 0.0


def _policy_graph_best_frontier_edge(graph: PolicyExplorationGraph) -> PolicyGraphEdge | None:
    edges = graph.active_frontier_edges()
    if not edges:
        return None
    return max(edges, key=_policy_graph_edge_score)


def _policy_graph_frontier_summary(graph: PolicyExplorationGraph) -> dict[str, Any]:
    edges = graph.active_frontier_edges()
    modules: dict[str, int] = {}
    scores: list[float] = []
    for edge in edges:
        if edge.module_name:
            modules[edge.module_name] = modules.get(edge.module_name, 0) + 1
        scores.append(_policy_graph_edge_score(edge))
    return {
        "frontier_count": len(edges),
        "module_counts": modules,
        "max_logic_score": max(scores, default=0.0),
        "mean_logic_score": sum(scores) / max(1, len(scores)),
    }


def _candidate_value_budget(config: dict[str, Any], round_index: int) -> int:
    repair_config = config.get("repair") if isinstance(config.get("repair"), dict) else {}
    policy = repair_config.get("policy") if isinstance(repair_config.get("policy"), dict) else config.get("policy")
    policy = policy if isinstance(policy, dict) else {}
    arbiter = policy.get("arbiter") if isinstance(policy.get("arbiter"), dict) else {}
    if int(round_index or 0) <= 1:
        return max(0, int(arbiter.get("candidate_value_budget_root", policy.get("candidate_value_budget_root", 4)) or 0))
    return max(0, int(arbiter.get("candidate_value_budget_branch", policy.get("candidate_value_budget_branch", 2)) or 0))


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


def _policy_loop_stop_plateau_satisfied(
    *,
    round_index: int,
    max_rounds: int,
    best_round_index: int,
    current_recovery: PolicyRecoverySnapshot,
    config: dict[str, Any],
) -> bool:
    policy = config.get("policy") if isinstance(config.get("policy"), dict) else {}
    ratio = float(policy.get("stop_plateau_window_ratio", 0.5) or 0.5)
    minimum = max(1, int(policy.get("stop_plateau_min_rounds", 2) or 2))
    window = max(minimum, int(max(1, max_rounds) * max(0.0, ratio) + 0.999999))
    return max(0, int(round_index) - int(best_round_index)) >= window


def _evaluate_policy_best_state_recovery(
    evaluator: RecoveryEvaluator,
    job: RepairJob,
    state: ArchiveState | None,
    fallback: PolicyRecoverySnapshot,
    config: dict[str, Any],
    cache: dict[str, PolicyRecoverySnapshot],
) -> PolicyRecoverySnapshot:
    if state is None:
        return fallback
    policy = config.get("policy") if isinstance(config.get("policy"), dict) else {}
    mode = str(policy.get("best_state_recovery_mode") or "policy_full")
    if mode not in {"policy_light", "policy_full", "training_oracle"}:
        mode = "policy_full"
    if mode == "policy_light":
        return fallback
    evaluated = evaluator.evaluate_state(job, state, mode=mode, cache=cache)
    source = str((evaluated.metadata or {}).get("score_source") or "")
    if float(evaluated.score or 0.0) <= 0.0 and source in {"", "none", "error"} and float(fallback.score or 0.0) > 0.0:
        return fallback
    return evaluated


def _policy_recovery_tie_breaks_best(
    recovery: PolicyRecoverySnapshot,
    best_recovery: PolicyRecoverySnapshot,
    *,
    depth: int,
    best_depth: int,
) -> bool:
    source = str((recovery.metadata or {}).get("score_source") or "")
    best_source = str((best_recovery.metadata or {}).get("score_source") or "")
    if source == "native_validation_capped" and best_source == "native_validation_capped":
        native_score = _native_validation_raw_score(recovery.native_validation)
        best_native_score = _native_validation_raw_score(best_recovery.native_validation)
        if native_score != best_native_score:
            return native_score > best_native_score
        return depth < best_depth
    return depth > best_depth


def _native_validation_raw_score(payload: dict[str, Any]) -> float:
    try:
        return float((payload or {}).get("score") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _loop_graph_finish_result(
    job: RepairJob,
    graph: PolicyExplorationGraph,
    diagnosis: dict[str, Any],
    selection: dict[str, Any],
    history: list[dict[str, Any]],
    warnings: list[str],
    *,
    reason: str,
    terminal_action: str,
    batch: RepairCandidateBatch | None = None,
    recovery: PolicyRecoverySnapshot | None = None,
    current_state: ArchiveState | None = None,
    current_recovery: PolicyRecoverySnapshot | None = None,
) -> RepairResult:
    final_node = graph.best_node() or graph.current_node()
    state = final_node.archive_state if final_node is not None else None
    patch_depth = state.patch_depth() if state is not None else 0
    if recovery is None and final_node is not None and final_node.recovery:
        recovery = PolicyRecoverySnapshot.from_dict(final_node.recovery)
    recovery_score = float(recovery.score or 0.0) if recovery is not None else 0.0
    if recovery_score > 0.0 or patch_depth > 0:
        status = "partial"
    else:
        status = "skipped"
    repaired_input = _state_source_input(state, job) if state is not None else dict(job.source_input or {})
    terminal = terminal_action if terminal_action else "finish"
    module_name = "policy_finish"
    payload = _diagnosis_with_candidate_selection(diagnosis, selection)
    payload["policy_loop"] = {
        "policy_step": bool(selection.get("policy_step")),
        "terminal_action": terminal,
        "stop_reason": reason,
        "rounds": list(history),
        "patch_depth": patch_depth,
        "patch_digest": state.effective_patch_digest() if state is not None else "",
        "recovery": recovery.to_dict() if recovery is not None else {},
        "graph_summary": graph.summary(),
        "graph": graph.to_dict(),
        "current_node_id": graph.current_node_id,
        "best_node_id": graph.best_node_id,
        "final_node_id": final_node.node_id if final_node is not None else "",
        "final_state_selection": "best_seen_graph_node",
    }
    if terminal == "stop":
        if state is not None and status == "skipped":
            status = "partial"
        payload["policy_stop_requested"] = True
        payload["policy_loop"]["policy_stop_requested"] = True
    if _policy_states_differ(state, current_state):
        payload["policy_loop"]["terminal_patch_depth"] = current_state.patch_depth() if current_state is not None else 0
        payload["policy_loop"]["terminal_patch_digest"] = current_state.effective_patch_digest() if current_state is not None else ""
        payload["policy_loop"]["terminal_recovery"] = current_recovery.to_dict() if current_recovery is not None else {}
    result = RepairResult(
        status=status,
        confidence=float(job.confidence or 0.0),
        format=job.format,
        repaired_input=repaired_input,
        repaired_state=state if status in {"repaired", "partial"} and state is not None else None,
        actions=[module_name],
        damage_flags=list(job.damage_flags),
        warnings=_dedupe(warnings),
        partial=status == "partial",
        module_name=module_name,
        diagnosis=payload,
        message=reason,
    )
    if batch is not None:
        return replace(result, warnings=_dedupe([*result.warnings, *batch.warnings]))
    return result

def _policy_states_differ(state: ArchiveState | None, current_state: ArchiveState | None) -> bool:
    if state is None or current_state is None:
        return state is not current_state
    return state.effective_patch_digest() != current_state.effective_patch_digest()


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
                    "materialization_semantics": "graph_patch_state_v2",
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
