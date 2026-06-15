from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import random
import tempfile
from typing import Any

from repair_training.build_policy_graph_rows import (
    _sanitize_action_features,
    _sanitize_diagnosis_hgt,
    _sanitize_recovery,
    _sanitize_training_graph,
    build_policy_graph_rows,
)
from sunpack.model_runtime.policy.schema import PolicyAction, PolicyGraphTrainingSample, sample_from_dict
from sunpack.analysis.knowledge import write_zip_runtime_evidence_facts
from sunpack.coordinator.analysis_stage import ArchiveAnalysisStage
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState
from sunpack.repair.job import RepairJob
from sunpack.repair.policy.manager import RepairPolicyManager
from sunpack.repair.policy.formats import get_repair_format_plugin
from sunpack.repair.policy.graph import PolicyRepairGraph
from sunpack.repair.policy.recovery_evaluator import PolicyRecoverySnapshot, RecoveryEvaluator
from sunpack.repair.runtime_cache import RepairRuntimeCache
from sunpack.repair.scheduler import RepairScheduler
from sunpack.config.loader import load_config
from sunpack.support.archive_state_view import ArchiveStateByteView


DEFAULT_TEACHER_BUDGET = {
    "max_expansions": 60,
    "max_depth": 10,
    "module_branch_k": 8,
    "rollout_depth": 4,
    "epsilon": 0.01,
    "teacher_stale_patience": 8,
    "stop_margin": 0.02,
    "rollout_branch_k": 3,
    "exploration_random_k": 2,
    "teacher_exploration_rate": 0.25,
    "teacher_second_best_rate": 0.20,
    "teacher_bad_branch_rate": 0.15,
    "teacher_undo_probe_rate": 0.12,
    "teacher_force_undo_after_stale": 2,
    "teacher_undo_margin": 0.05,
    "teacher_bad_branch_depth_min": 2,
    "teacher_bad_branch_depth_max": 4,
    "undo_positive_target_ratio": 0.20,
    "best_tie_margin": 0.02,
    "teacher_refresh_analysis": True,
    "runtime_action_top_n": 24,
    "teacher_deep_eval_top_n": 6,
    "teacher_shallow_eval_top_n": 24,
    "seed": 13,
}


def build_policy_teacher_samples(
    raw_rows: list[dict[str, Any]],
    *,
    format_name: str = "zip",
    budget: dict[str, Any] | None = None,
    runtime_config: dict[str, Any] | None = None,
    workspace: str | Path | None = None,
    recovery_mode: str = "policy_full",
    runtime_rollout: bool = True,
) -> list[PolicyGraphTrainingSample]:
    resolved_budget = {**DEFAULT_TEACHER_BUDGET, **dict(budget or {})}
    samples: list[PolicyGraphTrainingSample] = []
    runtime_context: _RuntimeTeacherContext | None = None
    for row_index, row in enumerate(raw_rows):
        explicit = _explicit_teacher_samples(row, row_index=row_index, format_name=format_name, budget=resolved_budget)
        if explicit:
            samples.extend(explicit)
            continue
        graph_rows = build_policy_graph_rows([row], format_name=format_name)
        if graph_rows:
            for sample in graph_rows:
                samples.append(label_teacher_sample(sample, budget=resolved_budget))
            continue
        if not runtime_rollout:
            continue
        if runtime_context is None:
            runtime_context = _RuntimeTeacherContext(
                config=dict(runtime_config or {}),
                workspace=Path(workspace) if workspace else None,
                recovery_mode=str(recovery_mode or "policy_full"),
                budget=resolved_budget,
            )
        for sample in runtime_context.rollout_row(row, row_index=row_index, format_name=format_name):
            samples.append(label_teacher_sample(sample, budget=resolved_budget))
    if runtime_context is not None:
        runtime_context.close()
    return samples


class _RuntimeTeacherContext:
    def __init__(self, *, config: dict[str, Any], workspace: Path | None, recovery_mode: str, budget: dict[str, Any]):
        self.workspace_root = workspace or Path(tempfile.mkdtemp(prefix="sunpack_policy_teacher_"))
        self.full_config, self.repair_config = _teacher_configs(config, self.workspace_root)
        self.scheduler = RepairScheduler({"repair": self.repair_config})
        self.policy_manager = RepairPolicyManager(self.repair_config)
        self.analysis_stage = ArchiveAnalysisStage(self.full_config)
        self.evaluator = RecoveryEvaluator(self.full_config)
        self.recovery_mode = recovery_mode
        self.budget = dict(budget)
        self.cache: dict[str, PolicyRecoverySnapshot] = {}
        self.rng = random.Random(int(self.budget.get("seed", 13) or 13))

    def close(self) -> None:
        self.evaluator.close()

    def rollout_row(self, row: dict[str, Any], *, row_index: int, format_name: str) -> list[PolicyGraphTrainingSample]:
        job = _job_from_row(row, row_index=row_index, format_name=format_name, workspace=self.workspace_root)
        if job is None:
            return []
        plugin = get_repair_format_plugin(job.format)
        if plugin is None:
            return []
        recovery = self.evaluator.evaluate_state(job, job.archive_state, mode=self.recovery_mode, cache=self.cache)
        repair_graph = PolicyRepairGraph.initialize(job, recovery)
        job = self._job_with_refreshed_knowledge(job, job.archive_state, recovery=recovery, step=0)
        diagnosis = self._diagnose_state(row=row, job=job, repair_graph=repair_graph, recovery=recovery, round_index=0)
        repair_graph.observe_current_state(recovery=recovery, diagnosis_hgt=diagnosis, verification=dict(recovery.verification or {}))
        memory: list[dict[str, Any]] = []
        samples: list[PolicyGraphTrainingSample] = []
        stale = 0
        bad_branch_budget = 0
        best_score = _best_score(repair_graph)
        max_depth = int(self.budget.get("max_depth", 10) or 10)
        max_expansions = int(self.budget.get("max_expansions", 60) or 60)
        epsilon = float(self.budget.get("epsilon", 0.01) or 0.01)
        for step in range(1, max_depth + 1):
            if repair_graph.graph.expansion_count >= max_expansions:
                break
            decision = self._decision_sample(row=row, job=job, plugin=plugin, repair_graph=repair_graph, diagnosis=diagnosis, memory=memory, step=step)
            if decision is None:
                break
            labelled, proposal_by_id = decision
            samples.append(labelled)
            chosen = _teacher_next_action(labelled, self.rng, self.budget, force_bad_branch=bad_branch_budget > 0)
            if chosen is None or chosen.action_type == "stop":
                break
            if chosen.action_type == "module" and _is_bad_branch_choice(labelled, chosen):
                if bad_branch_budget <= 0:
                    bad_branch_budget = self.rng.randint(
                        int(self.budget.get("teacher_bad_branch_depth_min", 2) or 2),
                        int(self.budget.get("teacher_bad_branch_depth_max", 4) or 4),
                    )
                else:
                    bad_branch_budget -= 1
            elif bad_branch_budget > 0:
                bad_branch_budget -= 1
            applied = self._apply_action(job=job, plugin=plugin, repair_graph=repair_graph, action=chosen, step=step, proposal_by_id=proposal_by_id)
            if applied is None or applied.archive_state is None:
                break
            recovery = self.evaluator.evaluate_state(job, applied.archive_state, mode=self.recovery_mode, cache=self.cache)
            job = self._job_with_refreshed_knowledge(replace(job, archive_state=applied.archive_state), applied.archive_state, recovery=recovery, step=step)
            diagnosis = self._diagnose_state(row=row, job=job, repair_graph=repair_graph, recovery=recovery, round_index=step)
            current = repair_graph.graph.current_node()
            if current is not None:
                current.recovery = recovery.to_dict()
                current.diagnosis_hgt = dict(diagnosis)
                current.verification = dict(recovery.verification or {})
            previous_best = best_score
            best_score = _best_score(repair_graph)
            best_updated = best_score > previous_best + epsilon
            stale = 0 if best_updated else stale + 1
            memory.append(_memory_entry(step=step, action=chosen, recovery=recovery, previous_score=previous_best, best_updated=best_updated, stale=stale, repair_graph=repair_graph))
            if stale >= int(self.budget.get("teacher_stale_patience", 8) or 8):
                break
        return samples

    def _job_with_refreshed_knowledge(self, job: RepairJob, state: ArchiveState | None, *, recovery: PolicyRecoverySnapshot, step: int) -> RepairJob:
        if state is None or not bool(self.budget.get("teacher_refresh_analysis", True)):
            return job
        try:
            refresh_dir = self.workspace_root / "teacher_analysis"
            refresh_dir.mkdir(parents=True, exist_ok=True)
            materialized = ArchiveStateByteView(state).materialize(refresh_dir / f"{job.archive_key or 'state'}_{step}.zip")
            from sunpack.repair.policy.recovery_evaluator import _task_for_materialized_state

            task = _task_for_materialized_state(job, state, materialized)
            self.analysis_stage.refresh_task_analysis(task)
            try:
                write_zip_runtime_evidence_facts(task)
            except Exception:
                pass
            knowledge = task.knowledge.to_dict()
            verification = knowledge.get("verification") if isinstance(knowledge.get("verification"), dict) else {}
            verification["summary"] = dict(recovery.verification or {})
            knowledge["verification"] = verification
            extraction = knowledge.get("extraction") if isinstance(knowledge.get("extraction"), dict) else {}
            if isinstance(recovery.extraction, dict) and recovery.extraction:
                extraction["failure"] = dict(recovery.extraction)
                knowledge["extraction"] = extraction
            return replace(job, archive_state=state, source_input={"kind": "file", "path": str(materialized), "format_hint": job.format}, knowledge=knowledge)
        except Exception:
            return job

    def _diagnose_state(
        self,
        *,
        row: dict[str, Any],
        job: RepairJob,
        repair_graph: PolicyRepairGraph,
        recovery: PolicyRecoverySnapshot,
        round_index: int,
    ) -> dict[str, Any]:
        diagnosis, selection = self.policy_manager.diagnose_state(
            job=job,
            archive_state=job.archive_state,
            graph=repair_graph.graph,
            recovery=recovery.to_dict(),
            round_index=round_index,
        )
        if diagnosis:
            return _sanitize_diagnosis_hgt(diagnosis)
        fallback = _diagnosis_hgt_from_row(row)
        if fallback:
            fallback = _sanitize_diagnosis_hgt(fallback)
            diagnostics = dict(fallback.get("diagnostics") or {})
            diagnostics["teacher_diagnosis_fallback_reason"] = selection.get("fallback_reason") or selection.get("decision_status") or "diagnosis_hgt_unavailable"
            fallback["diagnostics"] = diagnostics
        return fallback

    def _decision_sample(
        self,
        *,
        row: dict[str, Any],
        job: RepairJob,
        plugin: Any,
        repair_graph: PolicyRepairGraph,
        diagnosis: dict[str, Any],
        memory: list[dict[str, Any]],
        step: int,
    ) -> tuple[PolicyGraphTrainingSample, dict[str, Any]] | None:
        runtime_proposals = plugin.available_modules(scheduler=self.scheduler, job=job, diagnosis_hgt=diagnosis, graph=repair_graph.graph)
        exposed_edges = repair_graph.register_proposals([proposal.to_action_payload() for proposal in runtime_proposals], step=step)
        exposed_ids = {edge.candidate_id for edge in exposed_edges}
        proposals = _select_runtime_action_proposals([proposal for proposal in runtime_proposals if proposal.action_id in exposed_ids], repair_graph, self.budget)
        action_payloads = [proposal.to_action_payload() for proposal in proposals]
        action_payloads.extend([
            {"action_type": "undo", "action_id": "undo", "module_name": ""},
            {"action_type": "stop", "action_id": "stop", "module_name": ""},
        ])
        actions = [
            PolicyAction(
                action_type=str(payload.get("action_type") or "module"),  # type: ignore[arg-type]
                action_id=str(payload.get("action_id") or payload.get("candidate_id") or payload.get("action_type") or ""),
                module_name=str(payload.get("module_name") or payload.get("module") or ""),
                features=_sanitize_action_features(payload),
            )
            for payload in action_payloads
            if str(payload.get("action_type") or "") in {"module", "undo", "stop"}
        ]
        current = repair_graph.graph.current_node()
        best = repair_graph.graph.best_node()
        sample = PolicyGraphTrainingSample(
            sample_id=f"{row.get('sample_id') or row.get('archive_key') or job.archive_key}:step:{step}",
            format=job.format,
            graph=_sanitize_training_graph(repair_graph.graph.to_dict()),
            current_node_id=repair_graph.graph.current_node_id,
            best_node_id=repair_graph.graph.best_node_id,
            actions=actions,
            memory=list(memory[-64:]),
            diagnosis_hgt=_sanitize_diagnosis_hgt(diagnosis),
            current_recovery=_sanitize_recovery(current.recovery if current is not None else {}),
            best_recovery=_sanitize_recovery(best.recovery if best is not None else {}),
            source={"archive_key": job.archive_key, "sample_id": row.get("sample_id") or "", "damage_profile": row.get("damage_profile") or ""},
        )
        proposal_by_id = {proposal.action_id: proposal for proposal in proposals}
        outcomes = self._evaluate_actions(job=job, plugin=plugin, repair_graph=repair_graph, actions=actions, proposal_by_id=proposal_by_id, step=step)
        labelled = label_teacher_sample(sample, action_outcomes=outcomes, budget=self.budget)
        labelled = _with_branch_annotations(labelled, repair_graph)
        return labelled, proposal_by_id

    def _evaluate_actions(self, *, job: RepairJob, plugin: Any, repair_graph: PolicyRepairGraph, actions: list[PolicyAction], proposal_by_id: dict[str, Any], step: int) -> dict[str, float]:
        outcomes: dict[str, float] = {}
        current_best = _best_score(repair_graph)
        module_seen = 0
        deep_limit = max(0, int(self.budget.get("teacher_deep_eval_top_n", 6) or 0))
        shallow_limit = max(deep_limit, int(self.budget.get("teacher_shallow_eval_top_n", 24) or 0))
        for action in actions:
            if action.action_type == "stop":
                outcomes["stop:stop"] = current_best
                outcomes["stop"] = current_best
                continue
            if action.action_type == "undo":
                current = repair_graph.graph.current_node()
                if current is None or not current.parent_id:
                    outcomes[_action_key(action)] = current_best
                    outcomes[action.action_id] = current_best
                    continue
            if action.action_type == "module":
                module_seen += 1
                if module_seen > shallow_limit:
                    outcomes[_action_key(action)] = current_best
                    outcomes[action.action_id] = current_best
                    continue
            cloned = PolicyRepairGraph.from_payload(repair_graph.graph.to_dict())
            applied = self._apply_action(job=job, plugin=plugin, repair_graph=cloned, action=action, step=step, proposal_by_id=proposal_by_id)
            if applied is None or applied.archive_state is None:
                outcomes[_action_key(action)] = current_best
                outcomes[action.action_id] = current_best
                continue
            recovery = self.evaluator.evaluate_state(job, applied.archive_state, mode=self.recovery_mode, cache=self.cache)
            current = cloned.graph.current_node()
            if current is not None:
                current.recovery = recovery.to_dict()
                current.diagnosis_hgt = self._diagnose_state(row={}, job=replace(job, archive_state=applied.archive_state), repair_graph=cloned, recovery=recovery, round_index=step)
            if action.action_type == "module" and module_seen > deep_limit:
                value = _best_score(cloned)
            else:
                value = max(
                    _best_score(cloned),
                    self._rollout_value(job=job, plugin=plugin, repair_graph=cloned, depth=int(self.budget.get("rollout_depth", 4) or 4) - 1, step=step + 1),
                )
            outcomes[_action_key(action)] = value
            outcomes[action.action_id] = value
        return outcomes

    def _rollout_value(self, *, job: RepairJob, plugin: Any, repair_graph: PolicyRepairGraph, depth: int, step: int) -> float:
        if depth <= 0:
            return _best_score(repair_graph)
        diagnosis = repair_graph.graph.current_node().diagnosis_hgt if repair_graph.graph.current_node() is not None else {}
        proposals = plugin.available_modules(scheduler=self.scheduler, job=job, diagnosis_hgt=diagnosis, graph=repair_graph.graph)
        exposed_edges = repair_graph.register_proposals([proposal.to_action_payload() for proposal in proposals], step=step)
        exposed_ids = {edge.candidate_id for edge in exposed_edges}
        proposals = _select_teacher_proposals([proposal for proposal in proposals if proposal.action_id in exposed_ids], repair_graph, {**self.budget, "module_branch_k": int(self.budget.get("rollout_branch_k", 3) or 3)}, self.rng)
        actions = [PolicyAction(action_type="module", action_id=proposal.action_id, module_name=proposal.module_name, features=proposal.to_action_payload()) for proposal in proposals]
        current = repair_graph.graph.current_node()
        if current is not None and current.parent_id:
            actions.append(PolicyAction(action_type="undo", action_id="undo"))
        best = _best_score(repair_graph)
        proposal_by_id = {proposal.action_id: proposal for proposal in proposals}
        for action in actions:
            cloned = PolicyRepairGraph.from_payload(repair_graph.graph.to_dict())
            applied = self._apply_action(job=job, plugin=plugin, repair_graph=cloned, action=action, step=step, proposal_by_id=proposal_by_id)
            if applied is None or applied.archive_state is None:
                continue
            recovery = self.evaluator.evaluate_state(job, applied.archive_state, mode=self.recovery_mode, cache=self.cache)
            node = cloned.graph.current_node()
            if node is not None:
                node.recovery = recovery.to_dict()
                node.diagnosis_hgt = self._diagnose_state(row={}, job=replace(job, archive_state=applied.archive_state), repair_graph=cloned, recovery=recovery, round_index=step)
            best = max(best, _best_score(cloned), self._rollout_value(job=job, plugin=plugin, repair_graph=cloned, depth=depth - 1, step=step + 1))
        return best

    def _apply_action(self, *, job: RepairJob, plugin: Any, repair_graph: PolicyRepairGraph, action: PolicyAction, step: int, proposal_by_id: dict[str, Any]):
        if action.action_type == "undo":
            return repair_graph.undo(step=step)
        if action.action_type != "module":
            return None
        proposal = proposal_by_id.get(action.action_id)
        if proposal is None:
            proposal = next((item for item in proposal_by_id.values() if item.module_name == action.module_name), None)
        if proposal is None:
            return None
        module_job = plugin.build_module_job(job=job, module_name=proposal.module_name, graph=repair_graph.graph)
        materialized = plugin.materialize_module(scheduler=self.scheduler, proposal=proposal, job=module_job)
        return repair_graph.forward(candidate_id=proposal.action_id, module_name=proposal.module_name, materialized_candidate=materialized.candidate, failure=materialized.failure, step=step)


def label_teacher_sample(
    sample: PolicyGraphTrainingSample,
    *,
    action_outcomes: dict[str, float] | None = None,
    budget: dict[str, Any] | None = None,
) -> PolicyGraphTrainingSample:
    resolved_budget = {**DEFAULT_TEACHER_BUDGET, **dict(budget or {})}
    epsilon = float(resolved_budget.get("epsilon", 0.01) or 0.01)
    q_horizon = int(resolved_budget.get("rollout_depth", 0) or 0)
    best_score = _best_recovery_score(sample)
    outcomes = dict(action_outcomes or {})
    if not outcomes:
        outcomes = _outcomes_from_action_payloads(sample, best_score)
    future_best = max([best_score, sample.final_best_recovery, *outcomes.values()] or [best_score])
    stop_regret = max(0.0, future_best - best_score)
    has_promising_future = stop_regret > epsilon
    branch_bad = _sample_branch_bad(sample)
    best_elsewhere = _sample_best_elsewhere(sample)
    labelled_actions: list[PolicyAction] = []
    max_q = best_score
    for action in sample.actions:
        key = _action_key(action)
        if action.action_type == "stop":
            q_value = best_score
            q_source = "teacher_stop_current_best"
            evaluated = True
        else:
            q_value = float(outcomes.get(key, outcomes.get(action.action_id, action.action_q_value or 0.0)) or 0.0)
            if q_value <= 0.0 and action.action_prior >= 0.5:
                q_value = float(sample.final_best_recovery or best_score)
            if action.action_type == "undo" and branch_bad and best_elsewhere:
                q_value = max(q_value, future_best)
            q_value = max(0.0, min(1.0, q_value))
            q_source = "teacher_bounded_rollout" if key in outcomes or action.action_id in outcomes else action.q_source or "teacher_unexplored"
            evaluated = bool(key in outcomes or action.action_id in outcomes or action.is_teacher_evaluated or action.action_prior >= 0.5)
        max_q = max(max_q, q_value)
        labelled_actions.append(replace(
            action,
            action_q_value=q_value,
            q_source=q_source,
            q_horizon=q_horizon,
            is_teacher_evaluated=evaluated,
        ))
    best_tie_margin = float(resolved_budget.get("best_tie_margin", 0.02) or 0.02)
    labelled_actions = [
        replace(
            action,
            action_regret=max(0.0, max_q - float(action.action_q_value or 0.0)),
            best_action_set_member=(max_q - float(action.action_q_value or 0.0)) <= best_tie_margin,
            q_bucket=_q_bucket(float(action.action_q_value or 0.0), max_q, best_tie_margin),
            features=_with_action_dynamic_features(action, sample),
        )
        for action in labelled_actions
    ]
    return replace(
        sample,
        actions=labelled_actions,
        final_best_recovery=max(future_best, sample.final_best_recovery),
        has_promising_future=has_promising_future,
        stop_regret=stop_regret,
        branch_bad=branch_bad,
        best_elsewhere=best_elsewhere,
        untried_promising_sibling_count=_untried_promising_sibling_count(sample),
        teacher_budget=resolved_budget,
        teacher_trace_id=sample.teacher_trace_id or f"teacher:{sample.sample_id}",
    )


def _explicit_teacher_samples(
    row: dict[str, Any],
    *,
    row_index: int,
    format_name: str,
    budget: dict[str, Any],
) -> list[PolicyGraphTrainingSample]:
    decisions = row.get("teacher_decisions")
    if not isinstance(decisions, list):
        return []
    samples: list[PolicyGraphTrainingSample] = []
    for decision_index, decision in enumerate(decisions):
        if not isinstance(decision, dict):
            continue
        sample = sample_from_dict({
            "sample_id": str(decision.get("sample_id") or row.get("sample_id") or f"row:{row_index}:teacher:{decision_index}"),
            "format": str(row.get("format") or format_name),
            "graph": dict(decision.get("graph") or {}),
            "current_node_id": str(decision.get("current_node_id") or (decision.get("graph") or {}).get("current_node_id") or ""),
            "best_node_id": str(decision.get("best_node_id") or (decision.get("graph") or {}).get("best_node_id") or ""),
            "actions": list(decision.get("actions") or []),
            "memory": list(decision.get("memory") or []),
            "diagnosis_hgt": dict(decision.get("diagnosis_hgt") or {}),
            "current_recovery": dict(decision.get("current_recovery") or {}),
            "best_recovery": dict(decision.get("best_recovery") or {}),
            "final_best_recovery": _float(decision.get("final_best_recovery", row.get("final_best_recovery"))),
            "source": {"row_index": row_index, "teacher_decision_index": decision_index, "episode_id": row.get("episode_id") or row.get("archive_key") or ""},
        })
        outcomes = _decision_outcomes(decision)
        samples.append(label_teacher_sample(sample, action_outcomes=outcomes, budget=budget))
    return samples


def _decision_outcomes(decision: dict[str, Any]) -> dict[str, float]:
    raw = decision.get("action_outcomes")
    if not isinstance(raw, dict):
        raw = {}
    outcomes = {str(key): _float(value) for key, value in raw.items()}
    for action in decision.get("actions") or []:
        if not isinstance(action, dict):
            continue
        action_id = str(action.get("action_id") or action.get("candidate_id") or action.get("action_type") or "")
        action_type = str(action.get("action_type") or "")
        module = str(action.get("module_name") or action.get("module") or "")
        q_value = _float(action.get("action_q_value", action.get("q_value", action.get("future_best_recovery"))))
        if q_value <= 0.0:
            continue
        for key in {action_id, f"{action_type}:{action_id}", f"module:{module}" if module else ""}:
            if key:
                outcomes[key] = q_value
    return outcomes


def _outcomes_from_action_payloads(sample: PolicyGraphTrainingSample, best_score: float) -> dict[str, float]:
    outcomes: dict[str, float] = {}
    for action in sample.actions:
        if action.action_type == "stop":
            continue
        q_value = float(action.action_q_value or 0.0)
        if action.action_prior >= 0.5:
            q_value = max(q_value, float(sample.final_best_recovery or best_score))
        if q_value > 0.0:
            outcomes[_action_key(action)] = q_value
            outcomes[action.action_id] = q_value
    return outcomes


def _best_recovery_score(sample: PolicyGraphTrainingSample) -> float:
    score = _float(sample.best_recovery.get("score") if isinstance(sample.best_recovery, dict) else 0.0)
    graph = sample.graph if isinstance(sample.graph, dict) else {}
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    best_id = str(sample.best_node_id or graph.get("best_node_id") or "")
    if best_id and isinstance(nodes.get(best_id), dict):
        recovery = nodes[best_id].get("recovery") if isinstance(nodes[best_id].get("recovery"), dict) else {}
        score = max(score, _float(recovery.get("score")))
    for node in nodes.values():
        if not isinstance(node, dict):
            continue
        recovery = node.get("recovery") if isinstance(node.get("recovery"), dict) else {}
        score = max(score, _float(recovery.get("score")))
    return max(0.0, min(1.0, score))


def _action_key(action: PolicyAction) -> str:
    if action.action_type == "module" and action.module_name:
        return f"module:{action.module_name}"
    return f"{action.action_type}:{action.action_id or action.action_type}"


def _teacher_configs(config: dict[str, Any], workspace: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        base = load_config()
    except Exception:
        base = {}
    full = _merge_dicts(base, config)
    repair = dict(full.get("repair") or config.get("repair") or config)
    repair["workspace"] = str(workspace)
    repair.setdefault("policy", {"enabled": False})
    repair.setdefault("runtime_cache", {"enabled": True, "max_entries": 2048})
    full["repair"] = repair
    return full, repair


def _merge_dicts(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base or {})
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def _job_from_row(row: dict[str, Any], *, row_index: int, format_name: str, workspace: Path) -> RepairJob | None:
    source_input = _source_input_from_row(row)
    path = str(source_input.get("path") or source_input.get("archive_path") or "")
    if not path:
        return None
    fmt = str(row.get("format") or source_input.get("format_hint") or source_input.get("format") or format_name or "zip")
    descriptor = ArchiveInputDescriptor.from_any(source_input, archive_path=path, format_hint=fmt)
    state = ArchiveState.from_archive_input(descriptor)
    knowledge = dict(row.get("knowledge_payload") or row.get("knowledge") or {})
    password = row.get("password")
    if password is None and isinstance(row.get("damaged_input"), dict):
        password = row["damaged_input"].get("password")
    return RepairJob(
        source_input=source_input,
        format=fmt,
        confidence=float(row.get("confidence") or 0.0),
        extraction_failure=dict(row.get("extraction_failure") or (knowledge.get("extraction") or {}).get("failure") or {}),
        damage_flags=[str(item) for item in row.get("damage_flags") or [] if str(item)],
        password=str(password) if password else None,
        archive_key=str(row.get("archive_key") or row.get("sample_id") or f"row_{row_index}"),
        workspace=str(workspace),
        source_descriptor=descriptor,
        archive_state=state,
        knowledge=knowledge,
        repair_cache=RepairRuntimeCache(enabled=True, max_entries=2048),
    )


def _source_input_from_row(row: dict[str, Any]) -> dict[str, Any]:
    for key in ("damaged_input", "source_input", "archive_input"):
        value = row.get(key)
        if isinstance(value, dict):
            output = dict(value)
            output.setdefault("kind", "file")
            output.setdefault("format_hint", row.get("format") or output.get("format") or "zip")
            return output
    knowledge = row.get("knowledge_payload") if isinstance(row.get("knowledge_payload"), dict) else {}
    source = knowledge.get("source") if isinstance(knowledge.get("source"), dict) else {}
    source_input = source.get("input") if isinstance(source.get("input"), dict) else {}
    if source_input:
        output = dict(source_input)
        if not output.get("path") and output.get("entry_path"):
            output["path"] = output.get("entry_path")
        if not output.get("archive_path") and output.get("path"):
            output["archive_path"] = output.get("path")
        output.setdefault("kind", "file")
        output.setdefault("format_hint", row.get("format") or output.get("format") or "zip")
        return output
    path = str(row.get("path") or row.get("archive_path") or row.get("source_path") or "")
    return {"kind": "file", "path": path, "format_hint": row.get("format") or "zip"} if path else {}


def _diagnosis_hgt_from_row(row: dict[str, Any]) -> dict[str, Any]:
    for key in ("diagnosis_hgt", "diagnosis_gnn", "root_case"):
        value = row.get(key)
        if isinstance(value, dict):
            if "root_case" in value:
                return dict(value)
            if key == "root_case":
                return {"root_case": dict(value)}
    labels = row.get("root_case_labels") or row.get("root_cases") or []
    if not labels and isinstance(row.get("labels"), dict):
        labels = row["labels"].get("root_case_labels") or row["labels"].get("root_cases") or []
    scores = {str(label): 1.0 for label in labels or [] if str(label)}
    ranked = [{"root_case": key, "score": value} for key, value in scores.items()]
    return {"root_case": {"scores": scores, "ranked": ranked, "selected": list(scores)}}


def _select_teacher_proposals(proposals: list[Any], repair_graph: PolicyRepairGraph, budget: dict[str, Any], rng: random.Random) -> list[Any]:
    if not proposals:
        return []
    branch_k = max(1, int(budget.get("module_branch_k", 8) or 8))
    selected: list[Any] = []
    seen_family: set[str] = set()
    for proposal in proposals:
        family = str((proposal.payload or {}).get("route_family") or proposal.module_name)
        if family in seen_family:
            continue
        selected.append(proposal)
        seen_family.add(family)
        if len(selected) >= branch_k:
            break
    remaining = [proposal for proposal in proposals if proposal not in selected]
    rng.shuffle(remaining)
    for proposal in remaining[: max(0, int(budget.get("exploration_random_k", 2) or 2))]:
        if proposal not in selected:
            selected.append(proposal)
    return selected[:branch_k]


def _select_runtime_action_proposals(proposals: list[Any], repair_graph: PolicyRepairGraph, budget: dict[str, Any]) -> list[Any]:
    if not proposals:
        return []
    top_n = max(1, int(budget.get("runtime_action_top_n", 24) or 24))
    return sorted(proposals, key=_proposal_runtime_rank, reverse=True)[:top_n]


def _proposal_runtime_rank(proposal: Any) -> tuple[float, float, str]:
    payload = proposal.payload if isinstance(getattr(proposal, "payload", None), dict) else {}
    score = _float(payload.get("generation_priority", payload.get("score_hint", payload.get("confidence"))))
    confidence = _float(payload.get("confidence"))
    return (score, confidence, str(getattr(proposal, "module_name", "") or ""))


def _teacher_next_action(sample: PolicyGraphTrainingSample, rng: random.Random, budget: dict[str, Any] | None = None, *, force_bad_branch: bool = False) -> PolicyAction | None:
    if not sample.actions:
        return None
    resolved = {**DEFAULT_TEACHER_BUDGET, **dict(budget or {})}
    ordered = sorted(sample.actions, key=lambda action: float(action.action_q_value or 0.0), reverse=True)
    non_stop = [action for action in ordered if action.action_type != "stop"]
    modules = [action for action in ordered if action.action_type == "module"]
    undo = next((action for action in ordered if action.action_type == "undo"), None)
    if sample.has_promising_future and non_stop:
        ordered = non_stop + [action for action in ordered if action.action_type == "stop"]

    last_memory = sample.memory[-1] if sample.memory and isinstance(sample.memory[-1], dict) else {}
    stale = int(last_memory.get("branch_failed_streak") or 0)
    force_undo_after = int(resolved.get("teacher_force_undo_after_stale", 2) or 2)
    undo_margin = float(resolved.get("teacher_undo_margin", 0.05) or 0.05)
    best_q = float(ordered[0].action_q_value or 0.0)
    if undo is not None and stale >= force_undo_after and float(undo.action_q_value or 0.0) >= best_q - undo_margin:
        return undo

    # Intentionally visit some low-value module branches so the memory model sees
    # failed paths and can later learn to undo away from them.
    if modules and (force_bad_branch or rng.random() < float(resolved.get("teacher_bad_branch_rate", 0.15) or 0.0)):
        evaluated_modules = [action for action in modules if action.is_teacher_evaluated]
        pool = evaluated_modules or modules
        return min(pool, key=lambda action: float(action.action_q_value or 0.0))

    if undo is not None and rng.random() < float(resolved.get("teacher_undo_probe_rate", 0.12) or 0.0):
        return undo

    candidates = ordered
    if len(candidates) > 1 and rng.random() < float(resolved.get("teacher_exploration_rate", 0.25) or 0.0):
        limit = min(len(candidates), max(2, int(resolved.get("module_branch_k", 8) or 8)))
        return candidates[rng.randrange(1, limit)]
    if len(candidates) > 1 and rng.random() < float(resolved.get("teacher_second_best_rate", 0.20) or 0.0):
        return candidates[1]
    return candidates[0]


def _memory_entry(*, step: int, action: PolicyAction, recovery: PolicyRecoverySnapshot, previous_score: float, best_updated: bool, stale: int, repair_graph: PolicyRepairGraph) -> dict[str, Any]:
    current = repair_graph.graph.current_node()
    return {
        "round": step,
        "patch_depth": current.archive_state.patch_depth() if current is not None and current.archive_state is not None else 0,
        "graph_action": {
            "action_type": action.action_type,
            "action_id": action.action_id,
            "module_name": action.module_name,
            "module_family": _action_module_family(action),
        },
        "current_recovery": _sanitize_recovery(recovery.to_dict()),
        "recovery_delta": float(recovery.score or 0.0) - float(previous_score or 0.0),
        "best_updated": bool(best_updated),
        "branch_failed_streak": int(stale),
        "distance_from_best_node": _distance_from_best(repair_graph),
    }


def _is_bad_branch_choice(sample: PolicyGraphTrainingSample, action: PolicyAction) -> bool:
    if action.action_type != "module":
        return False
    best_q = max((float(item.action_q_value or 0.0) for item in sample.actions), default=0.0)
    return float(action.action_q_value or 0.0) < best_q - 0.05


def _with_branch_annotations(sample: PolicyGraphTrainingSample, repair_graph: PolicyRepairGraph) -> PolicyGraphTrainingSample:
    return replace(
        sample,
        branch_bad=sample.branch_bad or _distance_from_best(repair_graph) >= 2,
        best_elsewhere=sample.best_elsewhere or _distance_from_best(repair_graph) > 0,
        untried_promising_sibling_count=max(sample.untried_promising_sibling_count, _frontier_sibling_count(repair_graph)),
    )


def _frontier_sibling_count(repair_graph: PolicyRepairGraph) -> int:
    current = repair_graph.graph.current_node()
    if current is None:
        return 0
    parent_id = current.parent_id
    if not parent_id:
        return 0
    return sum(1 for edge in repair_graph.graph.edges.values() if edge.from_node_id == parent_id and edge.status == "frontier")


def _q_bucket(q_value: float, max_q: float, tie_margin: float) -> str:
    if max_q - q_value <= tie_margin:
        return "best"
    if max_q - q_value <= 0.10:
        return "near_best"
    if q_value <= 0.0:
        return "zero"
    return "low"


def _with_action_dynamic_features(action: PolicyAction, sample: PolicyGraphTrainingSample) -> dict[str, Any]:
    features = dict(action.features or {})
    family = str(features.get("module_family") or features.get("route_family") or action.module_name or "")
    features["module_family"] = family
    features["family_recent_failure_count"] = _family_recent_failure_count(sample.memory, family)
    features["family_best_delta_history"] = _family_best_delta_history(sample.memory, family)
    features["same_family_tried_on_branch"] = bool(features["family_recent_failure_count"])
    features["module_tried_on_current_node"] = _module_tried_on_current_node(sample, action)
    return features


def _family_recent_failure_count(memory: list[dict[str, Any]], family: str) -> int:
    if not family:
        return 0
    count = 0
    for item in memory[-32:]:
        action = item.get("graph_action") if isinstance(item.get("graph_action"), dict) else item
        if str(action.get("module_family") or action.get("module_name") or "") != family:
            continue
        if _float(item.get("recovery_delta")) <= 0.0 and not item.get("best_updated"):
            count += 1
    return count


def _family_best_delta_history(memory: list[dict[str, Any]], family: str) -> float:
    if not family:
        return 0.0
    best = 0.0
    for item in memory[-32:]:
        action = item.get("graph_action") if isinstance(item.get("graph_action"), dict) else item
        if str(action.get("module_family") or action.get("module_name") or "") == family:
            best = max(best, _float(item.get("recovery_delta")))
    return best


def _module_tried_on_current_node(sample: PolicyGraphTrainingSample, action: PolicyAction) -> bool:
    nodes = sample.graph.get("nodes") if isinstance(sample.graph.get("nodes"), dict) else {}
    current = nodes.get(sample.current_node_id) if isinstance(nodes.get(sample.current_node_id), dict) else {}
    expanded = {str(item) for item in current.get("expanded_candidate_ids") or [] if str(item)}
    return action.action_id in expanded or action.module_name in expanded


def _action_module_family(action: PolicyAction) -> str:
    return str(action.features.get("module_family") or action.features.get("route_family") or action.module_name or "")


def _sample_branch_bad(sample: PolicyGraphTrainingSample) -> bool:
    last = sample.memory[-1] if sample.memory else {}
    return bool(sample.branch_bad or int(last.get("branch_failed_streak") or 0) >= 2)


def _sample_best_elsewhere(sample: PolicyGraphTrainingSample) -> bool:
    return bool(sample.best_elsewhere or sample.current_node_id != sample.best_node_id)


def _untried_promising_sibling_count(sample: PolicyGraphTrainingSample) -> int:
    return int(sample.untried_promising_sibling_count or 0)


def _distance_from_best(repair_graph: PolicyRepairGraph) -> int:
    graph = repair_graph.graph
    node = graph.current_node()
    distance = 0
    while node is not None and node.node_id != graph.best_node_id and node.parent_id:
        distance += 1
        node = graph.nodes.get(node.parent_id)
    return distance


def _best_score(repair_graph: PolicyRepairGraph) -> float:
    best_id = repair_graph.stop_readiness().get("best_node_id") or repair_graph.graph.best_node_id
    node = repair_graph.graph.nodes.get(str(best_id))
    recovery = node.recovery if node is not None and isinstance(node.recovery, dict) else {}
    return max(0.0, min(1.0, _float(recovery.get("score"))))


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
