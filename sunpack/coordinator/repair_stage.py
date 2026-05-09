from __future__ import annotations

import os
from contextlib import nullcontext
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from sunpack.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from sunpack.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    ArchiveInputRange,
)
from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.tasks import ArchiveTask
from sunpack.extraction.result import ExtractionResult
from sunpack.repair.config import repair_config
from sunpack.repair.context import normalize_zip_runtime_route_evidence
from sunpack.repair.job import RepairJob
from sunpack.repair.knowledge import (
    write_repair_archive_status,
    write_repair_attempt,
    write_repair_candidate_log,
    write_repair_job_context,
    write_repair_result,
)
from sunpack.repair.result import RepairResult
from sunpack.repair.scheduler import RepairScheduler
from sunpack.support import repair_trace
from sunpack.support import archive_knowledge_projection as knowledge_view
from sunpack.verification.result import VerificationResult


class ArchiveRepairStage:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = repair_config(config or {})
        self.enabled = bool(self.config.get("enabled", True))
        self.scheduler = RepairScheduler(config or {}) if self.enabled else None
        round_limit = self.config.get("max_repair_rounds_per_task", self.config.get("max_attempts_per_task", 3))
        self.max_attempts_per_task = max(0, int(round_limit or 0))

    def repair_after_verification_assessment_result(
        self,
        task: ArchiveTask,
        result: ExtractionResult,
        verification: VerificationResult,
    ) -> RepairResult | None:
        if not self.enabled or self.scheduler is None:
            return None
        if self._attempts(task) >= self.max_attempts_per_task:
            return None
        job = self._job_from_verification_assessment(task, result, verification)
        if job is None:
            return None
        return self._run_and_apply(task, job, trigger="verification")

    def policy_active_for_verification(
        self,
        task: ArchiveTask,
        result: ExtractionResult,
        verification: VerificationResult,
    ) -> bool:
        if not self.enabled or self.scheduler is None:
            return False
        policy = self.config.get("policy") if isinstance(self.config.get("policy"), dict) else {}
        if not bool(policy.get("disable_beam_when_model_active", True)):
            return False
        repair_trace.write_probe_event("policy_probe_active_check_start", {
            "run_id": _policy_probe_run_id(task),
            "query_id": f"{task.key or task.main_path}:policy_active",
            "archive": task.main_path,
            "archive_key": task.key,
        })
        job = self._job_from_verification_assessment(task, result, verification)
        if job is None:
            repair_trace.write_probe_event("policy_probe_active_check_done", {
                "run_id": _policy_probe_run_id(task),
                "query_id": f"{task.key or task.main_path}:policy_active",
                "active": False,
                "reason": "no_job",
            })
            return False
        active = getattr(self.scheduler, "policy_active_for_job", None)
        result_active = bool(callable(active) and active(job))
        repair_trace.write_probe_event("policy_probe_active_check_done", {
            "run_id": _policy_probe_run_id(task),
            "query_id": f"{task.key or task.main_path}:policy_active",
            "active": result_active,
            "format": job.format,
            "damage_flag_count": len(job.damage_flags or []),
        })
        return result_active

    def _run_and_apply(self, task: ArchiveTask, job: RepairJob, *, trigger: str) -> RepairResult | None:
        if self.scheduler is None or self._attempts(task) >= self.max_attempts_per_task:
            return None
        attempts = self._attempts(task) + 1
        write_repair_attempt(task, attempts, trigger=trigger)
        result = self.scheduler.repair(job)
        self._append_repair_history(task, result)
        _append_candidate_log_from_result(task, result, phase="scheduler_repair", trigger=trigger)
        if not result.ok:
            return result
        descriptor = self._descriptor_from_repaired_input(task, result.repaired_input or {})
        if result.repaired_state is not None:
            task.set_archive_state(result.repaired_state)
        elif descriptor is None:
            return result
        else:
            task.set_archive_state(ArchiveState.from_archive_input(descriptor))
        if job.password is not None:
            write_repair_archive_status(task, password=job.password)
        write_repair_archive_status(task, repaired=True)
        return result

    def _job_from_verification_assessment(
        self,
        task: ArchiveTask,
        result: ExtractionResult,
        verification: VerificationResult,
        *,
        phase_timer: Callable[..., Any] | None = None,
        phase_prefix: str = "build_repair_job",
    ) -> RepairJob | None:
        probe_query_id = f"{task.key or task.main_path}:job_from_verification"
        repair_trace.write_probe_event("policy_probe_job_build_step", {
            "run_id": _policy_probe_run_id(task),
            "query_id": probe_query_id,
            "step": "start",
            "archive": task.main_path,
            "archive_key": task.key,
        })
        with _phase(phase_timer, f"{phase_prefix}_source_input"):
            source_input = self._source_input_from_task(task)
        repair_trace.write_probe_event("policy_probe_job_build_step", {
            "run_id": _policy_probe_run_id(task),
            "query_id": probe_query_id,
            "step": "source_input",
            "source_kind": (source_input or {}).get("kind") if isinstance(source_input, dict) else "",
        })
        if source_input is None:
            return None
        with _phase(phase_timer, f"{phase_prefix}_selected_format"):
            selected_format = self._format_from_source_or_task(source_input, task)
        with _phase(phase_timer, f"{phase_prefix}_failure_payload"):
            failure = self._failure_payload(task, result, format_hint=selected_format)
        repair_trace.write_probe_event("policy_probe_job_build_step", {
            "run_id": _policy_probe_run_id(task),
            "query_id": probe_query_id,
            "step": "failure_payload",
            "failure_kind": failure.get("failure_kind"),
        })
        with _phase(phase_timer, f"{phase_prefix}_verification_payload"):
            repair_hints = _verification_repair_hints(verification)
            if repair_hints:
                _merge_repair_hints_into_failure(failure, repair_hints)
            failure.update({
                "status": "verification_failed",
                "failure_stage": "verification",
                "assessment_status": verification.assessment_status,
                "source_integrity": verification.source_integrity,
                "decision_hint": verification.decision_hint,
                "completeness": verification.completeness,
                "recoverable_upper_bound": verification.recoverable_upper_bound,
                "complete_files": verification.complete_files,
                "partial_files": verification.partial_files,
                "failed_files": verification.failed_files,
                "missing_files": verification.missing_files,
                "unverified_files": verification.unverified_files,
                "archive_coverage": asdict(verification.archive_coverage),
                "repair_hints": repair_hints,
                "issues": [
                    {
                        "method": item.method,
                        "code": item.code,
                        "message": item.message,
                        "path": item.path,
                        "expected": item.expected,
                        "actual": item.actual,
                    }
                    for item in verification.issues
                ],
                "file_observations": [
                    {
                        "path": item.path,
                        "archive_path": item.archive_path,
                        "state": item.state,
                        "method": item.method,
                        "bytes_written": item.bytes_written,
                        "expected_size": item.expected_size,
                        "progress": item.progress,
                        "crc_expected": item.crc_expected,
                        "crc_actual": item.crc_actual,
                    }
                    for item in verification.file_observations
                ],
            })
        with _phase(phase_timer, f"{phase_prefix}_previous_repair_path"):
            previous_actions, previous_modules = self._previous_repair_path(task)
        if previous_actions:
            failure["previous_actions"] = previous_actions
        if previous_modules:
            failure["previous_modules"] = previous_modules
        with _phase(phase_timer, f"{phase_prefix}_analysis_prepass"):
            analysis_prepass = self._analysis_prepass(task)
        repair_trace.write_probe_event("policy_probe_job_build_step", {
            "run_id": _policy_probe_run_id(task),
            "query_id": probe_query_id,
            "step": "analysis_prepass",
            "prepass_keys": sorted(str(key) for key in analysis_prepass.keys())[:40],
        })
        with _phase(phase_timer, f"{phase_prefix}_analysis_evidence"):
            analysis_evidence = self._analysis_evidence_from_facts(task)
        repair_trace.write_probe_event("policy_probe_job_build_step", {
            "run_id": _policy_probe_run_id(task),
            "query_id": probe_query_id,
            "step": "analysis_evidence",
            "has_evidence": analysis_evidence is not None,
        })
        with _phase(phase_timer, f"{phase_prefix}_repair_history_payload"):
            repair_history = self._repair_history_payload(task, previous_actions, previous_modules)
        repair_trace.write_probe_event("policy_probe_job_build_step", {
            "run_id": _policy_probe_run_id(task),
            "query_id": probe_query_id,
            "step": "repair_history",
            "previous_action_count": len(previous_actions),
        })
        with _phase(phase_timer, f"{phase_prefix}_route_payload"):
            route_payload = self._zip_runtime_route_payload(
                task,
                source_input=source_input,
                format_hint=selected_format,
                analysis_prepass=analysis_prepass,
                analysis_evidence=analysis_evidence,
                extraction_failure=failure,
                extraction_diagnostics=dict(result.diagnostics or {}),
                repair_history=repair_history,
            )
        repair_trace.write_probe_event("policy_probe_job_build_step", {
            "run_id": _policy_probe_run_id(task),
            "query_id": probe_query_id,
            "step": "route_payload",
            "route_flag_count": len(route_payload.get("route_evidence_flags") or []),
        })
        route_flags = [str(item) for item in route_payload.get("route_evidence_flags") or [] if str(item)]
        if route_flags:
            repair_hints = dict(failure.get("repair_hints") or {})
            repair_hints["damage_flags"] = _dedupe([*list(repair_hints.get("damage_flags") or []), *route_flags])
            failure["repair_hints"] = repair_hints
        source_input = dict(route_payload.get("source_input") or source_input)
        with _phase(phase_timer, f"{phase_prefix}_damage_flags"):
            damage_flags = _dedupe([
                *self._flags_from_failure_text(result.error),
                *self._flags_from_verification(verification),
                *_flags_from_repair_hints(repair_hints),
                *route_flags,
                *list(route_payload.get("damage_flags") or []),
            ])
        with _phase(phase_timer, f"{phase_prefix}_normalize_route_evidence"):
            route_payload = normalize_zip_runtime_route_evidence({
                **route_payload,
                "source_input": source_input,
                "analysis_prepass": analysis_prepass,
                "analysis_evidence": dict(getattr(analysis_evidence, "details", {}) or {}) if analysis_evidence is not None else {},
                "extraction_failure": failure,
                "extraction_diagnostics": dict(result.diagnostics or {}),
                "repair_history": repair_history,
                "damage_flags": damage_flags,
            })
        repair_trace.write_probe_event("policy_probe_job_build_step", {
            "run_id": _policy_probe_run_id(task),
            "query_id": probe_query_id,
            "step": "route_payload_normalized",
            "damage_flag_count": len(route_payload.get("damage_flags") or []),
            "route_flag_count": len(route_payload.get("route_evidence_flags") or []),
        })
        damage_flags = list(route_payload.get("damage_flags") or damage_flags)
        route_flags = [str(item) for item in route_payload.get("route_evidence_flags") or [] if str(item)]
        if route_flags:
            repair_hints = dict(failure.get("repair_hints") or {})
            repair_hints["damage_flags"] = _dedupe([*list(repair_hints.get("damage_flags") or []), *route_flags])
            failure["repair_hints"] = repair_hints
        with _phase(phase_timer, f"{phase_prefix}_knowledge_payload"):
            knowledge = self._knowledge_payload(
                task,
                source_input=source_input,
                analysis_prepass=analysis_prepass,
                analysis_evidence=analysis_evidence,
                extraction_failure=failure,
                extraction_diagnostics=dict(result.diagnostics or {}),
                repair_history=repair_history,
                route_payload=route_payload,
                verification=verification,
                phase_timer=phase_timer,
                phase_prefix=f"{phase_prefix}_knowledge_payload",
            )
        repair_trace.write_probe_event("policy_probe_job_build_step", {
            "run_id": _policy_probe_run_id(task),
            "query_id": probe_query_id,
            "step": "knowledge_payload",
            "knowledge_keys": sorted(str(key) for key in knowledge.keys())[:40] if isinstance(knowledge, dict) else [],
        })
        repair_trace.write_probe_event("policy_probe_job_build_step", {
            "run_id": _policy_probe_run_id(task),
            "query_id": probe_query_id,
            "step": "return",
        })
        with _phase(phase_timer, f"{phase_prefix}_construct_job"):
            with _phase(phase_timer, f"{phase_prefix}_construct_job_format"):
                job_format = self._normalize_format(str(route_payload.get("format") or getattr(analysis_evidence, "format", "") or selected_format))
            with _phase(phase_timer, f"{phase_prefix}_construct_job_confidence"):
                confidence = float(getattr(analysis_evidence, "confidence", 0.0) or 0.0)
            with _phase(phase_timer, f"{phase_prefix}_construct_job_fuzzy"):
                fuzzy = analysis_prepass.get("fuzzy") if isinstance(analysis_prepass.get("fuzzy"), dict) else {}
                fuzzy_profile = dict(fuzzy.get("binary_profile") or fuzzy) if isinstance(fuzzy, dict) else {}
            with _phase(phase_timer, f"{phase_prefix}_construct_job_extraction_diagnostics"):
                extraction_diagnostics = dict(result.diagnostics or {})
            with _phase(phase_timer, f"{phase_prefix}_construct_job_password"):
                password = result.password_used if result.password_used is not None else self._password_from_task(task)
            with _phase(phase_timer, f"{phase_prefix}_construct_job_workspace"):
                workspace = str(self._workspace_root())
            with _phase(phase_timer, f"{phase_prefix}_construct_job_attempts"):
                attempts = _nested_int(knowledge, ("repair", "attempts"), 0)
            with _phase(phase_timer, f"{phase_prefix}_construct_job_source_descriptor"):
                source_descriptor = ArchiveInputDescriptor.from_any(
                    source_input,
                    archive_path=task.main_path,
                    part_paths=list(task.all_parts or [task.main_path]),
                    format_hint=job_format,
                    logical_name=str(task.logical_name or ""),
                )
            with _phase(phase_timer, f"{phase_prefix}_construct_job_archive_state"):
                archive_state = task.archive_state()
            with _phase(phase_timer, f"{phase_prefix}_construct_job_dataclass"):
                return RepairJob(
                    source_input=source_input,
                    format=job_format,
                    confidence=confidence,
                    analysis_evidence=analysis_evidence,
                    analysis_prepass=analysis_prepass,
                    fuzzy_profile=fuzzy_profile,
                    extraction_failure=failure,
                    extraction_diagnostics=extraction_diagnostics,
                    damage_flags=damage_flags,
                    password=password,
                    archive_key=task.key,
                    workspace=workspace,
                    attempts=attempts,
                    source_descriptor=source_descriptor,
                    archive_state=archive_state,
                    repair_history=repair_history,
                    knowledge=knowledge,
                )

    def _append_repair_history(self, task: ArchiveTask, result: RepairResult) -> None:
        history = knowledge_view.repair_history_items(task)
        item = self._result_payload(result)
        history.append(item)
        write_repair_result(task, result, phase="history")

    def _previous_repair_path(self, task: ArchiveTask) -> tuple[list[str], list[str]]:
        history_payload = knowledge_view.repair_history_payload(task)
        actions = [str(action) for action in history_payload.get("previous_actions") or []]
        modules = [str(module) for module in history_payload.get("previous_modules") or []]
        if actions or modules:
            return actions, modules
        history = knowledge_view.repair_history_items(task)
        for entry in history:
            if not isinstance(entry, dict) or not entry.get("ok"):
                continue
            actions.extend(str(action) for action in entry.get("actions") or [])
            module = str(entry.get("module_name") or "")
            if module:
                modules.append(module)
        return actions, modules

    def _repair_history_payload(self, task: ArchiveTask, previous_actions: list[str], previous_modules: list[str]) -> dict[str, Any]:
        history = knowledge_view.repair_history_items(task)
        patch_facts: list[str] = []
        residual_flags: list[str] = []
        for entry in history:
            diagnosis = entry.get("diagnosis") if isinstance(entry.get("diagnosis"), dict) else {}
            for key in ("patch_facts", "residual_facts"):
                patch_facts.extend(str(item) for item in diagnosis.get(key) or [] if str(item))
            selection = diagnosis.get("candidate_selection") if isinstance(diagnosis.get("candidate_selection"), dict) else {}
            candidate = selection.get("candidate") if isinstance(selection.get("candidate"), dict) else {}
            patch_facts.extend(str(item) for item in candidate.get("patch_facts") or [] if str(item))
            residual_flags.extend(str(item) for item in candidate.get("residual_facts") or [] if str(item))
        return {
            "previous_actions": list(previous_actions),
            "previous_modules": list(previous_modules),
            "path_actions": list(previous_actions),
            "path_modules": list(previous_modules),
            "applied_patch_facts": _dedupe(patch_facts),
            "residual_damage_flags": _dedupe(residual_flags),
            "route_evidence_flags": [],
        }

    def _zip_runtime_route_payload(
        self,
        task: ArchiveTask,
        *,
        source_input: dict[str, Any],
        format_hint: str = "",
        analysis_prepass: dict[str, Any],
        analysis_evidence: ArchiveFormatEvidence | None,
        extraction_failure: dict[str, Any],
        extraction_diagnostics: dict[str, Any],
        repair_history: dict[str, Any],
    ) -> dict[str, Any]:
        details = dict(getattr(analysis_evidence, "details", {}) or {}) if analysis_evidence is not None else {}
        fmt = self._normalize_format(str(format_hint or getattr(analysis_evidence, "format", "") or ""))
        if not fmt or fmt == "unknown":
            fmt = self._format_from_task(task)
        payload = {
            "format": fmt,
            "source_input": self._source_input_with_split_parts(task, source_input, format_hint=fmt),
            "analysis_prepass": dict(analysis_prepass or {}),
            "analysis_evidence": details,
            "extraction_failure": dict(extraction_failure or {}),
            "extraction_diagnostics": dict(extraction_diagnostics or {}),
            "repair_history": dict(repair_history or {}),
            "source_derivation": self._source_derivation_from_task(task),
            "zip_structure_features": self._zip_structure_features_from_task(task),
            "zip_container_tags": self._zip_container_tags_from_task(task),
            "damage_profile": self._damage_profile_from_task(task),
            "damage_flags": list(extraction_failure.get("damage_flags") or []),
        }
        if getattr(task, "all_parts", None) and len(task.all_parts or []) > 1:
            payload["split_sidecars_available"] = True
        return normalize_zip_runtime_route_evidence(payload)

    def _source_input_with_split_parts(self, task: ArchiveTask, source_input: dict[str, Any], *, format_hint: str = "") -> dict[str, Any]:
        output = dict(source_input or {})
        parts = [str(path) for path in getattr(task, "all_parts", []) or [] if str(path)]
        if len(parts) <= 1:
            return output
        if output.get("kind") == "concat_ranges" and output.get("ranges"):
            return output
        output["parts"] = [{"path": path, "role": "volume"} for path in parts]
        output["split_sidecars_available"] = True
        output.setdefault("format_hint", format_hint or self._format_from_task(task))
        return output

    def _format_from_source_or_task(self, source_input: dict[str, Any], task: ArchiveTask) -> str:
        fmt = str(source_input.get("format_hint") or source_input.get("format") or "")
        if fmt:
            return self._normalize_format(fmt)
        selected = knowledge_view.selected_format(task)
        if selected:
            return self._normalize_format(str(selected))
        detected = task.detected_ext or Path(task.main_path).suffix
        return self._normalize_format(str(detected).lstrip("."))

    def _knowledge_payload(
        self,
        task: ArchiveTask,
        *,
        source_input: dict[str, Any],
        analysis_prepass: dict[str, Any],
        analysis_evidence: ArchiveFormatEvidence | None,
        extraction_failure: dict[str, Any],
        extraction_diagnostics: dict[str, Any],
        repair_history: dict[str, Any],
        route_payload: dict[str, Any],
        verification: VerificationResult,
        phase_timer: Callable[..., Any] | None = None,
        phase_prefix: str = "build_repair_job_knowledge_payload",
    ) -> dict[str, Any]:
        return write_repair_job_context(
            task,
            source_input=source_input,
            analysis_prepass=analysis_prepass,
            analysis_evidence=analysis_evidence,
            extraction_failure=extraction_failure,
            extraction_diagnostics=extraction_diagnostics,
            repair_history=repair_history,
            route_payload=route_payload,
            verification=verification,
            phase_timer=phase_timer,
            phase_prefix=phase_prefix,
        )

    def _source_derivation_from_task(self, task: ArchiveTask) -> dict[str, Any]:
        return knowledge_view.source_derivation(task)

    def _zip_structure_features_from_task(self, task: ArchiveTask) -> dict[str, Any]:
        return knowledge_view.zip_structure_features(task)

    def _zip_container_tags_from_task(self, task: ArchiveTask) -> list[str]:
        return knowledge_view.zip_container_tags(task)

    def _damage_profile_from_task(self, task: ArchiveTask) -> str:
        return knowledge_view.damage_profile(task)

    def _source_input_from_task(self, task: ArchiveTask, *, format_hint: str = "") -> dict[str, Any] | None:
        descriptor = task.archive_state().to_archive_input_descriptor()
        source_input = descriptor.to_source_input()
        if source_input:
            if format_hint and not source_input.get("format_hint"):
                source_input["format_hint"] = format_hint
            return source_input
        return None

    def _source_input_from_archive_input(self, raw: dict[str, Any], *, archive_path: str, part_paths: list[str]) -> dict[str, Any] | None:
        descriptor = ArchiveInputDescriptor.from_dict(raw, archive_path=archive_path, part_paths=part_paths)
        if descriptor.open_mode == "file":
            return {"kind": "file", "path": descriptor.entry_path, "format_hint": descriptor.format_hint}
        if descriptor.open_mode == "file_range":
            part = descriptor.parts[0] if descriptor.parts else None
            item_range = part.range if part and part.range else None
            if item_range is None and descriptor.segment is not None:
                item_range = ArchiveInputRange(path=descriptor.entry_path, start=descriptor.segment.start, end=descriptor.segment.end)
            if item_range is None:
                return {"kind": "file", "path": descriptor.entry_path, "format_hint": descriptor.format_hint}
            return {"kind": "file_range", "path": item_range.path, "start": item_range.start, "end": item_range.end, "format_hint": descriptor.format_hint}
        if descriptor.open_mode == "concat_ranges" and descriptor.ranges:
            return {"kind": "concat_ranges", "ranges": [item.to_dict() for item in descriptor.ranges], "format_hint": descriptor.format_hint}
        if descriptor.parts:
            ranges = [
                {"path": part.path, "start": 0, "end": None}
                for part in descriptor.parts
            ]
            return {"kind": "concat_ranges", "ranges": ranges, "format_hint": descriptor.format_hint}
        return None

    @staticmethod
    def _password_from_task(task: ArchiveTask) -> str | None:
        return knowledge_view.archive_password(task)

    def _descriptor_from_repaired_input(self, task: ArchiveTask, repaired_input: dict[str, Any]) -> ArchiveInputDescriptor | None:
        if not repaired_input:
            return None
        if repaired_input.get("kind") == "archive_input" or repaired_input.get("open_mode"):
            return ArchiveInputDescriptor.from_dict(repaired_input, archive_path=task.main_path, part_paths=list(task.all_parts or []))
        kind = str(repaired_input.get("kind") or "file").lower()
        format_hint = str(repaired_input.get("format_hint") or repaired_input.get("format") or self._format_from_task(task))
        if kind == "file":
            path = str(repaired_input.get("path") or repaired_input.get("archive_path") or "")
            if not path:
                return None
            return ArchiveInputDescriptor(
                entry_path=path,
                open_mode="file",
                format_hint=format_hint,
                logical_name=str(task.logical_name or ""),
                parts=[ArchiveInputPart(path=path)],
                analysis={"source": "repair", "module": str(knowledge_view.get(task, "repair.last_result.module_name", ""))},
            )
        if kind in {"file_range", "concat_ranges"}:
            return ArchiveInputDescriptor.from_source_input(repaired_input, archive_path=task.main_path, part_paths=list(task.all_parts or []))
        return None

    def _failure_payload(self, task: ArchiveTask, result: ExtractionResult, *, format_hint: str = "") -> dict[str, Any]:
        flags = self._flags_from_failure_text(result.error)
        diagnostics = dict(result.diagnostics or {})
        worker_result = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
        native_diagnostics = worker_result.get("diagnostics") if isinstance(worker_result.get("diagnostics"), dict) else {}
        split_payload_damage = self._split_payload_damage_signal(task, worker_result, native_diagnostics)
        fmt = self._normalize_format(format_hint) if format_hint else self._format_from_task(task)
        payload = {
            "status": "failed",
            "format": fmt,
            "error": result.error,
            "damaged": "damaged" in flags or split_payload_damage,
            "checksum_error": "checksum_error" in flags or "crc_error" in flags or split_payload_damage,
            "missing_volume": "missing_volume" in flags,
            "wrong_password": "wrong_password" in flags,
            "archive_type": fmt,
        }
        if worker_result:
            for key in (
                "status",
                "native_status",
                "operation_result",
                "operation_result_name",
                "encrypted",
                "damaged",
                "checksum_error",
                "missing_volume",
                "wrong_password",
                "unsupported_method",
                "archive_type",
                "failed_item",
                "failure_stage",
                "failure_kind",
                "hresult",
                "hresult_hex",
                "message",
                "files_written",
                "bytes_written",
            ):
                if key in worker_result:
                    payload[key] = worker_result[key]
            if split_payload_damage:
                payload["damaged"] = True
                payload["checksum_error"] = True
                payload["wrong_password"] = False
                payload.setdefault("failure_kind", "data_error")
            worker_native = worker_result.get("diagnostics") if isinstance(worker_result.get("diagnostics"), dict) else {}
            output_trace = worker_native.get("output_trace") if isinstance(worker_native.get("output_trace"), dict) else {}
            if output_trace:
                payload["output_trace"] = dict(output_trace)
                items = output_trace.get("items") if isinstance(output_trace.get("items"), list) else []
                payload["complete_items"] = [dict(item) for item in items if isinstance(item, dict) and not item.get("failed")]
                payload["failed_items"] = [dict(item) for item in items if isinstance(item, dict) and item.get("failed")]
        if result.partial_outputs:
            payload["partial_outputs"] = True
        if result.progress_manifest:
            payload["progress_manifest"] = result.progress_manifest
        for key in ("failure_stage", "failure_kind"):
            if diagnostics.get(key) and not payload.get(key):
                payload[key] = diagnostics[key]
            if native_diagnostics.get(key) and not payload.get(key):
                payload[key] = native_diagnostics[key]
        if diagnostics:
            payload["diagnostics"] = diagnostics
        if native_diagnostics:
            payload["native_diagnostics"] = native_diagnostics
        return payload

    def _split_payload_damage_signal(
        self,
        task: ArchiveTask,
        worker_result: dict[str, Any],
        native_diagnostics: dict[str, Any],
    ) -> bool:
        is_split = bool(getattr(task.split_info, "is_split", False) or len(task.all_parts or []) > 1)
        if not is_split:
            return False
        for payload in (worker_result, native_diagnostics):
            if not isinstance(payload, dict):
                continue
            if payload.get("damaged") or payload.get("checksum_error"):
                return True
            if str(payload.get("native_status") or "").lower() == "damaged":
                return True
            failure_kind = str(payload.get("failure_kind") or "").lower()
            if failure_kind in {"corrupted_data", "data_error", "checksum_error", "crc_error"}:
                return True
        return False

    def _flags_from_failure_text(self, error: str) -> list[str]:
        text = str(error or "").lower()
        flags = []
        if "密码" in text or "password" in text:
            flags.append("wrong_password")
        if "分卷" in text or "volume" in text:
            flags.append("missing_volume")
        if "crc" in text or "校验" in text or "checksum" in text:
            flags.append("checksum_error")
        if "损坏" in text or "damage" in text or "corrupt" in text or "fatal error" in text:
            flags.append("damaged")
        return flags

    def _flags_from_verification(self, verification: VerificationResult) -> list[str]:
        flags = []
        if verification.source_integrity in {"damaged", "truncated", "payload_damaged"}:
            flags.append("damaged")
        if verification.source_integrity == "truncated":
            flags.append("probably_truncated")
        if verification.source_integrity == "payload_damaged":
            flags.append("checksum_error")
            flags.append("crc_error")
        if verification.completeness < 0.999:
            flags.append("exact_match_failed")
        coverage = verification.archive_coverage
        expected = int(getattr(coverage, "expected_files", 0) or 0) if coverage is not None else 0
        matched = int(getattr(coverage, "matched_files", 0) or getattr(coverage, "complete_files", 0) or 0) if coverage is not None else 0
        failed = int(getattr(coverage, "failed_files", 0) or 0) if coverage is not None else 0
        missing = int(getattr(coverage, "missing_files", 0) or 0) if coverage is not None else 0
        partial = int(getattr(coverage, "partial_files", 0) or 0) if coverage is not None else 0
        if expected and matched < expected:
            flags.append("partial_entries_remaining")
        if failed or missing or partial:
            flags.append("content_integrity_bad_or_unknown")
        if verification.assessment_status == "complete" and verification.source_integrity not in {"complete", "trusted"}:
            flags.extend(["content_integrity_bad_or_unknown", "exact_match_failed"])
        for issue in verification.issues:
            code = issue.code.lower()
            if "crc" in code or "checksum" in code:
                flags.extend(["checksum_error", "crc_error"])
            if "missing" in code:
                flags.append("missing_entries")
            if "size_under" in code or "file_count_under" in code:
                flags.append("probably_truncated")
        return _dedupe(flags)

    def _analysis_evidences_from_facts(self, task: ArchiveTask) -> list[ArchiveFormatEvidence]:
        evidences = []
        for item in knowledge_view.analysis_evidences(task):
            if not isinstance(item, dict):
                continue
            segments = [
                ArchiveSegment(
                    start_offset=int(segment.get("start_offset", 0) or 0),
                    end_offset=int(segment["end_offset"]) if segment.get("end_offset") is not None else None,
                    confidence=float(segment.get("confidence", 0.0) or 0.0),
                    role=str(segment.get("role") or "primary"),
                    damage_flags=list(segment.get("damage_flags") or []),
                    evidence=list(segment.get("evidence") or []),
                )
                for segment in item.get("segments") or []
                if isinstance(segment, dict)
            ]
            evidences.append(ArchiveFormatEvidence(
                format=str(item.get("format") or ""),
                confidence=float(item.get("confidence", 0.0) or 0.0),
                status=str(item.get("status") or "not_found"),
                segments=segments,
                warnings=list(item.get("warnings") or []),
                details=dict(item.get("details") or {}),
            ))
        return evidences

    def _analysis_evidence_from_facts(self, task: ArchiveTask) -> ArchiveFormatEvidence | None:
        evidences = self._analysis_evidences_from_facts(task)
        if not evidences:
            return None
        selected_format = knowledge_view.selected_format(task)
        if selected_format:
            for evidence in evidences:
                if evidence.format == selected_format:
                    return evidence
        return max(evidences, key=lambda item: item.confidence)

    def _damage_flags_from_evidence(self, evidence: ArchiveFormatEvidence) -> list[str]:
        flags = []
        for segment in evidence.segments:
            flags.extend(segment.damage_flags)
        for value in evidence.details.values():
            if isinstance(value, str) and value.endswith("_bad"):
                flags.append(value)
        return _dedupe(flags)

    def _analysis_confidence(self, task: ArchiveTask) -> float:
        evidence = self._analysis_evidence_from_facts(task)
        return float(evidence.confidence) if evidence is not None else 0.0

    def _analysis_prepass(self, task: ArchiveTask) -> dict[str, Any]:
        return knowledge_view.analysis_prepass(task)

    def _analysis_fuzzy_profile(self, task: ArchiveTask) -> dict[str, Any]:
        return knowledge_view.analysis_fuzzy_profile(task)

    def _format_from_task(self, task: ArchiveTask) -> str:
        selected = knowledge_view.selected_format(task)
        if selected:
            return self._normalize_format(str(selected))
        state = task.archive_state()
        if state.format_hint or state.source.format_hint:
            return self._normalize_format(str(state.format_hint or state.source.format_hint))
        detected = task.detected_ext or Path(task.main_path).suffix
        return self._normalize_format(str(detected).lstrip("."))

    def _normalize_format(self, fmt: str) -> str:
        text = str(fmt or "").lower().lstrip(".")
        aliases = {"gz": "gzip", "bz2": "bzip2", "seven_zip": "7z"}
        return aliases.get(text, text or "unknown")

    def _result_payload(self, result: RepairResult) -> dict[str, Any]:
        payload = asdict(result)
        payload["ok"] = result.ok
        return payload

    def _workspace_root(self) -> Path:
        return Path(str(self.config.get("workspace") or ".sunpack_repair"))

    def _attempts(self, task: ArchiveTask) -> int:
        return knowledge_view.repair_attempts(task)


def _dedupe(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _nested_int(payload: dict[str, Any], path: tuple[str, ...], default: int = 0) -> int:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    try:
        return int(current or default)
    except (TypeError, ValueError):
        return default


def _append_candidate_log_from_result(task: ArchiveTask, result: RepairResult, *, phase: str, trigger: str) -> None:
    diagnosis = result.diagnosis if isinstance(result.diagnosis, dict) else {}
    features = diagnosis.get("candidate_features") if isinstance(diagnosis.get("candidate_features"), dict) else {}
    selection = diagnosis.get("candidate_selection") if isinstance(diagnosis.get("candidate_selection"), dict) else {}
    generation = diagnosis.get("candidate_generation") if isinstance(diagnosis.get("candidate_generation"), dict) else {}
    capability = diagnosis.get("capability_decision") if isinstance(diagnosis.get("capability_decision"), dict) else {}
    if not features and not selection and not generation and not capability:
        return
    log = knowledge_view.repair_candidate_log(task)
    log.append({
        "phase": phase,
        "trigger": trigger,
        "candidate": dict(features),
        "selection": dict(selection),
        "generation": dict(generation),
        "capability": dict(capability),
        "result": {
            "status": result.status,
            "ok": result.ok,
            "module": result.module_name,
            "format": result.format,
            "confidence": float(result.confidence or 0.0),
            "partial": bool(result.partial),
        },
    })
    task.fact_bag.set("repair.candidate_log", log[-200:])
    write_repair_candidate_log(task, log[-200:])


def _verification_repair_hints(verification: VerificationResult) -> dict[str, Any]:
    hints = getattr(verification, "repair_hints", None)
    return dict(hints) if isinstance(hints, dict) else {}


def _policy_probe_run_id(task: ArchiveTask) -> str:
    return str(
        os.environ.get("SUNPACK_REPAIR_POLICY_PROBE_RUN_ID")
        or knowledge_view.sample_id(task)
        or task.key
        or task.main_path
    )


def _merge_repair_hints_into_failure(failure: dict[str, Any], hints: dict[str, Any]) -> None:
    if not hints:
        return
    if hints.get("failure_stage") and failure.get("failure_stage"):
        failure.setdefault("underlying_failure_stage", failure.get("failure_stage"))
    if hints.get("failure_kind") and failure.get("failure_kind"):
        failure.setdefault("underlying_failure_kind", failure.get("failure_kind"))
    for key in ("failure_kind", "native_status", "analysis_status", "selected_format"):
        if hints.get(key) and not failure.get(key):
            failure[key] = hints[key]
    if hints.get("failure_stage") and not failure.get("failure_stage"):
        failure["failure_stage"] = hints["failure_stage"]
    if hints.get("segment_start") is not None or hints.get("segment_end") is not None:
        failure["analysis_segment"] = {
            "start": hints.get("segment_start"),
            "end": hints.get("segment_end"),
        }


def _flags_from_repair_hints(hints: dict[str, Any]) -> list[str]:
    flags = [str(item) for item in hints.get("damage_flags") or [] if str(item or "")]
    failure_kind = str(hints.get("failure_kind") or "").lower()
    native_status = str(hints.get("native_status") or "").lower()
    analysis_status = str(hints.get("analysis_status") or "").lower()
    if failure_kind in {"unexpected_end", "input_truncated", "stream_truncated"}:
        flags.append("probably_truncated")
    if failure_kind in {"checksum_error", "corrupted_data", "data_error", "crc_error"}:
        flags.extend(["damaged", "checksum_error"])
    if native_status == "damaged" or analysis_status in {"damaged", "weak"}:
        flags.append("damaged")
    return _dedupe(flags)


def _verification_summary_payload(verification: VerificationResult) -> dict[str, Any]:
    coverage = getattr(verification, "archive_coverage", None)
    return {
        "completeness": float(getattr(verification, "completeness", 0.0) or 0.0),
        "recoverable_upper_bound": float(getattr(verification, "recoverable_upper_bound", 0.0) or 0.0),
        "assessment_status": str(getattr(verification, "assessment_status", "") or ""),
        "source_integrity": str(getattr(verification, "source_integrity", "") or ""),
        "decision_hint": str(getattr(verification, "decision_hint", "") or ""),
        "archive_coverage": {
            "completeness": float(getattr(coverage, "completeness", 0.0) or 0.0) if coverage is not None else 0.0,
            "file_coverage": float(getattr(coverage, "file_coverage", 0.0) or 0.0) if coverage is not None else 0.0,
            "byte_coverage": float(getattr(coverage, "byte_coverage", 0.0) or 0.0) if coverage is not None else 0.0,
            "expected_files": int(getattr(coverage, "expected_files", 0) or 0) if coverage is not None else 0,
            "matched_files": int(getattr(coverage, "matched_files", 0) or 0) if coverage is not None else 0,
            "complete_files": int(getattr(coverage, "complete_files", 0) or 0) if coverage is not None else 0,
            "partial_files": int(getattr(coverage, "partial_files", 0) or 0) if coverage is not None else 0,
            "failed_files": int(getattr(coverage, "failed_files", 0) or 0) if coverage is not None else 0,
            "missing_files": int(getattr(coverage, "missing_files", 0) or 0) if coverage is not None else 0,
        },
    }


def _phase(timer: Callable[..., Any] | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
