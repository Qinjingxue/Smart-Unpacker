from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from smart_unpacker.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from smart_unpacker.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    ArchiveInputRange,
)
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.repair.config import repair_config
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.result import RepairResult
from smart_unpacker.repair.scheduler import RepairScheduler


class ArchiveRepairStage:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = repair_config(config or {})
        self.enabled = bool(self.config.get("enabled", True))
        self.scheduler = RepairScheduler(config or {}) if self.enabled else None
        thresholds = self.config.get("thresholds") if isinstance(self.config.get("thresholds"), dict) else {}
        self.medium_min = float(thresholds.get("medium_confidence_min", 0.35) or 0.35)
        self.extractable_confidence = float(thresholds.get("extractable_confidence", 0.85) or 0.85)
        round_limit = self.config.get("max_repair_rounds_per_task", self.config.get("max_attempts_per_task", 3))
        self.max_attempts_per_task = max(0, int(round_limit or 0))

    def repair_medium_confidence_tasks(self, tasks: list[ArchiveTask]) -> None:
        if not self.enabled or self.scheduler is None or not self.config.get("trigger_on_medium_confidence", True):
            return
        for task in tasks:
            self.repair_medium_confidence_task(task)

    def repair_medium_confidence_task(self, task: ArchiveTask) -> RepairResult | None:
        if not self.enabled or self.scheduler is None or not self.config.get("trigger_on_medium_confidence", True):
            return None
        evidence = self._medium_confidence_evidence(task)
        if evidence is None:
            return None
        job = self._job_from_analysis(task, evidence)
        if job is None:
            return None
        return self._run_and_apply(task, job, trigger="analysis")

    def repair_after_extraction_failure(self, task: ArchiveTask, result: ExtractionResult) -> bool:
        repair_result = self.repair_after_extraction_failure_result(task, result)
        return bool(repair_result and repair_result.ok)

    def repair_after_extraction_failure_result(self, task: ArchiveTask, result: ExtractionResult) -> RepairResult | None:
        if not self.enabled or self.scheduler is None or not self.config.get("trigger_on_extraction_failure", True):
            return None
        if result.success or self._attempts(task) >= self.max_attempts_per_task:
            return None
        job = self._job_from_extraction_failure(task, result)
        if job is None:
            return None
        return self._run_and_apply(task, job, trigger="extraction")

    def _run_and_apply(self, task: ArchiveTask, job: RepairJob, *, trigger: str) -> RepairResult | None:
        if self.scheduler is None or self._attempts(task) >= self.max_attempts_per_task:
            return None
        attempts = self._attempts(task) + 1
        task.fact_bag.set("repair.attempts", attempts)
        task.fact_bag.set("repair.last_trigger", trigger)
        result = self.scheduler.repair(job)
        task.fact_bag.set("repair.last_result", self._result_payload(result))
        if not result.ok:
            return result
        task.fact_bag.set("repair.status", result.status)
        task.fact_bag.set("repair.module", result.module_name)
        descriptor = self._descriptor_from_repaired_input(task, result.repaired_input or {})
        if descriptor is None:
            return result
        task.set_archive_input(descriptor)
        if job.password is not None:
            task.fact_bag.set("archive.password", job.password)
        task.fact_bag.set("archive.repaired", True)
        return result

    def _job_from_analysis(self, task: ArchiveTask, evidence: ArchiveFormatEvidence) -> RepairJob | None:
        source_input = self._source_input_for_evidence(task, evidence)
        if source_input is None:
            return None
        flags = self._damage_flags_from_evidence(evidence)
        return RepairJob(
            source_input=source_input,
            format=self._normalize_format(evidence.format),
            confidence=float(evidence.confidence),
            analysis_evidence=evidence,
            analysis_prepass=self._analysis_prepass(task),
            fuzzy_profile=self._analysis_fuzzy_profile(task),
            damage_flags=flags,
            archive_key=task.key,
            workspace=str(self._workspace_root()),
            attempts=self._attempts(task),
            source_descriptor=ArchiveInputDescriptor.from_any(
                source_input,
                archive_path=task.main_path,
                part_paths=list(task.all_parts or []),
                format_hint=self._normalize_format(evidence.format),
                logical_name=str(task.logical_name or ""),
            ),
        )

    def _job_from_extraction_failure(self, task: ArchiveTask, result: ExtractionResult) -> RepairJob | None:
        source_input = self._source_input_from_task(task)
        if source_input is None:
            return None
        failure = self._failure_payload(task, result)
        return RepairJob(
            source_input=source_input,
            format=self._format_from_task(task),
            confidence=float(self._analysis_confidence(task) or 0.0),
            analysis_evidence=self._analysis_evidence_from_facts(task),
            analysis_prepass=self._analysis_prepass(task),
            fuzzy_profile=self._analysis_fuzzy_profile(task),
            extraction_failure=failure,
            extraction_diagnostics=dict(result.diagnostics or {}),
            damage_flags=self._flags_from_failure_text(result.error),
            password=result.password_used,
            archive_key=task.key,
            workspace=str(self._workspace_root()),
            attempts=self._attempts(task),
            source_descriptor=task.archive_input(),
        )

    def _medium_confidence_evidence(self, task: ArchiveTask) -> ArchiveFormatEvidence | None:
        evidences = [
            evidence
            for evidence in self._analysis_evidences_from_facts(task)
            if self.medium_min <= evidence.confidence < self.extractable_confidence
            and evidence.status in {"weak", "damaged", "extractable"}
            and (evidence.segments or self._damage_flags_from_evidence(evidence))
        ]
        if not evidences:
            return None
        return max(evidences, key=lambda item: item.confidence)

    def _source_input_for_evidence(self, task: ArchiveTask, evidence: ArchiveFormatEvidence) -> dict[str, Any] | None:
        current_source = task.archive_input()
        current_parts = current_source.part_paths() or list(task.all_parts or [task.main_path])
        current_entry = current_source.entry_path or task.main_path
        if evidence.segments:
            segment = evidence.segments[0]
            if len(current_parts) > 1:
                ranges = self._logical_range_to_file_ranges(
                    current_parts,
                    int(segment.start_offset),
                    int(segment.end_offset) if segment.end_offset is not None else None,
                )
                if ranges:
                    return {"kind": "concat_ranges", "ranges": ranges, "format_hint": evidence.format}
            if int(segment.start_offset) > 0 or segment.end_offset is not None:
                payload: dict[str, Any] = {
                    "kind": "file_range",
                    "path": current_entry,
                    "start": int(segment.start_offset),
                    "format_hint": evidence.format,
                }
                if segment.end_offset is not None:
                    payload["end"] = int(segment.end_offset)
                return payload
        return self._source_input_from_task(task, format_hint=evidence.format)

    def _source_input_from_task(self, task: ArchiveTask, *, format_hint: str = "") -> dict[str, Any] | None:
        raw = task.fact_bag.get("archive.input")
        if isinstance(raw, dict):
            source_input = task.archive_input().to_legacy_source_input()
            if source_input:
                if format_hint and not source_input.get("format_hint"):
                    source_input["format_hint"] = format_hint
                return source_input
        parts = list(task.all_parts or [task.main_path])
        if len(parts) > 1:
            return {
                "kind": "concat_ranges",
                "ranges": [{"path": path, "start": 0, "end": None} for path in parts],
                "format_hint": format_hint or self._format_from_task(task),
            }
        return {"kind": "file", "path": task.main_path, "format_hint": format_hint or self._format_from_task(task)}

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
                analysis={"source": "repair", "module": task.fact_bag.get("repair.module", "")},
            )
        if kind in {"file_range", "concat_ranges"}:
            return ArchiveInputDescriptor.from_legacy(repaired_input, archive_path=task.main_path, part_paths=list(task.all_parts or []))
        return None

    def _failure_payload(self, task: ArchiveTask, result: ExtractionResult) -> dict[str, Any]:
        flags = self._flags_from_failure_text(result.error)
        diagnostics = dict(result.diagnostics or {})
        worker_result = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
        native_diagnostics = worker_result.get("diagnostics") if isinstance(worker_result.get("diagnostics"), dict) else {}
        payload = {
            "status": "failed",
            "format": self._format_from_task(task),
            "error": result.error,
            "damaged": "damaged" in flags,
            "checksum_error": "checksum_error" in flags or "crc_error" in flags,
            "missing_volume": "missing_volume" in flags,
            "wrong_password": "wrong_password" in flags,
            "archive_type": self._format_from_task(task),
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

    def _analysis_evidences_from_facts(self, task: ArchiveTask) -> list[ArchiveFormatEvidence]:
        evidences = []
        for item in task.fact_bag.get("analysis.evidences") or []:
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
        selected_format = task.fact_bag.get("analysis.selected_format")
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
        prepass = task.fact_bag.get("analysis.prepass")
        return dict(prepass) if isinstance(prepass, dict) else {}

    def _analysis_fuzzy_profile(self, task: ArchiveTask) -> dict[str, Any]:
        fuzzy = task.fact_bag.get("analysis.fuzzy")
        if isinstance(fuzzy, dict) and isinstance(fuzzy.get("binary_profile"), dict):
            return dict(fuzzy["binary_profile"])
        return {}

    def _format_from_task(self, task: ArchiveTask) -> str:
        selected = task.fact_bag.get("analysis.selected_format")
        if selected:
            return self._normalize_format(str(selected))
        archive_input = task.fact_bag.get("archive.input")
        if isinstance(archive_input, dict) and archive_input.get("format_hint"):
            return self._normalize_format(str(task.archive_input().format_hint))
        detected = task.detected_ext or Path(task.main_path).suffix
        return self._normalize_format(str(detected).lstrip("."))

    def _normalize_format(self, fmt: str) -> str:
        text = str(fmt or "").lower().lstrip(".")
        aliases = {"gz": "gzip", "bz2": "bzip2", "seven_zip": "7z"}
        return aliases.get(text, text or "unknown")

    def _logical_range_to_file_ranges(self, parts: list[str], start: int, end: int | None) -> list[dict[str, Any]]:
        ranges = []
        cursor = 0
        for path in parts:
            try:
                size = Path(path).stat().st_size
            except OSError:
                return []
            part_start = cursor
            part_end = cursor + size
            cursor = part_end
            if start >= part_end:
                continue
            if end is not None and end <= part_start:
                break
            local_start = max(start, part_start) - part_start
            local_end = size if end is None else min(end, part_end) - part_start
            if local_end > local_start:
                ranges.append({"path": path, "start": int(local_start), "end": int(local_end)})
        return ranges

    def _result_payload(self, result: RepairResult) -> dict[str, Any]:
        payload = asdict(result)
        payload["ok"] = result.ok
        return payload

    def _workspace_root(self) -> Path:
        return Path(str(self.config.get("workspace") or ".smart_unpacker_repair"))

    def _attempts(self, task: ArchiveTask) -> int:
        return int(task.fact_bag.get("repair.attempts", 0) or 0)


def _dedupe(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
