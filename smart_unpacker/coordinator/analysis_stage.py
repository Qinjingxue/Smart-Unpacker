import os
from dataclasses import asdict
from typing import Any

from smart_unpacker.analysis import ArchiveAnalysisReport, ArchiveAnalysisScheduler
from smart_unpacker.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from smart_unpacker.contracts.tasks import ArchiveTask


class ArchiveAnalysisStage:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        analysis_config = self.config.get("analysis") if isinstance(self.config.get("analysis"), dict) else {}
        self.enabled = bool(analysis_config.get("enabled", True))
        self.scheduler = ArchiveAnalysisScheduler(self.config) if self.enabled else None

    def analyze_tasks(self, tasks: list[ArchiveTask]) -> list[ArchiveTask]:
        if not self.enabled or self.scheduler is None:
            return tasks
        for task in tasks:
            self.analyze_task(task)
        return tasks

    def analyze_task(self, task: ArchiveTask) -> ArchiveAnalysisReport | None:
        if self.scheduler is None:
            return None
        try:
            report = self.scheduler.analyze_task(task)
        except Exception as exc:
            task.fact_bag.set("analysis.status", "error")
            task.fact_bag.set("analysis.error", str(exc))
            return None

        self._record_report(task, report)
        selected = self._select_extractable_evidence(report)
        if selected is None:
            return report

        segment = selected.segments[0]
        segment_payload = self._segment_payload(task, selected, segment)
        archive_input = self._archive_input_for_segment(task, selected, segment)
        task.fact_bag.set("analysis.status", selected.status)
        task.fact_bag.set("analysis.selected_format", selected.format)
        task.fact_bag.set("analysis.segment", segment_payload)
        if archive_input:
            task.fact_bag.set("archive.input", archive_input)
        return report

    def _record_report(self, task: ArchiveTask, report: ArchiveAnalysisReport) -> None:
        task.fact_bag.set("analysis.status", "extractable" if report.has_extractable else "not_extractable")
        task.fact_bag.set("analysis.read_bytes", report.read_bytes)
        task.fact_bag.set("analysis.cache_hits", report.cache_hits)
        task.fact_bag.set("analysis.prepass", report.prepass)
        task.fact_bag.set(
            "analysis.evidences",
            [
                {
                    "format": evidence.format,
                    "confidence": evidence.confidence,
                    "status": evidence.status,
                    "warnings": list(evidence.warnings),
                    "details": dict(evidence.details),
                    "segments": [asdict(segment) for segment in evidence.segments],
                }
                for evidence in report.evidences
            ],
        )

    def _select_extractable_evidence(self, report: ArchiveAnalysisReport) -> ArchiveFormatEvidence | None:
        candidates = [
            evidence
            for evidence in report.selected
            if evidence.segments and evidence.segments[0].end_offset is not None
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda evidence: evidence.confidence)

    def _segment_payload(self, task: ArchiveTask, evidence: ArchiveFormatEvidence, segment: ArchiveSegment) -> dict:
        payload = asdict(segment)
        payload.update({
            "format": evidence.format,
            "format_hint": evidence.format,
            "path": task.main_path,
        })
        return payload

    def _archive_input_for_segment(
        self,
        task: ArchiveTask,
        evidence: ArchiveFormatEvidence,
        segment: ArchiveSegment,
    ) -> dict | None:
        parts = self._ordered_parts(task)
        if not parts:
            return None
        if evidence.format == "rar":
            return None
        if len(parts) == 1:
            if int(segment.start_offset) <= 0:
                return None
            if self._is_standard_archive_path(parts[0]):
                return None
            return {
                "kind": "file_range",
                "path": parts[0],
                "start": int(segment.start_offset),
                "end": int(segment.end_offset) if segment.end_offset is not None else None,
                "format_hint": evidence.format,
            }
        ranges = self._logical_range_to_file_ranges(
            parts,
            int(segment.start_offset),
            int(segment.end_offset) if segment.end_offset is not None else None,
        )
        if not ranges:
            return None
        return {
            "kind": "concat_ranges",
            "ranges": ranges,
            "format_hint": evidence.format,
        }

    def _ordered_parts(self, task: ArchiveTask) -> list[str]:
        volumes = list(getattr(task.split_info, "volumes", None) or [])
        if volumes:
            numbered = [
                (int(volume.get("number") or 0), str(volume.get("path") or ""))
                for volume in volumes
                if isinstance(volume, dict) and volume.get("path")
            ]
            numbered.sort(key=lambda item: item[0])
            paths = [path for _, path in numbered]
            if paths:
                return paths
        return list(task.all_parts or [task.main_path])

    def _is_standard_archive_path(self, path: str) -> bool:
        name = os.path.basename(path).lower()
        suffixes = []
        root = name
        while True:
            root, ext = os.path.splitext(root)
            if not ext:
                break
            suffixes.append(ext)
        if not suffixes:
            return False
        archive_exts = {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".zst"}
        split_exts = {".001"}
        return any(ext in archive_exts or ext in split_exts for ext in suffixes)

    def _logical_range_to_file_ranges(self, parts: list[str], start: int, end: int | None) -> list[dict]:
        ranges = []
        cursor = 0
        for path in parts:
            try:
                size = os.path.getsize(path)
            except OSError:
                return []
            part_start = cursor
            part_end = cursor + size
            cursor = part_end
            if end is not None and start >= end:
                break
            if start >= part_end:
                continue
            if end is not None and end <= part_start:
                break
            local_start = max(start, part_start) - part_start
            local_end = size if end is None else min(end, part_end) - part_start
            if local_end <= local_start:
                continue
            ranges.append({
                "path": path,
                "start": int(local_start),
                "end": int(local_end),
            })
        return ranges
