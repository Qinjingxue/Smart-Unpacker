import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, replace
from typing import Any

from packrelic.analysis import ArchiveAnalysisReport, ArchiveAnalysisScheduler
from packrelic.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from packrelic.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    ArchiveInputRange,
    ArchiveInputSegment,
)
from packrelic.contracts.archive_state import ArchiveState
from packrelic.contracts.detection import FactBag
from packrelic.contracts.tasks import ArchiveTask, SplitArchiveInfo


class ArchiveAnalysisStage:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        analysis_config = self.config.get("analysis") if isinstance(self.config.get("analysis"), dict) else {}
        self.enabled = bool(analysis_config.get("enabled", True))
        self.scheduler = ArchiveAnalysisScheduler(self.config) if self.enabled else None
        self._report_cache: dict[tuple, ArchiveAnalysisReport] = {}
        self._report_cache_lock = threading.Lock()

    def analyze_tasks(self, tasks: list[ArchiveTask]) -> list[ArchiveTask]:
        if not self.enabled or self.scheduler is None:
            return tasks
        groups = self._analysis_task_groups(tasks)
        max_workers = self._task_max_workers(len(groups))
        if max_workers > 1:
            grouped_results: list[list[ArchiveTask]] = [[] for _ in tasks]
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self._analyze_task_group, group): group
                    for group in groups
                }
                for future in as_completed(futures):
                    for index, task_results in future.result():
                        grouped_results[index] = task_results
            return [
                task_result
                for task_results in grouped_results
                for task_result in task_results
            ]
        expanded_tasks: list[ArchiveTask] = []
        for group in groups:
            for _index, task_results in self._analyze_task_group(group):
                expanded_tasks.extend(task_results)
        return expanded_tasks

    def _task_max_workers(self, task_count: int) -> int:
        if task_count <= 1:
            return 1
        analysis_config = self.config.get("analysis") if isinstance(self.config.get("analysis"), dict) else {}
        if not bool(analysis_config.get("task_parallel", True)):
            return 1
        configured = analysis_config.get("task_max_workers")
        if configured is None:
            configured = min(4, os.cpu_count() or 1)
        return max(1, min(int(configured or 1), task_count))

    def _remember_report(self, cache_key: tuple, report: ArchiveAnalysisReport) -> None:
        analysis_config = self.config.get("analysis") if isinstance(self.config.get("analysis"), dict) else {}
        limit = max(0, int(analysis_config.get("cache_size", 512) or 512))
        if limit <= 0:
            return
        with self._report_cache_lock:
            if len(self._report_cache) >= limit:
                self._report_cache.pop(next(iter(self._report_cache)))
            self._report_cache[cache_key] = report

    def _analysis_cache_key(self, task: ArchiveTask) -> tuple:
        try:
            patch_digest = task.archive_state().effective_patch_digest()
        except (TypeError, ValueError, AttributeError):
            patch_digest = str(task.fact_bag.get("archive.patch_digest") or "")
        parts = self._ordered_parts(task) or list(task.all_parts or [task.main_path])
        return (
            patch_digest,
            tuple(self._path_cache_fingerprint(path) for path in parts if path),
        )

    @staticmethod
    def _path_cache_fingerprint(path: str) -> tuple:
        normalized = os.path.abspath(os.path.normpath(path))
        try:
            stat = os.stat(normalized)
            return (normalized, int(stat.st_size), int(stat.st_mtime_ns))
        except OSError:
            return (normalized, -1, -1)

    def _analysis_task_groups(self, tasks: list[ArchiveTask]) -> list[list[tuple[int, ArchiveTask]]]:
        grouped: dict[tuple, list[tuple[int, ArchiveTask]]] = {}
        order: list[tuple] = []
        for index, task in enumerate(tasks):
            try:
                task.ensure_archive_state()
                cache_key = self._analysis_cache_key(task)
            except Exception:
                cache_key = ("task", id(task))
            if cache_key not in grouped:
                grouped[cache_key] = []
                order.append(cache_key)
            grouped[cache_key].append((index, task))
        return [grouped[key] for key in order]

    def _analyze_task_group(self, group: list[tuple[int, ArchiveTask]]) -> list[tuple[int, list[ArchiveTask]]]:
        if not group:
            return []
        if len(group) == 1:
            index, task = group[0]
            _, task_results = self._analyze_task_to_tasks(task)
            return [(index, task_results)]
        first_index, first_task = group[0]
        report, first_results = self._analyze_task_to_tasks(first_task)
        results = [(first_index, first_results)]
        if report is None:
            for index, task in group[1:]:
                task.fact_bag.set("analysis.status", first_task.fact_bag.get("analysis.status") or "error")
                if first_task.fact_bag.get("analysis.error"):
                    task.fact_bag.set("analysis.error", first_task.fact_bag.get("analysis.error"))
                results.append((index, [task]))
            return results
        for index, task in group[1:]:
            task_report = replace(report, cache_hits=report.cache_hits + 1)
            results.append((index, self._tasks_from_report(task, task_report)))
        return results

    def analyze_task(self, task: ArchiveTask) -> ArchiveAnalysisReport | None:
        report, _ = self._analyze_task_to_tasks(task)
        return report

    def analyze_task_to_tasks(self, task: ArchiveTask) -> list[ArchiveTask]:
        _, tasks = self._analyze_task_to_tasks(task)
        return tasks

    def _analyze_task_to_tasks(self, task: ArchiveTask) -> tuple[ArchiveAnalysisReport | None, list[ArchiveTask]]:
        if self.scheduler is None:
            return None, [task]
        task.ensure_archive_state()
        try:
            report = self._get_or_analyze_report(task)
        except Exception as exc:
            task.fact_bag.set("analysis.status", "error")
            task.fact_bag.set("analysis.error", str(exc))
            return None, [task]

        return report, self._tasks_from_report(task, report)

    def _get_or_analyze_report(self, task: ArchiveTask) -> ArchiveAnalysisReport:
        cache_key = self._analysis_cache_key(task)
        with self._report_cache_lock:
            report = self._report_cache.get(cache_key)
        if report is None:
            report = self.scheduler.analyze_task(task)
            self._remember_report(cache_key, report)
            return report
        return replace(report, cache_hits=report.cache_hits + 1)

    def _tasks_from_report(self, task: ArchiveTask, report: ArchiveAnalysisReport) -> list[ArchiveTask]:
        self._record_report(task, report)
        task.fact_bag.set("analysis.report_path", report.path)
        candidates = self._extractable_segments(report)
        if not candidates:
            password_candidate = self._password_required_embedded_segment(report)
            if password_candidate is not None:
                evidence, segment, index = password_candidate
                self._apply_selected_segment(task, evidence, segment, index=index)
                self._record_state_analysis(task, report)
            return [task]
        if len(candidates) == 1:
            evidence, segment, _ = candidates[0]
            self._apply_selected_segment(task, evidence, segment, index=0)
            self._record_state_analysis(task, report)
            return [task]
        return [
            self._child_task_for_segment(task, report, evidence, segment, index=index)
            for evidence, segment, index in candidates
        ]

    def _apply_selected_segment(
        self,
        task: ArchiveTask,
        evidence: ArchiveFormatEvidence,
        segment: ArchiveSegment,
        *,
        index: int,
    ) -> None:
        segment_payload = self._segment_payload(task, evidence, segment)
        archive_input = self._archive_input_for_segment(task, evidence, segment, index=index)
        task.fact_bag.set("analysis.status", evidence.status)
        task.fact_bag.set("analysis.selected_format", evidence.format)
        task.fact_bag.set("analysis.segment_index", index)
        task.fact_bag.set("analysis.segment", segment_payload)
        if archive_input:
            task.set_archive_state(ArchiveState.from_archive_input(archive_input))

    def _record_report(self, task: ArchiveTask, report: ArchiveAnalysisReport) -> None:
        task.fact_bag.set("analysis.status", "extractable" if report.has_extractable else "not_extractable")
        task.fact_bag.set("analysis.read_bytes", report.read_bytes)
        task.fact_bag.set("analysis.cache_hits", report.cache_hits)
        task.fact_bag.set("analysis.prepass", report.prepass)
        task.fact_bag.set("analysis.fuzzy", report.fuzzy)
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
        self._record_state_analysis(task, report)

    def _record_state_analysis(self, task: ArchiveTask, report: ArchiveAnalysisReport) -> None:
        state = task.archive_state()
        selected = report.selected[0] if report.selected else None
        analysis = {
            "status": "extractable" if report.has_extractable else "not_extractable",
            "report_path": report.path,
            "read_bytes": report.read_bytes,
            "cache_hits": report.cache_hits,
        }
        if selected is not None:
            analysis.update({
                "selected_format": selected.format,
                "confidence": float(selected.confidence),
            })
        task.set_archive_state(
            ArchiveState(
                source=state.source,
                patches=list(state.patches),
                patch_digest=state.effective_patch_digest(),
                logical_name=state.logical_name,
                format_hint=state.format_hint,
                analysis=analysis,
                verification=dict(state.verification),
            ),
        )

    def _extractable_segments(self, report: ArchiveAnalysisReport) -> list[tuple[ArchiveFormatEvidence, ArchiveSegment, int]]:
        candidates: list[tuple[ArchiveFormatEvidence, ArchiveSegment, int]] = []
        index = 1
        for evidence in sorted(report.selected, key=lambda item: item.confidence, reverse=True):
            for segment in evidence.segments:
                if segment.end_offset is None:
                    continue
                candidates.append((evidence, segment, index))
                index += 1
        candidates.sort(key=lambda item: (int(item[1].start_offset), item[0].format, item[2]))
        candidates = self._prefer_specific_segments(candidates)
        return [
            (evidence, segment, position)
            for position, (evidence, segment, _) in enumerate(candidates, start=1)
        ]

    def _prefer_specific_segments(
        self,
        candidates: list[tuple[ArchiveFormatEvidence, ArchiveSegment, int]],
    ) -> list[tuple[ArchiveFormatEvidence, ArchiveSegment, int]]:
        stream_to_container = {
            "gzip": "tar.gz",
            "bzip2": "tar.bz2",
            "xz": "tar.xz",
            "zstd": "tar.zst",
        }
        by_range = {
            (int(segment.start_offset), int(segment.end_offset), evidence.format)
            for evidence, segment, _ in candidates
            if segment.end_offset is not None
        }
        filtered = []
        for evidence, segment, index in candidates:
            if segment.end_offset is not None:
                container_format = stream_to_container.get(evidence.format)
                if container_format and (
                    int(segment.start_offset),
                    int(segment.end_offset),
                    container_format,
                ) in by_range:
                    continue
            filtered.append((evidence, segment, index))
        return filtered

    def _password_required_embedded_segment(
        self,
        report: ArchiveAnalysisReport,
    ) -> tuple[ArchiveFormatEvidence, ArchiveSegment, int] | None:
        candidates: list[tuple[ArchiveFormatEvidence, ArchiveSegment, int]] = []
        for evidence in report.evidences:
            if not evidence.details.get("password_required"):
                continue
            for index, segment in enumerate(evidence.segments, start=1):
                if int(segment.start_offset) <= 0:
                    continue
                candidates.append((evidence, segment, 0))
        if not candidates:
            return None
        return sorted(candidates, key=lambda item: (-item[0].confidence, int(item[1].start_offset)))[0]

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
        *,
        index: int = 1,
    ) -> ArchiveInputDescriptor | None:
        parts = self._ordered_parts(task)
        if not parts:
            return None
        if len(parts) == 1:
            if int(segment.start_offset) <= 0:
                return None
            if self._is_standard_archive_path(parts[0]):
                return None
            archive_range = ArchiveInputRange(
                path=parts[0],
                start=int(segment.start_offset),
                end=int(segment.end_offset) if segment.end_offset is not None else None,
            )
            return ArchiveInputDescriptor(
                entry_path=parts[0],
                open_mode="file_range",
                format_hint=evidence.format,
                logical_name=self._segment_logical_name(task, evidence, index),
                parts=[ArchiveInputPart(path=parts[0], range=archive_range)],
                segment=ArchiveInputSegment(
                    start=int(segment.start_offset),
                    end=int(segment.end_offset) if segment.end_offset is not None else None,
                    confidence=float(segment.confidence),
                ),
                analysis={
                    "status": evidence.status,
                    "confidence": float(evidence.confidence),
                    "damage_flags": list(segment.damage_flags),
                },
            )
        if evidence.format == "rar":
            return None
        ranges = self._logical_range_to_file_ranges(
            parts,
            int(segment.start_offset),
            int(segment.end_offset) if segment.end_offset is not None else None,
        )
        if not ranges:
            return None
        return ArchiveInputDescriptor(
            entry_path=task.main_path,
            open_mode="concat_ranges",
            format_hint=evidence.format,
            logical_name=self._segment_logical_name(task, evidence, index),
            ranges=[ArchiveInputRange(path=item["path"], start=item["start"], end=item.get("end")) for item in ranges],
            segment=ArchiveInputSegment(
                start=int(segment.start_offset),
                end=int(segment.end_offset) if segment.end_offset is not None else None,
                confidence=float(segment.confidence),
            ),
            analysis={
                "status": evidence.status,
                "confidence": float(evidence.confidence),
                "damage_flags": list(segment.damage_flags),
            },
        )

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

    def _child_task_for_segment(
        self,
        task: ArchiveTask,
        report: ArchiveAnalysisReport,
        evidence: ArchiveFormatEvidence,
        segment: ArchiveSegment,
        *,
        index: int,
    ) -> ArchiveTask:
        bag = self._clone_fact_bag(task.fact_bag)
        child = ArchiveTask(
            fact_bag=bag,
            score=task.score,
            key=f"{task.key}#segment{index}:{evidence.format}",
            main_path=task.main_path,
            all_parts=list(task.all_parts or []),
            logical_name=self._segment_logical_name(task, evidence, index),
            split_info=SplitArchiveInfo(
                is_split=task.split_info.is_split,
                is_sfx_stub=task.split_info.is_sfx_stub,
                parts=list(task.split_info.parts or []),
                preferred_entry=task.split_info.preferred_entry,
                source=task.split_info.source,
                volumes=list(task.split_info.volumes or []),
            ),
            decision=task.decision,
            stop_reason=task.stop_reason,
            matched_rules=list(task.matched_rules or []),
            detected_ext=task.detected_ext,
        )
        self._record_report(child, report)
        child.fact_bag.set("analysis.report_path", report.path)
        child.fact_bag.set("analysis.carrier_path", task.main_path)
        child.fact_bag.set("analysis.logical_archive_index", index)
        child.fact_bag.set("candidate.logical_name", child.logical_name)
        self._apply_selected_segment(child, evidence, segment, index=index)
        self._record_state_analysis(child, report)
        return child

    def _segment_logical_name(self, task: ArchiveTask, evidence: ArchiveFormatEvidence, index: int) -> str:
        base = str(task.logical_name or os.path.splitext(os.path.basename(task.main_path))[0] or "archive")
        if task.fact_bag.get("analysis.logical_archive_index"):
            return base
        if index <= 0:
            return base
        fmt = str(evidence.format or "archive").replace("/", "_")
        return f"{base}_{index:02d}_{fmt}"

    def _clone_fact_bag(self, fact_bag: FactBag) -> FactBag:
        cloned = FactBag()
        for key, value in fact_bag.to_dict().items():
            cloned.set(key, value)
        return cloned
