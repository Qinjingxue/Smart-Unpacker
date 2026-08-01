from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable

from sunpack.analysis import ArchiveAnalyzer
from sunpack.analysis.request import AnalysisRequest
from sunpack.analysis.result import ArchiveAnalysisReport
from sunpack.contracts.tasks import ArchiveTask
from sunpack.repair_inspection.cache import RepairInspectionCache
from sunpack.repair_inspection.request import RepairInspectionRequest
from sunpack.repair_inspection.result import RepairInspectionFeedback
from sunpack.repair_inspection.projector import RepairStateProjector
from sunpack.repair_inspection.source import analysis_source_for_task, detection_prepass_for_task


class RepairInspectionService:
    """Repair-loop inspection service backed by neutral Analysis capabilities."""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        *,
        analyzer: ArchiveAnalyzer | None = None,
        executor_pool=None,
        task_analyzer: Callable[[ArchiveTask], ArchiveAnalysisReport] | None = None,
        projector: RepairStateProjector | None = None,
    ):
        root = config or {}
        repair_inspection_config = root.get("repair_inspection")
        if not isinstance(repair_inspection_config, dict):
            repair_inspection_config = {}
        cache_size = repair_inspection_config.get("cache_size", 512)
        self.analyzer = analyzer or ArchiveAnalyzer(root, executor_pool=executor_pool)
        self.task_analyzer = task_analyzer
        self.projector = projector or RepairStateProjector()
        self.cache = RepairInspectionCache(int(cache_size or 0))

    def feedback_for_task(
        self,
        task: ArchiveTask,
        request: RepairInspectionRequest | None = None,
        *,
        use_cache: bool = True,
    ) -> RepairInspectionFeedback:
        return RepairInspectionFeedback.from_report(
            self.analyze_task(task, request=request, use_cache=use_cache)
        )

    def analyze_task(
        self,
        task: ArchiveTask,
        request: RepairInspectionRequest | None = None,
        *,
        use_cache: bool = True,
    ) -> ArchiveAnalysisReport:
        task.ensure_archive_state()
        effective = request or RepairInspectionRequest(
            initial_prepass=detection_prepass_for_task(task)
        )
        key = self.cache.key(task, effective)
        cached = self.cache.get(key) if use_cache else None
        if cached is not None:
            return replace(cached, cache_hits=cached.cache_hits + 1)
        if self.task_analyzer is not None and request is None:
            report = self.task_analyzer(task)
        else:
            report = self.analyzer.analyze(
                analysis_source_for_task(task),
                AnalysisRequest(
                    capabilities=effective.capabilities,
                    initial_prepass=effective.initial_prepass,
                ),
            )
        if use_cache:
            self.cache.put(key, report)
        return report

    def refresh_task(
        self,
        task: ArchiveTask,
        request: RepairInspectionRequest | None = None,
        *,
        phase_timer=None,
        phase_prefix: str = "inspection_refresh",
    ) -> RepairInspectionFeedback:
        try:
            feedback = self.feedback_for_task(task, request=request, use_cache=True)
        except Exception as exc:
            self.projector.project_error(task, exc)
            return RepairInspectionFeedback(status="error")
        if feedback.report is not None:
            self.projector.project(
                task,
                feedback.report,
                phase_timer=phase_timer,
                phase_prefix=phase_prefix,
            )
        return feedback

    def remember_report(
        self,
        task: ArchiveTask,
        report: ArchiveAnalysisReport,
        request: RepairInspectionRequest | None = None,
    ) -> None:
        effective = request or RepairInspectionRequest(
            initial_prepass=detection_prepass_for_task(task)
        )
        self.cache.put(self.cache.key(task, effective), report)

    def clear_cache(self) -> None:
        self.cache.clear()
