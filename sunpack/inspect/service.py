from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable

from sunpack.analysis import ArchiveAnalyzer
from sunpack.analysis.request import AnalysisRequest
from sunpack.analysis.result import ArchiveAnalysisReport
from sunpack.contracts.tasks import ArchiveTask
from sunpack.inspect.cache import InspectionReportCache
from sunpack.inspect.request import InspectionRequest
from sunpack.inspect.result import InspectionFeedback
from sunpack.inspect.projector import InspectionProjector
from sunpack.inspect.source import analysis_source_for_task, detection_prepass_for_task


class ArchiveInspector:
    """Repair-facing inspection service backed by neutral Analysis capabilities."""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        *,
        analyzer: ArchiveAnalyzer | None = None,
        executor_pool=None,
        task_analyzer: Callable[[ArchiveTask], ArchiveAnalysisReport] | None = None,
        projector: InspectionProjector | None = None,
    ):
        root = config or {}
        inspect_config = root.get("inspect") if isinstance(root.get("inspect"), dict) else {}
        cache_size = inspect_config.get("cache_size", 512)
        self.analyzer = analyzer or ArchiveAnalyzer(root, executor_pool=executor_pool)
        self.task_analyzer = task_analyzer
        self.projector = projector or InspectionProjector()
        self.cache = InspectionReportCache(int(cache_size or 0))

    def inspect_task(
        self,
        task: ArchiveTask,
        request: InspectionRequest | None = None,
        *,
        use_cache: bool = True,
    ) -> InspectionFeedback:
        return InspectionFeedback.from_report(
            self.analyze_task(task, request=request, use_cache=use_cache)
        )

    def analyze_task(
        self,
        task: ArchiveTask,
        request: InspectionRequest | None = None,
        *,
        use_cache: bool = True,
    ) -> ArchiveAnalysisReport:
        task.ensure_archive_state()
        effective = request or InspectionRequest(
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
        request: InspectionRequest | None = None,
        *,
        phase_timer=None,
        phase_prefix: str = "inspection_refresh",
    ) -> InspectionFeedback:
        try:
            feedback = self.inspect_task(task, request=request, use_cache=True)
        except Exception as exc:
            self.projector.project_error(task, exc)
            return InspectionFeedback(status="error")
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
        request: InspectionRequest | None = None,
    ) -> None:
        effective = request or InspectionRequest(
            initial_prepass=detection_prepass_for_task(task)
        )
        self.cache.put(self.cache.key(task, effective), report)

    def clear_cache(self) -> None:
        self.cache.clear()
