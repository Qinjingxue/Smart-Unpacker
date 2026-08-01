from __future__ import annotations

from dataclasses import asdict, replace
from typing import Any, Callable

from sunpack.support.archive_format_projection import write_inspection_error, write_inspection_refresh
from sunpack.analysis.result import ArchiveAnalysisReport, ArchiveFormatEvidence
from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.tasks import ArchiveTask


class RepairStateProjector:
    """Project neutral Analysis reports into repair-facing task state."""

    def project(
        self,
        task: ArchiveTask,
        report: ArchiveAnalysisReport,
        *,
        phase_timer: Callable[..., Any] | None = None,
        phase_prefix: str = "inspection",
    ) -> None:
        selected = _best_selected(report)
        task.fact_bag.set("inspection.status", "extractable" if report.has_extractable else "not_extractable")
        task.fact_bag.set("inspection.report_path", report.path)
        task.fact_bag.set("inspection.read_bytes", report.read_bytes)
        task.fact_bag.set("inspection.cache_hits", report.cache_hits)
        task.fact_bag.set("inspection.prepass", report.prepass)
        task.fact_bag.set("inspection.fuzzy", report.fuzzy)
        task.fact_bag.set("inspection.evidences", [
            {
                "format": evidence.format,
                "confidence": evidence.confidence,
                "status": evidence.status,
                "warnings": list(evidence.warnings),
                "details": dict(evidence.details),
                "segments": [asdict(segment) for segment in evidence.segments],
            }
            for evidence in report.evidences
        ])
        if selected is not None:
            task.fact_bag.set("inspection.selected_format", selected.format)
            task.fact_bag.set("inspection.confidence", float(selected.confidence or 0.0))

        write_inspection_refresh(task, report)
        self._record_state(task, report, phase_timer=phase_timer, phase_prefix=phase_prefix)

    def project_error(self, task: ArchiveTask, error: Exception | str) -> None:
        message = str(error)
        task.fact_bag.set("inspection.status", "error")
        task.fact_bag.set("inspection.error", message)
        write_inspection_error(task, message)

    def _record_state(
        self,
        task: ArchiveTask,
        report: ArchiveAnalysisReport,
        *,
        phase_timer: Callable[..., Any] | None = None,
        phase_prefix: str = "inspection",
    ) -> None:
        state = task.archive_state()
        selected = _best_selected(report)
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
        selected_format = str(getattr(selected, "format", "") or "")
        source = replace(state.source, format_hint=selected_format) if selected_format else state.source
        new_state = ArchiveState(
            source=source,
            patches=list(state.patches),
            patch_digest=state.effective_patch_digest(),
            logical_name=state.logical_name,
            format_hint=selected_format or state.format_hint,
            analysis=analysis,
            verification=dict(state.verification),
            knowledge=task.knowledge().to_dict(),
        )
        if dict(state.analysis) != analysis or state.format_hint != new_state.format_hint:
            task.set_archive_state(
                new_state,
                phase_timer=phase_timer,
                phase_prefix=f"{phase_prefix}_set_archive_state",
            )


def _best_selected(report: ArchiveAnalysisReport) -> ArchiveFormatEvidence | None:
    if not report.selected:
        return None
    return max(report.selected, key=lambda item: float(item.confidence or 0.0))
