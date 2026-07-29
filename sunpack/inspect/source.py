from __future__ import annotations

from sunpack.analysis.source import (
    AnalysisSource,
    PatchedAnalysisSource,
    analysis_source_for_descriptor as _analysis_source_for_descriptor,
)
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.tasks import ArchiveTask


def analysis_source_for_task(task: ArchiveTask) -> AnalysisSource:
    """Translate task/repair state into a neutral Analysis source."""

    state = task.archive_state()
    if state.patches:
        return PatchedAnalysisSource(state, report_path=state.source.entry_path or task.main_path)
    return analysis_source_for_descriptor(
        state.to_archive_input_descriptor(),
        report_path=task.main_path,
    )


def analysis_source_for_descriptor(
    descriptor: ArchiveInputDescriptor,
    *,
    report_path: str = "",
) -> AnalysisSource:
    return _analysis_source_for_descriptor(descriptor, report_path=report_path)


def detection_prepass_for_task(task: ArchiveTask) -> dict | None:
    value = task.fact_bag.get("analysis.signature_prepass")
    if not isinstance(value, dict) or not value.get("full_scan_complete"):
        return None
    return dict(value)
