from __future__ import annotations

from sunpack.analysis.result import ArchiveAnalysisReport, ArchiveFormatEvidence, ArchiveSegment
from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.inspect import ArchiveInspector


class _Analyzer:
    def __init__(self, report):
        self.report = report
        self.calls = []

    def analyze(self, source, request):
        self.calls.append((source, request))
        return self.report


def test_inspector_translates_report_to_repair_feedback_and_caches(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK")
    report = ArchiveAnalysisReport(
        path=str(archive),
        size=2,
        evidences=[ArchiveFormatEvidence(
            format="zip",
            confidence=0.9,
            status="damaged",
            segments=[ArchiveSegment(0, 2, 0.9, damage_flags=["boundary_unreliable"])],
        )],
        selected=[],
    )
    analyzer = _Analyzer(report)
    inspector = ArchiveInspector(analyzer=analyzer)
    task = ArchiveTask(
        fact_bag=FactBag(),
        score=10,
        main_path=str(archive),
        all_parts=[str(archive)],
        detected_ext="zip",
    )

    first = inspector.inspect_task(task)
    second = inspector.inspect_task(task)

    assert first.format == "zip"
    assert first.status == "damaged"
    assert first.damage_flags == ("boundary_unreliable",)
    assert first.start_trusted is True
    assert first.end_trusted is False
    assert second.report.cache_hits == 1
    assert len(analyzer.calls) == 1


def test_inspection_cache_distinguishes_patch_state(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK")
    report = ArchiveAnalysisReport(path=str(archive), size=2, evidences=[], selected=[])
    analyzer = _Analyzer(report)
    inspector = ArchiveInspector(analyzer=analyzer)
    task = ArchiveTask(
        fact_bag=FactBag(),
        score=10,
        main_path=str(archive),
        all_parts=[str(archive)],
        detected_ext="zip",
    )

    original = task.archive_state()
    task.set_archive_state(ArchiveState(
        source=original.source,
        patches=[PatchPlan(operations=[PatchOperation(op="insert", offset=0, data_b64="QQ==")])],
        logical_name=original.logical_name,
        format_hint=original.format_hint,
        knowledge=original.knowledge,
    ))
    inspector.analyze_task(task)
    first_digest = task.archive_state().effective_patch_digest()
    task.set_archive_state(ArchiveState(
        source=original.source,
        patches=[PatchPlan(operations=[PatchOperation(op="insert", offset=0, data_b64="Qg==")])],
        logical_name=original.logical_name,
        format_hint=original.format_hint,
        knowledge=original.knowledge,
    ))
    inspector.analyze_task(task)

    assert first_digest != task.archive_state().effective_patch_digest()
    assert len(analyzer.calls) == 2


def test_refresh_projects_feedback_into_task_and_archive_state(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK")
    evidence = ArchiveFormatEvidence(
        format="zip",
        confidence=0.95,
        status="extractable",
        segments=[ArchiveSegment(0, 2, 0.95)],
    )
    report = ArchiveAnalysisReport(
        path=str(archive),
        size=2,
        evidences=[evidence],
        selected=[evidence],
        prepass={"formats": ["zip"]},
    )
    task = ArchiveTask(
        fact_bag=FactBag(),
        score=10,
        main_path=str(archive),
        all_parts=[str(archive)],
        detected_ext="zip",
    )

    feedback = ArchiveInspector(analyzer=_Analyzer(report)).refresh_task(task)

    assert feedback.format == "zip"
    assert task.fact_bag.get("inspection.selected_format") == "zip"
    assert task.knowledge().get("inspection.summary.format") == "zip"
    assert task.archive_state().analysis["status"] == "extractable"
    assert task.archive_state().format_hint == "zip"
