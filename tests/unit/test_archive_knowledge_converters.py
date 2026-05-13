from pathlib import Path

from sunpack.analysis.knowledge import write_analysis_report
from sunpack.analysis.result import ArchiveAnalysisReport, ArchiveFormatEvidence
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.detection.knowledge import write_detection_task
from sunpack.extraction.knowledge import write_extraction_result
from sunpack.extraction.result import ExtractionResult
from sunpack.filesystem.knowledge import write_filesystem_task
from sunpack.relations.knowledge import write_relation_task
from sunpack.repair.knowledge import write_repair_result
from sunpack.repair.result import RepairResult
from sunpack.verification.knowledge import write_verification_result
from sunpack.verification.result import ArchiveCoverageSummary, VerificationResult


def test_layer_converters_write_archive_knowledge_namespaces(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK\x05\x06" + b"\0" * 18)
    bag = FactBag()
    bag.set("candidate.entry_path", str(archive))
    bag.set("candidate.member_paths", [str(archive)])
    bag.set("candidate.logical_name", "sample")
    bag.set("file.detected_ext", "zip")
    task = ArchiveTask.from_fact_bag(bag, score=10)

    write_filesystem_task(task)
    write_relation_task(task)
    write_detection_task(task)
    write_analysis_report(task, _analysis_report(str(archive)))
    write_extraction_result(task, ExtractionResult(success=False, archive=str(archive), out_dir=str(tmp_path / "out"), all_parts=[str(archive)], error="bad", diagnostics={"result": {"status": "failed", "failure_stage": "extract", "failure_kind": "data_error"}}, password_used="secret"))
    write_verification_result(task, VerificationResult(completeness=0.5, assessment_status="partial", decision_hint="repair", failed_files=1, archive_coverage=ArchiveCoverageSummary(completeness=0.5, expected_files=2, matched_files=1)))
    write_repair_result(task, RepairResult(status="repaired", module_name="zip_fix_cd_offset", actions=["fix_cd_offset"], repaired_input={"kind": "file", "path": str(archive)}, diagnosis={"patch_facts": ["fixed_field=cd_offset"]}))

    payload = task.knowledge().to_dict()

    assert payload["filesystem"]["path"] == str(archive)
    assert payload["relations"]["parts"] == [str(archive)]
    assert payload["detection"]["detected_ext"] == "zip"
    assert payload["analysis"]["selected_format"] == "zip"
    assert payload["format"]["zip"]["structure"]["has_data_descriptor"] is True
    assert payload["extraction"]["failure"]["failure_kind"] == "data_error"
    assert payload["archive"]["password"] == "secret"
    assert payload["archive"]["password_present"] is True
    assert payload["verification"]["summary"]["decision_hint"] == "repair"
    assert payload["repair"]["last_result"]["module_name"] == "zip_fix_cd_offset"
    assert "fixed_field=cd_offset" in payload["repair"]["patch_facts"]["flags"]


def _analysis_report(path: str) -> ArchiveAnalysisReport:
    evidence = ArchiveFormatEvidence(
        format="zip",
        confidence=0.9,
        status="extractable",
        details={
            "zip_structure_features": {"has_data_descriptor": True},
            "zip_container_tags": ["data_descriptor"],
        },
    )
    return ArchiveAnalysisReport(
        path=path,
        size=22,
        read_bytes=22,
        evidences=[evidence],
        selected=[evidence],
        prepass={"status": "ok", "selected_format": "zip"},
        fuzzy={},
    )
