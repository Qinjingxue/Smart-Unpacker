from pathlib import Path

from sunpack.analysis.knowledge import write_analysis_report, write_zip_runtime_evidence_facts
from sunpack.analysis.result import ArchiveAnalysisReport, ArchiveFormatEvidence
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.detection.knowledge import write_detection_task
from sunpack.extraction.knowledge import write_extraction_result
from sunpack.contracts.extraction import ExtractionResult
from sunpack.filesystem.knowledge import write_filesystem_task
from sunpack.relations.knowledge import write_relation_task
from sunpack.repair.knowledge import write_repair_result
from sunpack.repair.result import RepairResult
from sunpack.verification.knowledge import write_verification_result
from sunpack.contracts.verification import ArchiveCoverageSummary, FileVerificationObservation, VerificationIssue, VerificationResult


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
    assert "has_data_descriptor" not in payload["format"]["zip"].get("structure", {})
    assert payload["extraction"]["failure"]["failure_kind"] == "data_error"
    assert payload["archive"]["password"] == "secret"
    assert payload["archive"]["password_present"] is True
    assert payload["verification"]["summary"]["decision_hint"] == "repair"
    assert payload["repair"]["last_result"]["module_name"] == "zip_fix_cd_offset"
    assert "fixed_field=cd_offset" in payload["repair"]["patch_facts"]["flags"]


def test_extraction_verification_and_zip_runtime_evidence_facts(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK\x05\x06" + b"\0" * 18)
    bag = FactBag()
    bag.set("candidate.entry_path", str(archive))
    bag.set("candidate.member_paths", [str(archive), str(tmp_path / "sample.z01")])
    bag.set("file.detected_ext", "zip")
    task = ArchiveTask.from_fact_bag(bag, score=10)
    write_analysis_report(task, _analysis_report(str(archive)))
    knowledge = task.knowledge()
    knowledge.set("format.zip.structure.eocd", {"error": "bad_central_directory_signature", "physical_central_directory_offset": 10, "declared_central_directory_size": 40, "eocd_offset": 60}, source_layer="test")
    knowledge.set("format.zip.structure.directory_consistency", {"file_size": 22, "cd_entries_checked": 2, "central_local_crc_mismatch_count": 1, "central_local_compressed_size_mismatch_count": 1}, source_layer="test")
    task.set_knowledge(knowledge)
    write_extraction_result(
        task,
        ExtractionResult(
            success=False,
            archive=str(archive),
            out_dir=str(tmp_path / "out"),
            all_parts=[str(archive), str(tmp_path / "sample.z01")],
            error="checksum error",
            diagnostics={"result": {"status": "failed", "failure_stage": "item_extract", "failure_kind": "checksum_error", "native_status": "damaged"}},
            partial_outputs=True,
            progress_manifest_payload={
                "failure_stage": "item_extract",
                "failure_kind": "checksum_error",
                "files": [
                    {"archive_path": "a.txt", "status": "failed", "bytes_written": 0, "crc_ok": False, "failure_kind": "checksum_error"},
                    {"archive_path": "b.txt", "status": "complete", "bytes_written": 5, "crc_ok": True},
                ],
            },
        ),
    )
    issue = VerificationIssue(method="archive_test_crc", code="fail.archive_crc_mismatch", message="crc mismatch", path="a.txt")
    write_verification_result(
        task,
        VerificationResult(
            completeness=0.5,
            assessment_status="partial",
            decision_hint="repair",
            failed_files=1,
            archive_coverage=ArchiveCoverageSummary(completeness=0.5, expected_files=2, matched_files=1, failed_files=1),
            issues=[issue],
            file_observations=[
                FileVerificationObservation(path="a.txt", archive_path="a.txt", state="failed", bytes_written=1, expected_size=5, crc_expected=1, crc_actual=2, issues=[issue]),
            ],
        ),
    )
    write_zip_runtime_evidence_facts(task)

    payload = task.knowledge().to_dict()
    outcomes = payload["extraction"]["entry_outcomes"]
    breakdown = payload["verification"]["coverage_breakdown"]
    structure = payload["format"]["zip"]["structure"]

    assert outcomes["entry_failed_count"] == 1
    assert outcomes["crc_error_count"] >= 1
    assert breakdown["crc_mismatch_count"] >= 1
    assert breakdown["size_mismatch_count"] >= 1
    runtime = structure["runtime"]
    assert "directory_consistency" not in structure
    assert runtime["has_split_sidecars"] is True
    assert runtime["split_part_count"] == 2
    assert runtime["payload_content_failure_observed"] is True
    assert runtime["payload_direct_crc_or_hash_failure_observed"] is True
    assert runtime["payload_size_or_content_mismatch_observed"] is True
    assert runtime["no_payload_hash_crc_failure"] is False
    assert runtime["extraction_entry_outcomes"]["entry_failed_count"] == 1
    assert runtime["verification_coverage_breakdown"]["crc_mismatch_count"] >= 1


def test_zip_runtime_evidence_separates_structural_checksum_and_sfx_offset(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"sfx-prefix" + b"PK\x05\x06" + b"\0" * 18)
    bag = FactBag()
    bag.set("candidate.entry_path", str(archive))
    bag.set("file.detected_ext", "zip")
    task = ArchiveTask.from_fact_bag(bag, score=10)
    write_analysis_report(task, _analysis_report(str(archive)))
    knowledge = task.knowledge()
    knowledge.set(
        "format.zip.structure.eocd",
        {
            "error": "comment_length_mismatch",
            "archive_offset": 10,
            "declared_central_directory_offset": 20,
            "physical_central_directory_offset": 30,
            "declared_central_directory_size": 12,
            "physical_central_directory_size": 12,
            "central_directory_offset_delta": -10,
            "central_directory_size_delta": 0,
        },
        source_layer="test",
    )
    knowledge.set(
        "format.zip.structure.directory_consistency",
        {
            "file_size": 44,
            "cd_entries_checked": 1,
            "local_header_missing_count": 1,
            "central_local_offset_suspicious_count": 1,
            "descriptor": {
                "spurious_descriptor_candidate_count": 2,
                "descriptor_flag_mismatch_count": 1,
            },
        },
        source_layer="test",
    )
    knowledge.set("format.zip.structure.local_header", {"offset": 10, "plausible": True}, source_layer="test")
    task.set_knowledge(knowledge)
    write_extraction_result(
        task,
        ExtractionResult(
            success=False,
            archive=str(archive),
            out_dir=str(tmp_path / "out"),
            all_parts=[str(archive)],
            error="checksum error",
            diagnostics={"result": {"status": "failed", "failure_stage": "item_extract", "failure_kind": "checksum_error"}},
            progress_manifest_payload={
                "files": [{"archive_path": "a.txt", "status": "failed", "failure_kind": "checksum_error", "crc_ok": False}]
            },
        ),
    )
    write_verification_result(
        task,
        VerificationResult(
            completeness=1.0,
            assessment_status="complete",
            decision_hint="accept",
            archive_coverage=ArchiveCoverageSummary(completeness=1.0, expected_files=1, matched_files=1),
            file_observations=[FileVerificationObservation(path="a.txt", archive_path="a.txt", state="complete")],
        ),
    )
    write_zip_runtime_evidence_facts(task)

    structure = task.knowledge().to_dict()["format"]["zip"]["structure"]
    evidence = structure["runtime"]

    assert "directory_consistency" not in structure
    assert evidence["payload_verification_observed"] is True
    assert evidence["payload_verified_intact"] is True
    assert evidence["payload_unverified_but_no_failure"] is False
    assert evidence["payload_content_failure_observed"] is False
    assert evidence["payload_direct_crc_or_hash_failure_observed"] is False
    assert evidence["no_payload_hash_crc_failure"] is True


def test_zip_runtime_evidence_attributes_partial_payload_to_missing_range(tmp_path):
    archive = tmp_path / "sample.zip"
    part = tmp_path / "sample.z01"
    archive.write_bytes(b"PK\x05\x06" + b"\0" * 18)
    part.write_bytes(b"sidecar")
    bag = FactBag()
    bag.set("candidate.entry_path", str(archive))
    bag.set("file.detected_ext", "zip")
    task = ArchiveTask.from_fact_bag(bag, score=10)
    write_analysis_report(task, _analysis_report(str(archive)))
    knowledge = task.knowledge()
    knowledge.set(
        "source.input",
        {
            "kind": "file",
            "path": str(archive),
            "format_hint": "zip",
            "parts": [{"path": str(archive), "role": "main"}, {"path": str(part), "role": "volume"}],
        },
        source_layer="test",
    )
    knowledge.set(
        "format.zip.structure.eocd",
        {
            "declared_central_directory_offset": 1000,
            "physical_central_directory_offset": 800,
            "declared_central_directory_size": 30,
            "physical_central_directory_size": 30,
            "central_directory_offset_delta": 200,
            "central_directory_size_delta": 0,
        },
        source_layer="test",
    )
    knowledge.set(
        "format.zip.structure.directory_consistency",
        {
            "file_size": 830,
            "cd_entries_checked": 2,
            "descriptor": {
                "local_header_offset_points_inside_payload_count": 1,
                "local_header_offset_points_to_descriptor_or_payload_count": 1,
            },
        },
        source_layer="test",
    )
    task.set_knowledge(knowledge)
    write_extraction_result(
        task,
        ExtractionResult(
            success=False,
            archive=str(archive),
            out_dir=str(tmp_path / "out"),
            all_parts=[str(archive)],
            error="data error",
            diagnostics={"result": {"status": "failed", "failure_stage": "item_extract", "failure_kind": "data_error"}},
            partial_outputs=True,
            progress_manifest_payload={
                "files": [{"archive_path": "a.txt", "status": "partial", "failure_kind": "data_error"}]
            },
        ),
    )
    write_verification_result(
        task,
        VerificationResult(
            completeness=1.0,
            assessment_status="partial",
            decision_hint="repair",
            archive_coverage=ArchiveCoverageSummary(completeness=1.0),
        ),
    )
    write_zip_runtime_evidence_facts(task)

    structure = task.knowledge().to_dict()["format"]["zip"]["structure"]
    evidence = structure["runtime"]

    assert "evidence" not in structure
    assert evidence["has_split_sidecars"] is True
    assert evidence["split_part_count"] == 2
    assert evidence["payload_content_failure_observed"] is False
    assert evidence["extraction_item_failure_observed"] is True
    assert evidence["payload_failure_explained_by_missing_range"] is True
    assert evidence["payload_direct_crc_or_hash_failure_observed"] is False
    assert evidence["no_payload_hash_crc_failure"] is True
    assert evidence["payload_unverified_but_no_failure"] is True


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
