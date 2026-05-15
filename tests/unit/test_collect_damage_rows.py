import json
from pathlib import Path

from repair_training.build_features import main as build_features_main
from repair_training.core.features import damage_labels_for_row, damage_location_labels_from_target
from repair_training.collect_damage_rows import collect_damage_row
from repair_training.formats.zip.plugin import damage_feature_spec
from sunpack.analysis import ArchiveAnalysisReport
from sunpack.analysis.knowledge import write_analysis_report
from sunpack.analysis.result import ArchiveFormatEvidence
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.repair.policy.training_runtime import build_damage_analysis_request
from sunpack.repair.job import RepairJob
from sunpack.repair.scheduler import RepairScheduler


def test_collect_damage_row_uses_location_only_targets(monkeypatch, tmp_path):
    called_candidates = False

    def fail_candidates(*args, **kwargs):
        nonlocal called_candidates
        called_candidates = True
        raise AssertionError("damage row collector must not generate repair candidates")

    monkeypatch.setattr(RepairScheduler, "generate_repair_candidates", fail_candidates)
    monkeypatch.setattr(
        "repair_training.collect_damage_rows.observe_damage_runtime",
        lambda job, *, workspace, config=None: (
            {
                "format": "zip",
                "archive_state": {"patch_digest": "digest", "patches": []},
                "runtime_context": {
                    "archive_state": {"patch_depth": 0, "patch_digest": "digest"},
                    "analysis_summary": {"format": "zip", "confidence": 1.0},
                    "analysis_native_probe": {"format": "zip"},
                    "extraction_summary": {"has_failure": True, "failure_kind": "bad"},
                    "verification_summary": {"completeness": 0.0},
                },
            },
            {"state_digest": "digest", "patch_depth": 0},
        ),
    )

    damaged = tmp_path / "bad.zip"
    damaged.write_bytes(b"PK\x03\x04bad")
    record = {
        "sample_id": "sample",
        "query_id": "sample:0",
        "format": "zip",
        "damage_profile": "unit",
        "damaged_input": {"kind": "file", "path": str(damaged), "format_hint": "zip"},
        "corruption_plan": [
            {"zone": "zip.eocd.cd_offset", "offset": 1, "size": 4},
            {"zone": "archive.tail", "offset": 10, "size": 2},
        ],
    }

    row = collect_damage_row(record, workspace=tmp_path / "workspace")
    labels = set(row["damage_analysis_target"]["damage_labels"])

    assert labels == {"zone:eocd", "field:eocd.cd_offset", "zone:tail", "field:tail.trailing_bytes"}
    assert all(label.startswith(("zone:", "field:")) for label in labels)
    assert row["damage_analysis_input"]["runtime_context"]["archive_state"]["patch_depth"] == 0
    assert "candidate" not in json.dumps(row["damage_analysis_input"]).lower()
    assert not called_candidates


def test_damage_rows_build_features_location_only(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "repair_training.collect_damage_rows.observe_damage_runtime",
        lambda job, *, workspace, config=None: (
            {
                "format": "zip",
                "archive_state": {"patch_digest": "digest", "patches": []},
                "runtime_context": {
                    "archive_state": {"patch_depth": 0, "patch_digest": "digest"},
                    "analysis_summary": {"format": "zip", "confidence": 1.0},
                    "analysis_native_probe": {"format": "zip"},
                    "extraction_summary": {"has_failure": True, "failure_kind": "bad"},
                    "verification_summary": {"completeness": 0.0},
                },
            },
            {"state_digest": "digest", "patch_depth": 0},
        ),
    )
    run_dir = tmp_path / "run"
    datasets = run_dir / "datasets"
    datasets.mkdir(parents=True)
    damaged = tmp_path / "bad.zip"
    damaged.write_bytes(b"PK\x03\x04bad")
    rows = [
        collect_damage_row(
            {
                "sample_id": f"sample{i}",
                "format": "zip",
                "damaged_input": {"kind": "file", "path": str(damaged), "format_hint": "zip"},
                "corruption_plan": [{"zone": "zip.eocd.cd_offset" if i % 2 == 0 else "archive.tail", "offset": i, "size": 4}],
            },
            workspace=tmp_path / f"workspace{i}",
        )
        for i in range(4)
    ]
    with (datasets / "damage_rows.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    assert build_features_main(["--format", "zip", "--model", "damage_analysis", "--run-dir", str(run_dir)]) == 0
    schema = json.loads((run_dir / "features" / "damage_analysis" / "label_schema.json").read_text(encoding="utf-8"))

    assert schema["labels"]
    assert all(label.startswith(("zone:", "field:")) for label in schema["labels"])


def test_damage_label_normalizer_uses_explicit_labels_only():
    target = {
        "damage_labels": ["zone:central_directory"],
        "labels": [{"zone": {"kind": "record", "path": "zip.central_directory"}}],
    }

    assert damage_labels_for_row({"damage_analysis_target": target}) == ["zone:central_directory"]
    assert damage_location_labels_from_target(target) == ["zone:central_directory"]


def test_zip_structure_facts_enter_archive_knowledge_and_damage_request(tmp_path):
    archive = tmp_path / "bad.zip"
    archive.write_bytes(b"PK\x03\x04bad")
    facts = FactBag()
    facts.set("file.path", str(archive))
    facts.set("archive.knowledge", {"source": {"input": {"kind": "file", "path": str(archive), "format_hint": "zip"}}})
    facts.set("zip.eocd_structure", {"error": "bad_central_directory_signature", "eocd_offset": 17, "plausible": False})
    facts.set("zip.local_header", {"offset": 0, "plausible": True, "filename_len": 4, "error": ""})
    facts.set(
        "zip.directory_consistency",
        {
            "cd_parseable": True,
            "central_local_crc_mismatch_count": 1,
            "descriptor": {"descriptor_flag_mismatch_count": 1},
            "zip64_consistency": {"zip64_locator_present": True},
        },
    )
    facts.set("zip.local_header_plausible", True)
    facts.set("zip.local_header_offset", 0)
    facts.set("zip.local_header_error", "")
    task = ArchiveTask(fact_bag=facts, score=10, main_path=str(archive), detected_ext="zip")
    report = ArchiveAnalysisReport(
        path=str(archive),
        size=archive.stat().st_size,
        evidences=[ArchiveFormatEvidence(format="zip", confidence=1.0, status="damaged", details={})],
        selected=[ArchiveFormatEvidence(format="zip", confidence=1.0, status="damaged", details={})],
    )

    write_analysis_report(task, report)
    knowledge = task.knowledge().to_dict()
    structure = knowledge["format"]["zip"]["structure"]

    assert structure["eocd"]["error"] == "bad_central_directory_signature"
    assert structure["eocd.eocd_offset"] == 17
    assert structure["local_header"]["filename_len"] == 4
    assert structure["local_header.plausible"] is True
    assert structure["directory_consistency"]["central_local_crc_mismatch_count"] == 1
    assert structure["zip64_consistency"]["zip64_locator_present"] is True

    job = RepairJob(
        source_input={"kind": "file", "path": str(archive), "format_hint": "zip"},
        format="zip",
        knowledge=knowledge,
        archive_key="unit",
    )
    request = build_damage_analysis_request(job, None, diagnosis={"format": "zip"})
    probe = request.runtime_context["analysis_native_probe"]

    assert probe["structure"]["eocd"]["error"] == "bad_central_directory_signature"
    assert probe["raw_structure"]["local_header"]["filename_len"] == 4
    assert probe["structure"]["directory_consistency"]["descriptor"]["descriptor_flag_mismatch_count"] == 1
    assert probe["raw_structure"]["zip64_consistency"]["zip64_locator_present"] is True


def test_zip_damage_feature_spec_excludes_compressed_route_flags():
    spec = damage_feature_spec()

    assert "runtime_context.analysis_native_probe.structure." in spec.include_prefixes
    assert "runtime_context.analysis_native_probe.raw_structure." in spec.include_prefixes
    assert not any(prefix == "runtime_context.job_summary." for prefix in spec.include_prefixes)
    assert not any("route_evidence" in prefix or "damage_flags" in prefix for prefix in spec.include_prefixes)
