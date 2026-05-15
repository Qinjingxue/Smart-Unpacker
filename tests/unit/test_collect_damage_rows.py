import base64
import json
import zipfile
from pathlib import Path

from repair_training.build_features import main as build_features_main
from repair_training.core.features import damage_labels_for_row, damage_location_labels_from_target
from repair_training.collect_damage_rows import collect_damage_row
from repair_training.formats.zip.corruption_impl import build_corpus_corruption_case
from repair_training.formats.zip.plugin import damage_feature_spec
from repair_training.taxonomy import normalize_damage_record
from sunpack.analysis import ArchiveAnalysisReport
from sunpack.analysis.knowledge import write_analysis_report
from sunpack.analysis.result import ArchiveFormatEvidence
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.detection.pipeline.processors.modules.format_structure.zip_directory_consistency import inspect_zip_directory_consistency
from sunpack.detection.pipeline.processors.modules.format_structure.zip_eocd import inspect_zip_eocd_structure
from sunpack.repair.policy.training_runtime import build_damage_analysis_request
from sunpack.repair.job import RepairJob
from sunpack.repair.scheduler import RepairScheduler


def _write_source_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("alpha.txt", b"alpha" * 80)
        archive.writestr("beta.txt", b"beta" * 80)
        archive.writestr("gamma.txt", b"gamma" * 80)


def _profile_case(tmp_path: Path, profile: str):
    source = tmp_path / f"{profile}.zip"
    _write_source_zip(source)
    return build_corpus_corruption_case(
        tmp_path / f"generated-{profile}",
        source_path=source,
        fmt="zip",
        seed=123,
        variant_index=0,
        damage_profile=profile,
    )


def _profile_plan(tmp_path: Path, profile: str) -> list[dict]:
    source = tmp_path / f"{profile}.zip"
    case = _profile_case(tmp_path, profile)
    record = case.corpus_manifest_record(
        source_archive_id="unit-source",
        source_path=str(source),
        damage_profile=profile,
        variant_index=0,
    )
    return list(record.get("corruption_plan", []))


def _profile_zones(tmp_path: Path, profile: str) -> set[str]:
    return {str(item.get("zone") or "") for item in _profile_plan(tmp_path, profile)}


def test_zip_v3_distribution_keeps_total_and_sfx_mix():
    path = Path("repair_training") / "formats" / "zip" / "distributions" / "damage_distribution_zip_root_transition_v3.json"
    distribution = json.loads(path.read_text(encoding="utf-8"))

    total = sum(int(value) for value in distribution["profiles"].values())
    total += sum(int(value["count"]) for value in distribution["compound_profiles"].values())
    total += sum(int(value["count"]) for value in distribution["physical_profiles"].values())

    assert total == 2800
    assert distribution["profiles"]["zip_sfx_cd_damage"] == 220
    assert distribution["compound_profiles"]["compound_sfx_cd_offset_only"]["count"] == 40
    assert distribution["compound_profiles"]["compound_sfx_cd_offset_split_only"]["count"] == 40
    assert distribution["compound_profiles"]["compound_sfx_cd_offset_with_payload_no_local_header"]["count"] == 60


def test_zip_sfx_compound_profiles_do_not_auto_add_local_header(tmp_path):
    zones = _profile_zones(tmp_path, "compound_sfx_cd_offset_only")

    assert "zip.sfx.prefix" in zones
    assert any(zone.startswith("zip.central_directory") for zone in zones)
    assert not any(zone.startswith("zip.local_header") for zone in zones)
    assert not any("payload" in zone for zone in zones)

    split_zones = _profile_zones(tmp_path, "compound_sfx_cd_offset_split_only")
    assert "zip.missing_volume" in split_zones
    assert not any(zone.startswith("zip.local_header") for zone in split_zones)
    assert not any("payload" in zone for zone in split_zones)


def test_zip_sfx_payload_no_local_header_profiles_are_explicit(tmp_path):
    payload_zones = _profile_zones(tmp_path, "compound_sfx_cd_offset_with_payload_no_local_header")
    legacy_payload_zones = _profile_zones(tmp_path, "compound_sfx_cd_offset_payload_partial")

    assert "zip.sfx.prefix" in payload_zones
    assert any("payload" in zone for zone in payload_zones)
    assert not any(zone.startswith("zip.local_header") for zone in payload_zones)
    assert any("payload" in zone for zone in legacy_payload_zones)
    assert not any(zone.startswith("zip.local_header") for zone in legacy_payload_zones)


def test_zip_non_sfx_compound_still_auto_adds_local_header(tmp_path):
    zones = _profile_zones(tmp_path, "compound_boundary_drop_cd_payload_bad")

    assert any(zone.startswith("zip.local_header") for zone in zones)


def test_zip_descriptor_conflict_default_does_not_insert_fake_descriptor(tmp_path):
    for profile in ("zip_data_descriptor_conflict", "zip_data_descriptor_cd_conflict", "zip_data_descriptor_payload_bad"):
        plan = _profile_plan(tmp_path, profile)
        descriptor_items = [item for item in plan if str(item.get("zone") or "") == "zip.data_descriptor"]

        assert descriptor_items == []
        assert not any((item.get("operation") or {}).get("op") == "insert" for item in plan if "descriptor" in str(item.get("name") or ""))


def test_zip_descriptor_fake_span_profile_keeps_explicit_descriptor_and_cd_labels(tmp_path):
    plan = _profile_plan(tmp_path, "compound_descriptor_fake_span_flags_cd_offset")
    record = {"format": "zip", "corruption_plan": plan}
    labels = set(damage_location_labels_from_target(normalize_damage_record(record).to_dict()))

    assert any(item.get("zone") == "zip.data_descriptor" and (item.get("operation") or {}).get("op") == "insert" for item in plan)
    assert "field:data_descriptor.record" in labels
    assert "field:central_directory.local_header_offset" in labels
    assert "field:central_directory.compressed_size" in labels


def test_zip_cd_offset_near_valid_does_not_emit_noop_compressed_size(tmp_path):
    plan = _profile_plan(tmp_path, "compound_descriptor_fake_span_flags_cd_offset")
    compressed_size_items = [
        item
        for item in plan
        if item.get("zone") == "zip.central_directory.compressed_size"
    ]

    assert compressed_size_items
    case = _profile_case(tmp_path, "compound_descriptor_fake_span_flags_cd_offset")
    clean = case.clean_data
    for item in compressed_size_items:
        operation = item.get("operation") or {}
        offset = int(operation.get("offset") or 0)
        size = int(operation.get("size") or 0)
        data_b64 = str(operation.get("data_b64") or "")
        assert data_b64

        replacement = base64.b64decode(data_b64)
        assert clean[offset : offset + size] != replacement


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
    assert "runtime_context.extraction_summary." not in spec.include_prefixes
    assert "runtime_context.verification_summary." not in spec.include_prefixes
    assert "runtime_context.extraction_summary.entry_outcomes." in spec.include_prefixes
    assert "runtime_context.verification_summary.coverage_breakdown." in spec.include_prefixes
    assert "runtime_context.analysis_native_probe.structure.eocd.entry_count_delta" in spec.ignore_paths
    assert "runtime_context.analysis_native_probe.raw_structure.eocd.entry_count_delta" in spec.ignore_paths


def test_zip_eocd_probe_exposes_tolerant_candidate_fields(tmp_path):
    archive = tmp_path / "comment_mismatch.zip"
    # Valid EOCD signature with a declared comment longer than physically present.
    record = (
        b"PK\x05\x06"
        + b"\0" * 6
        + (1).to_bytes(2, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (10).to_bytes(2, "little")
        + b"abc"
    )
    archive.write_bytes(record)

    payload = inspect_zip_eocd_structure(str(archive))

    assert payload["eocd_candidate_found"] is True
    assert payload["eocd_candidate_offset"] == 0
    assert payload["eocd_candidate_declared_entry_count_present"] is True
    assert "eocd_candidate_comment_available_delta" in payload


def test_zip_directory_consistency_exposes_sfx_prefix_and_dual_offset_fields(tmp_path):
    clean = tmp_path / "clean.zip"
    with zipfile.ZipFile(clean, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.txt", "alpha")
        archive.writestr("b.txt", "beta")
    sfx = tmp_path / "sfx.zip"
    prefix = b"MZ-SUNPACK-SFX-STUB"
    sfx.write_bytes(prefix + clean.read_bytes())

    payload = inspect_zip_directory_consistency(str(sfx), max_entries=8)
    prefix_payload = payload["prefix"]

    assert prefix_payload["first_local_header_found"] is True
    assert prefix_payload["first_local_header_offset"] == len(prefix)
    assert prefix_payload["prefix_bytes_before_first_local"] == len(prefix)
    assert prefix_payload["prefix_has_executable_signature"] is True
    assert prefix_payload["local_offset_only_valid_with_prefix_count"] >= 1
    assert prefix_payload["local_offset_prefix_adjustment_success_ratio"] > 0


def test_zip_directory_consistency_exposes_descriptor_cd_offset_attribution(tmp_path):
    source = tmp_path / "descriptor_source.zip"
    _write_source_zip(source)
    case = build_corpus_corruption_case(
        tmp_path / "descriptor_case",
        source_path=source,
        fmt="zip",
        seed=77,
        variant_index=0,
        damage_profile="compound_descriptor_fake_span_flags_cd_offset",
    )

    payload = inspect_zip_directory_consistency(str(case.source_input["path"]), max_entries=8)
    descriptor = payload["descriptor"]

    for field in (
        "wrong_local_header_target_count",
        "local_header_offset_points_to_other_entry_count",
        "local_header_offset_points_inside_payload_count",
        "local_header_offset_points_inside_descriptor_count",
        "local_header_offset_points_outside_archive_count",
        "local_header_offset_bad_signature_count",
        "local_header_offset_target_conflict_ratio",
        "compressed_size_ends_after_descriptor_count",
        "compressed_size_ends_before_next_local_gap_count",
        "descriptor_span_present_count",
        "descriptor_span_conflicts_with_cd_size_count",
        "cd_offset_size_joint_conflict_count",
        "cd_offset_valid_but_size_conflict_count",
        "cd_size_valid_but_offset_conflict_count",
    ):
        assert field in descriptor
    assert descriptor["wrong_local_header_target_count"] > 0 or descriptor["local_header_offset_bad_signature_count"] > 0


def test_training_runtime_exposes_zip_observation_facts_in_structure(tmp_path):
    archive = tmp_path / "bad.zip"
    archive.write_bytes(b"PK\x03\x04bad")
    knowledge = {
        "source": {"input": {"kind": "file", "path": str(archive), "format_hint": "zip"}},
        "analysis": {"summary": {"format": "zip", "confidence": 1.0}},
        "format": {
            "zip": {
                "structure": {
                    "directory_consistency": {"cd_entries_checked": 2, "central_local_crc_mismatch_count": 1},
                    "evidence": {"payload_failure_without_header_mismatch": True},
                }
            }
        },
        "extraction": {"entry_outcomes": {"entry_failed_count": 1, "crc_error_count": 1}},
        "verification": {"coverage_breakdown": {"failed_files": 1, "crc_mismatch_count": 1}, "summary": {"decision_hint": "repair"}},
    }
    job = RepairJob(
        source_input={"kind": "file", "path": str(archive), "format_hint": "zip"},
        format="zip",
        knowledge=knowledge,
        archive_key="unit",
    )

    request = build_damage_analysis_request(job, None, diagnosis={"format": "zip"})
    structure = request.runtime_context["analysis_native_probe"]["structure"]

    assert structure["extraction_entry_outcomes"]["entry_failed_count"] == 1
    assert structure["verification_coverage_breakdown"]["crc_mismatch_count"] == 1
    assert structure["evidence"]["payload_failure_without_header_mismatch"] is True
