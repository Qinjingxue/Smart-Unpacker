import base64
import json
import zipfile
from pathlib import Path

import repair_training.collect_damage_rows as collect_damage_rows_module
from repair_training.core.material_records import attach_split_volumes
from repair_training.core.features import damage_labels_for_row, damage_location_labels_from_target, uncertain_labels_for_row
from repair_training.collect_damage_rows import collect_damage_row
from repair_training.formats.zip.corruption_impl import build_corpus_corruption_case
from repair_training.formats.zip.observability import apply_zip_observability
from repair_training.formats.zip.plugin import damage_feature_spec
from repair_training.taxonomy import normalize_damage_record
from sunpack.analysis import ArchiveAnalysisReport
from sunpack.analysis.knowledge import write_analysis_report
from sunpack.analysis.result import ArchiveFormatEvidence
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.detection.pipeline.processors.modules.format_structure.zip_directory_consistency import inspect_zip_directory_consistency
from sunpack.detection.pipeline.processors.modules.format_structure.zip_eocd import inspect_zip_eocd_structure
from sunpack.detection.pipeline.processors.modules.format_structure.zip_structure_graph import inspect_zip_structure_graph
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
    assert distribution["profiles"]["zip_sfx_cd_damage"] >= 180
    assert distribution["profiles"]["zip_extra_field_local_header_bad"] == 120
    assert distribution["compound_profiles"]["compound_sfx_cd_offset_only"]["count"] == 40
    assert distribution["compound_profiles"]["compound_sfx_cd_offset_split_only"]["count"] == 40
    assert distribution["compound_profiles"]["compound_sfx_cd_offset_with_payload_no_local_header"]["count"] == 60


def test_collect_damage_rows_limit_auto_expands_per_source(monkeypatch, tmp_path):
    class FakeCase:
        def __init__(self, profile: str, variant_index: int):
            self.profile = profile
            self.variant_index = variant_index

        def corpus_manifest_record(self, **kwargs):
            return {
                "sample_id": f"{kwargs['source_archive_id']}:{self.variant_index}",
                "source_archive_id": kwargs["source_archive_id"],
                "source_path": kwargs["source_path"],
                "damage_profile": self.profile,
                "variant_index": self.variant_index,
                "damaged_input": {"kind": "file", "path": str(tmp_path / "fake.zip"), "format_hint": "zip"},
                "corruption_plan": [],
            }

    sources = [
        {"source": tmp_path / f"source{i}.zip", "source_archive_id": f"source{i}", "source_derivation": {}}
        for i in range(3)
    ]
    monkeypatch.setattr(collect_damage_rows_module, "_load_profile_distribution", lambda path: ({"profiles": {"p": 9}}, {"p": {}}))
    monkeypatch.setattr(collect_damage_rows_module, "_expanded_profile_plan", lambda distribution, rng: [f"profile{i}" for i in range(9)])
    monkeypatch.setattr(collect_damage_rows_module, "_distributed_zip_sources", lambda zip_dir, selected: sources)
    monkeypatch.setattr(collect_damage_rows_module, "_choose_source_for_profile", lambda items, profile, counts, rng: items[0])
    monkeypatch.setattr(collect_damage_rows_module, "build_corpus_corruption_case", lambda *args, damage_profile, variant_index, **kwargs: FakeCase(damage_profile, variant_index))
    monkeypatch.setattr(collect_damage_rows_module, "_profile_layer_name", lambda profile: "unit")
    monkeypatch.setattr(collect_damage_rows_module, "_apply_profile_metadata", lambda record, profile, metadata: None)

    records = collect_damage_rows_module._generate_zip_records(
        material_root=tmp_path,
        workspace=tmp_path / "generated",
        seed=123,
        per_source=1,
        limit=9,
        distribution_path=tmp_path / "distribution.json",
    )

    assert len(records) == 9


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


def test_attach_split_volumes_reads_source_derivation_zip_split(tmp_path):
    damaged = tmp_path / "damaged.zip"
    z01 = tmp_path / "sample.z01"
    z02 = tmp_path / "sample.z02"
    damaged.write_bytes(b"bad")
    z01.write_bytes(b"part1")
    z02.write_bytes(b"part2")
    source_input = {"kind": "file", "path": str(damaged), "format_hint": "zip"}
    record = {
        "damage_profile": "compound_sfx_cd_offset_split_only",
        "damaged_input": source_input,
        "source_derivation": {
            "zip_container_tags": ["sfx", "split", "multi_volume"],
            "zip_split": {
                "volumes": [
                    {"index": 1, "path": str(z01)},
                    {"index": 2, "path": str(z02)},
                ]
            },
        },
    }

    attach_split_volumes(source_input, record)

    assert source_input["split_sidecars_available"] is True
    assert "open_mode" not in source_input
    assert [Path(item["path"]).name for item in source_input["parts"]] == ["damaged.zip", "sample.z01", "sample.z02"]
    assert len(source_input["ranges"]) == 3


def test_zip_descriptor_conflict_default_does_not_insert_fake_descriptor(tmp_path):
    for profile in ("zip_data_descriptor_conflict", "zip_data_descriptor_cd_conflict", "zip_data_descriptor_payload_bad"):
        plan = _profile_plan(tmp_path, profile)
        descriptor_items = [item for item in plan if str(item.get("zone") or "") == "zip.data_descriptor"]

        assert descriptor_items == []
        assert not any((item.get("operation") or {}).get("op") == "insert" for item in plan if "descriptor" in str(item.get("name") or ""))


def test_zip_split_missing_middle_volume_label_does_not_include_payload(tmp_path):
    labels = set(damage_location_labels_from_target(normalize_damage_record({"format": "zip", "corruption_plan": _profile_plan(tmp_path, "zip_split_missing_middle_volume")}).to_dict()))

    assert "field:split_volume.missing_range" in labels
    assert "zone:split_volume" in labels
    assert "field:payload.compressed_data" not in labels
    assert "zone:payload" not in labels


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
                "analysis": {"summary": {"format": "zip", "confidence": 1.0}},
                "format": {"zip": {"structure": {"graph": {"summary": {}}}}},
                "extraction": {"failure": {"failure_kind": "bad"}},
                "verification": {"summary": {"completeness": 0.0}},
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
    assert row["knowledge_payload"]["analysis"]["summary"]["format"] == "zip"
    assert "candidate" not in json.dumps(row["knowledge_payload"]).lower()
    assert not called_candidates


def test_collect_damage_row_preserves_single_field_root_after_observability(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "repair_training.collect_damage_rows.observe_damage_runtime",
        lambda job, *, workspace, config=None: (
            {
                "analysis": {"summary": {"format": "zip", "confidence": 1.0}},
                "format": {"zip": {"structure": {"graph": {"summary": {"cd_entries_checked": 0}}}}},
                "extraction": {"failure": {"failure_kind": "bad"}},
                "verification": {"summary": {"completeness": 0.0}},
            },
            {"state_digest": "digest", "patch_depth": 0},
        ),
    )
    damaged = tmp_path / "bad.zip"
    damaged.write_bytes(b"PK\x03\x04bad")

    row = collect_damage_row(
        {
            "sample_id": "single",
            "format": "zip",
            "single_field_root": "local_header.crc",
            "damaged_input": {"kind": "file", "path": str(damaged), "format_hint": "zip"},
            "corruption_plan": [{"zone": "zip.local_header.crc", "offset": 1, "size": 4}],
        },
        workspace=tmp_path / "workspace-single",
    )

    labels = set(row["damage_analysis_target"]["damage_labels"])
    assert "field:local_header.crc" in labels
    assert "zone:local_header" in labels


def test_damage_label_normalizer_uses_explicit_labels_only():
    target = {
        "damage_labels": ["zone:central_directory"],
        "labels": [{"zone": {"kind": "record", "path": "zip.central_directory"}}],
    }

    assert damage_labels_for_row({"damage_analysis_target": target}) == ["zone:central_directory"]
    assert damage_location_labels_from_target(target) == ["zone:central_directory"]


def _observability_target(labels, *, summary=None, runtime=None):
    return apply_zip_observability(
        {"damage_labels": list(labels), "labels": [], "metadata": {}},
        {
            "format": {
                "zip": {
                    "structure": {
                        "graph": {"summary": dict(summary or {})},
                        "runtime": dict(runtime or {}),
                    }
                }
            }
        },
    )


def test_zip_observability_marks_local_header_crc_observed_with_cd_mismatch():
    target = _observability_target(
        ["field:local_header.crc", "zone:local_header"],
        summary={"cd_entries_checked": 1, "central_local_crc_mismatch_count": 1},
    )

    assert "field:local_header.crc" in damage_labels_for_row({"damage_analysis_target": target})
    assert "zone:local_header" in damage_labels_for_row({"damage_analysis_target": target})
    assert not uncertain_labels_for_row({"damage_analysis_target": target})


def test_zip_observability_marks_local_header_crc_uncertain_when_reference_missing():
    target = _observability_target(
        ["field:local_header.crc", "field:local_header.compressed_size", "zone:local_header"],
        summary={"cd_entries_checked": 0, "central_local_crc_mismatch_count": 0, "central_local_compressed_size_mismatch_count": 0},
    )

    uncertain = set(uncertain_labels_for_row({"damage_analysis_target": target}))
    observed = set(damage_labels_for_row({"damage_analysis_target": target}))

    assert {"field:local_header.crc", "field:local_header.compressed_size", "zone:local_header"} <= uncertain
    assert "field:local_header.crc" not in observed


def test_zip_observability_marks_payload_observed_with_direct_crc_failure():
    target = _observability_target(
        ["field:payload.compressed_data", "zone:payload"],
        runtime={"payload_direct_crc_or_hash_failure_observed": True, "extraction_crc_error_count": 1},
    )

    assert "field:payload.compressed_data" in damage_labels_for_row({"damage_analysis_target": target})
    assert "zone:payload" in damage_labels_for_row({"damage_analysis_target": target})
    assert not uncertain_labels_for_row({"damage_analysis_target": target})


def test_zip_observability_marks_payload_uncertain_when_explained_by_missing_range():
    target = _observability_target(
        ["field:payload.compressed_data", "zone:payload"],
        runtime={
            "extraction_item_failure_observed": True,
            "payload_extraction_content_failure_observed": True,
            "payload_failure_explained_by_missing_range": True,
            "no_payload_hash_crc_failure": True,
        },
    )

    uncertain = set(uncertain_labels_for_row({"damage_analysis_target": target}))
    observed = set(damage_labels_for_row({"damage_analysis_target": target}))

    assert {"field:payload.compressed_data", "zone:payload"} <= uncertain
    assert "field:payload.compressed_data" not in observed


def test_zip_observability_marks_payload_uncertain_without_verification_signal():
    target = _observability_target(
        ["field:payload.compressed_data", "zone:payload"],
        runtime={"payload_unverified_but_no_failure": True},
    )

    uncertain = set(uncertain_labels_for_row({"damage_analysis_target": target}))
    observed = set(damage_labels_for_row({"damage_analysis_target": target}))

    assert {"field:payload.compressed_data", "zone:payload"} <= uncertain
    assert "field:payload.compressed_data" not in observed


def test_zip_structure_facts_enter_archive_knowledge_and_damage_request(tmp_path):
    archive = tmp_path / "bad.zip"
    archive.write_bytes(b"PK\x03\x04bad")
    facts = FactBag()
    facts.set("file.path", str(archive))
    facts.set("archive.knowledge", {"source": {"input": {"kind": "file", "path": str(archive), "format_hint": "zip"}}})
    facts.set(
        "zip.structure_graph",
        {
            "schema_version": 1,
            "format": "zip",
            "error": "",
            "nodes": [{"id": "eocd:0", "kind": "eocd", "status": "parsed", "start": 17, "end": 39}],
            "edges": [{"source_node": "eocd:0", "target_node": "central_directory:0", "kind": "points_to", "valid": False, "field": "eocd.cd_offset"}],
            "violations": [{"kind": "bad_signature", "field": "eocd.cd_offset", "delta": 17, "severity": "high"}],
            "explanations": [{"kind": "zip64_extra_resolution", "applies": True, "field": "zip64.locator", "delta": 0}],
            "summary": {
                "eocd_present": True,
                "cd_entry_count": 1,
                "zip64_locator_present": True,
                "central_local_crc_mismatch_count": 1,
            },
        },
    )
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

    assert set(structure) == {"graph", "summary"}
    assert structure["graph"]["nodes"][0]["kind"] == "eocd"
    assert structure["graph"]["violations"][0]["field"] == "eocd.cd_offset"
    assert structure["summary"]["central_local_crc_mismatch_count"] == 1
    assert structure["summary"]["zip64_locator_present"] is True

    job = RepairJob(
        source_input={"kind": "file", "path": str(archive), "format_hint": "zip"},
        format="zip",
        knowledge=knowledge,
        archive_key="unit",
    )
    request = build_damage_analysis_request(job, None, diagnosis={"format": "zip"})
    structure = request["format"]["zip"]["structure"]

    assert structure["graph"]["nodes"][0]["kind"] == "eocd"
    assert structure["graph"]["violations"][0]["field"] == "eocd.cd_offset"
    assert structure["summary"]["central_local_crc_mismatch_count"] == 1
    assert structure["summary"]["zip64_locator_present"] is True


def test_zip_structure_graph_native_outputs_graph_shape(tmp_path):
    archive = tmp_path / "clean.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", "hello")

    graph = inspect_zip_structure_graph(str(archive))

    assert graph["schema_version"] == 1
    assert graph["summary"]["cd_entry_count"] == 1
    assert any(node["kind"] == "eocd" for node in graph["nodes"])
    assert any(node["kind"] == "cd_entry" for node in graph["nodes"])
    assert any(node["kind"] == "local_header_candidate" for node in graph["nodes"])
    assert any(edge["kind"] == "points_to" for edge in graph["edges"])
    assert "directory_consistency" not in graph


def test_zip_damage_feature_spec_excludes_compressed_route_flags():
    spec = damage_feature_spec()

    assert spec.include_prefixes == ("knowledge_payload.",)
    assert "knowledge_payload.source.input.path" in spec.ignore_prefixes


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
    structure = request["format"]["zip"]["structure"]

    assert structure["directory_consistency"]["central_local_crc_mismatch_count"] == 1
    assert structure["evidence"]["payload_failure_without_header_mismatch"] is True
