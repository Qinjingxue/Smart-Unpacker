from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from sunpack.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputRange
from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack.repair.pipeline.modules._common import crop_source_input_ranges
from sunpack.repair.pipeline.modules._native_candidates import candidates_from_native_result
from sunpack.repair.pipeline.modules.seven_zip._scan import password_fingerprint
from sunpack.repair.pipeline.modules.seven_zip.atomic import SevenZipFixStartHeaderCrc
from sunpack.repair.runtime_cache import RepairRuntimeCache

from repair_training.core.plugin import load_training_format_plugin
from repair_training.formats.seven_zip.corruption_impl import main as build_seven_zip_material


def test_seven_zip_training_plugin_defaults():
    plugin = load_training_format_plugin("7z")

    assert plugin.format_name == "seven_zip"
    assert plugin.model_output_subdir == Path("models") / "seven_zip_policy_lab"
    assert plugin.default_collection_budget["root_branch_top_k"] == 5


def test_seven_zip_distribution_total_is_2800():
    path = Path("repair_training/formats/seven_zip/distributions/damage_distribution_seven_zip_root_transition_v2.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    total = sum(int(value if not isinstance(value, dict) else value.get("count", 0)) for group in ("profiles", "compound_profiles", "physical_profiles") for value in payload[group].values())

    assert payload["total"] == 2800
    assert total == 2800


def test_seven_zip_material_smoke_generates_manifest_and_metadata(tmp_path):
    if not (Path("tools/7z.exe").is_file() or shutil.which("7z") or shutil.which("7z.exe")):
        pytest.skip("7z executable is not available")
    material_root = tmp_path / "seven_zip_material"

    rc = build_seven_zip_material(["--limit", "3", "--material-root", str(material_root), "--clean"])

    assert rc == 0
    clean_manifest = material_root / "sources" / "clean_archive_manifest.jsonl"
    clean_rows = [json.loads(line) for line in clean_manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert clean_rows
    methods = {row["compression_method"] for row in clean_rows}
    levels = {int(row["compression_level"]) for row in clean_rows}
    assert {"LZMA2", "LZMA", "PPMd"}.issubset(methods)
    assert {1, 5, 9}.issubset(levels)
    assert any(row["sfx"] for row in clean_rows)
    assert any(row["split"] for row in clean_rows)
    assert any(row["encrypted"] and row["password_present"] for row in clean_rows)
    manifest = material_root / "damage_manifest.jsonl"
    rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(rows) == 3
    for row in rows:
        assert row["format"] == "seven_zip"
        assert row["damaged_input"]["format_hint"] == "7z"
        assert row["seven_zip_structure_features"]
        assert "seven_zip_signature_found" in row["runtime_damage_flags"]
        assert row["oracle"]["expected_files"]
        assert "physical_complete_expected" in row


def test_seven_zip_clean_only_writes_variant_coverage_report(tmp_path):
    if not (Path("tools/7z.exe").is_file() or shutil.which("7z") or shutil.which("7z.exe")):
        pytest.skip("7z executable is not available")
    material_root = tmp_path / "seven_zip_clean_only"

    rc = build_seven_zip_material([
        "--material-root",
        str(material_root),
        "--clean",
        "--clean-only",
        "--clean-variant-limit",
        "48",
    ])

    assert rc == 0
    assert (material_root / "sources" / "clean_archive_manifest.jsonl").is_file()
    assert not (material_root / "damage_manifest.jsonl").exists()
    report = json.loads((material_root / "material_distribution_report_seven_zip_v2.json").read_text(encoding="utf-8"))
    coverage = report["clean_variant_coverage"]
    assert coverage["variant_count"] == 48
    assert coverage["sfx_counts"].get("true")
    assert coverage["split_counts"].get("true")
    assert coverage["encrypted_counts"].get("true")


def test_seven_zip_split_profile_uses_split_parts(tmp_path):
    if not (Path("tools/7z.exe").is_file() or shutil.which("7z") or shutil.which("7z.exe")):
        pytest.skip("7z executable is not available")
    material_root = tmp_path / "seven_zip_split"
    distribution = tmp_path / "split_distribution.json"
    distribution.write_text(json.dumps({
        "total": 1,
        "profiles": {},
        "compound_profiles": {
            "compound_sfx_split_descriptor_payload_partial": {
                "count": 1,
                "compound_components": ["sfx_prefix", "payload_partial"],
                "expected_route_facts": ["split_archive", "carrier_prefix", "payload_crc_bad"],
                "physical_complete_expected": False,
            }
        },
        "physical_profiles": {},
    }), encoding="utf-8")

    rc = build_seven_zip_material([
        "--limit",
        "1",
        "--material-root",
        str(material_root),
        "--profile-distribution",
        str(distribution),
        "--clean",
    ])

    assert rc == 0
    row = json.loads((material_root / "damage_manifest.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert row["damaged_input"]["parts"]
    assert row["damaged_input"]["use_parts_only"] is True
    assert "split_archive" in row["seven_zip_container_tags"]
    assert row["source_derivation"]["split"] is True
    assert row["source_derivation"]["split_entry_path"]
    first_part = row["damaged_input"]["parts"][0]
    if row["source_derivation"]["sfx"]:
        assert first_part["role"] == "carrier"
        assert row["damaged_path"].endswith(".exe")


def test_seven_zip_split_trailing_junk_targets_logical_tail(tmp_path):
    if not (Path("tools/7z.exe").is_file() or shutil.which("7z") or shutil.which("7z.exe")):
        pytest.skip("7z executable is not available")
    material_root = tmp_path / "seven_zip_split_tail"
    distribution = tmp_path / "split_tail_distribution.json"
    distribution.write_text(json.dumps({
        "total": 1,
        "profiles": {
            "seven_zip_split_trailing_junk": {
                "count": 1,
                "compound_components": ["trailing_junk"],
                "expected_route_facts": ["split_sidecars_available", "trailing_junk"],
                "variant_requirements": ["split"],
            }
        },
        "compound_profiles": {},
        "physical_profiles": {},
    }), encoding="utf-8")

    rc = build_seven_zip_material([
        "--limit",
        "1",
        "--material-root",
        str(material_root),
        "--profile-distribution",
        str(distribution),
        "--clean",
    ])

    assert rc == 0
    row = json.loads((material_root / "damage_manifest.jsonl").read_text(encoding="utf-8").splitlines()[0])
    mutation = row["corruption_plan"][0]
    assert mutation["operation"] == "append"
    assert mutation["logical_offset"] == mutation["offset"]
    assert mutation["part_path"] == row["damaged_input"]["parts"][-1]["path"]
    assert mutation["part_offset"] >= 0


def test_crop_source_input_ranges_preserves_split_metadata():
    source = {
        "kind": "concat_ranges",
        "format_hint": "7z",
        "password": "secret",
        "parts": [{"path": "p1", "role": "carrier"}, {"path": "p2", "role": "volume"}],
        "ranges": [{"path": "p1", "start": 0, "end": 100}, {"path": "p2", "start": 0, "end": 200}],
        "split_sidecars_available": True,
        "logical_stream_built": True,
    }

    cropped = crop_source_input_ranges(source, 20)

    assert cropped is not None
    assert cropped["kind"] == "concat_ranges"
    assert cropped["ranges"] == [{"path": "p1", "start": 20, "end": 100}, {"path": "p2", "start": 0, "end": 200}]
    assert cropped["split_sidecars_available"] is True
    assert cropped["logical_stream_built"] is True
    assert cropped["parts"] == source["parts"]
    assert cropped["password"] == "secret"


def test_split_aware_carrier_crop_candidate_uses_concat_ranges():
    job = RepairJob(
        source_input={
            "kind": "concat_ranges",
            "format_hint": "7z",
            "parts": [{"path": "p1", "role": "carrier"}, {"path": "p2", "role": "volume"}],
            "ranges": [{"path": "p1", "start": 0, "end": 100}, {"path": "p2", "start": 0, "end": 200}],
            "split_sidecars_available": True,
            "logical_stream_built": True,
        },
        format="seven_zip",
        password="secret",
    )
    result = {
        "status": "repaired",
        "format": "7z",
        "native_target": "carrier_prefix",
        "candidates": [{
            "path": "debug-crop.7z",
            "offset": 20,
            "actions": ["crop_archive_carrier_prefix"],
            "patch_facts": ["after_archive_carrier_crop"],
        }],
    }

    candidates = candidates_from_native_result(
        "seven_zip_crop_carrier_prefix",
        result,
        job,
        RepairDiagnosis(format="seven_zip"),
        native_key="native_7z_atomic_repair",
    )

    assert candidates
    repaired_input = candidates[0].repaired_input
    assert repaired_input["kind"] == "concat_ranges"
    assert repaired_input["split_sidecars_available"] is True
    assert repaired_input["logical_stream_built"] is True
    assert repaired_input["ranges"][0]["start"] == 20
    assert repaired_input["password"] == "secret"
    assert "split_logical_stream_preserved_after_crop" in candidates[0].diagnosis["patch_facts"]


def test_seven_zip_native_carrier_crop_preserves_split_metadata(tmp_path):
    part1 = tmp_path / "archive.exe"
    part2 = tmp_path / "archive.7z.002"
    part1.write_bytes(b"carrier-prefix" + b"a" * 20)
    part2.write_bytes(b"b" * 20)
    source_input = {
        "kind": "concat_ranges",
        "format_hint": "7z",
        "ranges": [
            {"path": str(part1), "start": 0, "end": None, "part_index": 0},
            {"path": str(part2), "start": 0, "end": None, "part_index": 1},
        ],
        "parts": [
            {"path": str(part1), "index": 0, "volume_number": 1, "role": "carrier"},
            {"path": str(part2), "index": 1, "volume_number": 2, "role": "volume"},
        ],
        "split_sidecars_available": True,
        "logical_stream_built": True,
    }
    job = RepairJob(
        source_input=source_input,
        format="seven_zip",
        password="secret",
        workspace=str(tmp_path / "workspace"),
        repair_cache=RepairRuntimeCache(),
    )
    result = {
        "status": "repaired",
        "format": "7z",
        "native_target": "carrier_prefix",
        "candidates": [{
            "path": "debug-crop.7z",
            "offset": 14,
            "actions": ["crop_7z_carrier_prefix"],
            "patch_facts": ["cropped_carrier_prefix", "cropped_start=14", "cropped_end=34"],
        }],
    }

    candidates = candidates_from_native_result(
        "seven_zip_crop_carrier_prefix",
        result,
        job,
        RepairDiagnosis(format="seven_zip"),
        native_key="native_7z_atomic_repair",
    )

    repaired_input = candidates[0].repaired_input
    assert repaired_input["kind"] == "concat_ranges"
    assert repaired_input["split_sidecars_available"] is True
    assert repaired_input["logical_stream_built"] is True
    assert repaired_input["ranges"][0]["path"] == str(part1)
    assert repaired_input["ranges"][0]["start"] == 14
    assert repaired_input["ranges"][1]["path"] == str(part2)
    assert repaired_input["password"] == "secret"
    assert "split_logical_stream_preserved_after_crop" in candidates[0].diagnosis["patch_facts"]


def test_seven_zip_source_input_carries_password_for_file_concat_and_patched_state(tmp_path):
    source = tmp_path / "source.7z"
    part = tmp_path / "source.7z.001"
    source.write_bytes(b"abcdef")
    part.write_bytes(b"123456")

    file_payload = source_input_for_job(RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "7z"},
        format="seven_zip",
        password="secret",
    ))
    assert file_payload["password"] == "secret"

    concat_payload = source_input_for_job(RepairJob(
        source_input={
            "kind": "file",
            "path": str(source),
            "format_hint": "7z",
            "parts": [{"path": str(part)}],
            "use_parts_only": True,
        },
        format="seven_zip",
        password="secret",
        workspace=str(tmp_path / "workspace"),
        repair_cache=RepairRuntimeCache(),
    ))
    assert concat_payload["kind"] == "file"
    assert concat_payload["logical_stream_built"] is True
    assert concat_payload["password"] == "secret"

    descriptor = ArchiveInputDescriptor(
        entry_path=str(source),
        open_mode="file",
        format_hint="7z",
        ranges=[ArchiveInputRange(path=str(source), start=0, end=None)],
    )
    state = ArchiveState.from_archive_input(
        descriptor,
        patches=[PatchPlan(operations=[PatchOperation.replace_bytes(offset=0, data=b"Z")])],
    )
    patched_payload = source_input_for_job(RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "7z"},
        archive_state=state,
        format="seven_zip",
        password="secret",
    ))
    assert patched_payload["kind"] == "bytes"
    assert patched_payload["password"] == "secret"
    assert patched_payload["data"].startswith(b"Z")


def test_seven_zip_password_flags_veto_only_without_resolved_password():
    module = SevenZipFixStartHeaderCrc()
    diagnosis = RepairDiagnosis(format="seven_zip")
    encrypted_header_fact_job = RepairJob(
        source_input={"kind": "bytes", "data": b"", "format_hint": "7z"},
        format="seven_zip",
        damage_flags=["start_header_crc_bad", "encrypted_header_present", "wrong_password"],
    )
    password_required_job = RepairJob(
        source_input={"kind": "bytes", "data": b"", "format_hint": "7z"},
        format="seven_zip",
        damage_flags=["start_header_crc_bad", "password_required", "wrong_password"],
    )
    password_job = RepairJob(
        source_input={"kind": "bytes", "data": b"", "format_hint": "7z"},
        format="seven_zip",
        damage_flags=["start_header_crc_bad", "password_required", "wrong_password"],
        password="secret",
    )

    assert module.can_handle(encrypted_header_fact_job, diagnosis, {}) > 0.0
    assert module.can_handle(password_required_job, diagnosis, {}) == 0.0
    assert module.can_handle(password_job, diagnosis, {}) > 0.0


def test_seven_zip_password_fingerprint_is_stable_and_non_plaintext():
    first = password_fingerprint("secret")
    second = password_fingerprint("secret")
    other = password_fingerprint("different")

    assert first == second
    assert first != other
    assert first
    assert "secret" not in first
