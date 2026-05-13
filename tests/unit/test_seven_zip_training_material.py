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
from sunpack.repair.pipeline.modules.seven_zip._scan import password_fingerprint
from sunpack.repair.pipeline.modules.seven_zip.atomic import SevenZipFixStartHeaderCrc
from sunpack.repair.runtime_cache import RepairRuntimeCache

from repair_training.core.plugin import load_training_format_plugin
from repair_training.formats.seven_zip.corruption_impl import main as build_seven_zip_material


def test_seven_zip_training_plugin_defaults():
    plugin = load_training_format_plugin("7z")

    assert plugin.format_name == "seven_zip"
    assert plugin.model_output_subdir == Path("models") / "seven_zip_runtime_policy"
    assert plugin.default_collection_budget["root_branch_top_k"] == 5


def test_seven_zip_distribution_total_is_2800():
    path = Path("repair_training/formats/seven_zip/distributions/damage_distribution_seven_zip_root_transition_v1.json")
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
        "12",
    ])

    assert rc == 0
    assert (material_root / "sources" / "clean_archive_manifest.jsonl").is_file()
    assert not (material_root / "damage_manifest.jsonl").exists()
    report = json.loads((material_root / "material_distribution_report_seven_zip_v1.json").read_text(encoding="utf-8"))
    coverage = report["clean_variant_coverage"]
    assert coverage["variant_count"] == 12
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
    no_password_job = RepairJob(
        source_input={"kind": "bytes", "data": b"", "format_hint": "7z"},
        format="seven_zip",
        damage_flags=["start_header_crc_bad", "encrypted_header", "wrong_password"],
    )
    password_job = RepairJob(
        source_input={"kind": "bytes", "data": b"", "format_hint": "7z"},
        format="seven_zip",
        damage_flags=["start_header_crc_bad", "encrypted_header", "wrong_password"],
        password="secret",
    )

    assert module.can_handle(no_password_job, diagnosis, {}) == 0.0
    assert module.can_handle(password_job, diagnosis, {}) > 0.0


def test_seven_zip_password_fingerprint_is_stable_and_non_plaintext():
    first = password_fingerprint("secret")
    second = password_fingerprint("secret")
    other = password_fingerprint("different")

    assert first == second
    assert first != other
    assert first
    assert "secret" not in first
