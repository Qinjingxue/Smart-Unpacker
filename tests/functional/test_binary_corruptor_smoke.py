from pathlib import Path
import json

import pytest

from smart_unpacker.repair import RepairJob, RepairScheduler
from smart_unpacker.support.archive_state_view import archive_state_to_bytes
from tests.helpers.binary_corruptor import (
    BinaryCorruptor,
    CorruptionCase,
    apply_mutations,
    repair_result_summary,
    verify_corruption_case_output,
)


@pytest.mark.parametrize("seed", [1001, 2027])
def test_binary_corruptor_is_deterministic(tmp_path, seed):
    left = BinaryCorruptor(seed).build_default_cases(tmp_path / "left")
    right = BinaryCorruptor(seed).build_default_cases(tmp_path / "right")

    assert [case.case_id for case in left] == [case.case_id for case in right]
    assert [case.corrupted_sha256 for case in left] == [case.corrupted_sha256 for case in right]
    assert [case.mutation_summary() for case in left] == [case.mutation_summary() for case in right]
    for case in left:
        assert apply_mutations(case.clean_data, case.mutations) == case.corrupted_data
        assert case.patch_plan.operations


@pytest.mark.parametrize("case_index", range(15))
def test_binary_corruptor_cases_drive_repair_layer(tmp_path, case_index):
    case = BinaryCorruptor(424242).build_default_cases(tmp_path / "cases")[case_index]
    result = _run_repair(tmp_path, case)

    assert result.status in case.expected_statuses, case.mutation_summary()
    if case.expected_module:
        assert result.module_name == case.expected_module

    if result.ok:
        assert result.repaired_input is not None
        output = Path(result.repaired_input["path"])
        assert output.is_file()
        if case.output_required:
            verify_corruption_case_output(case, output)
        return

    assert result.repaired_input is None
    assert result.message or result.diagnosis


@pytest.mark.parametrize("case_index", [2, 5, 7])
def test_binary_corruptor_combination_profiles_record_grouped_mutations(tmp_path, case_index):
    case = BinaryCorruptor(515151).build_default_cases(tmp_path / "combo-cases")[case_index]

    assert apply_mutations(case.clean_data, case.mutations) == case.corrupted_data
    assert len(case.mutations) >= 3
    groups = {
        mutation.operation.details.get("combination_group")
        for mutation in case.mutations
    }
    assert groups >= {0, 1}
    assert all("combination_index" in mutation.operation.details for mutation in case.mutations)
    assert case.patch_plan.provenance["mutations"] == case.mutation_summary()

    result = _run_repair(tmp_path, case)
    assert result.status in case.expected_statuses, case.mutation_summary()
    if case.expected_module:
        assert result.module_name == case.expected_module
    if result.ok and case.output_required:
        verify_corruption_case_output(case, Path(result.repaired_input["path"]))


@pytest.mark.parametrize("case_index", [0, 1, 4, 8])
def test_binary_corruptor_archive_state_patch_input_matches_materialized_corruption(tmp_path, case_index):
    case = BinaryCorruptor(818181).build_default_cases(tmp_path / "virtual-cases")[case_index]
    state = case.archive_state_input()

    assert archive_state_to_bytes(state) == case.corrupted_data

    materialized_result = _run_repair(tmp_path / "materialized", case)
    virtual_result = _run_repair(tmp_path / "virtual", case, use_archive_state=True)

    assert virtual_result.status == materialized_result.status
    assert virtual_result.module_name == materialized_result.module_name
    if virtual_result.ok:
        assert virtual_result.repaired_input is not None
        assert Path(virtual_result.repaired_input["path"]).is_file()
        if case.output_required:
            verify_corruption_case_output(case, Path(virtual_result.repaired_input["path"]))


def test_binary_corruptor_multipart_cases_use_concat_ranges_and_cover_repair_outcomes(tmp_path):
    cases = BinaryCorruptor(909090).build_default_cases(tmp_path / "multipart-cases")
    tail_case = cases[10]
    missing_case = cases[11]

    for case in (tail_case, missing_case):
        assert case.source_input["kind"] == "concat_ranges"
        assert len(case.source_input["ranges"]) >= 2
        assert apply_mutations(case.clean_data, case.mutations) == case.corrupted_data

    tail_result = _run_repair(tmp_path / "tail", tail_case)
    assert tail_result.status in tail_case.expected_statuses
    assert tail_result.module_name == tail_case.expected_module
    verify_corruption_case_output(tail_case, Path(tail_result.repaired_input["path"]))

    missing_result = _run_repair(tmp_path / "missing", missing_case)
    assert missing_result.status in missing_case.expected_statuses
    assert missing_result.repaired_input is None
    assert missing_result.message or missing_result.diagnosis


def test_binary_corruptor_diagnostic_report_includes_minimal_reproduction_payload(tmp_path):
    case = BinaryCorruptor(31337).zip_missing_cd_payload_bad_tail(tmp_path / "diagnostic-case")
    result = _run_repair(tmp_path / "repair", case)

    report = case.diagnostic_report(result)
    assert report["seed"] == 31337
    assert report["case_id"] == "zip_missing_cd_payload_bad_tail"
    assert report["format"] == "zip"
    assert report["corrupted_sha256"] == case.corrupted_sha256
    assert report["mutations"] == case.mutation_summary()
    assert report["oracle"]["expected_statuses"] == list(case.expected_statuses)
    assert report["repair_result"] == repair_result_summary(result)
    assert report["repair_result"]["status"] == result.status
    assert report["repair_result"]["module_name"] == result.module_name
    assert "BinaryCorruptor(31337)" in report["regression_snippet"]
    assert "zip_missing_cd_payload_bad_tail(root)" in report["regression_snippet"]

    parsed = json.loads(case.diagnostic_json(result))
    assert parsed["corrupted_sha256"] == case.corrupted_sha256
    assert parsed["repair_result"]["status"] == result.status


def test_binary_corruptor_unrepairable_diagnostic_report_preserves_reason_context(tmp_path):
    case = BinaryCorruptor(41414).zip_multipart_missing_middle(tmp_path / "diagnostic-missing")
    result = _run_repair(tmp_path / "repair-missing", case)

    assert result.status in {"unrepairable", "unsupported"}
    report = case.diagnostic_report(result)
    assert report["oracle"]["expected_statuses"] == ["unrepairable", "unsupported"]
    assert report["repair_result"]["status"] == result.status
    assert report["repair_result"]["ok"] is False
    assert report["repair_result"]["diagnosis"]["diagnosis_keys"]
    assert report["source_input"]["kind"] == "concat_ranges"


@pytest.mark.parametrize("fmt", ["zip", "tar", "gzip"])
def test_binary_corruptor_raw_perturbations_are_reproducible_and_do_not_crash_repair(tmp_path, fmt):
    case = BinaryCorruptor(777).raw_binary_perturbation(tmp_path / "raw", fmt, budget=6)
    same_case = BinaryCorruptor(777).raw_binary_perturbation(tmp_path / "raw-again", fmt, budget=6)

    assert case.corrupted_sha256 == same_case.corrupted_sha256
    assert apply_mutations(case.clean_data, case.mutations) == case.corrupted_data
    assert {mutation.operation.op for mutation in case.mutations} <= {
        "append",
        "delete",
        "insert",
        "replace_range",
        "truncate",
    }

    result = _run_repair(tmp_path, case)
    assert result.status in case.expected_statuses
    if result.ok:
        assert result.repaired_input is not None
        assert Path(result.repaired_input["path"]).is_file()
    else:
        assert result.message or result.diagnosis


@pytest.mark.parametrize("case_index", [12, 13, 14])
def test_binary_corruptor_7z_and_rar_profiles_drive_repair_layer(tmp_path, case_index):
    case = BinaryCorruptor(123123).build_default_cases(tmp_path / "format-cases")[case_index]

    assert case.format in {"7z", "rar"}
    assert apply_mutations(case.clean_data, case.mutations) == case.corrupted_data
    result = _run_repair(tmp_path, case)

    assert result.status in case.expected_statuses, case.diagnostic_report(result)
    assert result.module_name == case.expected_module
    assert result.repaired_input is not None
    verify_corruption_case_output(case, Path(result.repaired_input["path"]))


@pytest.mark.parametrize("fmt", ["zip", "7z", "rar", "gzip"])
def test_binary_corruptor_zone_aware_raw_mutations_cover_semantic_zones(tmp_path, fmt):
    case = BinaryCorruptor(888).zone_aware_raw_perturbation(tmp_path / "zone", fmt)

    assert apply_mutations(case.clean_data, case.mutations) == case.corrupted_data
    zones = {mutation.zone for mutation in case.mutations}
    assert any(zone.endswith(".header") for zone in zones)
    assert any(zone.endswith(".payload") for zone in zones)
    assert any(zone.endswith(".footer") for zone in zones)
    assert any("fake_magic" in zone for zone in zones)

    result = _run_repair(tmp_path, case)
    assert result.status in case.expected_statuses
    assert result.message or result.diagnosis or result.ok


def test_binary_corruptor_encrypted_zip_with_password_repairs_structural_tail(tmp_path):
    case = _encrypted_case_or_skip(tmp_path, "encrypted_zip_trailing_junk")
    result = _run_repair(tmp_path, case)

    assert result.status in case.expected_statuses, case.diagnostic_report(result)
    assert result.module_name == case.expected_module
    assert result.ok is True


def test_binary_corruptor_encrypted_payload_without_password_is_not_misreported_repaired(tmp_path):
    case = _encrypted_case_or_skip(tmp_path, "encrypted_zip_payload_bad_unknown_password")
    result = _run_repair(tmp_path, case)

    assert result.status in case.expected_statuses, case.diagnostic_report(result)
    assert result.ok is False
    assert result.repaired_input is None


def _run_repair(tmp_path: Path, case: CorruptionCase, *, use_archive_state: bool = False):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair-workspace"),
            "max_modules_per_job": 8,
            "stages": {"deep": True},
            "deep": {
                "max_candidates_per_module": 4,
                "verify_candidates": False,
            },
        }
    })
    archive_state = case.archive_state_input() if use_archive_state else None
    return scheduler.repair(RepairJob(
        source_input=case.clean_source_input if use_archive_state else case.source_input,
        format=case.format,
        confidence=0.82,
        damage_flags=case.damage_flags,
        archive_key=case.case_id,
        archive_state=archive_state,
        password=case.password,
    ))


def _encrypted_case_or_skip(tmp_path: Path, builder_name: str) -> CorruptionCase:
    builder = getattr(BinaryCorruptor(919191), builder_name)
    try:
        return builder(tmp_path / builder_name)
    except FileNotFoundError as exc:
        pytest.skip(f"7z.exe is required for encrypted ZIP corruption fixtures: {exc}")
