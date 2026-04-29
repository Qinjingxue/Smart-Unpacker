from dataclasses import dataclass
import bz2
import gzip
import io
import lzma
import tarfile
import struct
from pathlib import Path
from types import SimpleNamespace
import zipfile
import zlib

import pytest

from sunpack.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from sunpack.config.schema import normalize_config
from sunpack.repair.config import enabled_module_configs
from sunpack.repair.candidate import CandidateSelector, CandidateValidation, RepairCandidate
from sunpack.repair import RepairJob, RepairScheduler
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.registry import get_repair_module_registry
from sunpack.repair.result import RepairResult


RAR4_MAGIC = b"Rar!\x1a\x07\x00"
RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"
DEFAULT_SALVAGE_MODULES = {
    "archive_nested_payload_salvage",
    "rar_file_quarantine_rebuild",
    "seven_zip_solid_block_partial_salvage",
    "tar_sparse_pax_longname_repair",
    "zip_conflict_resolver_rebuild",
}


def test_repair_scheduler_without_modules_returns_unsupported(tmp_path):
    scheduler = RepairScheduler({"repair": {"workspace": str(tmp_path), "modules": []}})
    job = RepairJob(
        source_input={"kind": "file_range", "path": "mixed.bin", "start": 128},
        format="zip",
        confidence=0.62,
        damage_flags=["boundary_unreliable"],
        archive_key="mixed.zip",
    )

    result = scheduler.repair(job)

    assert result.status == "unsupported"
    assert result.format == "zip"
    assert result.diagnosis["categories"] == ["boundary_repair"]


def test_default_repair_config_enables_deep_salvage_modules(tmp_path):
    scheduler = RepairScheduler({"repair": {"workspace": str(tmp_path / "repair")}})
    enabled = set(enabled_module_configs(scheduler.config))

    assert DEFAULT_SALVAGE_MODULES <= enabled


@pytest.mark.parametrize(
    ("module_name", "fmt", "flags", "failure_kind"),
    [
        (
            "archive_nested_payload_salvage",
            "archive",
            ["outer_container_bad", "nested_archive"],
            "structure_recognition",
        ),
        (
            "rar_file_quarantine_rebuild",
            "rar",
            ["file_block_bad", "crc_error", "checksum_error"],
            "checksum_error",
        ),
        (
            "seven_zip_solid_block_partial_salvage",
            "7z",
            ["solid_block_damaged", "packed_stream_bad", "damaged"],
            "data_error",
        ),
        (
            "tar_sparse_pax_longname_repair",
            "tar",
            ["pax_header_bad", "gnu_longname_bad", "damaged"],
            "structure_recognition",
        ),
        (
            "zip_conflict_resolver_rebuild",
            "zip",
            ["duplicate_entries", "overlapping_entries", "local_header_conflict"],
            "checksum_error",
        ),
    ],
)
def test_default_repair_config_routes_salvage_modules_without_module_override(
    tmp_path,
    module_name,
    fmt,
    flags,
    failure_kind,
):
    source = tmp_path / f"{module_name}.{fmt}"
    source.write_bytes(b"x" * 128)
    scheduler = RepairScheduler({"repair": {"workspace": str(tmp_path / "repair")}})
    job = RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": fmt},
        format=fmt,
        confidence=0.82,
        damage_flags=flags,
        extraction_failure={
            "failure_stage": "verification",
            "failure_kind": failure_kind,
            "decision_hint": "repair",
        },
        archive_key=module_name,
    )

    batch = scheduler.generate_repair_candidates(
        job,
        lazy=True,
    )
    selected = {candidate.module_name for candidate in batch.candidates}
    if module_name in selected:
        return

    result = scheduler.repair(job)
    decisions = result.diagnosis["capability_decision"]["modules"]
    selected_after_primary = {
        item["name"]
        for item in decisions
        if item["selected"] and "selected" in item["reasons"]
    }
    assert module_name in selected_after_primary


def test_auto_deep_prefers_rar_file_quarantine_over_generic_carrier_crop_for_split_damage(tmp_path):
    source = tmp_path / "damaged.part1.rar"
    source.write_bytes(b"Rar!\x1a\x07\x01\x00" + b"x" * 128)
    scheduler = RepairScheduler({"repair": {"workspace": str(tmp_path / "repair")}})
    job = RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "rar"},
        format="rar",
        confidence=0.97,
        damage_flags=["damaged", "missing_entries", "checksum_error", "crc_error"],
        extraction_failure={
            "failure_stage": "verification",
            "failure_kind": "structure_recognition",
            "decision_hint": "repair",
        },
        archive_key="damaged.part1.rar",
    )

    batch = scheduler.generate_repair_candidates(job, lazy=True)

    selected_modules = [candidate.module_name for candidate in batch.candidates]
    assert selected_modules
    assert selected_modules[0] == "rar_file_quarantine_rebuild"
    assert "rar_file_quarantine_rebuild" in selected_modules


def test_repair_diagnosis_combines_analysis_and_extraction_evidence(tmp_path):
    evidence = ArchiveFormatEvidence(
        format="zip",
        confidence=0.7,
        status="damaged",
        segments=[
            ArchiveSegment(
                start_offset=64,
                end_offset=None,
                confidence=0.7,
                damage_flags=["local_header_recovery", "boundary_unreliable"],
            )
        ],
    )
    scheduler = RepairScheduler({"repair": {"workspace": str(tmp_path)}})
    diagnosis = scheduler.diagnose(RepairJob(
        source_input={"kind": "file_range", "path": "carrier.bin", "start": 64},
        format="zip",
        confidence=0.55,
        analysis_evidence=evidence,
        extraction_failure={"checksum_error": True, "failed_item": "payload.bin"},
    ))

    assert diagnosis.format == "zip"
    assert diagnosis.start_trusted is True
    assert "boundary_repair" in diagnosis.categories
    assert "directory_rebuild" in diagnosis.categories
    assert "content_recovery" in diagnosis.categories


def test_repair_scheduler_runs_registered_module(tmp_path):
    module = _DummyBoundaryModule()
    registry = get_repair_module_registry()
    previous = registry.get(module.spec.name)
    registry.register(module)
    try:
        scheduler = RepairScheduler({
            "repair": {
                "workspace": str(tmp_path),
                "modules": [{"name": module.spec.name, "enabled": True}],
            }
        })
        result = scheduler.repair(RepairJob(
            source_input={"kind": "file_range", "path": "mixed.bin", "start": 10},
            format="zip",
            confidence=0.8,
            damage_flags=["boundary_unreliable"],
            archive_key="sample",
        ))
    finally:
        if previous is not None:
            registry.register(previous)

    assert result.ok is True
    assert result.module_name == module.spec.name
    assert result.repaired_input == {"kind": "file_range", "path": "mixed.bin", "start": 10, "end": 100}
    assert result.diagnosis["candidate_selection"]["selected_module"] == module.spec.name


def test_repair_scheduler_filters_unsafe_modules_by_default(tmp_path):
    result = _run_dummy_repair(tmp_path, _DummyUnsafeModule())

    assert result.status == "unsupported"


def test_repair_scheduler_allows_unsafe_modules_when_configured(tmp_path):
    result = _run_dummy_repair(tmp_path, _DummyUnsafeModule(), {
        "safety": {"allow_unsafe": True},
    })

    assert result.ok is True
    assert result.module_name == "dummy_unsafe_boundary"


def test_repair_scheduler_can_disable_partial_modules(tmp_path):
    result = _run_dummy_repair(tmp_path, _DummyPartialModule(), {
        "safety": {"allow_partial": False},
    })

    assert result.status == "unsupported"


def test_repair_scheduler_gates_deep_modules_and_passes_budget_config(tmp_path):
    source = tmp_path / "deep.zip"
    source.write_bytes(b"x" * 4096)
    module = _DummyDeepModule()

    disabled = _run_dummy_repair(tmp_path, module, source=source)
    size_blocked = _run_dummy_repair(tmp_path, module, {
        "stages": {"deep": True},
        "deep": {"max_input_size_mb": 0.001},
    }, source=source)
    allowed = _run_dummy_repair(tmp_path, module, {
        "stages": {"deep": True},
        "deep": {"max_input_size_mb": 1},
        "modules": [
            {
                "name": module.spec.name,
                "enabled": True,
                "deep": {"max_candidates_per_module": 2},
            }
        ],
    }, source=source)

    assert disabled.status == "unsupported"
    assert size_blocked.status == "unsupported"
    assert allowed.ok is True
    assert allowed.actions == ["deep_candidates=2"]


def test_repair_scheduler_auto_deep_escalates_after_verification_repair(tmp_path):
    source = tmp_path / "auto-deep.zip"
    source.write_bytes(b"x" * 4096)
    module = _DummyDeepModule()

    result = _run_dummy_repair(
        tmp_path,
        module,
        source=source,
        extraction_failure={"failure_stage": "verification", "decision_hint": "repair"},
    )

    assert result.ok is True
    assert result.module_name == module.spec.name
    assert result.actions == ["deep_candidates=1"]
    assert any("auto_deep" in warning for warning in result.warnings)


def test_repair_scheduler_auto_deep_requires_verification_repair(tmp_path):
    source = tmp_path / "auto-deep-fail.zip"
    source.write_bytes(b"x" * 4096)
    module = _DummyDeepModule()

    result = _run_dummy_repair(
        tmp_path,
        module,
        source=source,
        extraction_failure={"failure_stage": "verification", "decision_hint": "fail"},
    )

    assert result.status == "unsupported"
    decision = result.diagnosis["capability_decision"]
    assert decision["modules"][0]["policy_reasons"] == ["stage_disabled"]


def test_repair_scheduler_auto_deep_respects_limited_input_size(tmp_path):
    source = tmp_path / "auto-deep-large.zip"
    source.write_bytes(b"x" * 4096)
    module = _DummyDeepModule()

    result = _run_dummy_repair(
        tmp_path,
        module,
        {"auto_deep": {"max_input_size_mb": 0.001}},
        source=source,
        extraction_failure={"failure_stage": "verification", "decision_hint": "repair"},
    )

    assert result.status == "unsupported"
    decision = result.diagnosis["capability_decision"]
    assert decision["modules"][0]["policy_reasons"] == ["deep_input_size_blocked"]


def test_repair_scheduler_auto_deep_escalates_after_candidate_rejection(tmp_path):
    source = tmp_path / "auto-deep-rejected.zip"
    source.write_bytes(b"x" * 4096)
    rejected = _DummyRejectedBoundaryModule()
    deep = _DummyDeepModule()
    registry = get_repair_module_registry()
    previous_rejected = registry.get(rejected.spec.name)
    previous_deep = registry.get(deep.spec.name)
    registry.register(rejected)
    registry.register(deep)
    try:
        scheduler = RepairScheduler({
            "repair": {
                "workspace": str(tmp_path / "repair"),
                "modules": [
                    {"name": rejected.spec.name, "enabled": True},
                    {"name": deep.spec.name, "enabled": True},
                ],
            }
        })
        result = scheduler.repair(RepairJob(
            source_input={"kind": "file", "path": str(source)},
            format="zip",
            confidence=0.8,
            damage_flags=["boundary_unreliable"],
            archive_key="sample",
            extraction_failure={"failure_stage": "verification", "decision_hint": "repair"},
        ))
    finally:
        if previous_rejected is not None:
            registry.register(previous_rejected)
        if previous_deep is not None:
            registry.register(previous_deep)

    assert result.ok is True
    assert result.module_name == deep.spec.name
    assert result.actions == ["deep_candidates=1"]
    assert "candidate rejected" in result.warnings


def test_repair_scheduler_selects_best_generated_candidate(tmp_path):
    module = _DummyGeneratedCandidatesModule()
    registry = get_repair_module_registry()
    previous = registry.get(module.spec.name)
    registry.register(module)
    try:
        scheduler = RepairScheduler({
            "repair": {
                "workspace": str(tmp_path / "repair"),
                "stages": {"deep": True},
                "deep": {"verify_candidates": False},
                "modules": [{"name": module.spec.name, "enabled": True}],
            }
        })
        result = scheduler.repair(RepairJob(
            source_input={"kind": "file", "path": str(tmp_path / "source.zip")},
            format="zip",
            confidence=0.7,
            damage_flags=["boundary_unreliable"],
            archive_key="multi",
        ))
    finally:
        if previous is not None:
            registry.register(previous)

    assert result.ok is True
    assert result.actions == ["generated_best"]
    assert result.diagnosis["candidate_selection"]["candidate_count"] == 2
    assert result.diagnosis["candidate_selection"]["selected_module"] == module.spec.name


def test_repair_scheduler_exposes_generated_candidate_batch(tmp_path):
    module = _DummyGeneratedCandidatesModule()
    registry = get_repair_module_registry()
    previous = registry.get(module.spec.name)
    registry.register(module)
    try:
        scheduler = RepairScheduler({
            "repair": {
                "workspace": str(tmp_path / "repair"),
                "stages": {"deep": True},
                "deep": {"verify_candidates": False},
                "modules": [{"name": module.spec.name, "enabled": True}],
            }
        })
        batch = scheduler.generate_repair_candidates(RepairJob(
            source_input={"kind": "file", "path": str(tmp_path / "source.zip")},
            format="zip",
            confidence=0.7,
            damage_flags=["boundary_unreliable"],
            archive_key="multi",
        ))
    finally:
        if previous is not None:
            registry.register(previous)

    assert batch.terminal_result is None
    assert len(batch.candidates) == 2
    assert [candidate.actions for candidate in batch.candidates] == [["generated_low"], ["generated_best"]]
    assert batch.diagnosis["capability_decision"]["selected_modules"] == [module.spec.name]


def test_repair_scheduler_propagates_password_to_results_and_candidates(tmp_path):
    module = _DummyGeneratedCandidatesModule()
    registry = get_repair_module_registry()
    previous = registry.get(module.spec.name)
    registry.register(module)
    try:
        scheduler = RepairScheduler({
            "repair": {
                "workspace": str(tmp_path / "repair"),
                "stages": {"deep": True},
                "deep": {"verify_candidates": False},
                "modules": [{"name": module.spec.name, "enabled": True}],
            }
        })
        job = RepairJob(
            source_input={"kind": "file", "path": str(tmp_path / "source.zip")},
            format="zip",
            confidence=0.7,
            damage_flags=["boundary_unreliable"],
            archive_key="multi",
            password="secret",
        )
        batch = scheduler.generate_repair_candidates(job)
        result = scheduler.repair(job)
    finally:
        if previous is not None:
            registry.register(previous)

    assert all(candidate.repaired_input["password"] == "secret" for candidate in batch.candidates)
    assert result.repaired_input["password"] == "secret"


def test_repair_scheduler_routes_module_from_fuzzy_profile(tmp_path):
    module = _DummyFuzzyRouteModule()
    registry = get_repair_module_registry()
    previous = registry.get(module.spec.name)
    registry.register(module)
    try:
        scheduler = RepairScheduler({
            "repair": {
                "workspace": str(tmp_path),
                "modules": [{"name": module.spec.name, "enabled": True}],
            }
        })
        result = scheduler.repair(RepairJob(
            source_input={"kind": "file", "path": str(tmp_path / "carrier.bin")},
            format="zip",
            confidence=0.42,
            fuzzy_profile={"hints": ["carrier_prefix_likely"]},
            archive_key="carrier",
        ))
    finally:
        if previous is not None:
            registry.register(previous)

    assert result.ok is True
    assert result.module_name == module.spec.name
    assert result.diagnosis["candidate_selection"]["selected_module"] == module.spec.name


def test_repair_scheduler_synthesizes_unrepairable_from_module_requirements(tmp_path):
    module = _DummyTrailingOnlyRouteModule()
    registry = get_repair_module_registry()
    previous = registry.get(module.spec.name)
    registry.register(module)
    try:
        scheduler = RepairScheduler({
            "repair": {
                "workspace": str(tmp_path),
                "modules": [{"name": module.spec.name, "enabled": True}],
            }
        })
        result = scheduler.repair(RepairJob(
            source_input={"kind": "file", "path": str(tmp_path / "payload.zip")},
            format="zip",
            confidence=0.8,
            damage_flags=["checksum_error", "damaged"],
            archive_key="payload",
        ))
    finally:
        if previous is not None:
            registry.register(previous)

    assert result.status == "unrepairable"
    assert "no enabled repair module declares support" in result.message
    decision = result.diagnosis["capability_decision"]
    assert decision["automatic_unrepairable"] is True
    assert decision["format_supported_modules"] == [module.spec.name]
    assert decision["modules"][0]["declarative_reasons"] == ["route_requirements_unmet"]


def test_repair_scheduler_records_policy_filter_reasons(tmp_path):
    result = _run_dummy_repair(tmp_path, _DummyUnsafeModule())

    assert result.status == "unsupported"
    decision = result.diagnosis["capability_decision"]
    assert decision["automatic_unrepairable"] is False
    assert decision["modules"][0]["policy_reasons"] == ["unsafe_module_blocked"]


def test_repair_scheduler_uses_explicit_tie_breaker_for_equal_module_scores(tmp_path):
    later = _DummyNamedBoundaryModule("z_tie_boundary")
    earlier = _DummyNamedBoundaryModule("a_tie_boundary")
    registry = get_repair_module_registry()
    previous_later = registry.get(later.spec.name)
    previous_earlier = registry.get(earlier.spec.name)
    registry.register(later)
    registry.register(earlier)
    try:
        scheduler = RepairScheduler({
            "repair": {
                "workspace": str(tmp_path),
                "max_modules_per_job": 1,
                "modules": [
                    {"name": later.spec.name, "enabled": True},
                    {"name": earlier.spec.name, "enabled": True},
                ],
            }
        })
        result = scheduler.repair(RepairJob(
            source_input={"kind": "file_range", "path": "mixed.bin", "start": 10},
            format="zip",
            confidence=0.8,
            damage_flags=["boundary_unreliable"],
            archive_key="sample",
        ))
    finally:
        if previous_later is not None:
            registry.register(previous_later)
        if previous_earlier is not None:
            registry.register(previous_earlier)

    assert result.ok is True
    assert result.module_name == earlier.spec.name


def test_candidate_selector_prefers_validated_candidate_over_module_confidence():
    high_confidence = RepairCandidate(
        module_name="high_confidence",
        format="zip",
        repaired_input={"kind": "file", "path": "high.zip"},
        confidence=0.9,
        validations=[CandidateValidation(name="module_result", accepted=True, score=0.9)],
    )
    validated = RepairCandidate(
        module_name="validated",
        format="zip",
        repaired_input={"kind": "file", "path": "validated.zip"},
        confidence=0.8,
        validations=[
            CandidateValidation(name="module_result", accepted=True, score=0.8),
            CandidateValidation(
                name="native_candidate_validation",
                accepted=True,
                score=1.0,
                details={
                    "probe": {"is_archive": True, "is_broken": False},
                    "test": {"ok": True},
                    "dry_run": {"ok": True},
                },
            ),
        ],
    )

    selected, selection = CandidateSelector().select([high_confidence, validated])

    assert selected is validated
    assert selection["selected_module"] == "validated"
    assert selection["generation_priority"] > 0
    assert "score" not in selection


def test_candidate_native_validation_uses_candidate_password_for_encrypted_archive(tmp_path, monkeypatch):
    archive = tmp_path / "encrypted.zip"
    archive.write_bytes(b"not a real archive; native calls are faked")
    fake = _FakePasswordAwareNativeTester()
    dry_calls = []

    def fake_dry_run(path, *, format_hint="", password="", timeout=0):
        dry_calls.append({"path": path, "format_hint": format_hint, "password": password, "timeout": timeout})
        return SimpleNamespace(
            ok=True,
            returncode=0,
            message="ok",
            result={"status": "ok", "files_written": 2, "bytes_written": 12},
            diagnostics={},
        )

    monkeypatch.setattr("sunpack.repair.candidate.get_native_password_tester", lambda: fake)
    monkeypatch.setattr("sunpack.repair.candidate.dry_run_archive", fake_dry_run)

    candidate = RepairCandidate(
        module_name="encrypted_candidate",
        format="zip",
        repaired_input={"kind": "file", "path": str(archive), "format_hint": "zip", "password": "secret"},
        confidence=0.4,
        requires_native_validation=True,
        validations=[CandidateValidation(name="module_result", accepted=True, score=0.4)],
    )

    selected, selection = CandidateSelector().select([candidate])

    assert selected is not None
    assert fake.test_passwords == ["", "secret"]
    assert fake.resource_passwords == ["secret"]
    assert dry_calls[0]["password"] == "secret"
    details = selection["validations"][-1]["details"]
    assert details["password_present"] is True
    assert details["empty_password_ok"] is False
    assert details["archive_coverage"]["completeness"] == 1.0


def test_candidate_selector_uses_password_to_rank_and_reject_encrypted_candidates(tmp_path, monkeypatch):
    archive = tmp_path / "encrypted.zip"
    archive.write_bytes(b"encrypted candidate bytes")
    fake = _FakePasswordAwareNativeTester()

    def fake_dry_run(path, *, format_hint="", password="", timeout=0):
        ok = password == "secret"
        return SimpleNamespace(
            ok=ok,
            returncode=0 if ok else 2,
            message="ok" if ok else "wrong password",
            result={"status": "ok" if ok else "wrong_password", "files_written": 2 if ok else 0, "bytes_written": 12 if ok else 0},
            diagnostics={},
        )

    monkeypatch.setattr("sunpack.repair.candidate.get_native_password_tester", lambda: fake)
    monkeypatch.setattr("sunpack.repair.candidate.dry_run_archive", fake_dry_run)

    confident_unvalidated = RepairCandidate(
        module_name="confident_unvalidated",
        format="zip",
        repaired_input={"kind": "file", "path": str(tmp_path / "confident.zip"), "format_hint": "zip"},
        confidence=0.95,
        validations=[CandidateValidation(name="module_result", accepted=True, score=0.95)],
    )
    password_validated = RepairCandidate(
        module_name="password_validated",
        format="zip",
        repaired_input={"kind": "file", "path": str(archive), "format_hint": "zip", "password": "secret"},
        confidence=0.4,
        requires_native_validation=True,
        validations=[CandidateValidation(name="module_result", accepted=True, score=0.4)],
    )
    unknown_password = RepairCandidate(
        module_name="unknown_password",
        format="zip",
        repaired_input={"kind": "file", "path": str(archive), "format_hint": "zip"},
        confidence=0.9,
        requires_native_validation=True,
        validations=[CandidateValidation(name="module_result", accepted=True, score=0.9)],
    )

    selected, _selection = CandidateSelector().select([confident_unvalidated, password_validated])
    rejected, rejection = CandidateSelector().select([unknown_password])

    assert selected is not None
    assert selected.module_name == "password_validated"
    assert rejected is None
    assert rejection["accepted_count"] == 0


def test_candidate_validation_password_matrix_keeps_wrong_password_priority(tmp_path, monkeypatch):
    fake = _MatrixPasswordNativeTester()

    def fake_dry_run(path, *, format_hint="", password="", timeout=0):
        name = Path(path).name
        ok = password == "secret" and "payload_bad" not in name
        partial = password == "secret" and "payload_bad" in name
        failure_kind = "checksum_error" if partial else "encrypted_or_wrong_password"
        return SimpleNamespace(
            ok=ok,
            returncode=0 if ok else 2,
            message="ok" if ok else ("payload checksum error" if partial else "wrong password"),
            result={
                "status": "ok" if ok else "failed",
                "native_status": "ok" if ok else ("damaged" if partial else "wrong_password"),
                "failure_stage": "" if ok else "item_extract",
                "failure_kind": "" if ok else failure_kind,
                "files_written": 1 if ok or partial else 0,
                "bytes_written": 12 if ok or partial else 0,
            },
            diagnostics={"output_trace": {"items": [{"path": "good.txt", "bytes_written": 12}]}} if partial else {},
        )

    monkeypatch.setattr("sunpack.repair.candidate.get_native_password_tester", lambda: fake)
    monkeypatch.setattr("sunpack.repair.candidate.dry_run_archive", fake_dry_run)

    cases = [
        ("correct_header_bad", "7z", "secret", False, True, "ok"),
        ("correct_payload_bad", "zip", "secret", True, True, "checksum_error"),
        ("wrong_complete", "zip", "wrong", False, False, "encrypted_or_wrong_password"),
        ("wrong_structure", "zip", "wrong", False, False, "encrypted_or_wrong_password"),
        ("unknown_encrypted", "zip", "", False, False, "encrypted_or_wrong_password"),
    ]

    for name, fmt, password, partial, should_accept, expected_failure in cases:
        archive = tmp_path / f"{name}.{fmt}"
        archive.write_bytes(b"candidate bytes")
        candidate = RepairCandidate(
            module_name=name,
            format=fmt,
            repaired_input={
                "kind": "file",
                "path": str(archive),
                "format_hint": fmt,
                **({"password": password} if password else {}),
            },
            confidence=0.9,
            partial=partial,
            requires_native_validation=True,
            validations=[CandidateValidation(name="module_result", accepted=True, score=0.9)],
        )

        selected, selection = CandidateSelector().select([candidate])
        validation = (selection.get("validations") or [{}])[-1] if should_accept else {}

        if should_accept:
            assert selected is not None, name
            assert selected.module_name == name
            assert validation["details"]["password_present"] is True
            assert validation["details"]["dry_run"]["failure_kind"] in {"", expected_failure}
            continue

        assert selected is None, name
        assert selection["accepted_count"] == 0
        assert any("wrong password" in warning for warning in selection["warnings"])


def test_repair_scheduler_records_module_failure_feedback_for_later_decision(tmp_path):
    failing = _DummyFailingBoundaryModule()
    succeeding = _DummyNamedBoundaryModule("z_success_boundary")
    registry = get_repair_module_registry()
    previous_failing = registry.get(failing.spec.name)
    previous_succeeding = registry.get(succeeding.spec.name)
    registry.register(failing)
    registry.register(succeeding)
    try:
        scheduler = RepairScheduler({
            "repair": {
                "workspace": str(tmp_path),
                "modules": [
                    {"name": failing.spec.name, "enabled": True},
                    {"name": succeeding.spec.name, "enabled": True},
                ],
            }
        })
        result = scheduler.repair(RepairJob(
            source_input={"kind": "file_range", "path": "mixed.bin", "start": 10},
            format="zip",
            confidence=0.8,
            damage_flags=["boundary_unreliable"],
            archive_key="sample",
        ))
    finally:
        if previous_failing is not None:
            registry.register(previous_failing)
        if previous_succeeding is not None:
            registry.register(previous_succeeding)

    assert result.ok is True
    modules = {
        item["name"]: item
        for item in result.diagnosis["capability_decision"]["modules"]
    }
    assert modules[failing.spec.name]["execution_status"] == "unrepairable"
    assert modules[failing.spec.name]["dynamic_reasons"] == ["module_returned_unrepairable"]
    assert modules[succeeding.spec.name]["selected"] is True


def test_repair_scheduler_blocks_process_level_failures(tmp_path):
    scheduler = RepairScheduler({"repair": {"workspace": str(tmp_path)}})
    result = scheduler.repair(RepairJob(
        source_input={"kind": "file", "path": str(tmp_path / "broken.zip")},
        format="zip",
        extraction_failure={
            "failure_stage": "worker_start",
            "failure_kind": "process_start",
            "error": "worker missing",
        },
        extraction_diagnostics={
            "process_failure": {"failure_stage": "worker_start", "failure_kind": "process_start"},
        },
        archive_key="broken",
    ))

    assert result.status == "unrepairable"
    assert "outside archive repair scope" in result.message


def test_repair_config_is_normalized_by_config_schema():
    config = normalize_config({
        "recursive_extract": "1",
        "repair": {
            "safety": {"allow_unsafe": True, "allow_partial": "false"},
            "deep": {
                "max_candidates_per_module": "2",
                "max_entries": "12",
                "max_seconds_per_module": "1.5",
                "max_output_size_mb": "64",
                "max_entry_uncompressed_mb": "8",
                "verify_candidates": "false",
            },
            "auto_deep": {
                "enabled": "true",
                "require_verification_repair": "true",
                "max_modules": "1",
                "max_candidates_per_module": "1",
                "max_input_size_mb": "32",
            },
        },
    })

    assert config["repair"]["safety"]["allow_unsafe"] is True
    assert config["repair"]["safety"]["allow_partial"] is False
    assert config["repair"]["deep"]["max_candidates_per_module"] == 2
    assert config["repair"]["deep"]["max_entries"] == 12
    assert config["repair"]["deep"]["max_seconds_per_module"] == 1.5
    assert config["repair"]["deep"]["max_output_size_mb"] == 64.0
    assert config["repair"]["deep"]["max_entry_uncompressed_mb"] == 8.0
    assert config["repair"]["deep"]["verify_candidates"] is False
    assert config["repair"]["auto_deep"]["enabled"] is True
    assert config["repair"]["auto_deep"]["max_modules"] == 1
    assert config["repair"]["auto_deep"]["max_input_size_mb"] == 32.0
    assert config["repair"]["beam"]["enabled"] is True


def test_repair_config_rejects_removed_analysis_repair_settings():
    with pytest.raises(ValueError, match="trigger_on_medium_confidence"):
        normalize_config({"repair": {"trigger_on_medium_confidence": True}})
    with pytest.raises(ValueError, match="repair.thresholds"):
        normalize_config({"repair": {"thresholds": {"medium_confidence_min": 0.1}}})
    with pytest.raises(ValueError, match="trigger_on_extraction_failure"):
        normalize_config({"repair": {"trigger_on_extraction_failure": True}})


def test_zip_central_directory_rebuild_repairs_missing_eocd(tmp_path):
    source = tmp_path / "missing_cd.zip"
    _write_zip(source, {"a.txt": b"alpha", "b.txt": b"bravo"})
    data = source.read_bytes()
    eocd_offset = data.rfind(b"PK\x05\x06")
    cd_offset = struct.unpack_from("<I", data, eocd_offset + 16)[0]
    source.write_bytes(data[:cd_offset])

    result = _run_zip_repair(
        tmp_path,
        "zip_central_directory_rebuild",
        source,
        ["central_directory_bad"],
    )

    assert result.ok is True
    assert result.status == "repaired"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("a.txt") == b"alpha"
        assert archive.read("b.txt") == b"bravo"


def test_zip_partial_recovery_skips_damaged_entry(tmp_path):
    source = tmp_path / "partial.zip"
    _write_zip(source, {"bad.txt": b"broken", "good.txt": b"still here"})
    data = bytearray(source.read_bytes())
    first_lfh = data.find(b"PK\x03\x04")
    data[first_lfh:first_lfh + 4] = b"BAD!"
    source.write_bytes(bytes(data))

    result = _run_zip_repair(
        tmp_path,
        "zip_partial_recovery",
        source,
        ["damaged", "checksum_error"],
    )

    assert result.ok is True
    assert result.status == "partial"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.namelist() == ["good.txt"]
        assert archive.read("good.txt") == b"still here"


def test_zip_data_descriptor_recovery_materializes_sizes(tmp_path):
    source = tmp_path / "descriptor.zip"
    source.write_bytes(_descriptor_zip_fragment("dd.txt", b"descriptor payload"))

    result = _run_zip_repair(
        tmp_path,
        "zip_data_descriptor_recovery",
        source,
        ["data_descriptor", "compressed_size_bad"],
    )

    assert result.ok is True
    assert result.status == "repaired"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("dd.txt") == b"descriptor payload"


def test_zip_data_descriptor_recovery_supports_zip64_descriptor(tmp_path):
    source = tmp_path / "zip64_descriptor.zip"
    source.write_bytes(_descriptor_zip_fragment(
        "zip64-dd.txt",
        b"zip64 descriptor payload",
        zip64=True,
    ))

    result = _run_zip_repair(
        tmp_path,
        "zip_data_descriptor_recovery",
        source,
        ["data_descriptor", "compressed_size_bad"],
    )

    assert result.ok is True
    assert result.status == "repaired"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("zip64-dd.txt") == b"zip64 descriptor payload"


def test_zip_deep_partial_recovery_builds_best_verified_candidate(tmp_path):
    source = tmp_path / "deep_partial.zip"
    source.write_bytes(b"".join([
        _raw_stored_local_entry("good.txt", b"good payload"),
        _raw_stored_local_entry("bad.txt", b"bad payload", crc32=0),
        _raw_deflate_descriptor_entry("dd.txt", b"descriptor payload"),
        b"PK\x01\x02BROKEN-CENTRAL-DIR",
    ]))

    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "stages": {"deep": True},
            "modules": [{"name": "zip_deep_partial_recovery", "enabled": True}],
        }
    })
    result = scheduler.repair(RepairJob(
        source_input={"kind": "file", "path": str(source)},
        format="zip",
        confidence=0.7,
        damage_flags=["damaged", "local_header_recovery", "data_descriptor"],
        archive_key=source.name,
    ))

    assert result.ok is True
    assert result.status == "partial"
    assert result.module_name == "zip_deep_partial_recovery"
    native = result.diagnosis["native_zip_deep_recovery"]
    assert native["selected_candidate"] == "zip_deep_descriptor_recovered"
    assert native["verified_entries"] == 2
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.namelist() == ["good.txt", "dd.txt"]
        assert archive.read("good.txt") == b"good payload"
        assert archive.read("dd.txt") == b"descriptor payload"


def test_zip_eocd_repair_rebuilds_missing_eocd_from_central_directory(tmp_path):
    source = tmp_path / "missing_eocd.zip"
    _write_zip(source, {"payload.txt": b"zip payload"})
    data = source.read_bytes()
    source.write_bytes(data[:data.rfind(b"PK\x05\x06")])

    result = _run_repair(tmp_path, "zip_eocd_repair", "zip", source, ["eocd_bad", "central_directory_bad"])

    assert result.ok is True
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("payload.txt") == b"zip payload"


def test_zip_central_directory_offset_fix_rewrites_bad_eocd_offset(tmp_path):
    source = tmp_path / "bad_cd_offset.zip"
    _write_zip(source, {"payload.txt": b"zip payload"})
    data = bytearray(source.read_bytes())
    eocd_offset = bytes(data).rfind(b"PK\x05\x06")
    struct.pack_into("<I", data, eocd_offset + 16, 0)
    source.write_bytes(bytes(data))

    result = _run_repair(tmp_path, "zip_central_directory_offset_fix", "zip", source, ["central_directory_offset_bad"])

    assert result.ok is True
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("payload.txt") == b"zip payload"


def test_zip_trailing_junk_trim_removes_bytes_after_eocd(tmp_path):
    source = tmp_path / "zip_tail.zip"
    _write_zip(source, {"payload.txt": b"zip payload"})
    original = source.read_bytes()
    source.write_bytes(original + b"JUNK")

    result = _run_repair(tmp_path, "zip_trailing_junk_trim", "zip", source, ["trailing_junk"])

    assert result.ok is True
    assert result.repaired_input["path"]
    assert len(open(result.repaired_input["path"], "rb").read()) == len(original)


def test_zip_comment_length_fix_patches_oversized_comment_length(tmp_path):
    source = tmp_path / "bad_comment_len.zip"
    _write_zip(source, {"payload.txt": b"zip payload"})
    data = bytearray(source.read_bytes())
    eocd_offset = bytes(data).rfind(b"PK\x05\x06")
    struct.pack_into("<H", data, eocd_offset + 20, 12)
    source.write_bytes(bytes(data))

    result = _run_repair(tmp_path, "zip_comment_length_fix", "zip", source, ["comment_length_bad"])

    assert result.ok is True
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("payload.txt") == b"zip payload"


def test_zip_central_directory_count_fix_patches_bad_counts(tmp_path):
    source = tmp_path / "bad_count.zip"
    _write_zip(source, {"a.txt": b"a", "b.txt": b"b"})
    data = bytearray(source.read_bytes())
    eocd_offset = bytes(data).rfind(b"PK\x05\x06")
    struct.pack_into("<HH", data, eocd_offset + 8, 1, 1)
    source.write_bytes(bytes(data))

    result = _run_repair(tmp_path, "zip_central_directory_count_fix", "zip", source, ["central_directory_count_bad"])

    assert result.ok is True
    repaired = open(result.repaired_input["path"], "rb").read()
    repaired_eocd = repaired.rfind(b"PK\x05\x06")
    assert struct.unpack_from("<HH", repaired, repaired_eocd + 8) == (2, 2)
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("a.txt") == b"a"
        assert archive.read("b.txt") == b"b"


def test_tar_header_checksum_fix_rewrites_bad_checksum(tmp_path):
    source = tmp_path / "bad_checksum.tar"
    source.write_bytes(_tar_bytes({"payload.txt": b"tar payload"}))
    data = bytearray(source.read_bytes())
    data[148:156] = b"000000\0 "
    source.write_bytes(bytes(data))

    result = _run_repair(tmp_path, "tar_header_checksum_fix", "tar", source, ["tar_checksum_bad"])

    assert result.ok is True
    with tarfile.open(result.repaired_input["path"]) as archive:
        assert archive.extractfile("payload.txt").read() == b"tar payload"


def test_tar_trailing_zero_block_repair_appends_missing_end_blocks(tmp_path):
    source = tmp_path / "missing_zeros.tar"
    full = _tar_bytes({"payload.txt": b"tar payload"})
    source.write_bytes(full[:1024])

    result = _run_repair(tmp_path, "tar_trailing_zero_block_repair", "tar", source, ["missing_end_block"])

    assert result.ok is True
    with tarfile.open(result.repaired_input["path"]) as archive:
        assert archive.extractfile("payload.txt").read() == b"tar payload"


def test_tar_trailing_junk_trim_removes_bytes_after_zero_blocks(tmp_path):
    source = tmp_path / "tar_tail.tar"
    original = _tar_bytes({"payload.txt": b"tar payload"})
    source.write_bytes(original + b"JUNK")

    result = _run_repair(tmp_path, "tar_trailing_junk_trim", "tar", source, ["trailing_junk"])

    assert result.ok is True
    repaired = open(result.repaired_input["path"], "rb").read()
    assert repaired == original[:len(repaired)]
    assert not repaired.endswith(b"JUNK")
    with tarfile.open(result.repaired_input["path"]) as archive:
        assert archive.extractfile("payload.txt").read() == b"tar payload"


def test_gzip_footer_fix_rewrites_crc_and_isize(tmp_path):
    source = tmp_path / "bad_footer.gz"
    data = bytearray(gzip.compress(b"gzip payload"))
    data[-8:] = b"\0" * 8
    source.write_bytes(bytes(data))

    result = _run_repair(tmp_path, "gzip_footer_fix", "gzip", source, ["gzip_footer_bad"])

    assert result.ok is True
    assert gzip.decompress(open(result.repaired_input["path"], "rb").read()) == b"gzip payload"


def test_gzip_trailing_junk_trim_removes_bytes_after_stream(tmp_path):
    source = tmp_path / "gzip_tail.gz"
    original = gzip.compress(b"gzip payload")
    source.write_bytes(original + b"JUNK")

    result = _run_repair(tmp_path, "gzip_trailing_junk_trim", "gzip", source, ["trailing_junk"])

    assert result.ok is True
    assert open(result.repaired_input["path"], "rb").read() == original
    assert gzip.decompress(open(result.repaired_input["path"], "rb").read()) == b"gzip payload"


def test_bzip2_trailing_junk_trim_removes_bytes_after_stream(tmp_path):
    source = tmp_path / "bzip2_tail.bz2"
    original = bz2.compress(b"bzip2 payload")
    source.write_bytes(original + b"JUNK")

    result = _run_repair(tmp_path, "bzip2_trailing_junk_trim", "bzip2", source, ["trailing_junk"])

    assert result.ok is True
    assert open(result.repaired_input["path"], "rb").read() == original
    assert bz2.decompress(open(result.repaired_input["path"], "rb").read()) == b"bzip2 payload"


def test_gzip_truncated_partial_recovery_recompresses_prefix(tmp_path):
    payload = _pseudo_random_payload(512 * 1024)
    source = tmp_path / "truncated.gz"
    data = gzip.compress(payload)
    source.write_bytes(data[:len(data) * 9 // 10])

    result = _run_stream_partial_repair(tmp_path, "gzip_truncated_partial_recovery", "gzip", source)

    assert result.ok is True
    recovered = gzip.decompress(open(result.repaired_input["path"], "rb").read())
    assert payload.startswith(recovered)
    assert 0 < len(recovered) < len(payload)


def test_bzip2_truncated_partial_recovery_recompresses_prefix(tmp_path):
    payload = _pseudo_random_payload(2 * 1024 * 1024)
    source = tmp_path / "truncated.bz2"
    data = bz2.compress(payload)
    source.write_bytes(data[:len(data) * 9 // 10])

    result = _run_stream_partial_repair(tmp_path, "bzip2_truncated_partial_recovery", "bzip2", source)

    assert result.ok is True
    recovered = bz2.decompress(open(result.repaired_input["path"], "rb").read())
    assert payload.startswith(recovered)
    assert 0 < len(recovered) < len(payload)


def test_xz_trailing_junk_trim_removes_bytes_after_stream(tmp_path):
    source = tmp_path / "tail.xz"
    original = lzma.compress(b"xz payload", format=lzma.FORMAT_XZ)
    source.write_bytes(original + b"JUNK")

    result = _run_repair(tmp_path, "xz_trailing_junk_trim", "xz", source, ["trailing_junk"])

    assert result.ok is True
    assert open(result.repaired_input["path"], "rb").read() == original


def test_xz_truncated_partial_recovery_recompresses_prefix(tmp_path):
    payload = _pseudo_random_payload(1024 * 1024)
    source = tmp_path / "truncated.xz"
    data = lzma.compress(payload, format=lzma.FORMAT_XZ)
    source.write_bytes(data[:len(data) * 9 // 10])

    result = _run_stream_partial_repair(tmp_path, "xz_truncated_partial_recovery", "xz", source)

    assert result.ok is True
    recovered = lzma.decompress(open(result.repaired_input["path"], "rb").read())
    assert payload.startswith(recovered)
    assert 0 < len(recovered) < len(payload)


def test_zstd_trailing_junk_trim_removes_bytes_after_stream_when_backend_available(tmp_path):
    zstd = pytest.importorskip("zstandard")
    source = tmp_path / "tail.zst"
    original = zstd.ZstdCompressor().compress(b"zstd payload")
    source.write_bytes(original + b"JUNK")

    result = _run_repair(tmp_path, "zstd_trailing_junk_trim", "zstd", source, ["trailing_junk"])

    assert result.ok is True
    assert open(result.repaired_input["path"], "rb").read() == original


def test_zstd_truncated_partial_recovery_recompresses_prefix_when_backend_available(tmp_path):
    zstd = pytest.importorskip("zstandard")
    payload = _pseudo_random_payload(4 * 1024 * 1024)
    source = tmp_path / "truncated.zst"
    data = zstd.ZstdCompressor().compress(payload)
    source.write_bytes(data[:len(data) * 9 // 10])

    result = _run_stream_partial_repair(tmp_path, "zstd_truncated_partial_recovery", "zstd", source)

    assert result.ok is True
    recovered = _zstd_decompress_all(zstd, open(result.repaired_input["path"], "rb").read())
    assert payload.startswith(recovered)
    assert 0 < len(recovered) < len(payload)


def test_tar_gzip_truncated_partial_recovery_repairs_inner_tar(tmp_path):
    source = tmp_path / "truncated.tar.gz"
    tar_prefix = _partial_tar_prefix()
    data = gzip.compress(tar_prefix)
    source.write_bytes(data[:-8])

    result = _run_stream_partial_repair(tmp_path, "tar_gzip_truncated_partial_recovery", "tar.gz", source)

    assert result.ok is True
    assert result.repaired_input["format_hint"] == "tar.gz"
    with tarfile.open(result.repaired_input["path"], mode="r:gz") as archive:
        assert archive.getnames() == ["first.bin"]
        assert archive.extractfile("first.bin").read() == b"first payload"
    native = result.diagnosis["native_tar_compressed_partial_recovery"]
    assert native["members"] == 1
    assert native["truncated_members"] == 1


def test_tar_xz_truncated_partial_recovery_repairs_inner_tar(tmp_path):
    source = tmp_path / "truncated.tar.xz"
    tar_prefix = _partial_tar_prefix()
    data = lzma.compress(tar_prefix, format=lzma.FORMAT_XZ)
    source.write_bytes(data[:-12])

    result = _run_stream_partial_repair(tmp_path, "tar_xz_truncated_partial_recovery", "tar.xz", source)

    assert result.ok is True
    assert result.repaired_input["format_hint"] == "tar.xz"
    with tarfile.open(result.repaired_input["path"], mode="r:xz") as archive:
        assert archive.getnames() == ["first.bin"]
        assert archive.extractfile("first.bin").read() == b"first payload"


def test_tar_zstd_partial_recovery_repairs_inner_tar_when_backend_available(tmp_path):
    zstd = pytest.importorskip("zstandard")
    source = tmp_path / "partial.tar.zst"
    tar_prefix = _partial_tar_prefix()
    source.write_bytes(zstd.ZstdCompressor().compress(tar_prefix))

    result = _run_stream_partial_repair(tmp_path, "tar_zstd_truncated_partial_recovery", "tar.zst", source)

    assert result.ok is True
    assert result.repaired_input["format_hint"] == "tar.zst"
    decoded = _zstd_decompress_all(zstd, open(result.repaired_input["path"], "rb").read())
    with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:") as archive:
        assert archive.getnames() == ["first.bin"]
        assert archive.extractfile("first.bin").read() == b"first payload"


def test_seven_zip_boundary_trim_removes_bytes_after_next_header(tmp_path):
    source = tmp_path / "tail.7z"
    original = _seven_zip_bytes()
    source.write_bytes(original + b"JUNK")

    result = _run_repair(tmp_path, "seven_zip_boundary_trim", "7z", source, ["trailing_junk"])

    assert result.ok is True
    assert open(result.repaired_input["path"], "rb").read() == original


def test_seven_zip_start_header_crc_fix_rewrites_bad_crc(tmp_path):
    source = tmp_path / "bad_start_crc.7z"
    data = bytearray(_seven_zip_bytes())
    data[8:12] = b"\0\0\0\0"
    source.write_bytes(bytes(data))

    result = _run_repair(tmp_path, "seven_zip_start_header_crc_fix", "7z", source, ["start_header_crc_bad"])

    assert result.ok is True
    assert open(result.repaired_input["path"], "rb").read() == _seven_zip_bytes()


def test_archive_carrier_crop_deep_recovery_crops_embedded_7z(tmp_path):
    source = tmp_path / "carrier.bin"
    original = _seven_zip_bytes()
    source.write_bytes(b"JPEGDATA" + original)

    result = _run_deep_repair(
        tmp_path,
        "archive_carrier_crop_deep_recovery",
        "7z",
        source,
        ["carrier_archive", "boundary_unreliable"],
    )

    assert result.ok is True
    assert result.module_name == "archive_carrier_crop_deep_recovery"
    assert result.repaired_input["format_hint"] == "7z"
    assert open(result.repaired_input["path"], "rb").read() == original
    assert result.diagnosis["native_archive_deep_repair"]["offset"] == 8


def test_archive_carrier_crop_deep_recovery_crops_embedded_rar(tmp_path):
    source = tmp_path / "carrier-rar.bin"
    original = _rar4_bytes()
    source.write_bytes(b"GIF89a-data" + original)

    result = _run_deep_repair(
        tmp_path,
        "archive_carrier_crop_deep_recovery",
        "rar",
        source,
        ["carrier_archive", "boundary_unreliable"],
    )

    assert result.ok is True
    assert result.repaired_input["format_hint"] == "rar"
    assert open(result.repaired_input["path"], "rb").read() == original


def test_rar_carrier_crop_deep_recovery_crops_embedded_rar(tmp_path):
    source = tmp_path / "carrier-rar-dedicated.bin"
    original = _rar4_bytes()
    source.write_bytes(b"MZ-stub" + original)

    result = _run_deep_repair(
        tmp_path,
        "rar_carrier_crop_deep_recovery",
        "rar",
        source,
        ["sfx", "carrier_archive", "boundary_unreliable"],
    )

    assert result.ok is True
    assert result.module_name == "rar_carrier_crop_deep_recovery"
    assert result.repaired_input["format_hint"] == "rar"
    assert open(result.repaired_input["path"], "rb").read() == original


def test_seven_zip_precise_boundary_repair_trims_carrier_and_tail(tmp_path):
    source = tmp_path / "carrier-tail.7z"
    original = _seven_zip_bytes()
    source.write_bytes(b"SFX" + original + b"JUNK")

    result = _run_deep_repair(
        tmp_path,
        "seven_zip_precise_boundary_repair",
        "7z",
        source,
        ["carrier_archive", "trailing_junk", "boundary_unreliable"],
    )

    assert result.ok is True
    assert result.module_name == "seven_zip_precise_boundary_repair"
    assert open(result.repaired_input["path"], "rb").read() == original
    assert result.diagnosis["native_archive_deep_repair"]["offset"] == 3
    assert result.actions == ["crop_7z_to_precise_next_header_boundary"]


def test_seven_zip_crc_field_repair_rewrites_next_header_and_start_crc(tmp_path):
    source = tmp_path / "bad-next-crc.7z"
    original = _seven_zip_bytes()
    data = bytearray(original)
    data[8:12] = b"\0\0\0\0"
    data[28:32] = b"\0\0\0\0"
    source.write_bytes(bytes(data))

    result = _run_deep_repair(
        tmp_path,
        "seven_zip_crc_field_repair",
        "7z",
        source,
        ["next_header_crc_bad", "start_header_crc_bad"],
    )

    assert result.ok is True
    assert result.module_name == "seven_zip_crc_field_repair"
    assert open(result.repaired_input["path"], "rb").read() == original
    assert result.actions == ["recompute_7z_next_header_crc", "recompute_7z_start_header_crc"]


def test_rar_trailing_junk_trim_supports_rar4(tmp_path):
    source = tmp_path / "tail4.rar"
    original = _rar4_bytes()
    source.write_bytes(original + b"JUNK")

    result = _run_repair(tmp_path, "rar_trailing_junk_trim", "rar", source, ["trailing_junk"])

    assert result.ok is True
    assert open(result.repaired_input["path"], "rb").read() == original


def test_rar_trailing_junk_trim_supports_rar5(tmp_path):
    source = tmp_path / "tail5.rar"
    original = _rar5_bytes()
    source.write_bytes(original + b"JUNK")

    result = _run_repair(tmp_path, "rar_trailing_junk_trim", "rar", source, ["trailing_junk"])

    assert result.ok is True
    assert open(result.repaired_input["path"], "rb").read() == original


def test_rar_block_chain_trim_deep_trims_rar4_tail(tmp_path):
    source = tmp_path / "deep-tail4.rar"
    original = _rar4_bytes()
    source.write_bytes(b"SFX" + original + b"JUNK")

    result = _run_deep_repair(
        tmp_path,
        "rar_block_chain_trim",
        "rar",
        source,
        ["trailing_junk", "boundary_unreliable"],
    )

    assert result.ok is True
    assert result.module_name == "rar_block_chain_trim"
    assert open(result.repaired_input["path"], "rb").read() == original
    assert result.actions == ["walk_rar4_block_chain_trim_boundary"]


def test_rar_block_chain_trim_deep_trims_rar5_tail(tmp_path):
    source = tmp_path / "deep-tail5.rar"
    original = _rar5_bytes()
    source.write_bytes(original + b"JUNK")

    result = _run_deep_repair(
        tmp_path,
        "rar_block_chain_trim",
        "rar",
        source,
        ["trailing_junk", "boundary_unreliable"],
    )

    assert result.ok is True
    assert open(result.repaired_input["path"], "rb").read() == original
    assert result.actions == ["walk_rar5_block_chain_trim_boundary"]


def test_rar_end_block_repair_appends_rar4_end_block(tmp_path):
    source = tmp_path / "missing-end4.rar"
    without_end = RAR4_MAGIC + _rar4_block(0x73) + _rar4_block(0x74, flags=0x8000, payload=b"payload")
    expected = without_end + _rar4_block(0x7B)
    source.write_bytes(without_end)

    result = _run_deep_repair(
        tmp_path,
        "rar_end_block_repair",
        "rar",
        source,
        ["missing_end_block", "probably_truncated"],
    )

    assert result.ok is True
    assert result.module_name == "rar_end_block_repair"
    assert open(result.repaired_input["path"], "rb").read() == expected
    assert result.actions == ["append_rar4_end_block"]


def test_rar_end_block_repair_appends_rar5_end_block(tmp_path):
    source = tmp_path / "missing-end5.rar"
    without_end = RAR5_MAGIC + _rar5_block(1) + _rar5_block(2, data=b"payload")
    expected = without_end + _rar5_block(5)
    source.write_bytes(without_end)

    result = _run_deep_repair(
        tmp_path,
        "rar_end_block_repair",
        "rar",
        source,
        ["missing_end_block", "probably_truncated"],
    )

    assert result.ok is True
    assert open(result.repaired_input["path"], "rb").read() == expected
    assert result.actions == ["append_rar5_end_block"]


@dataclass
class _DummyBoundaryModule:
    spec = RepairModuleSpec(
        name="dummy_zip_boundary",
        formats=("zip",),
        categories=("boundary_repair",),
    )

    def can_handle(self, job, diagnosis, config):
        return 1.0 if "boundary_repair" in diagnosis.categories else 0.0

    def repair(self, job, diagnosis, workspace, config):
        return RepairResult(
            status="repaired",
            confidence=0.9,
            format=diagnosis.format,
            repaired_input={**job.source_input, "end": 100},
            actions=["dummy_boundary_trim"],
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
            workspace_paths=[workspace],
        )


@dataclass
class _DummyNamedBoundaryModule:
    name: str

    @property
    def spec(self):
        return RepairModuleSpec(
            name=self.name,
            formats=("zip",),
            categories=("boundary_repair",),
        )

    def can_handle(self, job, diagnosis, config):
        return 1.0 if "boundary_repair" in diagnosis.categories else 0.0

    def repair(self, job, diagnosis, workspace, config):
        return _dummy_result(self.spec.name, job, diagnosis, workspace)


@dataclass
class _DummyFailingBoundaryModule:
    spec = RepairModuleSpec(
        name="a_failing_boundary",
        formats=("zip",),
        categories=("boundary_repair",),
    )

    def can_handle(self, job, diagnosis, config):
        return 1.0 if "boundary_repair" in diagnosis.categories else 0.0

    def repair(self, job, diagnosis, workspace, config):
        return RepairResult(
            status="unrepairable",
            confidence=0.2,
            format=diagnosis.format,
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
            warnings=["dummy failure"],
            message="dummy module failed",
        )


@dataclass
class _DummyUnsafeModule:
    spec = RepairModuleSpec(
        name="dummy_unsafe_boundary",
        formats=("zip",),
        categories=("boundary_repair",),
        safe=False,
    )

    def can_handle(self, job, diagnosis, config):
        return 1.0 if "boundary_repair" in diagnosis.categories else 0.0

    def repair(self, job, diagnosis, workspace, config):
        return _dummy_result(self.spec.name, job, diagnosis, workspace)


@dataclass
class _DummyPartialModule:
    spec = RepairModuleSpec(
        name="dummy_partial_boundary",
        formats=("zip",),
        categories=("boundary_repair",),
        partial=True,
    )

    def can_handle(self, job, diagnosis, config):
        return 1.0 if "boundary_repair" in diagnosis.categories else 0.0

    def repair(self, job, diagnosis, workspace, config):
        return _dummy_result(self.spec.name, job, diagnosis, workspace, status="partial")


@dataclass
class _DummyRejectedBoundaryModule:
    spec = RepairModuleSpec(
        name="dummy_rejected_boundary",
        formats=("zip",),
        categories=("boundary_repair",),
    )

    def can_handle(self, job, diagnosis, config):
        return 1.0 if "boundary_repair" in diagnosis.categories else 0.0

    def generate_candidates(self, job, diagnosis, workspace, config):
        return [
            RepairCandidate(
                module_name=self.spec.name,
                format=diagnosis.format,
                repaired_input={**job.source_input, "end": 100},
                confidence=0.9,
                actions=["rejected_boundary"],
                validations=[
                    CandidateValidation(
                        name="dummy_rejection",
                        accepted=False,
                        score=0.0,
                        warnings=["candidate rejected"],
                    )
                ],
            )
        ]


@dataclass
class _DummyDeepModule:
    spec = RepairModuleSpec(
        name="dummy_deep_boundary",
        formats=("zip",),
        categories=("boundary_repair",),
        stage="deep",
    )

    def can_handle(self, job, diagnosis, config):
        return 1.0 if "boundary_repair" in diagnosis.categories else 0.0

    def repair(self, job, diagnosis, workspace, config):
        return _dummy_result(
            self.spec.name,
            job,
            diagnosis,
            workspace,
            actions=[f"deep_candidates={config['deep']['max_candidates_per_module']}"],
        )


@dataclass
class _DummyGeneratedCandidatesModule:
    spec = RepairModuleSpec(
        name="dummy_generated_candidates",
        formats=("zip",),
        categories=("boundary_repair",),
        stage="deep",
    )

    def can_handle(self, job, diagnosis, config):
        return 1.0 if "boundary_repair" in diagnosis.categories else 0.0

    def repair(self, job, diagnosis, workspace, config):
        return RepairResult(status="unrepairable", format=diagnosis.format, module_name=self.spec.name)

    def generate_candidates(self, job, diagnosis, workspace, config):
        return [
            RepairCandidate(
                module_name=self.spec.name,
                format="zip",
                repaired_input={"kind": "file", "path": str(job.source_input.get("path")), "format_hint": "zip"},
                stage="deep",
                confidence=0.2,
                actions=["generated_low"],
                validations=[CandidateValidation(name="dummy", accepted=True, score=0.2)],
            ),
            RepairCandidate(
                module_name=self.spec.name,
                format="zip",
                repaired_input={"kind": "file", "path": str(job.source_input.get("path")), "format_hint": "zip"},
                stage="deep",
                confidence=0.95,
                actions=["generated_best"],
                validations=[CandidateValidation(name="dummy", accepted=True, score=0.95)],
            ),
        ]


class _FakePasswordAwareNativeTester:
    def __init__(self):
        self.test_passwords = []
        self.resource_passwords = []

    def probe_archive(self, path):
        return SimpleNamespace(
            status=0,
            is_archive=True,
            is_encrypted=True,
            is_broken=False,
            checksum_error=False,
            offset=0,
            item_count=2,
            archive_type="zip",
            message="ok",
        )

    def test_archive(self, path, password=""):
        self.test_passwords.append(password)
        ok = password == "secret"
        return SimpleNamespace(
            status=0 if ok else 1,
            ok=ok,
            command_ok=ok,
            encrypted=True,
            checksum_error=False,
            archive_type="zip",
            message="ok" if ok else "wrong password",
        )

    def analyze_archive_resources(self, path, password=""):
        self.resource_passwords.append(password)
        return SimpleNamespace(
            status=0,
            ok=True,
            is_archive=True,
            is_encrypted=True,
            is_broken=False,
            archive_type="zip",
            item_count=2,
            file_count=2,
            total_unpacked_size=12,
            total_packed_size=8,
            message="ok",
        )


class _MatrixPasswordNativeTester:
    def probe_archive(self, path):
        return SimpleNamespace(
            status=0,
            is_archive=True,
            is_encrypted=True,
            is_broken=False,
            checksum_error=False,
            offset=0,
            item_count=2,
            archive_type=Path(path).suffix.lstrip(".") or "zip",
            message="ok",
        )

    def test_archive(self, path, password=""):
        ok = password == "secret" and "payload_bad" not in Path(path).name
        payload = password == "secret" and "payload_bad" in Path(path).name
        return SimpleNamespace(
            status=0 if ok else 1,
            ok=ok,
            command_ok=ok,
            encrypted=True,
            checksum_error=payload,
            archive_type=Path(path).suffix.lstrip(".") or "zip",
            message="ok" if ok else ("payload checksum error" if payload else "wrong password"),
        )

    def analyze_archive_resources(self, path, password=""):
        ok = password == "secret"
        return SimpleNamespace(
            status=0 if ok else 1,
            ok=ok,
            is_archive=True,
            is_encrypted=True,
            is_broken=False,
            archive_type=Path(path).suffix.lstrip(".") or "zip",
            item_count=2,
            file_count=2,
            total_unpacked_size=24,
            total_packed_size=16,
            message="ok" if ok else "wrong password",
        )


@dataclass
class _DummyFuzzyRouteModule:
    spec = RepairModuleSpec(
        name="dummy_fuzzy_route",
        formats=("zip",),
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_fuzzy_hints=("carrier_prefix_likely",),
                base_score=0.8,
            ),
        ),
    )

    def can_handle(self, job, diagnosis, config):
        return 0.0

    def repair(self, job, diagnosis, workspace, config):
        return _dummy_result(self.spec.name, job, diagnosis, workspace)


@dataclass
class _DummyTrailingOnlyRouteModule:
    spec = RepairModuleSpec(
        name="dummy_trailing_only_route",
        formats=("zip",),
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_flags=("trailing_junk",),
                base_score=0.8,
            ),
        ),
    )

    def can_handle(self, job, diagnosis, config):
        return 0.0

    def repair(self, job, diagnosis, workspace, config):
        return _dummy_result(self.spec.name, job, diagnosis, workspace)


def _dummy_result(module_name, job, diagnosis, workspace, *, status="repaired", actions=None):
    return RepairResult(
        status=status,
        confidence=0.9,
        format=diagnosis.format,
        repaired_input={**job.source_input, "end": 100},
        actions=list(actions or ["dummy_boundary_trim"]),
        module_name=module_name,
        diagnosis=diagnosis.as_dict(),
        workspace_paths=[workspace],
    )


def _run_dummy_repair(tmp_path, module, config=None, *, source=None, extraction_failure=None):
    registry = get_repair_module_registry()
    registry.register(module)
    repair_config = {
        "workspace": str(tmp_path / "repair"),
        "modules": [{"name": module.spec.name, "enabled": True}],
    }
    if config:
        _deep_merge(repair_config, config)
    scheduler = RepairScheduler({"repair": repair_config})
    source_input = (
        {"kind": "file", "path": str(source)}
        if source is not None
        else {"kind": "file_range", "path": "mixed.bin", "start": 10}
    )
    return scheduler.repair(RepairJob(
        source_input=source_input,
        format="zip",
        confidence=0.8,
        damage_flags=["boundary_unreliable"],
        archive_key="sample",
        extraction_failure=extraction_failure or {},
    ))


def _run_zip_repair(tmp_path, module_name, source, flags):
    return _run_repair(tmp_path, module_name, "zip", source, flags)


def _run_repair(tmp_path, module_name, fmt, source, flags):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [{"name": module_name, "enabled": True}],
        }
    })
    return scheduler.repair(RepairJob(
        source_input={"kind": "file", "path": str(source)},
        format=fmt,
        confidence=0.7,
        damage_flags=flags,
        archive_key=source.name,
    ))


def _run_stream_partial_repair(tmp_path, module_name, fmt, source):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "stages": {"deep": True},
            "modules": [{"name": module_name, "enabled": True}],
        }
    })
    return scheduler.repair(RepairJob(
        source_input={"kind": "file", "path": str(source)},
        format=fmt,
        confidence=0.7,
        damage_flags=["stream_truncated", "unexpected_end"],
        archive_key=source.name,
    ))


def _run_deep_repair(tmp_path, module_name, fmt, source, flags):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "stages": {"deep": True},
            "deep": {"verify_candidates": False},
            "modules": [{"name": module_name, "enabled": True}],
        }
    })
    return scheduler.repair(RepairJob(
        source_input={"kind": "file", "path": str(source)},
        format=fmt,
        confidence=0.7,
        damage_flags=flags,
        archive_key=source.name,
    ))


def _deep_merge(target, source):
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_merge(target[key], value)
        else:
            target[key] = value


def _write_zip(path, files):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in files.items():
            archive.writestr(name, payload)


def _tar_bytes(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def _partial_tar_prefix():
    first = _tar_member("first.bin", b"first payload")
    second = _tar_member("second.bin", _pseudo_random_payload(64 * 1024))
    return first + second[:512 + 128]


def _tar_member(name: str, payload: bytes) -> bytes:
    encoded_name = name.encode("utf-8")
    header = bytearray(512)
    header[:len(encoded_name)] = encoded_name
    header[100:108] = _tar_octal(0o644, 8)
    header[108:116] = _tar_octal(0, 8)
    header[116:124] = _tar_octal(0, 8)
    header[124:136] = _tar_octal(len(payload), 12)
    header[136:148] = _tar_octal(0, 12)
    header[148:156] = b" " * 8
    header[156] = ord("0")
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    checksum = sum(header)
    header[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    padding = b"\0" * ((512 - (len(payload) % 512)) % 512)
    return bytes(header) + payload + padding


def _tar_octal(value: int, length: int) -> bytes:
    return f"{value:0{length - 1}o}\0".encode("ascii")


def _descriptor_zip_fragment(name: str, payload: bytes, *, zip64: bool = False) -> bytes:
    encoded_name = name.encode("utf-8")
    crc32 = zlib.crc32(payload) & 0xFFFFFFFF
    compressed_size = 0xFFFFFFFF if zip64 else 0
    uncompressed_size = 0xFFFFFFFF if zip64 else 0
    descriptor = (
        struct.pack("<IIQQ", 0x08074B50, crc32, len(payload), len(payload))
        if zip64
        else struct.pack("<IIII", 0x08074B50, crc32, len(payload), len(payload))
    )
    return b"".join([
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0x08,
            0,
            0,
            0,
            0,
            compressed_size,
            uncompressed_size,
            len(encoded_name),
            0,
        ),
        encoded_name,
        payload,
        descriptor,
        b"PK\x01\x02BROKEN-CENTRAL-DIR",
    ])


def _raw_stored_local_entry(name: str, payload: bytes, *, crc32: int | None = None) -> bytes:
    encoded_name = name.encode("utf-8")
    crc = zlib.crc32(payload) & 0xFFFFFFFF if crc32 is None else crc32
    return b"".join([
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(payload),
            len(payload),
            len(encoded_name),
            0,
        ),
        encoded_name,
        payload,
    ])


def _raw_deflate_descriptor_entry(name: str, payload: bytes) -> bytes:
    encoded_name = name.encode("utf-8")
    compressor = zlib.compressobj(level=6, wbits=-15)
    compressed = compressor.compress(payload) + compressor.flush()
    crc32 = zlib.crc32(payload) & 0xFFFFFFFF
    return b"".join([
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0x08,
            8,
            0,
            0,
            0,
            0,
            0,
            len(encoded_name),
            0,
        ),
        encoded_name,
        compressed,
        struct.pack("<IIII", 0x08074B50, crc32, len(compressed), len(payload)),
    ])


def _pseudo_random_payload(size: int) -> bytes:
    value = 0x12345678
    output = bytearray()
    for _ in range(size):
        value ^= (value << 13) & 0xFFFFFFFF
        value ^= value >> 17
        value ^= (value << 5) & 0xFFFFFFFF
        output.append(value & 0xFF)
    return bytes(output)


def _zstd_decompress_all(zstd, data: bytes) -> bytes:
    with zstd.ZstdDecompressor().stream_reader(io.BytesIO(data)) as reader:
        return reader.read()


def _seven_zip_bytes() -> bytes:
    next_header = b"\x01"
    gap = b"abcde"
    start_header = struct.pack("<QQI", len(gap), len(next_header), zlib.crc32(next_header) & 0xFFFFFFFF)
    return b"7z\xbc\xaf\x27\x1c" + b"\x00\x04" + struct.pack("<I", zlib.crc32(start_header) & 0xFFFFFFFF) + start_header + gap + next_header


def _rar4_block(header_type: int, flags: int = 0, payload: bytes = b"") -> bytes:
    add_size = len(payload).to_bytes(4, "little") if payload else b""
    header_size = 7 + len(add_size)
    body = bytes([header_type]) + flags.to_bytes(2, "little") + header_size.to_bytes(2, "little") + add_size
    header_crc = (zlib.crc32(body) & 0xFFFF).to_bytes(2, "little")
    return header_crc + body + payload


def _rar4_bytes() -> bytes:
    return b"Rar!\x1a\x07\x00" + _rar4_block(0x73) + _rar4_block(0x7B)


def _rar5_vint(value: int) -> bytes:
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            output.append(byte | 0x80)
        else:
            output.append(byte)
            return bytes(output)


def _rar5_block(header_type: int, flags: int = 0, data: bytes = b"") -> bytes:
    fields = _rar5_vint(header_type) + _rar5_vint(flags)
    if data:
        flags |= 0x0002
        fields = _rar5_vint(header_type) + _rar5_vint(flags) + _rar5_vint(len(data))
    header_size = _rar5_vint(len(fields))
    header_data = header_size + fields
    return zlib.crc32(header_data).to_bytes(4, "little") + header_data + data


def _rar5_bytes() -> bytes:
    return b"Rar!\x1a\x07\x01\x00" + _rar5_block(1) + _rar5_block(5)
