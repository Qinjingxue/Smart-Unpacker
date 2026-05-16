from dataclasses import dataclass
import bz2
import gzip
import io
import json
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
from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.repair.config import enabled_module_configs
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.candidate import CandidateSelector, CandidateValidation, RepairCandidate, materialize_candidate
from sunpack.repair import RepairJob, RepairScheduler
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import base_archive_state_for_job, repair_operation_cache_key, source_input_for_job
from sunpack.repair.pipeline.modules.seven_zip._scan import password_fingerprint
from sunpack.repair.pipeline.modules.seven_zip.atomic import SevenZipFixStartHeaderCrc
from sunpack.repair.pipeline.registry import get_repair_module_registry, register_repair_module
from sunpack.repair.result import RepairResult
from sunpack.repair.runtime_cache import RepairRuntimeCache


RAR4_MAGIC = b"Rar!\x1a\x07\x00"
RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"
DEFAULT_SALVAGE_MODULES = {
    "archive_nested_payload_salvage",
    "rar_file_quarantine_rebuild",
    "seven_zip_salvage_solid_prefix",
    "tar_sparse_pax_longname_repair",
    "zip_resolve_duplicate_entries",
}


def _zip_profile_knowledge(profile: str) -> dict:
    knowledge = ArchiveKnowledge()
    knowledge.set("analysis.summary.format", "zip", source_layer="test", source_module="fixture")
    knowledge.set("source.profile", profile, source_layer="test", source_module="fixture")
    return knowledge.to_dict()


class _CountingLazyRepairModule:
    def __init__(self) -> None:
        self.calls = 0
        self.spec = RepairModuleSpec(
            name="test_counting_lazy_cache_module",
            formats=("zip",),
            categories=("directory_rebuild",),
            routes=(RepairRoute(formats=("zip",), require_any_flags=("test_cache_damage",), base_score=0.95),),
        )

    def can_handle(self, job, diagnosis, config):
        return 0.95 if "test_cache_damage" in set(job.damage_flags) else 0.0

    def generate_candidates(self, job, diagnosis, workspace, config):
        self.calls += 1
        return [RepairCandidate(
            module_name=self.spec.name,
            format="zip",
            repaired_input={"kind": "bytes", "data": b"cached", "format_hint": "zip"},
            status="repaired",
            confidence=0.9,
            actions=["test_cached_materialize"],
            damage_flags=list(job.damage_flags),
            diagnosis={"repair_name": self.spec.name},
            message="cached test candidate",
        )]


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


def test_repair_runtime_cache_reuses_same_lazy_materialization(tmp_path):
    module = _CountingLazyRepairModule()
    register_repair_module(module)
    source = tmp_path / "damaged.zip"
    source.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [{"name": module.spec.name, "enabled": True}],
        }
    })
    job = RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "zip"},
        format="zip",
        confidence=0.8,
        damage_flags=["test_cache_damage"],
        archive_key="cache-test.zip",
    )

    batch = scheduler.generate_repair_candidates(job, lazy=True)
    assert len(batch.candidates) == 1
    first = materialize_candidate(batch.candidates[0])
    second = materialize_candidate(batch.candidates[0])

    assert module.calls == 1
    assert first[0].module_name == module.spec.name
    assert second[0].module_name == module.spec.name
    assert scheduler.repair_cache.stats()["by_namespace"]["materialize_candidate"]["hits"] == 1


def test_repair_operation_cache_key_changes_when_file_changes(tmp_path):
    source = tmp_path / "damaged.zip"
    source.write_bytes(b"one")
    job = RepairJob(source_input={"kind": "file", "path": str(source), "format_hint": "zip"}, format="zip")
    first = repair_operation_cache_key(job, "op", {"param": True})

    source.write_bytes(b"two-two")
    second = repair_operation_cache_key(job, "op", {"param": True})

    assert first != second


def test_repair_operation_cache_key_distinguishes_password_fingerprint(tmp_path):
    source = tmp_path / "encrypted.7z"
    source.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\0" * 32)
    job = RepairJob(source_input={"kind": "file", "path": str(source), "format_hint": "7z"}, format="7z")

    first = repair_operation_cache_key(job, "seven_zip_scan_source", {"password_fingerprint": password_fingerprint("alpha")})
    second = repair_operation_cache_key(job, "seven_zip_scan_source", {"password_fingerprint": password_fingerprint("beta")})

    assert first != second
    assert "alpha" not in json.dumps(first)
    assert "beta" not in json.dumps(second)


def test_source_input_for_job_carries_password_for_file_concat_and_patched_state(tmp_path):
    source = tmp_path / "encrypted.7z"
    part = tmp_path / "encrypted.7z.001"
    source.write_bytes(b"tailxxxx")
    part.write_bytes(b"head")

    file_input = source_input_for_job(RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "7z"},
        format="7z",
        password="secret",
    ))
    assert file_input["password"] == "secret"

    concat_input = source_input_for_job(RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "7z", "parts": [{"path": str(part)}]},
        format="7z",
        password="secret",
    ))
    assert concat_input["kind"] == "concat_ranges"
    assert concat_input["password"] == "secret"

    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="7z")
    patched_state = ArchiveState.from_archive_input(
        descriptor,
        patches=[PatchPlan(operations=[PatchOperation.replace_bytes(offset=0, data=b"patched")])],
    )
    patched_input = source_input_for_job(RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "7z"},
        format="7z",
        archive_state=patched_state,
        password="secret",
    ))
    assert patched_input["kind"] == "bytes"
    assert patched_input["password"] == "secret"


def test_source_input_for_job_does_not_reexpand_materialized_logical_stream_parts(tmp_path):
    repaired = tmp_path / "repaired-logical.7z"
    original_part = tmp_path / "original.7z.001"
    repaired.write_bytes(b"repaired")
    original_part.write_bytes(b"original")

    payload = source_input_for_job(RepairJob(
        source_input={
            "kind": "file",
            "path": str(repaired),
            "format_hint": "7z",
            "parts": [{"path": str(original_part)}],
            "use_parts_only": True,
            "logical_stream_built": True,
            "split_sidecars_available": True,
        },
        format="7z",
        password="secret",
        workspace=str(tmp_path / "workspace"),
        repair_cache=RepairRuntimeCache(),
    ))

    assert payload["kind"] == "file"
    assert payload["path"] == str(repaired)
    assert "parts" not in payload
    assert payload["source_parts_metadata"] == [{"path": str(original_part)}]
    assert payload["logical_stream_built"] is True
    assert payload["split_sidecars_available"] is True
    assert payload["password"] == "secret"


def test_base_archive_state_for_job_uses_logical_split_source_instead_of_stale_file_state(tmp_path):
    source = tmp_path / "split.zip"
    part = tmp_path / "split.z01"
    source.write_bytes(b"tail")
    part.write_bytes(b"head")

    stale_file_state = ArchiveState.from_archive_input(ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip"))
    state = base_archive_state_for_job(RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "zip", "parts": [{"path": str(part)}]},
        archive_state=stale_file_state,
        format="zip",
        archive_key="split.zip",
    ))

    assert state.source.open_mode == "concat_ranges"
    assert [item.path for item in state.source.ranges] == [str(part), str(source)]


def test_seven_zip_wrong_password_flags_are_vetoed_only_without_resolved_password():
    module = SevenZipFixStartHeaderCrc()
    job = RepairJob(
        source_input={"kind": "bytes", "data": b"", "format_hint": "7z"},
        format="7z",
        damage_flags=["seven_zip_signature_found", "start_header_crc_bad", "wrong_password", "password_required"],
    )
    assert module.can_handle(job, RepairDiagnosis(format="7z"), {}) == 0.0

    header_fact_only = RepairJob(
        source_input=job.source_input,
        format="7z",
        damage_flags=["seven_zip_signature_found", "start_header_crc_bad", "wrong_password", "encrypted_header_present"],
    )
    assert module.can_handle(header_fact_only, RepairDiagnosis(format="7z"), {}) > 0.0

    unlocked = RepairJob(
        source_input=job.source_input,
        format="7z",
        damage_flags=list(job.damage_flags),
        password="secret",
    )
    assert module.can_handle(unlocked, RepairDiagnosis(format="7z"), {}) > 0.0


def test_repair_runtime_cache_invalidates_missing_materialized_path(tmp_path):
    cache = RepairRuntimeCache()
    produced = tmp_path / "candidate.zip"
    calls = {"count": 0}

    def compute():
        calls["count"] += 1
        produced.write_bytes(f"run-{calls['count']}".encode("ascii"))
        return {"selected_path": str(produced), "workspace_paths": [str(produced)]}

    first = cache.get_or_compute("native_test", {"source": "same"}, compute)
    second = cache.get_or_compute("native_test", {"source": "same"}, compute)
    produced.unlink()
    third = cache.get_or_compute("native_test", {"source": "same"}, compute)

    assert calls["count"] == 2
    assert first == second
    assert third["selected_path"] == str(produced)


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
            "seven_zip_salvage_solid_prefix",
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
                "zip_resolve_duplicate_entries",
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


def test_maximum_repair_prefers_rar_file_quarantine_over_generic_carrier_crop_for_split_damage(tmp_path):
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


def test_repair_scheduler_uses_unified_module_limits_for_all_modules(tmp_path):
    source = tmp_path / "deep.zip"
    source.write_bytes(b"x" * 4096)
    module = _DummyDeepModule()

    size_blocked = _run_dummy_repair(tmp_path, module, {
        "module_limits": {"max_input_size_mb": 0.001},
    }, source=source)
    allowed = _run_dummy_repair(tmp_path, module, {
        "module_limits": {"max_input_size_mb": 1},
        "modules": [
            {
                "name": module.spec.name,
                "enabled": True,
                "module_limits": {"max_candidates_per_module": 2},
            }
        ],
    }, source=source)

    assert size_blocked.status == "unsupported"
    decision = size_blocked.diagnosis["capability_decision"]
    assert decision["modules"][0]["policy_reasons"] == ["module_input_size_blocked"]
    assert allowed.ok is True
    assert allowed.actions == ["module_limit_candidates=2"]


def test_repair_scheduler_runs_all_matching_modules_without_auto_escalation(tmp_path):
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
    assert result.actions == ["module_limit_candidates=3"]
    assert not any("auto_deep" in warning for warning in result.warnings)


def test_repair_scheduler_does_not_require_verification_repair_for_payload_modules(tmp_path):
    source = tmp_path / "auto-deep-fail.zip"
    source.write_bytes(b"x" * 4096)
    module = _DummyDeepModule()

    result = _run_dummy_repair(
        tmp_path,
        module,
        source=source,
        extraction_failure={"failure_stage": "verification", "decision_hint": "fail"},
    )

    assert result.ok is True
    assert result.module_name == module.spec.name


def test_repair_scheduler_module_limits_respect_limited_input_size(tmp_path):
    source = tmp_path / "auto-deep-large.zip"
    source.write_bytes(b"x" * 4096)
    module = _DummyDeepModule()

    result = _run_dummy_repair(
        tmp_path,
        module,
        {"module_limits": {"max_input_size_mb": 0.001}},
        source=source,
        extraction_failure={"failure_stage": "verification", "decision_hint": "repair"},
    )

    assert result.status == "unsupported"
    decision = result.diagnosis["capability_decision"]
    assert decision["modules"][0]["policy_reasons"] == ["module_input_size_blocked"]


def test_repair_scheduler_considers_all_matching_modules_after_candidate_rejection(tmp_path):
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
    assert result.actions == ["module_limit_candidates=3"]
    selected = result.diagnosis["capability_decision"]["selected_modules"]
    assert rejected.spec.name in selected
    assert deep.spec.name in selected


def test_repair_scheduler_selects_best_generated_candidate(tmp_path):
    module = _DummyGeneratedCandidatesModule()
    registry = get_repair_module_registry()
    previous = registry.get(module.spec.name)
    registry.register(module)
    try:
        scheduler = RepairScheduler({
            "repair": {
                "workspace": str(tmp_path / "repair"),
                    "module_limits": {"verify_candidates": False},
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


def test_repair_scheduler_telemetry_writes_compact_ltr_records(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    module = _DummyGeneratedCandidatesModule()
    registry = get_repair_module_registry()
    previous = registry.get(module.spec.name)
    registry.register(module)
    try:
        scheduler = RepairScheduler({
            "repair": {
                "workspace": str(tmp_path / "repair"),
                "telemetry": {"enabled": True},
                    "module_limits": {"verify_candidates": False},
                "modules": [{"name": module.spec.name, "enabled": True}],
            }
        })
        result = scheduler.repair(RepairJob(
            source_input={"kind": "file", "path": str(tmp_path / "source.zip")},
            format="zip",
            confidence=0.7,
            damage_flags=["boundary_unreliable"],
            archive_key="telemetry",
        ))
    finally:
        if previous is not None:
            registry.register(previous)

    target = tmp_path / ".sunpack" / "datasets" / "repair_candidates_runtime_success.jsonl"
    pretty_target = tmp_path / ".sunpack" / "datasets" / "repair_candidates_runtime_success.pretty.json"
    failure_target = tmp_path / ".sunpack" / "datasets" / "repair_candidates_runtime_failure.jsonl"
    failure_pretty_target = tmp_path / ".sunpack" / "datasets" / "repair_candidates_runtime_failure.pretty.json"
    rows = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
    pretty_rows = json.loads(pretty_target.read_text(encoding="utf-8"))
    assert result.ok is True
    assert not failure_target.exists()
    assert not failure_pretty_target.exists()
    assert len(rows) == 2
    assert pretty_rows == rows
    assert {row["source"] for row in rows} == {"runtime.repair.telemetry"}
    assert {row["query_id"] for row in rows} == {"telemetry:0"}
    assert sum(1 for row in rows if row["candidate_selected"]) == 1
    assert sum(1 for row in rows if row["label"] == 2) == 1
    assert all("features" in row and "generation_priority" in row["features"] for row in rows)


def test_repair_scheduler_telemetry_splits_failed_repair_records(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    module = _DummyRejectedBoundaryModule()
    registry = get_repair_module_registry()
    previous = registry.get(module.spec.name)
    registry.register(module)
    try:
        scheduler = RepairScheduler({
            "repair": {
                "workspace": str(tmp_path / "repair"),
                "telemetry": {"enabled": True},
                "modules": [{"name": module.spec.name, "enabled": True}],
            }
        })
        result = scheduler.repair(RepairJob(
            source_input={"kind": "file", "path": str(tmp_path / "source.zip")},
            format="zip",
            confidence=0.7,
            damage_flags=["boundary_unreliable"],
            archive_key="telemetry-failed",
        ))
    finally:
        if previous is not None:
            registry.register(previous)

    success_target = tmp_path / ".sunpack" / "datasets" / "repair_candidates_runtime_success.jsonl"
    success_pretty_target = tmp_path / ".sunpack" / "datasets" / "repair_candidates_runtime_success.pretty.json"
    failure_target = tmp_path / ".sunpack" / "datasets" / "repair_candidates_runtime_failure.jsonl"
    failure_pretty_target = tmp_path / ".sunpack" / "datasets" / "repair_candidates_runtime_failure.pretty.json"
    rows = [json.loads(line) for line in failure_target.read_text(encoding="utf-8").splitlines()]
    pretty_rows = json.loads(failure_pretty_target.read_text(encoding="utf-8"))
    assert result.ok is False
    assert not success_target.exists()
    assert not success_pretty_target.exists()
    assert len(rows) == 1
    assert pretty_rows == rows
    assert rows[0]["source"] == "runtime.repair.telemetry"
    assert rows[0]["query_id"] == "telemetry-failed:0"
    assert rows[0]["result_status"] == "unrepairable"
    assert rows[0]["repair_success"] is False
    assert rows[0]["label"] == 0
    assert rows[0]["features"]["module"] == module.spec.name


def test_repair_scheduler_exposes_generated_candidate_batch(tmp_path):
    module = _DummyGeneratedCandidatesModule()
    registry = get_repair_module_registry()
    previous = registry.get(module.spec.name)
    registry.register(module)
    try:
        scheduler = RepairScheduler({
            "repair": {
                "workspace": str(tmp_path / "repair"),
                    "module_limits": {"verify_candidates": False},
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
                    "module_limits": {"verify_candidates": False},
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
        knowledge={
            "source": {"input": {"kind": "file", "path": str(tmp_path / "broken.zip"), "format_hint": "zip"}},
            "analysis": {"summary": {"format": "zip"}},
            "extraction": {
                "failure": {
                    "failure_stage": "worker_start",
                    "failure_kind": "process_start",
                    "error": "worker missing",
                },
                "diagnostics": {
                    "failure_stage": "worker_start",
                    "failure_kind": "process_start",
                    "process_failure": {"failure_stage": "worker_start", "failure_kind": "process_start"},
                },
            },
        },
        archive_key="broken",
    ))

    assert result.status == "unrepairable"
    assert "outside archive repair scope" in result.message


def test_repair_config_is_normalized_by_config_schema():
    config = normalize_config({
        "recursive_extract": "1",
        "verification": {
            "enabled": True,
            "max_retries": "2",
            "cleanup_failed_output": True,
            "accept_partial_when_source_damaged": True,
            "partial_min_completeness": "0.2",
            "complete_accept_threshold": "0.999",
            "partial_accept_threshold": "0.2",
            "retry_on_verification_failure": True,
            "methods": [],
        },
            "repair": {
                "safety": {"allow_unsafe": True, "allow_partial": "false"},
            "module_limits": {
                "max_candidates_per_module": "2",
                "max_entries": "12",
                "max_seconds_per_module": "1.5",
                "max_output_size_mb": "64",
                "max_entry_uncompressed_mb": "8",
                "verify_candidates": "false",
            },
            "telemetry": {"enabled": "true"},
        },
    })

    assert config["repair"]["safety"]["allow_unsafe"] is True
    assert config["repair"]["safety"]["allow_partial"] is False
    assert config["repair"]["module_limits"]["max_candidates_per_module"] == 2
    assert config["repair"]["module_limits"]["max_entries"] == 12
    assert config["repair"]["module_limits"]["max_seconds_per_module"] == 1.5
    assert config["repair"]["module_limits"]["max_output_size_mb"] == 64.0
    assert config["repair"]["module_limits"]["max_entry_uncompressed_mb"] == 8.0
    assert config["repair"]["module_limits"]["verify_candidates"] is False
    assert config["repair"]["beam"]["enabled"] is True
    assert config["repair"]["telemetry"]["enabled"] is True
    assert config["verification"]["max_retries"] == 2
    assert config["verification"]["partial_min_completeness"] == 0.2
    assert config["verification"]["complete_accept_threshold"] == 0.999


def test_repair_config_rejects_removed_analysis_repair_settings():
    with pytest.raises(ValueError, match="trigger_on_medium_confidence"):
        normalize_config({"repair": {"trigger_on_medium_confidence": True}})
    with pytest.raises(ValueError, match="repair.thresholds"):
        normalize_config({"repair": {"thresholds": {"medium_confidence_min": 0.1}}})
    with pytest.raises(ValueError, match="trigger_on_extraction_failure"):
        normalize_config({"repair": {"trigger_on_extraction_failure": True}})
    with pytest.raises(ValueError, match="repair.deep"):
        normalize_config({"repair": {"deep": {"max_candidates_per_module": 1}}})
    with pytest.raises(ValueError, match="repair.auto_deep"):
        normalize_config({"repair": {"auto_deep": {"enabled": True}}})
    with pytest.raises(ValueError, match="repair.stages"):
        normalize_config({"repair": {"stages": {"deep": True}}})
    with pytest.raises(ValueError, match="repair.max_modules_per_job"):
        normalize_config({"repair": {"max_modules_per_job": 1}})


def test_zip_atomic_zip64_route_requires_specific_zip64_flag(tmp_path):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [{"name": "zip_fix_zip64_locator", "enabled": True}],
        }
    })
    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(tmp_path / "generic.zip")},
        format="zip",
        confidence=0.7,
        damage_flags=["central_directory_bad"],
        archive_key="generic.zip",
    ), lazy=True)

    assert batch.terminal_result is not None
    decision = batch.terminal_result.diagnosis["capability_decision"]
    module = next(item for item in decision["modules"] if item["name"] == "zip_fix_zip64_locator")
    assert module["selected"] is False
    assert "route_required_flags_unmet" in module["reasons"]


def test_zip_atomic_can_handle_zero_vetoes_route_score(tmp_path):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [{"name": "zip_reconcile_cd_data_descriptor_conflict", "enabled": True}],
        }
    })
    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(tmp_path / "descriptor.zip")},
        format="zip",
        confidence=0.7,
        damage_flags=["data_descriptor"],
        archive_key="descriptor.zip",
    ), lazy=True)

    assert batch.terminal_result is not None
    decision = batch.terminal_result.diagnosis["capability_decision"]
    module = next(item for item in decision["modules"] if item["name"] == "zip_reconcile_cd_data_descriptor_conflict")
    assert module["route_score"] > 0.0
    assert module["fine_score"] == 0.0
    assert "can_handle_rejected" in module["reasons"]


def test_zip_sfx_route_prefers_carrier_crop_not_zip_atomic_fields(tmp_path):
    scheduler = RepairScheduler({"repair": {"workspace": str(tmp_path / "repair")}})
    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(tmp_path / "sfx.zip")},
        format="zip",
        confidence=0.7,
        damage_flags=["carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"],
        archive_key="sfx.zip",
    ), lazy=True)

    modules = {candidate.module_name for candidate in batch.candidates}
    assert "archive_carrier_crop_deep_recovery" in modules
    assert "zip_fix_zip64_locator" not in modules
    assert "zip_fix_cd_offset" not in modules
    assert "zip_rebuild_cd_from_data_descriptors" not in modules


def test_zip_missing_volume_route_prefers_partial_salvage(tmp_path):
    scheduler = RepairScheduler({"repair": {"workspace": str(tmp_path / "repair")}})
    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(tmp_path / "split.zip")},
        format="zip",
        confidence=0.7,
        damage_flags=["missing_volume", "input_truncated", "local_header_recovery"],
        archive_key="split.zip",
    ), lazy=True)

    modules = {candidate.module_name for candidate in batch.candidates}
    assert "zip_partial_salvage_missing_volume" in modules
    assert "zip_fix_cd_offset" not in modules
    assert "zip_fix_zip64_eocd" not in modules
    assert "zip_reconcile_cd_local_headers" not in modules


def test_zip_route_evidence_duplicate_entries_selects_atomic_module(tmp_path):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [{"name": "zip_resolve_duplicate_entries", "enabled": True}],
        }
    })
    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(tmp_path / "dup.zip"), "format_hint": "zip"},
        format="zip",
        confidence=0.7,
        damage_flags=["damaged"],
        analysis_prepass={"zip_structure_features": {"has_duplicate_entries": True}},
        archive_key="dup.zip",
    ), lazy=True)

    modules = {candidate.module_name for candidate in batch.candidates}
    assert "zip_resolve_duplicate_entries" in modules
    assert "duplicate_entries" in batch.diagnosis["capability_decision"]["damage_flags"]


def test_zip_route_evidence_raw_filename_selects_preserve_names(tmp_path):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [{"name": "zip_rebuild_cd_preserve_raw_names", "enabled": True}],
        }
    })
    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(tmp_path / "raw.zip"), "format_hint": "zip"},
        format="zip",
        confidence=0.7,
        damage_flags=["damaged"],
        analysis_prepass={"zip_structure_features": {"has_filename_encoding_risk": True}},
        archive_key="raw.zip",
    ), lazy=True)

    assert {candidate.module_name for candidate in batch.candidates} == {"zip_rebuild_cd_preserve_raw_names"}


def test_zip_route_evidence_zip64_extra_profile_selects_extra_repair(tmp_path):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [{"name": "zip_fix_zip64_extra_size", "enabled": True}],
        }
    })
    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(tmp_path / "zip64.zip"), "format_hint": "zip"},
        format="zip",
        confidence=0.7,
        damage_flags=["damaged"],
        analysis_prepass={
            "damage_profile": "zip_zip64_extra_size_mismatch",
            "zip_structure_features": {"has_zip64_extra": True},
        },
        archive_key="zip64.zip",
    ), lazy=True)

    assert {candidate.module_name for candidate in batch.candidates} == {"zip_fix_zip64_extra_size"}


def test_zip_route_evidence_extra_field_length_selects_extra_length_repair(tmp_path):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [
                {"name": "zip_fix_extra_field_length", "enabled": True},
                {"name": "zip_fix_cd_offset", "enabled": True},
            ],
        }
    })
    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(tmp_path / "extra.zip"), "format_hint": "zip"},
        format="zip",
        confidence=0.7,
        damage_flags=["damaged"],
        analysis_prepass={"damage_profile": "zip_extra_field_length_bad"},
        knowledge=_zip_profile_knowledge("zip_extra_field_length_bad"),
        archive_key="extra.zip",
    ), lazy=True)

    modules = {candidate.module_name for candidate in batch.candidates}
    assert "zip_fix_extra_field_length" in modules
    assert "zip_fix_cd_offset" not in modules


def test_zip_compound_extra_payload_profile_keeps_extra_field_repair_route(tmp_path):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [
                {"name": "zip_fix_extra_field_length", "enabled": True},
                {"name": "zip_fix_cd_offset", "enabled": True},
                {"name": "zip_rebuild_cd_from_local_headers", "enabled": True},
            ],
        }
    })
    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(tmp_path / "compound.zip"), "format_hint": "zip"},
        format="zip",
        confidence=0.7,
        damage_flags=["central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad", "checksum_error", "crc_error"],
        analysis_prepass={"damage_profile": "compound_extra_field_cd_offset_payload_bad"},
        knowledge=_zip_profile_knowledge("compound_extra_field_cd_offset_payload_bad"),
        archive_key="compound.zip",
    ), lazy=True)

    modules = {candidate.module_name for candidate in batch.candidates}
    assert "zip_fix_extra_field_length" in modules
    assert "payload_hash_mismatch" in batch.diagnosis["capability_decision"]["damage_flags"]


def test_zip_route_evidence_sfx_prefers_carrier_crop_from_structure(tmp_path):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [
                {"name": "archive_carrier_crop_deep_recovery", "enabled": True},
                {"name": "zip_fix_cd_offset", "enabled": True},
            ],
        }
    })
    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(tmp_path / "sfx.zip"), "format_hint": "zip"},
        format="zip",
        confidence=0.7,
        damage_flags=["damaged"],
        analysis_prepass={"zip_structure_features": {"has_sfx_prefix": True}},
        knowledge=_zip_profile_knowledge("zip_sfx_cd_damage"),
        archive_key="sfx.zip",
    ), lazy=True)

    modules = {candidate.module_name for candidate in batch.candidates}
    assert "archive_carrier_crop_deep_recovery" in modules
    assert "zip_fix_cd_offset" not in modules


def test_zip_compound_boundary_payload_profile_routes_carrier_crop(tmp_path):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [
                {"name": "archive_carrier_crop_deep_recovery", "enabled": True},
                {"name": "zip_rebuild_cd_from_local_headers", "enabled": True},
                {"name": "zip_local_header_partial_scan", "enabled": True},
            ],
        }
    })
    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(tmp_path / "compound_sfx.zip"), "format_hint": "zip"},
        format="zip",
        confidence=0.7,
        damage_flags=["central_directory_bad", "central_directory_offset_bad", "trailing_junk"],
        analysis_prepass={"damage_profile": "compound_boundary_drop_cd_payload_bad"},
        knowledge=_zip_profile_knowledge("compound_boundary_drop_cd_payload_bad"),
        archive_key="compound_sfx.zip",
    ), lazy=True)

    modules = {candidate.module_name for candidate in batch.candidates}
    assert "archive_carrier_crop_deep_recovery" in modules
    assert "carrier_archive" in batch.diagnosis["capability_decision"]["damage_flags"]


def test_zip_route_history_allows_rebuild_after_carrier_crop(tmp_path):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [{"name": "zip_rebuild_cd_from_local_headers", "enabled": True}],
        }
    })
    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(tmp_path / "cropped.zip"), "format_hint": "zip"},
        format="zip",
        confidence=0.7,
        damage_flags=["damaged", "central_directory_bad"],
        repair_history={"previous_modules": ["archive_carrier_crop_deep_recovery"]},
        archive_key="cropped.zip",
    ), lazy=True)

    assert {candidate.module_name for candidate in batch.candidates} == {"zip_rebuild_cd_from_local_headers"}
    assert "after_archive_carrier_crop" in batch.diagnosis["capability_decision"]["damage_flags"]


def test_zip_v23_raw_name_candidate_ranks_before_generic_rebuild(tmp_path):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [
                {"name": "zip_rebuild_cd_preserve_raw_names", "enabled": True},
                {"name": "zip_rebuild_cd_from_local_headers", "enabled": True},
                {"name": "zip_fix_cd_offset", "enabled": True},
            ],
        }
    })
    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(tmp_path / "raw.zip"), "format_hint": "zip"},
        format="zip",
        confidence=0.7,
        damage_flags=["damaged", "filename_encoding_bad", "raw_filename_bytes", "central_directory_bad", "central_directory_offset_bad", "local_header_recovery"],
        archive_key="raw.zip",
    ), lazy=True)

    selector = CandidateSelector(scheduler.config)
    ranked = sorted(((selector.generation_priority(candidate), candidate.module_name) for candidate in batch.candidates), reverse=True)
    assert ranked[0][1] == "zip_rebuild_cd_preserve_raw_names"


def test_zip_v23_zip64_extra_candidate_ranks_before_generic_rebuild(tmp_path):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [
                {"name": "zip_fix_zip64_extra_size", "enabled": True},
                {"name": "zip_rebuild_cd_from_local_headers", "enabled": True},
            ],
        }
    })
    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(tmp_path / "zip64.zip"), "format_hint": "zip"},
        format="zip",
        confidence=0.7,
        damage_flags=["damaged", "zip64", "zip64_extra_bad", "zip64_extra_size_bad", "central_directory_bad", "local_header_recovery"],
        archive_key="zip64.zip",
    ), lazy=True)

    selector = CandidateSelector(scheduler.config)
    ranked = sorted(((selector.generation_priority(candidate), candidate.module_name) for candidate in batch.candidates), reverse=True)
    assert ranked[0][1] == "zip_fix_zip64_extra_size"


def test_zip_v23_split_sidecars_do_not_force_partial_salvage(tmp_path):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [
                {"name": "zip_partial_salvage_missing_volume", "enabled": True},
                {"name": "zip_rebuild_cd_from_local_headers", "enabled": True},
                {"name": "zip_local_header_partial_scan", "enabled": True},
            ],
        }
    })
    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(tmp_path / "split.zip"), "format_hint": "zip", "parts": [{"path": str(tmp_path / "split.z01")}]},
        format="zip",
        confidence=0.7,
        damage_flags=["missing_volume", "input_truncated", "local_header_recovery"],
        analysis_prepass={"zip_structure_features": {"has_split_sidecars": True}},
        archive_key="split.zip",
    ), lazy=True)

    modules = {candidate.module_name for candidate in batch.candidates}
    assert "zip_partial_salvage_missing_volume" not in modules
    assert "zip_rebuild_cd_from_local_headers" in modules


def test_zip_v25_source_input_parts_become_concat_ranges(tmp_path):
    main = tmp_path / "split.zip"
    part = tmp_path / "split.z01"
    main.write_bytes(b"tail")
    part.write_bytes(b"head")

    source = source_input_for_job(RepairJob(
        source_input={"kind": "file", "path": str(main), "format_hint": "zip", "parts": [{"path": str(part)}]},
        format="zip",
        confidence=0.7,
        damage_flags=["split_sidecars_available", "local_header_recovery"],
        archive_key="split.zip",
    ))

    assert source["kind"] == "concat_ranges"
    assert [item["path"] for item in source["ranges"]] == [str(part), str(main)]


def test_zip_remove_spurious_data_descriptor_returns_single_delete_patch(tmp_path):
    import sunpack_native

    source = tmp_path / "descriptor_conflict.zip"
    fake_offset = _write_descriptor_conflict_zip(source)

    result = sunpack_native.zip_remove_spurious_data_descriptor(
        {"kind": "file", "path": str(source), "format_hint": "zip"},
        str(tmp_path / "native"),
        3,
        20000,
        512.0,
        30.0,
    )

    assert result["native_target"] == "spurious_data_descriptor_delete"
    candidate = result["candidates"][0]
    assert "removed_spurious_data_descriptor" in candidate["patch_facts"]
    operations = candidate["patch_plan"]["operations"]
    assert operations == [{
        "op": "delete",
        "target": "logical",
        "offset": fake_offset,
        "size": 18,
        "details": {
            "module": "zip_remove_spurious_data_descriptor",
            "native_target": "spurious_data_descriptor_delete",
            "descriptor_size_after_delete": 16,
        },
    }]


def test_zip_remove_spurious_data_descriptor_candidate_is_virtual_patch(tmp_path):
    source = tmp_path / "descriptor_conflict.zip"
    fake_offset = _write_descriptor_conflict_zip(source)
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [{"name": "zip_remove_spurious_data_descriptor", "enabled": True}],
            "virtual_patch_candidate": True,
        }
    })

    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "zip"},
        format="zip",
        confidence=0.7,
        damage_flags=[
            "data_descriptor",
            "compressed_size_bad",
            "local_header_conflict",
            "central_directory_offset_bad",
            "spurious_data_descriptor_candidate",
        ],
        archive_key="descriptor_conflict.zip",
    ), lazy=False)

    assert len(batch.candidates) == 1
    candidate = batch.candidates[0]
    assert candidate.module_name == "zip_remove_spurious_data_descriptor"
    assert candidate.repaired_input["kind"] in {"archive_state", "file"}
    operation = candidate.plan["patch_plan"]["operations"][0]
    assert operation["op"] == "delete"
    assert operation["offset"] == fake_offset
    assert operation["size"] == 18
    assert "removed_spurious_data_descriptor" in candidate.diagnosis["patch_facts"]


def test_zip_normalize_data_descriptor_flags_patches_only_bit3(tmp_path):
    source = tmp_path / "descriptor_conflict.zip"
    fake_offset = _write_descriptor_conflict_zip(source)
    data = source.read_bytes()
    patched = data[:fake_offset] + data[fake_offset + 18:]
    cd_offset = patched.find(b"PK\x01\x02")
    second_cd_offset = patched.find(b"PK\x01\x02", cd_offset + 4)
    patched = bytearray(patched)
    patched[second_cd_offset + 8:second_cd_offset + 10] = (0).to_bytes(2, "little")
    source.write_bytes(patched)
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [{"name": "zip_normalize_data_descriptor_flags", "enabled": True}],
            "virtual_patch_candidate": True,
        }
    })

    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "zip"},
        format="zip",
        confidence=0.7,
        damage_flags=[
            "data_descriptor",
            "compressed_size_bad",
            "local_header_conflict",
            "central_directory_bad",
            "after_descriptor_stream_reconcile",
        ],
        archive_key="descriptor_conflict.zip",
    ), lazy=False)

    assert len(batch.candidates) == 1
    candidate = batch.candidates[0]
    assert candidate.repaired_input["kind"] in {"archive_state", "file"}
    assert candidate.diagnosis["native_target"] == "data_descriptor_flags"
    assert "fixed_field=data_descriptor_bit3_flags" in candidate.diagnosis["patch_facts"]
    operations = candidate.diagnosis["patch_plan"]["operations"]
    assert len(operations) == 1
    assert operations[0]["op"] == "replace_range"
    assert operations[0]["size"] == 2


def test_zip_reconcile_cd_entry_names_from_local_headers_patches_only_name_bytes(tmp_path):
    source = tmp_path / "descriptor_conflict.zip"
    fake_offset = _write_descriptor_conflict_zip(source)
    data = source.read_bytes()
    patched = data[:fake_offset] + data[fake_offset + 18:]
    cd_offset = patched.find(b"PK\x01\x02")
    second_cd_offset = patched.find(b"PK\x01\x02", cd_offset + 4)
    patched = bytearray(patched)
    patched[second_cd_offset + 46:second_cd_offset + 56] = b"corrupt.tx"
    source.write_bytes(patched)
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [{"name": "zip_reconcile_cd_entry_names_from_local_headers", "enabled": True}],
            "virtual_patch_candidate": True,
        }
    })

    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "zip"},
        format="zip",
        confidence=0.7,
        damage_flags=[
            "central_directory_bad",
            "local_header_conflict",
            "exact_match_failed",
            "after_descriptor_stream_reconcile",
            "after_descriptor_flag_normalize",
        ],
        archive_key="descriptor_conflict.zip",
    ), lazy=False)

    assert len(batch.candidates) == 1
    candidate = batch.candidates[0]
    assert candidate.diagnosis["native_target"] == "cd_entry_names"
    assert "fixed_field=central_directory_entry_names" in candidate.diagnosis["patch_facts"]
    operations = candidate.diagnosis["patch_plan"]["operations"]
    assert len(operations) == 1
    assert operations[0]["op"] == "replace_range"
    assert operations[0]["offset"] == second_cd_offset + 46
    assert operations[0]["size"] == len(b"second.txt")


def test_zip_v23_duplicate_resolver_ranks_before_generic_rebuild(tmp_path):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [
                {"name": "zip_resolve_duplicate_entries", "enabled": True},
                {"name": "zip_rebuild_cd_from_local_headers", "enabled": True},
            ],
        }
    })
    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(tmp_path / "dup.zip"), "format_hint": "zip"},
        format="zip",
        confidence=0.7,
        damage_flags=["damaged", "duplicate_entries", "central_directory_bad", "local_header_recovery"],
        archive_key="dup.zip",
    ), lazy=True)

    selector = CandidateSelector(scheduler.config)
    ranked = sorted(((selector.generation_priority(candidate), candidate.module_name) for candidate in batch.candidates), reverse=True)
    assert ranked[0][1] == "zip_resolve_duplicate_entries"


def test_zip_rebuild_cd_from_local_headers_repairs_missing_eocd(tmp_path):
    source = tmp_path / "missing_cd.zip"
    _write_zip(source, {"a.txt": b"alpha", "b.txt": b"bravo"})
    data = source.read_bytes()
    eocd_offset = data.rfind(b"PK\x05\x06")
    cd_offset = struct.unpack_from("<I", data, eocd_offset + 16)[0]
    source.write_bytes(data[:cd_offset])

    result = _run_zip_repair(
        tmp_path,
        "zip_rebuild_cd_from_local_headers",
        source,
        ["central_directory_bad"],
    )

    assert result.ok is True
    assert result.status == "repaired"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("a.txt") == b"alpha"
        assert archive.read("b.txt") == b"bravo"


def test_zip_v24_raw_name_rebuild_uses_native_target_and_preserves_name_bytes(tmp_path):
    source = tmp_path / "raw_name_missing_cd.zip"
    raw_name = b"\xff-name.bin"
    _write_raw_name_zip_prefix(source, raw_name, b"payload")

    result = _run_zip_repair(
        tmp_path,
        "zip_rebuild_cd_preserve_raw_names",
        source,
        ["filename_encoding_bad", "raw_filename_bytes", "central_directory_bad", "local_header_recovery"],
    )

    assert result.ok is True
    assert result.diagnosis["native_target"] == "rebuild_cd_preserve_raw_names"
    assert result.diagnosis["raw_name_bytes_preserved"] is True
    repaired = Path(result.repaired_input["path"]).read_bytes()
    cd_offset = repaired.index(b"PK\x01\x02")
    name_len = struct.unpack_from("<H", repaired, cd_offset + 28)[0]
    name_start = cd_offset + 46
    assert repaired[name_start:name_start + name_len] == raw_name


def test_zip_local_header_partial_scan_skips_damaged_entry(tmp_path):
    source = tmp_path / "partial.zip"
    _write_zip(source, {"bad.txt": b"broken", "good.txt": b"still here"})
    data = bytearray(source.read_bytes())
    first_lfh = data.find(b"PK\x03\x04")
    data[first_lfh:first_lfh + 4] = b"BAD!"
    source.write_bytes(bytes(data))

    result = _run_zip_repair(
        tmp_path,
        "zip_local_header_partial_scan",
        source,
        ["damaged", "checksum_error"],
    )

    assert result.ok is True
    assert result.status == "partial"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.namelist() == ["good.txt"]
        assert archive.read("good.txt") == b"still here"


def test_zip_rebuild_cd_from_data_descriptors_materializes_sizes(tmp_path):
    source = tmp_path / "descriptor.zip"
    source.write_bytes(_descriptor_zip_fragment("dd.txt", b"descriptor payload"))

    result = _run_zip_repair(
        tmp_path,
        "zip_rebuild_cd_from_data_descriptors",
        source,
        ["data_descriptor", "compressed_size_bad"],
    )

    assert result.ok is True
    assert result.status == "repaired"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("dd.txt") == b"descriptor payload"


def test_zip_rebuild_cd_from_data_descriptors_supports_zip64_descriptor(tmp_path):
    source = tmp_path / "zip64_descriptor.zip"
    source.write_bytes(_descriptor_zip_fragment(
        "zip64-dd.txt",
        b"zip64 descriptor payload",
        zip64=True,
    ))

    result = _run_zip_repair(
        tmp_path,
        "zip_rebuild_cd_from_data_descriptors",
        source,
        ["data_descriptor", "compressed_size_bad"],
    )

    assert result.ok is True
    assert result.status == "repaired"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("zip64-dd.txt") == b"zip64 descriptor payload"


def test_zip_local_header_partial_scan_builds_best_verified_candidate(tmp_path):
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
            "modules": [{"name": "zip_local_header_partial_scan", "enabled": True}],
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
    assert result.module_name == "zip_local_header_partial_scan"
    native = result.diagnosis["native_zip_local_header_partial_scan_deep"]
    assert native["selected_candidate"] == "zip_deep_descriptor_recovered"
    assert native["verified_entries"] == 2
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.namelist() == ["good.txt", "dd.txt"]
        assert archive.read("good.txt") == b"good payload"
        assert archive.read("dd.txt") == b"descriptor payload"


def test_zip_fix_eocd_record_rebuilds_missing_eocd_from_central_directory(tmp_path):
    source = tmp_path / "missing_eocd.zip"
    _write_zip(source, {"payload.txt": b"zip payload"})
    data = source.read_bytes()
    source.write_bytes(data[:data.rfind(b"PK\x05\x06")])

    result = _run_repair(tmp_path, "zip_fix_eocd_record", "zip", source, ["eocd_bad", "central_directory_bad"])

    assert result.ok is True
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("payload.txt") == b"zip payload"


def test_zip_fix_cd_offset_rewrites_bad_eocd_offset(tmp_path):
    source = tmp_path / "bad_cd_offset.zip"
    _write_zip(source, {"payload.txt": b"zip payload"})
    data = bytearray(source.read_bytes())
    eocd_offset = bytes(data).rfind(b"PK\x05\x06")
    struct.pack_into("<I", data, eocd_offset + 16, 0)
    source.write_bytes(bytes(data))

    result = _run_repair(tmp_path, "zip_fix_cd_offset", "zip", source, ["central_directory_offset_bad"])

    assert result.ok is True
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("payload.txt") == b"zip payload"


def test_zip_trim_trailing_junk_removes_bytes_after_eocd(tmp_path):
    source = tmp_path / "zip_tail.zip"
    _write_zip(source, {"payload.txt": b"zip payload"})
    original = source.read_bytes()
    source.write_bytes(original + b"JUNK")

    result = _run_repair(tmp_path, "zip_trim_trailing_junk", "zip", source, ["trailing_junk"])

    assert result.ok is True
    assert result.repaired_input["path"]
    assert len(open(result.repaired_input["path"], "rb").read()) == len(original)


def test_zip_fix_eocd_comment_length_patches_oversized_comment_length(tmp_path):
    source = tmp_path / "bad_comment_len.zip"
    _write_zip(source, {"payload.txt": b"zip payload"})
    data = bytearray(source.read_bytes())
    eocd_offset = bytes(data).rfind(b"PK\x05\x06")
    struct.pack_into("<H", data, eocd_offset + 20, 12)
    source.write_bytes(bytes(data))

    result = _run_repair(tmp_path, "zip_fix_eocd_comment_length", "zip", source, ["comment_length_bad"])

    assert result.ok is True
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("payload.txt") == b"zip payload"


def test_zip_fix_cd_entry_count_patches_bad_counts(tmp_path):
    source = tmp_path / "bad_count.zip"
    _write_zip(source, {"a.txt": b"a", "b.txt": b"b"})
    data = bytearray(source.read_bytes())
    eocd_offset = bytes(data).rfind(b"PK\x05\x06")
    struct.pack_into("<HH", data, eocd_offset + 8, 1, 1)
    source.write_bytes(bytes(data))

    result = _run_repair(tmp_path, "zip_fix_cd_entry_count", "zip", source, ["central_directory_count_bad"])

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


def test_gzip_trim_trailing_junk_removes_bytes_after_stream(tmp_path):
    source = tmp_path / "gzip_tail.gz"
    original = gzip.compress(b"gzip payload")
    source.write_bytes(original + b"JUNK")

    result = _run_repair(tmp_path, "gzip_trim_trailing_junk", "gzip", source, ["trailing_junk"])

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


def test_seven_zip_trim_trailing_junk_removes_bytes_after_next_header(tmp_path):
    source = tmp_path / "tail.7z"
    original = _seven_zip_bytes()
    source.write_bytes(original + b"JUNK")

    result = _run_deep_repair(tmp_path, "seven_zip_trim_trailing_junk", "7z", source, ["trailing_junk"])

    assert result.ok is True
    assert open(result.repaired_input["path"], "rb").read() == original


def test_seven_zip_fix_start_header_crc_rewrites_bad_crc(tmp_path):
    source = tmp_path / "bad_start_crc.7z"
    data = bytearray(_seven_zip_bytes())
    data[8:12] = b"\0\0\0\0"
    source.write_bytes(bytes(data))

    result = _run_deep_repair(tmp_path, "seven_zip_fix_start_header_crc", "7z", source, ["start_header_crc_bad"])

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


def test_seven_zip_crop_carrier_prefix_trims_carrier_and_tail(tmp_path):
    source = tmp_path / "carrier-tail.7z"
    original = _seven_zip_bytes()
    source.write_bytes(b"SFX" + original + b"JUNK")

    result = _run_deep_repair(
        tmp_path,
        "seven_zip_crop_carrier_prefix",
        "7z",
        source,
        ["carrier_archive", "trailing_junk", "boundary_unreliable"],
    )

    assert result.ok is True
    assert result.module_name == "seven_zip_crop_carrier_prefix"
    assert open(result.repaired_input["path"], "rb").read() == original
    assert result.diagnosis["native_7z_atomic_repair"]["offset"] == 3
    assert result.actions == ["crop_7z_carrier_prefix"]


def test_seven_zip_fix_next_header_crc_rewrites_next_header_and_start_crc(tmp_path):
    source = tmp_path / "bad-next-crc.7z"
    original = _seven_zip_bytes()
    data = bytearray(original)
    data[8:12] = b"\0\0\0\0"
    data[28:32] = b"\0\0\0\0"
    source.write_bytes(bytes(data))

    result = _run_deep_repair(
        tmp_path,
        "seven_zip_fix_next_header_crc",
        "7z",
        source,
        ["next_header_crc_bad", "start_header_crc_bad"],
    )

    assert result.ok is True
    assert result.module_name == "seven_zip_fix_next_header_crc"
    assert open(result.repaired_input["path"], "rb").read() == original
    assert result.actions == ["recompute_7z_next_header_crc"]


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
            actions=[f"module_limit_candidates={config['module_limits']['max_candidates_per_module']}"],
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
            "module_limits": {"verify_candidates": False},
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


def _write_raw_name_zip_prefix(path, raw_name: bytes, payload: bytes):
    crc = zlib.crc32(payload) & 0xFFFF_FFFF
    local = bytearray()
    local.extend(b"PK\x03\x04")
    local.extend(struct.pack("<HHHHHIIIHH", 20, 0, 0, 0, 0, crc, len(payload), len(payload), len(raw_name), 0))
    local.extend(raw_name)
    local.extend(payload)
    path.write_bytes(bytes(local))


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


def _write_descriptor_conflict_zip(path: Path) -> int:
    entries = [
        ("first.txt", b"first payload"),
        ("second.txt", b"second payload"),
        ("third.txt", b"third payload"),
    ]
    locals_out = bytearray()
    central: list[tuple[str, bytes, bytes, int, int, int]] = []
    fake_offset = -1
    for index, (name, payload) in enumerate(entries):
        encoded_name = name.encode("utf-8")
        offset = len(locals_out)
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        locals_out.extend(struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0x08,
            0,
            0,
            0,
            0,
            0,
            0,
            len(encoded_name),
            0,
        ))
        locals_out.extend(encoded_name)
        locals_out.extend(payload)
        if index == 1:
            fake_offset = len(locals_out)
            locals_out.extend(b"PK\x07\x08" + b"F" * 14)
        locals_out.extend(struct.pack("<IIII", 0x08074B50, crc, len(payload), len(payload)))
        central_offset = offset - 18 if index > 1 else offset
        central.append((name, encoded_name, payload, central_offset, crc, len(payload)))

    cd_offset = sum(30 + len(name.encode("utf-8")) + len(payload) + 16 for name, payload in entries)
    central_out = bytearray()
    for _name, encoded_name, _payload, offset, crc, size in central:
        central_out.extend(struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            0x08,
            0,
            0,
            0,
            crc,
            size,
            size,
            len(encoded_name),
            0,
            0,
            0,
            0,
            0,
            offset,
        ))
        central_out.extend(encoded_name)
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        len(entries),
        len(entries),
        len(central_out),
        cd_offset,
        0,
    )
    path.write_bytes(bytes(locals_out) + bytes(central_out) + eocd)
    return fake_offset


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


