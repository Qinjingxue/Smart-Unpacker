from __future__ import annotations

import io
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import zipfile
import zlib

import pytest

from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.contracts.detection import FactBag
from sunpack.contracts.run_context import RunContext
from sunpack.contracts.tasks import ArchiveTask
from sunpack.config.schema import normalize_config
from sunpack.coordinator.extraction_batch import ExtractionBatchRunner
from sunpack.coordinator.repair_beam import RepairBeamLoop, RepairBeamState
from sunpack.coordinator.runner import PipelineRunner
from sunpack.detection import NestedOutputScanPolicy
from sunpack.extraction.result import ExtractionResult
from sunpack.extraction.scheduler import ExtractionScheduler
from sunpack.repair import RepairJob, RepairScheduler
from sunpack.repair.candidate import RepairCandidate, RepairCandidateBatch
from sunpack.verification import VerificationScheduler
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.tool_config import get_optional_rar


def _verification_config(methods: list[dict] | None = None, **overrides) -> dict:
    normalized_methods = []
    for method in methods or [
        {"name": "extraction_exit_signal"},
        {"name": "output_presence"},
        {"name": "archive_test_crc"},
    ]:
        item = dict(method)
        item.setdefault("enabled", True)
        normalized_methods.append(item)
    config = {
        "enabled": True,
        "max_retries": 2,
        "cleanup_failed_output": True,
        "accept_partial_when_source_damaged": True,
        "partial_min_completeness": 0.2,
        "complete_accept_threshold": 0.999,
        "partial_accept_threshold": 0.2,
        "retry_on_verification_failure": True,
        "methods": normalized_methods,
    }
    config.update(overrides)
    return config


def test_coordinator_real_repair_then_worker_extraction_for_prefixed_7z(tmp_path):
    _require_worker_or_skip()
    inner = _build_7z_archive(tmp_path, {"ok.txt": b"ok"})
    source = tmp_path / "prefixed.7z"
    source.write_bytes(b"SFX-PREFIX" + inner.read_bytes())
    extractor = _FailOnceThenRealExtractor(error="carrier archive prefix is damaged")
    task = _task(source, detected_ext="7z")
    task.fact_bag.set("analysis.selected_format", "7z")
    task.fact_bag.set("analysis.confidence", 0.82)
    config = {
        "repair": {
            "enabled": True,
            "workspace": str(tmp_path / "repair"),
            "max_repair_rounds_per_task": 1,
            "stages": {"deep": True},
            "deep": {"verify_candidates": False, "max_candidates_per_module": 4},
            "modules": [{"name": "archive_carrier_crop_deep_recovery", "enabled": True}],
            "beam": {"enabled": True, "max_rounds": 1},
        },
        "verification": _verification_config(),
    }
    runner = ExtractionBatchRunner(RunContext(), extractor, NestedOutputScanPolicy({}), config=config)

    try:
        outcome = runner._extract_verify_with_retries(task, str(tmp_path / "out"), runtime_scheduler=None)
    finally:
        extractor.close()

    assert outcome.success is True
    assert extractor.calls == 2
    assert outcome.repair_module == "archive_carrier_crop_deep_recovery"
    assert outcome.verification is not None
    assert outcome.verification.decision_hint == "accept"
    assert (tmp_path / "out" / "ok.txt").read_bytes() == b"ok"


def test_coordinator_real_zip_repair_then_worker_extraction(tmp_path):
    _require_worker_or_skip()
    source = tmp_path / "prefixed.zip"
    source.write_bytes(b"SFX-PREFIX" + _zip_bytes({"ok.txt": b"ok"}) + b"TAIL")
    extractor = _FailOnceThenRealExtractor(error="zip structure is damaged")
    task = _task(source, detected_ext="zip")
    task.fact_bag.set("analysis.selected_format", "zip")
    task.fact_bag.set("analysis.confidence", 0.82)
    config = {
        "repair": {
            "enabled": True,
            "workspace": str(tmp_path / "repair"),
            "max_repair_rounds_per_task": 1,
            "stages": {"deep": True},
            "deep": {"verify_candidates": False, "max_candidates_per_module": 4},
            "modules": [{"name": "zip_deep_partial_recovery", "enabled": True}],
            "beam": {"enabled": True, "max_rounds": 1},
        },
        "verification": {
            "enabled": True,
            "methods": [
                {"name": "extraction_exit_signal"},
                {"name": "output_presence"},
                {"name": "archive_test_crc"},
            ],
        },
    }
    runner = ExtractionBatchRunner(RunContext(), extractor, NestedOutputScanPolicy({}), config=config)

    try:
        outcome = runner._extract_verify_with_retries(task, str(tmp_path / "out"), runtime_scheduler=None)
    finally:
        extractor.close()

    assert outcome.success is True
    assert extractor.calls == 2
    assert outcome.repair_module == "zip_deep_partial_recovery"
    assert (tmp_path / "out" / "ok.txt").read_bytes() == b"ok"


def test_coordinator_real_tar_patch_plan_repair_then_worker_extraction(tmp_path):
    _require_worker_or_skip()
    source = tmp_path / "bad-checksum.tar"
    source.write_bytes(_tar_bytes({"ok.txt": b"ok"}, corrupt_first_checksum=True))
    extractor = _FailOnceThenRealExtractor(
        error="tar header checksum is damaged",
        failure_kind="structure_recognition",
    )
    task = _task(source, detected_ext="tar")
    task.fact_bag.set("analysis.selected_format", "tar")
    task.fact_bag.set("analysis.confidence", 0.82)
    _set_analysis_evidence(task, "tar", ["tar_checksum_bad"])
    config = {
        "repair": {
            "enabled": True,
            "workspace": str(tmp_path / "repair"),
            "max_repair_rounds_per_task": 1,
            "modules": [{"name": "tar_header_checksum_fix", "enabled": True}],
            "beam": {"enabled": True, "max_rounds": 1},
        },
        "verification": {
            "enabled": True,
            "methods": [
                {"name": "extraction_exit_signal"},
                {"name": "output_presence"},
                {"name": "archive_test_crc"},
            ],
        },
    }
    runner = ExtractionBatchRunner(RunContext(), extractor, NestedOutputScanPolicy({}), config=config)

    try:
        outcome = runner._extract_verify_with_retries(task, str(tmp_path / "out"), runtime_scheduler=None)
    finally:
        extractor.close()

    assert outcome.success is True
    assert extractor.calls == 2
    assert outcome.repair_module == "tar_header_checksum_fix"
    assert (tmp_path / "out" / "ok.txt").read_bytes() == b"ok"


def test_beam_uses_real_verification_coverage_to_pick_less_confident_better_zip(tmp_path):
    source = tmp_path / "source.zip"
    _write_zip(source, {"a.txt": b"a", "b.txt": b"b", "c.txt": b"c"})
    weak = tmp_path / "weak.zip"
    better = tmp_path / "better.zip"
    _write_zip(weak, {"a.txt": b"a"})
    _write_zip(better, {"a.txt": b"a", "b.txt": b"b"})
    task = _task(source, detected_ext="zip")
    verifier = VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": [{"name": "output_presence"}, {"name": "archive_test_crc"}],
            "partial_accept_threshold": 0.2,
        }
    })

    def assess(item):
        out_dir = tmp_path / f"assess-{item.candidate.module_name}"
        _extract_zip(Path(item.candidate.repaired_input["path"]), out_dir)
        result = ExtractionResult(
            success=True,
            archive=str(item.candidate.repaired_input["path"]),
            out_dir=str(out_dir),
            all_parts=[str(item.candidate.repaired_input["path"])],
        )
        return verifier.verify(task, result)

    run = RepairBeamLoop(
        _StaticCandidateScheduler([
            _candidate("weak_high_confidence", weak, 0.95),
            _candidate("better_low_confidence", better, 0.55),
        ]),
        beam_width=2,
        max_candidates_per_state=2,
        max_analyze_candidates=2,
        max_assess_candidates=2,
        analyze=lambda candidate: {"confidence": candidate.confidence},
        assess=assess,
    ).run([
        RepairBeamState(
            source_input={"kind": "file", "path": str(source), "format_hint": "zip"},
            format="zip",
            archive_state=task.archive_state().to_dict(),
            archive_key="beam-real-verification",
        )
    ], max_rounds=1)

    assert run.best_state is not None
    assert run.best_state.history[-1]["module"] == "better_low_confidence"
    assert run.best_state.completeness == pytest.approx(2 / 3, abs=0.02)


def test_beam_uses_real_worker_and_verification_to_pick_better_zip(tmp_path):
    _require_worker_or_skip()
    source = tmp_path / "source.zip"
    _write_zip(source, {"a.txt": b"a", "b.txt": b"b", "c.txt": b"c"})
    weak = tmp_path / "weak.zip"
    better = tmp_path / "better.zip"
    _write_zip(weak, {"a.txt": b"a"})
    _write_zip(better, {"a.txt": b"a", "b.txt": b"b"})

    run = _run_real_worker_beam_comparison(
        tmp_path,
        source,
        "zip",
        [
            _candidate("weak_zip_worker", weak, 0.95, fmt="zip"),
            _candidate("better_zip_worker", better, 0.55, fmt="zip"),
        ],
    )

    assert run.best_state is not None
    assert run.best_state.history[-1]["module"] == "better_zip_worker"
    assert run.best_state.completeness == pytest.approx(2 / 3, abs=0.02)


def test_beam_uses_real_worker_and_verification_to_pick_better_tar(tmp_path):
    _require_worker_or_skip()
    source = tmp_path / "source.tar"
    weak = tmp_path / "weak.tar"
    better = tmp_path / "better.tar"
    source.write_bytes(_tar_bytes({"a.txt": b"a", "b.txt": b"b", "c.txt": b"c"}))
    weak.write_bytes(_tar_bytes({"a.txt": b"a"}))
    better.write_bytes(_tar_bytes({"a.txt": b"a", "b.txt": b"b"}))

    run = _run_real_worker_beam_comparison(
        tmp_path,
        source,
        "tar",
        [
            _candidate("weak_tar_worker", weak, 0.95, fmt="tar"),
            _candidate("better_tar_worker", better, 0.55, fmt="tar"),
        ],
        expected_names=["a.txt", "b.txt", "c.txt"],
    )

    assert run.best_state is not None
    assert run.best_state.history[-1]["module"] == "better_tar_worker"
    assert run.best_state.completeness == pytest.approx(2 / 3, abs=0.02)


def test_beam_compares_real_7z_patch_plan_candidates_with_worker(tmp_path):
    _require_worker_or_skip()
    inner = _build_7z_archive(tmp_path, {"ok.txt": b"ok"})
    original = inner.read_bytes()
    source = tmp_path / "bad-header.7z"
    damaged = bytearray(original)
    damaged[0] = ord("X")
    source.write_bytes(damaged)
    task = _task(source, detected_ext="7z")
    task.fact_bag.set("analysis.selected_format", "7z")
    candidates = [
        _archive_state_replace_candidate("bad_7z_patch", task, 0, b"Y", 0.95, fmt="7z"),
        _archive_state_replace_candidate("good_7z_patch", task, 0, original[:1], 0.55, fmt="7z"),
    ]

    run = _run_real_worker_beam_comparison(
        tmp_path,
        source,
        "7z",
        candidates,
        source_task=task,
        expected_names=["ok.txt"],
    )

    assert run.best_state is not None
    assert run.best_state.history[-1]["module"] == "good_7z_patch"
    assert run.best_state.decision_hint == "accept"


def test_beam_compares_real_rar_patch_plan_candidates_with_worker_when_rar_available(tmp_path):
    _require_worker_or_skip()
    rar = get_optional_rar()
    if rar is None:
        pytest.skip("rar.exe is required to build real RAR patch-plan comparison fixture")
    inner = _build_rar_archive(tmp_path, rar, {"ok.txt": b"ok"})
    original = inner.read_bytes()
    source = tmp_path / "bad-header.rar"
    damaged = bytearray(original)
    damaged[0] = ord("X")
    source.write_bytes(damaged)
    task = _task(source, detected_ext="rar")
    task.fact_bag.set("analysis.selected_format", "rar")
    candidates = [
        _archive_state_replace_candidate("bad_rar_patch", task, 0, b"Y", 0.95, fmt="rar"),
        _archive_state_replace_candidate("good_rar_patch", task, 0, original[:1], 0.55, fmt="rar"),
    ]

    run = _run_real_worker_beam_comparison(
        tmp_path,
        source,
        "rar",
        candidates,
        source_task=task,
        expected_names=["ok.txt"],
    )

    assert run.best_state is not None
    assert run.best_state.history[-1]["module"] == "good_rar_patch"
    assert run.best_state.decision_hint == "accept"


def test_nested_salvage_output_recurses_into_inner_archive_repair_pipeline(tmp_path):
    _require_worker_or_skip()
    inner = b"SFX-PREFIX" + _zip_bytes({"final.txt": b"done"}) + b"TAIL"
    outer = _zip_bytes({"inner.zip": inner}, compression=zipfile.ZIP_DEFLATED)
    source = tmp_path / "outer-carrier.zip"
    source.write_bytes(b"BROKEN-OUTER" + outer + b"OUTER-TAIL")
    outer_task = _task(source, detected_ext=".zip")
    outer_task.fact_bag.set("analysis.selected_format", "archive")
    outer_task.fact_bag.set("analysis.confidence", 0.82)
    _set_analysis_evidence(outer_task, "archive", ["outer_container_bad", "nested_archive"])

    config = _nested_salvage_pipeline_config(tmp_path)
    runner = PipelineRunner(config)
    runner.batch_runner.analysis_stage = _PassthroughAnalysisStage()
    extractor = _FailOriginalPathsThenRealExtractor({source})
    runner.batch_runner.extractor = extractor
    try:
        first_roots = runner.batch_runner.execute([outer_task])
        inner_archive = next(Path(first_roots[0]).rglob("inner.zip"))
        extractor.fail_paths.add(str(inner_archive.resolve()))

        second_tasks = runner._scan_targets(first_roots)
        runner.batch_runner.execute(second_tasks)
    finally:
        extractor.close()
        runner.extractor.close()

    assert first_roots
    assert runner.context.success_count == 2
    assert not runner.context.failed_tasks
    assert outer_task.fact_bag.get("repair.module") == "archive_nested_payload_salvage"
    assert second_tasks[0].fact_bag.get("repair.module") == "zip_deep_partial_recovery"
    assert inner_archive.is_file()
    assert (inner_archive.with_suffix("") / "final.txt").read_bytes() == b"done"


def test_pipeline_runner_run_entry_repairs_real_rar_carrier_crop_when_available(tmp_path):
    _require_worker_or_skip()
    rar = get_optional_rar()
    if rar is None:
        pytest.skip("rar.exe is not configured for real RAR repair coverage")

    input_dir = tmp_path / "input"
    input_dir.mkdir()
    inner = _build_rar_archive(tmp_path / "rar-fixture", rar, {"final.txt": b"rar"})
    source = input_dir / "carrier.rar"
    source.write_bytes(b"SFX-PREFIX" + inner.read_bytes() + b"TAIL")

    config = _pipeline_runner_repair_config(
        tmp_path,
        modules=[{"name": "rar_carrier_crop_deep_recovery", "enabled": True}],
        extensions=[".rar"],
    )
    runner = PipelineRunner(config)
    extractor = _FailOriginalPathsThenRealExtractor({source})
    runner.extractor = extractor
    runner.batch_runner.extractor = extractor

    summary = runner.run(str(input_dir))

    assert summary.success_count == 1
    assert not summary.failed_tasks
    assert (input_dir / "carrier" / "final.txt").read_bytes() == b"rar"


@pytest.mark.parametrize(
    ("inner_name", "inner_payload", "inner_format", "flags", "modules", "expected_module"),
    [
        (
            "inner.tar",
            lambda tmp_path: _tar_bytes({"final.txt": b"tar"}, corrupt_first_checksum=True),
            "tar",
            ["tar_checksum_bad"],
            [{"name": "tar_header_checksum_fix", "enabled": True}],
            "tar_header_checksum_fix",
        ),
        (
            "inner.7z",
            lambda tmp_path: _build_7z_archive(tmp_path / "seven-fixture", {"final.txt": b"7z"}).read_bytes()
            + b"TRAILING-JUNK",
            "7z",
            ["trailing_junk", "boundary_unreliable"],
            [{"name": "seven_zip_boundary_trim", "enabled": True}],
            "seven_zip_boundary_trim",
        ),
    ],
)
def test_nested_salvage_recurses_into_inner_tar_and_7z_repair_pipeline(
    tmp_path,
    inner_name,
    inner_payload,
    inner_format,
    flags,
    modules,
    expected_module,
):
    _require_worker_or_skip()

    inner_archive = _run_nested_multiformat_repair_pipeline(
        tmp_path,
        inner_name=inner_name,
        inner_payload=inner_payload(tmp_path),
        inner_format=inner_format,
        flags=flags,
        inner_modules=modules,
        expected_module=expected_module,
    )

    assert (inner_archive.with_suffix("") / "final.txt").is_file()


def test_nested_salvage_recurses_into_inner_rar_crop_repair_when_available(tmp_path):
    _require_worker_or_skip()
    rar = get_optional_rar()
    if rar is None:
        pytest.skip("rar.exe is not configured for real nested RAR coverage")

    inner = _build_rar_archive(tmp_path / "nested-rar-fixture", rar, {"final.txt": b"rar"}).read_bytes()
    inner_archive = _run_nested_multiformat_repair_pipeline(
        tmp_path,
        inner_name="inner.rar",
        inner_payload=b"SFX-PREFIX" + inner + b"TAIL",
        inner_format="rar",
        flags=["carrier_archive", "sfx", "boundary_unreliable"],
        inner_modules=[{"name": "rar_carrier_crop_deep_recovery", "enabled": True}],
        expected_module="rar_carrier_crop_deep_recovery",
    )

    assert (inner_archive.with_suffix("") / "final.txt").read_bytes() == b"rar"


def test_zip_conflict_resolver_rejects_traversal_and_keeps_safe_duplicate(tmp_path):
    source = tmp_path / "adversarial.zip"
    source.write_bytes(b"".join([
        _raw_stored_local_entry("../evil.txt", b"evil"),
        _raw_stored_local_entry("dup.txt", b"bad", crc32=0),
        _raw_stored_local_entry("dup.txt", b"good"),
    ]))
    result = _run_single_module_repair(
        tmp_path,
        "zip_conflict_resolver_rebuild",
        "zip",
        source,
        ["duplicate_entries", "overlapping_entries", "local_header_conflict", "damaged"],
    )

    assert result.status == "partial"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.namelist() == ["dup.txt"]
        assert archive.read("dup.txt") == b"good"


def test_zip_conflict_resolver_rejects_windows_unicode_and_reserved_conflicts(tmp_path):
    source = tmp_path / "adversarial-windows.zip"
    source.write_bytes(b"".join([
        _raw_stored_local_entry("A.txt", b"upper"),
        _raw_stored_local_entry("a.txt", b"lower"),
        _raw_stored_local_entry("caf\u00e9.txt", b"nfc"),
        _raw_stored_local_entry("cafe\u0301.txt", b"nfd"),
        _raw_stored_local_entry("C:\\temp\\evil.txt", b"drive"),
        _raw_stored_local_entry("/abs.txt", b"abs"),
        _raw_stored_local_entry("../evil.txt", b"traversal"),
        _raw_stored_local_entry("CON", b"reserved"),
        _raw_stored_local_entry("NUL.txt", b"reserved"),
        _raw_stored_local_entry("keep.txt", b"keep"),
        _raw_stored_local_entry("dup.txt", b"bad", crc32=0),
        _raw_stored_local_entry("dup.txt", b"good"),
    ]))
    result = _run_single_module_repair(
        tmp_path,
        "zip_conflict_resolver_rebuild",
        "zip",
        source,
        ["duplicate_entries", "overlapping_entries", "local_header_conflict", "damaged"],
    )

    assert result.status == "partial"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        names = archive.namelist()
        payloads = {archive.read(name) for name in names}

    assert b"keep" in payloads
    assert b"good" in payloads
    assert len(payloads & {b"upper", b"lower"}) == 1
    assert len(payloads & {b"nfc", b"nfd"}) == 1
    assert not (payloads & {b"drive", b"abs", b"traversal", b"reserved"})
    assert len({_zip_name_conflict_key(name) for name in names}) == len(names)
    for name in names:
        normalized = name.replace("\\", "/")
        assert not normalized.startswith("/")
        assert ":" not in normalized
        assert ".." not in normalized.split("/")
        assert _windows_reserved_base(name) not in {"CON", "PRN", "AUX", "NUL"}


def test_zip_conflict_resolver_ignores_malicious_central_directory_metadata(tmp_path):
    source = tmp_path / "cd-local-conflict.zip"
    source.write_bytes(_zip_with_cd_local_metadata_conflicts())
    result = _run_single_module_repair(
        tmp_path,
        "zip_conflict_resolver_rebuild",
        "zip",
        source,
        ["duplicate_entries", "overlapping_entries", "local_header_conflict", "damaged"],
    )

    assert result.status == "partial"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.namelist() == ["safe.txt"]
        assert archive.read("safe.txt") == b"good-from-local"


def test_deep_module_input_size_limit_blocks_large_nested_salvage(tmp_path):
    inner = _zip_bytes({"inner.txt": b"payload"})
    source = tmp_path / "oversize-carrier.bin"
    source.write_bytes((b"x" * 4096) + inner)
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "stages": {"deep": True},
            "deep": {"max_input_size_mb": 0.001},
            "modules": [{"name": "archive_nested_payload_salvage", "enabled": True}],
        }
    })

    result = scheduler.repair(RepairJob(
        source_input={"kind": "file", "path": str(source)},
        format="zip",
        confidence=0.82,
        damage_flags=["outer_container_bad", "nested_archive", "damaged"],
        archive_key="oversize-carrier",
    ))

    assert result.ok is False
    modules = result.diagnosis["capability_decision"]["modules"]
    nested = next(item for item in modules if item["name"] == "archive_nested_payload_salvage")
    assert "deep_input_size_blocked" in nested["reasons"]


def test_deep_candidate_cap_limits_nested_payload_salvage_outputs(tmp_path):
    first = _zip_bytes({"first.txt": b"1"})
    second = _zip_bytes({"second.txt": b"2"})
    source = tmp_path / "two-nested.bin"
    source.write_bytes(b"prefix" + first + b"middle" + second + b"tail")
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "stages": {"deep": True},
            "deep": {"max_candidates_per_module": 1, "verify_candidates": False},
            "modules": [{"name": "archive_nested_payload_salvage", "enabled": True}],
        }
    })

    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(source)},
        format="zip",
        confidence=0.82,
        damage_flags=["outer_container_bad", "nested_archive", "damaged"],
        archive_key="two-nested",
    ))

    assert len(batch.candidates) == 1
    assert batch.candidates[0].module_name == "archive_nested_payload_salvage"


def test_deep_output_size_limit_rejects_candidate_and_removes_temp_files(tmp_path):
    from sunpack_native import zip_deep_partial_recovery

    source = tmp_path / "oversized-output.zip"
    source.write_bytes(_raw_stored_local_entry("large.bin", b"x" * 2048))
    workspace = tmp_path / "repair"

    result = dict(zip_deep_partial_recovery(
        {"kind": "file", "path": str(source), "format_hint": "zip"},
        str(workspace),
        4,
        20000,
        512.0,
        0.00001,
        512.0,
        30.0,
        False,
    ))

    assert result["status"] == "unrepairable"
    assert any("max_output_size_mb" in warning for warning in result["warnings"])
    assert not list(workspace.rglob("*.tmp"))
    assert not list(workspace.rglob("zip_deep_*.zip"))


def test_deep_time_budget_returns_without_candidates(tmp_path):
    from sunpack_native import zip_deep_partial_recovery

    source = tmp_path / "many-local-headers.zip"
    source.write_bytes(b"".join(
        _raw_stored_local_entry(f"file-{index}.txt", b"x")
        for index in range(256)
    ))

    result = dict(zip_deep_partial_recovery(
        {"kind": "file", "path": str(source), "format_hint": "zip"},
        str(tmp_path / "repair"),
        4,
        20000,
        512.0,
        2048.0,
        512.0,
        0.000000000001,
        False,
    ))

    assert result["status"] == "unrepairable"
    assert result["recovered_entries"] == 0
    assert any("time budget" in warning for warning in result["warnings"])


def test_coordinator_zero_max_repair_rounds_skips_repair_loop(tmp_path):
    _require_worker_or_skip()
    source = tmp_path / "prefixed.zip"
    source.write_bytes(b"SFX-PREFIX" + _zip_bytes({"ok.txt": b"ok"}) + b"TAIL")
    extractor = _AlwaysFailExtractor(error="zip structure is damaged")
    task = _task(source, detected_ext="zip")
    task.fact_bag.set("analysis.selected_format", "zip")
    task.fact_bag.set("analysis.confidence", 0.82)
    config = {
        "repair": {
            "enabled": True,
            "workspace": str(tmp_path / "repair"),
            "max_repair_rounds_per_task": 0,
            "stages": {"deep": True},
            "deep": {"verify_candidates": False, "max_candidates_per_module": 4},
            "modules": [{"name": "zip_deep_partial_recovery", "enabled": True}],
            "beam": {"enabled": True, "max_rounds": 2},
        },
        "verification": {
            "enabled": True,
            "methods": [
                {"name": "extraction_exit_signal"},
                {"name": "output_presence"},
                {"name": "archive_test_crc"},
            ],
        },
    }
    runner = ExtractionBatchRunner(RunContext(), extractor, NestedOutputScanPolicy({}), config=config)

    try:
        outcome = runner._extract_verify_with_retries(task, str(tmp_path / "out"), runtime_scheduler=None)
    finally:
        extractor.close()

    assert outcome.success is False
    assert extractor.calls == 1
    assert task.fact_bag.get("repair.module") is None
    assert task.fact_bag.get("repair.attempts") is None
    assert not (tmp_path / "repair").exists()


class _FailOnceThenRealExtractor:
    password_session = None

    def __init__(
        self,
        *,
        error: str = "zip end of central directory is missing",
        failure_kind: str = "structure_recognition",
        failure_stage: str = "archive_open",
    ):
        self.calls = 0
        self.error = error
        self.failure_kind = failure_kind
        self.failure_stage = failure_stage
        self.real = ExtractionScheduler(max_retries=1, process_config={"persistent_workers": False})
        self.password_session = self.real.password_session

    def close(self) -> None:
        self.real.close()

    def default_output_dir_for_task(self, task):
        return str(Path(task.main_path).with_suffix(""))

    def inspect(self, task, out_dir):
        return type("Preflight", (), {"skip_result": None})()

    def extract(self, task, out_dir, runtime_scheduler=None):
        self.calls += 1
        if self.calls == 1:
            return ExtractionResult(
                success=False,
                archive=task.main_path,
                out_dir=out_dir,
                all_parts=[task.main_path],
                error=self.error,
                diagnostics={
                    "failure_stage": self.failure_stage,
                    "failure_kind": self.failure_kind,
                    "result": {
                        "status": "failed",
                        "native_status": "damaged",
                        "failure_stage": self.failure_stage,
                        "failure_kind": self.failure_kind,
                    },
                },
            )
        return self.real.extract(task, out_dir, runtime_scheduler=runtime_scheduler)


class _FailOriginalPathsThenRealExtractor:
    password_session = None

    def __init__(self, fail_paths: set[Path], *, error: str = "synthetic structure failure before repair"):
        self.fail_paths = {str(path.resolve()) for path in fail_paths}
        self.failed_once: set[str] = set()
        self.error = error
        self.real = ExtractionScheduler(max_retries=1, process_config={"persistent_workers": False})
        self.password_session = self.real.password_session

    def close(self) -> None:
        self.real.close()

    def default_output_dir_for_task(self, task):
        return self.real.default_output_dir_for_task(task)

    def inspect(self, task, out_dir):
        return type("Preflight", (), {"skip_result": None})()

    def extract(self, task, out_dir, runtime_scheduler=None):
        archive_path = Path(task.archive_input().entry_path or task.main_path).resolve()
        key = str(archive_path)
        if key in self.fail_paths and key not in self.failed_once:
            self.failed_once.add(key)
            return ExtractionResult(
                success=False,
                archive=str(archive_path),
                out_dir=out_dir,
                all_parts=[str(archive_path)],
                error=self.error,
                diagnostics={
                    "failure_stage": "archive_open",
                    "failure_kind": "structure_recognition",
                    "result": {
                        "status": "failed",
                        "native_status": "damaged",
                        "failure_stage": "archive_open",
                        "failure_kind": "structure_recognition",
                    },
                },
            )
        return self.real.extract(task, out_dir, runtime_scheduler=runtime_scheduler)


class _AlwaysFailExtractor:
    password_session = None

    def __init__(
        self,
        *,
        error: str = "synthetic structure failure before repair",
        failure_kind: str = "structure_recognition",
        failure_stage: str = "archive_open",
    ):
        self.calls = 0
        self.error = error
        self.failure_kind = failure_kind
        self.failure_stage = failure_stage
        self.real = ExtractionScheduler(max_retries=1, process_config={"persistent_workers": False})
        self.password_session = self.real.password_session

    def close(self) -> None:
        self.real.close()

    def default_output_dir_for_task(self, task):
        return str(Path(task.main_path).with_suffix(""))

    def inspect(self, task, out_dir):
        return type("Preflight", (), {"skip_result": None})()

    def extract(self, task, out_dir, runtime_scheduler=None):
        self.calls += 1
        archive_path = Path(task.archive_input().entry_path or task.main_path)
        return ExtractionResult(
            success=False,
            archive=str(archive_path),
            out_dir=out_dir,
            all_parts=[str(archive_path)],
            error=self.error,
            diagnostics={
                "failure_stage": self.failure_stage,
                "failure_kind": self.failure_kind,
                "result": {
                    "status": "failed",
                    "native_status": "damaged",
                    "failure_stage": self.failure_stage,
                    "failure_kind": self.failure_kind,
                },
            },
        )


class _StaticCandidateScheduler:
    def __init__(self, candidates):
        self.candidates = list(candidates)

    def generate_repair_candidates(self, job, *, lazy=False):
        return RepairCandidateBatch(candidates=list(self.candidates))


class _PassthroughAnalysisStage:
    def analyze_task(self, task):
        return None

    def analyze_tasks(self, tasks):
        return list(tasks)

    def analyze_task_to_tasks(self, task):
        return [task]


def _candidate(module_name: str, path: Path, confidence: float, *, fmt: str = "zip") -> RepairCandidate:
    return _file_candidate(module_name, path, confidence, fmt=fmt)


def _file_candidate(module_name: str, path: Path, confidence: float, *, fmt: str) -> RepairCandidate:
    return RepairCandidate(
        module_name=module_name,
        format=fmt,
        repaired_input={"kind": "file", "path": str(path), "format_hint": fmt},
        confidence=confidence,
        status="partial",
        stage="deep",
        actions=[module_name],
        workspace_paths=[str(path)],
    )


def _archive_state_candidate(
    module_name: str,
    task: ArchiveTask,
    delete_prefix_bytes: int,
    confidence: float,
    *,
    fmt: str,
) -> RepairCandidate:
    patch = PatchPlan(
        id=module_name,
        operations=[
            PatchOperation.delete_range(
                offset=0,
                size=delete_prefix_bytes,
                details={"module": module_name},
            )
        ],
        provenance={"module": module_name},
        confidence=confidence,
    )
    state = ArchiveState.from_archive_input(task.archive_input(), patches=[patch])
    return RepairCandidate(
        module_name=module_name,
        format=fmt,
        repaired_input={"kind": "archive_state", "format_hint": fmt},
        confidence=confidence,
        status="partial",
        stage="deep",
        actions=[module_name],
        plan={"archive_state": state.to_dict()},
    )


def _archive_state_replace_candidate(
    module_name: str,
    task: ArchiveTask,
    offset: int,
    data: bytes,
    confidence: float,
    *,
    fmt: str,
) -> RepairCandidate:
    patch = PatchPlan(
        id=module_name,
        operations=[
            PatchOperation.replace_bytes(
                offset=offset,
                data=data,
                details={"module": module_name},
            )
        ],
        provenance={"module": module_name},
        confidence=confidence,
    )
    state = ArchiveState.from_archive_input(task.archive_input(), patches=[patch])
    return RepairCandidate(
        module_name=module_name,
        format=fmt,
        repaired_input={"kind": "archive_state", "format_hint": fmt},
        confidence=confidence,
        status="partial",
        stage="deep",
        actions=[module_name],
        plan={"archive_state": state.to_dict()},
    )


def _task(path: Path, *, detected_ext: str = "zip") -> ArchiveTask:
    bag = FactBag()
    bag.set("candidate.entry_path", str(path))
    bag.set("candidate.member_paths", [str(path)])
    bag.set("file.detected_ext", detected_ext)
    return ArchiveTask(
        fact_bag=bag,
        score=10,
        key=path.name,
        main_path=str(path),
        all_parts=[str(path)],
        logical_name=path.stem,
        detected_ext=detected_ext,
    ).ensure_archive_state()


def _set_analysis_evidence(task: ArchiveTask, fmt: str, damage_flags: list[str]) -> None:
    task.fact_bag.set("analysis.evidences", [{
        "format": fmt,
        "confidence": 0.82,
        "status": "damaged",
        "segments": [{
            "start_offset": 0,
            "end_offset": Path(task.main_path).stat().st_size,
            "confidence": 0.82,
            "damage_flags": list(damage_flags),
        }],
    }])


def _run_real_worker_beam_comparison(
    tmp_path: Path,
    source: Path,
    fmt: str,
    candidates: list[RepairCandidate],
    *,
    source_task: ArchiveTask | None = None,
    expected_names: list[str] | None = None,
):
    task = source_task or _task(source, detected_ext=fmt)
    task.fact_bag.set("analysis.selected_format", fmt)
    if expected_names:
        task.fact_bag.set("verification.expected_names", list(expected_names))
    verifier = VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": [
                {"name": "extraction_exit_signal"},
                {"name": "output_presence"},
                {"name": "expected_name_presence"},
                {"name": "archive_test_crc"},
            ],
            "partial_accept_threshold": 0.2,
        }
    })
    extractor = ExtractionScheduler(max_retries=1, process_config={"persistent_workers": False})

    def assess(item):
        original_state = task.archive_state()
        out_dir = tmp_path / f"assess-{item.candidate.module_name}"
        shutil.rmtree(out_dir, ignore_errors=True)
        try:
            archive_state = item.candidate.plan.get("archive_state") if isinstance(item.candidate.plan, dict) else None
            if isinstance(archive_state, dict):
                task.set_archive_state(archive_state)
                extract_task = task
            else:
                extract_task = _task(Path(item.candidate.repaired_input["path"]), detected_ext=fmt)
            result = extractor.extract(extract_task, str(out_dir), runtime_scheduler=None)
            return verifier.verify(task, result)
        finally:
            task.set_archive_state(original_state)

    try:
        return RepairBeamLoop(
            _StaticCandidateScheduler(candidates),
            beam_width=2,
            max_candidates_per_state=2,
            max_analyze_candidates=2,
            max_assess_candidates=2,
            analyze=lambda candidate: {"confidence": candidate.confidence},
            assess=assess,
        ).run([
            RepairBeamState(
                source_input={"kind": "file", "path": str(source), "format_hint": fmt},
                format=fmt,
                archive_state=task.archive_state().to_dict(),
                archive_key=f"beam-real-worker-{fmt}",
            )
        ], max_rounds=1)
    finally:
        extractor.close()


def _run_single_module_repair(tmp_path: Path, module_name: str, fmt: str, source: Path, flags: list[str]):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "stages": {"deep": True},
            "deep": {"verify_candidates": False, "max_candidates_per_module": 4},
            "modules": [{"name": module_name, "enabled": True}],
        }
    })
    return scheduler.repair(RepairJob(
        source_input={"kind": "file", "path": str(source)},
        format=fmt,
        confidence=0.82,
        damage_flags=flags,
        archive_key=source.name,
    ))


def _run_nested_multiformat_repair_pipeline(
    tmp_path: Path,
    *,
    inner_name: str,
    inner_payload: bytes,
    inner_format: str,
    flags: list[str],
    inner_modules: list[dict],
    expected_module: str,
) -> Path:
    outer = _zip_bytes({inner_name: inner_payload}, compression=zipfile.ZIP_DEFLATED)
    source = tmp_path / f"outer-{inner_format}.zip"
    source.write_bytes(b"BROKEN-OUTER" + outer + b"OUTER-TAIL")
    outer_task = _task(source, detected_ext=".zip")
    outer_task.fact_bag.set("analysis.selected_format", "archive")
    outer_task.fact_bag.set("analysis.confidence", 0.82)
    _set_analysis_evidence(outer_task, "archive", ["outer_container_bad", "nested_archive"])

    config = _nested_salvage_pipeline_config(tmp_path)
    config["repair"]["modules"] = [{"name": "archive_nested_payload_salvage", "enabled": True}]
    runner = PipelineRunner(config)
    runner.batch_runner.analysis_stage = _PassthroughAnalysisStage()
    outer_extractor = _FailOriginalPathsThenRealExtractor({source})
    inner_extractor = None
    runner.batch_runner.extractor = outer_extractor
    try:
        first_roots = runner.batch_runner.execute([outer_task])
        assert first_roots
        inner_archive = next(Path(first_roots[0]).rglob(inner_name))

        error = "tar header checksum is damaged" if inner_format == "tar" else "synthetic structure failure before repair"
        inner_config = _coordinator_repair_attempt_config(tmp_path, modules=inner_modules)
        scanned_tasks = runner._scan_targets(first_roots)
        assert any(Path(task.main_path).resolve() == inner_archive.resolve() for task in scanned_tasks)
        inner_extractor = _FailOnceThenRealExtractor(error=error, failure_kind="structure_recognition")
        inner_runner = ExtractionBatchRunner(
            RunContext(),
            inner_extractor,
            NestedOutputScanPolicy({}),
            config=inner_config,
        )
        inner_task = _task(inner_archive, detected_ext=inner_format)
        _prepare_repair_task(inner_task, inner_format, flags)
        inner_out = inner_archive.with_suffix("")
        outcome = inner_runner._extract_verify_with_retries(
            inner_task,
            str(inner_out),
            runtime_scheduler=None,
        )
    finally:
        outer_extractor.close()
        if inner_extractor is not None:
            inner_extractor.close()
        runner.extractor.close()

    assert runner.context.success_count == 1
    assert outcome.success is True
    assert not runner.context.failed_tasks
    assert outer_task.fact_bag.get("repair.module") == "archive_nested_payload_salvage"
    assert outcome.repair_module == expected_module
    return inner_archive


def _prepare_repair_task(task: ArchiveTask, fmt: str, flags: list[str]) -> None:
    task.detected_ext = fmt
    task.fact_bag.set("file.detected_ext", f".{fmt.lstrip('.')}")
    task.fact_bag.set("analysis.selected_format", fmt)
    task.fact_bag.set("analysis.confidence", 0.82)
    _set_analysis_evidence(task, fmt, flags)


def _coordinator_repair_attempt_config(tmp_path: Path, *, modules: list[dict]) -> dict:
    return {
        "repair": {
            "enabled": True,
            "workspace": str(tmp_path / "repair-inner"),
            "max_repair_rounds_per_task": 1,
            "stages": {"deep": True},
            "deep": {"verify_candidates": False, "max_candidates_per_module": 4},
            "modules": modules,
            "beam": {"enabled": True, "max_rounds": 1},
        },
        "verification": {
            "enabled": True,
            "methods": [
                {"name": "extraction_exit_signal"},
                {"name": "output_presence"},
                {"name": "archive_test_crc"},
            ],
        },
    }


def _pipeline_runner_repair_config(tmp_path: Path, *, modules: list[dict], extensions: list[str]) -> dict:
    return normalize_config(with_detection_pipeline({
        "recursive_extract": "2",
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
        "repair": {
            "enabled": True,
            "workspace": str(tmp_path / "repair"),
            "max_attempts_per_task": 2,
            "max_repair_rounds_per_task": 2,
            "stages": {"deep": True},
            "deep": {"verify_candidates": False, "max_candidates_per_module": 4},
            "modules": modules,
            "beam": {"enabled": True, "max_rounds": 2},
        },
        "verification": _verification_config(),
    }, precheck=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
    ], scoring=[
        {
            "name": "extension",
            "enabled": True,
            "extension_score_groups": [{"score": 5, "extensions": list(extensions)}],
        },
    ]))


def _nested_salvage_pipeline_config(tmp_path: Path) -> dict:
    return normalize_config(with_detection_pipeline({
        "recursive_extract": "3",
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
        "repair": {
            "enabled": True,
            "workspace": str(tmp_path / "repair"),
            "max_attempts_per_task": 2,
            "max_repair_rounds_per_task": 2,
            "stages": {"deep": True},
            "deep": {"verify_candidates": False, "max_candidates_per_module": 4},
            "modules": [
                {"name": "archive_nested_payload_salvage", "enabled": True},
                {"name": "zip_deep_partial_recovery", "enabled": True},
            ],
            "beam": {"enabled": True, "max_rounds": 2},
        },
        "verification": _verification_config(),
    }, precheck=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
    ], scoring=[
        {
            "name": "extension",
            "enabled": True,
            "extension_score_groups": [{"score": 5, "extensions": [".zip", ".tar", ".7z", ".rar"]}],
        },
        {"name": "zip_structure_identity", "enabled": True},
    ]))


def _zip_bytes(entries: dict[str, bytes], *, compression: int = zipfile.ZIP_STORED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def _tar_bytes(entries: dict[str, bytes], *, corrupt_first_checksum: bool = False) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    data = bytearray(buffer.getvalue())
    if corrupt_first_checksum:
        data[148:156] = b"0000000\0"
    return bytes(data)


def _write_zip(path: Path, entries: dict[str, bytes]) -> None:
    path.write_bytes(_zip_bytes(entries))


def _extract_zip(path: Path, out_dir: Path) -> None:
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True)
    with zipfile.ZipFile(path) as archive:
        archive.extractall(out_dir)


def _raw_stored_local_entry(name: str, payload: bytes, *, crc32: int | None = None) -> bytes:
    encoded = name.encode("utf-8")
    crc = zlib.crc32(payload) & 0xFFFFFFFF if crc32 is None else crc32
    return (
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
            len(encoded),
            0,
        )
        + encoded
        + payload
    )


def _zip_with_cd_local_metadata_conflicts() -> bytes:
    bad_payload = b"bad-from-local"
    good_payload = b"good-from-local"
    first = _raw_stored_local_entry("safe.txt", bad_payload, crc32=0)
    second_offset = len(first)
    second = _raw_stored_local_entry("safe.txt", good_payload)
    local = first + second
    central = b"".join([
        _central_directory_entry(
            "../evil.txt",
            local_header_offset=second_offset,
            crc32=0,
            compressed_size=999,
            uncompressed_size=999,
        ),
        _central_directory_entry(
            "safe.txt",
            local_header_offset=0,
            crc32=0,
            compressed_size=len(bad_payload),
            uncompressed_size=len(bad_payload),
        ),
    ])
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        2,
        2,
        len(central),
        len(local),
        0,
    )
    return local + central + eocd


def _central_directory_entry(
    name: str,
    *,
    local_header_offset: int,
    crc32: int,
    compressed_size: int,
    uncompressed_size: int,
) -> bytes:
    encoded = name.encode("utf-8")
    return (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            0,
            0,
            0,
            0,
            crc32,
            compressed_size,
            uncompressed_size,
            len(encoded),
            0,
            0,
            0,
            0,
            0,
            local_header_offset,
        )
        + encoded
    )


def _zip_name_conflict_key(name: str) -> str:
    import unicodedata

    normalized = name.replace("\\", "/").lstrip("/")
    folded = unicodedata.normalize("NFKD", normalized).encode("ascii", "ignore").decode("ascii")
    return folded.casefold()


def _windows_reserved_base(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1].split(".", 1)[0]
    return base.rstrip(" .").upper()


def _build_7z_archive(tmp_path: Path, entries: dict[str, bytes]) -> Path:
    seven_zip = _require_7z_tool_or_skip()
    source_dir = tmp_path / "seven-src"
    source_dir.mkdir(parents=True)
    for name, payload in entries.items():
        target = source_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    output = tmp_path / "inner.7z"
    subprocess.run(
        [str(seven_zip), "a", "-t7z", str(output.resolve()), *entries.keys()],
        cwd=str(source_dir),
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return output


def _build_rar_archive(tmp_path: Path, rar: Path, entries: dict[str, bytes]) -> Path:
    source_dir = tmp_path / "rar-src"
    source_dir.mkdir(parents=True)
    for name, payload in entries.items():
        target = source_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    output = tmp_path / "inner.rar"
    subprocess.run(
        [str(rar), "a", "-ep", str(output.resolve()), *entries.keys()],
        cwd=str(source_dir),
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return output


def _require_7z_tool_or_skip() -> Path:
    candidate = Path("tools") / "7z.exe"
    if candidate.is_file():
        return candidate.resolve()
    found = shutil.which("7z")
    if found:
        return Path(found)
    pytest.skip("7z executable is required for coordinator real worker coverage")


def _require_worker_or_skip() -> None:
    missing = [
        name
        for name in ("sevenzip_worker.exe", "7z.dll")
        if not (Path("tools") / name).is_file()
    ]
    if missing:
        pytest.skip(f"{', '.join(missing)} is required for coordinator real worker coverage")
