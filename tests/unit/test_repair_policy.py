import sys
import types
from dataclasses import replace
from pathlib import Path

import pytest

from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.repair_runtime_transition import RepairRuntimeTransitionEvaluator
from sunpack.coordinator.repair_stage import ArchiveRepairStage
from sunpack.extraction.result import ExtractionResult
from sunpack.repair.candidate import RepairCandidate, RepairCandidateBatch
from sunpack.repair.config import normalize_repair_config
from sunpack.repair.job import RepairJob
from sunpack.repair.policy.runtime_features import policy_candidate_payload
from sunpack.repair.scheduler import RepairScheduler
from sunpack.verification.result import ArchiveCoverageSummary, VerificationResult


@pytest.fixture(autouse=True)
def _skip_module_discovery(monkeypatch):
    monkeypatch.setattr("sunpack.repair.scheduler.discover_repair_modules", lambda: None)


def test_repair_policy_config_normalizes_defaults():
    config = normalize_repair_config({"policy": {"enabled": "true", "strict_provider_errors": "false"}})

    assert config["policy"]["enabled"] is True
    assert config["policy"]["fallback_to_selector"] is True
    assert config["policy"]["disable_beam_when_model_active"] is True
    assert config["policy"]["strict_provider_errors"] is False
    assert config["policy"]["provider_package"] == "sunpack_repair_models"


def test_missing_policy_package_falls_back_to_selector(tmp_path):
    first = _candidate("first", tmp_path / "first.zip", confidence=0.95)
    second = _candidate("second", tmp_path / "second.zip", confidence=0.1)
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_missing_package"},
        }
    })
    scheduler.generate_repair_candidates = lambda job: RepairCandidateBatch(candidates=[first, second])  # type: ignore[method-assign]

    result = scheduler.repair(_job(tmp_path))

    assert result.ok
    assert result.module_name == "first"
    assert result.diagnosis["candidate_selection"]["policy"]["fallback_reason"] == "policy_unavailable"
    assert result.diagnosis["candidate_selection"]["policy_fallback"] is True


def test_zip_policy_provider_selects_candidate_without_selector(tmp_path, monkeypatch):
    _install_policy_package(monkeypatch, "sunpack_policy_test_zip", _IndexProvider(selected_index=1))
    first = _candidate("selector_would_prefer", tmp_path / "first.zip", confidence=0.95)
    second = _candidate("model_choice", tmp_path / "second.zip", confidence=0.1)
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_zip"},
        }
    })
    scheduler.generate_repair_candidates = lambda job: RepairCandidateBatch(candidates=[first, second])  # type: ignore[method-assign]

    result = scheduler.repair(_job(tmp_path))

    assert result.ok
    assert result.module_name == "model_choice"
    selection = result.diagnosis["candidate_selection"]
    assert selection["policy"]["decision_status"] == "selected"
    assert selection["policy"]["provider_id"] == "test_zip_policy"
    assert "ltr_features" not in selection["candidates"][0]
    assert "runtime_context" in selection["candidates"][0]
    assert "candidate_proposal" in selection["candidates"][0]


def test_invalid_policy_decision_falls_back_to_selector(tmp_path, monkeypatch):
    _install_policy_package(monkeypatch, "sunpack_policy_test_invalid", _IndexProvider(selected_index=99))
    first = _candidate("selector_choice", tmp_path / "first.zip", confidence=0.95)
    second = _candidate("other", tmp_path / "second.zip", confidence=0.1)
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_invalid"},
        }
    })
    scheduler.generate_repair_candidates = lambda job: RepairCandidateBatch(candidates=[first, second])  # type: ignore[method-assign]

    result = scheduler.repair(_job(tmp_path))

    assert result.ok
    assert result.module_name == "selector_choice"
    assert result.diagnosis["candidate_selection"]["policy"]["decision_status"] == "fallback"
    assert result.diagnosis["candidate_selection"]["policy_fallback"] is True


def test_policy_contract_miss_falls_back_to_selector(tmp_path, monkeypatch):
    provider = _IndexProvider(selected_index=1)
    provider.supported_feature_contract_version = 999
    provider.required_payload_sections = ("runtime_context", "candidate_proposal")
    _install_policy_package(monkeypatch, "sunpack_policy_test_contract", provider)
    first = _candidate("selector_choice", tmp_path / "first.zip", confidence=0.95)
    second = _candidate("model_choice", tmp_path / "second.zip", confidence=0.1)
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_contract"},
        }
    })
    scheduler.generate_repair_candidates = lambda job: RepairCandidateBatch(candidates=[first, second])  # type: ignore[method-assign]

    result = scheduler.repair(_job(tmp_path))

    assert result.ok
    assert result.module_name == "selector_choice"
    policy = result.diagnosis["candidate_selection"]["policy"]
    assert policy["decision_status"] == "fallback"
    assert "feature_contract_miss" in ";".join(policy["provider_errors"])


def test_zip_policy_active_disables_beam_for_zip_only(tmp_path, monkeypatch):
    _install_policy_package(monkeypatch, "sunpack_policy_test_beam", _IndexProvider(selected_index=0))
    stage = ArchiveRepairStage({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_beam"},
        }
    })
    zip_task = _task(tmp_path / "broken.zip", fmt="zip")
    tar_task = _task(tmp_path / "broken.tar", fmt="tar")
    result = ExtractionResult(success=True, archive=zip_task.main_path, out_dir=str(tmp_path / "out"), all_parts=[zip_task.main_path])
    verification = _verification()

    assert stage.policy_active_for_verification(zip_task, result, verification) is True
    tar_result = ExtractionResult(success=True, archive=tar_task.main_path, out_dir=str(tmp_path / "out2"), all_parts=[tar_task.main_path])
    assert stage.policy_active_for_verification(tar_task, tar_result, verification) is False


def test_policy_candidate_payload_matches_training_minimal_shape_without_oracle(tmp_path):
    candidate = _candidate("zip_resolve_duplicate_entries", tmp_path / "fixed.zip", confidence=0.5)
    candidate = replace(
        candidate,
        diagnosis={
            "repair_name": "zip_resolve_duplicate_entries",
            "atomic_action_group": "duplicate_conflict",
            "route_family": "conflict",
            "native_key": "duplicate_policy_crc_match",
            "native_target": "duplicate_entries",
            "candidate_status": "complete",
            "patch_facts": ["resolved_duplicate_entries", "kept_entry_policy=crc_match"],
            "validation_details": {
                "policy": "crc_match",
                "duplicate_group_count": 1,
                "kept_entry_crc_match_count": 1,
                "kept_payload_verified_count": 1,
                "dropped_entry_count": 1,
            },
        },
    )
    job = _job(tmp_path)
    job = replace(
        job,
        attempts=2,
        analysis_prepass={
            "status": "ok",
            "selected_format": "zip",
            "zip_structure_features": {"has_duplicate_entries": True},
            "zip_container_tags": ["split_archive"],
            "fuzzy": {
                "binary_profile": {
                    "entropy_profile": {"head_entropy": 7.1, "overall_class": "binary"},
                    "byte_class_profile": {"head": {"printable_ratio": 0.2}},
                }
            },
        },
        extraction_failure={
            "status": "failed",
            "decision_hint": "repair",
            "archive_coverage": {"completeness": 0.5, "expected_files": 2, "matched_files": 1},
        },
        repair_history={
            "route_evidence_flags": ["duplicate_entries"],
            "repair_history_flags": ["after_cd_rebuild"],
            "residual_damage_flags": ["exact_match_failed"],
            "runtime_state_summary": {"directory_detected": True, "entry_count": 2},
            "source_derivation": {
                "zip_structure_features": {"has_duplicate_entries": True},
                "zip_container_tags": ["split_archive"],
                "zip_variant": "data_descriptor",
            },
        },
    )

    payload = policy_candidate_payload(job, candidate, index=3)

    assert payload["feature_contract_version"] == 3
    assert payload["round"] == 2
    assert payload["current_rank"] == 3
    assert payload["runtime_context"]["analysis_native_probe"]["has_duplicate_entries"] is True
    assert payload["runtime_context"]["analysis_native_probe"]["route_evidence_duplicate_entries"] == 1
    assert payload["runtime_context"]["job_summary"]["residual_damage_flags"] == ["exact_match_failed"]
    assert payload["candidate_proposal"]["validation_details"]["policy"] == "crc_match"
    assert payload["candidate_proposal"]["validation_details"]["kept_entry_crc_match_count"] == 1
    assert not _contains_forbidden_policy_key(payload)


def test_runtime_transition_evaluator_applies_candidate_and_restores_task(tmp_path):
    task = _task(tmp_path / "broken.zip", fmt="zip")
    original_digest = task.archive_state().effective_patch_digest()
    candidate = _candidate("zip_fix_cd_offset", tmp_path / "fixed.zip", confidence=0.5)
    extracted = ExtractionResult(success=True, archive=task.main_path, out_dir=str(tmp_path / "out"), all_parts=[task.main_path])
    extractor = _FakeExtractor(extracted)
    verifier = _FakeVerifier(_verification())
    stage = ArchiveRepairStage({"repair": {"workspace": str(tmp_path / "repair"), "policy": {"enabled": False}}})
    evaluator = RepairRuntimeTransitionEvaluator(
        extractor=extractor,
        verifier=verifier,
        repair_stage=stage,
        source_digest=lambda payload: "digest",
    )

    transition = evaluator.evaluate(task, candidate, temp_dir=tmp_path / "eval")

    assert transition.result is extracted
    assert transition.verification.decision_hint == "repair"
    assert transition.source_digest == "digest"
    assert task.archive_state().effective_patch_digest() == original_digest
    assert extractor.seen_archive_states


class _IndexProvider:
    provider_id = "test_zip_policy"
    supported_formats = ("zip",)

    def __init__(self, *, selected_index: int):
        self.selected_index = selected_index

    def available(self):
        return True

    def choose(self, request):
        return {
            "selected_index": self.selected_index,
            "confidence": 0.9,
            "metadata": {
                "model_id": "test",
                "private_score": 123.0,
            },
        }


class _FakeExtractor:
    def __init__(self, result):
        self.result = result
        self.seen_archive_states = []

    def extract(self, task, out_dir, runtime_scheduler=None):
        self.seen_archive_states.append(task.archive_state().effective_patch_digest())
        self.result.out_dir = str(out_dir)
        return self.result


class _FakeVerifier:
    config = {}

    def __init__(self, verification):
        self.verification = verification

    def verify(self, task, result):
        return self.verification


def _install_policy_package(monkeypatch, name: str, provider) -> None:
    module = types.ModuleType(name)
    module.get_repair_policy_providers = lambda: [provider]
    monkeypatch.setitem(sys.modules, name, module)


def _candidate(module: str, path: Path, *, confidence: float) -> RepairCandidate:
    path.write_bytes(module.encode("utf-8"))
    return RepairCandidate(
        module_name=module,
        format="zip",
        repaired_input={"kind": "file", "path": str(path), "format_hint": "zip"},
        confidence=confidence,
        actions=[module],
        workspace_paths=[str(path)],
    )


def _job(tmp_path: Path) -> RepairJob:
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")
    return RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "zip"},
        format="zip",
        archive_key="source",
        workspace=str(tmp_path / "repair"),
        extraction_failure={"status": "failed"},
    )


def _task(path: Path, *, fmt: str) -> ArchiveTask:
    path.write_bytes(b"broken")
    bag = FactBag()
    bag.set("analysis.selected_format", fmt)
    return ArchiveTask(
        fact_bag=bag,
        score=10,
        key=path.name,
        main_path=str(path),
        all_parts=[str(path)],
        logical_name=path.stem,
        detected_ext=fmt,
    ).ensure_archive_state()


def _verification() -> VerificationResult:
    return VerificationResult(
        completeness=0.5,
        recoverable_upper_bound=1.0,
        assessment_status="partial",
        source_integrity="complete",
        decision_hint="repair",
        archive_coverage=ArchiveCoverageSummary(
            completeness=0.5,
            file_coverage=0.5,
            byte_coverage=0.5,
            expected_files=1,
            matched_files=0,
            complete_files=0,
            confidence=0.5,
        ),
    )


def _contains_forbidden_policy_key(value) -> bool:
    forbidden = ("oracle", "future_return", "terminal_reward")
    if isinstance(value, dict):
        for key, item in value.items():
            text = str(key).lower()
            if any(token in text for token in forbidden):
                return True
            if text in {"label", "reward"}:
                return True
            if _contains_forbidden_policy_key(item):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden_policy_key(item) for item in value)
    return False
