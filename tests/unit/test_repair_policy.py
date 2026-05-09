import sys
import types
import json
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
from sunpack.support import archive_knowledge_projection as knowledge_view
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
    _install_policy_package(monkeypatch, "sunpack_policy_test_zip", _CandidateIdProvider(selected_module="model_choice"))
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
    assert selection["policy"]["selected_candidate_id"]
    assert selection["policy"]["selected_candidate_id_valid"] is True
    assert "ltr_features" not in selection["candidates"][0]
    assert "runtime_context" in selection["candidates"][0]
    assert "candidate_proposal" in selection["candidates"][0]


def test_policy_probe_writes_public_request_and_decision(tmp_path, monkeypatch):
    _install_policy_package(monkeypatch, "sunpack_policy_test_probe", _CandidateIdProvider(selected_module="model_choice"))
    probe_path = tmp_path / "policy_probe.jsonl"
    monkeypatch.setenv("SUNPACK_REPAIR_POLICY_PROBE_JSONL", str(probe_path))
    monkeypatch.setenv("SUNPACK_REPAIR_POLICY_PROBE_RUN_ID", "probe-run")
    first = _candidate("selector_would_prefer", tmp_path / "first.zip", confidence=0.95)
    second = _candidate("model_choice", tmp_path / "second.zip", confidence=0.1)
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_probe"},
        }
    })
    scheduler.generate_repair_candidates = lambda job: RepairCandidateBatch(candidates=[first, second])  # type: ignore[method-assign]

    result = scheduler.repair(_job(tmp_path))

    assert result.ok
    events = [json.loads(line) for line in probe_path.read_text(encoding="utf-8").splitlines()]
    assert [event["event"] for event in events] == [
        "policy_probe_request",
        "policy_probe_decision",
        "policy_probe_selected_result",
    ]
    request = events[0]
    decision = events[1]
    assert request["run_id"] == "probe-run"
    assert request["candidate_set_hash"]
    assert request["candidate_payloads"][0]["runtime_context"]
    assert "label" not in json.dumps(request, ensure_ascii=False)
    assert decision["policy"]["decision_status"] == "selected"
    assert decision["policy"]["selected_candidate_id"]
    assert decision["selected_candidate"]["module_name"] == "model_choice"


def test_legacy_selected_index_policy_decision_falls_back_to_selector(tmp_path, monkeypatch):
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
    assert result.diagnosis["candidate_selection"]["policy"]["invalid_candidate_id_reason"] == "invalid_policy_decision_legacy_selected_index"
    assert result.diagnosis["candidate_selection"]["policy_fallback"] is True


def test_invalid_candidate_id_policy_decision_falls_back_to_selector(tmp_path, monkeypatch):
    _install_policy_package(monkeypatch, "sunpack_policy_test_invalid_id", _CandidateIdProvider(selected_candidate_id="missing"))
    first = _candidate("selector_choice", tmp_path / "first.zip", confidence=0.95)
    second = _candidate("other", tmp_path / "second.zip", confidence=0.1)
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_invalid_id"},
        }
    })
    scheduler.generate_repair_candidates = lambda job: RepairCandidateBatch(candidates=[first, second])  # type: ignore[method-assign]

    result = scheduler.repair(_job(tmp_path))

    assert result.ok
    assert result.module_name == "selector_choice"
    assert result.diagnosis["candidate_selection"]["policy"]["decision_status"] == "fallback"
    assert result.diagnosis["candidate_selection"]["policy"]["invalid_candidate_id_reason"] == "invalid_candidate_id"
    assert result.diagnosis["candidate_selection"]["policy_fallback"] is True


def test_duplicate_candidate_id_blocks_policy_selection(tmp_path, monkeypatch):
    _install_policy_package(monkeypatch, "sunpack_policy_test_duplicate_ids", _CandidateIdProvider(selected_candidate_id="same"))
    monkeypatch.setattr(
        "sunpack.repair.scheduler._policy_candidate_payload",
        lambda job, candidate, index=0: {
            "feature_contract_version": 3,
            "candidate_id": "same",
            "module_name": candidate.module_name,
            "module": candidate.module_name,
            "runtime_context": {},
            "candidate_proposal": {},
        },
    )
    first = _candidate("selector_choice", tmp_path / "first.zip", confidence=0.95)
    second = _candidate("model_choice", tmp_path / "second.zip", confidence=0.1)
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_duplicate_ids"},
        }
    })
    scheduler.generate_repair_candidates = lambda job: RepairCandidateBatch(candidates=[first, second])  # type: ignore[method-assign]

    result = scheduler.repair(_job(tmp_path))

    assert result.ok
    assert result.module_name == "selector_choice"
    policy = result.diagnosis["candidate_selection"]["policy"]
    assert policy["decision_status"] == "fallback"
    assert policy["fallback_reason"] == "duplicate_candidate_id"
    assert policy["duplicate_candidate_id_count"] == 1
    assert result.diagnosis["candidate_selection"]["policy_fallback"] is True


def test_policy_contract_miss_falls_back_to_selector(tmp_path, monkeypatch):
    provider = _CandidateIdProvider(selected_module="model_choice")
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
    _install_policy_package(monkeypatch, "sunpack_policy_test_beam", _CandidateIdProvider(selected_module="zip"))
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
    knowledge = dict(job.knowledge)
    knowledge.update({
        "analysis": {
            "summary": {"format": "zip", "confidence": 0.5},
            "prepass": {
                "status": "ok",
                "selected_format": "zip",
                "fuzzy": {
                    "binary_profile": {
                        "entropy_profile": {"head_entropy": 7.1, "overall_class": "binary"},
                        "byte_class_profile": {"head": {"printable_ratio": 0.2}},
                    }
                },
            },
            "fuzzy": {
                "entropy_profile": {"head_entropy": 7.1, "overall_class": "binary"},
                "byte_class_profile": {"head": {"printable_ratio": 0.2}},
            },
        },
        "format": {"zip": {"structure": {"has_duplicate_entries": True}, "container_tags": ["split_archive"], "route_evidence_flags": ["duplicate_entries"]}},
        "extraction": {
            "failure": {
                "status": "failed",
                "decision_hint": "repair",
                "archive_coverage": {"completeness": 0.5, "expected_files": 2, "matched_files": 1},
            }
        },
        "repair": {
            "route_evidence": {"flags": ["duplicate_entries"]},
            "history": {
                "items": [],
                "repair_history_flags": ["after_cd_rebuild"],
                "residual_damage_flags": ["exact_match_failed"],
                "runtime_state_summary": {"directory_detected": True, "entry_count": 2},
            },
            "residual": {"flags": ["exact_match_failed"]},
        },
    })
    job = replace(
        job,
        attempts=2,
        knowledge=knowledge,
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
    task.set_knowledge({"test": {"stable": True}})
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
    restored_knowledge = task.knowledge().to_dict()
    assert restored_knowledge["test"]["stable"] is True
    assert "verification" not in restored_knowledge
    assert extractor.seen_archive_states


def test_runtime_repair_job_includes_descriptor_route_evidence(tmp_path):
    task = _task(tmp_path / "descriptor.zip", fmt="zip")
    _write_source_derivation(
        task,
        damage_profile="zip_data_descriptor_cd_conflict",
        zip_structure_features={"has_data_descriptor": True},
        zip_container_tags=["data_descriptor", "bit3"],
    )
    stage = ArchiveRepairStage({"repair": {"workspace": str(tmp_path / "repair"), "policy": {"enabled": False}}})
    job = stage._job_from_verification_assessment(task, _failed_extraction(task), _verification())  # noqa: SLF001

    assert job is not None
    assert "data_descriptor" in job.damage_flags
    assert "central_directory_offset_bad" in job.damage_flags
    assert "spurious_data_descriptor_candidate" in job.damage_flags
    assert "data_descriptor" in knowledge_view.repair_route_context(job.knowledge)["route_evidence_flags"]


def test_runtime_features_do_not_backfill_missing_archive_knowledge_from_job_fields(tmp_path):
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")
    job = RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "zip"},
        format="zip",
        analysis_prepass={"status": "ok", "selected_format": "zip"},
        extraction_failure={"status": "failed", "decision_hint": "repair"},
        damage_flags=["data_descriptor"],
        repair_history={"route_evidence_flags": ["data_descriptor"]},
        knowledge={},
    )

    payload = policy_candidate_payload(job, _candidate("zip_salvage_verified_entries", tmp_path / "fixed.zip", confidence=0.5), index=0)

    assert "source.input" in payload["runtime_context"]["knowledge_projection"]["feature_contract_miss"]
    assert payload["runtime_context"]["job_summary"]["route_evidence_flags"] == []


def test_runtime_features_source_has_no_legacy_repair_job_fallbacks():
    source = Path("sunpack/repair/policy/runtime_features.py").read_text(encoding="utf-8")
    forbidden = [
        "project_knowledge_sources",
        "_set_if_missing",
        "_feature_payload_sources",
        "_verification_summary_from_failure",
        'getattr(job, "source_input"',
        'getattr(job, "analysis_prepass"',
        'getattr(job, "extraction_failure"',
        'getattr(job, "repair_history"',
        'getattr(job, "damage_flags"',
    ]

    for token in forbidden:
        assert token not in source


def test_runtime_repair_job_includes_non_utf8_route_evidence(tmp_path):
    task = _task(tmp_path / "names.zip", fmt="zip")
    _write_source_derivation(
        task,
        damage_profile="zip_non_utf8_filename_directory_rebuild",
        zip_structure_features={"has_filename_encoding_risk": True},
        zip_container_tags=["filename_encoding", "non_utf8_names"],
    )
    stage = ArchiveRepairStage({"repair": {"workspace": str(tmp_path / "repair"), "policy": {"enabled": False}}})
    job = stage._job_from_verification_assessment(task, _failed_extraction(task), _verification())  # noqa: SLF001

    assert job is not None
    assert "filename_encoding_bad" in job.damage_flags
    assert "raw_filename_bytes" in job.damage_flags


def test_runtime_repair_job_preserves_split_sidecars_without_unavailable_flag(tmp_path):
    task = _task(tmp_path / "split.zip", fmt="zip")
    part = tmp_path / "split.z01"
    part.write_bytes(b"part")
    task.all_parts = [task.main_path, str(part)]
    task.split_info.parts = list(task.all_parts)
    task.split_info.is_split = True
    task.set_archive_state(task.archive_state())
    _write_source_derivation(
        task,
        damage_profile="zip_split_missing_middle_volume",
        zip_structure_features={"has_split_sidecars": True},
    )
    stage = ArchiveRepairStage({"repair": {"workspace": str(tmp_path / "repair"), "policy": {"enabled": False}}})
    job = stage._job_from_verification_assessment(task, _failed_extraction(task), _verification())  # noqa: SLF001

    assert job is not None
    assert job.source_input.get("parts")
    assert "split_sidecars_available" in job.damage_flags
    assert "missing_volume_unavailable" not in job.damage_flags


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


class _CandidateIdProvider:
    provider_id = "test_zip_policy"
    supported_formats = ("zip",)

    def __init__(self, *, selected_module: str = "", selected_candidate_id: str = ""):
        self.selected_module = selected_module
        self.selected_candidate_id = selected_candidate_id

    def available(self):
        return True

    def choose(self, request):
        selected_candidate_id = self.selected_candidate_id
        if not selected_candidate_id:
            for payload in getattr(request, "candidate_payloads", []) or []:
                if str(payload.get("module_name") or payload.get("module") or "") == self.selected_module:
                    selected_candidate_id = str(payload.get("candidate_id") or "")
                    break
        return {
            "selected_candidate_id": selected_candidate_id,
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
    knowledge = {
        "source": {"input": {"kind": "file", "path": str(source), "format_hint": "zip"}},
        "analysis": {"summary": {"format": "zip", "confidence": 0.5}},
        "extraction": {"failure": {"status": "failed"}},
        "verification": {"summary": {"decision_hint": "repair", "completeness": 0.0}},
        "repair": {"history": {"items": []}},
    }
    return RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "zip"},
        format="zip",
        archive_key="source",
        workspace=str(tmp_path / "repair"),
        extraction_failure={"status": "failed"},
        knowledge=knowledge,
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


def _write_source_derivation(task: ArchiveTask, **payload) -> None:
    knowledge = task.knowledge()
    knowledge.set("source.derivation", payload, source_layer="test", source_module="fixture")
    structure = payload.get("zip_structure_features")
    if isinstance(structure, dict):
        knowledge.set("format.zip.structure", structure, source_layer="test", source_module="fixture")
    tags = payload.get("zip_container_tags")
    if isinstance(tags, list):
        knowledge.set("format.zip.container_tags", tags, source_layer="test", source_module="fixture")
    if payload.get("damage_profile"):
        knowledge.set("source.profile", payload.get("damage_profile"), source_layer="test", source_module="fixture")
    task.set_knowledge(knowledge)


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


def _failed_extraction(task: ArchiveTask) -> ExtractionResult:
    return ExtractionResult(
        success=False,
        archive=task.main_path,
        out_dir="",
        all_parts=task.all_parts,
        error="archive is damaged",
        diagnostics={"result": {"status": "failed", "failure_stage": "extract", "failure_kind": "data_error"}},
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
