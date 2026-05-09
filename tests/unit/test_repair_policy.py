import sys
import types
from pathlib import Path

import pytest

from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.repair_stage import ArchiveRepairStage
from sunpack.extraction.result import ExtractionResult
from sunpack.repair.candidate import RepairCandidate, RepairCandidateBatch
from sunpack.repair.config import normalize_repair_config
from sunpack.repair.job import RepairJob
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
