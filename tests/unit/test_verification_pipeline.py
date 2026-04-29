from smart_unpacker.config.schema import normalize_config
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.passwords import PasswordSession
from smart_unpacker.verification import (
    FileVerificationObservation,
    VerificationScheduler,
    VerificationStepResult,
    register_verification_method,
)
from smart_unpacker.verification.result import VerificationIssue


CALLS = []


@register_verification_method("unit_complete_observation")
class UnitCompleteObservationMethod:
    def verify(self, evidence, config):
        CALLS.append(config["name"])
        return VerificationStepResult(
            method=config["name"],
            completeness_hint=float(config.get("completeness", 1.0)),
            source_integrity_hint=config.get("source_integrity", "complete"),
            decision_hint=config.get("decision_hint", "none"),
            file_observations=[
                FileVerificationObservation(path="inside.txt", archive_path="inside.txt", state="complete", progress=1.0)
            ],
        )


@register_verification_method("unit_missing_observation")
class UnitMissingObservationMethod:
    def verify(self, evidence, config):
        CALLS.append(config["name"])
        issue = VerificationIssue(method=config["name"], code="fail.unit_missing", message="missing", path="missing.bin")
        return VerificationStepResult(
            method=config["name"],
            status="warning",
            completeness_hint=0.5,
            decision_hint="repair",
            issues=[issue],
            file_observations=[
                FileVerificationObservation(path="inside.txt", archive_path="inside.txt", state="complete", progress=1.0),
                FileVerificationObservation(path="missing.bin", archive_path="missing.bin", state="missing", progress=0.0, issues=[issue]),
            ],
        )


@register_verification_method("unit_password_assessment")
class UnitPasswordAssessmentMethod:
    def verify(self, evidence, config):
        if evidence.password == config.get("expected_password"):
            return VerificationStepResult(method=config["name"], completeness_hint=1.0, decision_hint="accept")
        return VerificationStepResult(
            method=config["name"],
            completeness_hint=0.0,
            decision_hint="repair",
            issues=[
                VerificationIssue(
                    method=config["name"],
                    code="fail.password_mismatch",
                    message="Verification evidence password did not match",
                    expected=config.get("expected_password"),
                    actual=evidence.password,
                )
            ],
        )


def test_verification_scheduler_disabled_returns_disabled_assessment(tmp_path):
    CALLS.clear()
    task, result = _task_and_result(tmp_path)
    scheduler = VerificationScheduler({
        "verification": {
            "enabled": False,
            "methods": [{"name": "unit_complete_observation", "enabled": True}],
        }
    })

    verification = scheduler.verify(task, result)

    assert verification.assessment_status == "disabled"
    assert verification.decision_hint == "accept"
    assert verification.completeness == 1.0
    assert CALLS == []


def test_verification_scheduler_disabled_routes_failed_extraction_to_repair(tmp_path):
    CALLS.clear()
    task, result = _task_and_result(tmp_path)
    result = ExtractionResult(
        success=False,
        archive=result.archive,
        out_dir=result.out_dir,
        all_parts=result.all_parts,
        error="fatal archive damage",
    )
    scheduler = VerificationScheduler({
        "verification": {
            "enabled": False,
            "methods": [{"name": "unit_complete_observation", "enabled": True}],
        }
    })

    verification = scheduler.verify(task, result)

    assert verification.assessment_status == "disabled"
    assert verification.decision_hint == "repair"
    assert verification.completeness == 0.0
    assert CALLS == []


def test_verification_pipeline_aggregates_completeness_and_decision(tmp_path):
    CALLS.clear()
    task, result = _task_and_result(tmp_path)
    scheduler = VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": [
                {"name": "unit_complete_observation", "enabled": True, "completeness": 1.0},
                {"name": "unit_missing_observation", "enabled": True},
            ],
        }
    })

    verification = scheduler.verify(task, result)

    assert verification.decision_hint == "repair"
    assert verification.assessment_status == "inconsistent"
    assert verification.completeness == 0.5
    assert verification.complete_files == 1
    assert verification.missing_files == 1
    assert CALLS == ["unit_complete_observation", "unit_missing_observation"]


def test_verification_evidence_uses_password_session_when_result_has_no_password(tmp_path):
    task, result = _task_and_result(tmp_path)
    session = PasswordSession()
    session.set_resolved("sample-key", "secret")
    scheduler = VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": [
                {"name": "unit_password_assessment", "enabled": True, "expected_password": "secret"},
            ],
        }
    }, password_session=session)

    verification = scheduler.verify(task, result)

    assert verification.decision_hint == "accept"
    assert verification.completeness == 1.0


def test_verification_evidence_uses_archive_password_fact_when_session_has_none(tmp_path):
    task, result = _task_and_result(tmp_path)
    task.fact_bag.set("archive.password", "secret")
    scheduler = VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": [
                {"name": "unit_password_assessment", "enabled": True, "expected_password": "secret"},
            ],
        }
    })

    verification = scheduler.verify(task, result)

    assert verification.decision_hint == "accept"
    assert verification.completeness == 1.0


def test_verification_config_supplies_completeness_threshold_defaults():
    config = normalize_config({
        "recursive_extract": "1",
        "verification": {
            "enabled": True,
            "methods": [{"name": "unit_complete_observation"}],
        },
    })

    assert config["verification"]["enabled"] is True
    assert config["verification"]["complete_accept_threshold"] == 0.999
    assert config["verification"]["partial_accept_threshold"] == 0.2
    assert config["verification"]["methods"][0]["enabled"] is True


def _task_and_result(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    out_dir = tmp_path / "sample"
    out_dir.mkdir()
    (out_dir / "inside.txt").write_text("hello", encoding="utf-8")
    bag = FactBag()
    bag.set("resource.health", {"is_archive": True})
    bag.set("resource.analysis", {"file_count": 1, "total_unpacked_size": 5})
    task = ArchiveTask(fact_bag=bag, score=10, key="sample-key", main_path=str(archive), all_parts=[str(archive)])
    result = ExtractionResult(success=True, archive=str(archive), out_dir=str(out_dir), all_parts=[str(archive)])
    return task, result
