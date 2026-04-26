from smart_unpacker.config.schema import normalize_config
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.passwords import PasswordSession
from smart_unpacker.verification import (
    VerificationStepResult,
    VerificationScheduler,
    register_verification_method,
)
from smart_unpacker.verification.result import VerificationIssue


CALLS = []


@register_verification_method("unit_score_delta")
class UnitScoreDeltaMethod:
    def verify(self, evidence, config):
        CALLS.append(config["name"])
        return VerificationStepResult(
            method=config["name"],
            score_delta=int(config.get("score_delta", 0)),
            issues=[VerificationIssue(method=config["name"], code="warning.unit", message="unit")],
        )


@register_verification_method("unit_hard_fail")
class UnitHardFailMethod:
    def verify(self, evidence, config):
        CALLS.append(config["name"])
        return VerificationStepResult(
            method=config["name"],
            score_delta=int(config.get("score_delta", 0)),
            hard_fail=True,
            issues=[VerificationIssue(method=config["name"], code="fail.unit", message="unit fail")],
        )


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


def test_verification_scheduler_disabled_returns_disabled_without_running_methods(tmp_path):
    CALLS.clear()
    task, result = _task_and_result(tmp_path)
    scheduler = VerificationScheduler({
        "verification": {
            "enabled": False,
            "methods": [{"name": "unit_score_delta", "enabled": True, "score_delta": -100}],
        }
    })

    verification = scheduler.verify(task, result)

    assert verification.ok is True
    assert verification.status == "disabled"
    assert CALLS == []


def test_verification_pipeline_runs_methods_in_config_order_and_scores(tmp_path):
    CALLS.clear()
    task, result = _task_and_result(tmp_path)
    scheduler = VerificationScheduler({
        "verification": {
            "enabled": True,
            "initial_score": 100,
            "pass_threshold": 70,
            "fail_fast_threshold": 40,
            "methods": [
                {"name": "unit_score_delta", "enabled": True, "score_delta": -10},
                {"name": "unit_score_delta", "enabled": True, "score_delta": -15},
            ],
        }
    })

    verification = scheduler.verify(task, result)

    assert verification.ok is True
    assert verification.status == "passed"
    assert verification.score == 75
    assert CALLS == ["unit_score_delta", "unit_score_delta"]


def test_verification_pipeline_fails_fast_when_score_drops_below_threshold(tmp_path):
    CALLS.clear()
    task, result = _task_and_result(tmp_path)
    scheduler = VerificationScheduler({
        "verification": {
            "enabled": True,
            "initial_score": 100,
            "pass_threshold": 70,
            "fail_fast_threshold": 50,
            "methods": [
                {"name": "unit_score_delta", "enabled": True, "score_delta": -60},
                {"name": "unit_score_delta", "enabled": True, "score_delta": 0},
            ],
        }
    })

    verification = scheduler.verify(task, result)

    assert verification.ok is False
    assert verification.status == "failed_fast"
    assert verification.score == 40
    assert CALLS == ["unit_score_delta"]


def test_verification_pipeline_hard_fail_stops_immediately(tmp_path):
    CALLS.clear()
    task, result = _task_and_result(tmp_path)
    scheduler = VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": [
                {"name": "unit_hard_fail", "enabled": True, "score_delta": -1},
                {"name": "unit_score_delta", "enabled": True, "score_delta": 0},
            ],
        }
    })

    verification = scheduler.verify(task, result)

    assert verification.ok is False
    assert verification.status == "failed"
    assert CALLS == ["unit_hard_fail"]


def test_verification_evidence_uses_password_session_when_result_has_no_password(tmp_path):
    task, result = _task_and_result(tmp_path)
    session = PasswordSession()
    session.set_resolved("sample-key", "secret")
    scheduler = VerificationScheduler({"verification": {"enabled": True}}, password_session=session)

    verification = scheduler.verify(task, result)

    assert verification.ok is True
    assert verification.status == "passed"


def test_verification_config_is_normalized():
    config = normalize_config({
        "recursive_extract": "1",
        "verification": {
            "enabled": True,
            "methods": [{"name": "unit_score_delta", "score_delta": -1}],
        },
    })

    assert config["verification"]["enabled"] is True
    assert config["verification"]["initial_score"] == 100
    assert config["verification"]["methods"][0]["name"] == "unit_score_delta"
    assert config["verification"]["methods"][0]["enabled"] is True
