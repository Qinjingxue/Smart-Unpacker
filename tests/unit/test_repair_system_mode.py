from __future__ import annotations

import time

from sunpack.repair.stage import ArchiveRepairStage
from sunpack.coordinator.reporting import RunReporter
from sunpack.contracts.detection import FactBag
from sunpack.contracts.failures import FailureInfo, FailureKind
from sunpack.contracts.tasks import ArchiveTask
from sunpack.repair.loop import RepairLoopLimits, RepairLoopState
from sunpack.repair.model.assets import ModelAssetRegistry
from sunpack.repair.config import repair_config, repair_system_mode
from sunpack.repair.terminal_status import terminal_repair_status


def test_lite_repair_system_disables_repair_config(monkeypatch):
    monkeypatch.setenv("SUNPACK_REPAIR_SYSTEM", "lite")

    config = repair_config({"repair": {"enabled": True, "policy": {"enabled": True}}})

    assert repair_system_mode() == "lite"
    assert config["enabled"] is False
    assert config["max_attempts_per_task"] == 0
    assert config["max_repair_rounds_per_task"] == 0
    assert config["policy"]["enabled"] is False


def test_lite_repair_system_does_not_create_scheduler(monkeypatch):
    monkeypatch.setenv("SUNPACK_REPAIR_SYSTEM", "lite")

    stage = ArchiveRepairStage({"repair": {"enabled": True}})

    assert stage.enabled is False
    assert stage.scheduler is None
    assert stage.max_attempts_per_task == 0


def test_lite_repair_system_reports_precise_disabled_status(monkeypatch, capsys):
    monkeypatch.setenv("SUNPACK_REPAIR_SYSTEM", "lite")
    failure = FailureInfo(
        kind=FailureKind.DAMAGED,
        stage="verification",
        message="crc mismatch",
        repairable=True,
        details={"repair": {"system": "lite", "status": "disabled_by_edition"}},
    )

    RunReporter("zh").log_final_summary(
        time.time(),
        success_count=0,
        failed_tasks=["bad.zip"],
        failures=[failure],
    )

    output = capsys.readouterr().out
    assert "当前 Lite 版本未包含规则式或 native 自动修复" in output
    assert "原始错误状态保持不变" in output


def test_lite_does_not_mask_nonrepairable_failure(monkeypatch, capsys):
    monkeypatch.setenv("SUNPACK_REPAIR_SYSTEM", "lite")
    failure = FailureInfo(
        kind=FailureKind.FILESYSTEM_ERROR,
        stage="output",
        message="access denied",
        repairable=False,
    )

    RunReporter("zh").log_final_summary(
        time.time(),
        success_count=0,
        failed_tasks=["bad.zip [access denied]"],
        failures=[failure],
    )

    output = capsys.readouterr().out
    assert "access denied" in output
    assert "自动修复" not in output


def test_full_repair_terminal_status_preserves_loop_stop_reason(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SUNPACK_REPAIR_SYSTEM", "full")
    source = tmp_path / "bad.zip"
    source.write_bytes(b"broken")
    task = ArchiveTask(FactBag(), score=0, main_path=str(source))
    task.fact_bag.set("pipeline.repair_entered", True)
    RepairLoopState(task, RepairLoopLimits(max_rounds=1)).stop(
        "max_repair_rounds_reached",
        trigger="verification",
    )

    status = terminal_repair_status(
        task,
        decision_hint="repair",
        repair_enabled=True,
        attempt_source="rule",
        repair_module="zip_rule",
    )

    assert status["system"] == "full"
    assert status["status"] == "stopped"
    assert status["terminal_reason"] == "max_repair_rounds_reached"
    assert status["selected_attempt_source"] == "rule"
    assert status["selected_module"] == "zip_rule"

    RunReporter("zh").log_final_summary(
        time.time(),
        success_count=0,
        failed_tasks=["bad.zip [repair failed]"],
        failures=[FailureInfo(
            kind=FailureKind.DAMAGED,
            stage="verification",
            message="repair failed",
            repairable=True,
            details={"repair": status},
        )],
    )

    output = capsys.readouterr().out
    assert "状态=stopped" in output
    assert "原因=max_repair_rounds_reached" in output


def test_lite_model_status_is_explicitly_disabled_not_broken(monkeypatch):
    monkeypatch.setenv("SUNPACK_REPAIR_SYSTEM", "lite")

    status = ModelAssetRegistry(manifest_path="missing-manifest.json").status(load=True)

    assert status["ok"] is True
    assert status["repair_system"] == "lite"
    assert status["models"] == []
    assert "not included" in status["disabled_reason"]
