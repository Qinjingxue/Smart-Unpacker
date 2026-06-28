from __future__ import annotations

import time

from sunpack.repair.stage import ArchiveRepairStage
from sunpack.coordinator.reporting import RunReporter
from sunpack.repair.model.assets import ModelAssetRegistry
from sunpack.repair.config import repair_config, repair_system_mode


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


def test_lite_repair_system_reports_failed_verification_as_possible_damage(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SUNPACK_REPAIR_SYSTEM", "lite")

    RunReporter("zh").log_final_summary(
        str(tmp_path),
        time.time(),
        success_count=0,
        failed_tasks=["bad.zip"],
    )

    output = capsys.readouterr().out
    assert "当前版本未包含模型修复系统" in output
    assert "压缩包已损坏" in output


def test_lite_model_status_is_explicitly_disabled_not_broken(monkeypatch):
    monkeypatch.setenv("SUNPACK_REPAIR_SYSTEM", "lite")

    status = ModelAssetRegistry(manifest_path="missing-manifest.json").status(load=True)

    assert status["ok"] is True
    assert status["repair_system"] == "lite"
    assert status["models"] == []
    assert "not included" in status["disabled_reason"]
