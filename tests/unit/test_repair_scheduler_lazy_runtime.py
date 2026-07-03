import sys

from sunpack.repair.scheduler import RepairScheduler


def test_repair_scheduler_does_not_import_model_runtime_until_used():
    sys.modules.pop("sunpack.repair.model.runtime", None)

    scheduler = RepairScheduler({"repair": {}})

    assert scheduler._model_runtime is None
    assert "sunpack.repair.model.runtime" not in sys.modules
    runtime = scheduler.model_runtime
    assert runtime is scheduler.model_runtime
    assert "sunpack.repair.model.runtime" in sys.modules
