from pathlib import Path
from typing import Any

from smart_unpacker.repair.config import enabled_module_configs, repair_config
from smart_unpacker.repair.diagnosis import RepairDiagnosis, diagnose_repair_job
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.registry import discover_repair_modules, get_repair_module_registry
from smart_unpacker.repair.result import RepairResult


class RepairScheduler:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = repair_config(config or {})
        discover_repair_modules()

    def diagnose(self, job: RepairJob) -> RepairDiagnosis:
        return diagnose_repair_job(job)

    def repair(self, job: RepairJob) -> RepairResult:
        diagnosis = self.diagnose(job)
        if not self.config.get("enabled", True):
            return self._result("skipped", job, diagnosis, "repair layer is disabled")
        if not diagnosis.repairable:
            return self._result("unrepairable", job, diagnosis, "; ".join(diagnosis.notes) or "repair is blocked")

        modules = self._select_modules(job, diagnosis)
        if not modules:
            return self._result("unsupported", job, diagnosis, "no repair module is registered for this diagnosis")

        workspace = self._workspace_for(job)
        workspace.mkdir(parents=True, exist_ok=True)
        module_configs = enabled_module_configs(self.config)
        warnings = []
        for score, module in modules:
            try:
                result = module.repair(
                    job,
                    diagnosis,
                    str(workspace),
                    module_configs.get(module.spec.name, {}),
                )
            except Exception as exc:
                warnings.append(f"{module.spec.name}: {exc}")
                continue
            if result.ok:
                return result
            warnings.extend(result.warnings)
        return RepairResult(
            status="unrepairable",
            confidence=diagnosis.confidence,
            format=diagnosis.format,
            warnings=_dedupe(warnings),
            diagnosis=diagnosis.as_dict(),
            message="registered repair modules did not produce a candidate",
        )

    def _select_modules(self, job: RepairJob, diagnosis: RepairDiagnosis):
        enabled = enabled_module_configs(self.config)
        registry = get_repair_module_registry()
        candidates = []
        for name, module in registry.all().items():
            if name not in enabled:
                continue
            if diagnosis.format not in module.spec.formats and "archive" not in module.spec.formats:
                continue
            if module.spec.categories and not (set(module.spec.categories) & set(diagnosis.categories)):
                continue
            stages = self.config.get("stages", {}) if isinstance(self.config.get("stages"), dict) else {}
            if not stages.get(module.spec.stage, True):
                continue
            score = float(module.can_handle(job, diagnosis, enabled.get(name, {})) or 0.0)
            if score <= 0:
                continue
            candidates.append((score, module))
        candidates.sort(key=lambda item: item[0], reverse=True)
        limit = max(1, int(self.config.get("max_modules_per_job", 4) or 4))
        return candidates[:limit]

    def _workspace_for(self, job: RepairJob) -> Path:
        base = Path(job.workspace or self.config.get("workspace") or ".smart_unpacker_repair")
        key = _safe_key(job.archive_key or str(job.source_input.get("path") or job.source_input.get("archive_path") or "archive"))
        return base / key

    def _result(self, status: str, job: RepairJob, diagnosis: RepairDiagnosis, message: str) -> RepairResult:
        return RepairResult(
            status=status,
            confidence=diagnosis.confidence,
            format=diagnosis.format or job.format,
            damage_flags=list(job.damage_flags),
            diagnosis=diagnosis.as_dict(),
            message=message,
        )


def _safe_key(value: str) -> str:
    text = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(value or "archive"))
    return text[-120:] or "archive"


def _dedupe(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
