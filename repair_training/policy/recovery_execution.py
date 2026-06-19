from __future__ import annotations

from pathlib import Path
import tempfile
import time
from typing import Any

from sunpack.contracts.archive_state import ArchiveState
from sunpack.extraction.scheduler import ExtractionScheduler
from sunpack.repair.job import RepairJob
from sunpack.repair.search.recovery import (
    PolicyRecoverySnapshot,
    snapshot_from_verification,
    task_for_materialized_recovery_state,
    task_for_recovery_state,
)
from sunpack.support.archive_state_view import ArchiveStateByteView
from sunpack.verification.scheduler import VerificationScheduler


class TrainingRecoveryExecutor:
    """Training-side orchestration for expensive extract/verify observations."""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.extractor = ExtractionScheduler(
            process_config=dict(config.get("process") or {}),
            output_config=dict(config.get("output") or {}),
            extraction_config=dict(config.get("extraction") or {}),
        )

    def close(self) -> None:
        self.extractor.close()

    def __call__(self, job: RepairJob, state: ArchiveState, *, mode: str, oracle=None) -> PolicyRecoverySnapshot:
        timings: dict[str, float] = {}
        with tempfile.TemporaryDirectory(prefix="sunpack_recovery_eval_") as tmp:
            task_started = time.perf_counter()
            task = self._task(job, state, Path(tmp), timings)
            timings["task_for_state"] = time.perf_counter() - task_started
            extract_started = time.perf_counter()
            extracted = self.extractor.extract(task, tmp)
            timings["extract"] = time.perf_counter() - extract_started
            verify_started = time.perf_counter()
            verification = VerificationScheduler(_verification_config(self.config, mode)).verify(task, extracted)
            timings["verify"] = time.perf_counter() - verify_started
        snapshot = snapshot_from_verification(state, extracted, verification, oracle=oracle, mode=mode)
        metadata = dict(snapshot.metadata)
        metadata["timing"] = {key: round(value, 6) for key, value in sorted(timings.items())}
        metadata["state_size_bytes"] = int(ArchiveStateByteView(state).size)
        return PolicyRecoverySnapshot.from_dict({**snapshot.to_dict(), "metadata": metadata})

    def _task(self, job: RepairJob, state: ArchiveState, tmp: Path, timings: dict[str, float]):
        if not state.patches or not bool(self.config.get("repair", {}).get("materialize_patched_recovery_input", True)):
            return task_for_recovery_state(job, state)
        path = tmp / f"patched_recovery_input{_archive_suffix(state.format_hint or job.format or state.source.format_hint)}"
        started = time.perf_counter()
        ArchiveStateByteView(state).materialize(path)
        timings["materialize_patched_input"] = time.perf_counter() - started
        return task_for_materialized_recovery_state(job, state, path)


def _verification_config(config: dict[str, Any], mode: str) -> dict[str, Any]:
    if mode != "training_oracle":
        return config
    verification = dict(config.get("verification") or {})
    methods = list(verification.get("methods") or [])
    names = {str(item.get("name") or "") for item in methods if isinstance(item, dict)}
    if "oracle_expected_output_match" not in names:
        methods.insert(0, {"name": "oracle_expected_output_match", "enabled": True})
    for name in ("extraction_exit_signal", "output_presence"):
        if name not in names:
            methods.append({"name": name, "enabled": True})
    return {**config, "verification": {**verification, "enabled": True, "methods": methods}}


def _archive_suffix(fmt: str) -> str:
    normalized = str(fmt or "").lower().lstrip(".")
    return {"7z": ".7z", "rar": ".rar", "tar": ".tar", "gzip": ".gz", "bzip2": ".bz2", "xz": ".xz", "zstd": ".zst"}.get(normalized, ".zip")
