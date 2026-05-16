from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
import tempfile
import time
from typing import Any, Literal

from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.contracts.archive_state import ArchiveState
from sunpack.extraction.scheduler import ExtractionScheduler
from sunpack.extraction.result import ExtractionResult
from sunpack.repair.candidate import RepairCandidate
from sunpack.repair.job import RepairJob
from sunpack.support.archive_state_view import ArchiveStateByteView
from sunpack.verification.scheduler import VerificationScheduler
from sunpack.verification.result import VerificationResult


PolicyRecoveryMode = Literal["policy_light", "policy_full", "training_oracle"]


@dataclass(frozen=True)
class PolicyRecoverySnapshot:
    state_digest: str = ""
    patch_depth: int = 0
    score: float = 0.0
    status: str = ""
    decision_hint: str = ""
    completeness: float = 0.0
    output_quality_score: float = 0.0
    output_complete_ratio: float = 0.0
    complete_files: int = 0
    partial_files: int = 0
    failed_files: int = 0
    missing_files: int = 0
    recovered_bytes: int = 0
    extraction: dict[str, Any] = field(default_factory=dict)
    verification: dict[str, Any] = field(default_factory=dict)
    archive_coverage: dict[str, Any] = field(default_factory=dict)
    native_validation: dict[str, Any] = field(default_factory=dict)
    oracle: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state_digest": self.state_digest,
            "patch_depth": int(self.patch_depth or 0),
            "score": float(self.score or 0.0),
            "status": self.status,
            "decision_hint": self.decision_hint,
            "completeness": float(self.completeness or 0.0),
            "output_quality_score": float(self.output_quality_score or 0.0),
            "output_complete_ratio": float(self.output_complete_ratio or 0.0),
            "complete_files": int(self.complete_files or 0),
            "partial_files": int(self.partial_files or 0),
            "failed_files": int(self.failed_files or 0),
            "missing_files": int(self.missing_files or 0),
            "recovered_bytes": int(self.recovered_bytes or 0),
            "extraction": dict(self.extraction),
            "verification": dict(self.verification),
            "archive_coverage": dict(self.archive_coverage),
            "native_validation": dict(self.native_validation),
            "oracle": dict(self.oracle),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> "PolicyRecoverySnapshot":
        payload = payload if isinstance(payload, dict) else {}
        return cls(
            state_digest=str(payload.get("state_digest") or ""),
            patch_depth=_int(payload.get("patch_depth")),
            score=_clamp01(_float(payload.get("score"))),
            status=str(payload.get("status") or ""),
            decision_hint=str(payload.get("decision_hint") or ""),
            completeness=_clamp01(_float(payload.get("completeness"))),
            output_quality_score=_clamp01(_float(payload.get("output_quality_score"))),
            output_complete_ratio=_clamp01(_float(payload.get("output_complete_ratio"))),
            complete_files=_int(payload.get("complete_files")),
            partial_files=_int(payload.get("partial_files")),
            failed_files=_int(payload.get("failed_files")),
            missing_files=_int(payload.get("missing_files")),
            recovered_bytes=_int(payload.get("recovered_bytes")),
            extraction=dict(payload.get("extraction") or {}),
            verification=dict(payload.get("verification") or {}),
            archive_coverage=dict(payload.get("archive_coverage") or {}),
            native_validation=dict(payload.get("native_validation") or {}),
            oracle=dict(payload.get("oracle") or {}),
            metadata=dict(payload.get("metadata") or {}),
        )


class RecoveryEvaluator:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self._extractor: ExtractionScheduler | None = None

    def close(self) -> None:
        extractor = self._extractor
        self._extractor = None
        if extractor is not None:
            extractor.close()

    def __enter__(self) -> "RecoveryEvaluator":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _extractor_scheduler(self) -> ExtractionScheduler:
        if self._extractor is None:
            self._extractor = ExtractionScheduler(
                process_config=dict(self.config.get("process") or {}),
                output_config=dict(self.config.get("output") or {}),
                extraction_config=dict(self.config.get("extraction") or {}),
            )
        return self._extractor

    def evaluate_state(
        self,
        job: RepairJob,
        state: ArchiveState | None,
        *,
        mode: PolicyRecoveryMode = "policy_light",
        oracle: dict[str, Any] | None = None,
        cache: dict[str, PolicyRecoverySnapshot] | None = None,
    ) -> PolicyRecoverySnapshot:
        digest = state.effective_patch_digest() if state is not None else ""
        if cache is not None and digest and digest in cache:
            return cache[digest]
        try:
            snapshot = self._evaluate_state(job, state, mode=mode, oracle=oracle)
        except Exception as exc:
            snapshot = _failure_snapshot(state, exc)
        if cache is not None and digest:
            cache[digest] = snapshot
        return snapshot

    def evaluate_candidate(
        self,
        job: RepairJob,
        candidate: RepairCandidate,
        *,
        mode: PolicyRecoveryMode = "policy_light",
        oracle: dict[str, Any] | None = None,
        cache: dict[str, PolicyRecoverySnapshot] | None = None,
    ) -> PolicyRecoverySnapshot:
        native_validation = native_validation_summary(candidate)
        state = candidate.repaired_state
        if state is None:
            return _snapshot_from_parts(
                None,
                mode=mode,
                oracle=oracle,
                native_validation=native_validation,
                metadata={"status_reason": "candidate_without_repaired_state", "module_name": candidate.module_name},
            )
        digest = state.effective_patch_digest()
        if cache is not None and digest in cache:
            cached = cache[digest]
            if native_validation and not cached.native_validation:
                return PolicyRecoverySnapshot.from_dict({**cached.to_dict(), "native_validation": native_validation})
            return cached
        if mode == "policy_light":
            snapshot = _snapshot_from_parts(
                state,
                mode=mode,
                oracle=oracle,
                native_validation=native_validation,
                metadata={"module_name": candidate.module_name, "candidate_status": candidate.status},
            )
        else:
            try:
                evaluated = self._evaluate_state(job, state, mode=mode, oracle=oracle)
                evaluated_timing = {}
                if isinstance(evaluated.metadata, dict) and isinstance(evaluated.metadata.get("timing"), dict):
                    evaluated_timing = dict(evaluated.metadata["timing"])
                evaluated_profile = {}
                if isinstance(evaluated.metadata, dict):
                    for key in ("state_size_bytes", "extract_output_bytes", "extract_file_count"):
                        if evaluated.metadata.get(key) is not None:
                            evaluated_profile[key] = evaluated.metadata.get(key)
                snapshot = _snapshot_from_parts(
                    state,
                    mode=mode,
                    oracle=oracle,
                    extraction=evaluated.extraction,
                    verification=evaluated.verification,
                    native_validation=native_validation,
                    metadata={
                        "module_name": candidate.module_name,
                        "candidate_status": candidate.status,
                        "source": "candidate_full_evaluation",
                        **({"timing": evaluated_timing} if evaluated_timing else {}),
                        **evaluated_profile,
                    },
                )
            except Exception as exc:
                snapshot = _failure_snapshot(state, exc)
        if cache is not None:
            cache[digest] = snapshot
        return snapshot

    def _evaluate_state(
        self,
        job: RepairJob,
        state: ArchiveState | None,
        *,
        mode: PolicyRecoveryMode,
        oracle: dict[str, Any] | None,
    ) -> PolicyRecoverySnapshot:
        if mode in {"policy_full", "training_oracle"} and state is not None:
            full = self._full_evaluate_state(job, state, mode=mode, oracle=oracle)
            if full is not None:
                return full
        verification = _verification_from_job(job)
        if state is not None and state.verification:
            verification = {**verification, **dict(state.verification)}
        return _snapshot_from_parts(
            state,
            mode=mode,
            oracle=oracle,
            verification=verification,
            extraction=_extraction_from_job(job),
            metadata={"source": "job_summary", "mode": mode},
        )

    def _full_evaluate_state(
        self,
        job: RepairJob,
        state: ArchiveState,
        *,
        mode: PolicyRecoveryMode,
        oracle: dict[str, Any] | None,
    ) -> PolicyRecoverySnapshot | None:
        timings: dict[str, float] = {}
        state_size = 0
        try:
            state_size = int(ArchiveStateByteView(state).size)
        except Exception:
            state_size = 0
        extract_output_bytes = 0
        extract_file_count = 0
        with tempfile.TemporaryDirectory(prefix="sunpack_recovery_eval_") as tmp:
            extract_phases: dict[str, float] = {}
            started = time.perf_counter()
            task = self._task_for_extraction(job, state, tmp, timings=timings)
            timings["task_for_state"] = time.perf_counter() - started
            started = time.perf_counter()
            extracted = self._extractor_scheduler().extract(task, tmp, phase_timer=_phase_timer(extract_phases), phase_prefix="extract")
            timings["extract"] = time.perf_counter() - started
            for key, value in extract_phases.items():
                timings[f"extract.{key}"] = value
            extract_output_bytes, extract_file_count = _dir_size(tmp)
            started = time.perf_counter()
            verification = VerificationScheduler(self._config_for_mode(mode)).verify(task, extracted)
            timings["verify"] = time.perf_counter() - started
        started = time.perf_counter()
        snapshot = snapshot_from_verification(
            state,
            extracted,
            verification,
            oracle=oracle,
            mode=mode,
        )
        timings["snapshot"] = time.perf_counter() - started
        metadata = dict(snapshot.metadata)
        metadata["timing"] = {key: round(float(value), 6) for key, value in sorted(timings.items())}
        metadata["state_size_bytes"] = int(state_size)
        metadata["extract_output_bytes"] = int(extract_output_bytes)
        metadata["extract_file_count"] = int(extract_file_count)
        return PolicyRecoverySnapshot.from_dict({**snapshot.to_dict(), "metadata": metadata})

    def _task_for_extraction(self, job: RepairJob, state: ArchiveState, tmp: str | Path, *, timings: dict[str, float]) -> ArchiveTask:
        if state.patches and bool(self.config.get("repair", {}).get("materialize_patched_recovery_input", True)):
            suffix = _archive_suffix(state.format_hint or job.format or state.source.format_hint)
            path = Path(tmp) / f"patched_recovery_input{suffix}"
            started = time.perf_counter()
            _materialized, materialize_timing = ArchiveStateByteView(state).materialize_with_timing(path)
            timings["materialize_patched_input"] = timings.get("materialize_patched_input", 0.0) + (time.perf_counter() - started)
            for key, value in materialize_timing.items():
                timings[f"materialize_patched_input.{key}"] = (
                    timings.get(f"materialize_patched_input.{key}", 0.0) + float(value)
                )
            started = time.perf_counter()
            task = _task_for_materialized_state(job, state, path)
            timings["task_for_materialized_state"] = timings.get("task_for_materialized_state", 0.0) + (time.perf_counter() - started)
            return task
        return _task_for_state(job, state)

    def _config_for_mode(self, mode: PolicyRecoveryMode) -> dict[str, Any]:
        if mode != "training_oracle":
            return self.config
        verification = dict(self.config.get("verification") or {})
        if verification.get("methods"):
            return self.config
        return {
            **self.config,
            "verification": {
                **verification,
                "enabled": True,
                "methods": [
                    {"name": "oracle_expected_output_match", "enabled": True},
                    {"name": "extraction_exit_signal", "enabled": True},
                    {"name": "output_presence", "enabled": True},
                ],
            },
        }


def snapshot_from_verification(
    state: ArchiveState | None,
    extraction_result: ExtractionResult | dict[str, Any] | None,
    verification_result: VerificationResult | dict[str, Any] | None,
    *,
    oracle: dict[str, Any] | None = None,
    native_validation: dict[str, Any] | None = None,
    mode: PolicyRecoveryMode = "policy_full",
) -> PolicyRecoverySnapshot:
    return _snapshot_from_parts(
        state,
        mode=mode,
        oracle=oracle,
        extraction=_extraction_payload(extraction_result),
        verification=_verification_payload(verification_result),
        native_validation=dict(native_validation or {}),
        metadata={"source": "verification_result", "mode": mode},
    )


def native_validation_summary(candidate: RepairCandidate) -> dict[str, Any]:
    items = []
    accepted = True
    best_score = 0.0
    dry_run: dict[str, Any] = {}
    archive_coverage: dict[str, Any] = {}
    for validation in candidate.validations:
        details = dict(validation.details or {})
        accepted = accepted and bool(validation.accepted)
        best_score = max(best_score, _float(validation.score))
        if isinstance(details.get("dry_run"), dict):
            dry_run = {**dry_run, **dict(details["dry_run"])}
        if isinstance(details.get("archive_coverage"), dict):
            archive_coverage = {**archive_coverage, **dict(details["archive_coverage"])}
        items.append({
            "name": validation.name,
            "accepted": bool(validation.accepted),
            "score": _float(validation.score),
            "warnings": list(validation.warnings),
            "details": details,
        })
    return {
        "count": len(items),
        "accepted": accepted if items else False,
        "score": _clamp01(best_score),
        "items": items,
        "dry_run": dry_run,
        "archive_coverage": archive_coverage,
    }


def _snapshot_from_parts(
    state: ArchiveState | None,
    *,
    mode: PolicyRecoveryMode,
    oracle: dict[str, Any] | None = None,
    extraction: dict[str, Any] | None = None,
    verification: dict[str, Any] | None = None,
    native_validation: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> PolicyRecoverySnapshot:
    extraction = dict(extraction or {})
    verification = dict(verification or {})
    native_validation = dict(native_validation or {})
    oracle_payload = _oracle_payload(oracle)
    coverage = _coverage_payload(verification, native_validation)
    completeness = _first_float(coverage, "completeness", "file_coverage", "byte_coverage")
    if completeness <= 0:
        completeness = _first_float(verification, "completeness", "complete_ratio")
    output_quality = _first_float(verification, "output_quality_score", "output_quality")
    output_complete = _first_float(verification, "output_complete_ratio", "complete_ratio")
    native_score = _native_score(native_validation)
    score, source = _score(
        mode=mode,
        oracle=oracle_payload,
        coverage_score=completeness,
        verification_score=_first_positive(completeness, output_quality, output_complete),
        native_score=native_score,
    )
    complete_files = max(_first_int(verification, "complete_files"), _int(coverage.get("complete_files")))
    partial_files = max(_first_int(verification, "partial_files"), _int(coverage.get("partial_files")))
    failed_files = max(_first_int(verification, "failed_files"), _int(coverage.get("failed_files")))
    missing_files = max(_first_int(verification, "missing_files"), _int(coverage.get("missing_files")))
    status = str(verification.get("assessment_status") or extraction.get("status") or (metadata or {}).get("candidate_status") or "")
    if not status:
        status = _status_from_score(score)
    decision_hint = str(verification.get("decision_hint") or ("accept" if score >= 0.999 else "repair" if score > 0 else "none"))
    meta = dict(metadata or {})
    meta["score_source"] = source
    return PolicyRecoverySnapshot(
        state_digest=state.effective_patch_digest() if state is not None else "",
        patch_depth=state.patch_depth() if state is not None else 0,
        score=_clamp01(score),
        status=status,
        decision_hint=decision_hint,
        completeness=_clamp01(completeness),
        output_quality_score=_clamp01(output_quality),
        output_complete_ratio=_clamp01(output_complete),
        complete_files=complete_files,
        partial_files=partial_files,
        failed_files=failed_files,
        missing_files=missing_files,
        recovered_bytes=_first_int(verification, "output_total_bytes", "recovered_bytes", default=_int(extraction.get("bytes_written"))),
        extraction=extraction,
        verification=verification,
        archive_coverage=coverage,
        native_validation=native_validation,
        oracle=oracle_payload,
        metadata=meta,
    )


def _score(*, mode: str, oracle: dict[str, Any], coverage_score: float, verification_score: float, native_score: float) -> tuple[float, str]:
    oracle_score = _float(oracle.get("score"))
    if mode == "training_oracle" and oracle.get("available"):
        return oracle_score, "oracle"
    if coverage_score > 0:
        return coverage_score, "archive_coverage"
    if verification_score > 0:
        return verification_score, "verification"
    if native_score > 0:
        return native_score, "native_validation"
    return 0.0, "none"


def _oracle_payload(raw: dict[str, Any] | None) -> dict[str, Any]:
    raw = dict(raw or {})
    if not raw:
        return {"available": False, "score": 0.0}
    has_signal = "score" in raw
    if "score" in raw:
        score = _float(raw.get("score"))
    else:
        numerators = []
        denominators = []
        for good, total in (
            ("matched_hashes", "expected_hashes"),
            ("matched_crc", "expected_crc"),
            ("matched_files", "expected_files"),
            ("matched_bytes", "expected_bytes"),
        ):
            if raw.get(total) is not None and raw.get(good) is not None:
                has_signal = True
                numerators.append(_float(raw.get(good)))
                denominators.append(max(0.0, _float(raw.get(total))))
        score = max([(n / d) for n, d in zip(numerators, denominators) if d > 0], default=0.0)
    return {**raw, "available": bool(has_signal), "score": _clamp01(score)}


def _dir_size(path: str | Path) -> tuple[int, int]:
    total = 0
    count = 0
    try:
        for item in Path(path).rglob("*"):
            try:
                if item.is_file():
                    total += int(item.stat().st_size)
                    count += 1
            except OSError:
                continue
    except OSError:
        return 0, 0
    return total, count


def _phase_timer(output: dict[str, float]):
    @contextmanager
    def timer(name: str):
        started = time.perf_counter()
        try:
            yield
        finally:
            output[str(name)] = output.get(str(name), 0.0) + (time.perf_counter() - started)
    return timer


def _verification_from_job(job: RepairJob) -> dict[str, Any]:
    failure = job.extraction_failure if isinstance(job.extraction_failure, dict) else {}
    verification = failure.get("verification") if isinstance(failure.get("verification"), dict) else {}
    coverage = failure.get("archive_coverage") if isinstance(failure.get("archive_coverage"), dict) else verification.get("archive_coverage")
    payload = {**verification, **{key: value for key, value in failure.items() if key not in {"verification"}}}
    if isinstance(coverage, dict):
        payload["archive_coverage"] = dict(coverage)
    return payload


def _task_for_state(job: RepairJob, state: ArchiveState) -> ArchiveTask:
    source = state.source.to_archive_input_descriptor()
    main_path = source.entry_path or str(job.source_input.get("path") or job.source_input.get("archive_path") or "")
    parts = source.part_paths() or [main_path]
    bag = FactBag()
    fmt = state.format_hint or job.format or source.format_hint
    bag.set("analysis.selected_format", fmt)
    bag.set("archive.input", source.to_dict())
    if isinstance(job.knowledge, dict) and job.knowledge:
        bag.set("archive.knowledge", dict(job.knowledge))
    task = ArchiveTask(
        fact_bag=bag,
        score=10,
        key=job.archive_key or main_path,
        main_path=main_path,
        all_parts=parts,
        logical_name=state.logical_name or source.logical_name or job.archive_key,
        detected_ext=fmt,
    )
    task.set_archive_state(state)
    return task


def _task_for_materialized_state(job: RepairJob, state: ArchiveState, path: str | Path) -> ArchiveTask:
    path = Path(path)
    fmt = state.format_hint or job.format or state.source.format_hint
    source = {
        "kind": "file",
        "path": str(path),
        "archive_path": str(path),
        "format_hint": fmt,
        "format": fmt,
        "logical_name": state.logical_name or job.archive_key or path.name,
    }
    knowledge = _knowledge_for_materialized_state(job, source)
    bag = FactBag()
    bag.set("analysis.selected_format", fmt)
    bag.set("archive.input", dict(source))
    if job.password:
        bag.set("archive.password", job.password)
    if knowledge:
        bag.set("archive.knowledge", knowledge)
    task = ArchiveTask(
        fact_bag=bag,
        score=10,
        key=job.archive_key or str(path),
        main_path=str(path),
        all_parts=[str(path)],
        logical_name=state.logical_name or job.archive_key or path.name,
        detected_ext=fmt,
    )
    task.set_archive_input(source)
    if job.password:
        task.fact_bag.set("archive.password", job.password)
    return task


def _knowledge_for_materialized_state(job: RepairJob, source: dict[str, Any]) -> dict[str, Any]:
    knowledge = dict(job.knowledge) if isinstance(job.knowledge, dict) else {}
    source_payload = dict(source)
    current_source = knowledge.get("source")
    if isinstance(current_source, dict):
        knowledge["source"] = {**current_source, "input": source_payload}
    else:
        knowledge["source"] = {"input": source_payload}
    if job.password:
        archive = knowledge.get("archive")
        if isinstance(archive, dict):
            knowledge["archive"] = {**archive, "password": job.password}
        else:
            knowledge["archive"] = {"password": job.password}
    return knowledge


def _archive_suffix(fmt: str) -> str:
    fmt = str(fmt or "").lower().lstrip(".")
    if fmt in {"zip", "7z", "rar", "tar", "gz", "bz2", "xz"}:
        return f".{fmt}"
    if fmt in {"seven_zip", "7zip"}:
        return ".7z"
    return ".bin"


def _extraction_from_job(job: RepairJob) -> dict[str, Any]:
    failure = job.extraction_failure if isinstance(job.extraction_failure, dict) else {}
    diagnostics = job.extraction_diagnostics if isinstance(job.extraction_diagnostics, dict) else {}
    return {
        "success": False if failure else None,
        "status": str(failure.get("status") or diagnostics.get("status") or ""),
        "failure_stage": str(failure.get("failure_stage") or diagnostics.get("failure_stage") or ""),
        "failure_kind": str(failure.get("failure_kind") or diagnostics.get("failure_kind") or ""),
        "bytes_written": _first_int(failure, "bytes_written", "output_total_bytes"),
    }


def _extraction_payload(result: ExtractionResult | dict[str, Any] | None) -> dict[str, Any]:
    if result is None:
        return {}
    if isinstance(result, dict):
        return dict(result)
    diagnostics = result.diagnostics if isinstance(result.diagnostics, dict) else {}
    worker = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    return {
        "success": bool(result.success),
        "archive": result.archive,
        "out_dir": result.out_dir,
        "error": result.error,
        "partial_outputs": bool(result.partial_outputs),
        "progress_manifest": result.progress_manifest,
        "status": str(worker.get("status") or diagnostics.get("status") or ""),
        "failure_stage": str(worker.get("failure_stage") or diagnostics.get("failure_stage") or ""),
        "failure_kind": str(worker.get("failure_kind") or diagnostics.get("failure_kind") or ""),
        "files_written": _int(worker.get("files_written")),
        "bytes_written": _int(worker.get("bytes_written")),
    }


def _verification_payload(result: VerificationResult | dict[str, Any] | None) -> dict[str, Any]:
    if result is None:
        return {}
    if isinstance(result, dict):
        return dict(result)
    coverage = result.archive_coverage
    coverage_payload = {}
    if (
        float(getattr(coverage, "confidence", 0.0) or 0.0) > 0.0
        or int(getattr(coverage, "expected_files", 0) or 0) > 0
        or int(getattr(coverage, "matched_files", 0) or 0) > 0
    ):
        coverage_payload = {
            "completeness": coverage.completeness,
            "expected_files": coverage.expected_files,
            "matched_files": coverage.matched_files,
            "complete_files": coverage.complete_files,
            "partial_files": coverage.partial_files,
            "failed_files": coverage.failed_files,
            "missing_files": coverage.missing_files,
        }
    output_file_count = result.output_file_count
    complete_files = result.complete_files
    partial_files = result.partial_files
    failed_files = result.failed_files
    missing_files = result.missing_files
    empty_unobserved = (
        not coverage_payload
        and int(output_file_count or 0) == 0
        and int(complete_files or 0) == 0
        and int(partial_files or 0) == 0
        and int(failed_files or 0) == 0
        and int(missing_files or 0) == 0
    )
    completeness = 0.0 if empty_unobserved else result.completeness
    decision_hint = "none" if empty_unobserved and result.decision_hint == "accept" else result.decision_hint
    return {
        "decision_hint": decision_hint,
        "assessment_status": result.assessment_status,
        "source_integrity": result.source_integrity,
        "completeness": completeness,
        "recoverable_upper_bound": result.recoverable_upper_bound,
        "output_quality_score": result.output_quality_score,
        "output_file_count": output_file_count,
        "output_total_bytes": result.output_total_bytes,
        "output_complete_ratio": result.output_complete_ratio,
        "output_failed_ratio": result.output_failed_ratio,
        "output_empty": result.output_empty,
        "output_confidence": result.output_confidence,
        "complete_files": complete_files,
        "partial_files": partial_files,
        "failed_files": failed_files,
        "missing_files": missing_files,
        "archive_coverage": coverage_payload,
    }


def _coverage_payload(verification: dict[str, Any], native_validation: dict[str, Any]) -> dict[str, Any]:
    for source in (verification.get("archive_coverage"), native_validation.get("archive_coverage")):
        if isinstance(source, dict) and source:
            return dict(source)
    return {}


def _native_score(native_validation: dict[str, Any]) -> float:
    if not native_validation:
        return 0.0
    coverage = native_validation.get("archive_coverage") if isinstance(native_validation.get("archive_coverage"), dict) else {}
    if coverage:
        value = _first_float(coverage, "completeness", "file_coverage", "byte_coverage")
        if value > 0:
            return value
    dry_run = native_validation.get("dry_run") if isinstance(native_validation.get("dry_run"), dict) else {}
    if dry_run.get("ok"):
        return 1.0
    if _int(dry_run.get("files_written")) > 0:
        return 0.55
    if _int(dry_run.get("bytes_written")) > 0:
        return 0.35
    return _float(native_validation.get("score"))


def _failure_snapshot(state: ArchiveState | None, exc: Exception) -> PolicyRecoverySnapshot:
    return PolicyRecoverySnapshot(
        state_digest=state.effective_patch_digest() if state is not None else "",
        patch_depth=state.patch_depth() if state is not None else 0,
        status="evaluation_failed",
        metadata={"error": str(exc), "score_source": "error"},
    )


def _status_from_score(score: float) -> str:
    if score >= 0.999:
        return "complete"
    if score > 0:
        return "partial"
    return "empty"


def _first_positive(*values: float) -> float:
    for value in values:
        if value > 0:
            return value
    return 0.0


def _first_float(payload: dict[str, Any], *keys: str) -> float:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, dict):
            value = value.get("score")
        parsed = _float(value)
        if parsed > 0:
            return parsed
    return 0.0


def _first_int(payload: dict[str, Any], *keys: str, default: int = 0) -> int:
    for key in keys:
        if key in payload:
            return _int(payload.get(key))
    return int(default or 0)


def _float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value or 0.0)))
