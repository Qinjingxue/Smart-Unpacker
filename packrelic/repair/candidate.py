from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable

from packrelic.contracts.archive_state import ArchiveState
from packrelic.repair.result import RepairResult, RepairStatus
from packrelic.support.sevenzip_native import get_native_password_tester
from packrelic.support.sevenzip_worker import dry_run_archive


@dataclass(frozen=True)
class CandidateValidation:
    name: str
    accepted: bool
    score: float = 0.0
    warnings: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RepairCandidate:
    module_name: str
    format: str
    repaired_input: dict[str, Any] = field(default_factory=dict)
    status: RepairStatus = "repaired"
    stage: str = ""
    confidence: float = 0.0
    partial: bool = False
    requires_native_validation: bool = False
    actions: list[str] = field(default_factory=list)
    damage_flags: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    workspace_paths: list[str] = field(default_factory=list)
    diagnosis: dict[str, Any] = field(default_factory=dict)
    message: str = ""
    validations: list[CandidateValidation] = field(default_factory=list)
    score_hint: float = 0.0
    materializer: Callable[[], Any] | None = field(default=None, compare=False, repr=False)
    materialized: bool = True
    plan: dict[str, Any] = field(default_factory=dict)

    @property
    def is_lazy(self) -> bool:
        return self.materializer is not None and not self.materialized

    @classmethod
    def from_result(
        cls,
        result: RepairResult,
        *,
        score_hint: float = 0.0,
        stage: str = "",
        requires_native_validation: bool = False,
    ) -> "RepairCandidate | None":
        if not result.ok or not isinstance(result.repaired_input, dict):
            return None
        return cls(
            module_name=result.module_name,
            format=result.format,
            repaired_input=dict(result.repaired_input),
            status=result.status,
            stage=stage,
            confidence=float(result.confidence or 0.0),
            partial=bool(result.partial),
            requires_native_validation=bool(requires_native_validation),
            actions=list(result.actions),
            damage_flags=list(result.damage_flags),
            warnings=list(result.warnings),
            workspace_paths=list(result.workspace_paths),
            diagnosis=dict(result.diagnosis),
            message=str(result.message or ""),
            validations=[
                CandidateValidation(
                    name="module_result",
                    accepted=True,
                    score=float(result.confidence or 0.0),
                    details={"status": result.status, "module": result.module_name},
                )
            ],
            score_hint=float(score_hint or 0.0),
            plan=_result_plan(result),
        )

    def to_result(self, *, selection: dict[str, Any] | None = None) -> RepairResult:
        diagnosis = dict(self.diagnosis)
        if selection:
            diagnosis["candidate_selection"] = dict(selection)
        return RepairResult(
            status=self.status,
            confidence=self.confidence,
            format=self.format,
            repaired_input=dict(self.repaired_input),
            actions=list(self.actions),
            damage_flags=list(self.damage_flags),
            warnings=list(self.warnings),
            workspace_paths=list(self.workspace_paths),
            partial=self.partial,
            module_name=self.module_name,
            diagnosis=diagnosis,
            message=self.message,
            repaired_state=_archive_state_from_plan(self.plan),
        )


@dataclass(frozen=True)
class RepairCandidateBatch:
    candidates: list[RepairCandidate] = field(default_factory=list)
    diagnosis: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    message: str = ""
    terminal_result: RepairResult | None = None

    @property
    def ok(self) -> bool:
        return bool(self.candidates)


class CandidateSelector:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    def select(self, candidates: list[RepairCandidate]) -> tuple[RepairCandidate | None, dict[str, Any]]:
        materialized = materialize_candidates(candidates)
        validated = [self._with_native_validation(candidate) for candidate in materialized]
        accepted = [candidate for candidate in validated if self._accepted(candidate)]
        if not accepted:
            return None, {
                "candidate_count": len(validated),
                "accepted_count": 0,
                "message": "no accepted repair candidates",
                "warnings": _selection_warnings(validated),
            }
        scored = [(self.generation_priority(candidate), candidate) for candidate in accepted]
        scored.sort(key=lambda item: item[0], reverse=True)
        priority, selected = scored[0]
        return selected, {
            "candidate_count": len(validated),
            "accepted_count": len(accepted),
            "selected_module": selected.module_name,
            "selected_format": selected.format,
            "generation_priority": priority,
            "validations": [
                {
                    "name": validation.name,
                    "accepted": validation.accepted,
                    "score": validation.score,
                    "warnings": list(validation.warnings),
                    "details": dict(validation.details),
                }
                for validation in selected.validations
            ],
        }

    def _with_native_validation(self, candidate: RepairCandidate) -> RepairCandidate:
        if not candidate.requires_native_validation:
            return candidate
        deep = self.config.get("deep") if isinstance(self.config.get("deep"), dict) else {}
        if not bool(deep.get("verify_candidates", True)):
            validation = CandidateValidation(
                name="native_candidate_validation",
                accepted=True,
                score=0.0,
                details={"skipped": True, "reason": "repair.deep.verify_candidates is false"},
            )
            return replace(candidate, validations=[*candidate.validations, validation])

        repaired_input = candidate.repaired_input if isinstance(candidate.repaired_input, dict) else {}
        path = str(repaired_input.get("path") or "")
        kind = str(repaired_input.get("kind") or "file")
        if kind != "file" or not path:
            validation = CandidateValidation(
                name="native_candidate_validation",
                accepted=False,
                warnings=["native validation requires a repaired file candidate"],
                details={"kind": kind, "path": path},
            )
            return replace(candidate, validations=[*candidate.validations, validation])
        if not Path(path).is_file():
            validation = CandidateValidation(
                name="native_candidate_validation",
                accepted=False,
                warnings=["candidate file does not exist for native validation"],
                details={"path": path},
            )
            return replace(candidate, validations=[*candidate.validations, validation])

        password = str(repaired_input.get("password") or "")
        format_hint = str(repaired_input.get("format_hint") or candidate.format or "")
        timeout = float(deep.get("max_seconds_per_module", 30.0) or 30.0)
        try:
            tester = get_native_password_tester()
            probe = tester.probe_archive(path)
            empty_password_test = tester.test_archive(path, password="") if password else None
            test = tester.test_archive(path, password=password)
            resources = _analyze_resources(tester, path, password)
            dry_run = dry_run_archive(path, format_hint=format_hint, password=password, timeout=max(1.0, timeout))
        except Exception as exc:
            validation = CandidateValidation(
                name="native_candidate_validation",
                accepted=False,
                warnings=[f"native candidate validation failed to run: {exc}"],
                details={"path": path, "format_hint": format_hint},
            )
            return replace(candidate, validations=[*candidate.validations, validation])

        dry_result = dry_run.result
        diagnostics = dry_run.diagnostics
        output_trace = diagnostics.get("output_trace") if isinstance(diagnostics, dict) else {}
        if not isinstance(output_trace, dict):
            output_trace = {}
        output_items = output_trace.get("items") if isinstance(output_trace.get("items"), list) else []
        dry_files = int(dry_result.get("files_written", 0) or 0) if isinstance(dry_result, dict) else 0
        dry_bytes = int(dry_result.get("bytes_written", 0) or output_trace.get("total_bytes_written", 0) or 0)
        partial_progress = bool(candidate.partial and (dry_files > 0 or dry_bytes > 0 or output_items))

        probe_ok = bool(probe.is_archive and not (probe.is_broken and not candidate.partial))
        test_ok = bool(test.ok)
        empty_password_ok = bool(getattr(empty_password_test, "ok", False)) if empty_password_test is not None else test_ok
        resources_ok = bool(getattr(resources, "ok", False))
        dry_ok = bool(dry_run.ok)
        accepted = bool(probe_ok and (test_ok or dry_ok or partial_progress))
        score = 0.0
        if probe.is_archive:
            score += 0.2
        if probe_ok:
            score += 0.1
        if empty_password_ok:
            score += 0.04
        if test_ok:
            score += 0.32
        if resources_ok:
            score += 0.08
        if dry_ok:
            score += 0.35
        elif partial_progress:
            score += 0.12
        coverage_ratio = _candidate_coverage_ratio(resources, dry_files)
        if coverage_ratio is not None:
            score += min(0.1, coverage_ratio * 0.1)

        warnings = []
        if not probe_ok:
            warnings.append(probe.message or "native probe rejected candidate")
        if not test_ok and not candidate.partial:
            warnings.append(test.message or "native archive test failed")
        if not dry_ok and not partial_progress:
            warnings.append(dry_run.message or "worker dry-run failed")

        validation = CandidateValidation(
            name="native_candidate_validation",
            accepted=accepted,
            score=min(1.0, score),
            warnings=warnings,
            details={
                "path": path,
                "format_hint": format_hint,
                "password_present": bool(password),
                "empty_password_ok": empty_password_ok,
                "probe": {
                    "status": probe.status,
                    "is_archive": probe.is_archive,
                    "is_broken": probe.is_broken,
                    "is_encrypted": probe.is_encrypted,
                    "checksum_error": probe.checksum_error,
                    "item_count": probe.item_count,
                    "archive_type": probe.archive_type,
                    "message": probe.message,
                },
                "test": {
                    "status": test.status,
                    "ok": test.ok,
                    "command_ok": test.command_ok,
                    "encrypted": test.encrypted,
                    "checksum_error": test.checksum_error,
                    "archive_type": test.archive_type,
                    "message": test.message,
                },
                "resource_analysis": _resource_details(resources),
                "archive_coverage": {
                    "complete_files": dry_files,
                    "expected_files": int(getattr(resources, "file_count", 0) or 0) if resources is not None else 0,
                    "completeness": coverage_ratio,
                },
                "dry_run": {
                    "ok": dry_run.ok,
                    "returncode": dry_run.returncode,
                    "status": dry_result.get("status") if isinstance(dry_result, dict) else "",
                    "native_status": dry_result.get("native_status") if isinstance(dry_result, dict) else "",
                    "failure_stage": dry_result.get("failure_stage") if isinstance(dry_result, dict) else "",
                    "failure_kind": dry_result.get("failure_kind") if isinstance(dry_result, dict) else "",
                    "files_written": dry_files,
                    "bytes_written": dry_bytes,
                    "diagnostics": diagnostics,
                    "message": dry_run.message,
                },
            },
        )
        return replace(candidate, validations=[*candidate.validations, validation])

    @staticmethod
    def _accepted(candidate: RepairCandidate) -> bool:
        return bool(candidate.repaired_input) and not candidate.is_lazy and all(item.accepted for item in candidate.validations)

    @staticmethod
    def generation_priority(candidate: RepairCandidate) -> float:
        confidence = _clamp01(float(candidate.confidence or 0.0))
        score_hint = _clamp01(float(candidate.score_hint or 0.0))
        native_validation = _native_validation(candidate.validations)
        validation_score = max([_clamp01(float(item.score or 0.0)) for item in candidate.validations] or [0.0])

        if native_validation is not None and not _native_validation_skipped(native_validation):
            score = confidence * 0.06
            score += _native_validation_strength(native_validation) * 0.6
            score += validation_score * 0.06
        else:
            score = confidence * 0.45
            score += validation_score * 0.1
        score += score_hint * 0.12
        score += _patch_plan_priority(candidate) * 0.18
        score += _module_generation_bias(candidate)
        if candidate.stage == "deep":
            score -= 0.08
        if candidate.partial:
            score -= 0.01
        if _content_damage_candidate(candidate) and not candidate.partial and native_validation is None:
            score = min(score, 0.45)
        return _clamp01(score)


def _selection_warnings(candidates: list[RepairCandidate]) -> list[str]:
    warnings: list[str] = []
    for candidate in candidates:
        for validation in candidate.validations:
            if validation.accepted:
                continue
            warnings.extend(validation.warnings)
    return _dedupe(warnings)


def materialize_candidates(candidates: list[RepairCandidate]) -> list[RepairCandidate]:
    output: list[RepairCandidate] = []
    for candidate in candidates:
        output.extend(materialize_candidate(candidate))
    return output


def materialize_candidate(candidate: RepairCandidate) -> list[RepairCandidate]:
    if not candidate.is_lazy:
        return [candidate]
    try:
        produced = candidate.materializer() if candidate.materializer is not None else None
    except Exception as exc:
        return [_materialization_failed(candidate, str(exc))]
    items = produced if isinstance(produced, list) else [produced]
    materialized: list[RepairCandidate] = []
    for item in items:
        coerced = _coerce_materialized_candidate(candidate, item)
        if coerced is not None:
            materialized.append(coerced)
    if not materialized:
        return [_materialization_failed(candidate, "repair plan produced no candidate")]
    return materialized


def _coerce_materialized_candidate(plan: RepairCandidate, item: Any) -> RepairCandidate | None:
    if isinstance(item, RepairCandidate):
        return replace(
            item,
            score_hint=max(float(item.score_hint or 0.0), float(plan.score_hint or 0.0)),
            stage=item.stage or plan.stage,
            diagnosis={**plan.diagnosis, **item.diagnosis},
            materializer=None,
            materialized=True,
            plan={**plan.plan, **item.plan},
        )
    if isinstance(item, RepairResult):
        candidate = RepairCandidate.from_result(item, score_hint=plan.score_hint, stage=plan.stage)
        if candidate is None:
            return None
        return replace(candidate, diagnosis={**plan.diagnosis, **candidate.diagnosis}, plan=dict(plan.plan))
    return None


def _materialization_failed(candidate: RepairCandidate, message: str) -> RepairCandidate:
    return replace(
        candidate,
        materializer=None,
        materialized=True,
        validations=[
            *candidate.validations,
            CandidateValidation(
                name="repair_plan_materialization",
                accepted=False,
                warnings=[message],
                details={"module": candidate.module_name, "plan": dict(candidate.plan)},
            ),
        ],
        warnings=_dedupe([*candidate.warnings, message]),
        message=message,
    )


def _native_validation(validations: list[CandidateValidation]) -> CandidateValidation | None:
    native = [item for item in validations if item.name == "native_candidate_validation"]
    if not native:
        return None
    return max(native, key=lambda item: float(item.score or 0.0))


def _content_damage_candidate(candidate: RepairCandidate) -> bool:
    return bool({
        "checksum_error",
        "crc_error",
        "damaged",
        "content_integrity_bad_or_unknown",
        "corrupted_data",
        "data_error",
    } & {str(flag) for flag in candidate.damage_flags})


def _patch_plan_priority(candidate: RepairCandidate) -> float:
    plan = candidate.plan if isinstance(candidate.plan, dict) else {}
    archive_state = plan.get("archive_state") if isinstance(plan.get("archive_state"), dict) else {}
    patches = archive_state.get("patches") or archive_state.get("patch_stack") or []
    if not patches and plan:
        return 0.5
    if not patches:
        return 0.25
    operation_count = 0
    byte_cost = 0
    for patch in patches:
        if not isinstance(patch, dict):
            continue
        for operation in patch.get("operations") or []:
            if not isinstance(operation, dict):
                continue
            operation_count += 1
            try:
                byte_cost += max(0, int(operation.get("size") or 0))
            except (TypeError, ValueError):
                pass
            data = operation.get("data_b64") or operation.get("data") or ""
            byte_cost += len(str(data))
    complexity = min(0.7, operation_count * 0.08 + byte_cost / (1024 * 1024 * 50))
    return _clamp01(0.85 - complexity)


def _module_generation_bias(candidate: RepairCandidate) -> float:
    module_name = str(candidate.module_name or "")
    if module_name == "zip64_field_repair":
        return 0.16
    if module_name == "zip_eocd_repair":
        return 0.12
    if module_name == "seven_zip_crc_field_repair":
        return 0.1
    if module_name == "zip_central_directory_rebuild":
        flags = {str(flag) for flag in candidate.damage_flags}
        if "eocd_bad" in flags and not (flags & {"central_directory_bad", "directory_integrity_bad_or_unknown", "local_header_recovery"}):
            return 0.0
        return 0.08
    return 0.0


def _native_validation_skipped(validation: CandidateValidation) -> bool:
    details = validation.details if isinstance(validation.details, dict) else {}
    return bool(details.get("skipped"))


def _native_validation_strength(validation: CandidateValidation) -> float:
    details = validation.details if isinstance(validation.details, dict) else {}
    score = _clamp01(float(validation.score or 0.0))
    probe = details.get("probe") if isinstance(details.get("probe"), dict) else {}
    test = details.get("test") if isinstance(details.get("test"), dict) else {}
    dry_run = details.get("dry_run") if isinstance(details.get("dry_run"), dict) else {}

    strength = score * 0.4
    if probe.get("is_archive") and not probe.get("is_broken"):
        strength += 0.16
    if test.get("ok"):
        strength += 0.22
    if details.get("empty_password_ok"):
        strength += 0.03
    resources = details.get("resource_analysis") if isinstance(details.get("resource_analysis"), dict) else {}
    if resources.get("ok"):
        strength += 0.08
    coverage = details.get("archive_coverage") if isinstance(details.get("archive_coverage"), dict) else {}
    if coverage.get("completeness") is not None:
        strength += min(0.1, float(coverage.get("completeness") or 0.0) * 0.1)
    if dry_run.get("ok"):
        strength += 0.24
    elif int(dry_run.get("files_written", 0) or 0) > 0 or int(dry_run.get("bytes_written", 0) or 0) > 0:
        strength += 0.1
    return _clamp01(strength)


def _clamp01(value: float) -> float:
    return min(1.0, max(0.0, value))


def _analyze_resources(tester, path: str, password: str):
    analyze = getattr(tester, "analyze_archive_resources", None)
    if not callable(analyze):
        return None
    try:
        return analyze(path, password=password)
    except Exception as exc:
        return {"error": str(exc)}


def _resource_details(resources) -> dict[str, Any]:
    if resources is None:
        return {"available": False}
    if isinstance(resources, dict):
        return {"available": False, **resources}
    return {
        "available": True,
        "status": getattr(resources, "status", None),
        "ok": bool(getattr(resources, "ok", False)),
        "is_archive": bool(getattr(resources, "is_archive", False)),
        "is_encrypted": bool(getattr(resources, "is_encrypted", False)),
        "is_broken": bool(getattr(resources, "is_broken", False)),
        "archive_type": str(getattr(resources, "archive_type", "") or ""),
        "item_count": int(getattr(resources, "item_count", 0) or 0),
        "file_count": int(getattr(resources, "file_count", 0) or 0),
        "total_unpacked_size": int(getattr(resources, "total_unpacked_size", 0) or 0),
        "total_packed_size": int(getattr(resources, "total_packed_size", 0) or 0),
        "message": str(getattr(resources, "message", "") or ""),
    }


def _candidate_coverage_ratio(resources, complete_files: int) -> float | None:
    if resources is None:
        return None
    if isinstance(resources, dict):
        return None
    expected = int(getattr(resources, "file_count", 0) or 0)
    if expected <= 0:
        return None
    return _clamp01(float(max(0, int(complete_files or 0))) / float(expected))


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value)
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output


def _result_plan(result: RepairResult) -> dict[str, Any]:
    plan: dict[str, Any] = {}
    if result.repaired_state is not None:
        plan["archive_state"] = result.repaired_state.to_dict()
    patch_plan = result.diagnosis.get("patch_plan") if isinstance(result.diagnosis, dict) else None
    if isinstance(patch_plan, dict):
        plan["patch_plan"] = dict(patch_plan)
    return plan


def _archive_state_from_plan(plan: dict[str, Any]) -> ArchiveState | None:
    raw = plan.get("archive_state") if isinstance(plan, dict) else None
    if not isinstance(raw, dict):
        return None
    try:
        return ArchiveState.from_dict(raw)
    except (TypeError, ValueError):
        return None
