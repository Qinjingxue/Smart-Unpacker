from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import zipfile
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from repair_training.runtime_features import (  # noqa: E402
    _analysis_summary,
    _candidate_proposal,
    _extraction_summary,
    _job_summary,
    _repair_hints,
    _runtime_state_summary,
    _verification_summary,
)
from repair_training.training_corruption import build_corpus_corruption_case  # noqa: E402
from sunpack.contracts.detection import FactBag  # noqa: E402
from sunpack.contracts.tasks import ArchiveTask  # noqa: E402
from sunpack.coordinator.repair_stage import ArchiveRepairStage  # noqa: E402
from sunpack.extraction.result import ExtractionResult  # noqa: E402
from sunpack.repair.job import RepairJob  # noqa: E402
from sunpack.verification import VerificationScheduler  # noqa: E402
from sunpack.verification.result import (  # noqa: E402
    ArchiveCoverageSummary,
    SOURCE_INTEGRITY_DAMAGED,
    VerificationResult,
)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = Path(args.output_dir)
    if root.exists() and args.clean:
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    clean_zip = root / "clean.zip"
    _write_clean_zip(clean_zip)
    case_root = root / "case"
    case = build_corpus_corruption_case(
        case_root,
        source_path=clean_zip,
        fmt="zip",
        seed=int(args.seed),
        variant_index=0,
        damage_profile=args.profile,
    )
    manifest = root / "manifest.jsonl"
    record = case.corpus_manifest_record(
        source_archive_id="runtime_alignment_clean",
        source_path=str(clean_zip),
        damage_profile=args.profile,
        variant_index=0,
        material_format="zip",
        material_sample_id="runtime_alignment",
    )
    record["runtime_damage_flags"] = _alignment_runtime_damage_flags(case)
    record["runtime_initial_verification"] = _verification_summary_payload(_initial_verification(case))
    manifest.write_text(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    training = _run_training_collector(root, manifest, args)
    real = _run_real_project_rounds(root, case, args)
    report = _compare(training, real)
    report.update({
        "profile": args.profile,
        "mode": args.mode,
        "clean_zip": str(clean_zip),
        "damaged_zip": str(case.source_input.get("path") or ""),
        "manifest": str(manifest),
        "training_success": str(training["success_output"]),
        "training_failure": str(training["failure_output"]),
        "real_trace": str(real["trace_path"]),
    })
    output = root / "runtime_alignment_report.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if not report["fatal_mismatches"] else 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare training runtime features with real repair layer traces.")
    parser.add_argument("--output-dir", default=".sunpack/runtime-feature-alignment")
    parser.add_argument("--profile", default="zip_two_step_drop_cd_with_eocd_noise")
    parser.add_argument("--seed", type=int, default=20260501)
    parser.add_argument("--max-rounds", type=int, default=2)
    parser.add_argument("--mode", choices=("greedy_current_selector", "counterfactual"), default="greedy_current_selector")
    parser.add_argument("--clean", action=argparse.BooleanOptionalAction, default=True)
    return parser


def _write_clean_zip(path: Path) -> None:
    payloads = {
        "alpha.txt": b"alpha" * 20,
        "beta/data.bin": bytes(range(64)) * 3,
        "gamma.txt": b"gamma" * 30,
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in payloads.items():
            archive.writestr(name, payload)


def _alignment_runtime_damage_flags(case) -> list[str]:
    flags = [str(flag) for flag in getattr(case, "damage_flags", []) or [] if str(flag)]
    if "damaged" not in flags:
        flags.append("damaged")
    return flags


def _run_training_collector(root: Path, manifest: Path, args: argparse.Namespace) -> dict[str, Any]:
    success = root / "training_success.jsonl"
    failure = root / "training_failure.jsonl"
    workspace = root / "training_workspace"
    command = [
        sys.executable,
        "repair_training/collect_repair_plan_data.py",
        "--manifest", str(manifest),
        "--success-output", str(success),
        "--failure-output", str(failure),
        "--workspace", str(workspace),
        "--formats", "zip",
        "--max-rounds", str(max(1, int(args.max_rounds))),
        "--rollout-mode", args.mode,
        "--beam-size", "2" if args.mode == "counterfactual" else "1",
        "--branch-top-k", "2" if args.mode == "counterfactual" else "1",
        "--counterfactual-extra", "1" if args.mode == "counterfactual" else "0",
        "--max-total-states-per-sample", "5",
        "--max-candidates-per-round", "6",
        "--materialize-top-k-per-round", "6",
        "--proposal-mode", "eager" if args.mode == "greedy_current_selector" else "lazy",
        "--case-timeout-seconds", "30",
        "--no-pretty",
    ]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT)
    subprocess.run(command, cwd=REPO_ROOT, env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    rows = [*_read_jsonl(success), *_read_jsonl(failure)]
    return {
        "success_output": success,
        "failure_output": failure,
        "rows": rows,
        "runtime_rows": [row for row in rows if row.get("row_type", "action") != "terminal"],
    }


def _run_real_project_rounds(root: Path, case, args: argparse.Namespace) -> dict[str, Any]:
    trace_path = root / "real_repair_trace.jsonl"
    previous_trace = os.environ.get("SUNPACK_REPAIR_TRACE_JSONL")
    os.environ["SUNPACK_REPAIR_TRACE_JSONL"] = str(trace_path)
    try:
        config = {
            "repair": {
                "enabled": True,
                "workspace": str(root / "real_workspace"),
                "max_repair_rounds_per_task": max(1, int(args.max_rounds)),
                "max_attempts_per_task": max(1, int(args.max_rounds)),
                "module_limits": {"max_candidates_per_module": 4, "verify_candidates": False, "max_seconds_per_module": 3.0},
            },
            "verification": {
                "enabled": True,
                "methods": [{"name": "archive_test_crc"}],
                "partial_accept_threshold": 0.2,
                "complete_accept_threshold": 0.999,
            },
        }
        task = _task_for_case(case)
        stage = ArchiveRepairStage(config)
        first_verification = _initial_verification(case)
        first_extraction = ExtractionResult(
            success=False,
            archive=str(case.source_input.get("path") or ""),
            out_dir=str(root / "initial_out"),
            all_parts=[str(case.source_input.get("path") or "")],
            error="synthetic alignment damaged input requires repair",
            diagnostics={"result": {"status": "failed", "native_status": "crc_error", "files_written": 0, "bytes_written": 0}},
        )
        results = []
        result = stage.repair_after_verification_assessment_result(task, first_extraction, first_verification)
        results.append(_result_summary(result))
        current_result = result
        verifier = VerificationScheduler(config)
        for round_index in range(1, max(1, int(args.max_rounds))):
            if current_result is None or not getattr(current_result, "ok", False):
                break
            archive_path = str((current_result.repaired_input or {}).get("path") or "")
            extracted = _extract_zip_best_effort(Path(archive_path), root / f"real_extract_round_{round_index}")
            verification = verifier.verify(task, extracted)
            result = stage.repair_after_verification_assessment_result(task, extracted, verification)
            results.append({
                "verification": _verification_summary_payload(verification),
                "repair_result": _result_summary(result),
            })
            current_result = result
        events = _read_jsonl(trace_path)
        return {"trace_path": trace_path, "events": events, "results": results}
    finally:
        if previous_trace is None:
            os.environ.pop("SUNPACK_REPAIR_TRACE_JSONL", None)
        else:
            os.environ["SUNPACK_REPAIR_TRACE_JSONL"] = previous_trace


def _task_for_case(case) -> ArchiveTask:
    archive_path = str(case.source_input.get("path") or "")
    bag = FactBag()
    bag.set("analysis.selected_format", "zip")
    bag.set("analysis.status", "selected")
    bag.set("analysis.evidences", [{
        "format": "zip",
        "confidence": 0.82,
        "status": "selected",
        "segments": [{"start_offset": 0, "end_offset": None, "confidence": 0.82, "role": "primary", "damage_flags": list(case.damage_flags)}],
        "details": {},
    }])
    bag.set("analysis.prepass", {"status": "selected", "format": "zip", "confidence": 0.82})
    bag.set("analysis.fuzzy", {"binary_profile": {"status": "selected", "archive_type": "zip", "confidence": 0.82}})
    bag.set("archive.format_hint", "zip")
    task = ArchiveTask(fact_bag=bag, score=10, key="runtime_alignment", main_path=archive_path, all_parts=[archive_path], detected_ext="zip")
    task.ensure_archive_state()
    return task


def _initial_verification(case) -> VerificationResult:
    expected = len(case.expected_files or {})
    coverage = ArchiveCoverageSummary(
        completeness=0.0,
        file_coverage=0.0,
        expected_files=expected,
        missing_files=expected,
        confidence=1.0,
    )
    return VerificationResult(
        completeness=0.0,
        recoverable_upper_bound=1.0,
        assessment_status="unusable",
        source_integrity=SOURCE_INTEGRITY_DAMAGED,
        decision_hint="repair",
        missing_files=expected,
        archive_coverage=coverage,
        repair_hints={
            "selected_format": "zip",
            "analysis_status": "selected",
            "analysis_confidence": 0.82,
            "source_integrity": SOURCE_INTEGRITY_DAMAGED,
            "boundary_untrusted": True,
        },
    )


def _extract_zip_best_effort(archive: Path, out_dir: Path) -> ExtractionResult:
    out_dir.mkdir(parents=True, exist_ok=True)
    success = False
    diagnostics: dict[str, Any] = {"result": {"status": "failed", "files_written": 0, "bytes_written": 0}}
    error = ""
    files_written = 0
    bytes_written = 0
    try:
        with zipfile.ZipFile(archive) as zip_file:
            for info in zip_file.infolist():
                if info.is_dir():
                    continue
                target = out_dir / info.filename
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    data = zip_file.read(info)
                except Exception as exc:
                    error = str(exc)
                    continue
                target.write_bytes(data)
                files_written += 1
                bytes_written += len(data)
        success = files_written > 0
    except Exception as exc:
        error = str(exc)
    diagnostics["result"] = {
        "status": "success" if success else "failed",
        "native_status": "success" if success else "failed",
        "files_written": files_written,
        "bytes_written": bytes_written,
        "message": error,
    }
    return ExtractionResult(
        success=success,
        archive=str(archive),
        out_dir=str(out_dir),
        all_parts=[str(archive)],
        error=error,
        diagnostics=diagnostics,
        partial_outputs=success,
    )


def _compare(training: dict[str, Any], real: dict[str, Any]) -> dict[str, Any]:
    training_rounds = _training_round_contexts(training["runtime_rows"])
    real_rounds = _real_round_contexts(real["events"])
    comparisons = []
    fatal: list[str] = []
    for round_index in sorted(set(training_rounds) | set(real_rounds)):
        train_context = training_rounds.get(round_index, {})
        real_context = real_rounds.get(round_index, {})
        diff = _dict_diff(train_context, real_context)
        comparisons.append({
            "round": round_index,
            "training_keys": sorted(train_context),
            "real_keys": sorted(real_context),
            "missing_in_training": diff["missing_in_left"],
            "missing_in_real": diff["missing_in_right"],
            "different_values": diff["different_values"],
        })
        fatal.extend(f"round {round_index}: missing in training {key}" for key in diff["missing_in_left"])
        fatal.extend(f"round {round_index}: missing in real {key}" for key in diff["missing_in_right"])
    same_fields = all(not item["missing_in_training"] and not item["missing_in_real"] for item in comparisons)
    same_values = all(int(item.get("different_value_count", len(item.get("different_values", []))) or 0) == 0 for item in comparisons)
    return {
        "fatal_mismatches": fatal,
        "field_set_aligned": same_fields,
        "field_values_identical": same_values,
        "round_count_training": len(training_rounds),
        "round_count_real": len(real_rounds),
        "comparisons": comparisons,
        "real_results": real["results"],
        "training_row_count": len(training["rows"]),
        "real_event_count": len(real["events"]),
    }


def _training_round_contexts(rows: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    output: dict[int, dict[str, Any]] = {}
    for row in rows:
        stable = row.get("stable_features") if isinstance(row.get("stable_features"), dict) else {}
        context = stable.get("runtime_context") if isinstance(stable.get("runtime_context"), dict) else {}
        if not context:
            continue
        round_index = int(row.get("round", 0) or 0)
        output.setdefault(round_index, _flatten_context(context))
    return output


def _real_round_contexts(events: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    output: dict[int, dict[str, Any]] = {}
    for event in events:
        if event.get("event") not in {"repair_candidates_generated", "repair_candidates_terminal"}:
            continue
        job_raw = event.get("job") if isinstance(event.get("job"), dict) else {}
        evidence_raw = job_raw.get("analysis_evidence")
        analysis_evidence = SimpleNamespace(**evidence_raw) if isinstance(evidence_raw, dict) else None
        job = RepairJob(
            source_input=dict(job_raw.get("source_input") or {}),
            format=str(job_raw.get("format") or ""),
            confidence=float(job_raw.get("confidence", 0.0) or 0.0),
            analysis_evidence=analysis_evidence,
            analysis_prepass=dict(job_raw.get("analysis_prepass") or {}),
            fuzzy_profile=dict(job_raw.get("fuzzy_profile") or {}),
            extraction_failure=dict(job_raw.get("extraction_failure") or {}) if isinstance(job_raw.get("extraction_failure"), dict) else None,
            extraction_diagnostics=dict(job_raw.get("extraction_diagnostics") or {}),
            damage_flags=list(job_raw.get("damage_flags") or []),
            archive_key=str(job_raw.get("archive_key") or ""),
            workspace=str(job_raw.get("workspace") or ""),
            attempts=int(job_raw.get("attempts", 0) or 0),
        )
        context = {
            "analysis_summary": _analysis_summary(job),
            "extraction_summary": _extraction_summary(job),
            "verification_summary": _verification_summary(job),
            "repair_hints": _repair_hints(job),
            "previous_actions": list((job.extraction_failure or {}).get("previous_actions") or []),
            "previous_action_count": len((job.extraction_failure or {}).get("previous_actions") or []),
            "previous_modules": list((job.extraction_failure or {}).get("previous_modules") or []),
            "previous_module_count": len((job.extraction_failure or {}).get("previous_modules") or []),
            "runtime_state_summary": _runtime_state_summary({}),
            "job_summary": _job_summary(job),
        }
        output.setdefault(int(job.attempts or 0), _flatten_context(context))
    return output


def _flatten_context(context: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    _flatten(output, "", context)
    return output


def _flatten(output: dict[str, Any], prefix: str, value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _flatten(output, f"{prefix}.{key}" if prefix else str(key), item)
        return
    if isinstance(value, list):
        output[prefix] = [str(item) for item in value]
        return
    output[prefix] = value


def _dict_diff(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_keys = set(left)
    right_keys = set(right)
    common = sorted(left_keys & right_keys)
    different = [
        {"field": key, "training": left.get(key), "real": right.get(key)}
        for key in common
        if left.get(key) != right.get(key)
    ]
    return {
        "missing_in_left": sorted(right_keys - left_keys),
        "missing_in_right": sorted(left_keys - right_keys),
        "different_values": different[:80],
        "different_value_count": len(different),
    }


def _verification_summary_payload(verification: VerificationResult) -> dict[str, Any]:
    coverage = verification.archive_coverage
    return {
        "assessment_status": verification.assessment_status,
        "decision_hint": verification.decision_hint,
        "source_integrity": verification.source_integrity,
        "completeness": verification.completeness,
        "recoverable_upper_bound": verification.recoverable_upper_bound,
        "complete_files": verification.complete_files,
        "partial_files": verification.partial_files,
        "failed_files": verification.failed_files,
        "missing_files": verification.missing_files,
        "unverified_files": verification.unverified_files,
        "repair_hints": dict(verification.repair_hints or {}),
        "archive_coverage": asdict(coverage),
    }


def _result_summary(result: Any) -> dict[str, Any]:
    if result is None:
        return {"status": "none", "ok": False}
    return {
        "status": getattr(result, "status", ""),
        "ok": bool(getattr(result, "ok", False)),
        "module_name": getattr(result, "module_name", ""),
        "actions": list(getattr(result, "actions", []) or []),
        "repaired_input": getattr(result, "repaired_input", {}),
    }


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    output = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            output.append(json.loads(line))
    return output


if __name__ == "__main__":
    raise SystemExit(main())
