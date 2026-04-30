from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import pickle
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sunpack.repair import RepairJob, RepairResult
from sunpack.repair.candidate import CandidateSelector, candidate_feature_payload, materialize_candidates
from tests.functional import test_repair_capability_matrix as matrix


DEFAULT_SUCCESS_OUTPUT = Path(".sunpack") / "datasets" / "repair_candidates_ltr_success_from_tests.jsonl"
DEFAULT_FAILURE_OUTPUT = Path(".sunpack") / "datasets" / "repair_candidates_ltr_failure_from_tests.jsonl"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    cases = _selected_cases(args.case, args.exclude_case, args.limit)
    success_output = Path(args.output or args.success_output)
    failure_output = Path(args.failure_output)
    debug_output = Path(args.debug_output) if args.debug_output else None
    success_output.parent.mkdir(parents=True, exist_ok=True)
    failure_output.parent.mkdir(parents=True, exist_ok=True)
    if debug_output is not None:
        debug_output.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if args.append else "w"

    summary = {
        "cases": 0,
        "success_records": 0,
        "failure_records": 0,
        "debug_records": 0,
        "verified": 0,
        "failed": 0,
        "timeouts": 0,
        "skipped": 0,
        "slow_cases": [],
        "success_output": str(success_output),
        "failure_output": str(failure_output),
    }
    success_pretty = _pretty_path(success_output)
    failure_pretty = _pretty_path(failure_output)
    success_pretty_records: list[dict[str, Any]] = _load_pretty_records(success_pretty) if args.pretty and args.append else []
    failure_pretty_records: list[dict[str, Any]] = _load_pretty_records(failure_pretty) if args.pretty and args.append else []
    debug_pretty_records: list[dict[str, Any]] = []
    debug_handle = debug_output.open(mode, encoding="utf-8") if debug_output is not None else None
    success_handle = None
    failure_handle = None
    try:
        success_handle = success_output.open(mode, encoding="utf-8")
        failure_handle = failure_output.open(mode, encoding="utf-8")
        try:
            _collect_to_outputs(
                cases,
                args,
                success_handle,
                failure_handle,
                debug_handle,
                success_pretty_records,
                failure_pretty_records,
                debug_pretty_records,
                summary,
            )
        finally:
            success_handle.close()
            failure_handle.close()
    finally:
        if debug_handle is not None:
            debug_handle.close()
    if args.pretty:
        success_pretty.write_text(json.dumps(success_pretty_records, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        failure_pretty.write_text(json.dumps(failure_pretty_records, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        summary["success_pretty_output"] = str(success_pretty)
        summary["failure_pretty_output"] = str(failure_pretty)
        if debug_output is not None:
            debug_pretty = _pretty_path(debug_output)
            debug_pretty.write_text(json.dumps(debug_pretty_records, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
            summary["debug_pretty_output"] = str(debug_pretty)

    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 1 if summary["failed"] or summary["timeouts"] else 0


def _collect_to_outputs(
    cases: list[Any],
    args: argparse.Namespace,
    success_handle,
    failure_handle,
    debug_handle,
    success_pretty_records: list[dict[str, Any]],
    failure_pretty_records: list[dict[str, Any]],
    debug_pretty_records: list[dict[str, Any]],
    summary: dict[str, Any],
) -> None:
    for case in cases:
        started = time.perf_counter()
        if args.progress:
            print(f"START {case.case_id}", flush=True)
        case_summary, debug_records = _collect_case_with_timeout(case, args)
        elapsed_seconds = time.perf_counter() - started
        case_summary["elapsed_seconds"] = round(elapsed_seconds, 3)
        if elapsed_seconds >= float(args.slow_case_seconds or 0):
            summary["slow_cases"].append({
                "case_id": case.case_id,
                "elapsed_seconds": round(elapsed_seconds, 3),
                "records": len(debug_records),
            })
        ltr_records = [_ltr_record(record) for record in debug_records]
        is_success_case = _case_has_repair_success(case_summary)
        if args.pretty:
            if is_success_case:
                success_pretty_records.extend(ltr_records)
            else:
                failure_pretty_records.extend(ltr_records)
            if debug_handle is not None:
                debug_pretty_records.extend(debug_records)
        summary["cases"] += 1
        if is_success_case:
            summary["success_records"] += len(ltr_records)
        else:
            summary["failure_records"] += len(ltr_records)
        summary["debug_records"] += len(debug_records) if debug_handle is not None else 0
        summary["verified"] += 1 if case_summary["verified_by_test"] else 0
        summary["failed"] += 1 if case_summary["collection_status"] == "failed" else 0
        summary["timeouts"] += 1 if case_summary["collection_status"] == "timeout" else 0
        summary["skipped"] += 1 if case_summary["collection_status"] == "skipped" else 0
        target_handle = success_handle if is_success_case else failure_handle
        for record in ltr_records:
            target_handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str) + "\n")
        if debug_handle is not None:
            for record in debug_records:
                debug_handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str) + "\n")
        if args.verbose:
            print(_case_line(case_summary, len(debug_records)))
        elif args.progress:
            print(
                f"END {case.case_id} status={case_summary['collection_status']} "
                f"records={len(debug_records)} elapsed={case_summary['elapsed_seconds']}s",
                flush=True,
            )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect repair candidate ranking features from the functional repair matrix.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Success LTR JSONL target path. Alias for --success-output.",
    )
    parser.add_argument(
        "--success-output",
        default=str(DEFAULT_SUCCESS_OUTPUT),
        help="Compact LTR JSONL target path for repaired/partial test cases.",
    )
    parser.add_argument(
        "--failure-output",
        default=str(DEFAULT_FAILURE_OUTPUT),
        help="Compact LTR JSONL target path for unrepairable/failed test cases.",
    )
    parser.add_argument(
        "--debug-output",
        default=None,
        help="Optional debug JSONL target path with candidate explanations. Omitted by default.",
    )
    parser.add_argument("--append", action="store_true", help="Append instead of overwriting the JSONL file.")
    parser.set_defaults(pretty=True)
    parser.add_argument("--pretty", action="store_true", help="Also write formatted .pretty.json files for manual inspection. Enabled by default.")
    parser.add_argument("--no-pretty", action="store_false", dest="pretty", help="Only write compact JSONL files.")
    parser.add_argument("--case", action="append", default=[], help="Collect only a specific matrix case id. Repeatable.")
    parser.add_argument("--exclude-case", action="append", default=[], help="Skip a specific matrix case id. Repeatable.")
    parser.add_argument("--limit", type=int, default=0, help="Collect at most N cases after case filtering.")
    parser.add_argument(
        "--max-candidates-per-case",
        type=int,
        default=8,
        help="Verify at most N generated candidates per case for strong labels; all generated candidates are still logged.",
    )
    parser.add_argument(
        "--slow-case-seconds",
        type=float,
        default=15.0,
        help="Record cases slower than this threshold in the summary.",
    )
    parser.add_argument(
        "--case-timeout-seconds",
        type=float,
        default=30.0,
        help="Terminate and skip a case that takes longer than this many seconds. Use 0 to disable.",
    )
    parser.add_argument("--progress", action="store_true", help="Print START/END markers before and after each case.")
    parser.add_argument("--trace-steps", action="store_true", help="Print per-case phase markers inside the collector.")
    parser.add_argument(
        "--module-scope",
        choices=("format", "full", "expected"),
        default="format",
        help="Use a broad format-specific module group, the full configured module set, or only the case's expected modules. Default: format.",
    )
    parser.add_argument(
        "--strict-expected-selection",
        action="store_true",
        help="Mark collection failed when full-module selection differs from the matrix expected_module.",
    )
    parser.add_argument("--verbose", action="store_true", help="Print one summary line per case.")
    return parser


def _selected_cases(case_ids: list[str], exclude_case_ids: list[str], limit: int) -> list[Any]:
    selected = list(matrix.MATRIX)
    if case_ids:
        wanted = set(case_ids)
        selected = [case for case in selected if case.case_id in wanted]
        missing = sorted(wanted - {case.case_id for case in selected})
        if missing:
            raise SystemExit(f"unknown case id(s): {', '.join(missing)}")
    if exclude_case_ids:
        excluded = set(exclude_case_ids)
        selected = [case for case in selected if case.case_id not in excluded]
    if limit and limit > 0:
        selected = selected[:limit]
    return selected


def _modules_for_case(case, module_scope: str) -> tuple[str, ...]:
    if module_scope == "expected":
        return tuple(case.modules)
    if module_scope == "full":
        return ()
    competition_modules = tuple(getattr(case, "competition_modules", ()) or ())
    if competition_modules:
        return competition_modules
    dynamic = _dynamic_stream_modules(case)
    if dynamic is not None:
        return dynamic
    return _FORMAT_MODULES.get(str(case.fmt).lower(), ())


def _dynamic_stream_modules(case) -> tuple[str, ...] | None:
    fmt = str(case.fmt).lower()
    flags = set(case.flags)
    stream_formats = {"gzip", "bzip2", "xz", "zstd", "tar.gz", "tgz", "tar.bz2", "tar.xz", "tar.zst"}
    if fmt not in stream_formats:
        return None
    if "deflate_resync" in flags:
        return ("gzip_deflate_member_resync", "gzip_deflate_prefix_salvage", "gzip_truncated_partial_recovery")
    if flags & {"input_truncated", "probably_truncated", "unexpected_end", "unexpected_eof", "truncated"}:
        if case.modules:
            return tuple(case.modules)
        if fmt == "gzip":
            return ("gzip_truncated_partial_recovery",)
        if fmt == "bzip2":
            return ("bzip2_truncated_partial_recovery",)
        if fmt == "xz":
            return ("xz_truncated_partial_recovery",)
        if fmt == "zstd":
            return ("zstd_truncated_partial_recovery",)
    if flags & {"checksum_error", "data_error", "damaged"} and case.modules:
        return tuple(case.modules)
    return None


_FORMAT_MODULES: dict[str, tuple[str, ...]] = {
    "zip": (
        "zip_eocd_repair",
        "zip_comment_length_fix",
        "zip_central_directory_count_fix",
        "zip_central_directory_offset_fix",
        "zip64_field_repair",
        "zip_local_header_field_repair",
        "zip_trailing_junk_trim",
        "zip_central_directory_rebuild",
        "zip_data_descriptor_recovery",
        "zip_entry_quarantine_rebuild",
        "zip_partial_recovery",
        "zip_deep_partial_recovery",
        "zip_missing_volume_partial_salvage",
        "zip_conflict_resolver_rebuild",
        "archive_nested_payload_salvage",
    ),
    "7z": (
        "seven_zip_start_header_crc_fix",
        "seven_zip_next_header_field_repair",
        "seven_zip_boundary_trim",
        "seven_zip_precise_boundary_repair",
        "seven_zip_crc_field_repair",
        "seven_zip_solid_block_partial_salvage",
        "seven_zip_non_solid_partial_salvage",
        "archive_carrier_crop_deep_recovery",
    ),
    "rar": (
        "rar_trailing_junk_trim",
        "rar_carrier_crop_deep_recovery",
        "rar_block_chain_trim",
        "rar_end_block_repair",
        "rar_file_quarantine_rebuild",
        "rar4_file_quarantine_rebuild",
    ),
    "tar": (
        "tar_header_checksum_fix",
        "tar_truncated_partial_recovery",
        "tar_metadata_downgrade_recovery",
        "tar_sparse_pax_longname_repair",
        "tar_trailing_junk_trim",
        "tar_trailing_zero_block_repair",
    ),
    "gzip": (
        "gzip_trailing_junk_trim",
        "gzip_footer_fix",
        "gzip_deflate_member_resync",
        "gzip_deflate_prefix_salvage",
        "gzip_truncated_partial_recovery",
    ),
    "bzip2": (
        "bzip2_trailing_junk_trim",
        "bzip2_block_salvage",
        "bzip2_truncated_partial_recovery",
    ),
    "xz": (
        "xz_trailing_junk_trim",
        "xz_block_salvage",
        "xz_truncated_partial_recovery",
    ),
    "zstd": (
        "zstd_trailing_junk_trim",
        "zstd_frame_salvage",
        "zstd_truncated_partial_recovery",
    ),
    "tar.gz": ("tar_gzip_truncated_partial_recovery", "gzip_trailing_junk_trim", "gzip_truncated_partial_recovery"),
    "tgz": ("tar_gzip_truncated_partial_recovery", "gzip_trailing_junk_trim", "gzip_truncated_partial_recovery"),
    "tar.bz2": ("tar_bzip2_truncated_partial_recovery", "bzip2_trailing_junk_trim", "bzip2_truncated_partial_recovery"),
    "tar.xz": ("tar_xz_truncated_partial_recovery", "xz_trailing_junk_trim", "xz_truncated_partial_recovery"),
    "tar.zst": ("tar_zstd_truncated_partial_recovery", "zstd_trailing_junk_trim", "zstd_truncated_partial_recovery"),
}


def _pretty_path(path: Path) -> Path:
    suffix = "".join(path.suffixes)
    if suffix:
        return path.with_name(path.name.removesuffix(suffix) + ".pretty.json")
    return path.with_name(path.name + ".pretty.json")


def _load_pretty_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(loaded, list):
        return []
    return [item for item in loaded if isinstance(item, dict)]


def _case_has_repair_success(case_summary: dict[str, Any]) -> bool:
    return bool(case_summary.get("repair_success"))


def _collect_case_with_timeout(case, args: argparse.Namespace) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    timeout = float(args.case_timeout_seconds or 0)
    if timeout <= 0:
        return _collect_case(case, args)
    with tempfile.TemporaryDirectory(prefix=f"sunpack-candidate-worker-{case.case_id}-") as raw_tmp:
        result_path = Path(raw_tmp) / "result.pkl"
        process = mp.Process(target=_collect_case_worker, args=(case, args, str(result_path)), daemon=True)
        process.start()
        process.join(timeout)
        if process.is_alive():
            process.terminate()
            process.join(5)
            if process.is_alive():
                process.kill()
                process.join(5)
            case_summary = _case_summary(
                case,
                None,
                verified_by_test=False,
                verification_error=f"case collection exceeded {timeout:.1f}s timeout",
                collection_status="timeout",
                module_scope=args.module_scope,
            )
            return case_summary, [_empty_record(case, None, None, case_summary)]
        if result_path.exists():
            with result_path.open("rb") as handle:
                return pickle.load(handle)
        case_summary = _case_summary(
            case,
            None,
            verified_by_test=False,
            verification_error=f"case worker exited without a result (exitcode={process.exitcode})",
            collection_status="failed",
            module_scope=args.module_scope,
        )
        return case_summary, [_empty_record(case, None, None, case_summary)]


def _collect_case_worker(case, args: argparse.Namespace, result_path: str) -> None:
    result = _collect_case(case, args)
    with Path(result_path).open("wb") as handle:
        pickle.dump(result, handle)


def _collect_case(case, args: argparse.Namespace) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    with tempfile.TemporaryDirectory(prefix=f"sunpack-candidates-{case.case_id}-") as raw_tmp:
        root = Path(raw_tmp)
        try:
            _trace(args, case.case_id, "build")
            fixture = case.build(root / case.case_id)
            modules = _modules_for_case(case, args.module_scope)
            scheduler = matrix._repair_scheduler(root, modules=modules)
            job = RepairJob(
                source_input=fixture.source_input,
                format=case.fmt,
                confidence=0.82,
                damage_flags=list(case.flags),
                archive_key=case.case_id,
            )
            _trace(args, case.case_id, "generate")
            generated_batch = scheduler.generate_repair_candidates(job)
            _trace(args, case.case_id, "select")
            result = _select_generated_result(scheduler, job, generated_batch)
            _trace(args, case.case_id, "verify-selected")
            verified_by_test, verification_error = _verify_case_result(
                case,
                result,
                fixture,
                strict_expected_selection=bool(args.strict_expected_selection or args.module_scope == "expected"),
            )
            case_summary = _case_summary(
                case,
                result,
                verified_by_test=verified_by_test,
                verification_error=verification_error,
                collection_status="ok" if verified_by_test else "failed",
                module_scope=args.module_scope,
            )
            _trace(args, case.case_id, "label-candidates")
            records = _records_from_case(
                case,
                job,
                generated_batch,
                result,
                case_summary,
                fixture,
                scheduler.config,
                int(args.max_candidates_per_case or 0),
            )
            if not records:
                records.append(_empty_record(case, job, result, case_summary))
            return case_summary, records
        except pytest.skip.Exception as exc:
            case_summary = _case_summary(
                case,
                None,
                verified_by_test=False,
                verification_error=str(exc),
                collection_status="skipped",
                module_scope=args.module_scope,
            )
            return case_summary, [_empty_record(case, None, None, case_summary)]
        except Exception as exc:
            case_summary = _case_summary(
                case,
                None,
                verified_by_test=False,
                verification_error=str(exc),
                collection_status="failed",
                module_scope=args.module_scope,
            )
            return case_summary, [_empty_record(case, None, None, case_summary)]


def _trace(args: argparse.Namespace, case_id: str, step: str) -> None:
    if bool(getattr(args, "trace_steps", False)):
        print(f"TRACE {case_id} {step}", flush=True)


def _verify_case_result(case, result, fixture, *, strict_expected_selection: bool = True) -> tuple[bool, str | None]:
    try:
        if not strict_expected_selection:
            if result.status in {"repaired", "partial"}:
                if case.verify is not None:
                    try:
                        case.verify(result, fixture)
                    except pytest.skip.Exception:
                        raise
                    except Exception as exc:
                        return True, f"non_strict_selected_candidate_not_case_verified: {exc}"
                return True, None
            if result.status in case.expected_statuses:
                return True, None
            return False, f"unexpected result status={result.status} module={result.module_name}"
        status_ok = result.status in case.expected_statuses
        module_ok = not strict_expected_selection or case.expected_module is None or result.module_name == case.expected_module
        if not status_ok or not module_ok:
            return False, f"unexpected result status={result.status} module={result.module_name}"
        if result.status in {"repaired", "partial"} and case.verify is not None:
            case.verify(result, fixture)
        return True, None
    except pytest.skip.Exception:
        raise
    except Exception as exc:
        return False, str(exc)


def _select_generated_result(scheduler, job: RepairJob, generated_batch) -> RepairResult:
    if generated_batch.terminal_result is not None:
        return generated_batch.terminal_result
    selector = CandidateSelector(scheduler.config)
    selected, selection = selector.select(list(generated_batch.candidates))
    if selected is not None:
        return selected.to_result(selection=selection)
    diagnosis = dict(generated_batch.diagnosis) if isinstance(generated_batch.diagnosis, dict) else {}
    if selection:
        diagnosis["candidate_selection"] = dict(selection)
    return RepairResult(
        status="unrepairable",
        confidence=float(diagnosis.get("confidence", 0.0) or 0.0),
        format=str(diagnosis.get("format") or job.format),
        warnings=list(generated_batch.warnings or []),
        diagnosis=diagnosis,
        message=generated_batch.message or "registered repair modules did not produce a candidate",
    )


def _records_from_case(
    case,
    job: RepairJob,
    generated_batch,
    result,
    case_summary: dict[str, Any],
    fixture,
    scheduler_config: dict[str, Any],
    max_candidates_per_case: int,
) -> list[dict[str, Any]]:
    validated_by_id = _validated_features_by_id(result)
    selected_ids = _selected_candidate_ids(result, validated_by_id)
    candidate_labels = _candidate_labels(
        case,
        job,
        generated_batch,
        fixture,
        scheduler_config,
        selected_ids=selected_ids,
        max_candidates_per_case=max_candidates_per_case,
    )
    records = []
    for index, candidate in enumerate(generated_batch.candidates):
        features = candidate_feature_payload(candidate)
        candidate_id = str(features.get("candidate_id") or "")
        validated_features = validated_by_id.get(candidate_id)
        label_info = candidate_labels.get(candidate_id, {"label": 0, "label_source": "candidate_not_verified_budget"})
        selected = candidate_id in selected_ids
        records.append({
            "schema_version": 1,
            "source": "tests.functional.test_repair_capability_matrix",
            "archive_key": job.archive_key,
            "attempt_id": f"{case.case_id}:0",
            "case_id": case.case_id,
            "round": 0,
            "phase": "generated",
            "candidate_index": index,
            "candidate_id": candidate_id,
            "candidate_features": features,
            "validated_candidate_features": validated_features,
            "expected_module": case.expected_module,
            "actual_selected": case_summary["actual_selected"],
            "candidate_selected": selected,
            "selected": selected,
            "rejected": not selected,
            "candidate_label": label_info.get("label", 0),
            "candidate_label_source": label_info.get("label_source", "test_candidate_verification"),
            "candidate_verification_status": label_info.get("status"),
            "candidate_verification_error": label_info.get("error"),
            "candidate_native_accepted": label_info.get("native_accepted"),
            "candidate_is_expected_module": bool(case.expected_module and features.get("module") == case.expected_module),
            "result_status": case_summary["result_status"],
            "repair_success": case_summary["repair_success"],
            "test_passed": case_summary["test_passed"],
            "verified_by_test": case_summary["verified_by_test"],
            "verification_error": case_summary["verification_error"],
            "expected_statuses": list(case.expected_statuses),
            "format": case.fmt,
            "damage_flags": list(case.flags),
            "module_scope": case_summary.get("module_scope", "full"),
            "selection_summary": _selection_summary(result),
            "generation_summary": _generation_summary(generated_batch),
        })
    return records


def _ltr_record(record: dict[str, Any]) -> dict[str, Any]:
    features = record.get("validated_candidate_features") or record.get("candidate_features") or {}
    ltr_features = dict(features.get("ltr_features") or {}) if isinstance(features, dict) else {}
    label = _ltr_label(record)
    has_candidate = bool(record.get("candidate_id")) and bool(ltr_features)
    return {
        "schema_version": 1,
        "source": record.get("source"),
        "record_kind": "candidate" if has_candidate else "no_candidate",
        "query_id": record.get("attempt_id"),
        "case_id": record.get("case_id"),
        "candidate_id": record.get("candidate_id"),
        "candidate_index": record.get("candidate_index"),
        "has_candidate": has_candidate,
        "label": label,
        "label_source": record.get("candidate_label_source") or "test_candidate_verification",
        "candidate_selected": bool(record.get("candidate_selected")),
        "candidate_native_accepted": record.get("candidate_native_accepted"),
        "candidate_verification_status": record.get("candidate_verification_status"),
        "candidate_verification_error": record.get("candidate_verification_error"),
        "candidate_is_expected_module": bool(record.get("candidate_is_expected_module")),
        "expected_module": record.get("expected_module"),
        "actual_selected": record.get("actual_selected"),
        "result_status": record.get("result_status"),
        "repair_success": bool(record.get("repair_success")),
        "test_passed": bool(record.get("test_passed", record.get("verified_by_test"))),
        "verified_by_test": bool(record.get("verified_by_test")),
        "format": record.get("format"),
        "damage_flags": list(record.get("damage_flags") or []),
        "module_scope": record.get("module_scope", "full"),
        "query_features": _query_features(record),
        "features": ltr_features,
    }


def _ltr_label(record: dict[str, Any]) -> int:
    if record.get("candidate_id"):
        try:
            return int(record.get("candidate_label", 0))
        except (TypeError, ValueError):
            return 0
    return 0


def _candidate_labels(
    case,
    job: RepairJob,
    generated_batch,
    fixture,
    scheduler_config: dict[str, Any],
    *,
    selected_ids: set[str],
    max_candidates_per_case: int,
) -> dict[str, dict[str, Any]]:
    selector = CandidateSelector(scheduler_config)
    labels: dict[str, dict[str, Any]] = {}
    candidates_to_verify = _candidate_verification_subset(
        list(generated_batch.candidates),
        selected_ids=selected_ids,
        expected_module=case.expected_module,
        max_candidates=max_candidates_per_case,
    )
    materialized = materialize_candidates(candidates_to_verify)
    for candidate in materialized:
        candidate = selector._with_native_validation(candidate)
        features = candidate_feature_payload(candidate)
        candidate_id = str(features.get("candidate_id") or "")
        if not candidate_id:
            continue
        native_accepted = bool(candidate.repaired_input) and not candidate.is_lazy and all(
            validation.accepted for validation in candidate.validations
        )
        labels[candidate_id] = _candidate_label(case, candidate, fixture, native_accepted=native_accepted)
    return labels


def _candidate_verification_subset(candidates: list[Any], *, selected_ids: set[str], expected_module: str | None, max_candidates: int) -> list[Any]:
    if max_candidates <= 0 or len(candidates) <= max_candidates:
        return candidates
    ranked: list[tuple[int, float, int, Any]] = []
    for index, candidate in enumerate(candidates):
        features = candidate_feature_payload(candidate)
        candidate_id = str(features.get("candidate_id") or "")
        module = str(features.get("module") or getattr(candidate, "module_name", "") or "")
        priority = _safe_float(features.get("generation_priority"))
        keep_rank = 0
        if candidate_id in selected_ids:
            keep_rank -= 100
        if expected_module and module == expected_module:
            keep_rank -= 50
        ranked.append((keep_rank, -priority, index, candidate))
    ranked.sort(key=lambda item: item[:3])
    return [item[3] for item in ranked[:max_candidates]]


def _candidate_label(case, candidate, fixture, *, native_accepted: bool) -> dict[str, Any]:
    if not native_accepted:
        return {
            "label": 0,
            "label_source": "native_or_materialization_rejected",
            "status": getattr(candidate, "status", None),
            "error": _candidate_validation_error(candidate),
            "native_accepted": False,
        }
    result = candidate.to_result(selection={"selected_module": candidate.module_name})
    if result.status not in {"repaired", "partial"}:
        return {
            "label": 0,
            "label_source": "non_success_status",
            "status": result.status,
            "error": result.message,
            "native_accepted": True,
        }
    if case.verify is None:
        return {
            "label": 0,
            "label_source": "no_test_verifier",
            "status": result.status,
            "error": "matrix case has no candidate-level verifier",
            "native_accepted": True,
        }
    try:
        case.verify(result, fixture)
    except pytest.skip.Exception:
        raise
    except Exception as exc:
        return {
            "label": -1,
            "label_source": "hard_negative_failed_test_verification",
            "status": result.status,
            "error": str(exc),
            "native_accepted": True,
        }
    return {
        "label": 2 if result.status == "repaired" else 1,
        "label_source": "test_candidate_verification",
        "status": result.status,
        "error": None,
        "native_accepted": True,
    }


def _candidate_validation_error(candidate) -> str:
    warnings: list[str] = []
    for validation in getattr(candidate, "validations", []) or []:
        if validation.accepted:
            continue
        warnings.extend(validation.warnings)
    return "; ".join(warnings)


def _validated_features_by_id(result) -> dict[str, dict[str, Any]]:
    selection = _selection_payload(result)
    output: dict[str, dict[str, Any]] = {}
    for item in selection.get("candidates") or []:
        if not isinstance(item, dict):
            continue
        candidate_id = str(item.get("candidate_id") or "")
        if candidate_id:
            output[candidate_id] = item
    return output


def _selected_candidate_ids(result, validated_by_id: dict[str, dict[str, Any]]) -> set[str]:
    selection = _selection_payload(result)
    selected_module = str(selection.get("selected_module") or getattr(result, "module_name", "") or "")
    selected_priority = selection.get("generation_priority")
    selected: set[str] = set()
    for candidate_id, features in validated_by_id.items():
        if str(features.get("module") or "") != selected_module:
            continue
        if selected_priority is None or _float_equal(features.get("generation_priority"), selected_priority):
            selected.add(candidate_id)
    if selected:
        return selected
    return {
        candidate_id
        for candidate_id, features in validated_by_id.items()
        if str(features.get("module") or "") == selected_module
    }


def _case_summary(
    case,
    result,
    *,
    verified_by_test: bool,
    verification_error: str | None,
    collection_status: str,
    module_scope: str = "full",
) -> dict[str, Any]:
    result_status = getattr(result, "status", None)
    actual_selected = getattr(result, "module_name", None)
    status_ok = result is not None and result_status in case.expected_statuses
    module_ok = result is not None and (case.expected_module is None or actual_selected == case.expected_module)
    test_passed = bool(status_ok and module_ok and verified_by_test)
    repair_success = bool(test_passed and result_status in {"repaired", "partial"})
    return {
        "case_id": case.case_id,
        "expected_module": case.expected_module,
        "actual_selected": actual_selected,
        "result_status": result_status,
        "repair_success": repair_success,
        "test_passed": test_passed,
        "verified_by_test": bool(verified_by_test),
        "verification_error": verification_error,
        "collection_status": collection_status,
        "module_scope": module_scope,
    }


def _empty_record(case, job, result, case_summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "source": "tests.functional.test_repair_capability_matrix",
        "archive_key": getattr(job, "archive_key", case.case_id),
        "attempt_id": f"{case.case_id}:0",
        "case_id": case.case_id,
        "round": 0,
        "phase": "no_candidates",
        "candidate_index": None,
        "candidate_id": None,
        "candidate_features": None,
        "validated_candidate_features": None,
        "expected_module": case.expected_module,
        "actual_selected": case_summary["actual_selected"],
        "candidate_selected": False,
        "selected": False,
        "rejected": False,
        "candidate_is_expected_module": False,
        "result_status": case_summary["result_status"],
        "repair_success": case_summary["repair_success"],
        "test_passed": case_summary["test_passed"],
        "verified_by_test": case_summary["verified_by_test"],
        "verification_error": case_summary["verification_error"],
        "expected_statuses": list(case.expected_statuses),
        "format": case.fmt,
        "damage_flags": list(case.flags),
        "module_scope": case_summary.get("module_scope", "full"),
        "selection_summary": _selection_summary(result),
        "generation_summary": {"candidate_count": 0},
    }


def _query_features(record: dict[str, Any]) -> dict[str, Any]:
    damage_flags = list(record.get("damage_flags") or [])
    return {
        "format": record.get("format"),
        "damage_flag_count": len(damage_flags),
        "has_expected_module": 1 if record.get("expected_module") else 0,
        "result_status": record.get("result_status"),
    }


def _generation_summary(generated_batch) -> dict[str, Any]:
    diagnosis = generated_batch.diagnosis if isinstance(generated_batch.diagnosis, dict) else {}
    generation = diagnosis.get("candidate_generation") if isinstance(diagnosis.get("candidate_generation"), dict) else {}
    decision = diagnosis.get("capability_decision") if isinstance(diagnosis.get("capability_decision"), dict) else {}
    modules = decision.get("modules") if isinstance(decision.get("modules"), list) else []
    selected_modules = decision.get("selected_modules")
    if not isinstance(selected_modules, list):
        selected_modules = [
            item.get("name")
            for item in modules
            if isinstance(item, dict) and item.get("selected")
        ]
    return {
        "candidate_count": len(generated_batch.candidates),
        "terminal_result": _terminal_result_summary(generated_batch.terminal_result),
        "warnings": list(getattr(generated_batch, "warnings", []) or []),
        "message": str(getattr(generated_batch, "message", "") or ""),
        "candidate_generation": {
            "candidate_count": generation.get("candidate_count", len(generated_batch.candidates)),
            "auto_deep_attempted": bool(generation.get("auto_deep_attempted", False)),
            "warnings": list(generation.get("warnings") or []),
        },
        "capability_decision": {
            "format": decision.get("format"),
            "categories": list(decision.get("categories") or []),
            "selected_modules": selected_modules,
            "module_count": len(modules),
            "no_candidate_modules": [
                item.get("name")
                for item in modules
                if isinstance(item, dict) and "no_candidates" in set(item.get("dynamic_reasons") or [])
            ],
        },
    }


def _selection_payload(result) -> dict[str, Any]:
    diagnosis = getattr(result, "diagnosis", {}) if result is not None else {}
    if not isinstance(diagnosis, dict):
        return {}
    selection = diagnosis.get("candidate_selection")
    return dict(selection) if isinstance(selection, dict) else {}


def _selection_summary(result) -> dict[str, Any]:
    selection = _selection_payload(result)
    return {
        "candidate_count": selection.get("candidate_count"),
        "accepted_count": selection.get("accepted_count"),
        "selected_module": selection.get("selected_module"),
        "selected_format": selection.get("selected_format"),
        "generation_priority": selection.get("generation_priority"),
        "message": selection.get("message"),
    }


def _terminal_result_summary(result) -> dict[str, Any] | None:
    if result is None:
        return None
    return {
        "status": getattr(result, "status", None),
        "module_name": getattr(result, "module_name", None),
        "format": getattr(result, "format", None),
        "message": getattr(result, "message", None),
    }


def _compact_json(value: Any) -> Any:
    try:
        json.dumps(value, ensure_ascii=False, default=str)
        return value
    except TypeError:
        return str(value)


def _float_equal(left: Any, right: Any) -> bool:
    try:
        return abs(float(left) - float(right)) <= 1e-12
    except (TypeError, ValueError):
        return left == right


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _case_line(case_summary: dict[str, Any], records: int) -> str:
    return (
        f"{case_summary['case_id']}: {case_summary['collection_status']} "
        f"status={case_summary['result_status']} selected={case_summary['actual_selected']} "
        f"records={records} elapsed={case_summary.get('elapsed_seconds', 0)}s"
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
