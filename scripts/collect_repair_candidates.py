from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sunpack.repair import RepairJob
from sunpack.repair.candidate import candidate_feature_payload
from tests.functional import test_repair_capability_matrix as matrix


DEFAULT_LTR_OUTPUT = Path(".sunpack") / "datasets" / "repair_candidates_ltr_from_tests.jsonl"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    cases = _selected_cases(args.case, args.limit)
    ltr_output = Path(args.output or args.ltr_output)
    debug_output = Path(args.debug_output) if args.debug_output else None
    ltr_output.parent.mkdir(parents=True, exist_ok=True)
    if debug_output is not None:
        debug_output.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if args.append else "w"

    summary = {
        "cases": 0,
        "ltr_records": 0,
        "debug_records": 0,
        "verified": 0,
        "failed": 0,
        "skipped": 0,
        "ltr_output": str(ltr_output),
    }
    ltr_pretty_records: list[dict[str, Any]] = []
    debug_pretty_records: list[dict[str, Any]] = []
    debug_handle = debug_output.open(mode, encoding="utf-8") if debug_output is not None else None
    try:
        ltr_handle = ltr_output.open(mode, encoding="utf-8")
        try:
            _collect_to_outputs(
                cases,
                args,
                ltr_handle,
                debug_handle,
                ltr_pretty_records,
                debug_pretty_records,
                summary,
            )
        finally:
            ltr_handle.close()
    finally:
        if debug_handle is not None:
            debug_handle.close()
    if args.pretty:
        ltr_pretty = _pretty_path(ltr_output)
        ltr_pretty.write_text(json.dumps(ltr_pretty_records, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        summary["ltr_pretty_output"] = str(ltr_pretty)
        if debug_output is not None:
            debug_pretty = _pretty_path(debug_output)
            debug_pretty.write_text(json.dumps(debug_pretty_records, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
            summary["debug_pretty_output"] = str(debug_pretty)

    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 1 if summary["failed"] else 0


def _collect_to_outputs(
    cases: list[Any],
    args: argparse.Namespace,
    ltr_handle,
    debug_handle,
    ltr_pretty_records: list[dict[str, Any]],
    debug_pretty_records: list[dict[str, Any]],
    summary: dict[str, Any],
) -> None:
    for case in cases:
        case_summary, debug_records = _collect_case(case)
        ltr_records = [_ltr_record(record) for record in debug_records]
        if args.pretty:
            ltr_pretty_records.extend(ltr_records)
            if debug_handle is not None:
                debug_pretty_records.extend(debug_records)
        summary["cases"] += 1
        summary["ltr_records"] += len(ltr_records)
        summary["debug_records"] += len(debug_records) if debug_handle is not None else 0
        summary["verified"] += 1 if case_summary["verified_by_test"] else 0
        summary["failed"] += 1 if case_summary["collection_status"] == "failed" else 0
        summary["skipped"] += 1 if case_summary["collection_status"] == "skipped" else 0
        for record in ltr_records:
            ltr_handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str) + "\n")
        if debug_handle is not None:
            for record in debug_records:
                debug_handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str) + "\n")
        if args.verbose:
            print(_case_line(case_summary, len(debug_records)))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect repair candidate ranking features from the functional repair matrix.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="LTR JSONL target path. Alias for --ltr-output.",
    )
    parser.add_argument(
        "--ltr-output",
        default=str(DEFAULT_LTR_OUTPUT),
        help="Compact LTR JSONL target path.",
    )
    parser.add_argument(
        "--debug-output",
        default=None,
        help="Optional debug JSONL target path with candidate explanations. Omitted by default.",
    )
    parser.add_argument("--append", action="store_true", help="Append instead of overwriting the JSONL file.")
    parser.add_argument("--pretty", action="store_true", help="Also write formatted .pretty.json files for manual inspection.")
    parser.add_argument("--case", action="append", default=[], help="Collect only a specific matrix case id. Repeatable.")
    parser.add_argument("--limit", type=int, default=0, help="Collect at most N cases after case filtering.")
    parser.add_argument("--verbose", action="store_true", help="Print one summary line per case.")
    return parser


def _selected_cases(case_ids: list[str], limit: int) -> list[Any]:
    selected = list(matrix.MATRIX)
    if case_ids:
        wanted = set(case_ids)
        selected = [case for case in selected if case.case_id in wanted]
        missing = sorted(wanted - {case.case_id for case in selected})
        if missing:
            raise SystemExit(f"unknown case id(s): {', '.join(missing)}")
    if limit and limit > 0:
        selected = selected[:limit]
    return selected


def _pretty_path(path: Path) -> Path:
    suffix = "".join(path.suffixes)
    if suffix:
        return path.with_name(path.name.removesuffix(suffix) + ".pretty.json")
    return path.with_name(path.name + ".pretty.json")


def _collect_case(case) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    with tempfile.TemporaryDirectory(prefix=f"sunpack-candidates-{case.case_id}-") as raw_tmp:
        root = Path(raw_tmp)
        try:
            fixture = case.build(root / case.case_id)
            scheduler = matrix._repair_scheduler(root, modules=case.modules)
            job = RepairJob(
                source_input=fixture.source_input,
                format=case.fmt,
                confidence=0.82,
                damage_flags=list(case.flags),
                archive_key=case.case_id,
            )
            generated_batch = scheduler.generate_repair_candidates(job)
            result = scheduler.repair(job)
            verified_by_test, verification_error = _verify_case_result(case, result, fixture)
            case_summary = _case_summary(
                case,
                result,
                verified_by_test=verified_by_test,
                verification_error=verification_error,
                collection_status="ok" if verified_by_test else "failed",
            )
            records = _records_from_case(case, job, generated_batch, result, case_summary)
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
            )
            return case_summary, [_empty_record(case, None, None, case_summary)]
        except Exception as exc:
            case_summary = _case_summary(
                case,
                None,
                verified_by_test=False,
                verification_error=str(exc),
                collection_status="failed",
            )
            return case_summary, [_empty_record(case, None, None, case_summary)]


def _verify_case_result(case, result, fixture) -> tuple[bool, str | None]:
    try:
        status_ok = result.status in case.expected_statuses
        module_ok = case.expected_module is None or result.module_name == case.expected_module
        if not status_ok or not module_ok:
            return False, f"unexpected result status={result.status} module={result.module_name}"
        if result.status in {"repaired", "partial"} and case.verify is not None:
            case.verify(result, fixture)
        return True, None
    except pytest.skip.Exception:
        raise
    except Exception as exc:
        return False, str(exc)


def _records_from_case(case, job: RepairJob, generated_batch, result, case_summary: dict[str, Any]) -> list[dict[str, Any]]:
    validated_by_id = _validated_features_by_id(result)
    selected_ids = _selected_candidate_ids(result, validated_by_id)
    records = []
    for index, candidate in enumerate(generated_batch.candidates):
        features = candidate_feature_payload(candidate)
        candidate_id = str(features.get("candidate_id") or "")
        validated_features = validated_by_id.get(candidate_id)
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
            "candidate_is_expected_module": bool(case.expected_module and features.get("module") == case.expected_module),
            "result_status": case_summary["result_status"],
            "repair_success": case_summary["repair_success"],
            "verified_by_test": case_summary["verified_by_test"],
            "verification_error": case_summary["verification_error"],
            "expected_statuses": list(case.expected_statuses),
            "format": case.fmt,
            "damage_flags": list(case.flags),
            "selection_summary": _selection_summary(result),
            "generation_summary": _generation_summary(generated_batch),
        })
    return records


def _ltr_record(record: dict[str, Any]) -> dict[str, Any]:
    features = record.get("validated_candidate_features") or record.get("candidate_features") or {}
    ltr_features = dict(features.get("ltr_features") or {}) if isinstance(features, dict) else {}
    label = _ltr_label(record)
    return {
        "schema_version": 1,
        "source": record.get("source"),
        "query_id": record.get("attempt_id"),
        "case_id": record.get("case_id"),
        "candidate_id": record.get("candidate_id"),
        "candidate_index": record.get("candidate_index"),
        "label": label,
        "candidate_selected": bool(record.get("candidate_selected")),
        "candidate_is_expected_module": bool(record.get("candidate_is_expected_module")),
        "expected_module": record.get("expected_module"),
        "actual_selected": record.get("actual_selected"),
        "result_status": record.get("result_status"),
        "repair_success": bool(record.get("repair_success")),
        "verified_by_test": bool(record.get("verified_by_test")),
        "format": record.get("format"),
        "damage_flags": list(record.get("damage_flags") or []),
        "features": ltr_features,
    }


def _ltr_label(record: dict[str, Any]) -> int:
    selected = bool(record.get("candidate_selected"))
    expected = bool(record.get("candidate_is_expected_module"))
    if selected and expected and record.get("repair_success"):
        return 2
    if selected or expected:
        return 1
    return 0


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
) -> dict[str, Any]:
    result_status = getattr(result, "status", None)
    actual_selected = getattr(result, "module_name", None)
    status_ok = result is not None and result_status in case.expected_statuses
    module_ok = result is not None and (case.expected_module is None or actual_selected == case.expected_module)
    return {
        "case_id": case.case_id,
        "expected_module": case.expected_module,
        "actual_selected": actual_selected,
        "result_status": result_status,
        "repair_success": bool(status_ok and module_ok and verified_by_test),
        "verified_by_test": bool(verified_by_test),
        "verification_error": verification_error,
        "collection_status": collection_status,
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
        "verified_by_test": case_summary["verified_by_test"],
        "verification_error": case_summary["verification_error"],
        "expected_statuses": list(case.expected_statuses),
        "format": case.fmt,
        "damage_flags": list(case.flags),
        "selection_summary": _selection_summary(result),
        "generation_summary": {"candidate_count": 0},
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


def _case_line(case_summary: dict[str, Any], records: int) -> str:
    return (
        f"{case_summary['case_id']}: {case_summary['collection_status']} "
        f"status={case_summary['result_status']} selected={case_summary['actual_selected']} records={records}"
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
