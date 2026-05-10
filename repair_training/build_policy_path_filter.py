from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


BAD_TERMINAL_TOKENS = ("repeated_repair_input", "no_candidates", "unrepairable")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    rows = _read_jsonl(Path(args.ab_jsonl))
    path_filter, summary = build_path_filter(rows, regressions_only=not bool(args.all_model_paths))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(path_filter, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    summary.update({"output": str(output), "sample_count": len(path_filter)})
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build collect_runtime_repair_graph path-filter JSON from model runtime paths.")
    parser.add_argument("--ab-jsonl", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--all-model-paths", action="store_true", help="Include every model path instead of only model regressions.")
    return parser


def build_path_filter(rows: list[dict[str, Any]], *, regressions_only: bool = True) -> tuple[dict[str, list[str]], dict[str, Any]]:
    paired: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        paired[str(row.get("sample_id") or "")][str(row.get("mode") or "")] = row
    output: dict[str, list[str]] = {}
    summary = {"model_sample_count": 0, "regression_sample_count": 0, "path_from_probe_count": 0, "path_from_trace_count": 0}
    for sample_id, modes in paired.items():
        model = modes.get("zip_model_policy")
        if not model:
            continue
        baseline = modes.get("selector_baseline")
        summary["model_sample_count"] += 1
        regression = True
        if regressions_only:
            regression = _is_regression(baseline, model)
        if not regression:
            continue
        summary["regression_sample_count"] += 1
        path = _path_from_probe(model)
        if path:
            summary["path_from_probe_count"] += 1
        else:
            path = _path_from_trace(model)
            if path:
                summary["path_from_trace_count"] += 1
        if path:
            output[sample_id] = path
    return output, summary


def _is_regression(baseline: dict[str, Any] | None, model: dict[str, Any]) -> bool:
    model_recovery = _float(model.get("recovery_ratio"))
    selector_recovery = _float((baseline or {}).get("recovery_ratio"))
    terminal = str(model.get("terminal_status") or "").lower()
    return (
        baseline is None
        or model_recovery < selector_recovery - 1e-9
        or model_recovery <= 0.0
        or any(token in terminal for token in BAD_TERMINAL_TOKENS)
    )


def _path_from_probe(row: dict[str, Any]) -> list[str]:
    decisions = [event for event in _read_jsonl(Path(str(row.get("probe_path") or ""))) if str(event.get("event") or "") == "policy_probe_decision"]
    output: list[str] = []
    for event in decisions:
        selected = event.get("selected_candidate") if isinstance(event.get("selected_candidate"), dict) else {}
        signature = _candidate_signature(selected)
        if signature:
            output.append(signature)
    return output


def _path_from_trace(row: dict[str, Any]) -> list[str]:
    output: list[str] = []
    for event in _read_jsonl(Path(str(row.get("trace_path") or ""))):
        if str(event.get("event") or "") != "repair_selected_result":
            continue
        candidate = event.get("candidate") if isinstance(event.get("candidate"), dict) else {}
        signature = _candidate_signature(candidate)
        if signature:
            output.append(signature)
    return output


def _candidate_signature(candidate: dict[str, Any]) -> str:
    if not isinstance(candidate, dict) or not candidate:
        return ""
    proposal = candidate.get("candidate_proposal") if isinstance(candidate.get("candidate_proposal"), dict) else {}
    validation = proposal.get("validation_details") if isinstance(proposal.get("validation_details"), dict) else candidate.get("validation_details")
    policy = validation.get("policy") if isinstance(validation, dict) else ""
    facts = proposal.get("patch_facts") or candidate.get("patch_facts") or []
    return "|".join([
        str(candidate.get("module_name") or candidate.get("module") or ""),
        str(candidate.get("repair_name") or ""),
        str(candidate.get("native_target") or ""),
        str(policy or ""),
        ",".join(str(item) for item in facts or []),
    ])


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                rows.append(value)
    return rows


def _float(value: Any) -> float:
    try:
        return float(value if value is not None else 0.0)
    except Exception:
        return 0.0


if __name__ == "__main__":
    raise SystemExit(main())
