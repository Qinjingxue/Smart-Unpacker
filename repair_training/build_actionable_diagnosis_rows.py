from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from repair_training.core.diagnosis_gnn.actionable_roots import actionable_roots_from_actions, roots_for_module
from repair_training.core.diagnosis_gnn.root_cases import canonical_root_case


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    source_rows = read_jsonl(args.input)
    transition_rows = read_jsonl(args.transitions)
    annotated, summary = annotate_rows_with_actionable_roots(source_rows, transition_rows)
    output = Path(args.output)
    write_jsonl(output, annotated)
    summary_path = Path(args.summary_output) if args.summary_output else output.with_name("actionable_diagnosis_rows_summary.json")
    write_json(summary_path, summary)
    print(json.dumps({"output": str(output), "summary": str(summary_path), **summary}, ensure_ascii=False, sort_keys=True))
    return 0


def annotate_rows_with_actionable_roots(rows: list[dict[str, Any]], transitions: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    by_row_index: dict[int, list[dict[str, Any]]] = {}
    by_sample_id: dict[str, list[dict[str, Any]]] = {}
    for transition in transitions:
        source = transition.get("source") if isinstance(transition.get("source"), dict) else {}
        row_index = _int(source.get("row_index"), default=-1)
        if row_index >= 0:
            by_row_index.setdefault(row_index, []).append(transition)
        sample_id = str(source.get("sample_id") or "").strip()
        if sample_id:
            by_sample_id.setdefault(sample_id, []).append(transition)

    output: list[dict[str, Any]] = []
    covered = 0
    module_counts: dict[str, int] = {}
    root_counts: dict[str, int] = {}
    skipped_no_transition = 0
    skipped_no_actionable = 0
    for index, row in enumerate(rows):
        transitions_for_row = by_row_index.get(index) or by_sample_id.get(str(row.get("sample_id") or "").strip(), [])
        best = _best_initial_transition(transitions_for_row)
        injected = _injected_roots(row)
        roots: list[str] = []
        best_module = ""
        if best:
            actions = best.get("available_actions") or best.get("actions") or []
            roots = actionable_roots_from_actions(actions, injected)
            best_action = _best_module_action(actions)
            best_module = str(best_action.get("module_name") or best_action.get("module") or "")
        else:
            skipped_no_transition += 1
        if roots:
            updated = dict(row)
            updated["actionable_root_labels"] = roots
            updated["actionable_label_source"] = "oracle_best_path_first_action"
            updated["actionable_label_metadata"] = {
                "transition_sample_id": str(best.get("sample_id") or "") if best else "",
                "best_module": best_module,
                "module_roots": list(roots_for_module(best_module)),
                "injected_roots": sorted(injected),
            }
            covered += 1
            if best_module:
                module_counts[best_module] = module_counts.get(best_module, 0) + 1
            for root in roots:
                root_counts[root] = root_counts.get(root, 0) + 1
            output.append(updated)
        else:
            skipped_no_actionable += 1
            output.append(dict(row))
    return output, {
        "rows": len(rows),
        "transition_rows": len(transitions),
        "actionable_covered_rows": covered,
        "actionable_coverage": covered / max(1, len(rows)),
        "skipped_no_transition": skipped_no_transition,
        "skipped_no_actionable": skipped_no_actionable,
        "best_module_counts": dict(sorted(module_counts.items())),
        "actionable_root_counts": dict(sorted(root_counts.items())),
    }


def _best_initial_transition(transitions: list[dict[str, Any]]) -> dict[str, Any]:
    candidates = []
    for transition in transitions:
        if int(_int(transition.get("step_index"), default=0)) not in {0, 1}:
            continue
        actions = transition.get("available_actions") or transition.get("actions") or []
        best = _best_module_action(actions)
        if best:
            candidates.append((float(best.get("action_q_value") or best.get("q_value") or 0.0), transition))
    if not candidates:
        return {}
    return max(candidates, key=lambda item: item[0])[1]


def _best_module_action(actions: list[Any]) -> dict[str, Any]:
    best: dict[str, Any] = {}
    best_q = -1.0
    for raw in actions or []:
        action = dict(raw or {}) if isinstance(raw, dict) else {}
        if str(action.get("action_type") or "") != "module":
            continue
        module = str(action.get("module_name") or action.get("module") or "")
        if not module:
            continue
        q = float(action.get("action_q_value") or action.get("q_value") or 0.0)
        if q > best_q:
            best = action
            best_q = q
    return best


def _injected_roots(row: dict[str, Any]) -> set[str]:
    output: set[str] = set()
    labels = []
    target = row.get("damage_analysis_target") if isinstance(row.get("damage_analysis_target"), dict) else {}
    labels.extend(target.get("damage_labels") or [])
    for item in row.get("oracle_damage") or []:
        if isinstance(item, dict):
            labels.append(item.get("label"))
    for item in labels:
        root = canonical_root_case(str(item or ""))
        if root:
            output.add(root)
    for item in row.get("root_case_labels") or row.get("root_cases") or []:
        root = canonical_root_case(str(item or ""))
        if root:
            output.add(root)
    return output


def _int(value: Any, *, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Annotate ArchiveKnowledge rows with actionable root labels from policy transition rows.")
    parser.add_argument("--input", required=True, help="Original damaged/knowledge JSONL rows.")
    parser.add_argument("--transitions", required=True, help="Policy transition rows with action_q_value labels.")
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", default="")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
