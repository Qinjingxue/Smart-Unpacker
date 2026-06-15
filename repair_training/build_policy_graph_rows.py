from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from sunpack.model_runtime.diagnosis.root_cases import ROOT_CASES
from sunpack.model_runtime.policy.schema import PolicyAction, PolicyGraphTrainingSample


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    rows = build_policy_graph_rows(read_jsonl(args.input), format_name=args.format)
    output = Path(args.output)
    write_jsonl(output, [row.to_dict() for row in rows])
    write_json(Path(args.summary_output) if args.summary_output else output.with_name("policy_graph_rows_summary.json"), {
        "rows": len(rows),
        "actions": sum(len(row.actions) for row in rows),
        "formats": sorted({row.format for row in rows}),
    })
    return 0


def build_policy_graph_rows(raw_rows: list[dict[str, Any]], *, format_name: str = "zip") -> list[PolicyGraphTrainingSample]:
    samples: list[PolicyGraphTrainingSample] = []
    for row_index, row in enumerate(raw_rows):
        history_items = _history_items(row)
        final_best = _final_best_recovery(history_items, row)
        for item_index, item in enumerate(history_items):
            loop = _policy_loop(item)
            if not loop:
                continue
            graph = _sanitize_training_graph(loop.get("graph") if isinstance(loop.get("graph"), dict) else {})
            rounds = loop.get("rounds") if isinstance(loop.get("rounds"), list) else []
            last_round = rounds[-1] if rounds and isinstance(rounds[-1], dict) else {}
            action_payloads = last_round.get("actions") if isinstance(last_round.get("actions"), list) else []
            graph_action = last_round.get("graph_action") if isinstance(last_round.get("graph_action"), dict) else {}
            if not graph or not action_payloads:
                continue
            actions = _actions(action_payloads, graph_action, final_best)
            best_recovery = _sanitize_recovery(last_round.get("best_seen_recovery") if isinstance(last_round.get("best_seen_recovery"), dict) else {})
            best_score = _float(best_recovery.get("score"))
            stop_regret = max(0.0, final_best - best_score)
            samples.append(PolicyGraphTrainingSample(
                sample_id=str(row.get("sample_id") or row.get("archive_key") or f"row:{row_index}:{item_index}"),
                format=str(row.get("format") or format_name),
                graph=graph,
                current_node_id=str(loop.get("current_node_id") or graph.get("current_node_id") or ""),
                best_node_id=str(loop.get("best_node_id") or graph.get("best_node_id") or ""),
                actions=actions,
                memory=[_sanitize_memory_entry(entry) for entry in rounds if isinstance(entry, dict)],
                diagnosis_hgt=_sanitize_diagnosis_hgt(last_round.get("diagnosis_hgt") if isinstance(last_round.get("diagnosis_hgt"), dict) else {}),
                current_recovery=_sanitize_recovery(last_round.get("current_recovery") if isinstance(last_round.get("current_recovery"), dict) else {}),
                best_recovery=best_recovery,
                final_best_recovery=final_best,
                has_promising_future=stop_regret > 0.01,
                stop_regret=stop_regret,
                source={"row_index": row_index, "history_index": item_index, "episode_id": row.get("episode_id") or row.get("archive_key") or ""},
            ))
    return samples


def _history_items(row: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(row.get("diagnosis"), dict):
        return [row]
    repair = row.get("repair") if isinstance(row.get("repair"), dict) else {}
    history = repair.get("history") if isinstance(repair.get("history"), dict) else row.get("repair_history")
    if isinstance(history, dict) and isinstance(history.get("items"), list):
        return [item for item in history["items"] if isinstance(item, dict)]
    items = row.get("items") if isinstance(row.get("items"), list) else []
    return [item for item in items if isinstance(item, dict)]


def _policy_loop(item: dict[str, Any]) -> dict[str, Any]:
    diagnosis = item.get("diagnosis") if isinstance(item.get("diagnosis"), dict) else item
    loop = diagnosis.get("policy_loop") if isinstance(diagnosis.get("policy_loop"), dict) else {}
    return dict(loop)


def _final_best_recovery(items: list[dict[str, Any]], row: dict[str, Any]) -> float:
    best = _float(row.get("final_best_recovery"))
    for item in items:
        loop = _policy_loop(item)
        graph = loop.get("graph") if isinstance(loop.get("graph"), dict) else {}
        nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
        for node in nodes.values():
            if not isinstance(node, dict):
                continue
            recovery = node.get("recovery") if isinstance(node.get("recovery"), dict) else {}
            best = max(best, _float(recovery.get("score")))
    return best


def _actions(payloads: list[dict[str, Any]], selected: dict[str, Any], final_best: float) -> list[PolicyAction]:
    selected_type = str(selected.get("action_type") or "")
    selected_id = str(selected.get("action_id") or selected.get("candidate_id") or selected_type)
    selected_module = str(selected.get("module_name") or selected.get("module") or "")
    output = []
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        action_type = str(payload.get("action_type") or "").lower()
        if action_type not in {"stop", "undo", "module"}:
            continue
        action_id = str(payload.get("action_id") or payload.get("candidate_id") or action_type)
        module = str(payload.get("module_name") or payload.get("module") or "")
        chosen = action_type == selected_type and (action_id == selected_id or (module and module == selected_module))
        output.append(PolicyAction(
            action_type=action_type,  # type: ignore[arg-type]
            action_id=action_id,
            module_name=module,
            action_q_value=final_best if chosen else 0.0,
            action_prior=1.0 if chosen else 0.0,
            q_source="runtime_selected_final_best" if chosen else "runtime_unexplored",
            is_teacher_evaluated=bool(chosen),
            features=_sanitize_action_features(payload),
        ))
    return output


def _sanitize_training_graph(graph: dict[str, Any]) -> dict[str, Any]:
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    edges = graph.get("edges") if isinstance(graph.get("edges"), dict) else {}
    return {
        "current_node_id": str(graph.get("current_node_id") or ""),
        "best_node_id": str(graph.get("best_node_id") or ""),
        "frontier": [str(item) for item in graph.get("frontier") or [] if str(item)],
        "expansion_count": _int(graph.get("expansion_count")),
        "stale_expansion_count": _int(graph.get("stale_expansion_count")),
        "nodes": {
            str(node_id): _sanitize_node(node_id, node)
            for node_id, node in sorted(nodes.items())
            if isinstance(node, dict)
        },
        "edges": {
            str(edge_id): _sanitize_edge(edge_id, edge)
            for edge_id, edge in sorted(edges.items())
            if isinstance(edge, dict)
        },
    }


def _sanitize_node(node_id: Any, node: dict[str, Any]) -> dict[str, Any]:
    return {
        "node_id": str(node.get("node_id") or node_id),
        "parent_id": str(node.get("parent_id") or ""),
        "patch_digest": str(node.get("patch_digest") or ""),
        "patch_depth": _int(node.get("patch_depth")),
        "recovery": _sanitize_recovery(node.get("recovery") if isinstance(node.get("recovery"), dict) else {}),
        "status": str(node.get("status") or "active"),
        "created_round": _int(node.get("created_round")),
        "created_step": _int(node.get("created_step", node.get("created_round"))),
        "expanded_candidate_ids": [str(item) for item in node.get("expanded_candidate_ids") or [] if str(item)],
        "exploration": _sanitize_exploration(node.get("exploration") if isinstance(node.get("exploration"), dict) else {}),
        "module_name": str(node.get("module_name") or ""),
        "patch_status": str(node.get("patch_status") or ""),
        "failure_reason": str(node.get("failure_reason") or ""),
        "diagnosis_hgt": _sanitize_diagnosis_hgt(node.get("diagnosis_hgt") if isinstance(node.get("diagnosis_hgt"), dict) else {}),
        "verification": _sanitize_verification(node.get("verification") if isinstance(node.get("verification"), dict) else {}),
        "prediction_error_from_parent": _sanitize_prediction_error(node.get("prediction_error_from_parent") if isinstance(node.get("prediction_error_from_parent"), dict) else {}),
        "uncertainty": _sanitize_uncertainty(node.get("uncertainty") if isinstance(node.get("uncertainty"), dict) else {}),
    }


def _sanitize_edge(edge_id: Any, edge: dict[str, Any]) -> dict[str, Any]:
    return {
        "edge_id": str(edge.get("edge_id") or edge_id),
        "from_node_id": str(edge.get("from_node_id") or ""),
        "to_node_id": str(edge.get("to_node_id") or ""),
        "candidate_id": str(edge.get("candidate_id") or ""),
        "module_name": str(edge.get("module_name") or ""),
        "module_family": str(edge.get("module_family") or edge.get("route_family") or ""),
        "status": str(edge.get("status") or "frontier"),
        "created_round": _int(edge.get("created_round")),
        "predicted_next_state": _sanitize_predicted_next_state(edge.get("predicted_next_state") if isinstance(edge.get("predicted_next_state"), dict) else {}),
        "prediction_error": _sanitize_prediction_error(edge.get("prediction_error") if isinstance(edge.get("prediction_error"), dict) else {}),
        "prediction_model_version": str(edge.get("prediction_model_version") or ""),
        "predicted_at_step": _int(edge.get("predicted_at_step")),
        "exploration": _sanitize_exploration(edge.get("exploration") if isinstance(edge.get("exploration"), dict) else {}),
        "uncertainty": _sanitize_uncertainty(edge.get("uncertainty") if isinstance(edge.get("uncertainty"), dict) else {}),
    }


def _sanitize_memory_entry(entry: dict[str, Any]) -> dict[str, Any]:
    output = {
        "round": _int(entry.get("round", entry.get("round_index"))),
        "patch_depth": _int(entry.get("patch_depth")),
        "graph_action": _sanitize_graph_action(entry.get("graph_action") if isinstance(entry.get("graph_action"), dict) else {}),
        "current_recovery": _sanitize_recovery(entry.get("current_recovery") if isinstance(entry.get("current_recovery"), dict) else {}),
        "best_seen_recovery": _sanitize_recovery(entry.get("best_seen_recovery") if isinstance(entry.get("best_seen_recovery"), dict) else {}),
        "diagnosis_hgt": _sanitize_diagnosis_hgt(entry.get("diagnosis_hgt") if isinstance(entry.get("diagnosis_hgt"), dict) else {}),
        "recovery_delta": _float(entry.get("recovery_delta")),
        "best_updated": bool(entry.get("best_updated", False)),
        "branch_failed_streak": _int(entry.get("branch_failed_streak")),
        "distance_from_best_node": _int(entry.get("distance_from_best_node")),
        "prediction_error": _sanitize_prediction_error(entry.get("prediction_error") if isinstance(entry.get("prediction_error"), dict) else {}),
    }
    return {key: value for key, value in output.items() if value not in ({}, [], "", None)}


def _sanitize_graph_action(action: dict[str, Any]) -> dict[str, Any]:
    return {
        "action_type": str(action.get("action_type") or ""),
        "action_id": str(action.get("action_id") or action.get("candidate_id") or ""),
        "module_name": str(action.get("module_name") or action.get("module") or ""),
        "reason": str(action.get("reason") or ""),
    }


def _sanitize_action_features(payload: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "action_type",
        "action_id",
        "candidate_id",
        "module_name",
        "module",
        "module_family",
        "route_family",
        "atomic_action_group",
        "confidence",
        "score_hint",
        "generation_priority",
        "patch_depth",
    )
    return {key: payload[key] for key in allowed if key in payload}


def _sanitize_exploration(payload: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "visit_count",
        "last_visited_step",
        "outgoing_action_count",
        "expanded_action_count",
        "failed_action_count",
        "reopened_action_count",
        "fresh_action_count",
        "exhaustion_ratio",
        "subtree_node_count",
        "subtree_best_recovery",
        "subtree_best_delta",
        "steps_since_subtree_best_update",
        "attempt_count",
        "last_attempt_step",
        "undo_count_after_attempt",
        "reopened_after_exhaustion",
        "result_recovery_delta",
        "prediction_error_after_attempt",
        "result_patch_status",
    )
    output: dict[str, Any] = {}
    for key in allowed:
        if key not in payload:
            continue
        if key == "result_patch_status":
            output[key] = str(payload.get(key) or "")
        elif key == "reopened_after_exhaustion":
            output[key] = bool(payload.get(key))
        else:
            output[key] = _float(payload.get(key))
    return {key: value for key, value in output.items() if value not in ("", None)}


def _sanitize_uncertainty(payload: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "overall_uncertainty",
        "diagnosis_entropy",
        "diagnosis_top_margin",
        "diagnosis_selected_count",
        "verification_ambiguity",
        "exploration_uncertainty",
        "prediction_uncertainty",
        "transition_prediction_entropy",
        "transition_prediction_margin",
        "prediction_error_uncertainty",
        "result_ambiguity",
        "predicted_uncertainty",
    )
    output: dict[str, Any] = {}
    for key in allowed:
        if key in payload:
            output[key] = _float(payload.get(key))
    return {key: value for key, value in output.items() if value not in ("", None)}


def _sanitize_recovery(payload: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "score",
        "completeness",
        "status",
        "decision_hint",
        "recovered_files",
        "recovered_bytes",
        "complete_files",
        "failed_files",
        "missing_files",
        "partial_files",
        "score_source",
        "recovered_bytes_scaled",
        "complete_files_scaled",
        "failed_files_scaled",
        "missing_files_scaled",
        "partial_files_scaled",
    )
    return {key: payload[key] for key in keys if key in payload}


def _sanitize_verification(payload: dict[str, Any]) -> dict[str, Any]:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else payload
    keys = (
        "completeness",
        "assessment_status",
        "decision_hint",
        "complete_files",
        "failed_files",
        "missing_files",
        "partial_files",
    )
    cleaned = {key: summary[key] for key in keys if key in summary}
    return {"summary": cleaned} if cleaned else {}


def _sanitize_predicted_next_state(payload: dict[str, Any]) -> dict[str, Any]:
    if not payload:
        return {}
    recovery = payload.get("predicted_recovery") if isinstance(payload.get("predicted_recovery"), dict) else {}
    verification = payload.get("predicted_verification_summary") if isinstance(payload.get("predicted_verification_summary"), dict) else {}
    scores = payload.get("predicted_diagnosis_root_scores") if isinstance(payload.get("predicted_diagnosis_root_scores"), dict) else {}
    return {
        "predicted_recovery": _sanitize_recovery(recovery),
        "predicted_recovery_delta": _float(payload.get("predicted_recovery_delta")),
        "predicted_patch_status_hash": _float(payload.get("predicted_patch_status_hash")),
        "predicted_best_updated": bool(payload.get("predicted_best_updated", False)),
        "predicted_branch_stale_delta": _float(payload.get("predicted_branch_stale_delta")),
        "predicted_diagnosis_root_scores": {str(key): _float(value) for key, value in sorted(scores.items())},
        "predicted_verification_summary": {
            key: verification[key]
            for key in (
                "completeness",
                "complete_files_scaled",
                "failed_files_scaled",
                "missing_files_scaled",
                "partial_files_scaled",
            )
            if key in verification
        },
    }


def _sanitize_prediction_error(payload: dict[str, Any]) -> dict[str, Any]:
    if not payload:
        return {}
    keys = (
        "recovery_abs_error",
        "recovery_delta_error",
        "diagnosis_root_l1",
        "diagnosis_top1_changed",
        "verification_completeness_error",
        "patch_status_mismatch",
        "overall_prediction_error",
        "predicted_top_root",
        "actual_top_root",
    )
    return {key: payload[key] for key in keys if key in payload}


def _sanitize_diagnosis_hgt(payload: dict[str, Any]) -> dict[str, Any]:
    root = payload.get("root_case") if isinstance(payload.get("root_case"), dict) else {}
    scores = root.get("scores") if isinstance(root.get("scores"), dict) else payload.get("root_case_scores")
    ranked = root.get("ranked") if isinstance(root.get("ranked"), list) else payload.get("ranked_root_cases")
    selected = root.get("selected") if isinstance(root.get("selected"), list) else payload.get("selected_root_cases")
    cleaned_root: dict[str, Any] = {}
    if isinstance(scores, dict):
        cleaned_root["scores"] = {str(key): _float(value) for key, value in scores.items()}
    if isinstance(ranked, list):
        cleaned_root["ranked"] = [
            {"root_case": str(item.get("root_case") or ""), "score": _float(item.get("score"))}
            for item in ranked
            if isinstance(item, dict)
        ]
    if isinstance(selected, list):
        cleaned_root["selected"] = [str(item) for item in selected if str(item)]
    output: dict[str, Any] = {}
    if cleaned_root:
        output["root_case"] = cleaned_root
    diagnostics = payload.get("diagnostics") if isinstance(payload.get("diagnostics"), dict) else {}
    cleaned_diagnostics: dict[str, Any] = {}
    for key in (
        "root_evidence_scores",
        "root_transition_gain",
        "root_probe_viability",
        "priority_components",
    ):
        values = diagnostics.get(key) if isinstance(diagnostics.get(key), dict) else payload.get(key)
        cleaned = _sanitize_root_score_map(values if isinstance(values, dict) else {})
        if cleaned:
            cleaned_diagnostics[key] = cleaned
    summary = diagnostics.get("root_case_score_summary") if isinstance(diagnostics.get("root_case_score_summary"), dict) else {}
    if summary:
        cleaned_diagnostics["root_case_score_summary"] = {
            str(key): _float(value)
            for key, value in summary.items()
            if key in {"max_score", "mean_top3", "selected_count", "entropy", "top_margin"}
        }
    if cleaned_diagnostics:
        output["diagnostics"] = cleaned_diagnostics
    return output


def _sanitize_root_score_map(values: dict[str, Any]) -> dict[str, float]:
    roots = set(ROOT_CASES)
    return {
        str(key): _float(value)
        for key, value in sorted(values.items())
        if str(key) in roots
    }


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build RepairGraph policy transformer rows from runtime policy graph logs.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", default="")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
