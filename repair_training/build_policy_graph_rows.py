from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from repair_training.core.repair_policy_transformer.schema import PolicyAction, PolicyGraphTrainingSample


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
            graph = loop.get("graph") if isinstance(loop.get("graph"), dict) else {}
            rounds = loop.get("rounds") if isinstance(loop.get("rounds"), list) else []
            last_round = rounds[-1] if rounds and isinstance(rounds[-1], dict) else {}
            action_payloads = last_round.get("actions") if isinstance(last_round.get("actions"), list) else []
            graph_action = last_round.get("graph_action") if isinstance(last_round.get("graph_action"), dict) else {}
            if not graph or not action_payloads:
                continue
            actions = _actions(action_payloads, graph_action, final_best)
            samples.append(PolicyGraphTrainingSample(
                sample_id=str(row.get("sample_id") or row.get("archive_key") or f"row:{row_index}:{item_index}"),
                format=str(row.get("format") or format_name),
                graph=graph,
                current_node_id=str(loop.get("current_node_id") or graph.get("current_node_id") or ""),
                best_node_id=str(loop.get("best_node_id") or graph.get("best_node_id") or ""),
                actions=actions,
                memory=[dict(entry) for entry in rounds if isinstance(entry, dict)],
                diagnosis_hgt=dict(last_round.get("diagnosis_hgt") or {}),
                current_recovery=dict(last_round.get("current_recovery") or {}),
                best_recovery=dict(last_round.get("best_seen_recovery") or {}),
                final_best_recovery=final_best,
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
            features=dict(payload),
        ))
    return output


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build RepairGraph policy transformer rows from runtime policy graph logs.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", default="")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())

