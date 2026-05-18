from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from repair_training.core.repair_policy_transformer.inference import RepairPolicyTransformerModel
from repair_training.core.repair_policy_transformer.schema import (
    PolicyAction,
    PolicyGraphTrainingSample,
    PolicyGraphTransitionSample,
    transition_sample_from_dict,
)
from sunpack.repair.policy.graph import PolicyRepairGraph


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    transitions = [transition_sample_from_dict(row) for row in read_jsonl(args.input)]
    model = RepairPolicyTransformerModel(model_dir=args.model_dir, device=args.device)
    replayed, summary = replay_transition_predictions(transitions, model=model)
    output = Path(args.output)
    write_jsonl(output, [row.to_dict() for row in replayed])
    summary.update({
        "input": str(args.input),
        "output": str(output),
        "model_dir": str(args.model_dir),
    })
    write_json(Path(args.summary_output) if args.summary_output else output.with_name("policy_transition_prediction_replay_summary.json"), summary)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


def replay_transition_predictions(
    transitions: list[PolicyGraphTransitionSample],
    *,
    model: RepairPolicyTransformerModel,
) -> tuple[list[PolicyGraphTransitionSample], dict[str, Any]]:
    ordered = sorted(enumerate(transitions), key=lambda item: (_episode_key(item[1]), int(item[1].step_index or 0), item[0]))
    replayed_by_index: dict[int, PolicyGraphTransitionSample] = {}
    latest_graph_by_episode: dict[str, dict[str, Any]] = {}
    predicted_rows = 0
    error_rows = 0
    module_rows = 0
    error_values: list[float] = []
    for original_index, transition in ordered:
        episode = _episode_key(transition)
        graph_before = _copy_jsonish(latest_graph_by_episode.get(episode) or transition.graph_before)
        sample = PolicyGraphTrainingSample(
            sample_id=f"{transition.sample_id}:prediction_replay",
            format=transition.format,
            graph=graph_before,
            current_node_id=str(graph_before.get("current_node_id") or transition.current_node_id),
            best_node_id=str(graph_before.get("best_node_id") or transition.best_node_id),
            actions=list(transition.available_actions),
            current_recovery=_node_recovery(graph_before, str(graph_before.get("current_node_id") or transition.current_node_id)),
            best_recovery=_node_recovery(graph_before, str(graph_before.get("best_node_id") or transition.best_node_id)),
            source={**dict(transition.source or {}), "episode_id": transition.episode_id, "step_index": transition.step_index},
        )
        prediction = model.predict_sample(sample)
        selected = _prediction_for_action(prediction, transition.chosen_action)
        graph_after = _copy_jsonish(transition.graph_after)
        _merge_prediction_fields(graph_before, graph_after)
        if transition.chosen_action.action_type == "module":
            module_rows += 1
            if selected:
                predicted_rows += 1
                graph_after, error = _write_prediction_and_error(graph_after, selected)
                if error:
                    error_rows += 1
                    error_values.append(_float(error.get("overall_prediction_error")))
        latest_graph_by_episode[episode] = graph_after
        replayed_by_index[original_index] = replace(
            transition,
            graph_before=graph_before,
            current_node_id=str(graph_before.get("current_node_id") or transition.current_node_id),
            best_node_id=str(graph_before.get("best_node_id") or transition.best_node_id),
            graph_after=graph_after,
            source={**dict(transition.source or {}), "prediction_replay": True},
        )
    replayed = [replayed_by_index[index] for index in range(len(transitions)) if index in replayed_by_index]
    summary = {
        "rows": len(transitions),
        "module_rows": module_rows,
        "predicted_module_rows": predicted_rows,
        "prediction_error_rows": error_rows,
        "prediction_error_mean": sum(error_values) / max(1, len(error_values)),
        "prediction_error_max": max(error_values) if error_values else 0.0,
        "episodes": len({_episode_key(row) for row in transitions}),
    }
    return replayed, summary


def _prediction_for_action(prediction: dict[str, Any], action: PolicyAction) -> dict[str, Any]:
    for row in prediction.get("action_scores") or []:
        if _same_action_dict(row, action):
            metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
            return {
                "predicted_next_state": dict(metadata.get("predicted_next_state") or {}),
                "predicted_uncertainty": dict(metadata.get("predicted_uncertainty") or {}),
                "prediction_model_version": str((prediction.get("diagnostics") or {}).get("model_type") or "repair_policy_transformer"),
            }
    predictions = prediction.get("action_predictions") if isinstance(prediction.get("action_predictions"), dict) else {}
    key = action.action_id or _action_key(action)
    if isinstance(predictions.get(key), dict):
        return {"predicted_next_state": dict(predictions[key]), "prediction_model_version": "repair_policy_transformer"}
    return {}


def _write_prediction_and_error(graph_payload: dict[str, Any], selected: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    graph = PolicyRepairGraph.from_payload(graph_payload)
    current = graph.graph.current_node()
    if current is None:
        return graph_payload, {}
    incoming = next((edge for edge in graph.graph.edges.values() if edge.to_node_id == current.node_id), None)
    if incoming is None:
        return graph_payload, {}
    prediction = selected.get("predicted_next_state") if isinstance(selected.get("predicted_next_state"), dict) else {}
    if not prediction:
        return graph_payload, {}
    incoming.predicted_next_state = dict(prediction)
    incoming.prediction_model_version = str(selected.get("prediction_model_version") or "repair_policy_transformer")
    incoming.uncertainty = dict(selected.get("predicted_uncertainty") or incoming.uncertainty or {})
    graph._update_prediction_error_for_node(current)
    graph.refresh_exploration(step=int(current.created_step or 0))
    updated = graph.graph.to_dict()
    current_payload = (updated.get("nodes") or {}).get(current.node_id, {}) if isinstance(updated.get("nodes"), dict) else {}
    error = current_payload.get("prediction_error_from_parent") if isinstance(current_payload, dict) else {}
    return updated, dict(error or {})


def _merge_prediction_fields(source_graph: dict[str, Any], target_graph: dict[str, Any]) -> None:
    source_nodes = source_graph.get("nodes") if isinstance(source_graph.get("nodes"), dict) else {}
    target_nodes = target_graph.get("nodes") if isinstance(target_graph.get("nodes"), dict) else {}
    for node_id, source in source_nodes.items():
        if not isinstance(source, dict) or not isinstance(target_nodes.get(node_id), dict):
            continue
        target = target_nodes[node_id]
        for key in ("prediction_error_from_parent", "uncertainty", "exploration"):
            if isinstance(source.get(key), dict):
                target[key] = {**dict(target.get(key) or {}), **dict(source.get(key) or {})}
    source_edges = source_graph.get("edges") if isinstance(source_graph.get("edges"), dict) else {}
    target_edges = target_graph.get("edges") if isinstance(target_graph.get("edges"), dict) else {}
    for edge_id, source in source_edges.items():
        if not isinstance(source, dict) or not isinstance(target_edges.get(edge_id), dict):
            continue
        target = target_edges[edge_id]
        for key in ("predicted_next_state", "prediction_error", "uncertainty", "exploration"):
            if isinstance(source.get(key), dict):
                target[key] = {**dict(target.get(key) or {}), **dict(source.get(key) or {})}


def _same_action_dict(row: dict[str, Any], action: PolicyAction) -> bool:
    if str(row.get("action_id") or "") and action.action_id and str(row.get("action_id")) == action.action_id:
        return True
    return str(row.get("action_type") or "") == action.action_type and str(row.get("module_name") or "") == action.module_name


def _action_key(action: PolicyAction) -> str:
    if action.action_type == "module" and action.module_name:
        return f"module:{action.module_name}"
    return f"{action.action_type}:{action.action_id or action.action_type}"


def _episode_key(transition: PolicyGraphTransitionSample) -> str:
    return transition.episode_id or str((transition.source or {}).get("episode_id") or transition.sample_id.rsplit(":step:", 1)[0])


def _node_recovery(graph: dict[str, Any], node_id: str) -> dict[str, Any]:
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    node = nodes.get(node_id) if isinstance(nodes.get(node_id), dict) else {}
    return dict(node.get("recovery") or {}) if isinstance(node, dict) else {}


def _copy_jsonish(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Replay a world-pretrained policy model over transition rows and fill predicted_next_state/prediction_error.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--summary-output", default="")
    parser.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
