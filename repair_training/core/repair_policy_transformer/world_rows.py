from __future__ import annotations

from dataclasses import replace
from typing import Any

from repair_training.core.repair_policy_transformer.schema import (
    PolicyAction,
    PolicyGraphTransitionSample,
    PolicyGraphTrainingSample,
    PolicyWorldTrainingSample,
)


def build_policy_world_samples(transitions: list[PolicyGraphTransitionSample]) -> list[PolicyWorldTrainingSample]:
    output: list[PolicyWorldTrainingSample] = []
    for transition in transitions:
        output.append(_transition_world_sample(transition))
        output.append(_masked_world_sample(transition))
        output.append(_ranking_world_sample(transition))
    return output


def _transition_world_sample(transition: PolicyGraphTransitionSample) -> PolicyWorldTrainingSample:
    return PolicyWorldTrainingSample(
        task="transition",
        sample_id=f"{transition.sample_id}:transition",
        format=transition.format,
        graph=transition.graph_before,
        current_node_id=transition.current_node_id,
        best_node_id=transition.best_node_id,
        actions=list(transition.available_actions),
        chosen_action=transition.chosen_action,
        graph_after=transition.graph_after,
        observed_delta=transition.observed_delta or _observed_delta(transition.graph_before, transition.graph_after),
        source={**transition.source, "episode_id": transition.episode_id, "step_index": transition.step_index},
    )


def _masked_world_sample(transition: PolicyGraphTransitionSample) -> PolicyWorldTrainingSample:
    graph = dict(transition.graph_after or transition.graph_before or {})
    masked = _deepcopy_jsonish(graph)
    targets: dict[str, Any] = {}
    nodes = masked.get("nodes") if isinstance(masked.get("nodes"), dict) else {}
    target_id = str(masked.get("current_node_id") or transition.current_node_id or "")
    node = nodes.get(target_id) if isinstance(nodes.get(target_id), dict) else None
    if node is None and nodes:
        target_id, node = next((str(key), value) for key, value in nodes.items() if isinstance(value, dict))
    if isinstance(node, dict):
        recovery = node.get("recovery") if isinstance(node.get("recovery"), dict) else {}
        diagnosis = node.get("diagnosis_hgt") if isinstance(node.get("diagnosis_hgt"), dict) else {}
        targets = {
            "node_id": target_id,
            "recovery_score": _score(recovery),
            "patch_status": str(node.get("patch_status") or ""),
            "diagnosis_max_score": _diagnosis_max_score(diagnosis),
            "is_best_node": target_id == str(masked.get("best_node_id") or ""),
        }
        node["recovery"] = {"masked": True}
        node["diagnosis_hgt"] = {"masked": True}
        node["patch_status"] = "[MASK]"
    return PolicyWorldTrainingSample(
        task="masked_graph",
        sample_id=f"{transition.sample_id}:masked",
        format=transition.format,
        graph=graph,
        masked_graph=masked,
        mask_targets=targets,
        current_node_id=str(masked.get("current_node_id") or transition.current_node_id),
        best_node_id=str(masked.get("best_node_id") or transition.best_node_id),
        source={**transition.source, "episode_id": transition.episode_id, "step_index": transition.step_index},
    )


def _ranking_world_sample(transition: PolicyGraphTransitionSample) -> PolicyWorldTrainingSample:
    before_best = _graph_best_score(transition.graph_before)
    after_best = _graph_best_score(transition.graph_after)
    actions: list[PolicyAction] = []
    for action in transition.available_actions:
        key = _action_key(action)
        q = float(transition.action_q_values.get(key, transition.action_q_values.get(action.action_id, before_best)))
        if action.action_id == transition.chosen_action.action_id or (action.action_type == transition.chosen_action.action_type and action.module_name == transition.chosen_action.module_name):
            q = max(q, after_best)
        if action.action_type == "stop":
            q = before_best
        actions.append(replace(action, action_q_value=max(0.0, min(1.0, q))))
    max_q = max([before_best, *[action.action_q_value for action in actions]] or [before_best])
    actions = [replace(action, action_regret=max(0.0, max_q - action.action_q_value), best_action_set_member=max_q - action.action_q_value <= 0.02) for action in actions]
    actions = _apply_immediate_repeat_penalty(actions, transition.graph_before)
    actions = _apply_prediction_error_policy_bias(actions, transition.graph_before)
    max_q = max([before_best, *[action.action_q_value for action in actions]] or [before_best])
    actions = [replace(action, action_regret=max(0.0, max_q - action.action_q_value), best_action_set_member=max_q - action.action_q_value <= 0.02) for action in actions]
    ranking = PolicyGraphTrainingSample(
        sample_id=f"{transition.sample_id}:ranking",
        format=transition.format,
        graph=transition.graph_before,
        current_node_id=transition.current_node_id,
        best_node_id=transition.best_node_id,
        actions=actions,
        current_recovery=_current_recovery(transition.graph_before),
        best_recovery={"score": before_best},
        final_best_recovery=max_q,
        has_promising_future=max_q > before_best + 0.01,
        stop_regret=max(0.0, max_q - before_best),
        source={**transition.source, "episode_id": transition.episode_id, "step_index": transition.step_index},
    )
    return PolicyWorldTrainingSample(
        task="ranking",
        sample_id=ranking.sample_id,
        format=ranking.format,
        graph=ranking.graph,
        current_node_id=ranking.current_node_id,
        best_node_id=ranking.best_node_id,
        actions=actions,
        ranking_sample=ranking,
        source=ranking.source,
    )


def _apply_prediction_error_policy_bias(actions: list[PolicyAction], graph: dict[str, Any]) -> list[PolicyAction]:
    current = _current_node(graph)
    error = current.get("prediction_error_from_parent") if isinstance(current.get("prediction_error_from_parent"), dict) else {}
    if not error:
        return actions
    overall = _score({"score": error.get("overall_prediction_error")})
    parent_id = str(current.get("parent_id") or "")
    parent = (graph.get("nodes") or {}).get(parent_id, {}) if isinstance(graph.get("nodes"), dict) else {}
    current_score = _score(current.get("recovery") if isinstance(current.get("recovery"), dict) else {})
    parent_score = _score(parent.get("recovery") if isinstance(parent, dict) and isinstance(parent.get("recovery"), dict) else {})
    if overall <= 0.25 or current_score > parent_score + 0.01:
        return actions
    best_module_q = max([action.action_q_value for action in actions if action.action_type == "module"] or [0.0])
    output: list[PolicyAction] = []
    for action in actions:
        if action.action_type == "undo":
            output.append(replace(
                action,
                action_q_value=max(action.action_q_value, min(1.0, best_module_q + min(0.2, overall * 0.25))),
                q_source=action.q_source or "prediction_error_bias",
                is_teacher_evaluated=True,
            ))
        else:
            output.append(action)
    return output


def _apply_immediate_repeat_penalty(actions: list[PolicyAction], graph: dict[str, Any]) -> list[PolicyAction]:
    incoming_module, incoming_family = _incoming_module_family(graph)
    if not incoming_module and not incoming_family:
        return actions
    output: list[PolicyAction] = []
    for action in actions:
        if action.action_type != "module":
            output.append(action)
            continue
        family = str(action.features.get("module_family") or action.features.get("route_family") or action.module_name or "")
        same_module = bool(incoming_module and action.module_name == incoming_module)
        same_family = bool(incoming_family and family == incoming_family)
        if not same_module and not same_family:
            output.append(action)
            continue
        raw_q = float(action.action_q_value or 0.0)
        recovery_delta = _action_expected_delta(action, graph)
        penalty = 0.30 if same_module else 0.12
        if recovery_delta > 0.05:
            penalty *= 0.25
        q = max(0.0, raw_q - penalty)
        features = {
            **dict(action.features or {}),
            "same_as_parent_incoming_action": same_module,
            "same_family_as_parent_incoming_action": same_family,
            "repeat_action_penalty": penalty,
        }
        output.append(replace(
            action,
            action_q_value=q,
            q_source=action.q_source or "immediate_repeat_penalty",
            is_teacher_evaluated=True,
            best_action_set_member=False,
            features=features,
        ))
    return output


def _observed_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_best = _graph_best_score(before)
    after_best = _graph_best_score(after)
    current = _current_node(after)
    recovery = current.get("recovery") if isinstance(current.get("recovery"), dict) else {}
    return {
        "next_recovery_score": _score(recovery),
        "recovery_delta": _score(recovery) - _score((_current_node(before).get("recovery") if isinstance(_current_node(before).get("recovery"), dict) else {})),
        "patch_status": str(current.get("patch_status") or ""),
        "best_updated": after_best > before_best + 1e-9,
        "branch_stale_delta": int(after.get("stale_expansion_count") or 0) - int(before.get("stale_expansion_count") or 0),
        "diagnosis_root_case_delta": _diagnosis_max_score(current.get("diagnosis_hgt") if isinstance(current.get("diagnosis_hgt"), dict) else {}),
    }


def _action_expected_delta(action: PolicyAction, graph: dict[str, Any]) -> float:
    edges = graph.get("edges") if isinstance(graph.get("edges"), dict) else {}
    edge = None
    for item in edges.values() if isinstance(edges, dict) else []:
        if not isinstance(item, dict):
            continue
        if str(item.get("candidate_id") or "") == action.action_id or str(item.get("module_name") or "") == action.module_name:
            edge = item
            break
    exploration = edge.get("exploration") if isinstance(edge, dict) and isinstance(edge.get("exploration"), dict) else {}
    return _score({"score": exploration.get("result_recovery_delta")})


def _incoming_module_family(graph: dict[str, Any]) -> tuple[str, str]:
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    current_id = str(graph.get("current_node_id") or "")
    current = nodes.get(current_id) if isinstance(nodes.get(current_id), dict) else {}
    parent_id = str(current.get("parent_id") or "") if isinstance(current, dict) else ""
    if not current_id or not parent_id:
        return "", ""
    edges = graph.get("edges") if isinstance(graph.get("edges"), dict) else {}
    for edge in edges.values() if isinstance(edges, dict) else []:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("from_node_id") or "") == parent_id and str(edge.get("to_node_id") or "") == current_id:
            module = str(edge.get("module_name") or "")
            return module, str(edge.get("module_family") or module)
    module = str(current.get("module_name") or "") if isinstance(current, dict) else ""
    return module, module


def _current_node(graph: dict[str, Any]) -> dict[str, Any]:
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    node = nodes.get(str(graph.get("current_node_id") or "")) if isinstance(nodes, dict) else {}
    return dict(node or {}) if isinstance(node, dict) else {}


def _current_recovery(graph: dict[str, Any]) -> dict[str, Any]:
    recovery = _current_node(graph).get("recovery")
    return dict(recovery or {}) if isinstance(recovery, dict) else {}


def _graph_best_score(graph: dict[str, Any]) -> float:
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    best = 0.0
    for node in nodes.values() if isinstance(nodes, dict) else []:
        if isinstance(node, dict):
            recovery = node.get("recovery") if isinstance(node.get("recovery"), dict) else {}
            best = max(best, _score(recovery))
    return best


def _score(recovery: dict[str, Any]) -> float:
    try:
        return max(0.0, min(1.0, float(recovery.get("score", recovery.get("completeness", 0.0)) or 0.0)))
    except (TypeError, ValueError):
        return 0.0


def _diagnosis_max_score(diagnosis: dict[str, Any]) -> float:
    root = diagnosis.get("root_case") if isinstance(diagnosis.get("root_case"), dict) else {}
    scores = root.get("scores") if isinstance(root.get("scores"), dict) else {}
    values = []
    for value in scores.values():
        try:
            values.append(float(value))
        except (TypeError, ValueError):
            pass
    return max(values or [0.0])


def _action_key(action: PolicyAction) -> str:
    if action.action_type == "module" and action.module_name:
        return f"module:{action.module_name}"
    return f"{action.action_type}:{action.action_id or action.action_type}"


def _deepcopy_jsonish(value: Any) -> Any:
    import json

    return json.loads(json.dumps(value))
