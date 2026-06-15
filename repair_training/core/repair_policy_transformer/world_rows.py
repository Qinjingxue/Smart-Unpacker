from __future__ import annotations

from dataclasses import replace
from typing import Any

from sunpack.repair.model.policy.schema import (
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
        q = float(action.action_q_value or transition.action_q_values.get(key, transition.action_q_values.get(action.action_id, before_best)))
        if action.action_id == transition.chosen_action.action_id or (action.action_type == transition.chosen_action.action_type and action.module_name == transition.chosen_action.module_name):
            q = max(q, after_best)
        if action.action_type == "stop":
            q = before_best
        actions.append(replace(action, action_q_value=max(0.0, min(1.0, q))))
    max_q = max([before_best, *[action.action_q_value for action in actions]] or [before_best])
    actions = _refresh_best_action_set(actions, max_q=max_q)
    actions = _apply_module_history_feedback(actions, transition.graph_before)
    actions = _apply_immediate_repeat_penalty(actions, transition.graph_before)
    actions = _apply_current_node_retry_penalty(actions, transition.graph_before)
    actions = _apply_prediction_error_policy_bias(actions, transition.graph_before)
    actions = _cap_unpromising_undo(actions, transition.graph_before)
    actions = _apply_post_module_deepen_bias(actions, transition.graph_before)
    actions = _apply_post_undo_continue_bias(actions, transition.graph_before)
    actions = _apply_branch_continuation_bias(actions, transition.graph_before)
    actions = _sharpen_near_ties(actions, transition.graph_before)
    max_q = max([before_best, *[action.action_q_value for action in actions]] or [before_best])
    actions = _refresh_best_action_set(actions, max_q=max_q)
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


def _refresh_best_action_set(actions: list[PolicyAction], *, max_q: float) -> list[PolicyAction]:
    output: list[PolicyAction] = []
    for action in actions:
        margin = 0.006 if action.action_type == "module" else 0.02
        output.append(replace(
            action,
            action_regret=max(0.0, max_q - float(action.action_q_value or 0.0)),
            best_action_set_member=max_q - float(action.action_q_value or 0.0) <= margin,
        ))
    return output


def _cap_unpromising_undo(actions: list[PolicyAction], graph: dict[str, Any]) -> list[PolicyAction]:
    if _undo_has_promising_frontier(graph):
        return actions
    before_best = _graph_best_score(graph)
    output: list[PolicyAction] = []
    for action in actions:
        if action.action_type != "undo":
            output.append(action)
            continue
        cap = before_best + 0.02
        features = {**dict(action.features or {}), "undo_without_frontier_cap": cap}
        output.append(replace(
            action,
            action_q_value=max(0.0, min(float(action.action_q_value or 0.0), cap)),
            q_source=action.q_source or "unpromising_undo_cap",
            features=features,
            best_action_set_member=False,
        ))
    return output


def _sharpen_near_ties(actions: list[PolicyAction], graph: dict[str, Any]) -> list[PolicyAction]:
    module_actions = [action for action in actions if action.action_type == "module"]
    if len(module_actions) < 2:
        return actions
    max_q = max(float(action.action_q_value or 0.0) for action in module_actions)
    near = [action for action in module_actions if max_q - float(action.action_q_value or 0.0) <= 0.02]
    if len(near) < 3:
        return actions
    ordered = sorted(
        near,
        key=lambda action: (
            -_action_expected_delta(action, graph),
            -float(action.action_q_value or 0.0),
            str(action.module_name or action.action_id or ""),
        ),
    )
    rank_by_id = {id(action): rank for rank, action in enumerate(ordered)}
    output: list[PolicyAction] = []
    for action in actions:
        if action.action_type != "module" or action not in near:
            output.append(action)
            continue
        expected_delta = _action_expected_delta(action, graph)
        rank = rank_by_id.get(id(action), 0)
        penalty = 0.0 if expected_delta > 0.01 else 0.04
        penalty += min(0.08, 0.008 * rank)
        features = {**dict(action.features or {}), "near_tie_label_sharpening_penalty": penalty}
        output.append(replace(
            action,
            action_q_value=max(0.0, float(action.action_q_value or 0.0) - penalty),
            features=features,
        ))
    return output


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
    if not _undo_has_promising_frontier(graph):
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


def _apply_post_undo_continue_bias(actions: list[PolicyAction], graph: dict[str, Any]) -> list[PolicyAction]:
    if not _post_undo_continue_context(graph):
        return actions
    output: list[PolicyAction] = []
    for action in actions:
        if action.action_type == "module":
            features = {**dict(action.features or {}), "post_undo_continue_module_bonus": 0.12}
            output.append(replace(
                action,
                action_q_value=min(1.0, float(action.action_q_value or 0.0) + 0.12),
                q_source=action.q_source or "post_undo_continue_bias",
                features=features,
            ))
            continue
        if action.action_type == "undo":
            penalty = 0.30 if not _undo_has_promising_frontier(graph) else 0.16
            features = {**dict(action.features or {}), "post_undo_repeat_undo_penalty": penalty}
            output.append(replace(
                action,
                action_q_value=max(0.0, float(action.action_q_value or 0.0) - penalty),
                q_source=action.q_source or "post_undo_continue_bias",
                features=features,
                best_action_set_member=False,
            ))
            continue
        output.append(action)
    return output


def _apply_post_module_deepen_bias(actions: list[PolicyAction], graph: dict[str, Any]) -> list[PolicyAction]:
    if not _post_module_deepen_context(graph):
        return actions
    output: list[PolicyAction] = []
    for action in actions:
        if action.action_type == "module":
            bonus = 0.10
            features = {**dict(action.features or {}), "post_module_deepen_bonus": bonus}
            output.append(replace(
                action,
                action_q_value=min(1.0, float(action.action_q_value or 0.0) + bonus),
                q_source=action.q_source or "post_module_deepen_bias",
                features=features,
            ))
            continue
        if action.action_type == "undo":
            penalty = 0.24
            features = {**dict(action.features or {}), "post_module_immediate_undo_penalty": penalty}
            output.append(replace(
                action,
                action_q_value=max(0.0, float(action.action_q_value or 0.0) - penalty),
                q_source=action.q_source or "post_module_deepen_bias",
                features=features,
                best_action_set_member=False,
            ))
            continue
        output.append(action)
    return output


def _apply_branch_continuation_bias(actions: list[PolicyAction], graph: dict[str, Any]) -> list[PolicyAction]:
    continuation = _branch_continuation_score(graph)
    if continuation <= 0.08:
        return actions
    before_best = _graph_best_score(graph)
    best_module_q = max([float(action.action_q_value or 0.0) for action in actions if action.action_type == "module"] or [0.0])
    output: list[PolicyAction] = []
    for action in actions:
        features = dict(action.features or {})
        if action.action_type == "module":
            bonus = min(0.14, 0.05 + continuation * 0.35)
            features["branch_continuation_bonus"] = bonus
            features["branch_continuation_score"] = continuation
            output.append(replace(
                action,
                action_q_value=min(1.0, float(action.action_q_value or 0.0) + bonus),
                q_source=action.q_source or "branch_continuation_bias",
                features=features,
            ))
            continue
        if action.action_type == "undo":
            penalty = min(0.24, 0.08 + continuation * 0.35)
            features["premature_undo_on_promising_branch_penalty"] = penalty
            features["branch_continuation_score"] = continuation
            output.append(replace(
                action,
                action_q_value=max(0.0, min(float(action.action_q_value or 0.0) - penalty, max(before_best + 0.02, best_module_q - 0.04))),
                q_source=action.q_source or "branch_continuation_bias",
                features=features,
                best_action_set_member=False,
            ))
            continue
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


def _apply_module_history_feedback(actions: list[PolicyAction], graph: dict[str, Any]) -> list[PolicyAction]:
    module_history, family_history = _module_history_stats(graph)
    if not module_history and not family_history:
        return actions
    output: list[PolicyAction] = []
    for action in actions:
        if action.action_type != "module":
            output.append(action)
            continue
        family = str(action.features.get("module_family") or action.features.get("route_family") or action.module_name or "")
        exact = module_history.get(action.module_name, {})
        family_stats = family_history.get(family, {})
        penalty = _history_penalty(exact, exact=True)
        if penalty <= 0.0:
            penalty = _history_penalty(family_stats, exact=False)
        if penalty <= 0.0:
            output.append(action)
            continue
        features = {
            **dict(action.features or {}),
            "module_history_attempt_count": int(exact.get("attempts") or 0),
            "module_history_mean_delta": float(exact.get("mean_delta") or 0.0),
            "module_history_failure_rate": float(exact.get("failure_rate") or 0.0),
            "module_history_undo_rate": float(exact.get("undo_rate") or 0.0),
            "module_history_no_gain_penalty": penalty,
        }
        output.append(replace(
            action,
            action_q_value=max(0.0, float(action.action_q_value or 0.0) - penalty),
            q_source=action.q_source or "module_history_feedback",
            features=features,
            best_action_set_member=False,
        ))
    return output


def _apply_current_node_retry_penalty(actions: list[PolicyAction], graph: dict[str, Any]) -> list[PolicyAction]:
    tried_modules, tried_families = _current_node_tried_modules(graph)
    if not tried_modules and not tried_families:
        return actions
    output: list[PolicyAction] = []
    for action in actions:
        if action.action_type != "module":
            output.append(action)
            continue
        family = str(action.features.get("module_family") or action.features.get("route_family") or action.module_name or "")
        module_count = int(tried_modules.get(action.module_name, 0))
        family_count = int(tried_families.get(family, 0))
        if module_count <= 0 and family_count <= 0:
            output.append(action)
            continue
        module_penalty = min(0.30, 0.12 + 0.06 * max(0, module_count - 1)) if module_count > 0 else 0.0
        family_penalty = min(0.16, 0.05 + 0.03 * max(0, family_count - 1)) if family_count > 0 else 0.0
        penalty = max(module_penalty, family_penalty)
        features = {
            **dict(action.features or {}),
            "current_node_retried_module_count": module_count,
            "current_node_retried_family_count": family_count,
        }
        if module_penalty:
            features["current_node_retried_module_penalty"] = module_penalty
        if family_penalty:
            features["current_node_retried_family_penalty"] = family_penalty
        output.append(replace(
            action,
            action_q_value=max(0.0, float(action.action_q_value or 0.0) - penalty),
            q_source=action.q_source or "current_node_retry_penalty",
            features=features,
            best_action_set_member=False,
        ))
    return output


def _module_history_stats(graph: dict[str, Any]) -> tuple[dict[str, dict[str, float]], dict[str, dict[str, float]]]:
    module_raw: dict[str, dict[str, float]] = {}
    family_raw: dict[str, dict[str, float]] = {}
    edges = graph.get("edges") if isinstance(graph.get("edges"), dict) else {}
    for edge in edges.values() if isinstance(edges, dict) else []:
        if not isinstance(edge, dict):
            continue
        exploration = edge.get("exploration") if isinstance(edge.get("exploration"), dict) else {}
        attempted = _float(exploration.get("attempt_count")) > 0.0 or str(edge.get("status") or "") in {"expanded", "expanded_failed", "repeated"}
        if not attempted:
            continue
        module = str(edge.get("module_name") or "")
        family = str(edge.get("module_family") or edge.get("route_family") or module)
        delta = _float(exploration.get("result_recovery_delta", edge.get("recovery_delta")))
        failed = 1.0 if str(exploration.get("result_patch_status") or edge.get("patch_status") or edge.get("status") or "") in {"empty_failed", "empty_noop", "expanded_failed", "repeated"} else 0.0
        undo = min(1.0, _float(exploration.get("undo_count_after_attempt")))
        if module:
            _accumulate_history(module_raw.setdefault(module, {}), delta=delta, failed=failed, undo=undo)
        if family:
            _accumulate_history(family_raw.setdefault(family, {}), delta=delta, failed=failed, undo=undo)
    return (
        {key: _finalize_history(value) for key, value in module_raw.items()},
        {key: _finalize_history(value) for key, value in family_raw.items()},
    )


def _accumulate_history(payload: dict[str, float], *, delta: float, failed: float, undo: float) -> None:
    payload["attempts"] = _float(payload.get("attempts")) + 1.0
    payload["sum_delta"] = _float(payload.get("sum_delta")) + delta
    payload["failures"] = _float(payload.get("failures")) + failed
    payload["undos"] = _float(payload.get("undos")) + undo


def _finalize_history(payload: dict[str, float]) -> dict[str, float]:
    attempts = max(1.0, _float(payload.get("attempts")))
    return {
        "attempts": attempts,
        "mean_delta": _float(payload.get("sum_delta")) / attempts,
        "failure_rate": _float(payload.get("failures")) / attempts,
        "undo_rate": _float(payload.get("undos")) / attempts,
    }


def _history_penalty(stats: dict[str, float], *, exact: bool) -> float:
    attempts = _float(stats.get("attempts"))
    if attempts < (2.0 if exact else 3.0):
        return 0.0
    mean_delta = _float(stats.get("mean_delta"))
    failure_rate = _float(stats.get("failure_rate"))
    undo_rate = _float(stats.get("undo_rate"))
    if mean_delta > 0.01 and failure_rate < 0.6:
        return 0.0
    pressure = 0.0
    pressure += 0.10 if mean_delta <= 0.001 else 0.04
    pressure += min(0.10, failure_rate * 0.12)
    pressure += min(0.08, undo_rate * 0.10)
    pressure += min(0.06, (attempts - 1.0) * 0.015)
    if not exact:
        pressure *= 0.55
    return min(0.28 if exact else 0.14, pressure)


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


def _current_node_tried_modules(graph: dict[str, Any]) -> tuple[dict[str, int], dict[str, int]]:
    current_id = str(graph.get("current_node_id") or "")
    edges = graph.get("edges") if isinstance(graph.get("edges"), dict) else {}
    modules: dict[str, int] = {}
    families: dict[str, int] = {}
    for edge in edges.values() if isinstance(edges, dict) else []:
        if not isinstance(edge, dict) or str(edge.get("from_node_id") or "") != current_id:
            continue
        exploration = edge.get("exploration") if isinstance(edge.get("exploration"), dict) else {}
        attempted = _float(exploration.get("attempt_count")) > 0.0 or str(edge.get("status") or "") in {"expanded", "expanded_failed", "repeated"}
        if not attempted:
            continue
        module = str(edge.get("module_name") or "")
        family = str(edge.get("module_family") or edge.get("route_family") or module)
        if module:
            modules[module] = modules.get(module, 0) + 1
        if family:
            families[family] = families.get(family, 0) + 1
    return modules, families


def _current_node(graph: dict[str, Any]) -> dict[str, Any]:
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    node = nodes.get(str(graph.get("current_node_id") or "")) if isinstance(nodes, dict) else {}
    return dict(node or {}) if isinstance(node, dict) else {}


def _undo_has_promising_frontier(graph: dict[str, Any]) -> bool:
    current = _current_node(graph)
    parent_id = str(current.get("parent_id") or "")
    if not parent_id:
        return False
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    parent = nodes.get(parent_id) if isinstance(nodes, dict) and isinstance(nodes.get(parent_id), dict) else {}
    current_score = _score(current.get("recovery") if isinstance(current.get("recovery"), dict) else {})
    parent_score = _score(parent.get("recovery") if isinstance(parent, dict) and isinstance(parent.get("recovery"), dict) else {})
    parent_exploration = parent.get("exploration") if isinstance(parent, dict) and isinstance(parent.get("exploration"), dict) else {}
    current_exploration = current.get("exploration") if isinstance(current.get("exploration"), dict) else {}
    if _float(parent_exploration.get("fresh_action_count")) > 0:
        return True
    if _float(parent_exploration.get("exhaustion_ratio")) < 0.95 and _float(parent_exploration.get("outgoing_action_count")) > _float(parent_exploration.get("expanded_action_count")):
        return True
    if _float(parent_exploration.get("subtree_best_recovery")) > max(current_score, parent_score) + 0.02:
        return True
    summary = graph.get("graph_summary") if isinstance(graph.get("graph_summary"), dict) else graph.get("summary") if isinstance(graph.get("summary"), dict) else {}
    if _float(current_exploration.get("fresh_action_count")) <= 0 and _float(summary.get("untried_action_count")) > 0:
        return True
    return False


def _post_undo_continue_context(graph: dict[str, Any]) -> bool:
    current = _current_node(graph)
    exploration = current.get("exploration") if isinstance(current.get("exploration"), dict) else {}
    if _float(exploration.get("visit_count")) < 2:
        return False
    return _float(exploration.get("fresh_action_count")) > 0 or _float(exploration.get("exhaustion_ratio")) < 0.95


def _post_module_deepen_context(graph: dict[str, Any]) -> bool:
    current = _current_node(graph)
    parent_id = str(current.get("parent_id") or "")
    if not parent_id:
        return False
    if str(current.get("patch_status") or "") != "applied":
        return False
    exploration = current.get("exploration") if isinstance(current.get("exploration"), dict) else {}
    recovery = current.get("recovery") if isinstance(current.get("recovery"), dict) else {}
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    parent = nodes.get(parent_id) if isinstance(nodes, dict) and isinstance(nodes.get(parent_id), dict) else {}
    parent_recovery = parent.get("recovery") if isinstance(parent, dict) and isinstance(parent.get("recovery"), dict) else {}
    if _score(recovery) + 0.02 < _score(parent_recovery):
        return False
    return _float(exploration.get("fresh_action_count")) > 0 or _float(exploration.get("exhaustion_ratio")) < 0.85


def _branch_continuation_score(graph: dict[str, Any]) -> float:
    current = _current_node(graph)
    parent_id = str(current.get("parent_id") or "")
    if not parent_id:
        return 0.0
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    parent = nodes.get(parent_id) if isinstance(nodes, dict) and isinstance(nodes.get(parent_id), dict) else {}
    recovery = current.get("recovery") if isinstance(current.get("recovery"), dict) else {}
    parent_recovery = parent.get("recovery") if isinstance(parent, dict) and isinstance(parent.get("recovery"), dict) else {}
    exploration = current.get("exploration") if isinstance(current.get("exploration"), dict) else {}
    uncertainty = current.get("uncertainty") if isinstance(current.get("uncertainty"), dict) else {}
    error = current.get("prediction_error_from_parent") if isinstance(current.get("prediction_error_from_parent"), dict) else {}
    diagnosis = current.get("diagnosis_hgt") if isinstance(current.get("diagnosis_hgt"), dict) else {}
    parent_diagnosis = parent.get("diagnosis_hgt") if isinstance(parent, dict) and isinstance(parent.get("diagnosis_hgt"), dict) else {}
    recovery_delta = _score(recovery) - _score(parent_recovery)
    diagnosis_gain = _diagnosis_max_score(diagnosis) - _diagnosis_max_score(parent_diagnosis)
    prediction_error = _float(error.get("overall_prediction_error"))
    patch_status = str(current.get("patch_status") or "")
    score = 0.0
    score += max(0.0, recovery_delta) * 1.2
    score += max(0.0, diagnosis_gain) * 0.35
    score += 0.08 if patch_status == "applied" else 0.0
    score += min(0.10, _float(exploration.get("fresh_action_count")) / 64.0)
    score -= min(0.20, prediction_error * 0.45)
    score -= min(0.12, _float(uncertainty.get("overall_uncertainty")) * 0.10)
    if patch_status in {"empty_failed", "empty_noop", "repeated"}:
        score -= 0.20
    return max(0.0, min(1.0, score))


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


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
