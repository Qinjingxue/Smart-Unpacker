from __future__ import annotations

from dataclasses import replace
from typing import Any

from repair_training.policy.exploration import (
    current_node_tried_modules,
    history_penalty,
    incoming_module_family,
    module_history_stats,
)
from sunpack.repair.model.policy.schema import PolicyAction, PolicyGraphTransitionSample


def annotate_episode_future_best_q(transitions: list[PolicyGraphTransitionSample]) -> list[PolicyGraphTransitionSample]:
    if not transitions:
        return []
    future_best: list[float] = [0.0] * len(transitions)
    running = 0.0
    for index in range(len(transitions) - 1, -1, -1):
        running = max(running, _graph_best_score(transitions[index].graph_after))
        future_best[index] = running
    output: list[PolicyGraphTransitionSample] = []
    for index, transition in enumerate(transitions):
        chosen_q = future_best[index]
        stop_q = _graph_best_score(transition.graph_before)
        q_values = dict(transition.action_q_values or {})
        chosen_key = _action_key(transition.chosen_action)
        q_values[chosen_key] = max(float(q_values.get(chosen_key, 0.0) or 0.0), chosen_q)
        if transition.chosen_action.action_id:
            q_values[transition.chosen_action.action_id] = max(float(q_values.get(transition.chosen_action.action_id, 0.0) or 0.0), chosen_q)
        q_values["stop:stop"] = stop_q
        q_values["stop"] = stop_q
        max_known_q = max([chosen_q, stop_q, *[float(value or 0.0) for value in q_values.values()]] or [stop_q])
        actions = [
            _annotate_action_q(
                action,
                chosen=transition.chosen_action,
                chosen_q=chosen_q,
                stop_q=stop_q,
                action_q_values=q_values,
                max_known_q=max_known_q,
                horizon=len(transitions) - index,
            )
            for action in transition.available_actions
        ]
        actions = _shape_action_q_labels(actions, transition, max_known_q=max_known_q)
        max_known_q = max([stop_q, *[float(action.action_q_value or 0.0) for action in actions]] or [stop_q])
        actions = [_refresh_action_regret(action, max_known_q=max_known_q) for action in actions]
        chosen = _annotate_action_q(
            transition.chosen_action,
            chosen=transition.chosen_action,
            chosen_q=chosen_q,
            stop_q=stop_q,
            action_q_values=q_values,
            max_known_q=max_known_q,
            horizon=len(transitions) - index,
        )
        output.append(PolicyGraphTransitionSample(
            sample_id=transition.sample_id,
            format=transition.format,
            graph_before=transition.graph_before,
            current_node_id=transition.current_node_id,
            best_node_id=transition.best_node_id,
            available_actions=actions,
            chosen_action=chosen,
            graph_after=transition.graph_after,
            observed_delta=transition.observed_delta,
            action_q_values=q_values,
            episode_id=transition.episode_id,
            step_index=transition.step_index,
            exploration_policy=transition.exploration_policy,
            source={
                **dict(transition.source or {}),
                "q_label_source": "episode_future_best",
                "episode_future_best": chosen_q,
                "stop_q_value": stop_q,
            },
        ))
    return output

def _annotate_action_q(
    action: PolicyAction,
    *,
    chosen: PolicyAction,
    chosen_q: float,
    stop_q: float,
    action_q_values: dict[str, Any] | None = None,
    max_known_q: float,
    horizon: int,
) -> PolicyAction:
    from dataclasses import replace

    if action.action_type == "stop":
        q = stop_q
        source = "episode_stop_current_best"
        evaluated = True
    elif action_q_values and (_action_key(action) in action_q_values or action.action_id in action_q_values):
        q = float(action_q_values.get(_action_key(action), action_q_values.get(action.action_id, 0.0)) or 0.0)
        source = "bounded_action_rollout"
        evaluated = True
    elif _same_action(action, chosen):
        q = chosen_q
        source = "episode_chosen_future_best"
        evaluated = True
    else:
        return action
    q = _clamp01(q)
    max_known_q = _clamp01(max_known_q)
    return replace(
        action,
        action_q_value=q,
        q_source=source,
        q_horizon=max(0, int(horizon or 0)),
        action_regret=max(0.0, max_known_q - q),
        is_teacher_evaluated=evaluated,
        best_action_set_member=max_known_q - q <= 0.02,
        q_bucket=_q_bucket(q),
    )

def _shape_action_q_labels(
    actions: list[PolicyAction],
    transition: PolicyGraphTransitionSample,
    *,
    max_known_q: float,
) -> list[PolicyAction]:
    before_best = _graph_best_score(transition.graph_before)
    after_best = _graph_best_score(transition.graph_after)
    immediate_gain = max(0.0, after_best - before_best)
    continuation = _branch_continuation_score(transition.graph_before)
    incoming_module, incoming_family = incoming_module_family(transition.graph_before)
    tried_modules, tried_families = current_node_tried_modules(transition.graph_before)
    module_history, family_history = module_history_stats(transition.graph_before)
    chosen_key = _action_key(transition.chosen_action)
    best_module_q = max([float(action.action_q_value or 0.0) for action in actions if action.action_type == "module"] or [0.0])
    output: list[PolicyAction] = []
    for action in actions:
        q = float(action.action_q_value or 0.0)
        features = dict(action.features or {})
        if action.action_type == "module":
            family = str(features.get("module_family") or features.get("route_family") or action.module_name or "")
            same_module = bool(incoming_module and action.module_name == incoming_module)
            same_family = bool(incoming_family and family == incoming_family)
            tried_module_count = int(tried_modules.get(action.module_name, 0))
            tried_family_count = int(tried_families.get(family, 0))
            prior_penalty = history_penalty(module_history.get(action.module_name, {}), exact=True)
            if prior_penalty <= 0.0:
                prior_penalty = history_penalty(family_history.get(family, {}), exact=False)
            if prior_penalty > 0.0:
                q -= prior_penalty
                features["module_history_no_gain_penalty"] = prior_penalty
                exact = module_history.get(action.module_name, {})
                features["module_history_attempt_count"] = int(exact.get("attempts") or 0)
                features["module_history_mean_delta"] = float(exact.get("mean_delta") or 0.0)
                features["module_history_failure_rate"] = float(exact.get("failure_rate") or 0.0)
                features["module_history_undo_rate"] = float(exact.get("undo_rate") or 0.0)
            if same_module:
                q -= 0.35
                features["repeat_module_q_penalty"] = 0.35
            elif same_family:
                q -= 0.15
                features["repeat_family_q_penalty"] = 0.15
            if tried_module_count > 0:
                penalty = min(0.30, 0.12 + 0.06 * max(0, tried_module_count - 1))
                q -= penalty
                features["current_node_retried_module_count"] = tried_module_count
                features["current_node_retried_module_penalty"] = penalty
            elif tried_family_count > 0:
                penalty = min(0.16, 0.05 + 0.03 * max(0, tried_family_count - 1))
                q -= penalty
                features["current_node_retried_family_count"] = tried_family_count
                features["current_node_retried_family_penalty"] = penalty
            if _same_action(action, transition.chosen_action):
                features["chosen_immediate_gain"] = immediate_gain
                if immediate_gain <= 0.001 and transition.chosen_action.action_type == "module":
                    q -= 0.12
                    features["poor_chosen_action_q_penalty"] = 0.12
            elif max_known_q - q <= 0.02:
                q -= 0.04
                features["near_tie_unexecuted_q_penalty"] = 0.04
        if action.action_type == "undo":
            current = _current_node(transition.graph_before)
            exploration = current.get("exploration") if isinstance(current.get("exploration"), dict) else {}
            undo_opportunity = _undo_has_promising_frontier(transition.graph_before)
            if _float(exploration.get("exhaustion_ratio")) >= 0.75 and undo_opportunity:
                q = max(q, min(1.0, before_best + 0.08))
                features["undo_promising_frontier_bonus"] = 0.08
            elif not undo_opportunity:
                q = min(q - 0.18, before_best + 0.02)
                features["undo_without_frontier_penalty"] = 0.18
                features["undo_without_frontier_cap"] = before_best + 0.02
        if _post_module_deepen_context(transition.graph_before):
            if action.action_type == "module":
                q += 0.10
                features["post_module_deepen_bonus"] = 0.10
            elif action.action_type == "undo":
                q -= 0.24
                features["post_module_immediate_undo_penalty"] = 0.24
        if action.action_type == "module" and _post_undo_continue_context(transition.graph_before):
            q += 0.12
            features["post_undo_continue_module_bonus"] = 0.12
        if action.action_type == "module" and continuation > 0.08:
            bonus = min(0.14, 0.05 + continuation * 0.35)
            q += bonus
            features["branch_continuation_bonus"] = bonus
            features["branch_continuation_score"] = continuation
        if action.action_type == "undo" and _post_undo_continue_context(transition.graph_before):
            repeat_undo_penalty = 0.30 if not _undo_has_promising_frontier(transition.graph_before) else 0.16
            q -= repeat_undo_penalty
            features["post_undo_repeat_undo_penalty"] = repeat_undo_penalty
        if action.action_type == "undo" and continuation > 0.08:
            penalty = min(0.24, 0.08 + continuation * 0.35)
            q = min(q - penalty, max(before_best + 0.02, best_module_q - 0.04))
            features["premature_undo_on_promising_branch_penalty"] = penalty
            features["branch_continuation_score"] = continuation
        if action.action_type == "stop" and max_known_q > before_best + 0.02:
            q = min(q, before_best)
            features["premature_stop_penalty_active"] = True
        output.append(replace(
            action,
            action_q_value=_clamp01(q),
            features=features,
            q_source=action.q_source or "shaped_episode_future_best",
        ))
    return _spread_near_tie_modules(output)

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
    return _clamp01(score)

def _spread_near_tie_modules(actions: list[PolicyAction]) -> list[PolicyAction]:
    modules = [action for action in actions if action.action_type == "module"]
    if len(modules) < 3:
        return actions
    max_q = max(float(action.action_q_value or 0.0) for action in modules)
    near = [action for action in modules if max_q - float(action.action_q_value or 0.0) <= 0.02]
    if len(near) < 3:
        return actions
    ordered = sorted(
        near,
        key=lambda action: (
            -float(action.action_q_value or 0.0),
            str(action.module_name or action.action_id or ""),
        ),
    )
    rank_by_id = {id(action): rank for rank, action in enumerate(ordered)}
    output: list[PolicyAction] = []
    for action in actions:
        rank = rank_by_id.get(id(action))
        if rank is None:
            output.append(action)
            continue
        penalty = min(0.08, 0.008 * rank)
        features = {**dict(action.features or {}), "near_tie_rank_spread_penalty": penalty}
        output.append(replace(action, action_q_value=max(0.0, float(action.action_q_value or 0.0) - penalty), features=features))
    return output

def _refresh_action_regret(action: PolicyAction, *, max_known_q: float) -> PolicyAction:
    q = _clamp01(float(action.action_q_value or 0.0))
    tie_margin = 0.006 if action.action_type == "module" else 0.02
    return replace(
        action,
        action_regret=max(0.0, max_known_q - q),
        best_action_set_member=max_known_q - q <= tie_margin,
        q_bucket=_q_bucket(q),
    )

def _same_action(left: PolicyAction, right: PolicyAction) -> bool:
    if left.action_id and right.action_id and left.action_id == right.action_id:
        return True
    return left.action_type == right.action_type and left.module_name == right.module_name

def _action_key(action: PolicyAction) -> str:
    if action.action_type == "module" and action.module_name:
        return f"module:{action.module_name}"
    return f"{action.action_type}:{action.action_id or action.action_type}"

def _graph_best_score(graph: dict[str, Any]) -> float:
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    best = 0.0
    for node in nodes.values() if isinstance(nodes, dict) else []:
        if not isinstance(node, dict):
            continue
        recovery = node.get("recovery") if isinstance(node.get("recovery"), dict) else {}
        best = max(best, _score(recovery))
    return best

def _current_node(graph: dict[str, Any]) -> dict[str, Any]:
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    current_id = str(graph.get("current_node_id") or "")
    node = nodes.get(current_id) if isinstance(nodes, dict) else {}
    return dict(node) if isinstance(node, dict) else {}

def _score(recovery: dict[str, Any]) -> float:
    try:
        return _clamp01(float(recovery.get("score", recovery.get("completeness", 0.0)) or 0.0))
    except (TypeError, ValueError):
        return 0.0

def _diagnosis_max_score(diagnosis: dict[str, Any]) -> float:
    root = diagnosis.get("root_case") if isinstance(diagnosis.get("root_case"), dict) else {}
    scores = root.get("scores") if isinstance(root.get("scores"), dict) else diagnosis.get("root_case_scores")
    values: list[float] = []
    if isinstance(scores, dict):
        for value in scores.values():
            values.append(_float(value))
    return max(values or [0.0])

def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0

def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))

def _q_bucket(value: float) -> str:
    value = _clamp01(value)
    if value >= 0.99:
        return "complete"
    if value >= 0.75:
        return "high"
    if value >= 0.4:
        return "medium"
    if value > 0.0:
        return "low"
    return "zero"
