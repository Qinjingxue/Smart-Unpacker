from __future__ import annotations

from typing import Any

from sunpack.repair.model.diagnosis.root_cases import ROOT_CASES
from sunpack.repair.model.policy.schema import PolicyAction, PolicyGraphTrainingSample, PolicyWorldTrainingSample
from sunpack.support.hash_features import hash_unit as _hash_unit


NODE_FEATURE_DIM = 55
EDGE_FEATURE_DIM = 19
ACTION_FEATURE_DIM = 54
MEMORY_FEATURE_DIM = 17
WORLD_BASE_TARGET_DIM = 6
WORLD_RECOVERY_TARGET_DIM = 11
WORLD_TARGET_DIM = WORLD_BASE_TARGET_DIM + len(ROOT_CASES) + WORLD_RECOVERY_TARGET_DIM
UNCERTAINTY_TARGET_DIM = 1
MASK_TARGET_DIM = 4


def require_torch():
    try:
        import torch  # noqa: F401
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            f"RepairPolicyTransformer requires torch. Install the project runtime dependencies. Import error: {exc}"
        ) from exc


def tensorize_sample(sample: PolicyGraphTrainingSample) -> dict[str, Any]:
    require_torch()
    import torch

    nodes = _nodes(sample.graph)
    graph_context = _graph_context(sample.graph, sample)
    node_features = [_node_features(node_id, node, sample, graph_context) for node_id, node in nodes]
    if not node_features:
        node_features = [[0.0] * NODE_FEATURE_DIM]
    edge_features = [_edge_features(edge, sample) for _edge_id, edge in _edges(sample.graph)]
    if not edge_features:
        edge_features = [[0.0] * EDGE_FEATURE_DIM]
    actions = sample.actions
    action_context = _action_context(sample)
    action_features = [_action_features(action, index, action_context) for index, action in enumerate(actions)]
    if not action_features:
        action_features = [[0.0] * ACTION_FEATURE_DIM]
    memory_features = [_memory_features(item, index) for index, item in enumerate(sample.memory[-64:])]
    if not memory_features:
        memory_features = [[0.0] * MEMORY_FEATURE_DIM]
    q_values = [action.action_q_value for action in actions] or [0.0]
    priors = [action.action_prior for action in actions] or [0.0]
    continue_branch = _sample_branch_continuation_score(sample) > 0.08
    return {
        "node_x": torch.tensor(node_features, dtype=torch.float32),
        "edge_x": torch.tensor(edge_features, dtype=torch.float32),
        "action_x": torch.tensor(action_features, dtype=torch.float32),
        "memory_x": torch.tensor(memory_features, dtype=torch.float32),
        "q": torch.tensor(q_values, dtype=torch.float32),
        "prior": torch.tensor(priors, dtype=torch.float32),
        "has_promising_future": torch.tensor([1.0 if sample.has_promising_future else 0.0], dtype=torch.float32),
        "continue_branch": torch.tensor([1.0 if continue_branch else 0.0], dtype=torch.float32),
        "stop_regret": torch.tensor([_float(sample.stop_regret)], dtype=torch.float32),
        "action_regret": torch.tensor([_float(action.action_regret) for action in actions] or [0.0], dtype=torch.float32),
        "teacher_evaluated": torch.tensor([1.0 if action.is_teacher_evaluated else 0.0 for action in actions] or [0.0], dtype=torch.float32),
        "best_action_set": torch.tensor([1.0 if action.best_action_set_member else 0.0 for action in actions] or [0.0], dtype=torch.float32),
        "action_uncertainty": torch.tensor([_action_uncertainty(action, action_context) for action in actions] or [0.0], dtype=torch.float32),
        "action_continue_target": torch.tensor([_action_continue_target(action, continue_branch) for action in actions] or [0.0], dtype=torch.float32),
        "action_continue_mask": torch.tensor([_action_continue_mask(action, continue_branch) for action in actions] or [0.0], dtype=torch.float32),
        "actions": [action.to_dict() for action in actions],
        "sample_id": sample.sample_id,
    }


def tensorize_world_sample(sample: PolicyWorldTrainingSample) -> dict[str, Any]:
    ranking = _world_to_ranking_sample(sample)
    item = tensorize_sample(ranking)
    item["task"] = sample.task
    item["transition_target"] = _transition_target(sample)
    item["uncertainty_target"] = _uncertainty_target(sample)
    item["mask_target"] = _mask_target(sample)
    item["chosen_action_index"] = _chosen_action_index(sample, ranking.actions)
    return item


def _world_to_ranking_sample(sample: PolicyWorldTrainingSample) -> PolicyGraphTrainingSample:
    if sample.ranking_sample is not None:
        return sample.ranking_sample
    graph = sample.masked_graph if sample.task == "masked_graph" and sample.masked_graph else sample.graph
    actions = list(sample.actions)
    if sample.chosen_action is not None and not actions:
        actions = [sample.chosen_action]
    if not actions:
        actions = [PolicyAction(action_type="stop", action_id="stop")]
    return PolicyGraphTrainingSample(
        sample_id=sample.sample_id,
        format=sample.format,
        graph=graph,
        current_node_id=sample.current_node_id or str(graph.get("current_node_id") or ""),
        best_node_id=sample.best_node_id or str(graph.get("best_node_id") or ""),
        actions=actions,
        current_recovery=_current_recovery(graph, sample.current_node_id),
        best_recovery=_best_recovery(graph, sample.best_node_id),
        source=sample.source,
    )


def _transition_target(sample: PolicyWorldTrainingSample):
    require_torch()
    import torch

    delta = sample.observed_delta if isinstance(sample.observed_delta, dict) else {}
    current = _current_node(sample.graph_after)
    recovery = current.get("recovery") if isinstance(current.get("recovery"), dict) else {}
    verification = current.get("verification") if isinstance(current.get("verification"), dict) else {}
    summary = verification.get("summary") if isinstance(verification.get("summary"), dict) else verification
    diagnosis = current.get("diagnosis_hgt") if isinstance(current.get("diagnosis_hgt"), dict) else {}
    root_scores = _root_case_score_vector(diagnosis)
    values = [
        _float(delta.get("next_recovery_score")),
        _float(delta.get("recovery_delta")),
        _hash_unit(delta.get("patch_status")),
        1.0 if delta.get("best_updated") else 0.0,
        _float(delta.get("branch_stale_delta")),
        _float(delta.get("diagnosis_root_case_delta")),
        *root_scores,
        _float(recovery.get("score")),
        _float(recovery.get("completeness", summary.get("completeness"))),
        _float(recovery.get("recovered_bytes")) / 1_000_000_000.0,
        _float(recovery.get("complete_files", summary.get("complete_files"))) / 1024.0,
        _float(recovery.get("failed_files", summary.get("failed_files"))) / 1024.0,
        _float(recovery.get("missing_files", summary.get("missing_files"))) / 1024.0,
        _float(recovery.get("partial_files", summary.get("partial_files"))) / 1024.0,
        _hash_unit(recovery.get("status", summary.get("assessment_status"))),
        _hash_unit(recovery.get("decision_hint", summary.get("decision_hint"))),
        _hash_unit(current.get("patch_status")),
        1.0 if str(current.get("patch_status") or "") == "empty_failed" else 0.0,
    ]
    return torch.tensor(values, dtype=torch.float32)


def _mask_target(sample: PolicyWorldTrainingSample):
    require_torch()
    import torch

    targets = sample.mask_targets if isinstance(sample.mask_targets, dict) else {}
    return torch.tensor([
        _float(targets.get("recovery_score")),
        _hash_unit(targets.get("patch_status")),
        _float(targets.get("diagnosis_max_score")),
        1.0 if targets.get("is_best_node") else 0.0,
    ], dtype=torch.float32)


def _uncertainty_target(sample: PolicyWorldTrainingSample):
    require_torch()
    import torch

    current = _current_node(sample.graph_after)
    uncertainty = current.get("uncertainty") if isinstance(current.get("uncertainty"), dict) else {}
    incoming = _incoming_edge_to_current(sample.graph_after)
    edge_uncertainty = incoming.get("uncertainty") if isinstance(incoming.get("uncertainty"), dict) else {}
    value = _float(uncertainty.get("overall_uncertainty", edge_uncertainty.get("overall_uncertainty")))
    if value <= 0.0:
        error = current.get("prediction_error_from_parent") if isinstance(current.get("prediction_error_from_parent"), dict) else {}
        value = _float(error.get("overall_prediction_error"))
    return torch.tensor([_clamp01(value)], dtype=torch.float32)


def _chosen_action_index(sample: PolicyWorldTrainingSample, actions: list[PolicyAction]):
    if sample.chosen_action is None:
        return -1
    for index, action in enumerate(actions):
        if action.action_id == sample.chosen_action.action_id or (action.action_type == sample.chosen_action.action_type and action.module_name == sample.chosen_action.module_name):
            return index
    return -1


def _current_node(graph: dict[str, Any], current_node_id: str = "") -> dict[str, Any]:
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    node = nodes.get(current_node_id or graph.get("current_node_id")) if isinstance(nodes, dict) else {}
    return dict(node or {}) if isinstance(node, dict) else {}


def _incoming_edge_to_current(graph: dict[str, Any]) -> dict[str, Any]:
    current_id = str(graph.get("current_node_id") or "")
    edges = graph.get("edges") if isinstance(graph.get("edges"), dict) else {}
    for edge in edges.values():
        if isinstance(edge, dict) and str(edge.get("to_node_id") or "") == current_id:
            return dict(edge)
    return {}


def _current_recovery(graph: dict[str, Any], current_node_id: str) -> dict[str, Any]:
    node = _current_node(graph, current_node_id)
    return dict(node.get("recovery") or {}) if isinstance(node, dict) else {}


def _best_recovery(graph: dict[str, Any], best_node_id: str) -> dict[str, Any]:
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    node = nodes.get(best_node_id or graph.get("best_node_id")) if isinstance(nodes, dict) else {}
    return dict(node.get("recovery") or {}) if isinstance(node, dict) else {}


def _nodes(graph: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    raw = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    return [(str(node_id), dict(node or {})) for node_id, node in sorted(raw.items()) if isinstance(node, dict)]


def _edges(graph: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    raw = graph.get("edges") if isinstance(graph.get("edges"), dict) else {}
    return [(str(edge_id), dict(edge or {})) for edge_id, edge in sorted(raw.items()) if isinstance(edge, dict)]


def _graph_context(graph: dict[str, Any], sample: PolicyGraphTrainingSample) -> dict[str, Any]:
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    edges = graph.get("edges") if isinstance(graph.get("edges"), dict) else {}
    parent: dict[str, str] = {}
    children: dict[str, list[str]] = {}
    by_id: dict[str, dict[str, Any]] = {}
    for node_id, node in nodes.items():
        if not isinstance(node, dict):
            continue
        node_id = str(node_id)
        by_id[node_id] = node
        parent_id = str(node.get("parent_id") or "")
        parent[node_id] = parent_id
        if parent_id:
            children.setdefault(parent_id, []).append(node_id)
    current_path = set()
    node_id = sample.current_node_id
    distance_from_current: dict[str, int] = {}
    distance = 0
    while node_id and node_id in by_id:
        current_path.add(node_id)
        distance_from_current[node_id] = distance
        node_id = parent.get(node_id, "")
        distance += 1
    subtree_best: dict[str, float] = {}
    for node_id in by_id:
        stack = [node_id]
        best = 0.0
        while stack:
            item = stack.pop()
            node = by_id.get(item) or {}
            recovery = node.get("recovery") if isinstance(node.get("recovery"), dict) else {}
            best = max(best, _float(recovery.get("score")))
            stack.extend(children.get(item, []))
        subtree_best[node_id] = best
    best_updated_nodes = set()
    for edge in edges.values():
        if not isinstance(edge, dict):
            continue
        if _float(edge.get("recovery_delta")) > 0.0 or edge.get("best_updated"):
            best_updated_nodes.add(str(edge.get("to_node_id") or ""))
    return {
        "parent": parent,
        "current_path": current_path,
        "distance_from_current": distance_from_current,
        "subtree_best": subtree_best,
        "best_updated_nodes": best_updated_nodes,
        "nodes": by_id,
    }


def _node_features(node_id: str, node: dict[str, Any], sample: PolicyGraphTrainingSample, graph_context: dict[str, Any]) -> list[float]:
    recovery = node.get("recovery") if isinstance(node.get("recovery"), dict) else {}
    verification = node.get("verification") if isinstance(node.get("verification"), dict) else {}
    summary = verification.get("summary") if isinstance(verification.get("summary"), dict) else {}
    diagnosis = node.get("diagnosis_hgt") if isinstance(node.get("diagnosis_hgt"), dict) else {}
    if node_id == sample.current_node_id and not diagnosis:
        diagnosis = sample.diagnosis_hgt
    diagnosis_stats = _diagnosis_root_stats(diagnosis)
    parent_id = str(node.get("parent_id") or "")
    parent_node = (graph_context.get("nodes") or {}).get(parent_id) if parent_id else None
    parent_recovery = parent_node.get("recovery") if isinstance(parent_node, dict) and isinstance(parent_node.get("recovery"), dict) else {}
    score = _float(recovery.get("score"))
    distance = int((graph_context.get("distance_from_current") or {}).get(node_id, 64))
    is_on_current_branch = node_id in (graph_context.get("current_path") or set())
    exploration = node.get("exploration") if isinstance(node.get("exploration"), dict) else {}
    uncertainty = node.get("uncertainty") if isinstance(node.get("uncertainty"), dict) else {}
    return [
        score,
        _float(recovery.get("completeness", summary.get("completeness"))),
        _float(node.get("patch_depth")),
        _float(node.get("created_step", node.get("created_round"))),
        1.0 if node_id == sample.current_node_id else 0.0,
        1.0 if node_id == sample.best_node_id else 0.0,
        _hash_unit(node.get("module_name")),
        _hash_unit(node.get("patch_status")),
        1.0 if str(node.get("patch_status") or "") == "empty_failed" else 0.0,
        len(node.get("expanded_candidate_ids") or []) / 32.0,
        _float(exploration.get("visit_count")) / 64.0,
        _float(exploration.get("outgoing_action_count")) / 64.0,
        _float(exploration.get("expanded_action_count")) / 64.0,
        _float(exploration.get("failed_action_count")) / 64.0,
        _float(exploration.get("reopened_action_count")) / 64.0,
        _float(exploration.get("fresh_action_count")) / 64.0,
        _float(exploration.get("exhaustion_ratio")),
        _float(exploration.get("steps_since_subtree_best_update")) / 64.0,
        _hash_unit(node.get("failure_reason")),
        _hash_unit(node_id),
        diagnosis_stats["max_score"],
        diagnosis_stats["mean_top3"],
        diagnosis_stats["selected_count"],
        _hash_unit(diagnosis_stats["top_root"]),
        diagnosis_stats["evidence_max_score"],
        diagnosis_stats["evidence_mean_top3"],
        _hash_unit(diagnosis_stats["evidence_top_root"]),
        diagnosis_stats["gain_max_score"],
        diagnosis_stats["gain_mean_top3"],
        _hash_unit(diagnosis_stats["gain_top_root"]),
        diagnosis_stats["viability_max_score"],
        diagnosis_stats["viability_mean_top3"],
        _hash_unit(diagnosis_stats["viability_top_root"]),
        diagnosis_stats["direct_gain_top_match"],
        diagnosis_stats["direct_viability_top_match"],
        diagnosis_stats["gain_viability_top_match"],
        1.0 if node_id in (graph_context.get("best_updated_nodes") or set()) else 0.0,
        score - _float(parent_recovery.get("score")),
        _float((graph_context.get("subtree_best") or {}).get(node_id)),
        _float(node.get("branch_failed_streak")) / 16.0,
        min(distance, 64) / 64.0,
        1.0 if is_on_current_branch else 0.0,
        1.0 if is_on_current_branch and node_id != sample.current_node_id else 0.0,
        _prediction_error_value(node, "overall_prediction_error"),
        _prediction_error_value(node, "recovery_abs_error"),
        _prediction_error_value(node, "diagnosis_root_l1"),
        _prediction_error_value(node, "patch_status_mismatch"),
        _float(uncertainty.get("overall_uncertainty")),
        _float(uncertainty.get("diagnosis_entropy")),
        _float(uncertainty.get("verification_ambiguity")),
        _float(uncertainty.get("prediction_uncertainty")),
        _float(uncertainty.get("exploration_uncertainty")),
        _branch_continuation_score(node, parent_node if isinstance(parent_node, dict) else {}),
        max(0.0, score - _float(parent_recovery.get("score"))),
        1.0 if str(node.get("patch_status") or "") == "applied" and _float(exploration.get("fresh_action_count")) > 0 else 0.0,
    ]


def _edge_features(edge: dict[str, Any], sample: PolicyGraphTrainingSample) -> list[float]:
    predicted = edge.get("predicted_next_state") if isinstance(edge.get("predicted_next_state"), dict) else {}
    predicted_recovery = predicted.get("predicted_recovery") if isinstance(predicted.get("predicted_recovery"), dict) else {}
    error = edge.get("prediction_error") if isinstance(edge.get("prediction_error"), dict) else {}
    exploration = edge.get("exploration") if isinstance(edge.get("exploration"), dict) else {}
    uncertainty = edge.get("uncertainty") if isinstance(edge.get("uncertainty"), dict) else {}
    return [
        _hash_unit(edge.get("module_name")),
        _hash_unit(edge.get("module_family", edge.get("route_family"))),
        _float(edge.get("recovery_delta")),
        _hash_unit(edge.get("patch_status")),
        1.0 if str(edge.get("patch_status") or edge.get("status") or "") in {"empty_failed", "expanded_failed"} else 0.0,
        1.0 if edge.get("best_updated") else 0.0,
        _float(predicted_recovery.get("score")),
        _float(predicted.get("predicted_recovery_delta")),
        _float(error.get("overall_prediction_error")),
        1.0 if error else 0.0,
        _float(exploration.get("attempt_count")) / 16.0,
        _float(exploration.get("undo_count_after_attempt")) / 16.0,
        1.0 if exploration.get("reopened_after_exhaustion") else 0.0,
        _float(exploration.get("result_recovery_delta")),
        _float(exploration.get("prediction_error_after_attempt")),
        _float(uncertainty.get("overall_uncertainty")),
        _float(uncertainty.get("transition_prediction_entropy")),
        _float(uncertainty.get("prediction_error_uncertainty")),
        _float(uncertainty.get("result_ambiguity")),
    ]


def _action_context(sample: PolicyGraphTrainingSample) -> dict[str, Any]:
    current = (sample.graph.get("nodes") or {}).get(sample.current_node_id, {}) if isinstance(sample.graph.get("nodes"), dict) else {}
    current_exploration = current.get("exploration") if isinstance(current, dict) and isinstance(current.get("exploration"), dict) else {}
    current_uncertainty = current.get("uncertainty") if isinstance(current, dict) and isinstance(current.get("uncertainty"), dict) else {}
    nodes = sample.graph.get("nodes") if isinstance(sample.graph.get("nodes"), dict) else {}
    parent = nodes.get(str(current.get("parent_id") or "")) if isinstance(current, dict) and isinstance(nodes, dict) else {}
    parent_exploration = parent.get("exploration") if isinstance(parent, dict) and isinstance(parent.get("exploration"), dict) else {}
    parent_exhausted = _float(parent_exploration.get("exhaustion_ratio")) >= 1.0
    incoming_module, incoming_family = _incoming_module_family(sample.graph, sample.current_node_id)
    action_edges: dict[str, dict[str, Any]] = {}
    for _edge_id, edge in _edges(sample.graph):
        if str(edge.get("from_node_id") or "") == sample.current_node_id and str(edge.get("candidate_id") or ""):
            action_edges[str(edge.get("candidate_id"))] = edge
    recent_family_failures: dict[str, int] = {}
    family_best_delta: dict[str, float] = {}
    family_prediction_error: dict[str, list[float]] = {}
    family_uncertainty: dict[str, list[float]] = {}
    tried_module_counts: dict[str, int] = {}
    tried_family_counts: dict[str, int] = {}
    module_history = _module_history_stats(sample.graph)
    for item in sample.memory[-32:]:
        action = item.get("graph_action") if isinstance(item.get("graph_action"), dict) else item
        family = str(action.get("module_family") or action.get("route_family") or action.get("module_name") or "")
        if not family:
            continue
        delta = _float(item.get("recovery_delta"))
        if delta <= 0.0 and not item.get("best_updated"):
            recent_family_failures[family] = recent_family_failures.get(family, 0) + 1
        family_best_delta[family] = max(family_best_delta.get(family, -1.0), delta)
        err = item.get("prediction_error") if isinstance(item.get("prediction_error"), dict) else {}
        if err:
            family_prediction_error.setdefault(family, []).append(_float(err.get("overall_prediction_error")))
        uncertainty = item.get("uncertainty") if isinstance(item.get("uncertainty"), dict) else {}
        if uncertainty:
            family_uncertainty.setdefault(family, []).append(_float(uncertainty.get("overall_uncertainty")))
    for _edge_id, edge in _edges(sample.graph):
        if str(edge.get("from_node_id") or "") == sample.current_node_id:
            exploration = edge.get("exploration") if isinstance(edge.get("exploration"), dict) else {}
            attempted = _float(exploration.get("attempt_count")) > 0.0 or str(edge.get("status") or "") in {"expanded", "expanded_failed", "repeated"}
            if attempted:
                module = str(edge.get("module_name") or "")
                family = str(edge.get("module_family") or edge.get("route_family") or module)
                if module:
                    tried_module_counts[module] = tried_module_counts.get(module, 0) + 1
                if family:
                    tried_family_counts[family] = tried_family_counts.get(family, 0) + 1
        family = str(edge.get("module_family") or edge.get("route_family") or edge.get("module_name") or "")
        err = edge.get("prediction_error") if isinstance(edge.get("prediction_error"), dict) else {}
        if family and err:
            family_prediction_error.setdefault(family, []).append(_float(err.get("overall_prediction_error")))
        uncertainty = edge.get("uncertainty") if isinstance(edge.get("uncertainty"), dict) else {}
        if family and uncertainty:
            family_uncertainty.setdefault(family, []).append(_float(uncertainty.get("overall_uncertainty")))
    return {
        "current_exploration": current_exploration,
        "current_uncertainty": current_uncertainty,
        "action_edges": action_edges,
        "parent_exhausted": parent_exhausted,
        "recent_family_failures": recent_family_failures,
        "family_best_delta": family_best_delta,
        "family_prediction_error": {key: sum(values) / max(1, len(values)) for key, values in family_prediction_error.items()},
        "family_uncertainty": {key: sum(values) / max(1, len(values)) for key, values in family_uncertainty.items()},
        "incoming_module": incoming_module,
        "incoming_family": incoming_family,
        "branch_continuation_score": _branch_continuation_score(current if isinstance(current, dict) else {}, parent if isinstance(parent, dict) else {}),
        "tried_module_counts": tried_module_counts,
        "tried_family_counts": tried_family_counts,
        "module_history": module_history,
    }


def _action_features(action: Any, index: int, action_context: dict[str, Any]) -> list[float]:
    family = str(action.features.get("module_family") or action.features.get("route_family") or action.module_name or "")
    current_exploration = action_context.get("current_exploration") or {}
    edge = (action_context.get("action_edges") or {}).get(action.action_id) or {}
    edge_exploration = edge.get("exploration") if isinstance(edge.get("exploration"), dict) else {}
    edge_uncertainty = edge.get("uncertainty") if isinstance(edge.get("uncertainty"), dict) else {}
    current_uncertainty = action_context.get("current_uncertainty") or {}
    attempt_count = _float(edge_exploration.get("attempt_count"))
    current_fresh_count = _float(current_exploration.get("fresh_action_count"))
    action_is_fresh = action.action_type == "module" and attempt_count <= 0.0
    reopened = bool(edge_exploration.get("reopened_after_exhaustion"))
    incoming_module = str(action_context.get("incoming_module") or "")
    incoming_family = str(action_context.get("incoming_family") or "")
    same_incoming_module = action.action_type == "module" and incoming_module and action.module_name == incoming_module
    same_incoming_family = action.action_type == "module" and incoming_family and family == incoming_family
    branch_continuation = _float(action_context.get("branch_continuation_score"))
    if branch_continuation <= 0.0:
        branch_continuation = _float(action.features.get("branch_continuation_score"))
    tried_module_count = _float((action_context.get("tried_module_counts") or {}).get(action.module_name))
    tried_family_count = _float((action_context.get("tried_family_counts") or {}).get(family))
    module_history = action_context.get("module_history") if isinstance(action_context.get("module_history"), dict) else {}
    exact_history = module_history.get("module", {}).get(action.module_name, {}) if isinstance(module_history.get("module"), dict) else {}
    family_history = module_history.get("family", {}).get(family, {}) if isinstance(module_history.get("family"), dict) else {}
    return [
        1.0 if action.action_type == "stop" else 0.0,
        1.0 if action.action_type == "undo" else 0.0,
        1.0 if action.action_type == "module" else 0.0,
        _hash_unit(action.module_name),
        _hash_unit(action.action_id),
        _float(action.features.get("confidence")),
        _float(action.features.get("score_hint")),
        _float(action.features.get("patch_depth")),
        _float(action.features.get("generation_priority")),
        _float(action.score),
        _float(action.action_prior),
        index / 128.0,
        _hash_unit(family),
        0.0,
        0.0,
        1.0 if family and int((action_context.get("recent_family_failures") or {}).get(family, 0)) > 0 else 0.0,
        1.0 if attempt_count > 0.0 else 0.0,
        min(attempt_count, 16.0) / 16.0,
        1.0 if action_is_fresh else 0.0,
        1.0 if reopened else 0.0,
        min(current_fresh_count, 64.0) / 64.0,
        _float(current_exploration.get("exhaustion_ratio")),
        1.0 if action.action_type == "undo" and action_context.get("parent_exhausted") else 0.0,
        min(float((action_context.get("recent_family_failures") or {}).get(family, 0)), 16.0) / 16.0,
        _float((action_context.get("family_best_delta") or {}).get(family)),
        1.0 if _float((action_context.get("family_prediction_error") or {}).get(family)) > 0.25 else 0.0,
        _float((action_context.get("family_prediction_error") or {}).get(family)),
        _float(edge_uncertainty.get("overall_uncertainty")),
        _float(current_uncertainty.get("overall_uncertainty")),
        1.0 if _float((action_context.get("family_uncertainty") or {}).get(family)) > 0.35 else 0.0,
        _float((action_context.get("family_uncertainty") or {}).get(family)),
        _float(edge_uncertainty.get("result_ambiguity")),
        1.0 if same_incoming_module else 0.0,
        1.0 if same_incoming_family else 0.0,
        _hash_unit(incoming_module),
        _hash_unit(incoming_family),
        branch_continuation,
        1.0 if action.action_type == "module" and branch_continuation > 0.08 else 0.0,
        1.0 if action.action_type == "undo" and branch_continuation > 0.08 else 0.0,
        _float(action.features.get("post_undo_continue_module_bonus")),
        _float(action.features.get("post_undo_repeat_undo_penalty")),
        _float(action.features.get("post_module_deepen_bonus")),
        _float(action.features.get("post_module_immediate_undo_penalty")),
        min(tried_module_count, 16.0) / 16.0,
        min(tried_family_count, 16.0) / 16.0,
        _float(action.features.get("current_node_retried_module_penalty")),
        _float(action.features.get("current_node_retried_family_penalty")),
        min(_float(exact_history.get("attempts")), 64.0) / 64.0,
        _float(exact_history.get("mean_delta")),
        _float(exact_history.get("failure_rate")),
        _float(exact_history.get("undo_rate")),
        min(_float(family_history.get("attempts")), 64.0) / 64.0,
        _float(family_history.get("mean_delta")),
        _float(action.features.get("module_history_no_gain_penalty")),
    ]


def _sample_branch_continuation_score(sample: PolicyGraphTrainingSample) -> float:
    nodes = sample.graph.get("nodes") if isinstance(sample.graph.get("nodes"), dict) else {}
    current = nodes.get(sample.current_node_id) if isinstance(nodes.get(sample.current_node_id), dict) else {}
    parent = nodes.get(str(current.get("parent_id") or "")) if isinstance(current, dict) and isinstance(nodes, dict) else {}
    score = _branch_continuation_score(current if isinstance(current, dict) else {}, parent if isinstance(parent, dict) else {})
    action_score = max((_float(action.features.get("branch_continuation_score")) for action in sample.actions), default=0.0)
    return max(score, action_score)


def _action_continue_target(action: Any, continue_branch: bool) -> float:
    if not continue_branch:
        return 0.0
    if action.action_type == "module":
        return 1.0
    if action.action_type == "undo":
        return 0.0
    return 0.0


def _action_continue_mask(action: Any, continue_branch: bool) -> float:
    if not continue_branch:
        return 0.0
    return 1.0 if action.action_type in {"module", "undo"} else 0.0


def _incoming_module_family(graph: dict[str, Any], current_node_id: str) -> tuple[str, str]:
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    current = nodes.get(current_node_id) if isinstance(nodes.get(current_node_id), dict) else {}
    parent_id = str(current.get("parent_id") or "") if isinstance(current, dict) else ""
    if not current_node_id or not parent_id:
        return "", ""
    for _edge_id, edge in _edges(graph):
        if str(edge.get("from_node_id") or "") == parent_id and str(edge.get("to_node_id") or "") == current_node_id:
            module = str(edge.get("module_name") or "")
            return module, str(edge.get("module_family") or module)
    module = str(current.get("module_name") or "") if isinstance(current, dict) else ""
    return module, module


def _module_history_stats(graph: dict[str, Any]) -> dict[str, dict[str, dict[str, float]]]:
    module_raw: dict[str, dict[str, float]] = {}
    family_raw: dict[str, dict[str, float]] = {}
    for _edge_id, edge in _edges(graph):
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
    return {
        "module": {key: _finalize_history(value) for key, value in module_raw.items()},
        "family": {key: _finalize_history(value) for key, value in family_raw.items()},
    }


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


def _action_uncertainty(action: Any, action_context: dict[str, Any]) -> float:
    family = str(action.features.get("module_family") or action.features.get("route_family") or action.module_name or "")
    edge = (action_context.get("action_edges") or {}).get(action.action_id) or {}
    edge_uncertainty = edge.get("uncertainty") if isinstance(edge.get("uncertainty"), dict) else {}
    current_uncertainty = action_context.get("current_uncertainty") or {}
    family_uncertainty = (action_context.get("family_uncertainty") or {}).get(family)
    values = [
        _float(edge_uncertainty.get("overall_uncertainty")),
        _float(current_uncertainty.get("overall_uncertainty")),
        _float(family_uncertainty),
    ]
    return _clamp01(max(values))


def _memory_features(item: dict[str, Any], index: int) -> list[float]:
    action = item.get("graph_action") if isinstance(item.get("graph_action"), dict) else item
    recovery = item.get("current_recovery") if isinstance(item.get("current_recovery"), dict) else {}
    return [
        _hash_unit(action.get("action_type")),
        1.0 if str(action.get("action_type") or "") == "stop" else 0.0,
        1.0 if str(action.get("action_type") or "") == "undo" else 0.0,
        1.0 if str(action.get("action_type") or "") == "module" else 0.0,
        _hash_unit(action.get("module_name")),
        _float(recovery.get("score")),
        _float(item.get("patch_depth")),
        _float(item.get("round")),
        index / 64.0,
        _hash_unit(action.get("reason")),
        _float(item.get("recovery_delta")),
        1.0 if item.get("best_updated") else 0.0,
        _float(item.get("branch_failed_streak")) / 16.0,
        _float(item.get("distance_from_best_node")) / 16.0,
        _prediction_error_value(item, "overall_prediction_error"),
        _prediction_error_value(item, "recovery_abs_error"),
        _prediction_error_value(item, "diagnosis_root_l1"),
    ]


def _branch_continuation_score(node: dict[str, Any], parent: dict[str, Any]) -> float:
    recovery = node.get("recovery") if isinstance(node.get("recovery"), dict) else {}
    parent_recovery = parent.get("recovery") if isinstance(parent.get("recovery"), dict) else {}
    exploration = node.get("exploration") if isinstance(node.get("exploration"), dict) else {}
    uncertainty = node.get("uncertainty") if isinstance(node.get("uncertainty"), dict) else {}
    error = node.get("prediction_error_from_parent") if isinstance(node.get("prediction_error_from_parent"), dict) else {}
    diagnosis = node.get("diagnosis_hgt") if isinstance(node.get("diagnosis_hgt"), dict) else {}
    parent_diagnosis = parent.get("diagnosis_hgt") if isinstance(parent.get("diagnosis_hgt"), dict) else {}
    recovery_delta = _float(recovery.get("score")) - _float(parent_recovery.get("score"))
    diagnosis_gain = _diagnosis_root_stats(diagnosis)["max_score"] - _diagnosis_root_stats(parent_diagnosis)["max_score"]
    prediction_error = _float(error.get("overall_prediction_error"))
    patch_status = str(node.get("patch_status") or "")
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


def _diagnosis_root_stats(diagnosis: dict[str, Any]) -> dict[str, Any]:
    root = diagnosis.get("root_case") if isinstance(diagnosis.get("root_case"), dict) else {}
    scores = root.get("scores") if isinstance(root.get("scores"), dict) else diagnosis.get("root_case_scores")
    primary = _score_stats(scores if isinstance(scores, dict) else {})
    selected = root.get("selected") if isinstance(root.get("selected"), list) else diagnosis.get("selected_root_cases")
    diagnostics = diagnosis.get("diagnostics") if isinstance(diagnosis.get("diagnostics"), dict) else {}
    evidence = _score_stats(diagnostics.get("root_evidence_scores") if isinstance(diagnostics.get("root_evidence_scores"), dict) else {})
    gain = _score_stats(diagnostics.get("root_transition_gain") if isinstance(diagnostics.get("root_transition_gain"), dict) else {})
    viability = _score_stats(diagnostics.get("root_probe_viability") if isinstance(diagnostics.get("root_probe_viability"), dict) else {})
    return {
        "max_score": primary["max_score"],
        "mean_top3": primary["mean_top3"],
        "selected_count": len(selected or []) / 16.0,
        "top_root": primary["top_root"],
        "selected_roots": [str(item) for item in selected or [] if str(item)],
        "evidence_max_score": evidence["max_score"],
        "evidence_mean_top3": evidence["mean_top3"],
        "evidence_top_root": evidence["top_root"],
        "gain_max_score": gain["max_score"],
        "gain_mean_top3": gain["mean_top3"],
        "gain_top_root": gain["top_root"],
        "viability_max_score": viability["max_score"],
        "viability_mean_top3": viability["mean_top3"],
        "viability_top_root": viability["top_root"],
        "direct_gain_top_match": 1.0 if primary["top_root"] and primary["top_root"] == gain["top_root"] else 0.0,
        "direct_viability_top_match": 1.0 if primary["top_root"] and primary["top_root"] == viability["top_root"] else 0.0,
        "gain_viability_top_match": 1.0 if gain["top_root"] and gain["top_root"] == viability["top_root"] else 0.0,
    }


def _score_stats(scores: dict[str, Any]) -> dict[str, Any]:
    parsed = [(str(key), _float(value)) for key, value in scores.items() if str(key) in ROOT_CASES]
    parsed.sort(key=lambda item: item[1], reverse=True)
    top = parsed[:3]
    return {
        "max_score": top[0][1] if top else 0.0,
        "mean_top3": sum(value for _key, value in top) / max(1, len(top)),
        "top_root": top[0][0] if top else "",
    }


def _root_case_score_vector(diagnosis: dict[str, Any]) -> list[float]:
    root = diagnosis.get("root_case") if isinstance(diagnosis.get("root_case"), dict) else {}
    scores = root.get("scores") if isinstance(root.get("scores"), dict) else diagnosis.get("root_case_scores")
    scores = scores if isinstance(scores, dict) else {}
    return [_clamp01(_float(scores.get(label))) for label in ROOT_CASES]


def _prediction_error_value(payload: dict[str, Any], key: str) -> float:
    error = payload.get("prediction_error_from_parent") if isinstance(payload.get("prediction_error_from_parent"), dict) else None
    if error is None:
        error = payload.get("prediction_error") if isinstance(payload.get("prediction_error"), dict) else {}
    return _float((error or {}).get(key))


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))
