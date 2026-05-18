from __future__ import annotations

import hashlib
from typing import Any

from repair_training.core.repair_policy_transformer.schema import PolicyGraphTrainingSample


NODE_FEATURE_DIM = 16
ACTION_FEATURE_DIM = 12
MEMORY_FEATURE_DIM = 10


def require_torch():
    try:
        import torch  # noqa: F401
    except Exception as exc:  # pragma: no cover
        raise SystemExit("RepairPolicyTransformer requires torch. Install repair_training/requirements-training.txt.") from exc


def tensorize_sample(sample: PolicyGraphTrainingSample) -> dict[str, Any]:
    require_torch()
    import torch

    nodes = _nodes(sample.graph)
    node_features = [_node_features(node_id, node, sample) for node_id, node in nodes]
    if not node_features:
        node_features = [[0.0] * NODE_FEATURE_DIM]
    actions = sample.actions
    action_features = [_action_features(action, index) for index, action in enumerate(actions)]
    if not action_features:
        action_features = [[0.0] * ACTION_FEATURE_DIM]
    memory_features = [_memory_features(item, index) for index, item in enumerate(sample.memory[-64:])]
    if not memory_features:
        memory_features = [[0.0] * MEMORY_FEATURE_DIM]
    q_values = [action.action_q_value for action in actions] or [0.0]
    priors = [action.action_prior for action in actions] or [0.0]
    return {
        "node_x": torch.tensor(node_features, dtype=torch.float32),
        "action_x": torch.tensor(action_features, dtype=torch.float32),
        "memory_x": torch.tensor(memory_features, dtype=torch.float32),
        "q": torch.tensor(q_values, dtype=torch.float32),
        "prior": torch.tensor(priors, dtype=torch.float32),
        "actions": [action.to_dict() for action in actions],
        "sample_id": sample.sample_id,
    }


def _nodes(graph: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    raw = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    return [(str(node_id), dict(node or {})) for node_id, node in sorted(raw.items()) if isinstance(node, dict)]


def _node_features(node_id: str, node: dict[str, Any], sample: PolicyGraphTrainingSample) -> list[float]:
    recovery = node.get("recovery") if isinstance(node.get("recovery"), dict) else {}
    verification = node.get("verification") if isinstance(node.get("verification"), dict) else {}
    summary = verification.get("summary") if isinstance(verification.get("summary"), dict) else {}
    diagnosis = node.get("diagnosis_hgt") if isinstance(node.get("diagnosis_hgt"), dict) else {}
    if node_id == sample.current_node_id and not diagnosis:
        diagnosis = sample.diagnosis_hgt
    diagnosis_stats = _diagnosis_root_stats(diagnosis)
    return [
        _float(recovery.get("score")),
        _float(recovery.get("completeness", summary.get("completeness"))),
        _float(node.get("patch_depth")),
        _float(node.get("created_step", node.get("created_round"))),
        1.0 if node_id == sample.current_node_id else 0.0,
        1.0 if node_id == sample.best_node_id else 0.0,
        _hash_unit(node.get("module_name")),
        _hash_unit(node.get("patch_status")),
        1.0 if str(node.get("patch_status") or "") == "empty_failed" else 0.0,
        len(node.get("expanded_candidate_ids") or []) / 32.0,
        _hash_unit(node.get("failure_reason")),
        _hash_unit(node_id),
        diagnosis_stats["max_score"],
        diagnosis_stats["mean_top3"],
        diagnosis_stats["selected_count"],
        _hash_unit(diagnosis_stats["top_root"]),
    ]


def _action_features(action: Any, index: int) -> list[float]:
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
    ]


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
    ]


def _diagnosis_root_stats(diagnosis: dict[str, Any]) -> dict[str, Any]:
    root = diagnosis.get("root_case") if isinstance(diagnosis.get("root_case"), dict) else {}
    scores = root.get("scores") if isinstance(root.get("scores"), dict) else diagnosis.get("root_case_scores")
    parsed = [(str(key), _float(value)) for key, value in (scores or {}).items()] if isinstance(scores, dict) else []
    parsed.sort(key=lambda item: item[1], reverse=True)
    selected = root.get("selected") if isinstance(root.get("selected"), list) else diagnosis.get("selected_root_cases")
    top = parsed[:3]
    return {
        "max_score": top[0][1] if top else 0.0,
        "mean_top3": sum(value for _key, value in top) / max(1, len(top)),
        "selected_count": len(selected or []) / 16.0,
        "top_root": top[0][0] if top else "",
    }


def _hash_unit(value: Any, *, buckets: int = 2048) -> float:
    text = str(value or "")
    if not text:
        return 0.0
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return (int(digest[:8], 16) % buckets) / float(buckets - 1)


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
