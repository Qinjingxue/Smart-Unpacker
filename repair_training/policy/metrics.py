from __future__ import annotations

from typing import Any


def top1_action_accuracy(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = 0
    hits = 0
    for row in rows:
        actions = row.get("action_scores") if isinstance(row.get("action_scores"), list) else []
        if not actions:
            continue
        total += 1
        best = max(actions, key=lambda item: float(item.get("score") or 0.0))
        hits += 1 if float(best.get("action_prior") or 0.0) >= 0.5 else 0
    return {"top1_action_prior_accuracy": hits / max(1, total), "samples": total}


def policy_teacher_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = 0
    premature_stop = 0
    promising_total = 0
    undo_cases = 0
    undo_hits = 0
    exploration_total = 0
    exploration_hits = 0
    regret_sum = 0.0
    spearman_values = []
    best_set_hits = 0
    entropy_values = []
    pred_modules = {}
    for row in rows:
        actions = row.get("action_scores") if isinstance(row.get("action_scores"), list) else row.get("actions")
        if not isinstance(actions, list) or not actions:
            continue
        scored = [action for action in actions if isinstance(action, dict)]
        if not scored:
            continue
        total += 1
        pred_best = max(scored, key=lambda item: float(item.get("score") or 0.0))
        module = str(pred_best.get("module_name") or pred_best.get("action_type") or "")
        pred_modules[module] = pred_modules.get(module, 0) + 1
        if pred_best.get("best_action_set_member"):
            best_set_hits += 1
        entropy_values.append(_entropy([float(item.get("score") or 0.0) for item in scored]))
        q_best = max(scored, key=lambda item: float(item.get("action_q_value") or item.get("q") or 0.0))
        regret_sum += max(0.0, float(q_best.get("action_q_value") or q_best.get("q") or 0.0) - float(pred_best.get("action_q_value") or pred_best.get("q") or 0.0))
        spearman_values.append(_spearman(scored))
        promising = bool(row.get("has_promising_future")) or float(row.get("stop_regret") or 0.0) > 0.0
        if promising:
            promising_total += 1
            if str(pred_best.get("action_type") or "") == "stop":
                premature_stop += 1
            exploration_total += 1
            top_k = sorted(scored, key=lambda item: float(item.get("score") or 0.0), reverse=True)[: min(3, len(scored))]
            if any(str(item.get("action_type") or "") != "stop" for item in top_k):
                exploration_hits += 1
        undo = next((item for item in scored if str(item.get("action_type") or "") == "undo"), None)
        modules = [item for item in scored if str(item.get("action_type") or "") == "module"]
        if undo is not None and modules:
            undo_q = float(undo.get("action_q_value") or undo.get("q") or 0.0)
            best_module_q = max(float(item.get("action_q_value") or item.get("q") or 0.0) for item in modules)
            if undo_q > best_module_q:
                undo_cases += 1
                if str(pred_best.get("action_type") or "") == "undo":
                    undo_hits += 1
    return {
        "samples": total,
        "premature_stop_rate": premature_stop / max(1, promising_total),
        "undo_top1_when_branch_bad": undo_hits / max(1, undo_cases),
        "exploration_recall": exploration_hits / max(1, exploration_total),
        "top1_q_regret": regret_sum / max(1, total),
        "action_q_spearman": sum(spearman_values) / max(1, len(spearman_values)),
        "promising_future_samples": promising_total,
        "undo_branch_bad_samples": undo_cases,
        "best_set_top1_hit": best_set_hits / max(1, total),
        "prediction_entropy": sum(entropy_values) / max(1, len(entropy_values)),
        "module_collapse_rate": (max(pred_modules.values()) / max(1, total)) if pred_modules else 0.0,
    }


def _spearman(actions: list[dict[str, Any]]) -> float:
    if len(actions) < 2:
        return 1.0
    pred_order = sorted(range(len(actions)), key=lambda i: float(actions[i].get("score") or 0.0))
    q_order = sorted(range(len(actions)), key=lambda i: float(actions[i].get("action_q_value") or actions[i].get("q") or 0.0))
    pred_rank = {index: rank for rank, index in enumerate(pred_order)}
    q_rank = {index: rank for rank, index in enumerate(q_order)}
    n = len(actions)
    diff_sum = sum((pred_rank[i] - q_rank[i]) ** 2 for i in range(n))
    return 1.0 - (6.0 * diff_sum) / max(1.0, n * (n * n - 1))


def _entropy(values: list[float]) -> float:
    import math

    total = sum(max(0.0, value) for value in values)
    if total <= 0.0:
        return 0.0
    entropy = 0.0
    for value in values:
        p = max(0.0, value) / total
        if p > 0.0:
            entropy -= p * math.log(p)
    return entropy
