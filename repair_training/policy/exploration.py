from __future__ import annotations

from typing import Any

from sunpack.repair.model.policy.schema import PolicyAction


EXPLORATION_POLICIES = (
    "prior_biased", "deepening", "bad_branch", "undo_heavy",
    "family_coverage", "stop_probe", "teacher_guided",
)


def choose_action(actions: list[PolicyAction], policy: str, step: int, *, graph: dict[str, Any] | None = None) -> PolicyAction:
    previous_module, _previous_family = incoming_module_family(graph or {})
    modules = [action for action in actions if action.action_type == "module"]
    non_repeat_modules = [
        action for action in modules
        if not (previous_module and action.module_name == previous_module)
    ]
    if non_repeat_modules:
        modules = non_repeat_modules
    undo = next((action for action in actions if action.action_type == "undo"), None)
    stop = next((action for action in actions if action.action_type == "stop"), None)
    if policy == "undo_heavy" and undo is not None and step > 1 and step % 2 == 0:
        return undo
    if policy == "deepening" and modules:
        return modules[0]
    if policy == "stop_probe" and stop is not None and step >= 2:
        return stop
    if policy == "bad_branch" and modules:
        return modules[-1]
    if policy == "family_coverage" and modules:
        return modules[(step - 1) % len(modules)]
    if policy == "teacher_guided" and modules:
        return modules[0]
    if modules:
        return modules[0]
    return undo or stop or actions[0]

def incoming_module_family(graph: dict[str, Any]) -> tuple[str, str]:
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
            return str(edge.get("module_name") or ""), str(edge.get("module_family") or edge.get("module_name") or "")
    return str(current.get("module_name") or ""), str(current.get("module_name") or "")

def current_node_tried_modules(graph: dict[str, Any]) -> tuple[dict[str, int], dict[str, int]]:
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

def module_history_stats(graph: dict[str, Any]) -> tuple[dict[str, dict[str, float]], dict[str, dict[str, float]]]:
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

def history_penalty(stats: dict[str, float], *, exact: bool) -> float:
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

def _float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
