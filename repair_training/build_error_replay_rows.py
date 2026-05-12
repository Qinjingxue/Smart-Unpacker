from __future__ import annotations

import argparse
import copy
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


BAD_TERMINAL_TOKENS = ("repeated_repair_input", "no_candidates", "unrepairable")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    graph_rows = _read_jsonl(Path(args.training_jsonl))
    ab_rows = _read_jsonl(Path(args.ab_jsonl))
    rows, summary = build_replay_rows(graph_rows, ab_rows)
    rows = _amplify_rows(
        rows,
        selected_repeat=max(1, int(args.selected_repeat)),
        positive_repeat=max(1, int(args.positive_repeat)),
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    summary.update(
        {
            "output": str(output),
            "replay_row_count": len(rows),
            "selected_repeat": max(1, int(args.selected_repeat)),
            "positive_repeat": max(1, int(args.positive_repeat)),
        }
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build DAgger-style replay rows from runtime A/B regressions.")
    parser.add_argument("--training-jsonl", required=True)
    parser.add_argument("--ab-jsonl", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--selected-repeat",
        type=int,
        default=1,
        help="Repeat model-selected penalty rows this many times in the replay output.",
    )
    parser.add_argument(
        "--positive-repeat",
        type=int,
        default=1,
        help="Repeat positive-control/better-alternative rows this many times in the replay output.",
    )
    return parser


def build_replay_rows(graph_rows: list[dict[str, Any]], ab_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    graph_index = _GraphIndex(graph_rows)
    paired: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in ab_rows:
        paired[str(row.get("sample_id") or "")][str(row.get("mode") or "")] = row

    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    summary = {
        "regression_sample_count": 0,
        "probe_replay_row_count": 0,
        "probe_replay_selected_count": 0,
        "probe_replay_better_alternative_count": 0,
        "probe_replay_positive_control_count": 0,
        "probe_replay_noop_positive_count": 0,
        "probe_replay_selector_module_positive_count": 0,
        "probe_replay_selector_path_module_positive_count": 0,
        "legacy_graph_replay_row_count": 0,
        "unmatched_selected_candidate_count": 0,
        "request_without_probe_count": 0,
    }

    for sample_id, modes in paired.items():
        baseline = modes.get("selector_baseline")
        model = modes.get("zip_model_policy")
        if not baseline or not model:
            continue
        model_recovery = _float(model.get("recovery_ratio"))
        selector_recovery = _float(baseline.get("recovery_ratio"))
        terminal = str(model.get("terminal_status") or "").lower()
        regression = (
            model_recovery < selector_recovery - 1e-9
            or model_recovery <= 0.0
            or any(token in terminal for token in BAD_TERMINAL_TOKENS)
        )
        if not regression:
            continue
        summary["regression_sample_count"] += 1
        selector_ids = _selected_candidate_ids_from_trace(baseline)
        selector_modules = _selector_modules(baseline)
        requests = _probe_requests(model)
        decisions = _probe_decisions(model)
        if requests:
            for request_index, request in enumerate(requests):
                round_index = _int(request.get("round"), request_index)
                decision = _matching_decision(decisions, request, request_index)
                selected_id = str(_nested(decision, "policy", "selected_candidate_id") or _nested(decision, "selected_candidate", "candidate_id") or "")
                if not selected_id:
                    selected_ids = _selected_candidate_ids_from_trace(model)
                    selected_id = selected_ids[round_index] if round_index < len(selected_ids) else ""
                request_rows = _rows_from_probe_request(
                    request,
                    graph_index,
                    sample_id=sample_id,
                    round_index=round_index,
                    selected_candidate_id=selected_id,
                    model_recovery=model_recovery,
                    model_terminal=str(model.get("terminal_status") or ""),
                    selector_recovery=selector_recovery,
                    selector_candidate_id=selector_ids[round_index] if round_index < len(selector_ids) else "",
                    selector_module=_selector_module_for_round(baseline, round_index),
                    selector_modules=selector_modules,
                )
                if selected_id and not any(row.get("candidate_id") == selected_id for row in request_rows):
                    summary["unmatched_selected_candidate_count"] += 1
                for row in request_rows:
                    if _append_unique(output, seen, row):
                        summary["probe_replay_row_count"] += 1
                        if _nested(row, "rl", "probe_replay_selected"):
                            summary["probe_replay_selected_count"] += 1
                        if _nested(row, "rl", "error_replay_better_alternative"):
                            summary["probe_replay_better_alternative_count"] += 1
                        if _nested(row, "rl", "probe_replay_positive_control"):
                            summary["probe_replay_positive_control_count"] += 1
                        if _nested(row, "rl", "probe_replay_noop_positive"):
                            summary["probe_replay_noop_positive_count"] += 1
                        if _nested(row, "rl", "probe_replay_selector_module_positive"):
                            summary["probe_replay_selector_module_positive_count"] += 1
                        if _nested(row, "rl", "probe_replay_selector_path_module_positive"):
                            summary["probe_replay_selector_path_module_positive_count"] += 1
            continue

        summary["request_without_probe_count"] += 1
        for row in _legacy_graph_replay_rows(graph_index, sample_id, baseline, model, model_recovery, selector_recovery):
            if _append_unique(output, seen, row):
                summary["legacy_graph_replay_row_count"] += 1

    return output, summary


class _GraphIndex:
    def __init__(self, rows: list[dict[str, Any]]):
        self.by_sample_round_candidate: dict[tuple[str, int, str], list[dict[str, Any]]] = defaultdict(list)
        self.by_sample_candidate: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        self.by_candidate_set_candidate: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        self.by_sample_round: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            sample_id = str(row.get("sample_id") or "")
            candidate_id = str(row.get("candidate_id") or "")
            candidate_set_hash = str(row.get("candidate_set_hash") or "")
            round_index = _int(row.get("round"), 0)
            if sample_id and candidate_id:
                self.by_sample_round_candidate[(sample_id, round_index, candidate_id)].append(row)
                self.by_sample_candidate[(sample_id, candidate_id)].append(row)
            if candidate_set_hash and candidate_id:
                self.by_candidate_set_candidate[(candidate_set_hash, candidate_id)].append(row)
            if sample_id:
                self.by_sample_round[(sample_id, round_index)].append(row)

    def best_match(self, *, sample_id: str, round_index: int, candidate_id: str, candidate_set_hash: str = "") -> dict[str, Any] | None:
        pools = [
            self.by_sample_round_candidate.get((sample_id, round_index, candidate_id), []),
            self.by_candidate_set_candidate.get((candidate_set_hash, candidate_id), []) if candidate_set_hash else [],
            self.by_sample_candidate.get((sample_id, candidate_id), []),
        ]
        for pool in pools:
            if pool:
                return max(pool, key=_graph_return)
        return None

    def best_round_alternative(self, *, sample_id: str, round_index: int, threshold: float) -> dict[str, Any] | None:
        rows = self.by_sample_round.get((sample_id, round_index), [])
        better = [row for row in rows if _graph_return(row) > threshold + 1e-9]
        if not better:
            return None
        return max(better, key=_graph_return)


def _rows_from_probe_request(
    request: dict[str, Any],
    graph_index: _GraphIndex,
    *,
    sample_id: str,
    round_index: int,
    selected_candidate_id: str,
    model_recovery: float,
    model_terminal: str,
    selector_recovery: float,
    selector_candidate_id: str,
    selector_module: str,
    selector_modules: set[str],
) -> list[dict[str, Any]]:
    payloads = request.get("candidate_payloads") if isinstance(request.get("candidate_payloads"), list) else []
    candidate_set_hash = str(request.get("candidate_set_hash") or "")
    output: list[dict[str, Any]] = []
    best_graph_row: dict[str, Any] | None = None
    for rank, payload in enumerate(payloads):
        if not isinstance(payload, dict):
            continue
        candidate_id = str(payload.get("candidate_id") or "")
        if not candidate_id:
            continue
        graph_match = graph_index.best_match(
            sample_id=sample_id,
            round_index=round_index,
            candidate_id=candidate_id,
            candidate_set_hash=candidate_set_hash,
        )
        if graph_match and (best_graph_row is None or _graph_return(graph_match) > _graph_return(best_graph_row)):
            best_graph_row = graph_match
        selected = candidate_id == selected_candidate_id
        selector_selected = bool(selector_candidate_id and candidate_id == selector_candidate_id)
        positive_reason = ""
        if not selector_selected and selector_recovery > model_recovery + 1e-9:
            module_name = str(payload.get("module_name") or payload.get("module") or "")
            if selector_module and module_name == selector_module:
                selector_selected = True
                positive_reason = "selector_module"
            elif module_name and module_name in selector_modules:
                selector_selected = True
                positive_reason = "selector_path_module"
            elif not selector_candidate_id and not selector_module and _is_noop_payload(payload):
                selector_selected = True
                positive_reason = "noop_accept_current_state"
        graph_value = _graph_return(graph_match) if graph_match else None
        if not selected and not selector_selected and graph_value is None:
            continue
        row = _probe_action_row(
            request,
            payload,
            sample_id=sample_id,
            round_index=round_index,
            rank=rank,
            selected=selected,
            selector_selected=selector_selected,
            positive_reason=positive_reason,
            model_recovery=model_recovery,
            model_terminal=model_terminal,
            selector_recovery=selector_recovery,
            graph_row=graph_match,
        )
        output.append(row)

    better = best_graph_row
    if better is None:
        better = graph_index.best_round_alternative(sample_id=sample_id, round_index=round_index, threshold=model_recovery)
    if better is not None and _graph_return(better) > model_recovery + 1e-9:
        replay = _clone_replay_row(better, suffix=f"probe_better:{round_index}:{better.get('candidate_id')}")
        rl = replay.setdefault("rl", {})
        rl["error_replay_better_alternative"] = True
        rl["probe_replay"] = True
        rl["selector_recovery_return"] = selector_recovery
        rl["sequence_terminal_status"] = "better_alternative"
        output.append(replay)
    return output


def _probe_action_row(
    request: dict[str, Any],
    payload: dict[str, Any],
    *,
    sample_id: str,
    round_index: int,
    rank: int,
    selected: bool,
    selector_selected: bool,
    positive_reason: str,
    model_recovery: float,
    model_terminal: str,
    selector_recovery: float,
    graph_row: dict[str, Any] | None,
) -> dict[str, Any]:
    candidate_id = str(payload.get("candidate_id") or "")
    candidate_set_hash = str(request.get("candidate_set_hash") or "")
    query_id = f"{sample_id}:probe_replay:{round_index}:{candidate_set_hash[:16]}"
    graph_value = _graph_return(graph_row) if graph_row else None
    target_recovery = model_recovery if selected else (selector_recovery if selector_selected else graph_value)
    rl: dict[str, Any] = {
        "probe_replay": True,
        "probe_replay_selected": bool(selected),
        "probe_replay_selector_selected": bool(selector_selected),
        "error_replay_better_root_alternative": False,
        "sequence_terminal_status": model_terminal if selected else ("selector_alternative" if selector_selected else "graph_alternative"),
        "sequence_zero_recovery": bool(selected and model_recovery <= 0.0),
        "sequence_repeated_input": bool(selected and "repeated_repair_input" in model_terminal.lower()),
        "sequence_no_candidate": bool(selected and ("no_candidates" in model_terminal.lower() or "unrepairable" in model_terminal.lower())),
    }
    if selected:
        rl["error_replay_penalty"] = True
        rl["policy_rollout_return"] = model_recovery
        rl["policy_rollout_terminal_status"] = model_terminal
    if selector_selected:
        rl["error_replay_better_alternative"] = selector_recovery > model_recovery + 1e-9
        rl["probe_replay_positive_control"] = selector_recovery > model_recovery + 1e-9
        if positive_reason:
            rl["probe_replay_positive_reason"] = positive_reason
        if positive_reason == "noop_accept_current_state":
            rl["probe_replay_noop_positive"] = True
        if positive_reason == "selector_module":
            rl["probe_replay_selector_module_positive"] = True
        if positive_reason == "selector_path_module":
            rl["probe_replay_selector_path_module_positive"] = True
        if round_index == 0 and selector_recovery > model_recovery + 1e-9:
            rl["error_replay_better_root_alternative"] = True
        rl["selector_recovery_return"] = selector_recovery
    if graph_value is not None:
        rl["future_return"] = graph_value
        rl["single_path_robust_return"] = graph_value
        rl["terminal_reward"] = graph_value
        if graph_value > model_recovery + 1e-9 and not selected:
            rl["error_replay_better_alternative"] = True
            if round_index == 0:
                rl["error_replay_better_root_alternative"] = True
    if target_recovery is not None:
        rl.setdefault("future_return", _clamp01(float(target_recovery)))
        rl.setdefault("single_path_robust_return", _clamp01(float(target_recovery)))
        rl.setdefault("terminal_reward", _clamp01(float(target_recovery)))
    return {
        "row_type": "action",
        "collector": "probe_error_replay",
        "sample_id": sample_id,
        "episode_id": sample_id,
        "state_id": str(request.get("query_id") or query_id),
        "root_state_id": str(request.get("query_id") or query_id),
        "parent_state_id": "",
        "query_id": query_id,
        "round": int(round_index),
        "path_depth": int(round_index),
        "action_row_id": f"{query_id}|{rank}|{candidate_id}:probe_replay",
        "candidate_id": candidate_id,
        "path_candidate_ids": [candidate_id] if round_index == 0 else [],
        "root_candidate_id": candidate_id if round_index == 0 else "",
        "root_candidate_rank": rank if round_index == 0 else None,
        "root_action": round_index == 0,
        "candidate_id_collision_count": int(request.get("candidate_id_collision_count", 0) or 0),
        "candidate_set_hash": candidate_set_hash,
        "strategy": "runtime_probe_replay",
        "current_rank": rank,
        "branchable": True,
        "explored": True,
        "selected": bool(selected),
        "material_format": str(payload.get("format") or request.get("format") or "zip"),
        "module": payload.get("module_name") or payload.get("module"),
        "module_name": payload.get("module_name") or payload.get("module"),
        "repair_name": payload.get("repair_name"),
        "native_key": payload.get("native_key"),
        "native_target": payload.get("native_target"),
        "candidate_status": payload.get("candidate_status"),
        "terminal_status": model_terminal if selected else "replay_alternative",
        "terminal_recovery_ratio": _clamp01(model_recovery if selected else float(target_recovery or 0.0)),
        "stable_features": {
            "runtime_context": payload.get("runtime_context") if isinstance(payload.get("runtime_context"), dict) else {},
            "candidate_proposal": payload.get("candidate_proposal") if isinstance(payload.get("candidate_proposal"), dict) else {},
            "candidate": payload,
        },
        "rl": rl,
    }


def _legacy_graph_replay_rows(
    graph_index: _GraphIndex,
    sample_id: str,
    baseline: dict[str, Any],
    model: dict[str, Any],
    model_recovery: float,
    selector_recovery: float,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    terminal = str(model.get("terminal_status") or "").lower()
    for round_index, candidate_id in enumerate(_selected_candidate_ids_from_trace(model)):
        source = graph_index.best_match(sample_id=sample_id, round_index=round_index, candidate_id=candidate_id)
        if source:
            replay = _clone_replay_row(source, suffix=f"wrong:{round_index}:{candidate_id}")
            rl = replay.setdefault("rl", {})
            rl["error_replay_penalty"] = True
            rl["policy_rollout_return"] = model_recovery
            rl["policy_rollout_terminal_status"] = model.get("terminal_status")
            rl["sequence_terminal_status"] = model.get("terminal_status")
            rl["sequence_zero_recovery"] = model_recovery <= 0.0
            rl["sequence_repeated_input"] = "repeated_repair_input" in terminal
            rl["sequence_no_candidate"] = "no_candidates" in terminal or "unrepairable" in terminal
            replay["terminal_recovery_ratio"] = model_recovery
            replay["terminal_status"] = model.get("terminal_status")
            output.append(replay)
        better = graph_index.best_round_alternative(sample_id=sample_id, round_index=round_index, threshold=model_recovery)
        if better:
            replay = _clone_replay_row(better, suffix=f"better:{round_index}:{better.get('candidate_id')}")
            rl = replay.setdefault("rl", {})
            rl["error_replay_better_alternative"] = True
            rl["selector_recovery_return"] = selector_recovery
            rl["sequence_terminal_status"] = "better_alternative"
            output.append(replay)
    return output


def _probe_requests(model_row: dict[str, Any]) -> list[dict[str, Any]]:
    return [event for event in _probe_events(model_row) if str(event.get("event") or "") == "policy_probe_request"]


def _probe_decisions(model_row: dict[str, Any]) -> list[dict[str, Any]]:
    return [event for event in _probe_events(model_row) if str(event.get("event") or "") == "policy_probe_decision"]


def _probe_events(model_row: dict[str, Any]) -> list[dict[str, Any]]:
    path = Path(str(model_row.get("probe_path") or ""))
    return _read_jsonl(path) if path.is_file() else []


def _matching_decision(decisions: list[dict[str, Any]], request: dict[str, Any], fallback_index: int) -> dict[str, Any]:
    query_id = str(request.get("query_id") or "")
    for decision in decisions:
        if query_id and str(decision.get("query_id") or "") == query_id:
            return decision
    return decisions[fallback_index] if fallback_index < len(decisions) else {}


def _selected_candidate_ids_from_trace(row: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    trace_path = Path(str(row.get("trace_path") or ""))
    if trace_path.is_file():
        for event in _read_jsonl(trace_path):
            if str(event.get("event") or "") != "repair_selected_result":
                continue
            selection = event.get("selection") if isinstance(event.get("selection"), dict) else {}
            policy = selection.get("policy") if isinstance(selection.get("policy"), dict) else {}
            candidate = event.get("candidate") if isinstance(event.get("candidate"), dict) else {}
            candidate_id = str(policy.get("selected_candidate_id") or candidate.get("candidate_id") or "")
            if candidate_id:
                ids.append(candidate_id)
        if ids:
            return ids
    for round_candidates in row.get("round_candidate_lists") or []:
        if isinstance(round_candidates, list):
            for candidate in round_candidates[:1]:
                if isinstance(candidate, dict) and candidate.get("candidate_id"):
                    ids.append(str(candidate.get("candidate_id")))
    return ids


def _selector_module_for_round(row: dict[str, Any], round_index: int) -> str:
    path = row.get("repair_module_path")
    if isinstance(path, list) and round_index < len(path):
        return str(path[round_index] or "")
    actions = row.get("repair_action_path")
    if isinstance(actions, list) and round_index < len(actions):
        item = actions[round_index]
        if isinstance(item, dict):
            return str(item.get("module_name") or item.get("module") or "")
        return str(item or "")
    return ""


def _selector_modules(row: dict[str, Any]) -> set[str]:
    modules: set[str] = set()
    path = row.get("repair_module_path")
    if isinstance(path, list):
        modules.update(str(item) for item in path if str(item or ""))
    actions = row.get("repair_action_path")
    if isinstance(actions, list):
        for item in actions:
            if isinstance(item, dict):
                module = str(item.get("module_name") or item.get("module") or "")
            else:
                module = str(item or "")
            if module:
                modules.add(module)
    return modules


def _is_noop_payload(payload: dict[str, Any]) -> bool:
    proposal = payload.get("candidate_proposal") if isinstance(payload.get("candidate_proposal"), dict) else {}
    return bool(
        payload.get("noop")
        or payload.get("control_action")
        or proposal.get("noop")
        or proposal.get("control_action")
        or str(payload.get("module_name") or payload.get("module") or "") == "repair_accept_current_state"
    )


def _clone_replay_row(row: dict[str, Any], *, suffix: str) -> dict[str, Any]:
    output = copy.deepcopy(row)
    output["row_type"] = "action"
    output["collector"] = "error_replay"
    output["action_row_id"] = f"{row.get('action_row_id')}:replay:{suffix}"
    output["query_id"] = f"{row.get('query_id')}:replay:{suffix}"
    output["selected"] = False
    output["explored"] = True
    return output


def _amplify_rows(rows: list[dict[str, Any]], *, selected_repeat: int, positive_repeat: int) -> list[dict[str, Any]]:
    if selected_repeat <= 1 and positive_repeat <= 1:
        return rows
    output: list[dict[str, Any]] = []
    for row in rows:
        output.append(row)
        rl = row.get("rl") if isinstance(row.get("rl"), dict) else {}
        repeat = 1
        if bool(rl.get("probe_replay_selected")) or bool(rl.get("error_replay_penalty")):
            repeat = max(repeat, selected_repeat)
        if bool(rl.get("probe_replay_positive_control")) or bool(rl.get("error_replay_better_alternative")):
            repeat = max(repeat, positive_repeat)
        for index in range(1, repeat):
            extra = copy.deepcopy(row)
            suffix = f"amp{index}"
            extra["action_row_id"] = f"{row.get('action_row_id')}:{suffix}"
            extra["query_id"] = f"{row.get('query_id')}:{suffix}"
            extra_rl = extra.setdefault("rl", {})
            if isinstance(extra_rl, dict):
                extra_rl["replay_amplified"] = True
                extra_rl["replay_amplification_index"] = index
                extra_rl["replay_amplification_repeat"] = repeat
            output.append(extra)
    return output


def _append_unique(output: list[dict[str, Any]], seen: set[str], row: dict[str, Any]) -> bool:
    key = str(row.get("action_row_id") or "")
    if not key or key in seen:
        return False
    seen.add(key)
    output.append(row)
    return True


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _nested(value: Any, *keys: str) -> Any:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _graph_return(row: dict[str, Any] | None) -> float:
    if not row:
        return 0.0
    return _float(_nested(row, "rl", "future_return"))


def _float(value: Any) -> float:
    try:
        return float(value if value is not None else 0.0)
    except Exception:
        return 0.0


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


if __name__ == "__main__":
    raise SystemExit(main())
