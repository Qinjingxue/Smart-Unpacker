from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import replace
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from repair_training.collect_episodes import _job_from_record, _load_records, _record_id
from repair_training.core.plugin import normalize_format_name
from sunpack.repair.policy.recovery_evaluator import RecoveryEvaluator
from sunpack.repair.scheduler import RepairScheduler


REQUIRED_MODEL_DIRS = ("normal_structure", "damage_location", "state_value", "repair_action")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    if fmt != "zip":
        raise SystemExit("evaluate_policy_arbiter currently supports --format zip only")
    _ensure_private_importable()
    model_root = _validate_model_root(Path(args.model_root))
    os.environ["SUNPACK_ZIP_DAMAGE_MODEL_DIR"] = str(model_root)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    records = _load_records(args.manifest, args.material_root, fmt, limit=0)
    if args.samples:
        records = records[: max(0, int(args.samples))]
    oracle_best = _oracle_best_by_episode(Path(args.oracle_episodes)) if args.oracle_episodes else {}
    config = _scheduler_config(
        workspace=output / "workspace",
        model_root=model_root,
        max_rounds=int(args.max_rounds or 5),
    )
    started = time.perf_counter()
    runs: list[dict[str, Any]] = []
    if int(args.workers or 1) <= 1:
        for index, record in enumerate(records, start=1):
            runs.append(_evaluate_one(index, record, fmt=fmt, config=config, oracle_best=oracle_best))
    else:
        with ProcessPoolExecutor(max_workers=max(1, int(args.workers or 1))) as pool:
            futures = {
                pool.submit(_evaluate_one, index, record, fmt=fmt, config=config, oracle_best=oracle_best): index
                for index, record in enumerate(records, start=1)
            }
            for future in as_completed(futures):
                runs.append(future.result())
    runs.sort(key=lambda item: int(item.get("index") or 0))
    (output / "policy_runs.jsonl").write_text("\n".join(json.dumps(item, ensure_ascii=False, sort_keys=True) for item in runs) + ("\n" if runs else ""), encoding="utf-8")
    summary = _summary(runs, elapsed=time.perf_counter() - started)
    profile_summary = _profile_summary(runs)
    hard_cases = _hard_cases(runs)
    timing = _timing(runs, elapsed=time.perf_counter() - started)
    _write_json(output / "summary.json", summary)
    _write_json(output / "profile_summary.json", profile_summary)
    _write_json(output / "timing.json", timing)
    (output / "hard_cases.jsonl").write_text("\n".join(json.dumps(item, ensure_ascii=False, sort_keys=True) for item in hard_cases) + ("\n" if hard_cases else ""), encoding="utf-8")
    print(json.dumps({"output": str(output), **summary}, ensure_ascii=False, sort_keys=True))
    return 0


def _evaluate_one(index: int, record: dict[str, Any], *, fmt: str, config: dict[str, Any], oracle_best: dict[str, float]) -> dict[str, Any]:
    started = time.perf_counter()
    sample_id = _record_id(record)
    profile = str(record.get("damage_profile") or record.get("profile") or "unknown")
    try:
        job = _job_from_record(record, fmt)
        scheduler = RepairScheduler(config)
        result = scheduler.repair(job)
        final_state = result.repaired_state or job.archive_state
        final_job = replace(
            job,
            archive_state=final_state,
            repair_history=(result.diagnosis or {}).get("policy_loop", {}) if isinstance(result.diagnosis, dict) else {},
        )
        recovery = RecoveryEvaluator(config).evaluate_state(final_job, final_state, mode="training_oracle")
        loop_payload = (result.diagnosis or {}).get("policy_loop", {}) if isinstance(result.diagnosis, dict) else {}
        rounds = loop_payload.get("rounds") if isinstance(loop_payload.get("rounds"), list) else []
        decision_stats = _decision_stats(rounds)
        oracle = _oracle_value_for(sample_id, oracle_best)
        return {
            "index": index,
            "sample_id": sample_id,
            "episode_id": str(record.get("query_id") or sample_id),
            "damage_profile": profile,
            "status": result.status,
            "module_name": result.module_name,
            "actions": list(result.actions or []),
            "final_recovery": recovery.to_dict(),
            "final_recovery_status": _final_recovery_status(recovery.to_dict(), float(recovery.score or 0.0)),
            "final_recovery_score": float(recovery.score or 0.0),
            "oracle_best_recovery": oracle,
            "oracle_gap": max(0.0, oracle - float(recovery.score or 0.0)) if oracle is not None else None,
            "round_count": len(rounds),
            "terminal_action": loop_payload.get("terminal_action") or "",
            "stop_reason": loop_payload.get("stop_reason") or result.message,
            "decision_stats": decision_stats,
            "warnings": list(result.warnings or []),
            "elapsed_seconds": round(time.perf_counter() - started, 6),
        }
    except Exception as exc:
        return {
            "index": index,
            "sample_id": sample_id,
            "damage_profile": profile,
            "status": "error",
            "error": str(exc),
            "error_type": type(exc).__name__,
            "final_recovery_status": "error",
            "final_recovery_score": 0.0,
            "oracle_best_recovery": _oracle_value_for(sample_id, oracle_best),
            "round_count": 0,
            "decision_stats": {},
            "elapsed_seconds": round(time.perf_counter() - started, 6),
        }


def _decision_stats(rounds: list[dict[str, Any]]) -> dict[str, Any]:
    actions = Counter()
    high_gap_stop = 0
    premature_stop = 0
    bad_undo = 0
    loop_prevented = 0
    apply_zero_value_delta = 0
    candidate_value_predictions = 0
    candidate_count = 0
    for item in rounds:
        action = item.get("action") if isinstance(item.get("action"), dict) else {}
        selection = action.get("arbiter") if isinstance(action.get("arbiter"), dict) else action
        decision = str((action.get("decision") if isinstance(action.get("decision"), str) else "") or action.get("action") or "")
        if decision:
            actions[decision] += 1
        value_gap = _float(item.get("value_gap"))
        scores = selection.get("scores") if isinstance(selection.get("scores"), list) else []
        if decision == "stop" and value_gap > 0.12:
            high_gap_stop += 1
        if decision == "stop" and any(str(score.get("action") or "") == "apply_patch" and _float(score.get("value_delta")) > 0.06 for score in scores if isinstance(score, dict)):
            premature_stop += 1
        if decision == "undo_patch" and any(str(score.get("action") or "") == "undo_patch" and _float(score.get("value_delta")) < 0.0 for score in scores if isinstance(score, dict)):
            bad_undo += 1
        if any(str(score.get("hard_guard") or "") == "repeated_digest" for score in scores if isinstance(score, dict)):
            loop_prevented += 1
        apply_zero_value_delta += sum(1 for score in scores if isinstance(score, dict) and str(score.get("action") or "") == "apply_patch" and abs(_float(score.get("value_delta"))) < 1e-9)
        candidate_values = item.get("candidate_state_values") if isinstance(item.get("candidate_state_values"), dict) else {}
        candidate_value_predictions += sum(1 for value in candidate_values.values() if not (isinstance(value, dict) and (value.get("metadata") or {}).get("decision_reason") == "candidate_value_budget_fallback"))
        candidates = item.get("candidate_state_values") if isinstance(item.get("candidate_state_values"), dict) else {}
        candidate_count += len(candidates)
    return {
        "actions": dict(actions),
        "high_gap_stop_count": high_gap_stop,
        "premature_stop_count": premature_stop,
        "bad_undo_count": bad_undo,
        "loop_prevented_count": loop_prevented,
        "apply_zero_value_delta_count": apply_zero_value_delta,
        "candidate_value_predictions": candidate_value_predictions,
        "candidate_value_count": candidate_count,
    }


def _summary(runs: list[dict[str, Any]], *, elapsed: float) -> dict[str, Any]:
    scores = [_float(item.get("final_recovery_score")) for item in runs]
    statuses = Counter(str(item.get("status") or "") for item in runs)
    final_statuses = Counter(_run_final_recovery_status(item) for item in runs)
    oracle_scores = [_float(item.get("oracle_best_recovery")) for item in runs if item.get("oracle_best_recovery") is not None]
    gaps = [_float(item.get("oracle_gap")) for item in runs if item.get("oracle_gap") is not None]
    decision = _sum_decision_stats(runs)
    sample_count = max(1, len(runs))
    final_complete_rate = final_statuses.get("complete", 0) / sample_count
    oracle_complete_rate = _rate_or_none(oracle_scores, 0.999)
    return {
        "samples": len(runs),
        "errors": statuses.get("error", 0),
        "status_counts": dict(statuses),
        "scheduler_status_counts": dict(statuses),
        "final_recovery_status_counts": dict(final_statuses),
        "final_recovery_mean": _mean(scores),
        "final_recovery_ge_0_5": _rate(scores, 0.5),
        "final_recovery_ge_0_8": _rate(scores, 0.8),
        "final_recovery_ge_0_95": _rate(scores, 0.95),
        "final_recovery_complete_rate": final_complete_rate,
        "policy_final_complete_rate": final_complete_rate,
        "oracle_best_available_count": len(oracle_scores),
        "oracle_best_missing_count": len(runs) - len(oracle_scores),
        "oracle_best_recovery_mean": _mean_or_none(oracle_scores),
        "oracle_best_ge_0_5": _rate_or_none(oracle_scores, 0.5),
        "oracle_best_ge_0_8": _rate_or_none(oracle_scores, 0.8),
        "oracle_best_ge_0_95": _rate_or_none(oracle_scores, 0.95),
        "oracle_best_complete_rate": oracle_complete_rate,
        "oracle_repaired_rate": oracle_complete_rate,
        "policy_vs_oracle_complete_rate_gap": (oracle_complete_rate - final_complete_rate) if oracle_complete_rate is not None else None,
        "scheduler_repaired_rate": statuses.get("repaired", 0) / sample_count,
        "scheduler_partial_rate": statuses.get("partial", 0) / sample_count,
        "scheduler_give_up_rate": statuses.get("unrepairable", 0) / sample_count,
        "scheduler_skipped_rate": statuses.get("skipped", 0) / sample_count,
        "repaired_rate": statuses.get("repaired", 0) / sample_count,
        "partial_rate": statuses.get("partial", 0) / sample_count,
        "give_up_rate": statuses.get("unrepairable", 0) / sample_count,
        "skipped_rate": statuses.get("skipped", 0) / sample_count,
        "scheduler_partial_but_final_complete_count": sum(
            1 for item in runs if str(item.get("status") or "") == "partial" and _run_final_recovery_status(item) == "complete"
        ),
        "oracle_gap_available_count": len(gaps),
        "oracle_gap_missing_count": len(runs) - len(gaps),
        "oracle_gap_mean": _mean_or_none(gaps),
        "oracle_gap_p90": _percentile_or_none(gaps, 0.9),
        "decision_quality": decision,
        "elapsed_seconds": round(elapsed, 6),
    }


def _profile_summary(runs: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in runs:
        grouped[str(item.get("damage_profile") or "unknown")].append(item)
    output = {}
    for profile, items in sorted(grouped.items()):
        scores = [_float(item.get("final_recovery_score")) for item in items]
        oracle_scores = [_float(item.get("oracle_best_recovery")) for item in items if item.get("oracle_best_recovery") is not None]
        gaps = [_float(item.get("oracle_gap")) for item in items if item.get("oracle_gap") is not None]
        final_statuses = Counter(_run_final_recovery_status(item) for item in items)
        final_complete_rate = final_statuses.get("complete", 0) / max(1, len(items))
        oracle_complete_rate = _rate_or_none(oracle_scores, 0.999)
        output[profile] = {
            "count": len(items),
            "final_recovery_mean": _mean(scores),
            "ge_0_8": _rate(scores, 0.8),
            "lt_0_5": 1.0 - _rate(scores, 0.5),
            "final_recovery_complete_rate": final_complete_rate,
            "oracle_best_available_count": len(oracle_scores),
            "oracle_best_recovery_mean": _mean_or_none(oracle_scores),
            "oracle_best_complete_rate": oracle_complete_rate,
            "policy_vs_oracle_complete_rate_gap": (oracle_complete_rate - final_complete_rate) if oracle_complete_rate is not None else None,
            "oracle_gap_available_count": len(gaps),
            "oracle_gap_mean": _mean_or_none(gaps),
            "status_counts": dict(Counter(str(item.get("status") or "") for item in items)),
            "final_recovery_status_counts": dict(final_statuses),
        }
    return output


def _hard_cases(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cases = []
    for item in runs:
        score = _float(item.get("final_recovery_score"))
        gap = item.get("oracle_gap")
        stats = item.get("decision_stats") if isinstance(item.get("decision_stats"), dict) else {}
        reasons = []
        if item.get("status") == "error":
            reasons.append("error")
        if gap is not None and _float(gap) >= 0.25:
            reasons.append("oracle_gap_ge_0_25")
        if score <= 0.0:
            reasons.append("zero_final_recovery")
        elif score < 0.5:
            reasons.append("low_final_recovery_lt_0_5")
        if stats.get("high_gap_stop_count"):
            reasons.append("high_gap_stop")
        if stats.get("bad_undo_count"):
            reasons.append("bad_undo")
        if reasons:
            cases.append({**item, "hard_case_reasons": reasons})
    cases.sort(key=_hard_case_sort_key, reverse=True)
    return cases[:200]


def _timing(runs: list[dict[str, Any]], *, elapsed: float) -> dict[str, Any]:
    values = [_float(item.get("elapsed_seconds")) for item in runs]
    return {
        "elapsed_seconds": round(elapsed, 6),
        "per_sample_mean": _mean(values),
        "per_sample_p50": _percentile(values, 0.5),
        "per_sample_p90": _percentile(values, 0.9),
        "per_sample_max": max(values, default=0.0),
    }


def _sum_decision_stats(runs: list[dict[str, Any]]) -> dict[str, Any]:
    total = Counter()
    actions = Counter()
    for item in runs:
        stats = item.get("decision_stats") if isinstance(item.get("decision_stats"), dict) else {}
        for key in ("high_gap_stop_count", "premature_stop_count", "bad_undo_count", "loop_prevented_count", "apply_zero_value_delta_count", "candidate_value_predictions", "candidate_value_count"):
            total[key] += int(stats.get(key) or 0)
        actions.update(stats.get("actions") if isinstance(stats.get("actions"), dict) else {})
    return {**dict(total), "actions": dict(actions)}


def _run_final_recovery_status(item: dict[str, Any]) -> str:
    status = str(item.get("final_recovery_status") or "")
    if status:
        return status
    recovery = item.get("final_recovery") if isinstance(item.get("final_recovery"), dict) else {}
    return _final_recovery_status(recovery, _float(item.get("final_recovery_score")))


def _final_recovery_status(recovery: dict[str, Any], score: float) -> str:
    status = str(recovery.get("status") or "")
    if status:
        return status
    decision_hint = str(recovery.get("decision_hint") or "")
    if score >= 0.999 or decision_hint == "accept":
        return "complete"
    if score > 0.0:
        return "partial"
    return "none"


def _hard_case_sort_key(item: dict[str, Any]) -> tuple[float, float, float, float, float]:
    reasons = set(item.get("hard_case_reasons") if isinstance(item.get("hard_case_reasons"), list) else [])
    return (
        1.0 if "error" in reasons else 0.0,
        _float(item.get("oracle_gap")) if item.get("oracle_gap") is not None else 0.0,
        1.0 if "zero_final_recovery" in reasons else 0.0,
        1.0 if {"high_gap_stop", "bad_undo"} & reasons else 0.0,
        1.0 - _float(item.get("final_recovery_score")),
    )


def _scheduler_config(*, workspace: Path, model_root: Path, max_rounds: int) -> dict[str, Any]:
    repair = {
        "workspace": str(workspace),
        "max_repair_rounds_per_task": max_rounds,
        "max_attempts_per_task": max_rounds,
        "stagnation_patience_rounds": max_rounds,
        "policy": {
            "enabled": True,
            "fallback_to_selector": False,
            "provider_package": "sunpack_repair_models",
            "policy_model_root": str(model_root),
            "arbiter": {
                "candidate_value_budget_root": 4,
                "candidate_value_budget_branch": 2,
            },
        },
        "runtime_cache": {"enabled": True, "max_entries": 512},
        "training_module_selection_cache": True,
        "extraction": {"quiet": True},
        "verification": {
            "enabled": True,
            "methods": [
                {"name": "extraction_exit_signal", "enabled": True},
                {"name": "output_presence", "enabled": True},
            ],
        },
    }
    return {**repair, "repair": repair}


def _validate_model_root(path: Path) -> Path:
    root = path.resolve()
    if (root / "models").is_dir():
        root = root / "models"
    missing = [name for name in REQUIRED_MODEL_DIRS if not (root / name).is_dir()]
    if missing:
        raise SystemExit(f"model root {root} is missing required model directories: {', '.join(missing)}")
    return root


def _oracle_best_by_episode(path: Path) -> dict[str, float]:
    output: dict[str, float] = {}
    if not path.is_file():
        return output
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            payload = json.loads(line)
            episode_id = str(payload.get("episode_id") or "")
            best = 0.0
            for transition in payload.get("transitions") or []:
                for key in ("verification_before", "verification_after"):
                    snap = transition.get(key) if isinstance(transition, dict) else {}
                    if isinstance(snap, dict):
                        best = max(best, _float(snap.get("score")))
            if episode_id:
                output[episode_id] = best
                output[episode_id.split(":")[0]] = max(output.get(episode_id.split(":")[0], 0.0), best)
    return output


def _oracle_value_for(sample_id: str, oracle_best: dict[str, float]) -> float | None:
    if not oracle_best:
        return None
    if sample_id in oracle_best:
        return oracle_best[sample_id]
    return oracle_best.get(str(sample_id).split(":")[0])


def _ensure_private_importable() -> None:
    private = Path(".private").resolve()
    if private.is_dir() and str(private) not in sys.path:
        sys.path.insert(0, str(private))


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def _mean(values: list[float]) -> float:
    return sum(values) / max(1, len(values))


def _mean_or_none(values: list[float]) -> float | None:
    if not values:
        return None
    return _mean(values)


def _rate(values: list[float], threshold: float) -> float:
    return sum(1 for value in values if value >= threshold) / max(1, len(values))


def _rate_or_none(values: list[float], threshold: float) -> float | None:
    if not values:
        return None
    return _rate(values, threshold)


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * q))))
    return ordered[index]


def _percentile_or_none(values: list[float], q: float) -> float | None:
    if not values:
        return None
    return _percentile(values, q)


def _float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate the full four-model policy loop with PolicyDecisionArbiter.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--material-root", default="repair_training/material")
    parser.add_argument("--model-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--samples", type=int, default=0)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--max-rounds", type=int, default=5)
    parser.add_argument("--oracle-episodes", default="")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
