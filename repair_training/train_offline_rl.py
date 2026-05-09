from __future__ import annotations

import argparse
import hashlib
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np
from joblib import dump
from lightgbm import LGBMRegressor
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score


DEFAULT_DATASET_DIR = Path("repair_training") / "datasets"
DEFAULT_OUTPUT_DIR = Path("repair_training") / "models" / "offline_rl" / "zip_q_value"
FEATURE_CONTRACT_VERSION = 3
FEATURE_VIEWS = {
    "runtime_only",
    "runtime_plus_repair_prior",
    "runtime_plus_candidate_native_facts",
    "runtime_minimal_policy",
    "runtime_minimal_native_validation",
}


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    rows = _load_rows(_input_paths(args.input, Path(args.dataset_dir)))
    rows = [row for row in rows if _row_format(row) == args.format_scope and isinstance(row.get("rl"), dict)]
    rows = [row for row in rows if row.get("row_type") != "terminal" and row.get("action_row_id")]
    rows = [row for row in rows if _target_value(row, args.target) is not None]
    if not rows:
        raise SystemExit("no RL transition rows found")
    features = [_feature_dict(row, args.feature_view) for row in rows]
    y = np.array([float(_target_value(row, args.target) or 0.0) for row in rows], dtype=float)
    vectorizer = DictVectorizer(sparse=True)
    X = vectorizer.fit_transform(features)
    train_idx, eval_idx, split_summary = _split_rows(rows, args)
    if not eval_idx:
        train_idx = list(range(len(rows)))
        eval_idx = list(range(len(rows)))
        split_summary["eval_skipped"] = True
    else:
        split_summary["eval_skipped"] = False
    model = LGBMRegressor(
        objective="regression",
        n_estimators=int(args.n_estimators),
        learning_rate=float(args.learning_rate),
        num_leaves=int(args.num_leaves),
        min_child_samples=int(args.min_child_samples),
        random_state=int(args.seed),
        n_jobs=-1,
    )
    model.fit(X[train_idx], y[train_idx])
    all_scores = model.predict(X)
    eval_scores = all_scores[eval_idx]
    metrics = _metrics(rows, y, all_scores, eval_idx)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    model.booster_.save_model(str(output_dir / "model.txt"))
    dump(vectorizer, output_dir / "vectorizer.joblib")
    (output_dir / "feature_names.json").write_text(json.dumps(vectorizer.get_feature_names_out().tolist(), ensure_ascii=False, indent=2), encoding="utf-8")
    _write_jsonl(output_dir / "predictions.jsonl", _prediction_rows(rows, all_scores, eval_idx))
    summary = {
        "feature_view": args.feature_view,
        "feature_count": len(vectorizer.get_feature_names_out()),
        "target": args.target,
        "format_scope": args.format_scope,
        "row_count": len(rows),
        "train_row_count": len(train_idx),
        "eval_row_count": len(eval_idx),
        "input_files": [str(path) for path in _input_paths(args.input, Path(args.dataset_dir))],
        "metrics": metrics,
        **split_summary,
    }
    (output_dir / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    (output_dir / "training_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train a minimal offline RL Q-value model from repair-plan transitions.")
    parser.add_argument("--dataset-dir", default=str(DEFAULT_DATASET_DIR))
    parser.add_argument("--input", action="append", default=[], help="Input JSONL file. Repeatable; defaults to ZIP terminal recovery datasets.")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--feature-view", choices=sorted(FEATURE_VIEWS), default="runtime_minimal_native_validation")
    parser.add_argument("--target", choices=("future_return", "reward", "terminal_reward"), default="future_return")
    parser.add_argument("--format-scope", default="zip")
    parser.add_argument("--split-by", choices=("episode", "source_sample", "query"), default="source_sample")
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--n-estimators", type=int, default=300)
    parser.add_argument("--learning-rate", type=float, default=0.04)
    parser.add_argument("--num-leaves", type=int, default=31)
    parser.add_argument("--min-child-samples", type=int, default=20)
    return parser


def _input_paths(inputs: list[str], dataset_dir: Path) -> list[Path]:
    if inputs:
        return [Path(item) for item in inputs if Path(item).is_file()]
    preferred = [
        dataset_dir / "repair_plan_ltr_success_zip_terminal_recovery.jsonl",
        dataset_dir / "repair_plan_ltr_failure_zip_terminal_recovery.jsonl",
    ]
    if all(path.is_file() for path in preferred):
        return preferred
    return sorted(dataset_dir.glob("repair_plan_ltr_*terminal_recovery.jsonl"))


def _load_rows(paths: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(row, dict):
                    rows.append(row)
    return rows


def _feature_dict(row: dict[str, Any], view: str) -> dict[str, Any]:
    rl = row.get("rl") if isinstance(row.get("rl"), dict) else {}
    state_features = rl.get("state_features") if isinstance(rl.get("state_features"), dict) else {}
    action_features = rl.get("action_features") if isinstance(rl.get("action_features"), dict) else {}
    output: dict[str, Any] = {
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "top.round": int(row.get("round", 0) or 0),
        "top.material_format": row.get("material_format"),
        "top.module": row.get("module"),
        "top.current_rank": int(row.get("current_rank", 0) or 0),
        "top.branchable": bool(row.get("branchable")),
    }
    _flatten(output, "state", state_features.get("runtime_context") if isinstance(state_features.get("runtime_context"), dict) else {})
    _flatten(output, "candidate", action_features.get("candidate_proposal") if isinstance(action_features.get("candidate_proposal"), dict) else {})
    if view == "runtime_plus_candidate_native_facts":
        stable = row.get("stable_features") if isinstance(row.get("stable_features"), dict) else {}
        _flatten(output, "candidate_native", stable.get("candidate") if isinstance(stable.get("candidate"), dict) else {})
    if view in {"runtime_plus_repair_prior", "runtime_plus_candidate_native_facts"}:
        _flatten(output, "repair_prior", action_features.get("repair_prior_features") if isinstance(action_features.get("repair_prior_features"), dict) else {})
    if view in {"runtime_minimal_policy", "runtime_minimal_native_validation"}:
        output = {
            key: value
            for key, value in output.items()
            if (
                key == "feature_contract_version"
                or key.startswith("top.")
                or key.startswith("state.")
                or key.startswith("candidate.module")
                or key.startswith("candidate.repair_name")
                or key.startswith("candidate.atomic_action_group")
                or key.startswith("candidate.route_family")
                or key.startswith("candidate.format")
                or (
                    view == "runtime_minimal_native_validation"
                    and (
                        key.startswith("candidate.native_key")
                        or key.startswith("candidate.native_target")
                        or key.startswith("candidate.candidate_status")
                        or key.startswith("candidate.native_target_mismatch")
                        or key.startswith("candidate.validation_details")
                    )
                )
            )
        }
    return output


def _flatten(output: dict[str, Any], prefix: str, value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if _excluded_feature_key(str(key), path):
                continue
            _flatten(output, path, item)
        return
    if isinstance(value, list):
        tokens = [str(item) for item in value if item is not None and str(item)]
        for token in sorted(set(tokens)):
            output[f"{prefix}[]={token}"] = 1
        output[f"{prefix}.count"] = len(tokens)
        return
    if value is None:
        return
    if isinstance(value, bool):
        output[prefix] = int(value)
    elif isinstance(value, (int, float)):
        output[prefix] = float(value)
    else:
        text = str(value)
        if text:
            output[f"{prefix}={text}"] = 1


def _excluded_feature_key(key: str, path: str) -> bool:
    normalized = f"{path}.{key}".lower()
    safe_validation_prefixes = (
        "candidate.validation_details",
        "candidate_native.validation_details",
    )
    safe_validation_keys = (
        "policy",
        "crc_match_count",
        "kept_entries",
        "dropped_entries",
        "duplicate_group_count",
        "kept_entry_crc_match_count",
        "kept_payload_verified_count",
        "dropped_entry_count",
        "ambiguous_duplicate_group_count",
        "native_target",
        "accepted",
        "raw_filename_bytes_preserved",
    )
    if any(normalized.startswith(prefix) for prefix in safe_validation_prefixes):
        return False
    forbidden = (
        "oracle",
        "after_state",
        "delta",
        "terminal",
        "label",
        "reward",
        "future_return",
        "next_state",
        "selected_by_current_system",
        "materialized",
        "validation",
        "native_validation",
        "matched_entry",
        "wrong_entry",
        "source_derivation",
        "damage_profile",
        "difficulty_tags",
        "corruption",
        "runtime_score",
    )
    return any(token in normalized for token in forbidden)


def _target_value(row: dict[str, Any], target: str) -> float | None:
    rl = row.get("rl") if isinstance(row.get("rl"), dict) else {}
    value = rl.get(target)
    if value is None and target == "terminal_reward":
        value = rl.get("terminal_reward")
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def _split_rows(rows: list[dict[str, Any]], args: argparse.Namespace) -> tuple[list[int], list[int], dict[str, Any]]:
    keys = [_split_key(row, args.split_by) for row in rows]
    unique = sorted(set(keys))
    if len(unique) < 5:
        return list(range(len(rows))), [], {"split_by": args.split_by, "split_fallback": "too_few_keys", "train_keys": unique, "eval_keys": []}
    ordered = sorted(unique, key=lambda key: hashlib.sha256(f"{args.seed}:{key}".encode("utf-8")).hexdigest())
    split = max(1, int(len(ordered) * 0.8))
    train_keys = set(ordered[:split])
    eval_keys = set(ordered[split:])
    train_idx = [idx for idx, key in enumerate(keys) if key in train_keys]
    eval_idx = [idx for idx, key in enumerate(keys) if key in eval_keys]
    return train_idx, eval_idx, {
        "split_by": args.split_by,
        "split_fallback": "",
        "train_key_count": len(train_keys),
        "eval_key_count": len(eval_keys),
        "train_keys": sorted(train_keys)[:200],
        "eval_keys": sorted(eval_keys)[:200],
    }


def _split_key(row: dict[str, Any], split_by: str) -> str:
    if split_by == "query":
        return str(row.get("query_id") or "unknown")
    if split_by == "episode":
        return str(row.get("episode_id") or row.get("sample_id") or "unknown")
    value = row.get("material_sample_id")
    if not value:
        episode = str(row.get("episode_id") or row.get("sample_id") or "")
        value = episode.split(":")[0].split("_zip_")[0] if episode else ""
    return str(value or "unknown")


def _metrics(rows: list[dict[str, Any]], y: np.ndarray, scores: np.ndarray, eval_idx: list[int]) -> dict[str, Any]:
    y_eval = y[eval_idx]
    s_eval = scores[eval_idx]
    by_query: dict[str, list[tuple[dict[str, Any], float]]] = defaultdict(list)
    for idx in eval_idx:
        by_query[str(rows[idx].get("query_id") or "")].append((rows[idx], float(scores[idx])))
    top1_returns = []
    oracle_returns = []
    regrets = []
    for items in by_query.values():
        ranked = sorted(items, key=lambda item: item[1], reverse=True)
        chosen = ranked[0][0]
        chosen_return = float(_nested(chosen, "rl", "future_return") or 0.0)
        oracle_return = max(float(_nested(row, "rl", "future_return") or 0.0) for row, _ in items)
        top1_returns.append(chosen_return)
        oracle_returns.append(oracle_return)
        regrets.append(max(0.0, oracle_return - chosen_return))
    return {
        "mae": float(mean_absolute_error(y_eval, s_eval)) if len(eval_idx) else 0.0,
        "rmse": float(mean_squared_error(y_eval, s_eval) ** 0.5) if len(eval_idx) else 0.0,
        "r2": float(r2_score(y_eval, s_eval)) if len(eval_idx) > 1 else 0.0,
        "eval_query_count": len(by_query),
        "top1_future_return_mean": _mean(top1_returns),
        "oracle_future_return_mean": _mean(oracle_returns),
        "future_return_regret_mean": _mean(regrets),
        "future_return_regret_p90": _percentile(sorted(regrets), 0.90),
        "duplicate_conflict_regret_mean": _duplicate_conflict_regret_mean(by_query),
        "duplicate_policy_top1_accuracy": _duplicate_policy_top1_accuracy(by_query),
        "candidate_id_collision_count": _candidate_id_collision_count([rows[idx] for idx in eval_idx]),
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "target_mean": float(statistics.mean(y_eval)) if len(y_eval) else 0.0,
        "prediction_mean": float(statistics.mean(s_eval)) if len(s_eval) else 0.0,
    }


def _prediction_rows(rows: list[dict[str, Any]], scores: np.ndarray, eval_idx: list[int]) -> list[dict[str, Any]]:
    eval_set = set(eval_idx)
    output = []
    for idx, (row, score) in enumerate(zip(rows, scores)):
        output.append({
            "query_id": row.get("query_id"),
            "episode_id": row.get("episode_id"),
            "state_id": row.get("state_id"),
            "action_row_id": row.get("action_row_id"),
            "candidate_id": row.get("candidate_id"),
            "candidate_id_collision_key": f"{row.get('query_id') or ''}|{row.get('candidate_id') or ''}",
            "module": row.get("module"),
            "material_format": row.get("material_format"),
            "label": row.get("label"),
            "label_status": row.get("label_status"),
            "terminal_recovery_ratio": row.get("terminal_recovery_ratio"),
            "rl_future_return": _nested(row, "rl", "future_return"),
            "rl_reward": _nested(row, "rl", "reward"),
            "rl_done": _nested(row, "rl", "done"),
            "score": float(score),
            "eval_row": idx in eval_set,
        })
    return output


def _candidate_id_collision_count(rows: list[dict[str, Any]]) -> int:
    by_key: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in rows:
        key = (str(row.get("query_id") or ""), str(row.get("candidate_id") or ""))
        if not key[0] or not key[1]:
            continue
        by_key[key].add(str(row.get("action_row_id") or ""))
    return sum(max(0, len(actions) - 1) for actions in by_key.values())


def _duplicate_conflict_regret_mean(by_query: dict[str, list[tuple[dict[str, Any], float]]]) -> float:
    regrets = []
    for items in by_query.values():
        if not items or not any(_is_duplicate_conflict_row(row) for row, _ in items):
            continue
        chosen = max(items, key=lambda item: item[1])[0]
        chosen_return = float(_nested(chosen, "rl", "future_return") or 0.0)
        oracle_return = max(float(_nested(row, "rl", "future_return") or 0.0) for row, _ in items)
        regrets.append(max(0.0, oracle_return - chosen_return))
    return _mean(regrets)


def _duplicate_policy_top1_accuracy(by_query: dict[str, list[tuple[dict[str, Any], float]]]) -> float:
    hits = []
    for items in by_query.values():
        duplicate_items = [(row, score) for row, score in items if _is_duplicate_conflict_row(row)]
        if not duplicate_items:
            continue
        chosen = max(items, key=lambda item: item[1])[0]
        oracle_return = max(float(_nested(row, "rl", "future_return") or 0.0) for row, _ in items)
        chosen_return = float(_nested(chosen, "rl", "future_return") or 0.0)
        hits.append(1.0 if chosen_return >= oracle_return - 1e-9 else 0.0)
    return _mean(hits)


def _is_duplicate_conflict_row(row: dict[str, Any]) -> bool:
    sample = " ".join(str(row.get(key) or "") for key in ("sample_id", "episode_id", "module", "module_name"))
    if "zip_duplicate_entry_crc_conflict" in sample or "zip_resolve_duplicate_entries" in sample:
        return True
    facts = row.get("patch_facts") if isinstance(row.get("patch_facts"), list) else []
    return any("duplicate" in str(item).lower() for item in facts)


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _row_format(row: dict[str, Any]) -> str:
    value = str(row.get("material_format") or row.get("format") or "").lower().replace(".", "_").replace("-", "_")
    return {"seven_zip": "7z"}.get(value, value)


def _nested(value: Any, *keys: str) -> Any:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _mean(values: list[float]) -> float:
    return float(statistics.mean(values)) if values else 0.0


def _percentile(ordered: list[float], ratio: float) -> float:
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * ratio))))
    return float(ordered[index])


if __name__ == "__main__":
    raise SystemExit(main())
