from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import subprocess
import sys
import datetime as _dt
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np
from joblib import dump
from lightgbm import LGBMRegressor
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score


DEFAULT_DATASET_DIR = Path("repair_training") / "datasets"
DEFAULT_MODEL_SUBDIR = Path("models") / "zip_runtime_policy"
LATEST_RUN = Path("repair_training") / "latest_run.txt"
FEATURE_CONTRACT_VERSION = 3
FEATURE_VIEWS = {
    "runtime_only",
    "runtime_plus_repair_prior",
    "runtime_plus_candidate_native_facts",
    "runtime_minimal_policy",
    "runtime_minimal_native_validation",
}
TARGETS = {
    "future_return",
    "single_path_robust_return",
    "reward",
    "terminal_reward",
    "policy_rollout_blended_return",
    "policy_sequence_return_v1",
    "root_transition_return_v1",
    "subtree_oracle_return_v1",
}


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    run_dir = _resolve_run_dir(args)
    dataset_dir = _resolve_dataset_dir(args, run_dir)
    if not args.output_dir:
        args.output_dir = str((run_dir / DEFAULT_MODEL_SUBDIR) if run_dir is not None else Path("repair_training") / "models" / "zip_runtime_policy")
    input_paths = _input_paths(args.input, dataset_dir)
    rows = _load_rows(input_paths)
    replay_rows = _load_rows([Path(item) for item in getattr(args, "extra_replay_input", []) if Path(item).is_file()])
    rollout_rows = _load_rows([Path(item) for item in getattr(args, "policy_rollout_input", []) if Path(item).is_file()])
    if rollout_rows:
        _merge_policy_rollout_returns(rows, rollout_rows)
    if replay_rows:
        rows.extend(replay_rows)
    rows = [row for row in rows if _row_format(row) == args.format_scope and isinstance(row.get("rl"), dict)]
    rows = [row for row in rows if row.get("row_type") != "terminal" and row.get("action_row_id")]
    rows = [row for row in rows if _target_value(row, args.target) is not None]
    if not rows:
        raise SystemExit("no RL transition rows found")
    _annotate_root_query_best_returns(rows)
    features = [_feature_dict(row, args.feature_view) for row in rows]
    y = np.array([float(_target_value(row, args.target) or 0.0) for row in rows], dtype=float)
    sample_weight = np.array([_sample_weight(row, args.sample_weight_mode) for row in rows], dtype=float)
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
    model.fit(X[train_idx], y[train_idx], sample_weight=sample_weight[train_idx] if args.sample_weight_mode != "none" else None)
    all_scores = model.predict(X)
    eval_scores = all_scores[eval_idx]
    metrics = _metrics(rows, y, all_scores, eval_idx, sample_weight=sample_weight)
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
        "sample_weight_mode": args.sample_weight_mode,
        "format_scope": args.format_scope,
        "row_count": len(rows),
        "train_row_count": len(train_idx),
        "eval_row_count": len(eval_idx),
        "run_dir": str(run_dir or ""),
        "git_commit": _git_commit(),
        "trained_at": _now_iso(),
        "input_files": [str(path) for path in input_paths],
        "input_file_hashes": {str(path): _sha256_file(path) for path in input_paths},
        "policy_rollout_input_files": [str(path) for path in getattr(args, "policy_rollout_input", [])],
        "extra_replay_input_files": [str(path) for path in getattr(args, "extra_replay_input", [])],
        **_training_row_summary(rows),
        "metrics": metrics,
        **split_summary,
    }
    (output_dir / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    (output_dir / "training_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    _update_run_manifest(run_dir, args, output_dir, summary)
    if not bool(getattr(args, "skip_analysis_report", False)):
        _run_post_training_analysis(run_dir, output_dir)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train a minimal offline RL Q-value model from repair-plan transitions.")
    parser.add_argument("--run-dir", default="", help="Training run directory. Defaults to repair_training/latest_run.txt when available.")
    parser.add_argument("--dataset-dir", default="")
    parser.add_argument("--input", action="append", default=[], help="Input JSONL file. Repeatable; defaults to ZIP terminal recovery datasets.")
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--feature-view", choices=sorted(FEATURE_VIEWS), default="runtime_minimal_native_validation")
    parser.add_argument("--target", choices=sorted(TARGETS), default="root_transition_return_v1")
    parser.add_argument("--sample-weight-mode", choices=("none", "runtime_policy_v1", "root_transition_v1"), default="root_transition_v1")
    parser.add_argument("--policy-rollout-input", action="append", default=[], help="JSONL rollout return rows to merge into graph rows.")
    parser.add_argument("--extra-replay-input", action="append", default=[], help="JSONL replay rows to append to training rows.")
    parser.add_argument("--format-scope", default="zip")
    parser.add_argument("--split-by", choices=("episode", "source_sample", "query"), default="source_sample")
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--n-estimators", type=int, default=300)
    parser.add_argument("--learning-rate", type=float, default=0.04)
    parser.add_argument("--num-leaves", type=int, default=31)
    parser.add_argument("--min-child-samples", type=int, default=20)
    parser.add_argument("--skip-analysis-report", action="store_true", help="Do not run training analysis after model artifacts are written.")
    return parser


def _input_paths(inputs: list[str], dataset_dir: Path) -> list[Path]:
    if inputs:
        return [Path(item) for item in inputs if Path(item).is_file()]
    runtime_graph = [
        dataset_dir / "runtime_graph_success.jsonl",
        dataset_dir / "runtime_graph_failure.jsonl",
        dataset_dir / "runtime_repair_graph_success.jsonl",
        dataset_dir / "runtime_repair_graph_failure.jsonl",
    ]
    if any(path.is_file() for path in runtime_graph):
        return [path for path in runtime_graph if path.is_file()]
    preferred = [
        dataset_dir / "repair_plan_ltr_success_zip_terminal_recovery.jsonl",
        dataset_dir / "repair_plan_ltr_failure_zip_terminal_recovery.jsonl",
    ]
    if all(path.is_file() for path in preferred):
        return preferred
    return sorted(dataset_dir.glob("repair_plan_ltr_*terminal_recovery.jsonl"))


def _resolve_run_dir(args: argparse.Namespace) -> Path | None:
    if str(args.run_dir or "").strip():
        return Path(args.run_dir).resolve()
    if not args.input and LATEST_RUN.is_file():
        text = LATEST_RUN.read_text(encoding="utf-8").strip()
        if text:
            path = Path(text).resolve()
            if path.is_dir():
                args.run_dir = str(path)
                return path
    return None


def _resolve_dataset_dir(args: argparse.Namespace, run_dir: Path | None) -> Path:
    if str(args.dataset_dir or "").strip():
        return Path(args.dataset_dir)
    if run_dir is not None:
        return run_dir / "datasets"
    return DEFAULT_DATASET_DIR


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[1], text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def _update_run_manifest(run_dir: Path | None, args: argparse.Namespace, output_dir: Path, summary: dict[str, Any]) -> None:
    if run_dir is None:
        return
    manifest_path = run_dir / "run_manifest.json"
    payload: dict[str, Any] = {}
    if manifest_path.is_file():
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            payload = raw if isinstance(raw, dict) else {}
        except json.JSONDecodeError:
            payload = {}
    payload.setdefault("run_dir", str(run_dir))
    payload["training"] = {
        "trained_at": summary.get("trained_at") or _now_iso(),
        "output_dir": str(output_dir),
        "feature_view": args.feature_view,
        "target": args.target,
        "sample_weight_mode": args.sample_weight_mode,
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "row_count": summary.get("row_count"),
        "input_files": summary.get("input_files", []),
        "input_file_hashes": summary.get("input_file_hashes", {}),
        "metrics": summary.get("metrics", {}),
    }
    manifest_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def _run_post_training_analysis(run_dir: Path | None, output_dir: Path) -> None:
    if run_dir is None:
        return
    try:
        subprocess.check_call(
            [
                sys.executable,
                str(Path(__file__).resolve().parents[1] / "repair_training" / "analyze_training_run.py"),
                "--run-dir",
                str(run_dir),
                "--model-dir",
                str(output_dir),
            ],
            cwd=Path(__file__).resolve().parents[1],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        _merge_run_manifest(run_dir, {"training_analysis": {"status": "failed", "error": str(exc), "model_dir": str(output_dir)}})


def _merge_run_manifest(run_dir: Path, update: dict[str, Any]) -> None:
    manifest_path = run_dir / "run_manifest.json"
    payload: dict[str, Any] = {}
    if manifest_path.is_file():
        try:
            loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
            payload = loaded if isinstance(loaded, dict) else {}
        except Exception:
            payload = {}
    payload.update(update)
    manifest_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


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
    stable = row.get("stable_features") if isinstance(row.get("stable_features"), dict) else {}
    runtime_context = stable.get("runtime_context") if isinstance(stable.get("runtime_context"), dict) else {}
    candidate_proposal = stable.get("candidate_proposal") if isinstance(stable.get("candidate_proposal"), dict) else {}
    action_features = rl.get("action_features") if isinstance(rl.get("action_features"), dict) else {}
    output: dict[str, Any] = {
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "top.round": int(row.get("round", 0) or 0),
        "top.material_format": row.get("material_format"),
        "top.module": row.get("module"),
        "top.current_rank": int(row.get("current_rank", 0) or 0),
        "top.branchable": bool(row.get("branchable")),
    }
    _flatten(output, "state", runtime_context)
    _flatten(output, "candidate", candidate_proposal)
    if view == "runtime_plus_candidate_native_facts":
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
    if target == "root_transition_return_v1":
        return _root_transition_return(row)
    if target == "subtree_oracle_return_v1":
        rollout = _optional_float(rl.get("policy_rollout_return"))
        subtree = _optional_float(rl.get("subtree_oracle_return"))
        if rollout is not None:
            return _clamp01(0.7 * rollout + 0.3 * (subtree if subtree is not None else rollout))
        return subtree
    if target == "policy_rollout_blended_return":
        rollout = _optional_float(rl.get("policy_rollout_return"))
        graph = _optional_float(rl.get("future_return"))
        if rollout is not None:
            return _clamp01(0.7 * rollout + 0.3 * (graph if graph is not None else rollout))
        if int(row.get("round", 0) or 0) == 0 and graph is not None:
            return _clamp01(graph)
        return graph
    if target == "policy_sequence_return_v1":
        return _policy_sequence_return(row)
    value = rl.get(target)
    if value is None and target == "single_path_robust_return":
        value = rl.get("future_return")
    if value is None and target == "terminal_reward":
        value = rl.get("terminal_reward")
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def _root_transition_return(row: dict[str, Any]) -> float | None:
    rl = row.get("rl") if isinstance(row.get("rl"), dict) else {}
    rollout = _optional_float(rl.get("policy_rollout_return"))
    root_value = _optional_float(rl.get("root_candidate_return"))
    subtree = _optional_float(rl.get("subtree_oracle_return"))
    graph = _optional_float(rl.get("future_return"))
    if rollout is not None:
        anchor = root_value if int(row.get("round", 0) or 0) == 0 else subtree
        if anchor is None:
            anchor = graph if graph is not None else rollout
        return _sequence_penalized_value(row, _clamp01(0.7 * rollout + 0.3 * anchor))
    if int(row.get("round", 0) or 0) == 0 and root_value is not None:
        return _sequence_penalized_value(row, root_value)
    if subtree is not None:
        return _sequence_penalized_value(row, subtree)
    if graph is not None:
        return _sequence_penalized_value(row, graph)
    return _policy_sequence_return(row)


def _policy_sequence_return(row: dict[str, Any]) -> float | None:
    rl = row.get("rl") if isinstance(row.get("rl"), dict) else {}
    base = _optional_float(rl.get("policy_rollout_return"))
    if base is None:
        base = _optional_float(rl.get("single_path_robust_return"))
    if base is None:
        base = _optional_float(rl.get("future_return"))
    if base is None:
        base = _optional_float(rl.get("terminal_reward"))
    if base is None:
        base = _optional_float(row.get("terminal_recovery_ratio"))
    if base is None:
        base = _optional_float(row.get("recovery_ratio"))
    if base is None:
        return None
    return _sequence_penalized_value(row, base)


def _sequence_penalized_value(row: dict[str, Any], base: float) -> float:
    rl = row.get("rl") if isinstance(row.get("rl"), dict) else {}
    penalty = 0.0
    status = str(rl.get("sequence_terminal_status") or rl.get("policy_rollout_terminal_status") or row.get("terminal_status") or "").lower()
    if bool(rl.get("sequence_repeated_input")) or "repeated_repair_input" in status:
        penalty += 0.25
    if bool(rl.get("sequence_no_candidate")) or "no_candidates" in status or "unrepairable" in status:
        penalty += 0.20
    if bool(rl.get("sequence_zero_recovery")) or float(base) <= 0.0:
        penalty += 0.35
    if bool(rl.get("sequence_partial_regression")):
        penalty += 0.15
    return _clamp01(float(base) - penalty)


def _sample_weight(row: dict[str, Any], mode: str) -> float:
    if mode == "none":
        return 1.0
    weight = 1.0
    round_index = int(row.get("round", 0) or 0)
    if mode == "root_transition_v1":
        if round_index == 0:
            weight *= 8.0
        elif round_index == 1:
            weight *= 3.0
    else:
        if round_index == 0:
            weight *= 4.0
        elif round_index == 1:
            weight *= 2.0
    rl = row.get("rl") if isinstance(row.get("rl"), dict) else {}
    status = str(rl.get("sequence_terminal_status") or row.get("terminal_status") or "").lower()
    recovery = _optional_float(row.get("terminal_recovery_ratio"))
    if recovery is None:
        recovery = _optional_float(row.get("recovery_ratio"))
    if round_index == 0 and ("complete" in status or (recovery is not None and recovery >= 0.999)):
        weight *= 1.5
    if mode == "root_transition_v1" and bool(row.get("root_action")):
        root_value = _optional_float(rl.get("root_candidate_return"))
        if root_value is not None:
            query_best = _optional_float(row.get("_root_query_best_return"))
            if query_best is not None and root_value >= query_best - 1e-9:
                weight *= 2.0
    bad = (
        (recovery is not None and recovery <= 0.0)
        or "repeated_repair_input" in status
        or "no_candidates" in status
        or "unrepairable" in status
        or bool(rl.get("error_replay_penalty"))
        or bool(rl.get("sequence_zero_recovery"))
    )
    if round_index == 0 and bad:
        weight *= 2.0
    if bool(rl.get("error_replay_penalty")):
        weight *= 6.0 if bool(rl.get("probe_replay")) else 5.0
    if bool(rl.get("error_replay_better_alternative")):
        weight *= 5.0 if bool(rl.get("probe_replay")) else 4.0
    if bool(rl.get("error_replay_better_root_alternative")):
        weight *= 2.0
    strategy = str(row.get("strategy") or "")
    if bool(rl.get("path_replay")) or strategy.startswith("runtime_path_filter"):
        weight *= 3.0
    return float(weight)


def _annotate_root_query_best_returns(rows: list[dict[str, Any]]) -> None:
    by_query: dict[str, float] = {}
    for row in rows:
        if int(row.get("round", 0) or 0) != 0:
            continue
        value = _optional_float(_nested(row, "rl", "root_candidate_return"))
        if value is None:
            value = _optional_float(_nested(row, "rl", "subtree_oracle_return"))
        if value is None:
            value = _optional_float(_nested(row, "rl", "future_return"))
        if value is None:
            continue
        query_id = str(row.get("query_id") or "")
        by_query[query_id] = max(float(value), by_query.get(query_id, 0.0))
    for row in rows:
        query_id = str(row.get("query_id") or "")
        if query_id in by_query:
            row["_root_query_best_return"] = by_query[query_id]


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


def _merge_policy_rollout_returns(rows: list[dict[str, Any]], rollout_rows: list[dict[str, Any]]) -> None:
    by_key: dict[tuple[str, int, str], dict[str, Any]] = {}
    by_sample_candidate: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in rollout_rows:
        sample_id = str(item.get("sample_id") or "")
        candidate_id = str(item.get("selected_candidate_id") or item.get("candidate_id") or "")
        if not sample_id or not candidate_id:
            continue
        try:
            round_index = int(item.get("round", 0) or 0)
        except Exception:
            round_index = 0
        by_key[(sample_id, round_index, candidate_id)] = item
        by_sample_candidate[(sample_id, candidate_id)].append(item)
    matched = 0
    for row in rows:
        key = (str(row.get("sample_id") or ""), int(row.get("round", 0) or 0), str(row.get("candidate_id") or ""))
        item = by_key.get(key)
        if not item:
            candidates = by_sample_candidate.get((key[0], key[2]), [])
            item = candidates[0] if len(candidates) == 1 else None
        if not item:
            continue
        matched += 1
        rl = row.setdefault("rl", {})
        if not isinstance(rl, dict):
            continue
        rl["policy_rollout_return"] = _clamp01(_float(item.get("final_recovery_ratio")))
        rl["policy_rollout_terminal_status"] = str(item.get("final_terminal_status") or "")
        rl["policy_rollout_selected"] = True
        rl["sequence_terminal_status"] = str(item.get("final_terminal_status") or "")
        rl["sequence_zero_recovery"] = float(rl["policy_rollout_return"]) <= 0.0
        status = str(item.get("final_terminal_status") or "").lower()
        rl["sequence_repeated_input"] = "repeated_repair_input" in status
        rl["sequence_no_candidate"] = "no_candidates" in status or "unrepairable" in status
    # Store a lightweight module-global diagnostic for the current process.
    globals()["_LAST_POLICY_ROLLOUT_MERGE_SUMMARY"] = {
        "policy_rollout_input_row_count": len(rollout_rows),
        "policy_rollout_matched_row_count": matched,
    }


def _training_row_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    root_rows = [row for row in rows if int(row.get("round", 0) or 0) == 0]
    root_positive = [
        row for row in root_rows
        if (_optional_float(row.get("terminal_recovery_ratio")) or _optional_float(row.get("recovery_ratio")) or 0.0) >= 0.999
    ]
    bad_status = ("repeated_repair_input", "no_candidates", "unrepairable")
    root_bad = [
        row for row in root_rows
        if any(token in str(row.get("terminal_status") or "").lower() for token in bad_status)
        or (_optional_float(row.get("terminal_recovery_ratio")) or _optional_float(row.get("recovery_ratio")) or 0.0) <= 0.0
    ]
    return {
        "root_row_count": len(root_rows),
        "root_positive_count": len(root_positive),
        "root_bad_terminal_count": len(root_bad),
        "root_action_row_count": sum(1 for row in root_rows if bool(row.get("root_action"))),
        "root_top5_coverage_count": sum(1 for row in root_rows if bool(row.get("root_action")) and _safe_int(row.get("current_rank"), 999) < 5),
        "root_unexplored_candidate_count": sum(1 for row in root_rows if row.get("explored") is False),
        "policy_rollout_selected_row_count": sum(1 for row in rows if bool(_nested(row, "rl", "policy_rollout_selected"))),
        **dict(globals().get("_LAST_POLICY_ROLLOUT_MERGE_SUMMARY") or {}),
        "error_replay_row_count": sum(1 for row in rows if bool(_nested(row, "rl", "error_replay_penalty")) or bool(_nested(row, "rl", "error_replay_better_alternative"))),
        "probe_replay_row_count": sum(1 for row in rows if bool(_nested(row, "rl", "probe_replay"))),
        "probe_replay_selected_count": sum(1 for row in rows if bool(_nested(row, "rl", "probe_replay_selected"))),
        "probe_replay_better_alternative_count": sum(1 for row in rows if bool(_nested(row, "rl", "probe_replay")) and bool(_nested(row, "rl", "error_replay_better_alternative"))),
        "probe_replay_better_root_alternative_count": sum(1 for row in rows if bool(_nested(row, "rl", "probe_replay")) and bool(_nested(row, "rl", "error_replay_better_root_alternative"))),
        "path_replay_row_count": sum(1 for row in rows if bool(_nested(row, "rl", "path_replay")) or str(row.get("strategy") or "").startswith("runtime_path_filter")),
        "rollout_matched_by_probe_count": sum(1 for row in rows if bool(_nested(row, "rl", "policy_rollout_selected")) and str(_nested(row, "rl", "policy_rollout_source") or "") == "probe"),
        "unmatched_selected_candidate_count": sum(1 for row in rows if bool(_nested(row, "rl", "unmatched_selected_candidate"))),
    }


def _metrics(rows: list[dict[str, Any]], y: np.ndarray, scores: np.ndarray, eval_idx: list[int], *, sample_weight: np.ndarray | None = None) -> dict[str, Any]:
    y_eval = y[eval_idx]
    s_eval = scores[eval_idx]
    by_query: dict[str, list[tuple[int, dict[str, Any], float]]] = defaultdict(list)
    for idx in eval_idx:
        by_query[str(rows[idx].get("query_id") or "")].append((idx, rows[idx], float(scores[idx])))
    top1_returns = []
    oracle_returns = []
    regrets = []
    weighted_regrets = []
    for items in by_query.values():
        ranked = sorted(items, key=lambda item: item[2], reverse=True)
        chosen = ranked[0][1]
        chosen_return = float(_nested(chosen, "rl", "future_return") or 0.0)
        oracle_return = max(float(_nested(row, "rl", "future_return") or 0.0) for _, row, _ in items)
        top1_returns.append(chosen_return)
        oracle_returns.append(oracle_return)
        regrets.append(max(0.0, oracle_return - chosen_return))
        if sample_weight is not None:
            query_weight = float(np.mean([sample_weight[idx] for idx, _, _ in items])) if items else 1.0
            weighted_regrets.append(max(0.0, oracle_return - chosen_return) * query_weight)
    root_metrics = _root_transition_metrics(by_query)
    return {
        "mae": float(mean_absolute_error(y_eval, s_eval)) if len(eval_idx) else 0.0,
        "rmse": float(mean_squared_error(y_eval, s_eval) ** 0.5) if len(eval_idx) else 0.0,
        "r2": float(r2_score(y_eval, s_eval)) if len(eval_idx) > 1 else 0.0,
        "eval_query_count": len(by_query),
        "top1_future_return_mean": _mean(top1_returns),
        "oracle_future_return_mean": _mean(oracle_returns),
        "future_return_regret_mean": _mean(regrets),
        "future_return_regret_p90": _percentile(sorted(regrets), 0.90),
        "weighted_future_return_regret_mean": _mean(weighted_regrets) if weighted_regrets else _mean(regrets),
        "duplicate_conflict_regret_mean": _duplicate_conflict_regret_mean(by_query),
        "duplicate_policy_top1_accuracy": _duplicate_policy_top1_accuracy(by_query),
        "candidate_id_collision_count": _candidate_id_collision_count([rows[idx] for idx in eval_idx]),
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "target_mean": float(statistics.mean(y_eval)) if len(y_eval) else 0.0,
        "prediction_mean": float(statistics.mean(s_eval)) if len(s_eval) else 0.0,
        **root_metrics,
    }


def _prediction_rows(rows: list[dict[str, Any]], scores: np.ndarray, eval_idx: list[int]) -> list[dict[str, Any]]:
    eval_set = set(eval_idx)
    output = []
    for idx, (row, score) in enumerate(zip(rows, scores)):
        output.append({
            "query_id": row.get("query_id"),
            "episode_id": row.get("episode_id"),
            "state_id": row.get("state_id"),
            "root_state_id": row.get("root_state_id"),
            "action_row_id": row.get("action_row_id"),
            "candidate_id": row.get("candidate_id"),
            "root_candidate_id": row.get("root_candidate_id"),
            "root_action": row.get("root_action"),
            "candidate_id_collision_key": f"{row.get('query_id') or ''}|{row.get('candidate_id') or ''}",
            "module": row.get("module"),
            "material_format": row.get("material_format"),
            "label": row.get("label"),
            "label_status": row.get("label_status"),
            "terminal_recovery_ratio": row.get("terminal_recovery_ratio"),
            "rl_future_return": _nested(row, "rl", "future_return"),
            "rl_subtree_oracle_return": _nested(row, "rl", "subtree_oracle_return"),
            "rl_root_candidate_return": _nested(row, "rl", "root_candidate_return"),
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


def _duplicate_conflict_regret_mean(by_query: dict[str, list[tuple[int, dict[str, Any], float]]]) -> float:
    regrets = []
    for items in by_query.values():
        if not items or not any(_is_duplicate_conflict_row(row) for _, row, _ in items):
            continue
        chosen = max(items, key=lambda item: item[2])[1]
        chosen_return = float(_nested(chosen, "rl", "future_return") or 0.0)
        oracle_return = max(float(_nested(row, "rl", "future_return") or 0.0) for _, row, _ in items)
        regrets.append(max(0.0, oracle_return - chosen_return))
    return _mean(regrets)


def _duplicate_policy_top1_accuracy(by_query: dict[str, list[tuple[int, dict[str, Any], float]]]) -> float:
    hits = []
    for items in by_query.values():
        duplicate_items = [(row, score) for _, row, score in items if _is_duplicate_conflict_row(row)]
        if not duplicate_items:
            continue
        chosen = max(items, key=lambda item: item[2])[1]
        oracle_return = max(float(_nested(row, "rl", "future_return") or 0.0) for _, row, _ in items)
        chosen_return = float(_nested(chosen, "rl", "future_return") or 0.0)
        hits.append(1.0 if chosen_return >= oracle_return - 1e-9 else 0.0)
    return _mean(hits)


def _root_transition_metrics(by_query: dict[str, list[tuple[int, dict[str, Any], float]]]) -> dict[str, Any]:
    regrets: list[float] = []
    hits: list[float] = []
    chosen_returns: list[float] = []
    best_returns: list[float] = []
    coverage = 0
    for items in by_query.values():
        root_items = [(idx, row, score) for idx, row, score in items if bool(row.get("root_action")) or int(row.get("round", 0) or 0) == 0]
        if not root_items:
            continue
        valued: list[tuple[int, dict[str, Any], float, float]] = []
        for idx, row, score in root_items:
            value = _optional_float(_nested(row, "rl", "root_candidate_return"))
            if value is None:
                value = _optional_float(_nested(row, "rl", "subtree_oracle_return"))
            if value is None:
                value = _optional_float(_nested(row, "rl", "future_return"))
            if value is None:
                continue
            valued.append((idx, row, score, float(value)))
        if not valued:
            continue
        coverage += 1
        chosen = max(valued, key=lambda item: item[2])
        chosen_return = chosen[3]
        best_return = max(item[3] for item in valued)
        chosen_returns.append(chosen_return)
        best_returns.append(best_return)
        regrets.append(max(0.0, best_return - chosen_return))
        hits.append(1.0 if chosen_return >= best_return - 1e-9 else 0.0)
    return {
        "root_query_count": coverage,
        "root_top1_accuracy": _mean(hits),
        "root_mean_regret": _mean(regrets),
        "root_best_return_mean": _mean(best_returns),
        "root_selected_return_mean": _mean(chosen_returns),
    }


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


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return int(default)
        return int(value)
    except Exception:
        return int(default)


def _float(value: Any, default: float = 0.0) -> float:
    parsed = _optional_float(value)
    return default if parsed is None else parsed


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _mean(values: list[float]) -> float:
    return float(statistics.mean(values)) if values else 0.0


def _percentile(ordered: list[float], ratio: float) -> float:
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * ratio))))
    return float(ordered[index])


if __name__ == "__main__":
    raise SystemExit(main())
