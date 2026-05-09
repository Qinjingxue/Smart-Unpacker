from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any

import numpy as np
from joblib import dump
from lightgbm import LGBMRegressor
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from repair_training.evaluate_offline_policy import _build_graph, _evaluate_policy
from repair_training.train_offline_rl import (
    _feature_dict,
    _input_paths,
    _load_rows,
    _nested,
    _prediction_rows,
    _row_format,
    _split_rows,
    _target_value,
    _write_jsonl,
)


FEATURE_SETS: dict[str, dict[str, Any]] = {
    "module_identity": {
        "include": (
            "feature_contract_version",
            "top.material_format",
            "top.module",
            "candidate.module",
            "candidate.repair_name",
            "candidate.atomic_action_group",
            "candidate.route_family",
            "candidate.format",
        ),
    },
    "module_identity_rank": {
        "extends": "module_identity",
        "include": (
            "top.round",
            "top.current_rank",
            "top.branchable",
        ),
    },
    "module_identity_rank_state": {
        "extends": "module_identity_rank",
        "include": ("state.",),
    },
    "module_identity_rank_state_plan": {
        "extends": "module_identity_rank_state",
        "include": (
            "candidate.plan_kind",
            "candidate.input_kind",
            "candidate.requires_",
            "candidate.has_archive_state_plan",
            "candidate.patch_cost",
            "candidate.estimated_cost",
        ),
    },
    "minimal_plus_scores": {
        "extends": "module_identity_rank_state",
        "include": (
            "candidate.confidence",
            "candidate.score_hint",
            "candidate.cost_",
            "candidate.risk_",
            "candidate.evidence_",
            "candidate.benefit_",
            "candidate.context_mismatch_",
            "candidate.lazy_no_output_",
            "candidate.proposal_ltr.",
        ),
    },
    "minimal_plus_repair_prior": {
        "extends": "module_identity_rank_state",
        "include": ("repair_prior.",),
    },
    "minimal_plus_native_identity": {
        "extends": "module_identity_rank_state",
        "include": (
            "candidate.native_key",
            "candidate.native_target",
            "candidate.candidate_status",
            "candidate.native_target_mismatch",
        ),
    },
    "minimal_plus_patch_facts": {
        "extends": "module_identity_rank_state",
        "include": (
            "candidate.patch_facts",
            "candidate.residual_facts",
            "candidate.raw_name_",
            "candidate.split_sidecars_available",
            "candidate.logical_stream_built",
            "candidate.after_archive_carrier_crop",
        ),
    },
    "minimal_plus_validation": {
        "extends": "module_identity_rank_state",
        "include": ("candidate.validation_details",),
    },
    "minimal_plus_native_identity_validation": {
        "extends": "minimal_plus_native_identity",
        "include": ("candidate.validation_details",),
    },
    "minimal_plus_patch_validation": {
        "extends": "minimal_plus_patch_facts",
        "include": ("candidate.validation_details",),
    },
    "state_candidate_no_native_dup": {
        "include": (
            "feature_contract_version",
            "top.",
            "state.",
            "candidate.",
            "repair_prior.",
        ),
    },
    "state_candidate_no_prior": {
        "include": (
            "feature_contract_version",
            "top.",
            "state.",
            "candidate.",
            "candidate_native.",
        ),
    },
    "module_state": {
        "include": (
            "feature_contract_version",
            "top.",
            "state.",
            "candidate.module",
            "candidate.repair_name",
            "candidate.atomic_action_group",
            "candidate.route_family",
            "candidate.format",
            "candidate.actions",
            "candidate.damage_flags",
            "candidate.plan_kind",
            "candidate.input_kind",
        ),
    },
    "module_state_scores": {
        "extends": "module_state",
        "include": (
            "candidate.confidence",
            "candidate.score_hint",
            "candidate.patch_cost",
            "candidate.estimated_cost",
            "candidate.requires_",
            "candidate.has_archive_state_plan",
            "candidate.cost_",
            "candidate.risk_",
            "candidate.evidence_",
            "candidate.benefit_",
            "candidate.context_mismatch_",
            "candidate.lazy_no_output_",
            "candidate.proposal_ltr.",
        ),
    },
    "module_state_scores_prior": {
        "extends": "module_state_scores",
        "include": ("repair_prior.",),
    },
    "native_identity": {
        "extends": "module_state_scores_prior",
        "include": (
            "candidate.native_key",
            "candidate.native_target",
            "candidate.candidate_status",
            "candidate.native_target_mismatch",
            "candidate_native.native_key",
            "candidate_native.native_target",
            "candidate_native.candidate_status",
            "candidate_native.native_target_mismatch",
        ),
    },
    "native_patch_facts": {
        "extends": "native_identity",
        "include": (
            "candidate.patch_facts",
            "candidate.residual_facts",
            "candidate.raw_name_",
            "candidate.split_sidecars_available",
            "candidate.logical_stream_built",
            "candidate.after_archive_carrier_crop",
            "candidate_native.patch_facts",
            "candidate_native.residual_facts",
            "candidate_native.raw_name_",
            "candidate_native.split_sidecars_available",
            "candidate_native.logical_stream_built",
            "candidate_native.after_archive_carrier_crop",
        ),
    },
    "native_patch_validation": {
        "extends": "native_patch_facts",
        "include": (
            "candidate.validation_details",
            "candidate_native.validation_details",
        ),
    },
    "candidate_only_native_patch_validation": {
        "include": (
            "feature_contract_version",
            "top.",
            "candidate.",
            "candidate_native.",
            "repair_prior.",
        ),
    },
    "full": {
        "include": ("",),
    },
}


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    input_paths = _input_paths(args.input, Path(args.dataset_dir))
    rows = _load_rows(input_paths)
    rows = [row for row in rows if _row_format(row) == args.format_scope and isinstance(row.get("rl"), dict)]
    rows = [row for row in rows if row.get("row_type") != "terminal" and row.get("action_row_id")]
    rows = [row for row in rows if _target_value(row, args.target) is not None]
    if not rows:
        raise SystemExit("no RL transition rows found")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    graph = _build_graph(_load_rows(input_paths))
    selected_sets = args.feature_set or list(FEATURE_SETS)
    results = []
    for feature_set in selected_sets:
        if feature_set not in FEATURE_SETS:
            raise SystemExit(f"unknown feature set: {feature_set}")
        result = _run_one(feature_set, rows, graph, input_paths, args, output_dir)
        results.append(result)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))

    summary = {
        "input_files": [str(path) for path in input_paths],
        "target": args.target,
        "format_scope": args.format_scope,
        "row_count": len(rows),
        "results": results,
        "ranked_by_policy_regret": sorted(
            results,
            key=lambda item: (
                float(item.get("policy_mean_regret_vs_oracle", 1.0)),
                int(item.get("feature_count", 0)),
            ),
        ),
        "ranked_by_policy_recovery": sorted(
            results,
            key=lambda item: (
                float(item.get("policy_mean_terminal_recovery", 0.0)),
                -int(item.get("feature_count", 0)),
            ),
            reverse=True,
        ),
    }
    (output_dir / "ablation_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run offline RL feature ablations on repair-plan data.")
    parser.add_argument("--dataset-dir", default="repair_training/datasets")
    parser.add_argument("--input", action="append", default=[])
    parser.add_argument("--output-dir", default="repair_training/models/offline_rl/feature_ablation")
    parser.add_argument("--feature-set", action="append", choices=sorted(FEATURE_SETS))
    parser.add_argument("--target", choices=("future_return", "reward", "terminal_reward"), default="future_return")
    parser.add_argument("--format-scope", default="zip")
    parser.add_argument("--split-by", choices=("episode", "source_sample", "query"), default="source_sample")
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--n-estimators", type=int, default=180)
    parser.add_argument("--learning-rate", type=float, default=0.05)
    parser.add_argument("--num-leaves", type=int, default=31)
    parser.add_argument("--min-child-samples", type=int, default=20)
    parser.add_argument("--max-steps", type=int, default=20)
    return parser


def _run_one(feature_set: str, rows: list[dict[str, Any]], graph: dict[str, Any], input_paths: list[Path], args: argparse.Namespace, output_dir: Path) -> dict[str, Any]:
    features = [_filter_features(_feature_dict(row, "runtime_plus_candidate_native_facts"), feature_set) for row in rows]
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
        verbosity=-1,
    )
    model.fit(X[train_idx], y[train_idx])
    scores = model.predict(X)

    feature_dir = output_dir / feature_set
    feature_dir.mkdir(parents=True, exist_ok=True)
    model.booster_.save_model(str(feature_dir / "model.txt"))
    dump(vectorizer, feature_dir / "vectorizer.joblib")
    feature_names = vectorizer.get_feature_names_out().tolist()
    (feature_dir / "feature_names.json").write_text(json.dumps(feature_names, ensure_ascii=False, indent=2), encoding="utf-8")
    predictions = _prediction_rows(rows, scores, eval_idx)
    _write_jsonl(feature_dir / "predictions.jsonl", predictions)

    policy_name = f"ltr:{feature_set}"
    prediction_map = {
        feature_set: {
            "candidate": {
                (str(row.get("query_id") or ""), str(row.get("candidate_id") or "")): float(row.get("score") or 0.0)
                for row in predictions
            },
            "action": {
                (str(row.get("query_id") or ""), str(row.get("action_row_id") or "")): float(row.get("score") or 0.0)
                for row in predictions
                if row.get("action_row_id")
            },
        }
    }
    oracle_cache: dict[str, dict[str, Any]] = {}
    oracle_eval = _evaluate_offline("oracle_upper_bound", graph, prediction_map, args, oracle_cache)
    policy_eval = _evaluate_offline(policy_name, graph, prediction_map, args, oracle_cache)
    metrics = _query_metrics(rows, y, scores, eval_idx)
    result = {
        "feature_set": feature_set,
        "feature_count": len(feature_names),
        "used_feature_count": int(X.shape[1]),
        "query_r2": metrics["r2"],
        "query_mae": metrics["mae"],
        "query_regret_mean": metrics["future_return_regret_mean"],
        "duplicate_query_regret_mean": metrics["duplicate_conflict_regret_mean"],
        "policy_mean_terminal_recovery": policy_eval.get("mean_terminal_recovery"),
        "policy_mean_regret_vs_oracle": policy_eval.get("mean_regret_vs_oracle"),
        "policy_p90_regret_vs_oracle": policy_eval.get("p90_regret_vs_oracle"),
        "policy_duplicate_profile_regret": _duplicate_profile_regret(policy_eval),
        "oracle_mean_terminal_recovery": oracle_eval.get("mean_terminal_recovery"),
        "output_dir": str(feature_dir),
        **{key: value for key, value in split_summary.items() if key in {"split_by", "train_key_count", "eval_key_count"}},
    }
    (feature_dir / "metrics.json").write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return result


def _filter_features(features: dict[str, Any], feature_set: str) -> dict[str, Any]:
    prefixes = _feature_prefixes(feature_set)
    return {key: value for key, value in features.items() if any(key.startswith(prefix) for prefix in prefixes)}


def _feature_prefixes(feature_set: str) -> tuple[str, ...]:
    spec = FEATURE_SETS[feature_set]
    prefixes: list[str] = []
    parent = spec.get("extends")
    if parent:
        prefixes.extend(_feature_prefixes(str(parent)))
    prefixes.extend(str(item) for item in spec.get("include") or ())
    return tuple(dict.fromkeys(prefixes))


def _evaluate_offline(policy: str, graph: dict[str, Any], predictions: dict[str, dict[str, dict[tuple[str, str], float]]], args: argparse.Namespace, oracle_cache: dict[str, dict[str, Any]]) -> dict[str, Any]:
    namespace = argparse.Namespace(seed=args.seed, max_steps=args.max_steps)
    return _evaluate_policy(policy, graph, predictions, namespace, oracle_cache)


def _query_metrics(rows: list[dict[str, Any]], y: np.ndarray, scores: np.ndarray, eval_idx: list[int]) -> dict[str, Any]:
    y_eval = y[eval_idx]
    s_eval = scores[eval_idx]
    by_query: dict[str, list[tuple[dict[str, Any], float]]] = {}
    for idx in eval_idx:
        by_query.setdefault(str(rows[idx].get("query_id") or ""), []).append((rows[idx], float(scores[idx])))
    regrets = []
    duplicate_regrets = []
    for items in by_query.values():
        chosen = max(items, key=lambda item: item[1])[0]
        chosen_return = float(_nested(chosen, "rl", "future_return") or 0.0)
        oracle_return = max(float(_nested(row, "rl", "future_return") or 0.0) for row, _ in items)
        regret = max(0.0, oracle_return - chosen_return)
        regrets.append(regret)
        if any(_is_duplicate_row(row) for row, _ in items):
            duplicate_regrets.append(regret)
    return {
        "mae": float(mean_absolute_error(y_eval, s_eval)) if len(eval_idx) else 0.0,
        "rmse": float(mean_squared_error(y_eval, s_eval) ** 0.5) if len(eval_idx) else 0.0,
        "r2": float(r2_score(y_eval, s_eval)) if len(eval_idx) > 1 else 0.0,
        "future_return_regret_mean": _mean(regrets),
        "duplicate_conflict_regret_mean": _mean(duplicate_regrets),
    }


def _duplicate_profile_regret(policy_eval: dict[str, Any]) -> float:
    values = []
    for item in policy_eval.get("profile_regret_top20") or []:
        key = str(item.get("key") or "")
        if "duplicate" in key:
            values.append(float(item.get("mean_regret") or 0.0))
    return max(values or [0.0])


def _is_duplicate_row(row: dict[str, Any]) -> bool:
    text = " ".join(str(row.get(key) or "") for key in ("sample_id", "episode_id", "module", "module_name"))
    return "duplicate" in text


def _mean(values: list[float]) -> float:
    return float(statistics.mean(values)) if values else 0.0


if __name__ == "__main__":
    raise SystemExit(main())
