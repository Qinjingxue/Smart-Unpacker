"""Train RL model with only 4 state feature groups (no candidate features)."""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np
from lightgbm import LGBMRegressor
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
from repair_training.train_offline_rl import _feature_dict, _flatten, _excluded_feature_key

KEEP_PREFIXES = (
    "state.verification_summary.",
    "state.extraction_summary.",
    "state.job_summary.",
    "top.",
    "candidate.module",
)


def _filter_features(row: dict, view: str) -> dict:
    full = _feature_dict(row, view)
    return {k: v for k, v in full.items() if any(k.startswith(p) for p in KEEP_PREFIXES)}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Train slim RL model (4 state groups only)")
    parser.add_argument("--dataset-dir", default=str(Path("repair_training/datasets")))
    parser.add_argument("--output-dir", default=str(Path("repair_training/models/offline_rl/zip_q_value_slim")))
    parser.add_argument("--format-scope", default="zip")
    parser.add_argument("--target", default="future_return")
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--n-estimators", type=int, default=500)
    parser.add_argument("--learning-rate", type=float, default=0.03)
    parser.add_argument("--num-leaves", type=int, default=63)
    parser.add_argument("--min-child-samples", type=int, default=20)
    args = parser.parse_args(argv)

    dataset_dir = Path(args.dataset_dir)
    rows = []
    for path in sorted(dataset_dir.glob("repair_plan_ltr_*_zip_terminal_recovery.jsonl")):
        with path.open("r", encoding="utf-8") as h:
            for line in h:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict) or not isinstance(row.get("rl"), dict):
                    continue
                if row.get("row_type") == "terminal" or not row.get("action_row_id"):
                    continue
                rl = row["rl"]
                if not isinstance(rl.get("future_return"), (int, float)):
                    continue
                rows.append(row)

    if not rows:
        raise SystemExit("no RL transition rows found")

    print(f"Loaded {len(rows)} rows")

    features = [_filter_features(row, "runtime_only") for row in rows]
    y = np.array([float(row["rl"]["future_return"]) for row in rows], dtype=float)

    vectorizer = DictVectorizer(sparse=True)
    X = vectorizer.fit_transform(features)
    feat_names = list(vectorizer.get_feature_names_out())

    print(f"Features: {len(feat_names)}")
    for p in KEEP_PREFIXES:
        n = sum(1 for f in feat_names if f.startswith(p))
        print(f"  {p}{'*' if n else ''} : {n}")

    # Split by source_sample
    split_keys = []
    for row in rows:
        v = row.get("material_sample_id")
        ep = str(row.get("episode_id") or row.get("sample_id") or "")
        if not v:
            v = ep.split(":")[0].split("_zip_")[0] if ep else ""
        split_keys.append(str(v or "unknown"))

    unique = sorted(set(split_keys))
    ordered = sorted(unique, key=lambda k: hashlib.sha256(f"{args.seed}:{k}".encode("utf-8")).hexdigest())
    split = max(1, int(len(ordered) * 0.8))
    train_keys = set(ordered[:split])
    eval_keys = set(ordered[split:])
    train_idx = [i for i, k in enumerate(split_keys) if k in train_keys]
    eval_idx = [i for i, k in enumerate(split_keys) if k in eval_keys]

    print(f"Train: {len(train_idx)}, Eval: {len(eval_idx)}, Eval keys: {len(eval_keys)}")

    # Train
    model = LGBMRegressor(
        objective="regression",
        n_estimators=args.n_estimators,
        learning_rate=args.learning_rate,
        num_leaves=args.num_leaves,
        min_child_samples=args.min_child_samples,
        random_state=args.seed,
        n_jobs=-1,
    )
    model.fit(X[train_idx], y[train_idx])
    all_scores = model.predict(X)
    eval_scores = all_scores[eval_idx]
    y_eval = y[eval_idx]

    # Standard metrics
    metrics = {
        "r2": float(r2_score(y_eval, eval_scores)) if len(eval_idx) > 1 else 0.0,
        "mae": float(mean_absolute_error(y_eval, eval_scores)) if len(eval_idx) else 0.0,
        "rmse": float(mean_squared_error(y_eval, eval_scores) ** 0.5) if len(eval_idx) else 0.0,
    }

    # Regret
    by_query = defaultdict(list)
    for i in eval_idx:
        by_query[str(rows[i].get("query_id") or "")].append((float(rows[i]["rl"]["future_return"]), float(all_scores[i])))
    top1_returns = []
    oracle_returns = []
    regrets = []
    for items in by_query.values():
        ranked = sorted(items, key=lambda x: x[1], reverse=True)
        top1_returns.append(ranked[0][0])
        oracle_returns.append(max(x[0] for x in items))
        regrets.append(max(0.0, oracle_returns[-1] - top1_returns[-1]))

    metrics.update({
        "eval_query_count": len(by_query),
        "top1_future_return_mean": float(statistics.mean(top1_returns)) if top1_returns else 0.0,
        "oracle_future_return_mean": float(statistics.mean(oracle_returns)) if oracle_returns else 0.0,
        "future_return_regret_mean": float(statistics.mean(regrets)) if regrets else 0.0,
        "future_return_regret_p90": float(np.percentile(sorted(regrets), 90)) if regrets else 0.0,
        "target_mean": float(statistics.mean(y_eval)) if len(y_eval) else 0.0,
        "prediction_mean": float(statistics.mean(eval_scores)) if len(eval_scores) else 0.0,
    })

    # Save
    from joblib import dump
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    model.booster_.save_model(str(output_dir / "model.txt"))
    dump(vectorizer, output_dir / "vectorizer.joblib")
    (output_dir / "feature_names.json").write_text(json.dumps(feat_names, ensure_ascii=False, indent=2), encoding="utf-8")
    (output_dir / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")

    # Print
    print()
    print("=" * 60)
    print("SLIM MODEL RESULTS (4 state groups, no candidate features)")
    print("=" * 60)
    print(f"Features:  {len(feat_names)}")
    print(f"Rows:      {len(rows)} (train: {len(train_idx)}, eval: {len(eval_idx)})")
    print()
    print(f"R2:         {metrics['r2']:.4f}")
    print(f"MAE:        {metrics['mae']:.4f}")
    print(f"RMSE:       {metrics['rmse']:.4f}")
    print(f"Queries:    {metrics['eval_query_count']}")
    print(f"Oracle:     {metrics['oracle_future_return_mean']:.4f}")
    print(f"Top-1:      {metrics['top1_future_return_mean']:.4f}")
    print(f"Regret:     {metrics['future_return_regret_mean']:.6f}")
    print(f"Regret P90: {metrics['future_return_regret_p90']:.6f}")
    print()
    print("COMPARISON vs FULL MODEL:")
    print(f"  Full (219 feat): R2=0.9814  MAE=0.0203  Regret=0.00072")
    print(f"  Slim ({len(feat_names):3d} feat):  R2={metrics['r2']:.4f}  MAE={metrics['mae']:.4f}  Regret={metrics['future_return_regret_mean']:.6f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
