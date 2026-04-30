from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


DEFAULT_DATASET_DIR = Path("repair_training") / "datasets"
DEFAULT_OUTPUT_DIR = Path("repair_training") / "models" / "baseline_ltr"
FEATURE_VIEWS = {"stable_only", "stable_plus_teacher", "teacher_only_baseline"}
LABEL_GAIN = {-1: 0, 0: 0, 1: 1, 2: 2, 3: 4}


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    _ensure_training_imports()
    from joblib import dump
    from lightgbm import LGBMRanker
    from sklearn.feature_extraction import DictVectorizer

    rows = _load_rows(args.input)
    if not rows:
        raise SystemExit("no LTR rows found")
    grouped = _group_rows(rows)
    grouped = {query: items for query, items in grouped.items() if items}
    if not grouped:
        raise SystemExit("no non-empty LTR query groups found")

    train_queries, eval_queries = _split_queries(sorted(grouped), int(args.seed))
    eval_skipped = not eval_queries
    feature_rows = []
    labels = []
    query_ids = []
    row_refs = []
    for query_id in train_queries:
        for row in grouped[query_id]:
            feature_rows.append(_row_features(row, args.feature_view))
            labels.append(_gain(row.get("label")))
            query_ids.append(query_id)
            row_refs.append(row)
    vectorizer = DictVectorizer(sparse=True)
    x_train = vectorizer.fit_transform(feature_rows)
    y_train = labels
    train_group = _group_sizes(query_ids)
    ranker = LGBMRanker(
        objective="lambdarank",
        n_estimators=int(args.n_estimators),
        learning_rate=float(args.learning_rate),
        num_leaves=int(args.num_leaves),
        min_child_samples=int(args.min_child_samples),
        random_state=int(args.seed),
        n_jobs=1,
        verbosity=-1,
    )
    if len(set(y_train)) <= 1:
        raise SystemExit("training labels have only one class; collect more varied rows first")
    ranker.fit(x_train, y_train, group=train_group)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ranker.booster_.save_model(str(output_dir / "model.txt"))
    dump(vectorizer, output_dir / "vectorizer.joblib")
    feature_names = list(vectorizer.get_feature_names_out())
    (output_dir / "feature_names.json").write_text(json.dumps(feature_names, ensure_ascii=False, indent=2), encoding="utf-8")

    eval_rows = [row for query in (eval_queries or train_queries) for row in grouped[query]]
    eval_features = [_row_features(row, args.feature_view) for row in eval_rows]
    eval_x = vectorizer.transform(eval_features)
    scores = list(ranker.predict(eval_x))
    metrics = _metrics(eval_rows, scores, eval_skipped=eval_skipped)
    predictions = _prediction_rows(eval_rows, scores)
    _write_jsonl(output_dir / "predictions.jsonl", predictions)
    (output_dir / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    summary = {
        "feature_view": args.feature_view,
        "input_files": [str(path) for path in _input_paths(args.input)],
        "output_dir": str(output_dir),
        "row_count": len(rows),
        "query_count": len(grouped),
        "train_query_count": len(train_queries),
        "eval_query_count": len(eval_queries),
        "eval_skipped": eval_skipped,
        "feature_count": len(feature_names),
        "label_counts": dict(sorted(Counter(str(_gain(row.get("label"))) for row in rows).items())),
        "raw_label_counts": dict(sorted(Counter(str(int(row.get("label", 0) or 0)) for row in rows).items())),
        "metrics": metrics,
    }
    (output_dir / "training_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train a baseline repair-plan LTR ranker from JSONL rows.")
    parser.add_argument("--input", action="append", default=[], help="Input JSONL file. Repeatable; defaults to repair_training/datasets/*.jsonl.")
    parser.add_argument("--feature-view", choices=sorted(FEATURE_VIEWS), default="stable_only")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--n-estimators", type=int, default=80)
    parser.add_argument("--learning-rate", type=float, default=0.05)
    parser.add_argument("--num-leaves", type=int, default=15)
    parser.add_argument("--min-child-samples", type=int, default=3)
    return parser


def _ensure_training_imports() -> None:
    missing = []
    for module in ("lightgbm", "sklearn", "numpy", "scipy", "joblib"):
        try:
            __import__(module)
        except Exception:
            missing.append(module)
    if missing:
        raise SystemExit(f"missing training dependencies: {', '.join(missing)}; run repair_training\\train_ltr.ps1")


def _input_paths(inputs: list[str]) -> list[Path]:
    if inputs:
        paths = [Path(item) for item in inputs]
    else:
        paths = sorted(DEFAULT_DATASET_DIR.glob("*.jsonl"))
    output = []
    for path in paths:
        name = path.name.lower()
        if not path.is_file():
            continue
        if name.startswith("repair_plan_collect_events") or name.endswith(".pretty.json"):
            continue
        output.append(path)
    return output


def _load_rows(inputs: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in _input_paths(inputs):
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(row, dict) and "query_id" in row and "label" in row:
                    rows.append(row)
    return rows


def _group_rows(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get("query_id") or row.get("sample_id") or "")].append(row)
    return dict(grouped)


def _split_queries(queries: list[str], seed: int) -> tuple[list[str], list[str]]:
    if len(queries) < 5:
        return queries, []
    ordered = sorted(queries, key=lambda query: hashlib.sha256(f"{seed}:{query}".encode("utf-8")).hexdigest())
    split = max(1, int(len(ordered) * 0.8))
    if split >= len(ordered):
        return ordered, []
    return sorted(ordered[:split]), sorted(ordered[split:])


def _group_sizes(query_ids: list[str]) -> list[int]:
    counts = []
    previous = None
    current = 0
    for query_id in query_ids:
        if previous is None:
            previous = query_id
        if query_id != previous:
            counts.append(current)
            previous = query_id
            current = 0
        current += 1
    if current:
        counts.append(current)
    return counts


def _gain(label: Any) -> int:
    try:
        raw = int(label or 0)
    except Exception:
        raw = 0
    return int(LABEL_GAIN.get(raw, 0))


def _row_features(row: dict[str, Any], view: str) -> dict[str, Any]:
    features: dict[str, Any] = {}
    _put_scalar(features, "top.material_format", row.get("material_format"))
    _put_scalar(features, "top.format", row.get("format") or _nested(row, "stable_features", "state", "format"))
    _put_scalar(features, "top.damage_profile", _nested(row, "stable_features", "state", "damage_profile"))
    _put_scalar(features, "top.round", row.get("round"))
    if view in {"stable_only", "stable_plus_teacher"}:
        stable = row.get("stable_features") if isinstance(row.get("stable_features"), dict) else {}
        _flatten(features, "state", stable.get("state"))
        _flatten(features, "candidate", stable.get("candidate"))
        _flatten(features, "before_state", stable.get("before_state"))
    if view in {"stable_plus_teacher", "teacher_only_baseline"}:
        _flatten(features, "teacher", row.get("teacher_features"))
    return features


def _flatten(output: dict[str, Any], prefix: str, value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"after_state", "delta_features", "label_details"}:
                continue
            _flatten(output, f"{prefix}.{key}", item)
        return
    if isinstance(value, list):
        for item in value:
            if item is None:
                continue
            token = str(item)
            if token:
                output[f"{prefix}[]={token}"] = 1
        output[f"{prefix}.count"] = len(value)
        return
    _put_scalar(output, prefix, value)


def _put_scalar(output: dict[str, Any], key: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, bool):
        output[key] = int(value)
        return
    if isinstance(value, (int, float)):
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            return
        output[key] = value
        return
    text = str(value)
    if text:
        output[f"{key}={text}"] = 1


def _nested(row: dict[str, Any], *keys: str) -> Any:
    current: Any = row
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _metrics(rows: list[dict[str, Any]], scores: list[float], *, eval_skipped: bool) -> dict[str, Any]:
    by_query: dict[str, list[tuple[dict[str, Any], float]]] = defaultdict(list)
    for row, score in zip(rows, scores):
        by_query[str(row.get("query_id") or "")].append((row, float(score)))
    ndcg1 = []
    ndcg3 = []
    top1_labels = []
    top1_hits = []
    for items in by_query.values():
        ranked = sorted(items, key=lambda item: item[1], reverse=True)
        labels = [_gain(row.get("label")) for row, _ in ranked]
        ideal = sorted(labels, reverse=True)
        ndcg1.append(_ndcg_at(labels, ideal, 1))
        ndcg3.append(_ndcg_at(labels, ideal, 3))
        raw_top = int(ranked[0][0].get("label", 0) or 0)
        top1_labels.append(raw_top)
        best_raw = max(int(row.get("label", 0) or 0) for row, _ in items)
        top1_hits.append(1 if raw_top == best_raw else 0)
    return {
        "eval_skipped": bool(eval_skipped),
        "query_count": len(by_query),
        "row_count": len(rows),
        "label_counts": dict(sorted(Counter(str(int(row.get("label", 0) or 0)) for row in rows).items())),
        "ndcg@1": _mean(ndcg1),
        "ndcg@3": _mean(ndcg3),
        "top1_label_mean": _mean(top1_labels),
        "top1_hit_best_label_rate": _mean(top1_hits),
    }


def _ndcg_at(labels: list[int], ideal: list[int], k: int) -> float:
    dcg = _dcg(labels[:k])
    idcg = _dcg(ideal[:k])
    return 0.0 if idcg <= 0 else dcg / idcg


def _dcg(labels: list[int]) -> float:
    return sum(((2 ** label) - 1) / math.log2(index + 2) for index, label in enumerate(labels))


def _mean(values: list[float | int]) -> float:
    if not values:
        return 0.0
    return float(sum(float(value) for value in values) / len(values))


def _prediction_rows(rows: list[dict[str, Any]], scores: list[float]) -> list[dict[str, Any]]:
    output = []
    for row, score in sorted(zip(rows, scores), key=lambda item: (str(item[0].get("query_id") or ""), -float(item[1]))):
        output.append({
            "query_id": row.get("query_id"),
            "sample_id": row.get("sample_id"),
            "module": row.get("module"),
            "label": row.get("label"),
            "label_status": row.get("label_status"),
            "score": float(score),
            "selected_by_current_system": bool(row.get("selected_by_current_system")),
        })
    return output


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, default=str) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
