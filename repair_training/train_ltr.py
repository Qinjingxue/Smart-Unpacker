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
FORMAT_SCOPES = {"all", "zip", "tar", "tar_gz", "tar_bz2", "tar_xz", "gzip", "bzip2", "xz", "zstd", "7z", "rar"}
LABEL_TARGETS = {"immediate", "future", "discounted", "blended", "strategy"}
SPLIT_BY = {"query", "episode", "source_sample"}
LABEL_GAIN = {-1: 0, 0: 0, 1: 1, 2: 2, 3: 4}


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    output_dir = Path(args.output_dir)
    _ensure_training_imports()
    from joblib import dump
    from lightgbm import LGBMRanker
    from sklearn.feature_extraction import DictVectorizer

    source_rows = _load_rows(args.input)
    rows = _filter_rows_by_format(source_rows, args.format_scope)
    if not rows:
        _write_skip_summary(output_dir, args, source_rows, rows, "no_rows_for_format_scope")
        return 0
    raw_grouped = _group_rows(rows)
    grouped = _filter_groups(raw_grouped, args)
    if not grouped:
        _write_skip_summary(output_dir, args, source_rows, rows, "candidate_competition_too_low", raw_grouped=raw_grouped, grouped=grouped)
        return 0
    if len(grouped) < int(args.min_trainable_queries):
        _write_skip_summary(output_dir, args, source_rows, rows, "too_few_queries", raw_grouped=raw_grouped, grouped=grouped)
        return 0

    train_queries, eval_queries, split_info = _split_groups(grouped, args)
    eval_skipped = not eval_queries
    feature_rows = []
    labels = []
    sample_weights = []
    query_ids = []
    row_refs = []
    for query_id in train_queries:
        for row in grouped[query_id]:
            feature_rows.append(_row_features(row, args.feature_view, args.format_scope))
            labels.append(_target_gain(row, args.label_target))
            sample_weights.append(_target_weight(row, args.label_target))
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
        _write_skip_summary(output_dir, args, source_rows, rows, "label_single_class", raw_grouped=raw_grouped, grouped=grouped)
        return 0
    ranker.fit(x_train, y_train, group=train_group, sample_weight=sample_weights)

    output_dir.mkdir(parents=True, exist_ok=True)
    ranker.booster_.save_model(str(output_dir / "model.txt"))
    dump(vectorizer, output_dir / "vectorizer.joblib")
    feature_names = list(vectorizer.get_feature_names_out())
    (output_dir / "feature_names.json").write_text(json.dumps(feature_names, ensure_ascii=False, indent=2), encoding="utf-8")

    eval_rows = [row for query in (eval_queries or train_queries) for row in grouped[query]]
    eval_features = [_row_features(row, args.feature_view, args.format_scope) for row in eval_rows]
    eval_x = vectorizer.transform(eval_features)
    scores = list(ranker.predict(eval_x))
    metrics = _metrics(eval_rows, scores, eval_skipped=eval_skipped, label_target=args.label_target)
    predictions = _prediction_rows(eval_rows, scores, args.label_target)
    _write_jsonl(output_dir / "predictions.jsonl", predictions)
    (output_dir / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    summary = {
        "feature_view": args.feature_view,
        "format_scope": args.format_scope,
        "label_target": args.label_target,
        "input_files": [str(path) for path in _input_paths(args.input)],
        "output_dir": str(output_dir),
        "source_row_count": len(source_rows),
        "row_count": len(rows),
        "query_count": len(grouped),
        "unfiltered_query_count": len(raw_grouped),
        "filtered_query_count": max(0, len(raw_grouped) - len(grouped)),
        "filtered_row_count": max(0, sum(len(items) for items in raw_grouped.values()) - sum(len(items) for items in grouped.values())),
        "min_candidates_per_query": _min_candidates(args),
        "train_query_count": len(train_queries),
        "eval_query_count": len(eval_queries),
        "eval_skipped": eval_skipped,
        **split_info,
        "feature_count": len(feature_names),
        "label_target": args.label_target,
        "label_counts": dict(sorted(Counter(str(_target_gain(row, args.label_target)) for row in rows).items())),
        "raw_label_counts": dict(sorted(Counter(str(int(row.get("label", 0) or 0)) for row in rows).items())),
        "target_label_counts": dict(sorted(Counter(str(_target_gain(row, args.label_target)) for row in rows).items())),
        "target_weight_counts": dict(sorted(Counter(str(_target_weight(row, args.label_target)) for row in rows).items())),
        "metrics": metrics,
    }
    (output_dir / "training_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train a baseline repair-plan LTR ranker from JSONL rows.")
    parser.add_argument("--input", action="append", default=[], help="Input JSONL file. Repeatable; defaults to repair_training/datasets/*.jsonl.")
    parser.add_argument("--feature-view", choices=sorted(FEATURE_VIEWS), default="stable_only")
    parser.add_argument("--format-scope", choices=sorted(FORMAT_SCOPES), default="all", help="Train on one material format, or all rows for the legacy unified baseline.")
    parser.add_argument("--label-target", choices=sorted(LABEL_TARGETS), default="immediate", help="Which collected label target to optimize.")
    parser.add_argument("--split-by", choices=sorted(SPLIT_BY), default="query", help="Split train/eval by query, episode, or source material sample.")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--n-estimators", type=int, default=80)
    parser.add_argument("--learning-rate", type=float, default=0.05)
    parser.add_argument("--num-leaves", type=int, default=15)
    parser.add_argument("--min-child-samples", type=int, default=3)
    parser.add_argument("--min-candidates-per-query", type=int, default=2, help="Filter query groups with fewer candidates. Defaults to 2.")
    parser.add_argument("--include-single-candidate-queries", action="store_true", help="Disable low-value single-candidate query filtering.")
    parser.add_argument("--min-trainable-queries", type=int, default=30, help="Skip training and write skip_summary.json when fewer query groups remain.")
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
                if isinstance(row, dict) and "query_id" in row and "label" in row and row.get("row_type") != "terminal":
                    rows.append(row)
    return rows


def _filter_rows_by_format(rows: list[dict[str, Any]], format_scope: str) -> list[dict[str, Any]]:
    if format_scope == "all":
        return rows
    return [row for row in rows if _row_format_scope(row) == format_scope]


def _row_format_scope(row: dict[str, Any]) -> str:
    value = row.get("material_format")
    if not value:
        value = row.get("format") or _nested(row, "stable_features", "state", "format")
    return _normalize_format_scope(str(value or ""))


def _normalize_format_scope(value: str) -> str:
    normalized = value.strip().lower().replace(".", "_").replace("-", "_")
    aliases = {
        "tgz": "tar_gz",
        "tar_gzip": "tar_gz",
        "tbz": "tar_bz2",
        "tbz2": "tar_bz2",
        "tar_bzip2": "tar_bz2",
        "txz": "tar_xz",
        "tar_zst": "tar_zst",
        "seven_zip": "7z",
    }
    return aliases.get(normalized, normalized)


def _group_rows(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get("query_id") or row.get("sample_id") or "")].append(row)
    return dict(grouped)


def _filter_groups(grouped: dict[str, list[dict[str, Any]]], args: argparse.Namespace) -> dict[str, list[dict[str, Any]]]:
    minimum = _min_candidates(args)
    return {query: items for query, items in grouped.items() if items and len(items) >= minimum}


def _min_candidates(args: argparse.Namespace) -> int:
    if bool(getattr(args, "include_single_candidate_queries", False)):
        return 1
    return max(1, int(getattr(args, "min_candidates_per_query", 2) or 2))


def _split_groups(grouped: dict[str, list[dict[str, Any]]], args: argparse.Namespace) -> tuple[list[str], list[str], dict[str, Any]]:
    split_by = str(getattr(args, "split_by", "query") or "query")
    seed = int(getattr(args, "seed", 2026) or 2026)
    queries = sorted(grouped)
    if split_by == "query":
        train, eval_ = _split_keys(queries, seed)
        return train, eval_, {
            "split_by": "query",
            "split_fallback": "",
            "train_source_count": 0,
            "eval_source_count": 0,
            "train_sources": [],
            "eval_sources": [],
        }
    query_to_source: dict[str, str] = {}
    source_to_queries: dict[str, list[str]] = defaultdict(list)
    for query in queries:
        rows = grouped.get(query) or []
        source = _split_source_key(rows[0] if rows else {}, split_by)
        query_to_source[query] = source
        source_to_queries[source].append(query)
    sources = sorted(source_to_queries)
    if len(sources) < 2:
        train, eval_ = _split_keys(queries, seed)
        return train, eval_, {
            "split_by": split_by,
            "split_fallback": "query_too_few_sources",
            "train_source_count": len(set(query_to_source.get(query, "") for query in train)),
            "eval_source_count": len(set(query_to_source.get(query, "") for query in eval_)),
            "train_sources": sorted(set(query_to_source.get(query, "") for query in train))[:200],
            "eval_sources": sorted(set(query_to_source.get(query, "") for query in eval_))[:200],
        }
    train_sources, eval_sources = _split_keys(sources, seed)
    if not eval_sources:
        train_sources, eval_sources = sources, []
    train_set = set(train_sources)
    eval_set = set(eval_sources)
    train = sorted(query for query in queries if query_to_source.get(query) in train_set)
    eval_ = sorted(query for query in queries if query_to_source.get(query) in eval_set)
    return train, eval_, {
        "split_by": split_by,
        "split_fallback": "",
        "train_source_count": len(train_sources),
        "eval_source_count": len(eval_sources),
        "train_sources": train_sources[:200],
        "eval_sources": eval_sources[:200],
    }


def _split_keys(keys: list[str], seed: int) -> tuple[list[str], list[str]]:
    if len(keys) < 5:
        return sorted(keys), []
    ordered = sorted(keys, key=lambda key: hashlib.sha256(f"{seed}:{key}".encode("utf-8")).hexdigest())
    split = max(1, int(len(ordered) * 0.8))
    if split >= len(ordered):
        return ordered, []
    return sorted(ordered[:split]), sorted(ordered[split:])


def _split_source_key(row: dict[str, Any], split_by: str) -> str:
    if split_by == "episode":
        value = row.get("episode_id") or row.get("sample_id") or row.get("query_id")
        return str(value or "unknown")
    if split_by == "source_sample":
        value = row.get("material_sample_id")
        if not value:
            derivation = row.get("source_derivation") if isinstance(row.get("source_derivation"), dict) else {}
            value = derivation.get("sample_id") or derivation.get("source_sample_id")
        if not value:
            episode = str(row.get("episode_id") or row.get("sample_id") or row.get("query_id") or "")
            value = episode.split(":")[0].split("_zip_")[0] if episode else ""
        return str(value or "unknown")
    return str(row.get("query_id") or "unknown")


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


def _target_gain(row: dict[str, Any], target: str) -> int:
    target = str(target or "immediate")
    targets = row.get("training_targets") if isinstance(row.get("training_targets"), dict) else {}
    if target == "future":
        return int(_gain(targets.get("future_gain", row.get("label"))))
    if target == "discounted":
        value = targets.get("discounted_gain")
        if value is None:
            details = row.get("label_details") if isinstance(row.get("label_details"), dict) else {}
            value = details.get("discounted_future_gain")
        return _rank_label_from_gain_float(_gain_float(value, fallback=row.get("label")))
    if target == "blended":
        value = targets.get("blended_gain")
        return _rank_label_from_gain_float(_gain_float(value, fallback=row.get("label")))
    if target == "strategy":
        value = targets.get("strategy_gain")
        if value is None:
            details = row.get("label_details") if isinstance(row.get("label_details"), dict) else {}
            value = details.get("strategy_gain")
        return _strategy_rank_label(row, value)
    return int(_gain(row.get("label")))


def _strategy_rank_label(row: dict[str, Any], value: Any) -> int:
    targets = row.get("training_targets") if isinstance(row.get("training_targets"), dict) else {}
    risk_class = str(targets.get("risk_class") or "")
    if risk_class.startswith("hard_negative") or int(row.get("label", 0) or 0) < 0:
        return 0
    gain = _gain_float(value, fallback=row.get("label"))
    if gain <= 0:
        return 1
    if gain < 2:
        return 2
    if gain < 3:
        return 3
    return 5


def _target_weight(row: dict[str, Any], target: str) -> float:
    if str(target or "") != "strategy":
        return 1.0
    targets = row.get("training_targets") if isinstance(row.get("training_targets"), dict) else {}
    try:
        hard_weight = float(targets.get("hard_negative_weight", 0.0) or 0.0)
    except Exception:
        hard_weight = 0.0
    if hard_weight > 0:
        return 1.0 + hard_weight
    return 1.0


def _rank_label_from_gain_float(value: float) -> int:
    if value <= 0:
        return 0
    return max(0, min(4, int(math.ceil(float(value)))))


def _gain_float(value: Any, *, fallback: Any = 0) -> float:
    try:
        if value is None:
            return float(_gain(fallback))
        raw = float(value)
    except Exception:
        return float(_gain(fallback))
    # Stored future targets use raw labels; map integer labels to LambdaMART gains
    # while preserving discounted/blended fractional distance.
    if raw in LABEL_GAIN:
        return float(LABEL_GAIN[int(raw)])
    lower = math.floor(raw)
    upper = math.ceil(raw)
    if lower == upper:
        return float(LABEL_GAIN.get(int(lower), 0))
    low_gain = float(LABEL_GAIN.get(int(lower), 0))
    high_gain = float(LABEL_GAIN.get(int(upper), low_gain))
    return low_gain + (high_gain - low_gain) * (raw - lower)


def _row_features(row: dict[str, Any], view: str, format_scope: str = "all") -> dict[str, Any]:
    features: dict[str, Any] = {}
    if format_scope == "all":
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


def _write_skip_summary(
    output_dir: Path,
    args: argparse.Namespace,
    source_rows: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    reason: str,
    *,
    raw_grouped: dict[str, list[dict[str, Any]]] | None = None,
    grouped: dict[str, list[dict[str, Any]]] | None = None,
) -> None:
    raw_grouped = raw_grouped if raw_grouped is not None else _group_rows(rows)
    grouped = grouped if grouped is not None else _filter_groups(raw_grouped, args)
    output_dir.mkdir(parents=True, exist_ok=True)
    for stale in ("model.txt", "vectorizer.joblib", "feature_names.json", "metrics.json", "predictions.jsonl", "training_summary.json"):
        path = output_dir / stale
        if path.exists():
            path.unlink()
    label_values = [int(row.get("label", 0) or 0) for row in rows]
    summary = {
        "skipped": True,
        "skip_reason": reason,
        "feature_view": args.feature_view,
        "format_scope": args.format_scope,
        "split_by": str(getattr(args, "split_by", "query") or "query"),
        "input_files": [str(path) for path in _input_paths(args.input)],
        "output_dir": str(output_dir),
        "source_row_count": len(source_rows),
        "row_count": len(rows),
        "raw_query_count": len(raw_grouped),
        "query_count": len(grouped),
        "filtered_query_count": max(0, len(raw_grouped) - len(grouped)),
        "filtered_row_count": max(0, sum(len(items) for items in raw_grouped.values()) - sum(len(items) for items in grouped.values())),
        "min_candidates_per_query": _min_candidates(args),
        "min_trainable_queries": int(args.min_trainable_queries),
        "raw_label_counts": dict(sorted(Counter(str(value) for value in label_values).items())),
        "label_gain_counts": dict(sorted(Counter(str(_target_gain(row, args.label_target)) for row in rows).items())),
        "target_weight_counts": dict(sorted(Counter(str(_target_weight(row, args.label_target)) for row in rows).items())),
        "has_multiple_labels": len(set(_target_gain(row, args.label_target) for row in rows)) > 1,
        "has_candidate_competition": any(len(items) >= _min_candidates(args) for items in raw_grouped.values()),
    }
    (output_dir / "skip_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


def _flatten(output: dict[str, Any], prefix: str, value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"after_state", "delta_features", "label_details", "difficulty_tags"}:
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


def _metrics(rows: list[dict[str, Any]], scores: list[float], *, eval_skipped: bool, label_target: str) -> dict[str, Any]:
    by_query: dict[str, list[tuple[dict[str, Any], float]]] = defaultdict(list)
    for row, score in zip(rows, scores):
        by_query[str(row.get("query_id") or "")].append((row, float(score)))
    ndcg1 = []
    ndcg3 = []
    top1_labels = []
    top1_hits = []
    for items in by_query.values():
        ranked = sorted(items, key=lambda item: item[1], reverse=True)
        labels = [_target_gain(row, label_target) for row, _ in ranked]
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
        "label_target": label_target,
        "label_counts": dict(sorted(Counter(str(int(row.get("label", 0) or 0)) for row in rows).items())),
        "target_label_counts": dict(sorted(Counter(str(_target_gain(row, label_target)) for row in rows).items())),
        "target_weight_counts": dict(sorted(Counter(str(_target_weight(row, label_target)) for row in rows).items())),
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


def _prediction_rows(rows: list[dict[str, Any]], scores: list[float], label_target: str) -> list[dict[str, Any]]:
    output = []
    for row, score in sorted(zip(rows, scores), key=lambda item: (str(item[0].get("query_id") or ""), -float(item[1]))):
        output.append({
            "query_id": row.get("query_id"),
            "sample_id": row.get("sample_id"),
            "module": row.get("module"),
            "label": row.get("label"),
            "target_gain": _target_gain(row, label_target),
            "target_weight": _target_weight(row, label_target),
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
