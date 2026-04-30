from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


DEFAULT_DATASET_DIR = Path("repair_training") / "datasets"
DEFAULT_MODEL_ROOT = Path("repair_training") / "models"
DEFAULT_OUTPUT = DEFAULT_DATASET_DIR / "ltr_data_quality_report.json"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    rows = _load_rows(_input_paths(args.input, Path(args.dataset_dir)))
    report = _build_report(rows, Path(args.model_root))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")
    if args.markdown:
        _markdown_path(output).write_text(_markdown_report(report), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, default=str))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Summarize repair-plan LTR dataset quality.")
    parser.add_argument("--dataset-dir", default=str(DEFAULT_DATASET_DIR), help="Directory containing LTR JSONL datasets.")
    parser.add_argument("--input", action="append", default=[], help="Input JSONL file. Repeatable; defaults to --dataset-dir/*.jsonl.")
    parser.add_argument("--model-root", default=str(DEFAULT_MODEL_ROOT), help="Root containing trained LTR model summaries.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="JSON report output path.")
    parser.add_argument("--markdown", action="store_true", help="Also write a compact Markdown report next to --output.")
    return parser


def _input_paths(inputs: list[str], dataset_dir: Path) -> list[Path]:
    paths = [Path(item) for item in inputs] if inputs else sorted(dataset_dir.glob("*.jsonl"))
    output = []
    for path in paths:
        name = path.name.lower()
        if not path.is_file():
            continue
        if name.startswith("repair_plan_collect_events") or name.endswith(".pretty.json"):
            continue
        if name.startswith("predictions"):
            continue
        output.append(path)
    return output


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
                if isinstance(row, dict) and ("query_id" in row or "sample_id" in row):
                    row["_source_file"] = str(path)
                    rows.append(row)
    return rows


def _build_report(rows: list[dict[str, Any]], model_root: Path) -> dict[str, Any]:
    query_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        query_groups[str(row.get("query_id") or row.get("sample_id") or "")].append(row)
    label_counts = Counter(str(int(row.get("label", 0) or 0)) for row in rows)
    status_counts = Counter(str(row.get("label_status") or "unknown") for row in rows)
    format_counts = Counter(_row_format(row) for row in rows)
    module_counts = Counter(str(row.get("module") or "<none>") for row in rows)
    source_counts = Counter(str(row.get("_source_file") or "") for row in rows)
    query_sizes = [len(items) for items in query_groups.values()]
    best_labels = [max((int(row.get("label", 0) or 0) for row in items), default=0) for items in query_groups.values()]
    no_candidate_rows = sum(1 for row in rows if str(row.get("label_status") or "") == "no_candidates")
    failed_rows = sum(1 for row in rows if str(row.get("label_status") or "") in {"failed", "timeout"})
    timeout_rows = sum(1 for row in rows if str(row.get("label_status") or "") == "timeout")
    partial_rows = sum(1 for row in rows if int(row.get("label", 0) or 0) == 1 or str(row.get("label_status") or "") == "partial")
    state_progress_rows = sum(1 for row in rows if int(row.get("label", 0) or 0) == 2 or str(row.get("label_status") or "") == "state_progress")
    total = max(1, len(rows))
    model_metrics = _model_metrics(model_root, source_counts, len(rows))
    report = {
        "dataset": {
            "row_count": len(rows),
            "query_count": len(query_groups),
            "source_files": dict(sorted(source_counts.items())),
        },
        "label_distribution": dict(sorted(label_counts.items(), key=lambda item: int(item[0]))),
        "sample_best_label_distribution": dict(sorted(Counter(str(label) for label in best_labels).items(), key=lambda item: int(item[0]))),
        "label_status_distribution": dict(sorted(status_counts.items())),
        "format_distribution": dict(sorted(format_counts.items())),
        "module_distribution_top20": dict(module_counts.most_common(20)),
        "query_candidate_count": _series_summary(query_sizes),
        "query_candidate_count_distribution": dict(sorted(Counter(str(size) for size in query_sizes).items(), key=lambda item: int(item[0]))),
        "quality_ratios": {
            "partial_row_ratio": partial_rows / total,
            "state_progress_row_ratio": state_progress_rows / total,
            "no_candidate_row_ratio": no_candidate_rows / total,
            "timeout_or_failed_row_ratio": failed_rows / total,
        },
        "failure_signal_counts": {
            "no_candidate_rows": no_candidate_rows,
            "timeout_rows": timeout_rows,
            "failed_or_timeout_rows": failed_rows,
        },
        "format_detection_quality": _format_detection_quality(rows),
        "per_format": _per_format_report(rows, model_metrics),
        "model_metric_comparison": model_metrics,
    }
    report["warnings"] = _quality_warnings(report)
    return report


def _row_format(row: dict[str, Any]) -> str:
    if row.get("material_format"):
        return str(row["material_format"])
    stable = row.get("stable_features") if isinstance(row.get("stable_features"), dict) else {}
    state = stable.get("state") if isinstance(stable.get("state"), dict) else {}
    return str(row.get("format") or state.get("format") or "unknown")


def _per_format_report(rows: list[dict[str, Any]], model_metrics: dict[str, Any]) -> dict[str, Any]:
    by_format: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_format[_row_format(row)].append(row)
    output: dict[str, Any] = {}
    for fmt, items in sorted(by_format.items()):
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in items:
            groups[str(row.get("query_id") or row.get("sample_id") or "")].append(row)
        query_sizes = [len(values) for values in groups.values()]
        labels = Counter(str(int(row.get("label", 0) or 0)) for row in items)
        statuses = Counter(str(row.get("label_status") or "unknown") for row in items)
        modules = Counter(str(row.get("module") or "<none>") for row in items)
        output[fmt] = {
            "row_count": len(items),
            "query_count": len(groups),
            "label_distribution": dict(sorted(labels.items(), key=lambda item: int(item[0]))),
            "label_status_distribution": dict(sorted(statuses.items())),
            "query_candidate_count": _series_summary(query_sizes),
            "query_candidate_count_distribution": dict(sorted(Counter(str(size) for size in query_sizes).items(), key=lambda item: int(item[0]))),
            "quality_ratios": _quality_ratios(items),
            "module_distribution_top10": dict(modules.most_common(10)),
            "trainability": _format_trainability(items, groups),
            "model_metrics": _metrics_for_format(model_metrics, fmt),
        }
    return output


def _quality_ratios(rows: list[dict[str, Any]]) -> dict[str, float]:
    total = max(1, len(rows))
    return {
        "partial_row_ratio": sum(1 for row in rows if int(row.get("label", 0) or 0) == 1 or str(row.get("label_status") or "") == "partial") / total,
        "state_progress_row_ratio": sum(1 for row in rows if int(row.get("label", 0) or 0) == 2 or str(row.get("label_status") or "") == "state_progress") / total,
        "complete_row_ratio": sum(1 for row in rows if int(row.get("label", 0) or 0) == 3 or str(row.get("label_status") or "") == "complete") / total,
        "hard_negative_row_ratio": sum(1 for row in rows if int(row.get("label", 0) or 0) == -1 or str(row.get("label_status") or "") == "hard_negative") / total,
    }


def _format_trainability(rows: list[dict[str, Any]], groups: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    candidate_groups = {query: items for query, items in groups.items() if len(items) >= 2}
    gains = {_label_gain(row.get("label")) for row in rows}
    reasons = []
    if len(candidate_groups) < 30:
        reasons.append("too_few_queries")
    if len(gains) < 2:
        reasons.append("label_single_class")
    if not candidate_groups:
        reasons.append("candidate_competition_too_low")
    return {
        "trainable": not reasons,
        "reasons": reasons,
        "candidate_query_count": len(candidate_groups),
        "label_gain_count": len(gains),
    }


def _label_gain(label: Any) -> int:
    try:
        raw = int(label or 0)
    except Exception:
        raw = 0
    return {-1: 0, 0: 0, 1: 1, 2: 2, 3: 4}.get(raw, 0)


def _metrics_for_format(model_metrics: dict[str, Any], fmt: str) -> dict[str, Any]:
    prefix = f"{fmt}/"
    output = {}
    for key, value in model_metrics.items():
        if key.startswith(prefix):
            output[key[len(prefix):]] = value
    return output


def _format_detection_quality(rows: list[dict[str, Any]]) -> dict[str, Any]:
    mismatches = []
    compared_top = 0
    matched_top = 0
    compared_state = 0
    matched_state = 0
    for row in rows:
        material = _normalize_format_name(row.get("material_format"))
        if not material:
            continue
        top = _normalize_format_name(row.get("format"))
        state = _normalize_format_name(_nested(row, "stable_features", "state", "format"))
        if top:
            compared_top += 1
            matched_top += 1 if top == material else 0
        if state:
            compared_state += 1
            matched_state += 1 if state == material else 0
        if (top and top != material) or (state and state != material):
            mismatches.append({
                "query_id": row.get("query_id"),
                "sample_id": row.get("sample_id"),
                "material_format": row.get("material_format"),
                "top_format": row.get("format"),
                "state_format": _nested(row, "stable_features", "state", "format"),
            })
    return {
        "top_format_compared": compared_top,
        "top_format_match_ratio": matched_top / max(1, compared_top),
        "state_format_compared": compared_state,
        "state_format_match_ratio": matched_state / max(1, compared_state),
        "mismatch_count": len(mismatches),
        "mismatches_sample": mismatches[:50],
    }


def _normalize_format_name(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace(".", "_").replace("-", "_")
    aliases = {
        "tgz": "tar_gz",
        "tar_gzip": "tar_gz",
        "tbz": "tar_bz2",
        "tbz2": "tar_bz2",
        "tar_bzip2": "tar_bz2",
        "txz": "tar_xz",
        "seven_zip": "7z",
    }
    return aliases.get(normalized, normalized)


def _nested(row: dict[str, Any], *keys: str) -> Any:
    current: Any = row
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _series_summary(values: list[int]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "min": 0, "p50": 0, "p90": 0, "max": 0, "mean": 0.0}
    ordered = sorted(values)
    return {
        "count": len(values),
        "min": ordered[0],
        "p50": _percentile(ordered, 0.50),
        "p90": _percentile(ordered, 0.90),
        "max": ordered[-1],
        "mean": statistics.mean(ordered),
    }


def _percentile(ordered: list[int], ratio: float) -> float:
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, int(math.ceil(len(ordered) * ratio) - 1)))
    return float(ordered[index])


def _model_metrics(model_root: Path, source_counts: Counter[str], row_count: int) -> dict[str, Any]:
    output: dict[str, Any] = {}
    if not model_root.is_dir():
        return output
    current_sources = {_normalize_path(path) for path in source_counts if path}
    for summary_path in sorted(model_root.rglob("training_summary.json")):
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        view = str(summary.get("feature_view") or summary_path.parent.name)
        key = str(summary_path.parent.relative_to(model_root)).replace("\\", "/")
        summary_sources = {_normalize_path(path) for path in summary.get("input_files", []) if path}
        summary_row_count = int(summary.get("row_count") or 0)
        format_scope = str(summary.get("format_scope") or "all")
        stale_reasons = []
        if current_sources and summary_sources and current_sources != summary_sources:
            stale_reasons.append("input_files_differ")
        if format_scope == "all" and row_count and summary_row_count and row_count != summary_row_count:
            stale_reasons.append("row_count_differs")
        output[key] = {
            "feature_view": view,
            "format_scope": format_scope,
            "row_count": summary.get("row_count"),
            "query_count": summary.get("query_count"),
            "feature_count": summary.get("feature_count"),
            "metrics": summary.get("metrics", {}),
            "matches_current_dataset": not stale_reasons,
            "stale_reasons": stale_reasons,
        }
    for summary_path in sorted(model_root.rglob("skip_summary.json")):
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        view = str(summary.get("feature_view") or summary_path.parent.name)
        key = str(summary_path.parent.relative_to(model_root)).replace("\\", "/")
        summary_sources = {_normalize_path(path) for path in summary.get("input_files", []) if path}
        stale_reasons = []
        if current_sources and summary_sources and current_sources != summary_sources:
            stale_reasons.append("input_files_differ")
        output[key] = {
            "feature_view": view,
            "format_scope": str(summary.get("format_scope") or "all"),
            "status": "skipped",
            "skip_reason": summary.get("skip_reason"),
            "row_count": summary.get("row_count"),
            "query_count": summary.get("query_count"),
            "feature_count": 0,
            "metrics": {},
            "matches_current_dataset": not stale_reasons,
            "stale_reasons": stale_reasons,
        }
    return output


def _normalize_path(value: str) -> str:
    try:
        return str(Path(value).resolve()).replace("\\", "/").lower()
    except Exception:
        return str(value).replace("\\", "/").lower()


def _quality_warnings(report: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    row_count = max(1, int(report.get("dataset", {}).get("row_count", 0) or 0))
    formats = report.get("format_distribution", {}) if isinstance(report.get("format_distribution"), dict) else {}
    zip_ratio = int(formats.get("zip", 0) or 0) / row_count
    if zip_ratio > 0.5:
        warnings.append("zip_dominates_dataset")
    for fmt, count in formats.items():
        if int(count or 0) / row_count < 0.05:
            warnings.append(f"format_underrepresented:{fmt}")
    stream_rows = sum(int(formats.get(fmt, 0) or 0) for fmt in ("gzip", "bzip2", "xz", "zstd"))
    labels = report.get("label_distribution", {}) if isinstance(report.get("label_distribution"), dict) else {}
    positive_rows = sum(int(labels.get(str(label), 0) or 0) for label in (1, 2, 3))
    if stream_rows / row_count > 0.3 and positive_rows == 0:
        warnings.append("stream_rows_no_positive_labels")
    negative_ratio = (int(labels.get("-1", 0) or 0) + int(labels.get("0", 0) or 0)) / row_count
    if negative_ratio < 0.15:
        warnings.append("negative_labels_too_sparse")
    candidate_distribution = report.get("query_candidate_count_distribution", {}) if isinstance(report.get("query_candidate_count_distribution"), dict) else {}
    query_count = max(1, int(report.get("dataset", {}).get("query_count", 0) or 0))
    single_ratio = int(candidate_distribution.get("1", 0) or 0) / query_count
    if single_ratio > 0.1:
        warnings.append("too_many_single_candidate_queries")
    candidate_summary = report.get("query_candidate_count", {}) if isinstance(report.get("query_candidate_count"), dict) else {}
    if float(candidate_summary.get("p90", 0.0) or 0.0) <= 2.0:
        warnings.append("low_candidate_competition")
    ratios = report.get("quality_ratios", {}) if isinstance(report.get("quality_ratios"), dict) else {}
    if float(ratios.get("timeout_or_failed_row_ratio", 0.0) or 0.0) > 0.02:
        warnings.append("timeouts_present")
    metrics = report.get("model_metric_comparison", {}) if isinstance(report.get("model_metric_comparison"), dict) else {}
    if any(isinstance(item, dict) and not item.get("matches_current_dataset", True) for item in metrics.values()):
        warnings.append("model_metrics_stale")
    stable = _model_ndcg(metrics, "stable_only")
    teacher = _model_ndcg(metrics, "teacher_only_baseline")
    if stable is not None and teacher is not None and stable > 0.95 and abs(stable - teacher) < 0.05:
        warnings.append("dataset_may_be_too_easy")
    per_format = report.get("per_format", {}) if isinstance(report.get("per_format"), dict) else {}
    for fmt, item in per_format.items():
        if not isinstance(item, dict):
            continue
        trainability = item.get("trainability") if isinstance(item.get("trainability"), dict) else {}
        for reason in trainability.get("reasons", []) or []:
            if reason == "too_few_queries":
                warnings.append(f"format_too_few_queries:{fmt}")
            elif reason == "label_single_class":
                warnings.append(f"format_label_single_class:{fmt}")
            elif reason == "candidate_competition_too_low":
                warnings.append(f"format_low_candidate_competition:{fmt}")
        if not trainability.get("trainable", False):
            warnings.append(f"format_not_trainable:{fmt}")
    return warnings


def _model_ndcg(metrics: dict[str, Any], view: str) -> float | None:
    for item in metrics.values():
        if not isinstance(item, dict) or item.get("feature_view") != view:
            continue
        if not item.get("matches_current_dataset", True):
            continue
        inner = item.get("metrics") if isinstance(item.get("metrics"), dict) else {}
        try:
            return float(inner.get("ndcg@1"))
        except Exception:
            return None
    return None


def _markdown_path(path: Path) -> Path:
    return path.with_suffix(".md")


def _markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# LTR Data Quality Report",
        "",
        f"- Rows: {report['dataset']['row_count']}",
        f"- Queries: {report['dataset']['query_count']}",
        f"- Labels: `{json.dumps(report['label_distribution'], ensure_ascii=False, sort_keys=True)}`",
        f"- Best labels: `{json.dumps(report['sample_best_label_distribution'], ensure_ascii=False, sort_keys=True)}`",
        f"- Formats: `{json.dumps(report['format_distribution'], ensure_ascii=False, sort_keys=True)}`",
        f"- Candidate count: `{json.dumps(report['query_candidate_count'], ensure_ascii=False, sort_keys=True)}`",
        f"- Quality ratios: `{json.dumps(report['quality_ratios'], ensure_ascii=False, sort_keys=True)}`",
        f"- Format detection: `{json.dumps(report.get('format_detection_quality', {}), ensure_ascii=False, sort_keys=True)}`",
        f"- Warnings: `{json.dumps(report.get('warnings', []), ensure_ascii=False, sort_keys=True)}`",
        "",
        "## Per Format",
    ]
    for fmt, item in report.get("per_format", {}).items():
        lines.append(f"- `{fmt}`: rows={item.get('row_count')} queries={item.get('query_count')} labels=`{json.dumps(item.get('label_distribution', {}), ensure_ascii=False, sort_keys=True)}` trainable=`{json.dumps(item.get('trainability', {}), ensure_ascii=False, sort_keys=True)}`")
    lines.extend([
        "",
        "## Model Metrics",
    ])
    for name, item in report.get("model_metric_comparison", {}).items():
        lines.append(f"- `{name}`: `{json.dumps(item.get('metrics', {}), ensure_ascii=False, sort_keys=True)}`")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
