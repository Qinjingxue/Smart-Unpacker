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
        "model_metric_comparison": _model_metrics(model_root),
    }
    return report


def _row_format(row: dict[str, Any]) -> str:
    if row.get("material_format"):
        return str(row["material_format"])
    stable = row.get("stable_features") if isinstance(row.get("stable_features"), dict) else {}
    state = stable.get("state") if isinstance(stable.get("state"), dict) else {}
    return str(row.get("format") or state.get("format") or "unknown")


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


def _model_metrics(model_root: Path) -> dict[str, Any]:
    output: dict[str, Any] = {}
    if not model_root.is_dir():
        return output
    for summary_path in sorted(model_root.rglob("training_summary.json")):
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        view = str(summary.get("feature_view") or summary_path.parent.name)
        key = str(summary_path.parent.relative_to(model_root)).replace("\\", "/")
        output[key] = {
            "feature_view": view,
            "row_count": summary.get("row_count"),
            "query_count": summary.get("query_count"),
            "feature_count": summary.get("feature_count"),
            "metrics": summary.get("metrics", {}),
        }
    return output


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
        "",
        "## Model Metrics",
    ]
    for name, item in report.get("model_metric_comparison", {}).items():
        lines.append(f"- `{name}`: `{json.dumps(item.get('metrics', {}), ensure_ascii=False, sort_keys=True)}`")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
