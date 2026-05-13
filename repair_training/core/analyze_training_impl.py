from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from repair_training.core.plugin import load_training_format_plugin, normalize_format_name


LATEST_RUN = Path("repair_training") / "latest_run.txt"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    run_dir = _resolve_run_dir(args.run_dir)
    run_manifest = _read_json(run_dir / "run_manifest.json", [])
    plugin = load_training_format_plugin(_format_from_run_manifest(run_manifest))
    model_dir = Path(args.model_dir).resolve() if str(args.model_dir or "").strip() else (run_dir / plugin.model_output_subdir)
    reports_dir = run_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    analysis = analyze_training(run_dir, model_dir)
    json_path = Path(args.output_json or reports_dir / "training_analysis.json")
    md_path = Path(args.output_md or reports_dir / "training_analysis.md")
    json_path.write_text(json.dumps(analysis, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    md_path.write_text(_markdown_report(analysis), encoding="utf-8")
    _update_manifest(run_dir, "training_analysis", {"status": "ok", "json": str(json_path), "markdown": str(md_path), "model_dir": str(model_dir)})
    print(json.dumps({"run_dir": str(run_dir), "model_dir": str(model_dir), "json": str(json_path), "markdown": str(md_path)}, ensure_ascii=False, sort_keys=True))
    return 0


def analyze_training(run_dir: Path, model_dir: Path) -> dict[str, Any]:
    warnings: list[str] = []
    run_manifest = _read_json(run_dir / "run_manifest.json", warnings)
    plugin = load_training_format_plugin(_format_from_run_manifest(run_manifest))
    summary = _read_json(model_dir / "training_summary.json", warnings)
    metrics = _read_json(model_dir / "metrics.json", warnings)
    collection = _read_json(run_dir / "reports" / "collection_analysis.json", warnings)
    predictions = list(_iter_jsonl(model_dir / "predictions.jsonl", warnings))
    score_values = [_float(row.get("score")) for row in predictions if _float(row.get("score")) is not None]
    eval_predictions = [row for row in predictions if bool(row.get("eval_row"))]
    root_predictions = [row for row in predictions if bool(row.get("root_action"))]
    label_counts = Counter(str(row.get("label")) for row in predictions if row.get("label") is not None)
    module_counts = Counter(str(row.get("module") or "") for row in predictions if row.get("module"))
    by_query: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in predictions:
        query = str(row.get("query_id") or "")
        if query:
            by_query[query].append(row)
    prediction_regret = _prediction_regret(by_query)
    findings = _training_findings(summary, metrics, predictions, collection, prediction_regret)
    analysis = {
        "run_dir": str(run_dir),
        "model_dir": str(model_dir),
        "warnings": warnings,
        "training_summary": {
            "row_count": summary.get("row_count", 0),
            "train_row_count": summary.get("train_row_count", 0),
            "eval_row_count": summary.get("eval_row_count", 0),
            "feature_count": summary.get("feature_count", 0),
            "feature_view": summary.get("feature_view", ""),
            "target": summary.get("target", ""),
            "sample_weight_mode": summary.get("sample_weight_mode", ""),
            "split_by": summary.get("split_by", ""),
            "root_row_count": summary.get("root_row_count", 0),
            "root_action_row_count": summary.get("root_action_row_count", 0),
            "root_unexplored_candidate_count": summary.get("root_unexplored_candidate_count", 0),
        },
        "metrics": metrics,
        "prediction_summary": {
            "prediction_rows": len(predictions),
            "eval_prediction_rows": len(eval_predictions),
            "root_prediction_rows": len(root_predictions),
            "score_mean": _mean(score_values),
            "score_p10": _percentile(score_values, 0.10),
            "score_p50": _percentile(score_values, 0.50),
            "score_p90": _percentile(score_values, 0.90),
            "label_counts": dict(label_counts),
            "top_modules": module_counts.most_common(20),
            **prediction_regret,
        },
        "collection_oracle_best": (collection.get("oracle_best") if isinstance(collection.get("oracle_best"), dict) else {}),
        "actionable_findings": findings,
    }
    analysis["format_report_sections"] = plugin.training_report_sections(analysis) if plugin.training_report_sections else []
    return analysis


def _prediction_regret(by_query: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    regrets: list[float] = []
    root_regrets: list[float] = []
    hits: list[float] = []
    for rows in by_query.values():
        scored = [(row, _float(row.get("score"))) for row in rows if _float(row.get("score")) is not None]
        valued = [(row, score, _row_value(row)) for row, score in scored if _row_value(row) is not None]
        if not valued:
            continue
        chosen = max(valued, key=lambda item: item[1])
        best_value = max(float(item[2] or 0.0) for item in valued)
        chosen_value = float(chosen[2] or 0.0)
        regrets.append(max(0.0, best_value - chosen_value))
        root_items = [item for item in valued if bool(item[0].get("root_action")) or int(_safe_int(item[0].get("round"), 0)) == 0]
        if root_items:
            root_chosen = max(root_items, key=lambda item: item[1])
            root_best = max(float(item[2] or 0.0) for item in root_items)
            root_chosen_value = float(root_chosen[2] or 0.0)
            root_regrets.append(max(0.0, root_best - root_chosen_value))
            hits.append(1.0 if root_chosen_value >= root_best - 1e-9 else 0.0)
    return {
        "prediction_query_count": len(regrets),
        "prediction_regret_mean": _mean(regrets),
        "prediction_regret_p90": _percentile(regrets, 0.90),
        "prediction_root_regret_mean": _mean(root_regrets),
        "prediction_root_top1_accuracy": _mean(hits),
    }


def _row_value(row: dict[str, Any]) -> float | None:
    for key in ("rl_root_candidate_return", "rl_subtree_oracle_return", "rl_future_return", "terminal_recovery_ratio"):
        value = _float(row.get(key))
        if value is not None:
            return value
    return None


def _training_findings(summary: dict[str, Any], metrics: dict[str, Any], predictions: list[dict[str, Any]], collection: dict[str, Any], prediction_regret: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    if not summary:
        findings.append("training_summary.json is missing; model training may not have completed.")
        return findings
    if not predictions:
        findings.append("predictions.jsonl is missing or empty; prediction distribution analysis skipped.")
    target = str(summary.get("target") or "")
    if target != "root_transition_return_v1":
        findings.append(f"Training target is {target}; recommended default is root_transition_return_v1.")
    weight = str(summary.get("sample_weight_mode") or "")
    if weight != "root_transition_v1":
        findings.append(f"Sample weight mode is {weight}; recommended default is root_transition_v1.")
    root_regret = _float(metrics.get("root_mean_regret"))
    if root_regret is not None and root_regret > 0.05:
        findings.append(f"Root mean regret is high: {root_regret:.4f}.")
    if int(metrics.get("candidate_id_collision_count", 0) or 0):
        findings.append(f"Candidate ID collisions in eval: {metrics.get('candidate_id_collision_count')}.")
    collection_best = collection.get("oracle_best") if isinstance(collection.get("oracle_best"), dict) else {}
    if collection_best and _float(collection_best.get("mean_recovery")) is not None and _float(metrics.get("top1_future_return_mean")) is not None:
        gap = float(collection_best.get("mean_recovery") or 0.0) - float(metrics.get("top1_future_return_mean") or 0.0)
        if gap > 0.10:
            findings.append(f"Top1 predicted return is far below collection oracle mean recovery: gap={gap:.4f}.")
    if not findings:
        findings.append("No blocking training issues detected.")
    return findings


def _markdown_report(analysis: dict[str, Any]) -> str:
    summary = analysis.get("training_summary", {})
    metrics = analysis.get("metrics", {})
    pred = analysis.get("prediction_summary", {})
    lines = [
        "# Training Analysis",
        "",
        "## Summary",
        "",
        _table(
            ["Metric", "Value"],
            [
                ["Run", analysis.get("run_dir", "")],
                ["Model dir", analysis.get("model_dir", "")],
                ["Rows", summary.get("row_count", 0)],
                ["Train rows", summary.get("train_row_count", 0)],
                ["Eval rows", summary.get("eval_row_count", 0)],
                ["Features", summary.get("feature_count", 0)],
                ["Feature view", summary.get("feature_view", "")],
                ["Target", summary.get("target", "")],
                ["Sample weight", summary.get("sample_weight_mode", "")],
                ["Split", summary.get("split_by", "")],
            ],
        ),
        "",
        "## Key Metrics",
        "",
        _table(
            ["Metric", "Value"],
            [[key, _format_value(value)] for key, value in sorted(metrics.items()) if key in {
                "r2",
                "mae",
                "rmse",
                "eval_query_count",
                "top1_future_return_mean",
                "oracle_future_return_mean",
                "future_return_regret_mean",
                "root_query_count",
                "root_top1_accuracy",
                "root_mean_regret",
                "root_best_return_mean",
                "root_selected_return_mean",
                "candidate_id_collision_count",
            }],
        ),
        "",
        "## Prediction Distribution",
        "",
        _table(
            ["Metric", "Value"],
            [
                ["Prediction rows", pred.get("prediction_rows", 0)],
                ["Eval prediction rows", pred.get("eval_prediction_rows", 0)],
                ["Root prediction rows", pred.get("root_prediction_rows", 0)],
                ["Score mean", _format_value(pred.get("score_mean", 0))],
                ["Score p10", _format_value(pred.get("score_p10", 0))],
                ["Score p50", _format_value(pred.get("score_p50", 0))],
                ["Score p90", _format_value(pred.get("score_p90", 0))],
                ["Prediction regret mean", _format_value(pred.get("prediction_regret_mean", 0))],
                ["Prediction root regret mean", _format_value(pred.get("prediction_root_regret_mean", 0))],
                ["Prediction root top1 accuracy", _format_value(pred.get("prediction_root_top1_accuracy", 0))],
            ],
        ),
        "",
        "## Actionable Findings",
        "",
        *[f"- {item}" for item in analysis.get("actionable_findings", [])],
        "",
        "## Top Modules",
        "",
        _table(["Module", "Prediction Rows"], pred.get("top_modules", [])[:20]),
    ]
    for section in analysis.get("format_report_sections") or []:
        if not isinstance(section, dict):
            continue
        title = str(section.get("title") or "Format Details")
        rows = section.get("rows") if isinstance(section.get("rows"), list) else []
        headers = section.get("headers") if isinstance(section.get("headers"), list) else []
        lines.extend(["", f"## {title}", ""])
        if headers and rows:
            lines.append(_table(headers, rows))
        elif section.get("text"):
            lines.append(str(section.get("text")))
    if analysis.get("warnings"):
        lines.extend(["", "## Warnings", "", *[f"- {item}" for item in analysis["warnings"]]])
    return "\n".join(lines) + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze a trained runtime policy model run and write JSON/Markdown reports.")
    parser.add_argument("--run-dir", default="")
    parser.add_argument("--model-dir", default="")
    parser.add_argument("--output-json", default="")
    parser.add_argument("--output-md", default="")
    return parser


def _resolve_run_dir(raw: str) -> Path:
    if str(raw or "").strip():
        return Path(raw).resolve()
    if LATEST_RUN.is_file():
        text = LATEST_RUN.read_text(encoding="utf-8").strip()
        if text:
            return Path(text).resolve()
    raise SystemExit("No --run-dir provided and repair_training/latest_run.txt is missing")


def _format_from_run_manifest(manifest: dict[str, Any]) -> str:
    inputs = manifest.get("inputs") if isinstance(manifest.get("inputs"), dict) else {}
    return normalize_format_name(str(inputs.get("format") or inputs.get("formats") or "zip"))


def _read_json(path: Path, warnings: list[str]) -> dict[str, Any]:
    if not path.is_file():
        warnings.append(f"missing json input: {path}")
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        warnings.append(f"failed to read {path}: {exc}")
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _iter_jsonl(path: Path, warnings: list[str]):
    if not path.is_file():
        warnings.append(f"missing jsonl input: {path}")
        return
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
                yield row


def _float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _mean(values: list[float]) -> float:
    return float(statistics.mean(values)) if values else 0.0


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * q))))
    return float(ordered[idx])


def _format_value(value: Any) -> str:
    numeric = _float(value)
    if numeric is not None:
        return f"{numeric:.6f}"
    return str(value)


def _table(headers: list[Any], rows: list[list[Any] | tuple[Any, ...]]) -> str:
    output = ["| " + " | ".join(str(item) for item in headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        output.append("| " + " | ".join(_md_cell(item) for item in row) + " |")
    return "\n".join(output)


def _md_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _update_manifest(run_dir: Path, key: str, value: dict[str, Any]) -> None:
    path = run_dir / "run_manifest.json"
    payload: dict[str, Any] = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            payload = loaded if isinstance(loaded, dict) else {}
        except Exception:
            payload = {}
    payload[key] = value
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
