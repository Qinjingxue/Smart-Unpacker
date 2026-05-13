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
    reports_dir = run_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    analysis = analyze_run(run_dir, material_report=Path(args.material_report) if args.material_report else None)
    json_path = Path(args.output_json or reports_dir / "collection_analysis.json")
    md_path = Path(args.output_md or reports_dir / "collection_analysis.md")
    json_path.write_text(json.dumps(analysis, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    md_path.write_text(_markdown_report(analysis), encoding="utf-8")
    _update_manifest(run_dir, "collection_analysis", {"status": "ok", "json": str(json_path), "markdown": str(md_path)})
    print(json.dumps({"run_dir": str(run_dir), "json": str(json_path), "markdown": str(md_path)}, ensure_ascii=False, sort_keys=True))
    return 0


def analyze_run(run_dir: Path, *, material_report: Path | None = None) -> dict[str, Any]:
    dataset_dir = run_dir / "datasets"
    summary_path = dataset_dir / "runtime_graph_summary.json"
    success_path = dataset_dir / "runtime_graph_success.jsonl"
    failure_path = dataset_dir / "runtime_graph_failure.jsonl"
    warnings: list[str] = []
    run_manifest = _read_json(run_dir / "run_manifest.json", warnings)
    format_name = _format_from_run_manifest(run_manifest)
    plugin = load_training_format_plugin(format_name)
    summary = _read_json(summary_path, warnings)
    if material_report is None:
        material_report = _resolve_material_report(run_dir, run_manifest, plugin, warnings)
    material_distribution = _read_json(material_report, warnings) if material_report else {}
    material_index = _load_material_index_for_plugin(run_dir, run_manifest, plugin, warnings)
    profile_lookup = _profile_lookup(material_distribution)

    row_type_counts: Counter[str] = Counter()
    label_counts: Counter[str] = Counter()
    terminal_counts: Counter[str] = Counter()
    profile_rows: Counter[str] = Counter()
    profile_samples: dict[str, set[str]] = defaultdict(set)
    layer_samples: dict[str, set[str]] = defaultdict(set)
    best_by_sample: dict[str, dict[str, Any]] = {}
    root_rows = 0
    root_explored = 0
    root_unexplored = 0
    required_payload_miss = 0
    feature_contract_versions: Counter[str] = Counter()

    for row in _iter_jsonl(success_path, warnings):
        _accumulate_row(
            row,
            row_type_counts=row_type_counts,
            label_counts=label_counts,
            terminal_counts=terminal_counts,
            profile_rows=profile_rows,
            profile_samples=profile_samples,
            layer_samples=layer_samples,
            best_by_sample=best_by_sample,
            feature_contract_versions=feature_contract_versions,
            material_index=material_index,
            profile_lookup=profile_lookup,
        )
        if bool(row.get("root_action")):
            root_rows += 1
            if row.get("explored") is False:
                root_unexplored += 1
            else:
                root_explored += 1
        stable = row.get("stable_features") if isinstance(row.get("stable_features"), dict) else {}
        if row.get("row_type") == "action" and (not isinstance(stable.get("runtime_context"), dict) or not isinstance(stable.get("candidate_proposal"), dict)):
            required_payload_miss += 1
    for row in _iter_jsonl(failure_path, warnings):
        _accumulate_row(
            row,
            row_type_counts=row_type_counts,
            label_counts=label_counts,
            terminal_counts=terminal_counts,
            profile_rows=profile_rows,
            profile_samples=profile_samples,
            layer_samples=layer_samples,
            best_by_sample=best_by_sample,
            feature_contract_versions=feature_contract_versions,
            material_index=material_index,
            profile_lookup=profile_lookup,
        )

    best_values = [float(item.get("recovery", 0.0) or 0.0) for item in best_by_sample.values()]
    complete = sum(1 for item in best_by_sample.values() if item.get("complete"))
    zero = sum(1 for value in best_values if value <= 0.0)
    profile_best = _profile_best_summary(best_by_sample)
    phase_seconds = summary.get("phase_seconds") if isinstance(summary.get("phase_seconds"), dict) else {}
    findings = _collection_findings(summary, complete, zero, best_by_sample, required_payload_miss, profile_best)

    return {
        "run_dir": str(run_dir),
        "inputs": {
            "summary": str(summary_path),
            "success": str(success_path),
            "failure": str(failure_path),
            "material_distribution_report": str(material_report or ""),
        },
        "warnings": warnings,
        "summary": {
            "samples": int(summary.get("samples", len(best_by_sample)) or 0),
            "success_rows": int(summary.get("success_rows", row_type_counts.total()) or 0),
            "failure_rows": int(summary.get("failure_rows", 0) or 0),
            "wall_seconds": float(summary.get("wall_seconds", 0.0) or 0.0),
            "candidate_id_collision_count": int(summary.get("candidate_id_collision_count", 0) or 0),
            "feature_contract_version": summary.get("feature_contract_version"),
        },
        "row_type_counts": dict(row_type_counts),
        "label_counts": dict(label_counts),
        "terminal_status_counts": dict(terminal_counts or Counter(summary.get("terminal_status_counts") or {})),
        "oracle_best": {
            "sample_count": len(best_by_sample),
            "complete_count": complete,
            "zero_count": zero,
            "mean_recovery": _mean(best_values),
            "p50_recovery": _percentile(best_values, 0.50),
            "p90_recovery": _percentile(best_values, 0.90),
        },
        "root_coverage": {
            "root_action_rows": root_rows or int(summary.get("root_action_row_count", 0) or 0),
            "root_explored_action_rows": root_explored or int(summary.get("root_explored_action_count", 0) or 0),
            "root_unexplored_action_rows": root_unexplored or int(summary.get("root_unexplored_candidate_count", 0) or 0),
            "root_top5_candidate_count": int(summary.get("root_top5_candidate_count", 0) or 0),
            "root_top5_explored_count": int(summary.get("root_top5_explored_count", 0) or 0),
        },
        "profile_sample_counts": {key: len(value) for key, value in sorted(profile_samples.items())},
        "profile_row_counts": dict(profile_rows),
        "layer_sample_counts": {key: len(value) for key, value in sorted(layer_samples.items())},
        "profile_best_recovery": profile_best,
        "feature_contract_versions": dict(feature_contract_versions),
        "required_payload_miss_count": required_payload_miss,
        "phase_top_seconds": _top_mapping(phase_seconds, limit=20),
        "material_distribution": plugin.compact_material_distribution(material_distribution) if plugin.compact_material_distribution else _default_compact_material_distribution(material_distribution),
        "format_report_sections": plugin.collection_report_sections(material_distribution) if plugin.collection_report_sections else [],
        "actionable_findings": findings,
    }


def _accumulate_row(
    row: dict[str, Any],
    *,
    row_type_counts: Counter[str],
    label_counts: Counter[str],
    terminal_counts: Counter[str],
    profile_rows: Counter[str],
    profile_samples: dict[str, set[str]],
    layer_samples: dict[str, set[str]],
    best_by_sample: dict[str, dict[str, Any]],
    feature_contract_versions: Counter[str],
    material_index: dict[str, dict[str, Any]],
    profile_lookup: list[str],
) -> None:
    row_type = str(row.get("row_type") or "unknown")
    row_type_counts[row_type] += 1
    if "label" in row:
        label_counts[str(row.get("label"))] += 1
    if row.get("terminal_status"):
        terminal_counts[str(row.get("terminal_status"))] += 1
    sample = str(row.get("sample_id") or "")
    material_meta = material_index.get(sample, {})
    profile = str(row.get("damage_profile") or row.get("profile") or material_meta.get("damage_profile") or _infer_profile_from_sample(sample, profile_lookup) or "")
    if profile:
        profile_rows[profile] += 1
    if profile and sample:
        profile_samples[profile].add(sample)
    layer = str(row.get("profile_layer") or row.get("damage_layer") or material_meta.get("profile_layer") or material_meta.get("damage_layer") or "")
    if layer and sample:
        layer_samples[layer].add(sample)
    stable = row.get("stable_features") if isinstance(row.get("stable_features"), dict) else {}
    ctx = stable.get("runtime_context") if isinstance(stable.get("runtime_context"), dict) else {}
    if ctx.get("feature_contract_version") is not None:
        feature_contract_versions[str(ctx.get("feature_contract_version"))] += 1
    recovery = _row_recovery(row)
    if sample:
        current = best_by_sample.get(sample)
        if current is None or recovery > float(current.get("recovery", 0.0) or 0.0):
            best_by_sample[sample] = {
                "sample_id": sample,
                "profile": profile,
                "layer": layer,
                "recovery": recovery,
                "status": str((row.get("oracle_ground_truth") or {}).get("status") or row.get("label_status") or row.get("terminal_status") or ""),
                "complete": recovery >= 0.999 or str((row.get("oracle_ground_truth") or {}).get("status") or row.get("label_status") or "").lower() == "complete",
            }


def _profile_best_summary(best_by_sample: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    values: dict[str, list[float]] = defaultdict(list)
    complete: Counter[str] = Counter()
    zero: Counter[str] = Counter()
    for item in best_by_sample.values():
        profile = str(item.get("profile") or "unknown")
        recovery = float(item.get("recovery", 0.0) or 0.0)
        values[profile].append(recovery)
        if bool(item.get("complete")):
            complete[profile] += 1
        if recovery <= 0.0:
            zero[profile] += 1
    output = {}
    for profile, vals in values.items():
        output[profile] = {
            "samples": len(vals),
            "complete": int(complete.get(profile, 0)),
            "zero": int(zero.get(profile, 0)),
            "mean_recovery": _mean(vals),
        }
    return dict(sorted(output.items()))


def _profile_lookup(material_distribution: dict[str, Any]) -> list[str]:
    profile_counts = material_distribution.get("profile_counts") if isinstance(material_distribution.get("profile_counts"), dict) else {}
    return sorted((str(item) for item in profile_counts if str(item)), key=len, reverse=True)


def _infer_profile_from_sample(sample_id: str, profiles: list[str]) -> str:
    if not sample_id:
        return ""
    for profile in profiles:
        if profile and profile in sample_id:
            return profile
    return ""


def _collection_findings(summary: dict[str, Any], complete: int, zero: int, best_by_sample: dict[str, dict[str, Any]], payload_miss: int, profile_best: dict[str, dict[str, Any]]) -> list[str]:
    findings: list[str] = []
    collisions = int(summary.get("candidate_id_collision_count", 0) or 0)
    if collisions:
        findings.append(f"candidate_id_collision_count is {collisions}; candidate identity must be fixed before training.")
    top5 = int(summary.get("root_top5_candidate_count", 0) or 0)
    explored = int(summary.get("root_top5_explored_count", 0) or 0)
    if top5 and explored < top5:
        findings.append(f"Root Top5 exploration incomplete: {explored}/{top5}.")
    if payload_miss:
        findings.append(f"{payload_miss} action rows are missing runtime_context or candidate_proposal.")
    if best_by_sample and zero / max(1, len(best_by_sample)) > 0.20:
        findings.append(f"Zero-recovery samples are high: {zero}/{len(best_by_sample)}.")
    weak_profiles = [
        (profile, data)
        for profile, data in profile_best.items()
        if int(data.get("samples", 0) or 0) >= 20 and float(data.get("mean_recovery", 0.0) or 0.0) < 0.35
    ][:8]
    if weak_profiles:
        findings.append("Low-recovery profiles: " + ", ".join(f"{profile}={data['mean_recovery']:.3f}" for profile, data in weak_profiles))
    if not findings:
        findings.append("No blocking collection issues detected.")
    return findings


def _markdown_report(analysis: dict[str, Any]) -> str:
    s = analysis.get("summary", {})
    best = analysis.get("oracle_best", {})
    root = analysis.get("root_coverage", {})
    lines = [
        "# Runtime Graph Collection Analysis",
        "",
        "## Summary",
        "",
        _table(
            ["Metric", "Value"],
            [
                ["Run", analysis.get("run_dir", "")],
                ["Samples", s.get("samples", 0)],
                ["Success rows", s.get("success_rows", 0)],
                ["Failure rows", s.get("failure_rows", 0)],
                ["Wall seconds", s.get("wall_seconds", 0)],
                ["Candidate collisions", s.get("candidate_id_collision_count", 0)],
                ["Best complete", best.get("complete_count", 0)],
                ["Best zero", best.get("zero_count", 0)],
                ["Best mean recovery", f"{float(best.get('mean_recovery', 0.0) or 0.0):.4f}"],
            ],
        ),
        "",
        "## Root Coverage",
        "",
        _table(["Metric", "Value"], [[k, v] for k, v in root.items()]),
        "",
        "## Actionable Findings",
        "",
        *[f"- {item}" for item in analysis.get("actionable_findings", [])],
        "",
        "## Label Counts",
        "",
        _counter_table(analysis.get("label_counts", {}), ["Label", "Rows"]),
        "",
        "## Terminal Status Counts",
        "",
        _counter_table(analysis.get("terminal_status_counts", {}), ["Status", "Rows"], limit=20),
        "",
        "## Best Recovery By Profile",
        "",
        _table(
            ["Profile", "Samples", "Complete", "Zero", "Mean Recovery"],
            [
                [profile, data.get("samples", 0), data.get("complete", 0), data.get("zero", 0), f"{float(data.get('mean_recovery', 0.0) or 0.0):.4f}"]
                for profile, data in sorted(analysis.get("profile_best_recovery", {}).items(), key=lambda item: float(item[1].get("mean_recovery", 0.0) or 0.0))
            ][:40],
        ),
        "",
        "## Phase Cost Top",
        "",
        _table(["Phase", "Seconds"], [[k, f"{float(v):.3f}"] for k, v in analysis.get("phase_top_seconds", [])]),
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


def _default_compact_material_distribution(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "profile_counts": report.get("profile_counts", {}),
        "layer_counts": report.get("layer_counts", {}),
        "target_errors": report.get("target_errors", {}),
        "physical_complete_expected_counts": report.get("physical_complete_expected_counts", {}),
    }


def _load_material_index_from_manifest(manifest: Path | None, warnings: list[str]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    if manifest is None or not manifest.is_file():
        warnings.append(f"missing material manifest for profile index: {manifest}")
        return output
    for row in _iter_jsonl(manifest, warnings):
        sample_id = str(row.get("sample_id") or "")
        if not sample_id:
            continue
        derivation = row.get("source_derivation") if isinstance(row.get("source_derivation"), dict) else {}
        output[sample_id] = {
            "damage_profile": row.get("damage_profile") or row.get("profile"),
            "profile_layer": row.get("profile_layer") or row.get("damage_layer") or derivation.get("layer"),
            "damage_layer": row.get("damage_layer") or derivation.get("layer"),
            "physical_complete_expected": row.get("physical_complete_expected"),
        }
    return output


def _format_from_run_manifest(manifest: dict[str, Any]) -> str:
    inputs = manifest.get("inputs") if isinstance(manifest.get("inputs"), dict) else {}
    return normalize_format_name(str(inputs.get("format") or inputs.get("formats") or "zip"))


def _resolve_material_report(run_dir: Path, run_manifest: dict[str, Any], plugin: Any, warnings: list[str]) -> Path | None:
    if plugin.resolve_collection_material_report:
        candidate = plugin.resolve_collection_material_report(run_dir, run_manifest)
        if candidate and candidate.is_file():
            return candidate
    inputs = run_manifest.get("inputs") if isinstance(run_manifest.get("inputs"), dict) else {}
    for key in ("material_distribution_report", "distribution_report"):
        raw = str(inputs.get(key) or "").strip()
        if raw:
            path = Path(raw)
            if path.is_file():
                return path.resolve()
    manifest = _manifest_path_from_run_manifest(run_manifest)
    if manifest and manifest.is_file():
        reports = sorted(manifest.parent.glob("material_distribution_report*.json"))
        if reports:
            return reports[0].resolve()
    warnings.append("missing material distribution report")
    return None


def _load_material_index_for_plugin(run_dir: Path, run_manifest: dict[str, Any], plugin: Any, warnings: list[str]) -> dict[str, dict[str, Any]]:
    if plugin.load_material_index:
        try:
            loaded = plugin.load_material_index(run_dir, run_manifest)
            if loaded:
                return loaded
        except Exception as exc:
            warnings.append(f"plugin material index failed: {exc}")
    return _load_material_index_from_manifest(_manifest_path_from_run_manifest(run_manifest), warnings)


def _manifest_path_from_run_manifest(run_manifest: dict[str, Any]) -> Path | None:
    inputs = run_manifest.get("inputs") if isinstance(run_manifest.get("inputs"), dict) else {}
    for key in ("manifest_abs", "manifest"):
        raw = str(inputs.get(key) or "").strip()
        if raw:
            return Path(raw).resolve()
    return None


def _row_recovery(row: dict[str, Any]) -> float:
    oracle = row.get("oracle_ground_truth") if isinstance(row.get("oracle_ground_truth"), dict) else {}
    for value in (oracle.get("recovery_ratio"), oracle.get("completeness"), row.get("terminal_recovery_ratio"), row.get("recovery_ratio")):
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return 0.0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze a runtime graph collection run and write JSON/Markdown reports.")
    parser.add_argument("--run-dir", default="")
    parser.add_argument("--material-report", default="")
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


def _read_json(path: Path | None, warnings: list[str]) -> dict[str, Any]:
    if path is None or not path.is_file():
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


def _top_mapping(mapping: dict[str, Any], *, limit: int) -> list[list[Any]]:
    items = []
    for key, value in mapping.items():
        try:
            items.append((str(key), float(value)))
        except (TypeError, ValueError):
            continue
    return [[key, value] for key, value in sorted(items, key=lambda item: item[1], reverse=True)[:limit]]


def _counter_table(counter: dict[str, Any], headers: list[str], *, limit: int = 100) -> str:
    rows = [[key, value] for key, value in sorted(counter.items(), key=lambda item: int(item[1] or 0) if str(item[1]).isdigit() else 0, reverse=True)[:limit]]
    return _table(headers, rows)


def _table(headers: list[Any], rows: list[list[Any]]) -> str:
    output = ["| " + " | ".join(str(item) for item in headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        output.append("| " + " | ".join(_md_cell(item) for item in row) + " |")
    return "\n".join(output)


def _md_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _mean(values: list[float]) -> float:
    return float(statistics.mean(values)) if values else 0.0


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * q))))
    return float(ordered[idx])


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
