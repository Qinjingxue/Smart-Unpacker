from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from repair_training.core.diagnosis_gnn.actionable_roots import ACTIONABLE_ROOT_SEMANTICS, ROOT_HYPOTHESIS_TRAINING_OBJECTIVE
from repair_training.core.diagnosis_gnn.root_cases import ROOT_CASES, canonical_root_case


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    graph_rows = read_jsonl(args.graphs)
    probe_rows = read_jsonl(args.probes)
    output_rows, summary = build_probe_training_rows(
        graph_rows,
        probe_rows,
        hard_label_margin=float(args.hard_label_margin),
    )
    output = Path(args.output)
    write_jsonl(output, output_rows)
    summary_path = Path(args.summary_output) if args.summary_output else output.with_name("diagnosis_root_probe_rows_summary.json")
    write_json(summary_path, summary)
    print(json.dumps({"output": str(output), "summary": str(summary_path), **summary}, ensure_ascii=False, sort_keys=True))
    return 0


def build_probe_training_rows(graph_rows: list[dict[str, Any]], probe_rows: list[dict[str, Any]], *, hard_label_margin: float = 0.10) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in probe_rows:
        key = _probe_key(row)
        if key:
            grouped.setdefault(key, []).append(row)
    output = []
    covered = 0
    hard = 0
    for row in graph_rows:
        key = _graph_key(row)
        probes = grouped.get(key, [])
        if not probes:
            output.append(dict(row))
            continue
        transition_targets: dict[str, float] = {}
        evidence_targets: dict[str, float] = {}
        viability_targets: dict[str, float] = {}
        positive_targets: dict[str, float] = {}
        hard_negative_targets: dict[str, float] = {}
        max_gain = max((_probe_gain_score(probe) for probe in probes), default=0.0)
        for probe in probes:
            root = canonical_root_case(str(probe.get("candidate_root") or probe.get("root_case") or ""))
            if not root:
                continue
            gain = _probe_gain_score(probe)
            transition_targets[root] = max(transition_targets.get(root, 0.0), gain)
            evidence_targets[root] = max(evidence_targets.get(root, 0.0), _clamp01(_float(probe.get("evidence_delta", probe.get("ak_consistency_delta")))))
            viability_targets[root] = max(viability_targets.get(root, 0.0), _probe_viability_score(probe))
            if gain > 0.01:
                positive_targets[root] = max(positive_targets.get(root, 0.0), _normalized_gain(gain, max_gain))
            if _is_hard_negative_probe(probe):
                hard_negative_targets[root] = 1.0
        updated = _with_auxiliary_targets(
            row,
            transition_targets,
            evidence_targets,
            viability_targets,
            positive_targets,
            hard_negative_targets,
        )
        best_roots = _hard_labels_from_targets(transition_targets, margin=hard_label_margin)
        if best_roots:
            labels = dict(updated.get("labels") or {})
            labels["root_case"] = {"labels": best_roots}
            updated["labels"] = labels
            hard += 1
        covered += 1
        output.append(updated)
    return output, {
        "schema": "diagnosis_root_probe_rows_v1",
        "diagnosis_semantics": ACTIONABLE_ROOT_SEMANTICS,
        "training_objective": ROOT_HYPOTHESIS_TRAINING_OBJECTIVE,
        "rows": len(graph_rows),
        "probe_rows": len(probe_rows),
        "covered_rows": covered,
        "hard_label_rows": hard,
        "coverage": covered / max(1, len(graph_rows)),
    }


def _with_auxiliary_targets(
    row: dict[str, Any],
    transition_targets: dict[str, float],
    evidence_targets: dict[str, float],
    viability_targets: dict[str, float],
    positive_targets: dict[str, float],
    hard_negative_targets: dict[str, float],
) -> dict[str, Any]:
    updated = dict(row)
    labels = dict(updated.get("labels") or {})
    auxiliary = dict(labels.get("auxiliary") or {})
    if transition_targets:
        auxiliary["root_transition_gain_targets"] = dict(sorted(_closed_world_targets(transition_targets).items()))
    if evidence_targets:
        auxiliary["root_evidence_targets"] = dict(sorted(_closed_world_targets(evidence_targets).items()))
    if viability_targets:
        auxiliary["root_probe_viability_targets"] = dict(sorted(_closed_world_targets(viability_targets).items()))
    if positive_targets:
        auxiliary["root_positive_probe_targets"] = dict(sorted(_closed_world_targets(positive_targets).items()))
    if hard_negative_targets:
        auxiliary["root_hard_negative_targets"] = dict(sorted(_closed_world_targets(hard_negative_targets).items()))
    auxiliary["diagnosis_semantics"] = ACTIONABLE_ROOT_SEMANTICS
    auxiliary["training_objective"] = ROOT_HYPOTHESIS_TRAINING_OBJECTIVE
    labels["auxiliary"] = auxiliary
    updated["labels"] = labels
    return updated


def _closed_world_targets(targets: dict[str, float]) -> dict[str, float]:
    if not targets:
        return {}
    return {root: _clamp01(targets.get(root, 0.0)) for root in ROOT_CASES}


def _hard_labels_from_targets(targets: dict[str, float], *, margin: float) -> list[str]:
    if not targets:
        return []
    ranked = sorted(targets.items(), key=lambda item: item[1], reverse=True)
    best, best_score = ranked[0]
    second = ranked[1][1] if len(ranked) > 1 else -1.0
    if best_score <= 0.0 or best_score < second + max(0.0, float(margin)):
        return []
    return [best]


def _probe_gain_score(row: dict[str, Any]) -> float:
    return _clamp01(max(0.0, _float(row.get("recovery_delta"))))


def _probe_viability_score(row: dict[str, Any]) -> float:
    patch_state_count = int(_float(row.get("patch_state_count")))
    failed_count = int(_float(row.get("materialization_failed_count")))
    recovery_delta = _float(row.get("recovery_delta"))
    if recovery_delta > 0.01:
        return 1.0
    if patch_state_count > 0:
        return 0.45
    if failed_count > 0:
        return 0.0
    return 0.0


def _normalized_gain(gain: float, max_gain: float) -> float:
    if max_gain <= 0.0:
        return 0.0
    return _clamp01(gain / max_gain)


def _is_hard_negative_probe(row: dict[str, Any]) -> bool:
    if bool(row.get("hard_negative")):
        return True
    if _probe_gain_score(row) > 0.01:
        return False
    if int(_float(row.get("patch_state_count"))) > 0:
        return False
    return _float(row.get("materialization_failed_count")) > 0.0


def _graph_key(row: dict[str, Any]) -> str:
    return str(row.get("sample_id") or row.get("graph_sample_id") or "")


def _probe_key(row: dict[str, Any]) -> str:
    return str(row.get("graph_sample_id") or row.get("sample_id") or row.get("source_sample_id") or "")


def _float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value or 0.0)))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build DiagnosisGNN root-hypothesis probe training rows.")
    parser.add_argument("--graphs", required=True, help="DiagnosisGraph rows JSONL.")
    parser.add_argument("--probes", required=True, help="Root probe/intervention rows JSONL.")
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", default="")
    parser.add_argument("--hard-label-margin", type=float, default=0.10)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
