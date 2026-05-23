from __future__ import annotations

import argparse
import json
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from repair_training.collect_damage_rows import _job_from_record, observe_damage_runtime
from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from repair_training.core.diagnosis_graph.dispatcher import build_diagnosis_graph_sample
from repair_training.core.diagnosis_gnn.actionable_roots import modules_for_root
from repair_training.core.diagnosis_gnn.inference import DiagnosisGNNModel
from sunpack.repair.scheduler import RepairScheduler, _route_flags_from_damage_analysis
from sunpack.repair.policy.formats import get_repair_format_plugin


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    rows = _select_rows(read_jsonl(args.input), limit=int(args.limit), profile=str(args.profile or ""))
    model = DiagnosisGNNModel(model_dir=args.model_dir, device=args.device)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    reports = []
    started = time.perf_counter()
    for index, row in enumerate(rows):
        reports.append(_evaluate_row(
            row,
            model=model,
            workspace=output / "workspace" / f"sample_{index:04d}",
            topks=[int(item) for item in str(args.topks).split(",") if item.strip()],
            max_rounds=int(args.max_rounds),
            max_modules_per_round=int(args.max_modules_per_round),
            min_improvement=float(args.min_improvement),
        ))
    summary = _summary(reports, elapsed=time.perf_counter() - started)
    write_jsonl(output / "hgt_repair_guidance_paths.jsonl", reports)
    write_json(output / "hgt_repair_guidance_summary.json", summary)
    print(json.dumps({"output": str(output), **summary}, ensure_ascii=False, sort_keys=True))
    return 0


def _evaluate_row(
    row: dict[str, Any],
    *,
    model: DiagnosisGNNModel,
    workspace: Path,
    topks: list[int],
    max_rounds: int,
    max_modules_per_round: int,
    min_improvement: float,
) -> dict[str, Any]:
    raw = ((row.get("metadata") or {}).get("raw_damage_record") or {})
    if not raw:
        raise ValueError(f"row has no metadata.raw_damage_record: {row.get('sample_id')}")
    root_job = _with_damage_flags(_with_training_oracle(_job_from_record(raw, str(row.get("format") or "zip")), raw), raw, row)
    initial = _observe_job(root_job, workspace=workspace / "initial", template=row, round_index=0)
    strategies = {}
    for topk in topks:
        strategies[str(topk)] = _run_guided_strategy(
            initial,
            model=model,
            workspace=workspace / f"top{topk}",
            topk=topk,
            max_rounds=max_rounds,
            max_modules_per_round=max_modules_per_round,
            min_improvement=min_improvement,
        )
    return {
        "sample_id": row.get("sample_id"),
        "profile": ((row.get("metadata") or {}).get("damage_profile") or row.get("damage_profile") or ""),
        "truth_labels": sorted(str(label) for label in (row.get("damage_analysis_target") or {}).get("damage_labels") or []),
        "initial_recovery": initial["recovery"],
        "strategies": strategies,
    }


def _run_guided_strategy(
    observed: dict[str, Any],
    *,
    model: DiagnosisGNNModel,
    workspace: Path,
    topk: int,
    max_rounds: int,
    max_modules_per_round: int,
    min_improvement: float,
) -> dict[str, Any]:
    current = observed
    best_recovery = float(current["recovery"]["score"])
    best_round = 0
    history = []
    for round_index in range(1, max_rounds + 1):
        prediction = model.predict_sample(current["graph_sample"])
        ranked_roots = _ranked_roots(prediction)
        modules = _modules_for_ranked_roots(ranked_roots[:topk])[:max_modules_per_round]
        step = {
            "round": round_index,
            "state_digest": current["state_digest"],
            "recovery": current["recovery"],
            "hgt_top_roots": ranked_roots[:10],
            "allowed_modules": modules,
            "tried_modules": [],
        }
        if not modules:
            step["stop_reason"] = "no_modules_from_hgt_topk"
            history.append(step)
            break
        best_candidate = None
        for module in modules:
            candidate_report = _try_module(
                current,
                module_name=module,
                workspace=workspace / f"round_{round_index:02d}" / _safe_name(module),
                template_row=current["row"],
                round_index=round_index,
            )
            step["tried_modules"].append(candidate_report["summary"])
            if candidate_report.get("observed") is None:
                continue
            recovery = float(candidate_report["observed"]["recovery"]["score"])
            if best_candidate is None or recovery > float(best_candidate["observed"]["recovery"]["score"]):
                best_candidate = candidate_report
        if best_candidate is None:
            step["stop_reason"] = "no_candidate_state"
            history.append(step)
            break
        next_observed = best_candidate["observed"]
        next_recovery = float(next_observed["recovery"]["score"])
        step["selected_module"] = best_candidate["module_name"]
        step["selected_recovery"] = next_observed["recovery"]
        step["recovery_delta"] = next_recovery - float(current["recovery"]["score"])
        history.append(step)
        current = next_observed
        if next_recovery > best_recovery + min_improvement:
            best_recovery = next_recovery
            best_round = round_index
        if best_recovery >= 0.999:
            break
    return {
        "topk": topk,
        "rounds": len(history),
        "initial_recovery": float(observed["recovery"]["score"]),
        "final_recovery": float(current["recovery"]["score"]),
        "best_recovery": best_recovery,
        "best_round": best_round,
        "improved": best_recovery > float(observed["recovery"]["score"]) + min_improvement,
        "complete": best_recovery >= 0.999,
        "history": history,
    }


def _try_module(
    observed: dict[str, Any],
    *,
    module_name: str,
    workspace: Path,
    template_row: dict[str, Any],
    round_index: int,
) -> dict[str, Any]:
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(workspace / "repair"),
            "policy": {"enabled": False, "strict_provider_errors": False},
            "modules": [{"name": module_name, "enabled": True}],
            "module_limits": {"max_seconds_per_module": 30.0, "verify_candidates": False},
            "safety": {"allow_partial": True, "allow_lossy": False, "allow_unsafe": False},
        }
    })
    job = observed["job"]
    plugin = get_repair_format_plugin(str(job.format or "zip"))
    if plugin is None:
        return {
            "module_name": module_name,
            "observed": None,
            "summary": {
                "module_name": module_name,
                "candidate_count": 0,
                "terminal_result": "unsupported_policy_format",
                "message": f"no policy format plugin for {job.format}",
                "candidates": [],
                "best_recovery": {},
            },
        }
    proposals = [
        proposal for proposal in plugin.available_modules(scheduler=scheduler, job=job, diagnosis_hgt={}, graph=None)
        if proposal.module_name == module_name
    ]
    summaries = []
    best_observed = None
    for candidate_index, proposal in enumerate(proposals):
        materialized = plugin.materialize_module(scheduler=scheduler, proposal=proposal, job=job)
        candidate = materialized.candidate
        if candidate is None:
            summaries.append({
                "candidate_index": candidate_index,
                "module_name": proposal.module_name,
                "status": "materialization_failed",
                "has_repaired_state": False,
                "message": json.dumps(materialized.failure, ensure_ascii=False, sort_keys=True),
            })
            continue
        state = candidate.repaired_state
        summaries.append({
            "candidate_index": candidate_index,
            "module_name": candidate.module_name,
            "status": candidate.status,
            "has_repaired_state": state is not None,
            "message": candidate.message,
        })
        if state is None:
            continue
        candidate_job = replace(job, archive_state=state, attempts=round_index)
        candidate_observed = _observe_job(
            candidate_job,
            workspace=workspace / f"candidate_{candidate_index:02d}",
            template=template_row,
            round_index=round_index,
        )
        summaries[-1]["recovery"] = candidate_observed["recovery"]
        if best_observed is None or float(candidate_observed["recovery"]["score"]) > float(best_observed["recovery"]["score"]):
            best_observed = candidate_observed
    return {
        "module_name": module_name,
        "observed": best_observed,
        "summary": {
            "module_name": module_name,
            "candidate_count": len(proposals),
            "terminal_result": "",
            "message": "policy_plugin_materialization",
            "candidates": summaries[:5],
            "best_recovery": best_observed["recovery"] if best_observed is not None else {},
        },
    }


def _observe_job(job, *, workspace: Path, template: dict[str, Any], round_index: int) -> dict[str, Any]:
    knowledge, observation = observe_damage_runtime(job, workspace=workspace, config=_oracle_verification_config())
    row = dict(template)
    row["knowledge_payload"] = knowledge
    row["runtime_observation"] = observation
    row["state_digest"] = str(observation.get("state_digest") or "")
    row["round_index"] = round_index
    row["patch_depth"] = int(observation.get("patch_depth") or 0)
    row["format"] = str(row.get("format") or job.format or "zip")
    graph_sample = build_diagnosis_graph_sample(row)
    observed_job = replace(
        job,
        knowledge=knowledge,
        extraction_failure=_nested(knowledge, "extraction", "failure") or {},
        extraction_diagnostics=_nested(knowledge, "extraction", "diagnostics") or {},
        archive_state=job.archive_state,
    )
    return {
        "job": observed_job,
        "row": row,
        "graph_sample": graph_sample,
        "state_digest": row["state_digest"],
        "recovery": _recovery_from_knowledge(knowledge),
    }


def _with_training_oracle(job, record: dict[str, Any]):
    oracle = record.get("oracle") if isinstance(record.get("oracle"), dict) else {}
    if not oracle:
        return job
    knowledge = dict(job.knowledge or {})
    verification = dict(knowledge.get("verification") or {})
    verification["oracle"] = {
        "expected_files": oracle.get("expected_files") or {},
        "expected_bytes": oracle.get("expected_bytes") or {},
        "expected_payload": oracle.get("expected_payload") or {},
        "oracle_strength": record.get("oracle_strength") or oracle.get("oracle_strength") or "",
    }
    knowledge["verification"] = verification
    return replace(job, knowledge=knowledge)


def _with_damage_flags(job, record: dict[str, Any], row: dict[str, Any]):
    flags = [str(item) for item in record.get("damage_flags") or [] if str(item)]
    targets = []
    for payload in (
        record.get("damage_analysis_target"),
        row.get("damage_analysis_target"),
        ((row.get("metadata") or {}).get("raw_damage_record") or {}).get("damage_analysis_target"),
    ):
        if isinstance(payload, dict):
            targets.append(payload)
    for target in targets:
        try:
            flags.extend(_route_flags_from_damage_analysis(target))
        except Exception:
            labels = [str(item) for item in target.get("damage_labels") or [] if str(item)]
            flags.extend(label.split(":", 1)[1].replace(".", "_") for label in labels if label.startswith("field:"))
    return replace(job, damage_flags=sorted(set(flags)))


def _oracle_verification_config() -> dict[str, Any]:
    return {
        "verification": {
            "enabled": True,
            "methods": [
                {"name": "oracle_expected_output_match", "enabled": True},
                {"name": "extraction_exit_signal", "enabled": True},
                {"name": "output_presence", "enabled": True},
            ],
        }
    }


def _ranked_roots(prediction: dict[str, Any]) -> list[dict[str, Any]]:
    root = prediction.get("root_case") if isinstance(prediction.get("root_case"), dict) else {}
    ranked = root.get("ranked") if isinstance(root.get("ranked"), list) else []
    output = []
    for item in ranked:
        if not isinstance(item, dict):
            continue
        root_name = str(item.get("root_case") or "")
        if root_name:
            output.append({"root_case": root_name, "score": float(item.get("score") or 0.0)})
    return output


def _modules_for_ranked_roots(ranked_roots: list[dict[str, Any]]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for item in ranked_roots:
        for module in modules_for_root(str(item.get("root_case") or "")):
            if module not in seen:
                seen.add(module)
                output.append(module)
    return output


def _recovery_from_knowledge(knowledge: dict[str, Any]) -> dict[str, Any]:
    summary = _nested(knowledge, "verification", "summary") or {}
    coverage = summary.get("archive_coverage") if isinstance(summary.get("archive_coverage"), dict) else {}
    score = _first_float(coverage, "completeness", "file_coverage", "byte_coverage")
    if score <= 0:
        score = _first_float(summary, "completeness", "complete_ratio")
    return {
        "score": _clamp01(score),
        "completeness": _clamp01(_first_float(summary, "completeness", default=score)),
        "assessment_status": str(summary.get("assessment_status") or ""),
        "decision_hint": str(summary.get("decision_hint") or ""),
        "archive_coverage": dict(coverage),
    }


def _first_float(payload: dict[str, Any], *keys: str, default: float = 0.0) -> float:
    for key in keys:
        try:
            value = payload.get(key)
            if value is not None:
                return float(value)
        except (TypeError, ValueError):
            continue
    return float(default)


def _nested(payload: dict[str, Any], *path: str) -> Any:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value or 0.0)))


def _select_rows(rows: list[dict[str, Any]], *, limit: int, profile: str) -> list[dict[str, Any]]:
    selected = []
    for row in rows:
        row_profile = str((row.get("metadata") or {}).get("damage_profile") or row.get("damage_profile") or "")
        if profile and row_profile != profile:
            continue
        selected.append(row)
        if limit > 0 and len(selected) >= limit:
            break
    return selected


def _summary(reports: list[dict[str, Any]], *, elapsed: float) -> dict[str, Any]:
    strategies: dict[str, list[dict[str, Any]]] = {}
    for report in reports:
        for topk, payload in (report.get("strategies") or {}).items():
            strategies.setdefault(topk, []).append(payload)
    strategy_summary = {}
    for topk, items in sorted(strategies.items(), key=lambda item: int(item[0])):
        strategy_summary[topk] = {
            "rows": len(items),
            "mean_initial_recovery": sum(float(item.get("initial_recovery") or 0.0) for item in items) / max(1, len(items)),
            "mean_best_recovery": sum(float(item.get("best_recovery") or 0.0) for item in items) / max(1, len(items)),
            "improved_rate": sum(1 for item in items if item.get("improved")) / max(1, len(items)),
            "complete_rate": sum(1 for item in items if item.get("complete")) / max(1, len(items)),
            "mean_rounds": sum(int(item.get("rounds") or 0) for item in items) / max(1, len(items)),
            **_module_stats(items),
        }
    return {
        "schema": "hgt_repair_guidance_eval_v1",
        "rows": len(reports),
        "elapsed_seconds": round(float(elapsed), 3),
        "strategies": strategy_summary,
    }


def _module_stats(items: list[dict[str, Any]]) -> dict[str, Any]:
    attempted = 0
    proposals = 0
    patch_state = 0
    materialization_failed = 0
    no_proposal = 0
    for item in items:
        for step in item.get("history") or []:
            for module in step.get("tried_modules") or []:
                attempted += 1
                count = int(module.get("candidate_count") or 0)
                proposals += count
                if count <= 0:
                    no_proposal += 1
                candidates = module.get("candidates") if isinstance(module.get("candidates"), list) else []
                if any(isinstance(candidate, dict) and candidate.get("has_repaired_state") for candidate in candidates):
                    patch_state += 1
                elif candidates:
                    materialization_failed += 1
    return {
        "module_attempts": attempted,
        "module_proposals": proposals,
        "patch_state_module_attempts": patch_state,
        "patch_state_attempt_rate": patch_state / max(1, attempted),
        "materialization_failed_attempts": materialization_failed,
        "materialization_failed_rate": materialization_failed / max(1, attempted),
        "no_proposal_attempts": no_proposal,
        "no_proposal_rate": no_proposal / max(1, attempted),
    }


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(value or "module"))[:120] or "module"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run real repair rollouts guided by Diagnosis HGT top-k root hypotheses.")
    parser.add_argument("--input", required=True, help="Damage rows JSONL with metadata.raw_damage_record.")
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    parser.add_argument("--limit", type=int, default=12)
    parser.add_argument("--profile", default="")
    parser.add_argument("--topks", default="1,3,5")
    parser.add_argument("--max-rounds", type=int, default=5)
    parser.add_argument("--max-modules-per-round", type=int, default=8)
    parser.add_argument("--min-improvement", type=float, default=0.01)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
