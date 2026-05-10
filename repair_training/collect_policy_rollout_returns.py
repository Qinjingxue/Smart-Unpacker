from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_ROOT = ROOT / ".private"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    ab_jsonl = Path(args.ab_jsonl) if args.ab_jsonl else None
    if ab_jsonl is None:
        ab_jsonl = _run_runtime_ab(args)
    rows = _collect_rollout_rows(ab_jsonl)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    summary = {
        "ab_jsonl": str(ab_jsonl),
        "output": str(output),
        "rollout_row_count": len(rows),
        "unmatched_trace_count": sum(1 for row in rows if not row.get("selected_candidate_id")),
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect model single-path rollout returns from real runtime A/B traces.")
    parser.add_argument("--ab-jsonl", default="", help="Existing evaluate_runtime_policy_ab JSONL. If omitted, run the A/B tool.")
    parser.add_argument("--dataset", default=str(PRIVATE_ROOT / "zip_runtime_top5_full_20260510_051853_success.jsonl"))
    parser.add_argument("--sample-count", type=int, default=200)
    parser.add_argument("--seed", type=int, default=20260510)
    parser.add_argument("--case-timeout-seconds", type=float, default=45.0)
    parser.add_argument("--run-timeout-seconds", type=float, default=55.0)
    parser.add_argument("--max-rounds", type=int, default=5)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--output", default=str(PRIVATE_ROOT / "reports" / "policy_rollout_returns.jsonl"))
    return parser


def _run_runtime_ab(args: argparse.Namespace) -> Path:
    output_json = PRIVATE_ROOT / "reports" / "policy_rollout_source_ab.json"
    output_jsonl = PRIVATE_ROOT / "reports" / "policy_rollout_source_ab.jsonl"
    cmd = [
        sys.executable,
        str(PRIVATE_ROOT / "tools" / "evaluate_runtime_policy_ab.py"),
        "--dataset",
        str(args.dataset),
        "--sample-count",
        str(args.sample_count),
        "--seed",
        str(args.seed),
        "--case-timeout-seconds",
        str(args.case_timeout_seconds),
        "--run-timeout-seconds",
        str(args.run_timeout_seconds),
        "--max-rounds",
        str(args.max_rounds),
        "--workers",
        str(args.workers),
        "--parallel-mode",
        "worker_pool",
        "--enable-policy-probe",
        "--output-json",
        str(output_json),
        "--output-jsonl",
        str(output_jsonl),
    ]
    env = dict(**__import__("os").environ)
    env["PYTHONPATH"] = f"{PRIVATE_ROOT};{ROOT};{env.get('PYTHONPATH', '')}"
    subprocess.run(cmd, cwd=str(ROOT), env=env, check=True)
    return output_jsonl


def _collect_rollout_rows(ab_jsonl: Path) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for run in _read_jsonl(ab_jsonl):
        if str(run.get("mode") or "") != "zip_model_policy":
            continue
        selected = _selected_candidates_from_trace(Path(str(run.get("trace_path") or "")))
        if not selected:
            selected = _selected_candidates_from_probe(Path(str(run.get("probe_path") or "")))
        for index, item in enumerate(selected):
            output.append({
                "sample_id": run.get("sample_id"),
                "round": int(item.get("round", index) or 0),
                "state_candidate_set_hash": item.get("candidate_set_hash") or "",
                "selected_candidate_id": item.get("selected_candidate_id") or "",
                "selected_action_signature": item.get("selected_action_signature") or "",
                "selected_module": item.get("selected_module") or "",
                "final_recovery_ratio": float(run.get("recovery_ratio") or 0.0),
                "final_terminal_status": str(run.get("terminal_status") or ""),
                "action_path": list(run.get("repair_module_path") or []),
                "source_ab_row": {
                    "complete": bool(run.get("complete")),
                    "wall_seconds": run.get("wall_seconds"),
                    "policy_selected_count": run.get("policy_selected_count"),
                },
            })
    return output


def _selected_candidates_from_trace(path: Path) -> list[dict[str, Any]]:
    rows = []
    for event in _read_jsonl(path):
        if str(event.get("event") or "") != "repair_selected_result":
            continue
        selection = event.get("selection") if isinstance(event.get("selection"), dict) else {}
        policy = selection.get("policy") if isinstance(selection.get("policy"), dict) else {}
        candidate = event.get("candidate") if isinstance(event.get("candidate"), dict) else {}
        result = event.get("result") if isinstance(event.get("result"), dict) else {}
        selected_candidate_id = str(policy.get("selected_candidate_id") or candidate.get("candidate_id") or "")
        if not selected_candidate_id:
            continue
        rows.append({
            "round": len(rows),
            "selected_candidate_id": selected_candidate_id,
            "selected_module": result.get("module_name") or candidate.get("module_name") or candidate.get("module") or "",
            "selected_action_signature": _candidate_signature(candidate),
            "candidate_set_hash": "",
        })
    return rows


def _selected_candidates_from_probe(path: Path) -> list[dict[str, Any]]:
    output = []
    for event in _read_jsonl(path):
        if str(event.get("event") or "") != "policy_probe_decision":
            continue
        policy = event.get("policy") if isinstance(event.get("policy"), dict) else {}
        selected = event.get("selected_candidate") if isinstance(event.get("selected_candidate"), dict) else {}
        selected_candidate_id = str(policy.get("selected_candidate_id") or selected.get("candidate_id") or "")
        if selected_candidate_id:
            output.append({
                "round": int(event.get("round", len(output)) or 0),
                "selected_candidate_id": selected_candidate_id,
                "selected_module": selected.get("module_name") or selected.get("module") or "",
                "selected_action_signature": _candidate_signature(selected),
                "candidate_set_hash": event.get("candidate_set_hash") or "",
            })
    return output


def _candidate_signature(payload: dict[str, Any]) -> str:
    parts = [
        str(payload.get("module_name") or payload.get("module") or ""),
        str(payload.get("repair_name") or ""),
        str(payload.get("native_target") or ""),
        "|".join(str(item) for item in payload.get("patch_facts") or []),
    ]
    return "::".join(parts)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


if __name__ == "__main__":
    raise SystemExit(main())
