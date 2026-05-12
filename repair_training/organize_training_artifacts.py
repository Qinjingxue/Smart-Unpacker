from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TRAINING_ROOT = ROOT / "repair_training"
RUNS_ROOT = TRAINING_ROOT / "runs"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    actions: list[dict[str, Any]] = []
    run_dir = _resolve_run_dir(args)
    if args.migrate_latest_sunpack:
        _plan_latest_sunpack_migration(run_dir, actions)
    if args.clean_legacy:
        _plan_cleanup(actions)
    _print_actions(actions)
    if args.apply:
        _apply_actions(actions)
        _write_latest_run(run_dir)
        _write_manifest(run_dir, actions)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Organize repair training datasets/models into repair_training/runs and remove temporary artifacts.")
    parser.add_argument("--run-dir", default="", help="Destination run directory. Defaults to repair_training/runs/<date>_organized.")
    parser.add_argument("--run-name", default="organized", help="Run name suffix used when --run-dir is omitted.")
    parser.add_argument("--migrate-latest-sunpack", action="store_true", default=True, help="Move latest .sunpack/runtime_graph_full_zip_* files into the run datasets/logs/tmp layout.")
    parser.add_argument("--no-migrate-latest-sunpack", dest="migrate_latest_sunpack", action="store_false")
    parser.add_argument("--clean-legacy", action="store_true", default=True, help="Remove legacy datasets/models/temp artifacts outside runs.")
    parser.add_argument("--no-clean-legacy", dest="clean_legacy", action="store_false")
    parser.add_argument("--apply", action="store_true", help="Apply planned moves/deletes. Without this, only prints a dry-run plan.")
    return parser


def _resolve_run_dir(args: argparse.Namespace) -> Path:
    if args.run_dir:
        return (ROOT / args.run_dir).resolve() if not Path(args.run_dir).is_absolute() else Path(args.run_dir).resolve()
    safe = _safe_name(args.run_name or "organized")
    return (RUNS_ROOT / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{safe}").resolve()


def _plan_latest_sunpack_migration(run_dir: Path, actions: list[dict[str, Any]]) -> None:
    sunpack = ROOT / ".sunpack"
    summaries = sorted(sunpack.glob("runtime_graph_full_zip_*_summary.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not summaries:
        return
    summary = summaries[0]
    prefix = summary.name.removesuffix("_summary.json")
    mapping = {
        sunpack / f"{prefix}_success.jsonl": run_dir / "datasets" / "runtime_graph_success.jsonl",
        sunpack / f"{prefix}_failure.jsonl": run_dir / "datasets" / "runtime_graph_failure.jsonl",
        sunpack / f"{prefix}_summary.json": run_dir / "datasets" / "runtime_graph_summary.json",
        sunpack / f"{prefix}_debug.jsonl": run_dir / "logs" / "debug_events.jsonl",
    }
    workspace = sunpack / f"{prefix}_ws"
    if workspace.exists():
        mapping[workspace] = run_dir / "tmp" / "workspace"
    for src, dst in mapping.items():
        if src.exists():
            actions.append({"action": "move", "src": str(src), "dst": str(dst)})


def _plan_cleanup(actions: list[dict[str, Any]]) -> None:
    for path in [
        TRAINING_ROOT / "__pycache__",
        TRAINING_ROOT / "_test_out",
        TRAINING_ROOT / "_test_out2",
        ROOT / ".sunpack" / "runtime-repair-graph",
    ]:
        if path.exists():
            actions.append({"action": "delete", "path": str(path)})
    for root in [TRAINING_ROOT / "datasets", TRAINING_ROOT / "models"]:
        if root.exists():
            actions.append({"action": "delete", "path": str(root)})
    sunpack = ROOT / ".sunpack"
    if sunpack.exists():
        for path in sunpack.iterdir():
            if path.name == "corpus":
                continue
            if path.exists():
                actions.append({"action": "delete", "path": str(path)})


def _apply_actions(actions: list[dict[str, Any]]) -> None:
    for action in actions:
        if action["action"] == "move":
            src = Path(action["src"])
            dst = Path(action["dst"])
            _assert_safe_destination(dst)
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists():
                if dst.is_dir():
                    shutil.rmtree(dst)
                else:
                    dst.unlink()
            shutil.move(str(src), str(dst))
        elif action["action"] == "delete":
            path = Path(action["path"])
            _assert_safe_delete(path)
            if path.is_dir():
                shutil.rmtree(path)
            elif path.exists():
                path.unlink()


def _write_latest_run(run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (TRAINING_ROOT / "latest_run.txt").write_text(str(run_dir) + "\n", encoding="utf-8")


def _write_manifest(run_dir: Path, actions: list[dict[str, Any]]) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    summary_path = run_dir / "datasets" / "runtime_graph_summary.json"
    summary = {}
    if summary_path.is_file():
        try:
            raw_summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary = raw_summary if isinstance(raw_summary, dict) else {}
        except json.JSONDecodeError:
            summary = {}
    payload = {
        "status": "organized",
        "collector": "runtime_repair_graph",
        "organized_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "run_dir": str(run_dir),
        "outputs": {
            "success_output": str(run_dir / "datasets" / "runtime_graph_success.jsonl"),
            "failure_output": str(run_dir / "datasets" / "runtime_graph_failure.jsonl"),
            "summary_output": str(summary_path),
        },
        "summary": summary,
        "actions": actions,
    }
    manifest = run_dir / "run_manifest.json"
    if manifest.exists():
        try:
            existing = json.loads(manifest.read_text(encoding="utf-8"))
            if isinstance(existing, dict):
                payload = {**existing, **payload, "organization": payload}
        except json.JSONDecodeError:
            pass
    manifest.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def _print_actions(actions: list[dict[str, Any]]) -> None:
    print(json.dumps({"dry_run_actions": actions, "action_count": len(actions)}, ensure_ascii=False, indent=2))


def _assert_safe_destination(path: Path) -> None:
    resolved = path.resolve()
    runs = RUNS_ROOT.resolve()
    if runs not in resolved.parents and resolved != runs:
        raise RuntimeError(f"refusing to write outside repair_training/runs: {resolved}")


def _assert_safe_delete(path: Path) -> None:
    resolved = path.resolve()
    allowed_roots = [
        (ROOT / ".sunpack").resolve(),
        TRAINING_ROOT.resolve(),
    ]
    if not any(root == resolved or root in resolved.parents for root in allowed_roots):
        raise RuntimeError(f"refusing to delete outside workspace training/temp roots: {resolved}")
    protected = {
        (TRAINING_ROOT / "material").resolve(),
        (TRAINING_ROOT / "source_material").resolve(),
    }
    if resolved in protected or any(protected_path in resolved.parents for protected_path in protected):
        raise RuntimeError(f"refusing to delete protected training source material: {resolved}")


def _safe_name(value: str) -> str:
    output = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(value)).strip("._-")
    return output or "organized"


if __name__ == "__main__":
    raise SystemExit(main())
