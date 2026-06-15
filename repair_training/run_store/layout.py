from __future__ import annotations

import datetime as _dt
import json
import re
from pathlib import Path
from typing import Any


TRAINING_ROOT = Path("repair_training")
RUNS_ROOT = TRAINING_ROOT / "runs"
EVALUATION_RUNS_ROOT = RUNS_ROOT / "evaluation"
TMP_ROOT = TRAINING_ROOT / "tmp"
LATEST_RUNS = TRAINING_ROOT / "latest_runs.json"
LEGACY_LATEST_RUN = TRAINING_ROOT / "latest_run.txt"


def safe_name(value: str, fallback: str = "run") -> str:
    output = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "")).strip("_")
    return output or fallback


def create_or_resolve_run_dir(*, format_name: str, run_name: str, run_dir: str | Path | None = None) -> Path:
    if str(run_dir or "").strip():
        return Path(run_dir).resolve()
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    return (RUNS_ROOT / format_name / f"{stamp}_{safe_name(run_name)}").resolve()


def ensure_run_layout(run_dir: Path) -> dict[str, Path]:
    paths = {
        "run_dir": run_dir,
        "datasets_dir": run_dir / "datasets",
        "models_dir": run_dir / "models",
        "reports_dir": run_dir / "reports",
        "logs_dir": run_dir / "logs",
        "tmp_dir": run_dir / "tmp",
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths


def create_evaluation_run_dir(run_dir: str | Path | None = None, *, run_name: str = "evaluation") -> Path:
    if run_dir:
        root = Path(run_dir).resolve()
    else:
        stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        root = (EVALUATION_RUNS_ROOT / f"{stamp}_{safe_name(run_name)}").resolve()
    ensure_run_layout(root)
    return root


def latest_training_dataset(format_name: str = "zip") -> Path:
    format_name = safe_name(format_name, fallback="zip")
    latest = latest_run_for_format(format_name)
    if latest is not None:
        dataset = latest / "datasets" / "runtime_graph_success.jsonl"
        if dataset.is_file():
            return dataset

    newest: tuple[int, Path] | None = None
    format_root = RUNS_ROOT / format_name
    try:
        run_dirs = list(format_root.iterdir())
    except OSError:
        run_dirs = []
    for run_dir in run_dirs:
        try:
            if not run_dir.is_dir():
                continue
            dataset = run_dir / "datasets" / "runtime_graph_success.jsonl"
            stat = dataset.stat()
        except OSError:
            continue
        candidate = (stat.st_mtime_ns, dataset)
        if newest is None or candidate[0] > newest[0]:
            newest = candidate
    if newest is not None:
        return newest[1]
    return TRAINING_ROOT / "datasets" / "runtime_graph_success.jsonl"


def read_latest_runs() -> dict[str, str]:
    if not LATEST_RUNS.is_file():
        return {}
    try:
        payload = json.loads(LATEST_RUNS.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def latest_run_for_format(format_name: str) -> Path | None:
    runs = read_latest_runs()
    value = str(runs.get(format_name) or "").strip()
    if value:
        path = Path(value).resolve()
        if path.is_dir():
            return path
    if format_name == "zip" and LEGACY_LATEST_RUN.is_file():
        legacy = LEGACY_LATEST_RUN.read_text(encoding="utf-8").strip()
        if legacy:
            path = Path(legacy).resolve()
            if path.is_dir():
                return path
    return None


def write_latest_run(format_name: str, run_dir: Path) -> None:
    runs = read_latest_runs()
    runs[format_name] = str(run_dir.resolve())
    LATEST_RUNS.parent.mkdir(parents=True, exist_ok=True)
    LATEST_RUNS.write_text(json.dumps(runs, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    if format_name == "zip":
        LEGACY_LATEST_RUN.write_text(str(run_dir.resolve()), encoding="utf-8")


def update_run_manifest(run_dir: Path, **updates: Any) -> None:
    manifest = run_dir / "run_manifest.json"
    payload: dict[str, Any] = {}
    if manifest.is_file():
        try:
            raw = json.loads(manifest.read_text(encoding="utf-8"))
            payload = raw if isinstance(raw, dict) else {}
        except json.JSONDecodeError:
            payload = {}
    payload.update(updates)
    manifest.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")
