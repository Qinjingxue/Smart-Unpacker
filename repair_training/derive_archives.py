from __future__ import annotations

import argparse
import bz2
import concurrent.futures
import gzip
import hashlib
import io
import json
import lzma
import os
import random
import shutil
import subprocess
import sys
import tarfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DEFAULT_SOURCE_ROOT = Path("repair_training") / "source_material"
DEFAULT_MATERIAL_ROOT = Path("repair_training") / "material"
DEFAULT_CONFIG = Path("repair_training") / "archive_derivation_config.json"
DERIVED_SIDE_SUFFIX = ".derived.json"


DEFAULT_CONFIG_DATA: dict[str, Any] = {
    "tools": {
        "seven_zip": "tools/7z.exe",
        "rar": "tools/rar.exe",
        "zstd": "tools/zstd.exe",
    },
    "parallel": {
        "workers": 0,
        "task_timeout_seconds": 120,
    },
    "derivation": {
        "random_mode": {
            "enabled": True,
            "archives_per_sample": 5,
            "seed": "random",
        },
    },
    "formats": {
        "zip": {"enabled": True, "levels": [0, 5, 9], "methods": ["deflate", "store"]},
        "7z": {"enabled": True, "levels": [0, 5, 9], "methods": ["lzma2"], "solid": [True, False]},
        "tar": {"enabled": True},
        "tar_gz": {"enabled": True, "levels": [1, 6, 9]},
        "tar_bz2": {"enabled": True, "levels": [1, 6, 9]},
        "tar_xz": {"enabled": True, "levels": [0, 6, 9]},
        "gzip": {"enabled": True, "levels": [1, 6, 9]},
        "bzip2": {"enabled": True, "levels": [1, 6, 9]},
        "xz": {"enabled": True, "levels": [0, 6, 9]},
        "zstd": {"enabled": True, "levels": [1, 3, 10]},
        "rar": {"enabled": True, "levels": [0, 3, 5], "solid": [False]},
    },
}


@dataclass(frozen=True)
class DeriveTask:
    sample_id: str
    source_dir: Path
    material_root: Path
    material_format: str
    output_path: Path
    format: str
    method: str = ""
    level: int | None = None
    solid: bool | None = None
    tool: str = "python"
    tool_path: str = ""
    command: tuple[str, ...] = ()
    runner: Callable[["DeriveTask", float], None] | None = None


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    source_root = Path(args.source_root)
    material_root = Path(args.material_root)
    config_path = Path(args.config)
    config = _load_or_create_config(config_path)
    source_root.mkdir(parents=True, exist_ok=True)
    material_root.mkdir(parents=True, exist_ok=True)
    _ensure_material_format_dirs(material_root)

    formats = _csv_filter(args.formats)
    samples = set(args.sample or [])
    organized = _organize_root_source_files(source_root, samples)
    timeout = float(args.task_timeout_seconds or (config.get("parallel") or {}).get("task_timeout_seconds") or 120)
    workers_setting = int(args.workers if args.workers is not None else (config.get("parallel") or {}).get("workers") or 0)
    tools = _resolve_tools(config.get("tools") if isinstance(config.get("tools"), dict) else {})
    source_samples = _source_samples(source_root, samples)
    manifest_paths = {sample.name: sample / "derived_manifest.jsonl" for sample in source_samples}
    for sample in source_samples:
        _clear_previous_derived(sample, material_root)
    random_mode = _random_mode_config(config, args)
    tasks, skipped = _build_tasks(source_samples, material_root, config, tools, formats)
    all_task_count = len(tasks)
    if random_mode["enabled"]:
        tasks = _sample_tasks_by_source(tasks, int(random_mode["archives_per_sample"]), random_mode["seed"])
    workers = _resolve_workers(workers_setting, len(tasks))
    records = list(skipped)
    started = time.perf_counter()

    if tasks:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(_run_task, task, timeout) for task in tasks]
            for future in concurrent.futures.as_completed(futures):
                records.append(future.result())

    by_sample: dict[str, list[dict[str, Any]]] = {sample.name: [] for sample in source_samples}
    for record in records:
        by_sample.setdefault(str(record.get("sample_id") or ""), []).append(record)
    for sample_id, sample_records in by_sample.items():
        manifest_path = manifest_paths.get(sample_id)
        if manifest_path is None:
            continue
        _write_manifest(manifest_path, sample_records, bool(args.pretty))

    summary = {
        "source_root": str(source_root),
        "material_root": str(material_root),
        "config": str(config_path),
        "samples": len(source_samples),
        "organized_root_files": organized,
        "tasks": len(tasks),
        "available_tasks": all_task_count,
        "random_mode": random_mode,
        "workers": workers,
        "generated": sum(1 for record in records if record.get("status") == "generated"),
        "skipped": sum(1 for record in records if record.get("status") == "skipped"),
        "failed": sum(1 for record in records if record.get("status") == "failed"),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "missing_tools": {name: str(path) for name, path in tools.items() if path and not path.is_file()},
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 1 if summary["failed"] else 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Derive archive material from plain source folders for repair-plan training.")
    parser.add_argument("--source-root", default=str(DEFAULT_SOURCE_ROOT), help="Root containing <sample_id> source folders.")
    parser.add_argument("--material-root", default=str(DEFAULT_MATERIAL_ROOT), help="Output root for material/<format>/<sample_id> archives.")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="Archive derivation JSON config.")
    parser.add_argument("--formats", default="", help="Optional comma-separated format allowlist.")
    parser.add_argument("--sample", action="append", default=[], help="Optional source sample folder name filter. Repeatable.")
    parser.add_argument("--workers", type=int, default=None, help="Parallel workers. 0 means auto; defaults to config.")
    parser.add_argument("--task-timeout-seconds", type=float, default=0, help="Per external tool task timeout; defaults to config.")
    parser.add_argument("--random-mode", action="store_true", default=None, help="Randomly sample archive derivations per source sample.")
    parser.add_argument("--no-random-mode", action="store_false", dest="random_mode", help="Generate every enabled format/algorithm/level combination.")
    parser.add_argument("--archives-per-sample", type=int, default=0, help="Random mode archive budget per source sample; defaults to config.")
    parser.add_argument("--seed", default="", help="Random mode seed. Use 'random' for a fresh seed; defaults to config.")
    parser.set_defaults(pretty=True)
    parser.add_argument("--pretty", action="store_true", help="Also write formatted derived_manifest.pretty.json. Enabled by default.")
    parser.add_argument("--no-pretty", action="store_false", dest="pretty", help="Only write JSONL manifests.")
    return parser


def _load_or_create_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(DEFAULT_CONFIG_DATA, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return json.loads(json.dumps(DEFAULT_CONFIG_DATA))
    with path.open(encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise SystemExit(f"invalid derivation config: {path}")
    return _merged_config(loaded)


def _merged_config(loaded: dict[str, Any]) -> dict[str, Any]:
    merged = json.loads(json.dumps(DEFAULT_CONFIG_DATA))
    for key in ("tools", "parallel", "derivation", "formats"):
        if isinstance(loaded.get(key), dict):
            for item_key, item_value in loaded[key].items():
                if key == "formats" and isinstance(item_value, dict) and isinstance(merged[key].get(item_key), dict):
                    merged[key][item_key].update(item_value)
                elif key == "derivation" and item_key == "random_mode" and isinstance(item_value, dict) and isinstance(merged[key].get(item_key), dict):
                    merged[key][item_key].update(item_value)
                else:
                    merged[key][item_key] = item_value
    return merged


def _resolve_tools(raw: dict[str, Any]) -> dict[str, Path]:
    output: dict[str, Path] = {}
    for name, value in raw.items():
        if not value:
            continue
        path = Path(str(value))
        output[name] = path if path.is_absolute() else REPO_ROOT / path
    return output


def _source_samples(source_root: Path, samples: set[str]) -> list[Path]:
    if not source_root.exists():
        return []
    result = []
    for item in sorted(source_root.iterdir()):
        if not item.is_dir():
            continue
        if samples and item.name not in samples:
            continue
        if any(path.is_file() for path in item.rglob("*")):
            result.append(item)
    return result


def _organize_root_source_files(source_root: Path, samples: set[str]) -> int:
    moved = 0
    for path in sorted(source_root.iterdir()):
        if not path.is_file():
            continue
        if path.name in {".gitignore", ".gitkeep"}:
            continue
        sample_name = _safe_sample_name(path.stem)
        if samples and sample_name not in samples:
            continue
        sample_dir = _sample_dir_for_root_file(source_root, sample_name, path.name)
        sample_dir.mkdir(parents=True, exist_ok=True)
        target = sample_dir / path.name
        if target.exists():
            raise RuntimeError(f"refusing to overwrite source material file: {target}")
        shutil.move(str(path), str(target))
        moved += 1
    return moved


def _sample_dir_for_root_file(source_root: Path, sample_name: str, filename: str) -> Path:
    candidate = source_root / sample_name
    if not (candidate / filename).exists():
        return candidate
    index = 2
    while True:
        candidate = source_root / f"{sample_name}_{index}"
        if not (candidate / filename).exists():
            return candidate
        index += 1


def _safe_sample_name(raw: str) -> str:
    value = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in str(raw or "").strip())
    return value or "sample"


def _ensure_material_format_dirs(material_root: Path) -> None:
    for name in ("zip", "7z", "rar", "tar", "gzip", "bzip2", "xz", "zstd", "tar_gz", "tar_bz2", "tar_xz", "tar_zst"):
        (material_root / name).mkdir(parents=True, exist_ok=True)


def _clear_previous_derived(sample_dir: Path, material_root: Path) -> None:
    manifest = sample_dir / "derived_manifest.jsonl"
    if manifest.is_file():
        for record in _read_jsonl(manifest):
            output = Path(str(record.get("output_path") or ""))
            if output.is_absolute() and output.exists() and _is_inside(output, material_root):
                output.unlink()
            sidecar = Path(str(record.get("derivation_json_path") or ""))
            if sidecar.is_absolute() and sidecar.exists() and _is_inside(sidecar, material_root):
                sidecar.unlink()
    for target in (sample_dir / "derived_manifest.jsonl", sample_dir / "derived_manifest.pretty.json"):
        if target.exists():
            target.unlink()
    for format_dir in material_root.iterdir() if material_root.exists() else []:
        target_sample = format_dir / sample_dir.name
        if not target_sample.is_dir():
            continue
        for sidecar in sorted(target_sample.glob(f"*{DERIVED_SIDE_SUFFIX}")):
            output = _output_from_sidecar(sidecar)
            if output.exists() and _is_inside(output, target_sample):
                output.unlink()
            if sidecar.exists() and _is_inside(sidecar, target_sample):
                sidecar.unlink()
        damaged = target_sample / "damaged"
        if damaged.exists():
            if not _is_inside(damaged, target_sample):
                raise RuntimeError(f"refusing to remove generated damaged directory outside sample: {damaged}")
            shutil.rmtree(damaged)
        for name in ("damage_manifest.jsonl", "damage_manifest.pretty.json"):
            path = target_sample / name
            if path.exists():
                path.unlink()


def _build_tasks(source_samples: list[Path], material_root: Path, config: dict[str, Any], tools: dict[str, Path], formats: set[str]) -> tuple[list[DeriveTask], list[dict[str, Any]]]:
    tasks: list[DeriveTask] = []
    skipped: list[dict[str, Any]] = []
    format_config = config.get("formats") if isinstance(config.get("formats"), dict) else {}
    for sample in source_samples:
        for name, cfg in sorted(format_config.items()):
            if formats and name not in formats:
                continue
            if not isinstance(cfg, dict) or not bool(cfg.get("enabled", False)):
                continue
            builder = _TASK_BUILDERS.get(name)
            if builder is None:
                skipped.append(_skip_record(sample, name, "unsupported_format"))
                continue
            new_tasks, new_skipped = builder(sample, material_root, cfg, tools)
            tasks.extend(new_tasks)
            skipped.extend(new_skipped)
    return tasks, skipped


def _random_mode_config(config: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    derivation = config.get("derivation") if isinstance(config.get("derivation"), dict) else {}
    random_mode = derivation.get("random_mode") if isinstance(derivation.get("random_mode"), dict) else {}
    enabled = bool(random_mode.get("enabled", True))
    if args.random_mode is not None:
        enabled = bool(args.random_mode)
    archives_per_sample = int(args.archives_per_sample or random_mode.get("archives_per_sample") or 5)
    seed = str(args.seed or random_mode.get("seed") or "random")
    return {
        "enabled": enabled,
        "archives_per_sample": max(0, archives_per_sample),
        "seed": seed,
    }


def _sample_tasks_by_source(tasks: list[DeriveTask], archives_per_sample: int, raw_seed: str) -> list[DeriveTask]:
    if archives_per_sample <= 0:
        return []
    seed = _resolve_seed(raw_seed)
    output: list[DeriveTask] = []
    by_sample: dict[str, list[DeriveTask]] = {}
    for task in tasks:
        by_sample.setdefault(task.sample_id, []).append(task)
    for sample_id, sample_tasks in sorted(by_sample.items()):
        if len(sample_tasks) <= archives_per_sample:
            output.extend(sample_tasks)
            continue
        sample_seed = f"{seed}:{sample_id}"
        rng = random.Random(sample_seed)
        output.extend(sorted(rng.sample(sample_tasks, archives_per_sample), key=lambda item: (item.material_format, item.output_path.name)))
    return output


def _zip_tasks(sample: Path, material_root: Path, cfg: dict[str, Any], tools: dict[str, Path]) -> tuple[list[DeriveTask], list[dict[str, Any]]]:
    seven_zip = tools.get("seven_zip")
    if not seven_zip or not seven_zip.is_file():
        return [], [_skip_record(sample, "zip", "missing_tool", tool="seven_zip", tool_path=str(seven_zip or ""))]
    tasks = []
    for method in _as_list(cfg.get("methods") or ["deflate"]):
        for level in _levels(cfg, [5]):
            output = _output_path(material_root, "zip", sample.name, f"{sample.name}__zip__{method}__l{level}.zip")
            command = [str(seven_zip), "a", "-tzip", f"-mx={level}", "-y", str(output.resolve()), "."]
            command.insert(4, "-mm=Copy" if method == "store" else "-mm=Deflate")
            tasks.append(DeriveTask(sample.name, sample, material_root, "zip", output, "zip", method=str(method), level=level, tool="7z", tool_path=str(seven_zip), command=tuple(command), runner=_run_external))
    return tasks, []


def _seven_zip_tasks(sample: Path, material_root: Path, cfg: dict[str, Any], tools: dict[str, Path]) -> tuple[list[DeriveTask], list[dict[str, Any]]]:
    seven_zip = tools.get("seven_zip")
    if not seven_zip or not seven_zip.is_file():
        return [], [_skip_record(sample, "7z", "missing_tool", tool="seven_zip", tool_path=str(seven_zip or ""))]
    tasks = []
    for method in _as_list(cfg.get("methods") or ["lzma2"]):
        for solid in _as_list(cfg.get("solid") or [False]):
            for level in _levels(cfg, [5]):
                solid_bool = bool(solid)
                output = _output_path(material_root, "7z", sample.name, f"{sample.name}__7z__{method}__solid{int(solid_bool)}__l{level}.7z")
                command = [str(seven_zip), "a", "-t7z", f"-mx={level}", f"-m0={method}", f"-ms={'on' if solid_bool else 'off'}", "-y", str(output.resolve()), "."]
                tasks.append(DeriveTask(sample.name, sample, material_root, "7z", output, "7z", method=str(method), level=level, solid=solid_bool, tool="7z", tool_path=str(seven_zip), command=tuple(command), runner=_run_external))
    return tasks, []


def _rar_tasks(sample: Path, material_root: Path, cfg: dict[str, Any], tools: dict[str, Path]) -> tuple[list[DeriveTask], list[dict[str, Any]]]:
    rar = tools.get("rar")
    if not rar or not rar.is_file():
        return [], [_skip_record(sample, "rar", "missing_tool", tool="rar", tool_path=str(rar or ""))]
    tasks = []
    for solid in _as_list(cfg.get("solid") or [False]):
        for level in _levels(cfg, [3]):
            solid_bool = bool(solid)
            output = _output_path(material_root, "rar", sample.name, f"{sample.name}__rar__solid{int(solid_bool)}__m{level}.rar")
            command = [str(rar), "a", "-idq", "-r", f"-m{level}", "-ep1"]
            if solid_bool:
                command.append("-s")
            command.extend([str(output.resolve()), "*"])
            tasks.append(DeriveTask(sample.name, sample, material_root, "rar", output, "rar", method="rar", level=level, solid=solid_bool, tool="rar", tool_path=str(rar), command=tuple(command), runner=_run_external))
    return tasks, []


def _tar_tasks(sample: Path, material_root: Path, cfg: dict[str, Any], tools: dict[str, Path]) -> tuple[list[DeriveTask], list[dict[str, Any]]]:
    output = _output_path(material_root, "tar", sample.name, f"{sample.name}__tar.tar")
    return [DeriveTask(sample.name, sample, material_root, "tar", output, "tar", method="tar", runner=_run_tar)], []


def _compressed_tar_tasks(material_format: str, fmt: str, suffix: str, method: str, runner: Callable[[DeriveTask, float], None]) -> Callable[[Path, Path, dict[str, Any], dict[str, Path]], tuple[list[DeriveTask], list[dict[str, Any]]]]:
    def build(sample: Path, material_root: Path, cfg: dict[str, Any], tools: dict[str, Path]) -> tuple[list[DeriveTask], list[dict[str, Any]]]:
        tasks = []
        for level in _levels(cfg, [6]):
            output = _output_path(material_root, material_format, sample.name, f"{sample.name}__{material_format}__l{level}.{suffix}")
            tasks.append(DeriveTask(sample.name, sample, material_root, material_format, output, fmt, method=method, level=level, runner=runner))
        return tasks, []
    return build


def _stream_tasks(material_format: str, fmt: str, suffix: str, method: str, runner: Callable[[DeriveTask, float], None]) -> Callable[[Path, Path, dict[str, Any], dict[str, Path]], tuple[list[DeriveTask], list[dict[str, Any]]]]:
    def build(sample: Path, material_root: Path, cfg: dict[str, Any], tools: dict[str, Path]) -> tuple[list[DeriveTask], list[dict[str, Any]]]:
        tasks = []
        for level in _levels(cfg, [6]):
            output = _output_path(material_root, material_format, sample.name, f"{sample.name}__{material_format}__l{level}.{suffix}")
            tasks.append(DeriveTask(sample.name, sample, material_root, material_format, output, fmt, method=method, level=level, runner=runner))
        return tasks, []
    return build


def _zstd_tasks(sample: Path, material_root: Path, cfg: dict[str, Any], tools: dict[str, Path]) -> tuple[list[DeriveTask], list[dict[str, Any]]]:
    try:
        import zstandard  # noqa: F401
        runner = _run_zstd_python
        tool = "python-zstandard"
        tool_path = ""
    except Exception:
        zstd = tools.get("zstd")
        if not zstd or not zstd.is_file():
            return [], [_skip_record(sample, "zstd", "missing_tool", tool="zstd", tool_path=str(zstd or ""))]
        runner = _run_zstd_external
        tool = "zstd"
        tool_path = str(zstd)
    tasks = []
    for level in _levels(cfg, [3]):
        output = _output_path(material_root, "zstd", sample.name, f"{sample.name}__zstd__l{level}.zst")
        command: tuple[str, ...] = ()
        if tool == "zstd":
            command = (tool_path, "-f", f"-{level}", "-o", str(output.resolve()), "-")
        tasks.append(DeriveTask(sample.name, sample, material_root, "zstd", output, "zstd", method="zstd", level=level, tool=tool, tool_path=tool_path, command=command, runner=runner))
    return tasks, []


def _run_task(task: DeriveTask, timeout: float) -> dict[str, Any]:
    started = time.perf_counter()
    task.output_path.parent.mkdir(parents=True, exist_ok=True)
    if task.output_path.exists():
        task.output_path.unlink()
    try:
        if task.runner is None:
            raise RuntimeError("derive task has no runner")
        task.runner(task, timeout)
        if not task.output_path.is_file():
            raise RuntimeError("derive task did not create output archive")
        record = _base_record(task, "generated")
        record.update({
            "sha256": _sha256_path(task.output_path),
            "size": task.output_path.stat().st_size,
            "elapsed_seconds": round(time.perf_counter() - started, 3),
        })
        sidecar = Path(str(task.output_path) + DERIVED_SIDE_SUFFIX)
        record["derivation_json_path"] = str(sidecar)
        sidecar.write_text(json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return record
    except Exception as exc:
        if task.output_path.exists():
            task.output_path.unlink()
        record = _base_record(task, "failed")
        record["error"] = str(exc)
        record["elapsed_seconds"] = round(time.perf_counter() - started, 3)
        return record


def _run_external(task: DeriveTask, timeout: float) -> None:
    completed = subprocess.run(
        list(task.command),
        cwd=str(task.source_dir),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout if timeout > 0 else None,
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout or "").strip() or f"tool exited {completed.returncode}")


def _run_tar(task: DeriveTask, timeout: float) -> None:
    with tarfile.open(task.output_path, "w") as archive:
        _add_tree_to_tar(archive, task.source_dir)


def _run_tar_gz(task: DeriveTask, timeout: float) -> None:
    with tarfile.open(task.output_path, "w:gz", compresslevel=int(task.level or 6)) as archive:
        _add_tree_to_tar(archive, task.source_dir)


def _run_tar_bz2(task: DeriveTask, timeout: float) -> None:
    with tarfile.open(task.output_path, "w:bz2", compresslevel=int(task.level or 6)) as archive:
        _add_tree_to_tar(archive, task.source_dir)


def _run_tar_xz(task: DeriveTask, timeout: float) -> None:
    with tarfile.open(task.output_path, "w:xz", preset=int(task.level or 6)) as archive:
        _add_tree_to_tar(archive, task.source_dir)


def _run_gzip_stream(task: DeriveTask, timeout: float) -> None:
    payload = _tar_bytes(task.source_dir)
    with task.output_path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=int(task.level or 6), mtime=0) as handle:
            handle.write(payload)


def _run_bzip2_stream(task: DeriveTask, timeout: float) -> None:
    task.output_path.write_bytes(bz2.compress(_tar_bytes(task.source_dir), compresslevel=int(task.level or 6)))


def _run_xz_stream(task: DeriveTask, timeout: float) -> None:
    task.output_path.write_bytes(lzma.compress(_tar_bytes(task.source_dir), format=lzma.FORMAT_XZ, preset=int(task.level or 6)))


def _run_zstd_python(task: DeriveTask, timeout: float) -> None:
    import zstandard

    compressor = zstandard.ZstdCompressor(level=int(task.level or 3))
    task.output_path.write_bytes(compressor.compress(_tar_bytes(task.source_dir)))


def _run_zstd_external(task: DeriveTask, timeout: float) -> None:
    payload = _tar_bytes(task.source_dir)
    completed = subprocess.run(
        [str(task.tool_path), "-f", f"-{int(task.level or 3)}", "-o", str(task.output_path.resolve()), "-"],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout if timeout > 0 else None,
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout or b"").decode("utf-8", "replace").strip() or f"zstd exited {completed.returncode}")


_TASK_BUILDERS: dict[str, Callable[[Path, Path, dict[str, Any], dict[str, Path]], tuple[list[DeriveTask], list[dict[str, Any]]]]] = {
    "zip": _zip_tasks,
    "7z": _seven_zip_tasks,
    "rar": _rar_tasks,
    "tar": _tar_tasks,
    "tar_gz": _compressed_tar_tasks("tar_gz", "tar.gz", "tar.gz", "gzip", _run_tar_gz),
    "tar_bz2": _compressed_tar_tasks("tar_bz2", "tar.bz2", "tar.bz2", "bzip2", _run_tar_bz2),
    "tar_xz": _compressed_tar_tasks("tar_xz", "tar.xz", "tar.xz", "xz", _run_tar_xz),
    "gzip": _stream_tasks("gzip", "gzip", "gz", "gzip", _run_gzip_stream),
    "bzip2": _stream_tasks("bzip2", "bzip2", "bz2", "bzip2", _run_bzip2_stream),
    "xz": _stream_tasks("xz", "xz", "xz", "xz", _run_xz_stream),
    "zstd": _zstd_tasks,
}


def _add_tree_to_tar(archive: tarfile.TarFile, source_dir: Path) -> None:
    for path in sorted(source_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name.startswith("derived_manifest."):
            continue
        archive.add(path, arcname=str(path.relative_to(source_dir)).replace("\\", "/"), recursive=False)


def _tar_bytes(source_dir: Path) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        _add_tree_to_tar(archive, source_dir)
    return buffer.getvalue()


def _output_path(material_root: Path, material_format: str, sample_id: str, filename: str) -> Path:
    return material_root / material_format / sample_id / filename


def _base_record(task: DeriveTask, status: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": status,
        "sample_id": task.sample_id,
        "source_material_dir": str(task.source_dir),
        "material_format": task.material_format,
        "format": task.format,
        "method": task.method,
        "level": task.level,
        "solid": task.solid,
        "tool": task.tool,
        "tool_path": task.tool_path,
        "output_path": str(task.output_path),
        "output_name": task.output_path.name,
        "command": list(task.command),
    }


def _skip_record(sample: Path, material_format: str, reason: str, *, tool: str = "", tool_path: str = "") -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "skipped",
        "sample_id": sample.name,
        "source_material_dir": str(sample),
        "material_format": material_format,
        "format": material_format.replace("_", ".") if material_format.startswith("tar_") else material_format,
        "reason": reason,
        "tool": tool,
        "tool_path": tool_path,
    }


def _write_manifest(path: Path, records: list[dict[str, Any]], pretty: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    records = sorted(records, key=lambda item: (str(item.get("material_format") or ""), str(item.get("output_name") or ""), str(item.get("reason") or "")))
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str) + "\n")
    if pretty:
        path.with_name("derived_manifest.pretty.json").write_text(json.dumps(records, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            item = json.loads(line)
            if isinstance(item, dict):
                records.append(item)
    return records


def _output_from_sidecar(sidecar: Path) -> Path:
    try:
        loaded = json.loads(sidecar.read_text(encoding="utf-8"))
        if isinstance(loaded, dict) and loaded.get("output_path"):
            return Path(str(loaded["output_path"]))
    except Exception:
        pass
    name = sidecar.name
    if name.endswith(DERIVED_SIDE_SUFFIX):
        return sidecar.with_name(name[: -len(DERIVED_SIDE_SUFFIX)])
    return sidecar


def _levels(cfg: dict[str, Any], default: list[int]) -> list[int]:
    values = cfg.get("levels", default)
    if not isinstance(values, list):
        values = default
    return [int(value) for value in values]


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return [value]


def _csv_filter(raw: str) -> set[str]:
    return {item.strip().lower() for item in str(raw or "").split(",") if item.strip()}


def _resolve_seed(raw: str) -> int:
    if str(raw).strip().lower() in {"", "random", "none"}:
        return random.SystemRandom().randrange(1, 2**31 - 1) ^ int(time.time_ns() & 0x7FFFFFFF)
    return int(raw)


def _resolve_workers(workers: int, task_count: int) -> int:
    if task_count <= 0:
        return 1
    if workers and workers > 0:
        return max(1, min(int(workers), task_count))
    return max(1, min(task_count, os.cpu_count() or 1))


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
