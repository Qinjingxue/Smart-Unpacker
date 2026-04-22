import argparse
import json
import os
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
TEST_MIN_INSPECTION_SIZE_BYTES = 0
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from smart_unpacker import DecompressionEngine
from smart_unpacker.detection.inspector import ArchiveInspector
from smart_unpacker.support.types import InspectionResult
from synthetic_samples import create_profile_dataset, temporary_generated_dir


DEFAULT_PROFILE_TARGET = "generated"
DEFAULT_PROFILE_FOCUS = ["fakepicture.jpg"]


def round_float(value: float) -> float:
    return round(value, 6)


def print_json_safe(payload: dict) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    try:
        print(text)
    except UnicodeEncodeError:
        print(json.dumps(payload, ensure_ascii=True, indent=2))


class ProfilingArchiveInspector(ArchiveInspector):
    def __init__(self, engine):
        super().__init__(engine)
        self.profile_records: dict[str, dict] = {}

    def _record_step(self, record: dict, step_name: str, fn):
        start = time.perf_counter()
        result = fn()
        record["steps"][step_name] = round_float(time.perf_counter() - start)
        return result

    def _stream_find_tail_magic_from_offset(self, norm_path, absolute_offset):
        start = time.perf_counter()
        result = super()._stream_find_tail_magic_from_offset(norm_path, absolute_offset)
        record = self.profile_records.get(os.path.normpath(norm_path))
        if record is not None:
            record["stream_tail_magic_seconds"] += time.perf_counter() - start
        return result

    def _stream_find_tail_after_markers(self, norm_path, markers):
        start = time.perf_counter()
        result = super()._stream_find_tail_after_markers(norm_path, markers)
        record = self.profile_records.get(os.path.normpath(norm_path))
        if record is not None:
            record["stream_marker_scan_seconds"] += time.perf_counter() - start
        return result

    def inspect_archive_candidate(self, path, relation=None, scene_context=None):
        norm_path = os.path.normpath(path)
        scene_cache_key = scene_context.target_dir if scene_context else None
        cache_key = (norm_path, scene_cache_key)
        cached = self.inspect_cache.get(cache_key)
        if cached is not None:
            return cached

        record = {
            "path": norm_path,
            "size_bytes": 0,
            "steps": {},
            "stream_marker_scan_seconds": 0.0,
            "stream_tail_magic_seconds": 0.0,
            "decision": "not_archive",
            "should_extract": False,
            "score": 0,
            "detected_ext": None,
            "validation_ok": False,
            "validation_skipped": False,
            "validation_encrypted": False,
            "probe_detected_archive": False,
            "probe_offset": 0,
            "reasons": [],
        }
        self.profile_records[norm_path] = record

        info = self._make_inspection(norm_path)
        overall_start = time.perf_counter()
        try:
            self._record_step(record, "stat_and_ext", lambda: self._apply_stat(record, info, norm_path))
            self._record_step(record, "size_extension_signals", lambda: self._apply_size_and_extension_signals(info, info.ext))
            self._record_step(record, "read_signature", lambda: self._apply_signature_read(record, info, norm_path))
            self._record_step(record, "detect_signature", lambda: self._detect_signature(info, record["signature"]))
            self._record_step(record, "magic_analysis", lambda: self._apply_magic_analysis(info, norm_path))
            self._record_step(record, "embedded_tail_analysis", lambda: self._apply_embedded_tail_analysis(info, info.ext, norm_path))
            if not info.magic_matched:
                self._record_step(record, "probe_analysis", lambda: self._apply_probe_analysis(info, info.ext, norm_path))
            else:
                record["steps"]["probe_analysis"] = 0.0
            self._record_step(record, "disguise_signal", lambda: self._apply_disguise_signal(info, info.ext))
            self._record_step(record, "split_signals", lambda: self._apply_split_signals(info, norm_path, info.ext))
            self._record_step(record, "validation_signal", lambda: self._apply_validation_signal(info, info.ext, norm_path))
            self._record_step(
                record,
                "scene_semantics",
                lambda: self.engine.scene_analyzer.apply_scene_semantics(info, relation, scene_context),
            )
            self._record_step(record, "finalize_decision", lambda: self._finalize_inspection_decision(info, info.ext))
        except Exception as exc:
            info.decision = "not_archive"
            info.should_extract = False
            info.reasons.append(f"-99 检查失败: {exc}")
            record["error"] = str(exc)
        finally:
            record["total_seconds"] = round_float(time.perf_counter() - overall_start)
            record["decision"] = info.decision
            record["should_extract"] = info.should_extract
            record["score"] = info.score
            record["detected_ext"] = info.detected_ext
            record["validation_ok"] = info.validation_ok
            record["validation_skipped"] = info.validation_skipped
            record["validation_encrypted"] = info.validation_encrypted
            record["probe_detected_archive"] = info.probe_detected_archive
            record["probe_offset"] = info.probe_offset
            record["reasons"] = list(info.reasons)
            record.pop("signature", None)

        self.inspect_cache[cache_key] = info
        return info

    @staticmethod
    def _apply_stat(record: dict, info: InspectionResult, norm_path: str):
        info.size = os.path.getsize(norm_path)
        _, ext = os.path.splitext(norm_path)
        info.ext = ext.lower()
        record["size_bytes"] = info.size

    @staticmethod
    def _apply_signature_read(record: dict, info: InspectionResult, norm_path: str):
        with open(norm_path, "rb") as handle:
            record["signature"] = handle.read(8)


class ProfilingEngine(DecompressionEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Keep profiling behavior stable regardless of repository-level config.
        self.MIN_SIZE = TEST_MIN_INSPECTION_SIZE_BYTES
        self.inspector = ProfilingArchiveInspector(self)
        self.inspect_cache = self.inspector.inspect_cache
        self.validation_cache = self.inspector.validation_cache
        self.probe_cache = self.inspector.probe_cache
        self.call_metrics = {
            "probe_calls": 0,
            "probe_seconds_total": 0.0,
            "validate_calls": 0,
            "validate_seconds_total": 0.0,
            "inspect_calls": 0,
            "inspect_seconds_total": 0.0,
            "scan_readonly_calls": 0,
            "scan_readonly_seconds_total": 0.0,
        }

    def _probe_archive_with_7z(self, path):
        self.call_metrics["probe_calls"] += 1
        start = time.perf_counter()
        try:
            return super()._probe_archive_with_7z(path)
        finally:
            self.call_metrics["probe_seconds_total"] += time.perf_counter() - start

    def _validate_with_7z(self, path):
        self.call_metrics["validate_calls"] += 1
        start = time.perf_counter()
        try:
            return super()._validate_with_7z(path)
        finally:
            self.call_metrics["validate_seconds_total"] += time.perf_counter() - start

    def inspect_archive_candidate(self, path, relation=None, scene_context=None):
        self.call_metrics["inspect_calls"] += 1
        start = time.perf_counter()
        try:
            return super().inspect_archive_candidate(path, relation=relation, scene_context=scene_context)
        finally:
            self.call_metrics["inspect_seconds_total"] += time.perf_counter() - start

    def scan_archives_readonly(self, target_dir=None):
        self.call_metrics["scan_readonly_calls"] += 1
        start = time.perf_counter()
        try:
            return super().scan_archives_readonly(target_dir=target_dir)
        finally:
            self.call_metrics["scan_readonly_seconds_total"] += time.perf_counter() - start


def build_parser():
    parser = argparse.ArgumentParser(
        description="Profile disguised archive detection performance and highlight hotspots."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=DEFAULT_PROFILE_TARGET,
        help="Target file or directory to profile. Defaults to a generated synthetic dataset.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum number of hottest files or steps to keep in summaries.",
    )
    parser.add_argument(
        "--focus",
        nargs="*",
        default=DEFAULT_PROFILE_FOCUS,
        help="Basename filters used to highlight specific heavy disguised samples.",
    )
    return parser


def collect_target_files(target_path: Path) -> list[Path]:
    if target_path.is_file():
        return [target_path]
    return sorted(path for path in target_path.rglob("*") if path.is_file())


def inspect_files(engine: ProfilingEngine, target_path: Path) -> list[dict]:
    records = []
    for file_path in collect_target_files(target_path):
        root = str(file_path.parent)
        filename = file_path.name
        scene_context = engine._resolve_scene_context_for_path(root, engine.root_dir)
        relation = engine._build_directory_relationships(root, [filename], scan_root=engine.root_dir)[filename]
        engine.inspect_archive_candidate(str(file_path), relation=relation, scene_context=scene_context)
        records.append(engine.inspector.profile_records[os.path.normpath(str(file_path))])
    return records


def summarize_hot_steps(records: list[dict], limit: int) -> list[dict]:
    step_totals: dict[str, float] = {}
    for record in records:
        for step_name, seconds in record["steps"].items():
            step_totals[step_name] = step_totals.get(step_name, 0.0) + seconds
        step_totals["stream_marker_scan_seconds"] = step_totals.get("stream_marker_scan_seconds", 0.0) + record["stream_marker_scan_seconds"]
        step_totals["stream_tail_magic_seconds"] = step_totals.get("stream_tail_magic_seconds", 0.0) + record["stream_tail_magic_seconds"]
    ranked = sorted(step_totals.items(), key=lambda item: item[1], reverse=True)
    return [{"step": name, "seconds_total": round_float(seconds)} for name, seconds in ranked[:limit]]


def summarize_hottest_files(records: list[dict], limit: int, focus_names: set[str]) -> dict:
    ranked = sorted(records, key=lambda item: item["total_seconds"], reverse=True)
    hottest = []
    focused = []
    for record in ranked[:limit]:
        hottest.append(
            {
                "path": record["path"],
                "size_bytes": record["size_bytes"],
                "total_seconds": record["total_seconds"],
                "stream_marker_scan_seconds": round_float(record["stream_marker_scan_seconds"]),
                "stream_tail_magic_seconds": round_float(record["stream_tail_magic_seconds"]),
                "decision": record["decision"],
                "detected_ext": record["detected_ext"],
                "validation_skipped": record["validation_skipped"],
                "steps": record["steps"],
            }
        )
    for record in ranked:
        if Path(record["path"]).name in focus_names:
            focused.append(
                {
                    "path": record["path"],
                    "size_bytes": record["size_bytes"],
                    "total_seconds": record["total_seconds"],
                    "stream_marker_scan_seconds": round_float(record["stream_marker_scan_seconds"]),
                    "stream_tail_magic_seconds": round_float(record["stream_tail_magic_seconds"]),
                    "decision": record["decision"],
                    "detected_ext": record["detected_ext"],
                    "validation_skipped": record["validation_skipped"],
                    "probe_offset": record["probe_offset"],
                    "steps": record["steps"],
                    "reasons": record["reasons"],
                }
            )
    return {"hottest_files": hottest, "focused_files": focused}


def summarize_scan_tasks(tasks, target_root: Path, limit: int) -> list[dict]:
    summary = []
    for task in tasks[:limit]:
        summary.append(
            {
                "key": str(Path(task.key).resolve().relative_to(target_root.resolve())),
                "main_path": str(Path(task.main_path).resolve().relative_to(target_root.resolve())),
                "parts_count": len(task.all_parts),
                "group_score": task.group_info.group_score,
                "decision": task.group_info.main_info.decision,
                "detected_ext": task.group_info.main_info.detected_ext,
                "validation_skipped": task.group_info.main_info.validation_skipped,
            }
        )
    return summary


def main():
    args = build_parser().parse_args()
    temp_ctx = None
    if args.path == DEFAULT_PROFILE_TARGET:
        temp_ctx = temporary_generated_dir("generated-profile-")
        generated_dir = Path(temp_ctx.name)
        create_profile_dataset(generated_dir)
        target_path = generated_dir.resolve()
    else:
        target_path = Path(args.path).resolve()
        if not target_path.exists():
            raise SystemExit(f"Target does not exist: {target_path}")

    try:
        root_dir = str(target_path if target_path.is_dir() else target_path.parent)
        inspect_engine = ProfilingEngine(root_dir, [], None, lambda: None, selected_paths=[str(target_path)])
        inspect_engine.max_workers_limit = 1
        inspect_engine.current_concurrency_limit = 1

        inspect_start = time.perf_counter()
        inspection_records = inspect_files(inspect_engine, target_path)
        inspect_elapsed = time.perf_counter() - inspect_start

        scan_engine = ProfilingEngine(root_dir, [], None, lambda: None, selected_paths=[str(target_path)])
        scan_engine.max_workers_limit = 1
        scan_engine.current_concurrency_limit = 1
        scan_start = time.perf_counter()
        tasks = scan_engine.scan_archives_readonly()
        scan_elapsed = time.perf_counter() - scan_start

        focus_names = {name for name in args.focus}
        total_inspect_seconds = sum(record["total_seconds"] for record in inspection_records)

        output = {
            "target": str(target_path),
            "generated_target": temp_ctx is not None,
            "file_count": len(inspection_records),
            "task_count": len(tasks),
            "timing": {
                "inspect_elapsed_seconds": round_float(inspect_elapsed),
                "scan_elapsed_seconds": round_float(scan_elapsed),
                "sum_file_inspect_seconds": round_float(total_inspect_seconds),
            },
            "engine_metrics": {
                "inspect_calls": inspect_engine.call_metrics["inspect_calls"],
                "inspect_seconds_total": round_float(inspect_engine.call_metrics["inspect_seconds_total"]),
                "inspect_probe_calls": inspect_engine.call_metrics["probe_calls"],
                "inspect_probe_seconds_total": round_float(inspect_engine.call_metrics["probe_seconds_total"]),
                "inspect_validate_calls": inspect_engine.call_metrics["validate_calls"],
                "inspect_validate_seconds_total": round_float(inspect_engine.call_metrics["validate_seconds_total"]),
                "scan_readonly_calls": scan_engine.call_metrics["scan_readonly_calls"],
                "scan_readonly_seconds_total": round_float(scan_engine.call_metrics["scan_readonly_seconds_total"]),
                "scan_probe_calls": scan_engine.call_metrics["probe_calls"],
                "scan_probe_seconds_total": round_float(scan_engine.call_metrics["probe_seconds_total"]),
                "scan_validate_calls": scan_engine.call_metrics["validate_calls"],
                "scan_validate_seconds_total": round_float(scan_engine.call_metrics["validate_seconds_total"]),
            },
            "hot_steps": summarize_hot_steps(inspection_records, args.limit),
            "hot_files": summarize_hottest_files(inspection_records, args.limit, focus_names),
            "scan_task_samples": summarize_scan_tasks(tasks, target_path if target_path.is_dir() else target_path.parent, args.limit),
        }
        print_json_safe(output)
    finally:
        if temp_ctx is not None:
            temp_ctx.cleanup()


if __name__ == "__main__":
    main()
