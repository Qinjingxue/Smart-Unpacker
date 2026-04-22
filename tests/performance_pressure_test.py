import argparse
import json
import statistics
import subprocess
import tempfile
import threading
import time
import zipfile
from pathlib import Path

import edge_cases_test as helpers


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
LARGE_FILE_SIZE = 1 * 1024 * 1024 + 256 * 1024
ARCHIVE_FILE_SIZE = 2 * 1024 * 1024 + 128 * 1024
TEST_MIN_INSPECTION_SIZE_BYTES = 0


def build_parser():
    parser = argparse.ArgumentParser(description="Pressure test for archive grouping, probing, validation, and concurrency.")
    parser.add_argument("--normal-count", type=int, default=300, help="Number of ordinary large files to generate.")
    parser.add_argument("--true-archive-count", type=int, default=6, help="Number of real archives.")
    parser.add_argument("--disguised-archive-count", type=int, default=6, help="Number of disguised archives.")
    parser.add_argument("--encrypted-true-archive-count", type=int, default=0, help="Number of encrypted real archives.")
    parser.add_argument("--encrypted-disguised-archive-count", type=int, default=0, help="Number of encrypted disguised archives.")
    parser.add_argument("--container-count", type=int, default=8, help="Number of container files like docx/jar/apk.")
    parser.add_argument("--passwords", nargs="*", default=["123"], help="Passwords passed to the engine.")
    parser.add_argument("--encrypted-password", default="123", help="Password used when generating encrypted archives.")
    parser.add_argument("--no-builtin-passwords", action="store_true", help="Disable builtin password candidates for the pressure run.")
    parser.add_argument("--benchmark", action="store_true", help="Run a multi-round benchmark suite and print comparative summaries.")
    parser.add_argument(
        "--benchmark-profile",
        choices=["quick", "standard", "heavy"],
        default="standard",
        help="Preset suite used with --benchmark.",
    )
    return parser


def write_large_file(path: Path, label: str, size=LARGE_FILE_SIZE, mz=False):
    chunk = (f"PRESSURE::{label}::".encode("utf-8") * 4096)[:65536]
    with open(path, "wb") as handle:
        if mz:
            handle.write(b"MZ")
            remaining = size - 2
        else:
            remaining = size
        while remaining > 0:
            piece = chunk[: min(len(chunk), remaining)]
            handle.write(piece)
            remaining -= len(piece)


def write_archive_payload(source_dir: Path, archive_id: str):
    source_dir.mkdir(parents=True, exist_ok=True)
    marker_name = f"{archive_id}.marker.txt"
    marker_text = f"pressure::{archive_id}"
    (source_dir / marker_name).write_text(marker_text, encoding="utf-8")
    write_large_file(source_dir / "payload.bin", archive_id, size=ARCHIVE_FILE_SIZE)
    return marker_name, marker_text


def create_true_archive(work_dir: Path, archive_id: str, archive_format: str, password=None):
    source_dir = work_dir / f"{archive_id}_src"
    marker_name, marker_text = write_archive_payload(source_dir, archive_id)
    if archive_format == "7z":
        helpers.create_7z_archive(source_dir, work_dir / f"{archive_id}.7z", password=password)
        entry_name = f"{archive_id}.7z"
    elif archive_format == "zip":
        helpers.create_zip_archive(source_dir, work_dir / f"{archive_id}.zip", password=password)
        entry_name = f"{archive_id}.zip"
    elif archive_format == "rar":
        helpers.create_rar_archive(source_dir, work_dir / f"{archive_id}.rar", password=password)
        entry_name = f"{archive_id}.rar"
    else:
        raise ValueError(f"Unsupported archive format: {archive_format}")

    return {
        "id": archive_id,
        "kind": "true_archive",
        "entry_name": entry_name,
        "marker_name": marker_name,
        "marker_text": marker_text,
        "password_protected": bool(password),
    }


def create_disguised_archive(work_dir: Path, archive_id: str, archive_format: str, disguise_ext: str, password=None):
    metadata = create_true_archive(work_dir, archive_id, archive_format, password=password)
    original_path = work_dir / metadata["entry_name"]
    disguised_path = original_path.with_name(original_path.name + disguise_ext)
    original_path.rename(disguised_path)
    metadata["kind"] = "disguised_archive"
    metadata["entry_name"] = disguised_path.name
    metadata["disguise_ext"] = disguise_ext
    return metadata


def create_container_file(path: Path, container_type: str):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        if container_type == "jar":
            zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            zf.writestr("com/example/App.class", b"\xca\xfe\xba\xbe" * 64)
        elif container_type == "docx":
            zf.writestr("[Content_Types].xml", "<Types></Types>")
            zf.writestr("word/document.xml", "<w:document></w:document>")
            zf.writestr("_rels/.rels", "<Relationships></Relationships>")
        elif container_type == "apk":
            zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" * 128)
            zf.writestr("classes.dex", b"dex\n035\x00" * 512)
            zf.writestr("resources.arsc", b"\x02\x00\x0c\x00" * 512)
        elif container_type == "xlsx":
            zf.writestr("[Content_Types].xml", "<Types></Types>")
            zf.writestr("xl/workbook.xml", "<workbook></workbook>")
            zf.writestr("_rels/.rels", "<Relationships></Relationships>")
        else:
            raise ValueError(f"Unsupported container type: {container_type}")


def generate_pressure_corpus(
    root_dir: Path,
    normal_count: int,
    true_archive_count: int,
    disguised_archive_count: int,
    encrypted_true_archive_count: int,
    encrypted_disguised_archive_count: int,
    container_count: int,
    encrypted_password: str,
):
    categories = {
        "normal": [],
        "true_archives": [],
        "disguised_archives": [],
        "encrypted_true_archives": [],
        "encrypted_disguised_archives": [],
        "containers": [],
    }

    regular_exts = [".jpg", ".png", ".mp4", ".dll", ".pak", ".bin", ".dat", ".log"]
    for index in range(normal_count):
        ext = regular_exts[index % len(regular_exts)]
        file_path = root_dir / f"bulk_asset_{index:04d}{ext}"
        write_large_file(file_path, f"normal_{index}")
        categories["normal"].append(file_path.name)

    true_formats = ["7z", "zip", "rar"]
    for index in range(true_archive_count):
        archive_format = true_formats[index % len(true_formats)]
        metadata = create_true_archive(root_dir, f"real_archive_{index:02d}", archive_format)
        categories["true_archives"].append(metadata)

    disguise_exts = [".dat", ".bin", ".jpg", ".cache", ".resource", ".blob"]
    for index in range(disguised_archive_count):
        archive_format = true_formats[index % len(true_formats)]
        disguise_ext = disguise_exts[index % len(disguise_exts)]
        metadata = create_disguised_archive(root_dir, f"masked_archive_{index:02d}", archive_format, disguise_ext)
        categories["disguised_archives"].append(metadata)

    for index in range(encrypted_true_archive_count):
        archive_format = true_formats[index % len(true_formats)]
        metadata = create_true_archive(
            root_dir,
            f"encrypted_real_archive_{index:02d}",
            archive_format,
            password=encrypted_password,
        )
        categories["encrypted_true_archives"].append(metadata)

    for index in range(encrypted_disguised_archive_count):
        archive_format = true_formats[index % len(true_formats)]
        disguise_ext = disguise_exts[index % len(disguise_exts)]
        metadata = create_disguised_archive(
            root_dir,
            f"encrypted_masked_archive_{index:02d}",
            archive_format,
            disguise_ext,
            password=encrypted_password,
        )
        categories["encrypted_disguised_archives"].append(metadata)

    container_specs = [
        ("jar", ".jar"),
        ("docx", ".docx"),
        ("apk", ".apk"),
        ("xlsx", ".xlsx"),
    ]
    for index in range(container_count):
        container_type, ext = container_specs[index % len(container_specs)]
        path = root_dir / f"container_{index:02d}{ext}"
        create_container_file(path, container_type)
        categories["containers"].append({"name": path.name, "type": container_type})

    write_large_file(root_dir / "ordinary_tool.exe", "ordinary_tool", mz=True)
    write_large_file(root_dir / "ordinary_tool.part1.rar", "ordinary_tool_part")

    return categories


def make_instrumented_engine_class():
    base_class = helpers.load_engine_class()

    class InstrumentedEngine(base_class):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            # Keep the pressure suite stable regardless of repository-level config.
            self.MIN_SIZE = TEST_MIN_INSPECTION_SIZE_BYTES
            self.metrics = {
                "probe_calls": 0,
                "probe_cache_hits": 0,
                "probe_seconds_total": 0.0,
                "validate_calls": 0,
                "validate_cache_hits": 0,
                "validate_seconds_total": 0.0,
                "scan_calls": 0,
                "scan_seconds_total": 0.0,
                "extract_calls": 0,
                "extract_success": 0,
                "extract_fail": 0,
                "extract_seconds_total": 0.0,
                "find_password_calls": 0,
                "find_password_seconds_total": 0.0,
                "password_test_command_calls": 0,
                "password_extract_command_calls": 0,
                "initial_tasks_total": 0,
                "nested_tasks_total": 0,
                "task_group_sizes": [],
                "sampler_points": [],
                "extract_observed_active_workers": [],
            }

        def _probe_archive_with_7z(self, path):
            self.metrics["probe_calls"] += 1
            if path in self.probe_cache:
                self.metrics["probe_cache_hits"] += 1
            start = time.perf_counter()
            try:
                return super()._probe_archive_with_7z(path)
            finally:
                self.metrics["probe_seconds_total"] += time.perf_counter() - start

        def _validate_with_7z(self, path):
            self.metrics["validate_calls"] += 1
            if path in self.validation_cache:
                self.metrics["validate_cache_hits"] += 1
            start = time.perf_counter()
            try:
                return super()._validate_with_7z(path)
            finally:
                self.metrics["validate_seconds_total"] += time.perf_counter() - start

        def scan_archives(self, target_dir=None):
            self.metrics["scan_calls"] += 1
            start = time.perf_counter()
            tasks = super().scan_archives(target_dir=target_dir)
            self.metrics["scan_seconds_total"] += time.perf_counter() - start
            self.metrics["task_group_sizes"].extend(len(task.all_parts) for task in tasks)
            if target_dir is None or Path(target_dir).resolve() == Path(self.root_dir).resolve():
                self.metrics["initial_tasks_total"] += len(tasks)
            else:
                self.metrics["nested_tasks_total"] += len(tasks)
            return tasks

        def extract(self, task):
            self.metrics["extract_calls"] += 1
            start = time.perf_counter()
            stop_event = threading.Event()
            observer = threading.Thread(target=self._observe_extract_activity, args=(stop_event,), daemon=True)
            observer.start()
            try:
                result = super().extract(task)
                self.metrics["extract_seconds_total"] += time.perf_counter() - start
                if result:
                    self.metrics["extract_success"] += 1
                else:
                    self.metrics["extract_fail"] += 1
                return result
            finally:
                stop_event.set()
                observer.join(timeout=0.2)

        def _find_working_password(self, archive, startupinfo):
            self.metrics["find_password_calls"] += 1
            start = time.perf_counter()
            try:
                last_error = ""
                last_result = None
                passwords_to_try = list(self.passwords) if self.passwords else [""]
                for pwd in passwords_to_try:
                    self.metrics["password_test_command_calls"] += 1
                    cmd = [self.seven_z_path, "t", archive, "-y"]
                    if pwd:
                        cmd.append(f"-p{pwd}")
                    result = subprocess.run(cmd, capture_output=True, text=True, startupinfo=startupinfo)
                    combined = f"{result.stdout}\n{result.stderr}"
                    if result.returncode == 0:
                        self.add_recent_password(pwd)
                        return pwd, result, ""
                    last_result = result
                    last_error = combined.lower()
                    if self._has_archive_damage_signals(last_error) and not self._has_definite_wrong_password(last_error):
                        return pwd, result, last_error
                    if "wrong password" not in last_error:
                        return None, result, last_error
                return None, last_result, last_error
            finally:
                self.metrics["find_password_seconds_total"] += time.perf_counter() - start

        def _extract_archive_once(self, archive, out_dir, password, startupinfo):
            self.metrics["password_extract_command_calls"] += 1
            return super()._extract_archive_once(archive, out_dir, password, startupinfo)

        def run(self):
            sampler = threading.Thread(target=self._sample_runtime_metrics, daemon=True)
            self.is_running = True
            sampler.start()
            try:
                return super().run()
            finally:
                self.is_running = False
                sampler.join(timeout=1)

        def _sample_runtime_metrics(self):
            while self.is_running:
                with self.lock:
                    self.metrics["sampler_points"].append(
                        {
                            "timestamp": time.perf_counter(),
                            "active_workers": self.active_workers,
                            "concurrency_limit": self.current_concurrency_limit,
                        }
                    )
                time.sleep(0.2)

        def _observe_extract_activity(self, stop_event):
            while not stop_event.is_set():
                with self.lock:
                    self.metrics["extract_observed_active_workers"].append(self.active_workers)
                time.sleep(0.02)

    return InstrumentedEngine


def count_extracted_markers(root_dir: Path, archive_metadata):
    extracted = []
    for item in archive_metadata:
        candidates = list(root_dir.rglob(item["marker_name"]))
        matched = next((path for path in candidates if path.read_text(encoding="utf-8") == item["marker_text"]), None)
        if matched is not None:
            extracted.append(
                {
                    "id": item["id"],
                    "entry_name": item["entry_name"],
                    "path": str(matched.relative_to(root_dir)),
                }
            )
    return extracted


def summarize_sampler_points(points):
    if not points:
        return {
            "samples": 0,
            "peak_active_workers": 0,
            "peak_concurrency_limit": 0,
            "avg_active_workers": 0.0,
            "avg_concurrency_limit": 0.0,
        }
    active = [point["active_workers"] for point in points]
    limits = [point["concurrency_limit"] for point in points]
    return {
        "samples": len(points),
        "peak_active_workers": max(active),
        "peak_concurrency_limit": max(limits),
        "avg_active_workers": round(statistics.mean(active), 3),
        "avg_concurrency_limit": round(statistics.mean(limits), 3),
    }


def build_warnings(dataset_summary, engine_metrics, extracted_true, extracted_disguised):
    warnings = []
    total_files = dataset_summary["total_files"]
    probe_ratio = engine_metrics["probe_calls"] / total_files if total_files else 0.0
    validate_ratio = engine_metrics["validate_calls"] / total_files if total_files else 0.0

    expected_extractable = (
        dataset_summary["true_archive_count"]
        + dataset_summary["disguised_archive_count"]
        + dataset_summary["encrypted_true_archive_count"]
        + dataset_summary["encrypted_disguised_archive_count"]
    )
    actual_extractable = len(extracted_true) + len(extracted_disguised)

    if probe_ratio > 0.35:
        warnings.append(f"7z probe 次数占比偏高: {engine_metrics['probe_calls']} / {total_files} = {probe_ratio:.2%}")
    if validate_ratio > 0.35:
        warnings.append(f"7z validate 次数占比偏高: {engine_metrics['validate_calls']} / {total_files} = {validate_ratio:.2%}")
    if actual_extractable < expected_extractable:
        warnings.append(f"可解压归档提取数不足: expected={expected_extractable}, actual={actual_extractable}")
    observed_peak_workers = max(
        engine_metrics["runtime"]["peak_active_workers"],
        engine_metrics.get("extract_observed_peak_active_workers", 0),
    )
    if observed_peak_workers <= 1 and engine_metrics["detected_max_workers"] > 1:
        warnings.append("并发峰值未超过 1，可能没有有效利用并发能力")
    if expected_extractable and dataset_summary["encrypted_archive_count"] and engine_metrics["find_password_calls"] == 0:
        warnings.append("存在加密归档但未发生密码探测，请检查密码路径是否被覆盖")

    return warnings


def compute_ratios(dataset_summary, metrics):
    total_files = dataset_summary["total_files"] or 1
    return {
        "probe_ratio": round(metrics["probe_calls"] / total_files, 4),
        "validate_ratio": round(metrics["validate_calls"] / total_files, 4),
        "extract_ratio": round(metrics["extract_calls"] / total_files, 4),
    }


def run_single_pressure_case(config, InstrumentedEngine):
    with tempfile.TemporaryDirectory(prefix="performance-pressure-", dir=str(ROOT)) as temp_dir:
        work_dir = Path(temp_dir)
        dataset = generate_pressure_corpus(
            root_dir=work_dir,
            normal_count=config["normal_count"],
            true_archive_count=config["true_archive_count"],
            disguised_archive_count=config["disguised_archive_count"],
            encrypted_true_archive_count=config["encrypted_true_archive_count"],
            encrypted_disguised_archive_count=config["encrypted_disguised_archive_count"],
            container_count=config["container_count"],
            encrypted_password=config["encrypted_password"],
        )

        total_files = sum(1 for path in work_dir.rglob("*") if path.is_file())
        total_bytes = sum(path.stat().st_size for path in work_dir.rglob("*") if path.is_file())
        logs = []
        engine = InstrumentedEngine(
            str(work_dir),
            config["passwords"],
            logs.append,
            lambda: None,
            use_builtin_passwords=config["use_builtin_passwords"],
        )
        engine.max_workers_limit = max(1, engine.max_workers_limit)
        engine.current_concurrency_limit = min(engine.current_concurrency_limit, engine.max_workers_limit)

        start = time.perf_counter()
        engine.run()
        elapsed = time.perf_counter() - start

        all_true_archives = dataset["true_archives"] + dataset["encrypted_true_archives"]
        all_disguised_archives = dataset["disguised_archives"] + dataset["encrypted_disguised_archives"]
        extracted_true = count_extracted_markers(work_dir, all_true_archives)
        extracted_disguised = count_extracted_markers(work_dir, all_disguised_archives)

        metrics = {
            "detected_max_workers": engine.max_workers_limit,
            "final_concurrency_limit": engine.current_concurrency_limit,
            "probe_calls": engine.metrics["probe_calls"],
            "probe_cache_hits": engine.metrics["probe_cache_hits"],
            "probe_seconds_total": round(engine.metrics["probe_seconds_total"], 4),
            "validate_calls": engine.metrics["validate_calls"],
            "validate_cache_hits": engine.metrics["validate_cache_hits"],
            "validate_seconds_total": round(engine.metrics["validate_seconds_total"], 4),
            "scan_calls": engine.metrics["scan_calls"],
            "scan_seconds_total": round(engine.metrics["scan_seconds_total"], 4),
            "extract_calls": engine.metrics["extract_calls"],
            "extract_success": engine.metrics["extract_success"],
            "extract_fail": engine.metrics["extract_fail"],
            "extract_seconds_total": round(engine.metrics["extract_seconds_total"], 4),
            "find_password_calls": engine.metrics["find_password_calls"],
            "find_password_seconds_total": round(engine.metrics["find_password_seconds_total"], 4),
            "password_test_command_calls": engine.metrics["password_test_command_calls"],
            "password_extract_command_calls": engine.metrics["password_extract_command_calls"],
            "password_attempts_per_find": round(
                engine.metrics["password_test_command_calls"] / max(engine.metrics["find_password_calls"], 1),
                3,
            ),
            "use_builtin_passwords": bool(config["use_builtin_passwords"]),
            "configured_password_count": len(config["passwords"]),
            "builtin_password_count": len(engine.builtin_passwords),
            "initial_tasks_total": engine.metrics["initial_tasks_total"],
            "nested_tasks_total": engine.metrics["nested_tasks_total"],
            "avg_task_group_size": round(statistics.mean(engine.metrics["task_group_sizes"]), 3) if engine.metrics["task_group_sizes"] else 0.0,
            "max_task_group_size": max(engine.metrics["task_group_sizes"], default=0),
            "runtime": summarize_sampler_points(engine.metrics["sampler_points"]),
            "extract_observed_peak_active_workers": max(engine.metrics["extract_observed_active_workers"], default=0),
        }

        dataset_summary = {
            "normal_count": len(dataset["normal"]),
            "true_archive_count": len(dataset["true_archives"]),
            "disguised_archive_count": len(dataset["disguised_archives"]),
            "encrypted_true_archive_count": len(dataset["encrypted_true_archives"]),
            "encrypted_disguised_archive_count": len(dataset["encrypted_disguised_archives"]),
            "encrypted_archive_count": len(dataset["encrypted_true_archives"]) + len(dataset["encrypted_disguised_archives"]),
            "container_count": len(dataset["containers"]),
            "total_files": total_files,
            "total_bytes": total_bytes,
        }
        ratios = compute_ratios(dataset_summary, metrics)
        warnings = build_warnings(dataset_summary, metrics, extracted_true, extracted_disguised)

        return {
            "case_id": config["case_id"],
            "label": config["label"],
            "overall_seconds": round(elapsed, 4),
            "dataset": dataset_summary,
            "metrics": metrics,
            "ratios": ratios,
            "extracted_true_archives": extracted_true,
            "extracted_disguised_archives": extracted_disguised,
            "failed_tasks": list(engine.failed_tasks),
            "warnings": warnings,
            "logs_tail": logs[-120:],
        }


def build_benchmark_suite(profile, passwords):
    if profile == "quick":
        cases = [
            {"case_id": "quick_s", "label": "Quick Small", "normal_count": 200, "true_archive_count": 4, "disguised_archive_count": 4, "container_count": 6},
            {"case_id": "quick_m", "label": "Quick Medium", "normal_count": 500, "true_archive_count": 6, "disguised_archive_count": 6, "container_count": 10},
            {
                "case_id": "quick_pwd_builtin",
                "label": "Quick Password Builtin",
                "normal_count": 220,
                "true_archive_count": 3,
                "disguised_archive_count": 3,
                "encrypted_true_archive_count": 2,
                "encrypted_disguised_archive_count": 2,
                "container_count": 6,
                "passwords": [],
                "encrypted_password": "123",
                "use_builtin_passwords": True,
            },
        ]
    elif profile == "heavy":
        cases = [
            {"case_id": "heavy_s", "label": "Heavy Small", "normal_count": 500, "true_archive_count": 6, "disguised_archive_count": 6, "container_count": 10},
            {"case_id": "heavy_m", "label": "Heavy Medium", "normal_count": 1200, "true_archive_count": 10, "disguised_archive_count": 10, "container_count": 16},
            {"case_id": "heavy_l", "label": "Heavy Large", "normal_count": 2000, "true_archive_count": 14, "disguised_archive_count": 14, "container_count": 24},
            {
                "case_id": "heavy_pwd_builtin",
                "label": "Heavy Password Builtin",
                "normal_count": 1000,
                "true_archive_count": 8,
                "disguised_archive_count": 8,
                "encrypted_true_archive_count": 4,
                "encrypted_disguised_archive_count": 4,
                "container_count": 14,
                "passwords": [],
                "encrypted_password": "123",
                "use_builtin_passwords": True,
            },
        ]
    else:
        cases = [
            {"case_id": "std_s", "label": "Standard Small", "normal_count": 300, "true_archive_count": 6, "disguised_archive_count": 6, "container_count": 8},
            {"case_id": "std_m", "label": "Standard Medium", "normal_count": 800, "true_archive_count": 8, "disguised_archive_count": 8, "container_count": 12},
            {"case_id": "std_l", "label": "Standard Large", "normal_count": 1500, "true_archive_count": 12, "disguised_archive_count": 12, "container_count": 18},
            {
                "case_id": "std_pwd_builtin",
                "label": "Standard Password Builtin",
                "normal_count": 450,
                "true_archive_count": 5,
                "disguised_archive_count": 5,
                "encrypted_true_archive_count": 3,
                "encrypted_disguised_archive_count": 3,
                "container_count": 8,
                "passwords": [],
                "encrypted_password": "123",
                "use_builtin_passwords": True,
            },
            {
                "case_id": "std_pwd_no_builtin",
                "label": "Standard Password No Builtin",
                "normal_count": 450,
                "true_archive_count": 5,
                "disguised_archive_count": 5,
                "encrypted_true_archive_count": 3,
                "encrypted_disguised_archive_count": 3,
                "container_count": 8,
                "passwords": ["123"],
                "encrypted_password": "123",
                "use_builtin_passwords": False,
            },
        ]

    for case in cases:
        case.setdefault("encrypted_true_archive_count", 0)
        case.setdefault("encrypted_disguised_archive_count", 0)
        case.setdefault("encrypted_password", "123")
        case.setdefault("use_builtin_passwords", True)
        case["passwords"] = list(case.get("passwords", passwords))
    return cases


def summarize_benchmark_runs(runs):
    comparisons = []
    baseline = runs[0]
    for run in runs:
        comparisons.append(
            {
                "case_id": run["case_id"],
                "label": run["label"],
                "total_files": run["dataset"]["total_files"],
                "overall_seconds": run["overall_seconds"],
                "seconds_per_100_files": round(run["overall_seconds"] / max(run["dataset"]["total_files"], 1) * 100, 4),
                "probe_ratio": run["ratios"]["probe_ratio"],
                "validate_ratio": run["ratios"]["validate_ratio"],
                "extract_ratio": run["ratios"]["extract_ratio"],
                "scan_seconds_total": run["metrics"]["scan_seconds_total"],
                "probe_seconds_total": run["metrics"]["probe_seconds_total"],
                "validate_seconds_total": run["metrics"]["validate_seconds_total"],
                "extract_seconds_total": run["metrics"]["extract_seconds_total"],
                "find_password_calls": run["metrics"]["find_password_calls"],
                "find_password_seconds_total": run["metrics"]["find_password_seconds_total"],
                "password_test_command_calls": run["metrics"]["password_test_command_calls"],
                "password_attempts_per_find": run["metrics"]["password_attempts_per_find"],
                "encrypted_archive_count": run["dataset"]["encrypted_archive_count"],
                "use_builtin_passwords": run["metrics"]["use_builtin_passwords"],
                "peak_active_workers": max(
                    run["metrics"]["runtime"]["peak_active_workers"],
                    run["metrics"]["extract_observed_peak_active_workers"],
                ),
                "warning_count": len(run["warnings"]),
                "delta_vs_first_seconds": round(run["overall_seconds"] - baseline["overall_seconds"], 4),
                "delta_vs_first_probe_ratio": round(run["ratios"]["probe_ratio"] - baseline["ratios"]["probe_ratio"], 4),
                "delta_vs_first_validate_ratio": round(run["ratios"]["validate_ratio"] - baseline["ratios"]["validate_ratio"], 4),
            }
        )

    aggregate = {
        "fastest_case": min(comparisons, key=lambda item: item["overall_seconds"])["case_id"],
        "slowest_case": max(comparisons, key=lambda item: item["overall_seconds"])["case_id"],
        "lowest_probe_ratio_case": min(comparisons, key=lambda item: item["probe_ratio"])["case_id"],
        "highest_probe_ratio_case": max(comparisons, key=lambda item: item["probe_ratio"])["case_id"],
        "lowest_validate_ratio_case": min(comparisons, key=lambda item: item["validate_ratio"])["case_id"],
        "highest_validate_ratio_case": max(comparisons, key=lambda item: item["validate_ratio"])["case_id"],
        "peak_observed_workers": max(item["peak_active_workers"] for item in comparisons),
        "total_benchmark_seconds": round(sum(item["overall_seconds"] for item in comparisons), 4),
    }
    return {"comparisons": comparisons, "aggregate": aggregate}


def main():
    args = build_parser().parse_args()
    helpers.ensure_prerequisites()
    InstrumentedEngine = make_instrumented_engine_class()
    if args.benchmark:
        suite = build_benchmark_suite(args.benchmark_profile, args.passwords)
        runs = [run_single_pressure_case(config, InstrumentedEngine) for config in suite]
        output = {
            "mode": "benchmark",
            "profile": args.benchmark_profile,
            "runs": runs,
            "summary": summarize_benchmark_runs(runs),
        }
    else:
        config = {
            "case_id": "single",
            "label": "Single Run",
            "normal_count": args.normal_count,
            "true_archive_count": args.true_archive_count,
            "disguised_archive_count": args.disguised_archive_count,
            "encrypted_true_archive_count": args.encrypted_true_archive_count,
            "encrypted_disguised_archive_count": args.encrypted_disguised_archive_count,
            "container_count": args.container_count,
            "passwords": args.passwords,
            "encrypted_password": args.encrypted_password,
            "use_builtin_passwords": not args.no_builtin_passwords,
        }
        output = run_single_pressure_case(config, InstrumentedEngine)

    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
