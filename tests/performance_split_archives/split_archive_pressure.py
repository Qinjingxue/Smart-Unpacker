import json
import argparse
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from smart_unpacker.coordinator.runner import PipelineRunner
from smart_unpacker.coordinator.scanner import ScanOrchestrator
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.real_archives import ArchiveCase, ArchiveFixtureFactory
from tests.helpers.tool_config import require_7z


PASSWORD = "split-secret"
WRONG_PASSWORD = "wrong-password"
PAYLOAD_SIZE = 180 * 1024


@dataclass
class PressureCase:
    name: str
    case: ArchiveCase
    passwords: list[str]
    expected: str
    build_seconds: float


def pressure_config(passwords: list[str] | None = None) -> dict:
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "recursive_extract": {"mode": "fixed", "max_rounds": 1},
        "post_extract": {
            "archive_cleanup_mode": "keep",
            "flatten_single_directory": False,
        },
        "user_passwords": passwords or [],
        "builtin_passwords": [],
        "max_retries": 1,
        "performance": {"scheduler_profile": "single"},
    }, hard_stop=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
    ], scoring=[
        {
            "name": "extension",
            "enabled": True,
            "extension_score_groups": [{"score": 5, "extensions": [".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".001", ".exe"]}],
        },
        {"name": "archive_identity", "enabled": True},
    ], confirmation=[
        {"name": "seven_zip_probe", "enabled": True},
        {"name": "seven_zip_validation", "enabled": True, "reject_on_failed": False},
    ])


def timed(factory: Callable[[], ArchiveCase]) -> tuple[ArchiveCase, float]:
    started = time.perf_counter()
    case = factory()
    return case, time.perf_counter() - started


def create_case(root: Path, case_id: str, **kwargs) -> tuple[ArchiveCase, float]:
    factory = ArchiveFixtureFactory()
    return timed(lambda: factory.create(root, case_id, "7z", payload_size=PAYLOAD_SIZE, **kwargs))


def keep_only_first_part(case: ArchiveCase):
    parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file() and path.name.endswith(tuple(f".{i:03d}" for i in range(1, 100))))
    for part in parts[1:]:
        part.unlink()


def corrupt_second_part(case: ArchiveCase):
    parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file() and path.name.endswith(tuple(f".{i:03d}" for i in range(1, 100))))
    if len(parts) < 2:
        raise RuntimeError(f"Expected at least two split parts for {case.case_id}")
    second = parts[1]
    raw = bytearray(second.read_bytes())
    if len(raw) < 64:
        raw.extend(b"x" * (64 - len(raw)))
    start = max(8, len(raw) // 3)
    raw[start:start + 32] = b"\0" * 32
    second.write_bytes(raw)


def misname_second_part(case: ArchiveCase):
    parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file() and path.name.endswith(tuple(f".{i:03d}" for i in range(1, 100))))
    if len(parts) < 2:
        raise RuntimeError(f"Expected at least two split parts for {case.case_id}")
    second = parts[1]
    target = second.with_name(f"{case.case_id}.7z")
    if target.exists():
        target.unlink()
    second.rename(target)
    for extra in parts[2:]:
        extra.unlink()


def ensure_two_part_shape(case: ArchiveCase):
    parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file() and path.name.endswith(tuple(f".{i:03d}" for i in range(1, 100))))
    if len(parts) > 2:
        for extra in parts[2:]:
            extra.unlink()


def build_cases(root: Path) -> list[PressureCase]:
    cases: list[PressureCase] = []

    case, build = create_case(root, "archive", split=True)
    ensure_two_part_shape(case)
    cases.append(PressureCase("normal_split", case, [], "success", build))

    case, build = create_case(root, "missing", split=True)
    keep_only_first_part(case)
    cases.append(PressureCase("missing_only_001", case, [], "failure", build))

    case, build = create_case(root, "corrupt", split=True)
    ensure_two_part_shape(case)
    corrupt_second_part(case)
    cases.append(PressureCase("corrupt_second_part", case, [], "failure", build))

    case, build = create_case(root, "encrypted", split=True, password=PASSWORD)
    ensure_two_part_shape(case)
    cases.append(PressureCase("encrypted_no_password", case, [], "failure", build))
    cases.append(PressureCase("encrypted_wrong_password", case, [WRONG_PASSWORD], "failure", 0.0))
    cases.append(PressureCase("encrypted_correct_password", case, [PASSWORD], "success", 0.0))

    case, build = create_case(root, "sfxsplit", split=True, sfx=True)
    ensure_two_part_shape(case)
    cases.append(PressureCase("sfx_split", case, [], "success", build))

    case, build = create_case(root, "misnamed", split=True)
    misname_second_part(case)
    cases.append(PressureCase("misnamed_split_member", case, [], "success", build))

    return cases


def marker_extracted(case: ArchiveCase) -> bool:
    for path in case.archive_dir.rglob(case.marker_name):
        try:
            if path.read_text(encoding="utf-8") == case.marker_text:
                return True
        except OSError:
            pass
    return False


def clean_outputs(case: ArchiveCase):
    for path in case.archive_dir.iterdir():
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)


def run_case(pressure_case: PressureCase) -> dict:
    clean_outputs(pressure_case.case)

    scan_config = pressure_config(passwords=pressure_case.passwords)
    started = time.perf_counter()
    scan_results = ScanOrchestrator(scan_config).scan(str(pressure_case.case.archive_dir))
    scan_seconds = time.perf_counter() - started

    started = time.perf_counter()
    summary = PipelineRunner(pressure_config(passwords=pressure_case.passwords)).run(str(pressure_case.case.archive_dir))
    pipeline_seconds = time.perf_counter() - started

    extracted = marker_extracted(pressure_case.case)
    observed = "success" if summary.success_count > 0 and extracted else "failure"
    pipeline_status = "success" if summary.success_count > 0 else "failure"
    return {
        "case": pressure_case.name,
        "expected": pressure_case.expected,
        "observed": observed,
        "pipeline_status": pipeline_status,
        "marker_extracted": extracted,
        "build_ms": round(pressure_case.build_seconds * 1000, 2),
        "scan_ms": round(scan_seconds * 1000, 2),
        "pipeline_ms": round(pipeline_seconds * 1000, 2),
        "scan_results": len(scan_results),
        "success_count": summary.success_count,
        "failed_count": len(summary.failed_tasks),
        "failed_tasks": list(summary.failed_tasks),
        "files": sorted(path.name for path in pressure_case.case.archive_dir.iterdir() if path.is_file()),
    }


def print_table(rows: list[dict]):
    headers = [
        "case",
        "expected",
        "observed",
        "pipeline_status",
        "marker_extracted",
        "build_ms",
        "scan_ms",
        "pipeline_ms",
        "scan_results",
        "success_count",
        "failed_count",
    ]
    widths = {header: len(header) for header in headers}
    for row in rows:
        for header in headers:
            widths[header] = max(widths[header], len(str(row[header])))
    print(" | ".join(header.ljust(widths[header]) for header in headers))
    print("-+-".join("-" * widths[header] for header in headers))
    for row in rows:
        print(" | ".join(str(row[header]).ljust(widths[header]) for header in headers))


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate and pressure-test real split archive edge cases.")
    parser.add_argument("--strict", action="store_true", help="Return non-zero when expected and observed results differ.")
    args = parser.parse_args()

    require_7z()
    with tempfile.TemporaryDirectory(prefix="smart_unpacker_split_pressure_") as temp:
        root = Path(temp)
        cases = build_cases(root)
        rows = []
        for pressure_case in cases:
            rows.append(run_case(pressure_case))
        print_table(rows)
        print("\nJSON:")
        print(json.dumps(rows, ensure_ascii=False, indent=2))

    failures = [row for row in rows if row["expected"] != row["observed"]]
    if failures:
        print(f"\nUnexpected results: {len(failures)}", file=sys.stderr)
        if args.strict:
            return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FileNotFoundError as exc:
        print(f"SKIP: {exc}")
        raise SystemExit(0)
    except subprocess.TimeoutExpired as exc:
        print(f"ERROR: command timed out: {exc}", file=sys.stderr)
        raise SystemExit(2)
