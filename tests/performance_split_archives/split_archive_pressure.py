import argparse
import json
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

from smart_unpacker.config.schema import normalize_config
from smart_unpacker.coordinator.runner import PipelineRunner
from smart_unpacker.coordinator.scanner import ScanOrchestrator
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.real_archives import ArchiveCase, ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar, require_7z


PASSWORD = "pressure-secret"
WRONG_PASSWORDS = ["wrong-password", "123456", "letmein"]
PASSWORD_TRY_LIST = [*WRONG_PASSWORDS[:2], PASSWORD]
PAYLOAD_SIZE = 180 * 1024
FORMATS = ("7z", "zip", "rar")


@dataclass
class PressureCase:
    name: str
    archive_format: str
    variant: str
    case: ArchiveCase | None
    passwords: list[str]
    expected: str
    build_seconds: float
    skip_reason: str | None = None


def pressure_config(passwords: list[str] | None = None) -> dict:
    return normalize_config(with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "recursive_extract": "1",
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
        "user_passwords": passwords or [],
        "builtin_passwords": [],
        "max_retries": 1,
        "performance": {"scheduler_profile": "single"},
    }, precheck=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
    ], scoring=[
        {
            "name": "extension",
            "enabled": True,
            "extension_score_groups": [{
                "score": 5,
                "extensions": [
                    ".zip",
                    ".7z",
                    ".rar",
                    ".001",
                    ".exe",
                    ".jpg",
                    ".jpeg",
                ],
            }],
        },
        {"name": "embedded_payload_identity", "enabled": True},
        {"name": "seven_zip_structure_identity", "enabled": True},
        {"name": "zip_structure_identity", "enabled": True},
        {"name": "rar_structure_identity", "enabled": True},
    ], confirmation=[
        {"name": "seven_zip_probe", "enabled": True},
        {"name": "seven_zip_validation", "enabled": True, "reject_on_failed": False},
    ]))


def timed(factory: Callable[[], ArchiveCase]) -> tuple[ArchiveCase, float]:
    started = time.perf_counter()
    case = factory()
    return case, time.perf_counter() - started


def create_case(root: Path, case_id: str, archive_format: str, **kwargs) -> tuple[ArchiveCase, float]:
    factory = ArchiveFixtureFactory()
    return timed(lambda: factory.create(root, case_id, archive_format, payload_size=PAYLOAD_SIZE, **kwargs))


def build_or_skip(
    root: Path,
    archive_format: str,
    variant: str,
    *,
    passwords: list[str] | None = None,
    expected: str = "success",
    case_id: str | None = None,
    **kwargs,
) -> PressureCase:
    effective_case_id = case_id or f"{archive_format}_{variant}".replace("-", "_")
    name = f"{archive_format}:{variant}"
    try:
        case, build_seconds = create_case(root, effective_case_id, archive_format, **kwargs)
        return PressureCase(name, archive_format, variant, case, passwords or [], expected, build_seconds)
    except (FileNotFoundError, RuntimeError) as exc:
        return PressureCase(name, archive_format, variant, None, passwords or [], "skip", 0.0, str(exc))


def build_password_case(
    root: Path,
    archive_format: str,
    variant: str,
    *,
    case_id: str | None = None,
    **kwargs,
) -> list[PressureCase]:
    base_case_id = case_id or f"{archive_format}_{variant}_password".replace("-", "_")
    views = [
        ("no_password", [], "failure"),
        ("wrong_passwords", list(WRONG_PASSWORDS), "failure"),
        ("correct_after_wrong_passwords", list(PASSWORD_TRY_LIST), "success"),
    ]
    cases: list[PressureCase] = []
    for suffix, passwords, expected in views:
        view_variant = f"{variant}:{suffix}"
        try:
            case, build_seconds = create_case(
                root,
                f"{base_case_id}_{suffix}",
                archive_format,
                password=PASSWORD,
                **kwargs,
            )
        except (FileNotFoundError, RuntimeError) as exc:
            cases.append(PressureCase(
                f"{archive_format}:{view_variant}",
                archive_format,
                view_variant,
                None,
                passwords,
                "skip",
                0.0,
                str(exc),
            ))
            continue
        cases.append(PressureCase(
            f"{archive_format}:{view_variant}",
            archive_format,
            view_variant,
            case,
            passwords,
            expected,
            build_seconds,
        ))
    return cases


def build_format_cases(root: Path, archive_format: str) -> list[PressureCase]:
    cases: list[PressureCase] = []

    cases.append(build_or_skip(root, archive_format, "single_plain"))
    cases.extend(build_password_case(root, archive_format, "single_password"))

    cases.append(build_or_skip(root, archive_format, "split_plain", split=True))
    cases.extend(build_password_case(root, archive_format, "split_password", split=True))

    cases.append(build_or_skip(root, archive_format, "sfx_single_plain", sfx=True))
    cases.extend(build_password_case(root, archive_format, "sfx_single_password", sfx=True))

    cases.append(build_or_skip(root, archive_format, "sfx_split_plain", split=True, sfx=True))
    cases.extend(build_password_case(root, archive_format, "sfx_split_password", split=True, sfx=True))

    cases.append(build_or_skip(root, archive_format, "jpg_carrier_plain", carrier="jpg"))
    cases.extend(build_password_case(root, archive_format, "jpg_carrier_password", carrier="jpg"))

    cases.append(build_or_skip(root, archive_format, "wrong_suffix_plain", disguise_ext=".wrongext"))
    cases.append(build_or_skip(root, archive_format, "corrupt_single_header", expected="failure", corruption="header_damage"))
    cases.append(build_or_skip(root, archive_format, "corrupt_single_tail", expected="failure", corruption="tail_damage"))
    cases.append(build_or_skip(root, archive_format, "missing_split_member", expected="failure", split=True, split_issue="missing_last"))
    cases.append(build_or_skip(root, archive_format, "corrupt_split_member", expected="failure", split=True, split_issue="corrupt_member"))

    return cases


def build_cases(root: Path, requested_formats: list[str]) -> list[PressureCase]:
    cases: list[PressureCase] = []
    for archive_format in requested_formats:
        if archive_format == "rar" and not get_optional_rar():
            cases.append(PressureCase(
                "rar:all",
                "rar",
                "all",
                None,
                [],
                "skip",
                0.0,
                "RAR generator is not configured. Set SMART_UNPACKER_TEST_RAR or tests/test_tools.json rar_exe.",
            ))
            continue
        cases.extend(build_format_cases(root, archive_format))
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
        elif path.name == "failed_log.txt":
            path.unlink(missing_ok=True)


def run_case(pressure_case: PressureCase) -> dict:
    if pressure_case.case is None:
        return {
            "case": pressure_case.name,
            "format": pressure_case.archive_format,
            "variant": pressure_case.variant,
            "expected": pressure_case.expected,
            "observed": "skip",
            "pipeline_status": "skip",
            "marker_extracted": False,
            "password_count": len(pressure_case.passwords),
            "build_ms": 0.0,
            "scan_ms": 0.0,
            "pipeline_ms": 0.0,
            "scan_results": 0,
            "success_count": 0,
            "failed_count": 0,
            "failed_tasks": [],
            "skip_reason": pressure_case.skip_reason,
            "files": [],
        }

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
        "format": pressure_case.archive_format,
        "variant": pressure_case.variant,
        "expected": pressure_case.expected,
        "observed": observed,
        "pipeline_status": pipeline_status,
        "marker_extracted": extracted,
        "password_count": len(pressure_case.passwords),
        "build_ms": round(pressure_case.build_seconds * 1000, 2),
        "scan_ms": round(scan_seconds * 1000, 2),
        "pipeline_ms": round(pipeline_seconds * 1000, 2),
        "scan_results": len(scan_results),
        "success_count": summary.success_count,
        "failed_count": len(summary.failed_tasks),
        "failed_tasks": list(summary.failed_tasks),
        "skip_reason": pressure_case.skip_reason,
        "files": sorted(path.name for path in pressure_case.case.archive_dir.iterdir() if path.is_file()),
    }


def print_table(rows: list[dict]):
    headers = [
        "case",
        "expected",
        "observed",
        "pipeline_status",
        "marker_extracted",
        "password_count",
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


def parse_formats(value: str) -> list[str]:
    requested = [item.strip().lower() for item in value.split(",") if item.strip()]
    unknown = sorted(set(requested) - set(FORMATS))
    if unknown:
        raise argparse.ArgumentTypeError(f"Unsupported formats: {', '.join(unknown)}")
    return requested or list(FORMATS)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate and pressure-test broad real archive edge cases.")
    parser.add_argument("--strict", action="store_true", help="Return non-zero when expected and observed results differ.")
    parser.add_argument("--formats", type=parse_formats, default=list(FORMATS), help="Comma-separated formats to cover: 7z,zip,rar.")
    args = parser.parse_args()

    require_7z()
    with tempfile.TemporaryDirectory(prefix="smart_unpacker_archive_pressure_") as temp:
        root = Path(temp)
        cases = build_cases(root, args.formats)
        rows = [run_case(pressure_case) for pressure_case in cases]
        print_table(rows)
        print("\nJSON:")
        print(json.dumps(rows, ensure_ascii=False, indent=2))

    failures = [
        row for row in rows
        if row["expected"] != "skip" and row["expected"] != row["observed"]
    ]
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
