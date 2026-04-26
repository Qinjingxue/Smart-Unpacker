from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def case_workspace(tmp_path: Path) -> Path:
    return tmp_path / "workspace"


def pytest_addoption(parser):
    parser.addoption(
        "--run-slow-real-archives",
        action="store_true",
        default=False,
        help="Run the full real-archive integration matrix.",
    )
    parser.addoption(
        "--run-large-archive-performance",
        action="store_true",
        default=False,
        help="Run opt-in large archive performance tests that generate multi-GB fixtures.",
    )
    parser.addoption(
        "--large-archive-count",
        action="store",
        type=int,
        default=10,
        help="Number of large archives to generate for --run-large-archive-performance.",
    )
    parser.addoption(
        "--large-archive-size-mb",
        action="store",
        type=int,
        default=300,
        help="Payload size in MiB for each generated large archive.",
    )
    parser.addoption(
        "--large-archive-max-extract-seconds",
        action="store",
        type=float,
        default=300.0,
        help="Maximum allowed end-to-end extraction time for the large archive performance test.",
    )
    parser.addoption(
        "--large-archive-min-parallel-7z",
        action="store",
        type=int,
        default=2,
        help="Minimum observed concurrent 7z.exe process count for the large archive performance test.",
    )
    parser.addoption(
        "--large-archive-scheduler-profile",
        action="store",
        default="auto",
        choices=("auto", "conservative", "aggressive"),
        help="Scheduler profile used by the large archive performance test.",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "slow_real_archive: full real archive matrix cases that are slower than the default integration smoke set",
    )
    config.addinivalue_line(
        "markers",
        "large_archive_performance: opt-in large archive performance tests that generate multi-GB fixtures",
    )


def pytest_collection_modifyitems(config, items):
    skip_slow = None
    if not config.getoption("--run-slow-real-archives"):
        skip_slow = pytest.mark.skip(reason="use --run-slow-real-archives to run the full real-archive matrix")
    skip_large = None
    if not config.getoption("--run-large-archive-performance"):
        skip_large = pytest.mark.skip(
            reason="use --run-large-archive-performance to run multi-GB performance tests"
        )
    for item in items:
        if skip_slow and "slow_real_archive" in item.keywords:
            item.add_marker(skip_slow)
        if skip_large and "large_archive_performance" in item.keywords:
            item.add_marker(skip_large)
