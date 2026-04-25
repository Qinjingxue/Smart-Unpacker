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


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "slow_real_archive: full real archive matrix cases that are slower than the default integration smoke set",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-slow-real-archives"):
        return

    skip_slow = pytest.mark.skip(reason="use --run-slow-real-archives to run the full real-archive matrix")
    for item in items:
        if "slow_real_archive" in item.keywords:
            item.add_marker(skip_slow)
