from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import pytest


ERROR_RECORDS_DIR = Path(__file__).resolve().parent / "error_records"
_RECORD_COUNTER = {"n": 0}


def _error_info_for(request) -> dict:
    node = request.node
    info = getattr(node, "_plan_error_info", None)
    if info is None:
        info = {}
        node._plan_error_info = info
    return info


@pytest.fixture
def plan_error(request) -> dict:
    """Tests append structured context here; the failure hook writes it to error_records/."""
    return _error_info_for(request)


@pytest.fixture
def plan1_error(plan_error) -> dict:
    return plan_error


@pytest.fixture
def plan2_error(plan_error) -> dict:
    return plan_error


def _in_real_folder(item) -> bool:
    try:
        item_path = Path(getattr(item, "path", None) or item.fspath)
    except TypeError:
        return False
    return item_path.resolve().is_relative_to(Path(__file__).resolve().parent)


def _safe_name(nodeid: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in nodeid)
    return safe[:180] or "test"


def _write_error_record(item, report) -> None:
    nodeid = str(item.nodeid)
    info = dict(getattr(item, "_plan_error_info", None) or {})
    _RECORD_COUNTER["n"] += 1
    counter = _RECORD_COUNTER["n"]
    ERROR_RECORDS_DIR.mkdir(parents=True, exist_ok=True)
    record_path = ERROR_RECORDS_DIR / f"{counter:03d}_{_safe_name(nodeid)}.txt"
    stdout = getattr(report, "capstdout", None) or ""
    lines = [
        f"test: {nodeid}",
        f"time: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"duration_seconds: {getattr(report, 'duration', 0.0):.3f}",
        "",
        "=== longrepr ===",
        str(getattr(report, "longreprtext", "") or ""),
        "",
        "=== captured stdout ===",
        str(stdout),
        "",
        "=== plan context ===",
        json.dumps(info, ensure_ascii=False, indent=2, default=str),
        "",
    ]
    record_path.write_text("\n".join(lines), encoding="utf-8")
    with (ERROR_RECORDS_DIR / "index.txt").open("a", encoding="utf-8") as handle:
        handle.write(f"{record_path.name}\t{nodeid}\n")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when == "call" and report.failed and _in_real_folder(item):
        _write_error_record(item, report)


def pytest_sessionstart(session):
    # 每次运行开始时清空旧记录；只清理本目录下的 error_records。
    root = Path(__file__).resolve().parent
    if ERROR_RECORDS_DIR.resolve().is_relative_to(root):
        shutil.rmtree(ERROR_RECORDS_DIR, ignore_errors=True)
    ERROR_RECORDS_DIR.mkdir(parents=True, exist_ok=True)
    (ERROR_RECORDS_DIR / "README.md").write_text(
        "# error_records\n\n"
        "本目录由 tests/real/conftest.py 自动管理：每次运行开始时清空，\n"
        "失败的用例会把详细错误写入这里（含断言、捕获输出和用例上下文），用于后续统一修复。\n",
        encoding="utf-8",
    )
