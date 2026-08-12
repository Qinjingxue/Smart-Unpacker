from __future__ import annotations

import uuid

from tests.helpers.marker_utils import marker_was_extracted
from tests.real.plan1_real_archives.plan1_support import run_plan1_pipeline


WRONG_PASSWORD_LIST_SIZE = 100


def wrong_password_list(count: int = WRONG_PASSWORD_LIST_SIZE) -> list[str]:
    """计划第 3 条：100 个全部错误的密码，且彼此唯一。"""
    return [f"wrong-{index:03d}-{uuid.uuid4().hex[:8]}" for index in range(count)]


def assert_password_error(case, error_info: dict | None = None) -> None:
    """全错密码下必须：0 成功、有失败任务、失败分类为密码错误、marker 未解出。"""
    passwords = wrong_password_list()
    summary = run_plan1_pipeline(case.archive_dir, passwords=passwords)
    extracted = marker_was_extracted(case.archive_dir, case.marker_name, case.marker_text)
    if error_info is not None:
        error_info.update(
            {
                "password_list_size": len(passwords),
                "pipeline_success_count": summary.success_count,
                "pipeline_failed_tasks": [str(item) for item in summary.failed_tasks],
                "failure_kinds": [str(failure.kind) for failure in summary.failures],
                "password_failure_reported": any(
                    failure.is_password_failure for failure in summary.failures
                ),
                "marker_extracted": extracted,
            }
        )
    assert summary.success_count == 0, f"expected 0 success, got {summary.success_count}"
    assert summary.failed_tasks, "expected failed tasks for all-wrong passwords"
    assert any(failure.is_password_failure for failure in summary.failures), (
        f"no password failure reported; kinds={[str(f.kind) for f in summary.failures]}"
    )
    assert not extracted, "marker must not be extracted with all-wrong passwords"
