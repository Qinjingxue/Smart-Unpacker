from __future__ import annotations

import uuid

from tests.real.plan1_real_archives.plan1_support import (
    assert_plan1_success,
    marker_was_extracted,
    run_plan1_pipeline,
)


PASSWORD_LIST_SIZE = 100
CORRECT_PASSWORD_INDEX = 63


def encrypted_password_list(
    correct: str,
    *,
    count: int = PASSWORD_LIST_SIZE,
    correct_index: int = CORRECT_PASSWORD_INDEX,
) -> list[str]:
    """计划第 2 条：100 个混合密码 = 99 个唯一错误密码 + 正确密码插在中间。"""
    if not 0 <= correct_index < count:
        raise ValueError("correct_index out of range")
    wrong = [f"wrong-{index:03d}-{uuid.uuid4().hex[:8]}" for index in range(count - 1)]
    wrong.insert(correct_index, correct)
    return wrong


assert_plan2_success = assert_plan1_success
run_plan2_pipeline = run_plan1_pipeline

__all__ = [
    "PASSWORD_LIST_SIZE",
    "CORRECT_PASSWORD_INDEX",
    "assert_plan2_success",
    "encrypted_password_list",
    "marker_was_extracted",
    "run_plan2_pipeline",
]
