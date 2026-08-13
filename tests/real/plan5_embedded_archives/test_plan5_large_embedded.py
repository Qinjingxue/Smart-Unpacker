from __future__ import annotations

from collections import Counter

from tests.real.plan5_embedded_archives.plan5_support import (
    LARGE_SEGMENT_COUNT,
    _segment_table,
    assert_plan5_success,
    build_large_embedded_case,
)


def test_plan5_large_file_extracts_128_real_embedded_archives(tmp_path, plan5_error):
    """一个文件中循环嵌入 128 个真实归档，给正确密码后全部可见地解出。"""
    case = build_large_embedded_case(
        tmp_path,
        count=LARGE_SEGMENT_COUNT,
        error_info=plan5_error,
    )
    plan5_error["case_id"] = case.case_id
    plan5_error["file_name"] = case.file_path.name
    plan5_error["file_size"] = case.file_path.stat().st_size
    plan5_error["segment_count"] = len(case.segments)
    plan5_error["format_counts"] = dict(Counter(segment.archive_format for segment in case.segments))
    plan5_error["segments"] = _segment_table(case)

    assert len(case.segments) == LARGE_SEGMENT_COUNT
    assert_plan5_success(
        case,
        passwords=[case.password],
        error_info=plan5_error,
    )
