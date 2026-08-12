from __future__ import annotations

from tests.real.plan5_embedded_archives.plan5_support import (
    assert_plan5_native_scan_coverage,
    assert_plan5_single_task_scan,
    build_embedded_mixed_case,
    _segment_table,
)


def test_plan5_native_scan_covers_every_embedded_segment(tmp_path, plan5_error):
    """检测层：native 全流扫描必须命中每个构造段，且垃圾块两两不同。"""
    case = build_embedded_mixed_case(tmp_path, error_info=plan5_error)
    plan5_error["case_id"] = case.case_id
    plan5_error["file_size"] = case.file_path.stat().st_size
    plan5_error["segment_count"] = len(case.segments)
    plan5_error["segments"] = _segment_table(case)
    plan5_error["skipped_formats"] = list(case.skipped_formats)

    assert_plan5_native_scan_coverage(case, error_info=plan5_error)

    digests = [digest for _length, digest in case.junk_blocks]
    plan5_error["junk_block_count"] = len(digests)
    plan5_error["distinct_junk_blocks"] = len(set(digests))
    assert len(set(digests)) == len(digests), (
        "junk blocks must be random and mutually distinct, but duplicates were generated"
    )


def test_plan5_mixed_file_scans_as_single_archive_task(tmp_path, plan5_error):
    """扫描层：整个混合文件必须恰好成为一个待处理压缩包任务。"""
    case = build_embedded_mixed_case(tmp_path, error_info=plan5_error)
    plan5_error["case_id"] = case.case_id
    plan5_error["file_name"] = case.file_path.name
    plan5_error["segment_count"] = len(case.segments)
    plan5_error["segments"] = _segment_table(case)
    plan5_error["skipped_formats"] = list(case.skipped_formats)

    assert_plan5_single_task_scan(case, error_info=plan5_error)
