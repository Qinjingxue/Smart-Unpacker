from benchmarks.scenarios.worker_initial_concurrency_matrix import (
    _cpu_weight_for_variant,
    _parse_int_list,
    _parse_variants,
    _summarize,
    _write_payloads,
)


def test_cpu_weight_modes_support_legacy_and_unit_ab_comparison():
    assert _cpu_weight_for_variant("7z-solid", "legacy") == 4
    assert _cpu_weight_for_variant("rar-solid", "legacy") == 2
    assert _cpu_weight_for_variant("7z-solid", "unit") == 1
    assert _cpu_weight_for_variant("zip-deflate", "unit") == 1


def _row(
    variant: str,
    initial: int,
    throughput: float,
    *,
    solid: bool = False,
    peak: int | None = None,
) -> dict:
    return {
        "archive_variant": variant,
        "initial_active_jobs": initial,
        "solid_archive": solid,
        "all_passed": True,
        "throughput_jobs_per_second": throughput,
        "queue_latency_p95_ms": 10.0 + initial,
        "observed_peak_active_jobs": initial if peak is None else peak,
        "worker_rss_peak_mib": 80.0,
    }


def test_matrix_parsers_deduplicate_candidates_and_variants():
    assert _parse_int_list("8,16,8", minimum=1, maximum=32, label="initial") == [8, 16]
    assert _parse_variants(["7z-solid,zip-deflate", "7z-solid"]) == [
        "7z-solid",
        "zip-deflate",
    ]


def test_matrix_payload_sizes_match_requested_shape(tmp_path):
    assert _write_payloads(tmp_path, file_count=3, file_size_bytes=7) == 21
    assert [path.stat().st_size for path in sorted(tmp_path.iterdir())] == [7, 7, 7]


def test_matrix_summary_includes_parallel_solid_candidates_in_cross_format_score():
    rows = [
        _row("zip-deflate", 8, 100.0),
        _row("zip-deflate", 8, 110.0),
        _row("zip-deflate", 16, 120.0),
        _row("zip-deflate", 16, 130.0),
        _row("7z-solid", 8, 20.0, solid=True, peak=2),
        _row("7z-solid", 16, 30.0, solid=True, peak=4),
    ]

    summary = _summarize(rows)

    assert summary["all_passed"] is True
    assert summary["by_archive_variant"]["zip-deflate"]["best_measured_initial_active_jobs"] == 16
    assert summary["by_archive_variant"]["7z-solid"]["observed_serialized"] is False
    assert summary["cross_variant_all"]["recommended_initial_active_jobs"] == 16
    assert summary["cross_variant_non_solid"]["recommended_initial_active_jobs"] == 16
