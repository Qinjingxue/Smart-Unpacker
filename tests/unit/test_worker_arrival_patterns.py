from benchmarks.scenarios.worker_arrival_patterns import _arrival_controls, _summarize


def test_arrival_controls_model_bulk_clustered_and_discrete_workloads():
    assert _arrival_controls(
        "cli-bulk",
        jobs=12,
        burst_size=4,
        idle_gap_seconds=1.5,
        discrete_interval_seconds=0.2,
    ) == {"scheduled_idle_seconds": 0.0}

    clustered = _arrival_controls(
        "watch-clustered",
        jobs=12,
        burst_size=4,
        idle_gap_seconds=1.5,
        discrete_interval_seconds=0.2,
    )
    assert clustered["idle_before_indices"] == {4: 1.5, 8: 1.5}
    assert clustered["scheduled_idle_seconds"] == 3.0

    discrete = _arrival_controls(
        "watch-discrete",
        jobs=4,
        burst_size=4,
        idle_gap_seconds=1.5,
        discrete_interval_seconds=0.2,
    )
    assert discrete["submission_offsets_seconds"] == [0.0, 0.2, 0.4, 0.6]


def test_arrival_summary_prefers_the_fastest_passing_candidate():
    base = {
        "all_passed": True,
        "scheduled_idle_seconds": 1.0,
        "queue_latency_p95_ms": 10.0,
        "worker_rss_peak_mib": 100.0,
        "controller_activity_session_count": 3,
        "controller_saturated_segment_count": 2,
        "controller_warm_start_count": 1,
    }
    rows = [
        {**base, "warm_start_decay_seconds": 0.0, "warm_start_confirmations": 1, "wall_ms": 2200.0},
        {**base, "warm_start_decay_seconds": 5.0, "warm_start_confirmations": 2, "wall_ms": 1800.0},
    ]

    summary = _summarize(rows)

    assert summary["all_passed"] is True
    assert summary["recommended_candidate"] == "decay-5-confirmations-2"
