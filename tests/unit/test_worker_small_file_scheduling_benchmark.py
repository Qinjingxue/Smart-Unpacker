from benchmarks.scenarios.worker_small_file_scheduling import (
    _jain_index,
    _parse_capacities,
    _summarize_batch,
)


def test_parse_capacities_deduplicates_and_rejects_out_of_range_values():
    assert _parse_capacities("1,2,2,8") == [1, 2, 8]
    try:
        _parse_capacities("0")
    except ValueError as exc:
        assert "between 1 and 32" in str(exc)
    else:
        raise AssertionError("capacity zero must be rejected")


def test_jain_index_is_one_for_equal_counts_and_lower_for_a_skew():
    assert _jain_index([4, 4, 4, 4]) == 1.0
    assert _jain_index([8, 0, 0, 0]) == 0.25


def test_batch_summary_uses_native_events_for_utilization_and_admission_fairness():
    submitted_at = {"a-1": 0.0, "b-1": 0.0, "a-2": 0.0, "b-2": 0.0}
    events = [
        {"received_at": 1.0, "event": "job_admitted", "job_id": "a-1", "request_id": "request-00", "active_jobs": 1},
        {"received_at": 1.0, "event": "job_started", "job_id": "a-1", "request_id": "request-00", "active_jobs": 1},
        {"received_at": 2.0, "event": "job_admitted", "job_id": "b-1", "request_id": "request-01", "active_jobs": 2},
        {"received_at": 2.0, "event": "job_started", "job_id": "b-1", "request_id": "request-01", "active_jobs": 2},
        {"received_at": 3.0, "event": "job_finished", "job_id": "a-1", "request_id": "request-00", "active_jobs": 1},
        {"received_at": 3.0, "event": "job_admitted", "job_id": "a-2", "request_id": "request-00", "active_jobs": 2},
        {"received_at": 4.0, "event": "job_finished", "job_id": "b-1", "request_id": "request-01", "active_jobs": 1},
        {"received_at": 4.0, "event": "job_admitted", "job_id": "b-2", "request_id": "request-01", "active_jobs": 2},
        {"received_at": 5.0, "event": "job_finished", "job_id": "a-2", "request_id": "request-00", "active_jobs": 1},
        {"received_at": 6.0, "event": "job_finished", "job_id": "b-2", "request_id": "request-01", "active_jobs": 0},
    ]
    results = {job_id: {"status": "ok"} for job_id in submitted_at}

    summary = _summarize_batch(
        capacity=2,
        client_count=2,
        submitted_at=submitted_at,
        events=events,
        results=results,
        failures={},
        started_at=0.0,
        submission_finished_at=0.5,
        finished_at=6.0,
        admission_case={"name": "fixed-capacity", "blocker": "none", "description": "test", "expected_max_active": 2},
        resource_metrics={},
        controller_events=[],
        sample_interval_ms=500,
    )

    assert summary["all_passed"] is True
    assert summary["observed_peak_active_jobs"] == 2
    assert summary["thread_capacity_utilization"] == 0.666667
    assert summary["early_admission_jain_index"] == 1.0
    assert summary["overall_admission_jain_index"] == 1.0
    assert summary["longest_same_request_admission_run"] == 1
    assert summary["controller_adjustment_count"] == 0


def test_batch_summary_reports_controller_adjustment_latency():
    summary = _summarize_batch(
        capacity=4,
        client_count=1,
        submitted_at={"job-1": 0.0},
        events=[
            {"received_at": 0.0, "event": "job_queued", "job_id": "job-1", "request_id": "request-00", "active_jobs": 0},
            {"received_at": 0.0, "event": "job_admitted", "job_id": "job-1", "request_id": "request-00", "active_jobs": 1},
            {"received_at": 1.0, "event": "job_finished", "job_id": "job-1", "request_id": "request-00", "active_jobs": 0},
        ],
        results={"job-1": {"status": "ok"}},
        failures={},
        started_at=0.0,
        submission_finished_at=0.1,
        finished_at=1.0,
        admission_case={"name": "adaptive-baseline", "blocker": "adaptive", "description": "test", "expected_max_active": None},
        resource_metrics={},
        controller_events=[
            {"received_at": 0.6, "active_limit": 4},
            {"received_at": 1.1, "active_limit": 6},
        ],
        sample_interval_ms=500,
    )

    assert summary["sample_interval_ms"] == 500
    assert summary["controller_adjustment_count"] == 2
    assert summary["controller_first_adjustment_after_enqueue_ms"] == 600.0
    assert summary["controller_peak_active_limit"] == 6
