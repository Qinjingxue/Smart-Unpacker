from __future__ import annotations


READER_METRIC_KEYS = (
    "logical_bytes",
    "physical_bytes",
    "physical_reads",
    "cache_hits",
    "cache_misses",
    "handle_hits",
)


def metrics_delta(before: dict, after: dict) -> dict[str, int]:
    return {key: int(after.get(key, 0)) - int(before.get(key, 0)) for key in READER_METRIC_KEYS}
