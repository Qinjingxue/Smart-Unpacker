from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Scenario:
    group: str
    name: str
    module: str
    description: str


_ROWS = [
    ("reader", "password-fast-path", "benchmarks.scenarios.reader_password_fast_path", "Password candidate fast paths."),
    ("reader", "password-size-scaling", "benchmarks.scenarios.reader_password_size_scaling", "Password cost versus payload size."),
    ("reader", "seven-zip-password", "benchmarks.scenarios.reader_seven_zip_password", "7z password probe optimization."),
    ("reader", "embedded-scan", "benchmarks.scenarios.reader_embedded_scan", "Native and CLI embedded scanning."),
    ("reader", "volume-anchor", "benchmarks.scenarios.reader_volume_anchor", "Bounded native volume-anchor probing."),
    ("memory", "residual-rss", "benchmarks.scenarios.memory_residual_rss", "Residual RSS and Python allocations."),
    ("memory", "worker-manifest", "benchmarks.scenarios.memory_worker_manifest", "Native manifest materialization."),
    ("scan", "directory", "benchmarks.scenarios.scan_directory", "Directory scanner comparison."),
    ("scan", "hotspots", "benchmarks.scenarios.scan_hotspots", "Full scan hotspot instrumentation."),
    ("scan", "synthetic-pressure", "benchmarks.scenarios.scan_synthetic_pressure", "Synthetic mixed-corpus scan."),
    ("extraction", "format-matrix", "benchmarks.scenarios.extraction_format_matrix", "Format and workload matrix."),
    ("extraction", "real-archive", "benchmarks.scenarios.extraction_real_archive", "Fresh-process real archive baseline."),
    ("extraction", "large-archive-profile", "benchmarks.scenarios.extraction_large_archive", "Large archive pipeline profile."),
    ("extraction", "split-pressure", "benchmarks.scenarios.extraction_split_pressure", "Split and carrier archive matrix."),
]

SCENARIOS = {(group, name): Scenario(group, name, module, description) for group, name, module, description in _ROWS}
