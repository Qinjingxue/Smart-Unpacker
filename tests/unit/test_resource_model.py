from types import SimpleNamespace

import pytest

from sunpack.coordinator.scheduling.resource_model import estimate_resource_demand


@pytest.mark.parametrize(
    ("archive_type", "method", "solid", "file_count"),
    [
        ("zip", "Store", False, 1),
        ("zip", "Deflate64", False, 50_000),
        ("7z", "LZMA2", False, 1),
        ("7z", "LZMA2", True, 50_000),
        ("rar", "PPMd", True, 1),
    ],
)
def test_all_archive_types_use_one_cpu_token(archive_type, method, solid, file_count):
    demand = estimate_resource_demand(SimpleNamespace(
        ok=True,
        archive_type=archive_type,
        dominant_method=method,
        solid=solid,
        file_count=file_count,
        archive_size=0,
        total_unpacked_size=0,
        total_packed_size=0,
        largest_dictionary_size=0,
    ))

    assert demand.cpu == 1


def test_memory_and_io_weights_still_protect_heavy_archives():
    demand = estimate_resource_demand(SimpleNamespace(
        ok=True,
        archive_type="7z",
        dominant_method="LZMA2",
        solid=True,
        file_count=50_000,
        archive_size=2 << 30,
        total_unpacked_size=4 << 30,
        total_packed_size=2 << 30,
        largest_dictionary_size=256 << 20,
    ))

    assert demand.cpu == 1
    assert demand.memory == 5
    assert demand.io == 6
