from pathlib import Path

from benchmarks.scenarios.sevenzip_worker_matrix import _case_job
from benchmarks.scenarios.worker_read_patterns import MIB, _pattern_table, _prefetch_recommendation


def test_case_job_uses_production_format_policy_inputs(tmp_path):
    tar_path = tmp_path / "payload.tar"
    tar_path.write_bytes(b"tar")
    tar_job = _case_job(
        {"path": tar_path, "format": "tar"},
        job_id="tar",
        output_dir=tmp_path / "tar-output",
        dll_path=Path("7z.dll"),
    )

    first_volume = tmp_path / "archive.part1.rar"
    second_volume = tmp_path / "archive.part2.rar"
    first_volume.write_bytes(b"first")
    second_volume.write_bytes(b"second")
    rar_job = _case_job(
        {"path": first_volume, "format": "rar-split"},
        job_id="rar",
        output_dir=tmp_path / "rar-output",
        dll_path=Path("7z.dll"),
    )

    assert tar_job["format_hint"] == "tar"
    assert rar_job["format_hint"] == "rar"
    assert rar_job["archive_input"] == {
        "entry_path": str(first_volume),
        "open_mode": "native_volumes",
        "format_hint": "rar",
        "parts": [
            {"path": str(first_volume), "volume_number": 1, "canonical_name": first_volume.name},
            {"path": str(second_volume), "volume_number": 2, "canonical_name": second_volume.name},
        ],
    }


def test_prefetch_recommendation_uses_seek_and_run_shape():
    assert _prefetch_recommendation({
        "input_sequential_read_ratio": 0.95,
        "input_seek_count": 1,
        "input_max_sequential_run_bytes": 8 * MIB,
    }) == "sequential prefetch candidate"
    assert _prefetch_recommendation({
        "input_sequential_read_ratio": 0.50,
        "input_seek_count": 8,
        "input_max_sequential_run_bytes": 4 * MIB,
    }) == "seek-epoch prefetch candidate"
    assert _prefetch_recommendation({
        "input_sequential_read_ratio": 0.50,
        "input_seek_count": 13,
        "input_max_sequential_run_bytes": 4 * MIB,
    }) == "avoid global prefetch"


def test_pattern_table_includes_solid_variant_and_wall_share():
    table = _pattern_table([{
        "format": "7z",
        "variant": "solid",
        "archive_bytes": 32 * MIB,
        "input_stream_mode": "file",
        "input_seek_count": 2,
        "input_seek_forward_bytes": 8 * MIB,
        "input_seek_backward_bytes": 4 * MIB,
        "input_logical_read_call_count": 12,
        "input_sequential_read_ratio": 0.75,
        "input_sequential_run_count": 3,
        "input_max_sequential_run_bytes": 6 * MIB,
        "input_read_file_wall_ms": 10.0,
        "input_read_file_wall_ratio": 0.25,
        "prefetch_recommendation": "seek-epoch prefetch candidate",
    }])

    assert "7z (solid)" in table
    assert "75.0%" in table
    assert "25.0%" in table
