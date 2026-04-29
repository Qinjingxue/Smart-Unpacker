from pathlib import Path
import struct
import zlib

import pytest

from sunpack.coordinator.scanner import ScanOrchestrator
from sunpack.coordinator.runner import PipelineRunner
from sunpack.detection.scheduler import DetectionScheduler
from tests.helpers.detection_config import with_detection_pipeline


SCAN_CONFIG = with_detection_pipeline({
    "thresholds": {"archive_score_threshold": 1, "maybe_archive_threshold": 1},
}, precheck=[
    {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
], scoring=[
    {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 1, "extensions": [".zip", ".7z", ".rar", ".001"]}]},
    {"name": "embedded_payload_identity", "enabled": True},
    {"name": "seven_zip_structure_identity", "enabled": True, "structure_score": 1},
    {"name": "rar_structure_identity", "enabled": True, "structure_score": 1},
])


def _minimal_7z_header() -> bytes:
    next_header = b"\x17\x06"
    start_header = struct.pack("<QQI", 0, len(next_header), zlib.crc32(next_header) & 0xFFFFFFFF)
    start_crc = zlib.crc32(start_header) & 0xFFFFFFFF
    return b"7z\xbc\xaf\x27\x1c" + b"\x00\x04" + struct.pack("<I", start_crc) + start_header + next_header


def _write_files(root: Path, names: list[str]):
    root.mkdir(parents=True, exist_ok=True)
    for name in names:
        (root / name).write_bytes(f"fixture::{name}".encode("utf-8"))


def _scan_parts(root: Path) -> dict[str, list[str]]:
    results = ScanOrchestrator(SCAN_CONFIG).scan(str(root))
    actual = {}
    for result in results:
        key = Path(result.main_path).name
        if key.endswith(".7z.001"):
            key = key.removesuffix(".7z.001")
        elif key.endswith(".zip.001"):
            key = key.removesuffix(".zip.001")
        elif ".part1.rar" in key:
            key = key.split(".part1.rar", 1)[0]
        elif key.endswith(".exe") and len(result.all_parts) > 1:
            key = key.removesuffix(".exe")
        actual[key] = sorted(Path(path).name for path in result.all_parts)
    return actual


@pytest.mark.parametrize(
    ("name", "files", "expected"),
    [
        (
            "similar unrelated files are not grouped",
            ["alpha.7z.001", "alpha.7z.002", "alpha.7z.003", "alpha.004", "alpha.7z.notes.txt"],
            {"alpha": ["alpha.7z.001", "alpha.7z.002", "alpha.7z.003"]},
        ),
        (
            "similar group names do not cross",
            [
                "story.7z.001",
                "story.7z.002",
                "story.7z.003",
                "story_alt.7z.001",
                "story_alt.7z.002",
                "story_alt.7z.003",
            ],
            {
                "story": ["story.7z.001", "story.7z.002", "story.7z.003"],
                "story_alt": ["story_alt.7z.001", "story_alt.7z.002", "story_alt.7z.003"],
            },
        ),
        (
            "interleaved formats form separate groups",
            [
                "mix_a.7z.001",
                "mix_b.zip.001",
                "mix_c.part1.rar",
                "mix_a.7z.002",
                "mix_b.zip.002",
                "mix_c.part2.rar",
                "mix_a.7z.003",
                "mix_b.zip.003",
                "mix_c.part3.rar",
            ],
            {
                "mix_a": ["mix_a.7z.001", "mix_a.7z.002", "mix_a.7z.003"],
                "mix_b": ["mix_b.zip.001", "mix_b.zip.002", "mix_b.zip.003"],
                "mix_c": ["mix_c.part1.rar", "mix_c.part2.rar", "mix_c.part3.rar"],
            },
        ),
        (
            "missing first volume is not treated as an extractable group",
            ["losthead.7z.002", "losthead.7z.003"],
            {},
        ),
        (
            "fake disguised part files are ignored without real head",
            ["trap.part1.rar.mask", "trap.part2.rar.mask", "trap.part3.rar.mask"],
            {},
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_relationship_grouping_scenarios(tmp_path, name, files, expected):
    _write_files(tmp_path / name, files)

    assert _scan_parts(tmp_path / name) == expected


def test_disguised_sfx_companion_groups_with_disguised_parts_not_noise(tmp_path):
    root = tmp_path / "disguised_exe_companion_with_regular_exe"
    _write_files(
        root,
        [
            "bundle.exe",
            "bundle.7z.001.camouflage",
            "bundle.7z.002.camouflage",
            "bundle.7z.003.camouflage",
            "helper.exe",
            "helper.part1.rar",
        ],
    )
    (root / "bundle.exe").write_bytes(_minimal_7z_header())
    (root / "helper.exe").write_bytes(b"MZ")

    actual = _scan_parts(root)

    assert actual == {
        "bundle": [
            "bundle.7z.001.camouflage",
            "bundle.7z.002.camouflage",
            "bundle.7z.003.camouflage",
            "bundle.exe",
        ],
    }


def test_missing_middle_split_volume_is_failed_before_detection(tmp_path):
    root = tmp_path / "missing_middle"
    _write_files(root, ["gap.7z.001", "gap.7z.002", "gap.7z.004"])

    bags = DetectionScheduler(SCAN_CONFIG).build_candidate_fact_bags([str(root)])
    gap = next(bag for bag in bags if bag.get("candidate.logical_name") == "gap")

    assert gap.get("relation.split_group_complete") is False
    assert gap.get("relation.split_missing_reason") == "missing_middle"
    assert gap.get("relation.split_missing_indices") == [3]

    summary = PipelineRunner(SCAN_CONFIG).run(str(root))

    assert summary.success_count == 0
    assert any("分卷缺失或不完整" in item for item in summary.failed_tasks)


def test_missing_head_split_volume_is_failed_before_detection(tmp_path):
    root = tmp_path / "missing_head"
    _write_files(root, ["lost.7z.002", "lost.7z.003"])

    bags = DetectionScheduler(SCAN_CONFIG).build_candidate_fact_bags([str(root)])
    lost = next(bag for bag in bags if bag.get("candidate.logical_name") == "lost")

    assert lost.get("relation.split_group_complete") is False
    assert lost.get("relation.split_missing_reason") == "missing_head"
    assert lost.get("relation.split_missing_indices") == [1]

    summary = PipelineRunner(SCAN_CONFIG).run(str(root))

    assert summary.success_count == 0
    assert any("分卷缺失或不完整" in item for item in summary.failed_tasks)


def test_missing_head_split_volume_can_be_recovered_by_fuzzy_candidate(tmp_path):
    root = tmp_path / "recovered_head"
    _write_files(root, ["lost.7z", "lost.7z.002", "lost.7z.003"])
    for path in root.iterdir():
        path.write_bytes(b"x" * (1024 * 1024))

    actual = _scan_parts(root)

    assert actual == {
        "lost.7z": ["lost.7z", "lost.7z.002", "lost.7z.003"],
    }
