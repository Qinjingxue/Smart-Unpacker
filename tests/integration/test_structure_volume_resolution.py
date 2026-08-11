from __future__ import annotations

import re
from pathlib import Path

import pytest

from sunpack.config.loader import load_config
from sunpack.config.schema import normalize_config
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.engine import PipelineEngine
from sunpack.coordinator.task_provider import ArchiveTaskProvider
from sunpack.coordinator.target_groups import relation_group_to_fact_bag
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.detection.input_planning import ArchiveInputPlanningStage
from sunpack.extraction.scheduler import ExtractionScheduler
from sunpack.filesystem.directory_scanner import DirectoryScanner
from sunpack.relations import RelationsScheduler
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.real_archives import ArchiveFixtureFactory


MIB = 1024 * 1024


@pytest.fixture(scope="module")
def mixed_real_volumes(tmp_path_factory):
    root = tmp_path_factory.mktemp("structure-volume-resolution")
    return root, *_mixed_real_volume_directory(root)


def test_mixed_camouflaged_real_volumes_are_structure_resolved_and_extractable(mixed_real_volumes):
    tmp_path, common, cases, paths_by_format = mixed_real_volumes
    scheduler = RelationsScheduler()
    all_paths = [str(path) for path in common.iterdir() if path.is_file()]

    for archive_format in ("7z", "zip", "rar"):
        current = [str(paths_by_format[archive_format][0])]
        group = scheduler.resolve_volume_once(current, all_paths, format_hint=archive_format)

        assert group is not None
        assert {Path(path).name for path in group.all_paths} == {
            path.name for path in paths_by_format[archive_format]
        }
        assert [volume.number for volume in group.split_volumes] == list(
            range(1, len(paths_by_format[archive_format]) + 1)
        )
        assert all(path.stat().st_size > MIB for path in paths_by_format[archive_format])
        if archive_format == "rar":
            assert all(volume.source == "structure" for volume in group.split_volumes)
        else:
            assert group.split_volumes[0].source == "structure"

        task = ArchiveTask.from_fact_bag(relation_group_to_fact_bag(group), score=100)
        planned = ArchiveInputPlanningStage(load_config()).plan_task_to_tasks(task)
        assert len(planned) == 1
        extractor = ExtractionScheduler(max_retries=1)
        out_dir = tmp_path / "direct_outputs" / archive_format
        try:
            result = extractor.extract(planned[0], str(out_dir))
        finally:
            extractor.close()

        assert result.success is True
        marker = next(out_dir.rglob(cases[archive_format].marker_name))
        assert marker.read_text(encoding="utf-8") == cases[archive_format].marker_text


def test_mixed_directory_schedules_only_one_structural_head_per_format(mixed_real_volumes):
    _tmp_path, common, _cases, paths_by_format = mixed_real_volumes
    config = normalize_config(
        with_detection_pipeline(
            {},
            precheck=[
                {"name": "size_range", "enabled": True, "gte": 0},
                {"name": "seven_zip_structure_accept", "enabled": True},
                {"name": "zip_structure_accept", "enabled": True},
                {"name": "rar_structure_accept", "enabled": True},
            ],
            scoring=[],
        )
    )

    tasks = ArchiveTaskProvider(config).scan_targets([str(common)])

    assert {Path(task.main_path).name for task in tasks} == {
        paths_by_format[archive_format][0].name
        for archive_format in ("7z", "zip", "rar")
    }


def test_pipeline_uses_initial_structure_group_without_missing_volume_retry(
    mixed_real_volumes, monkeypatch
):
    tmp_path, common, cases, paths_by_format = mixed_real_volumes
    first = paths_by_format["7z"][0]
    output_root = tmp_path / "pipeline_output"
    config = normalize_config(
        with_detection_pipeline(
            {
                "recursive_extract": "1",
                "repair": {"enabled": False},
                "verification": {"enabled": False, "methods": []},
                "post_extract": {
                    "archive_cleanup_mode": "k",
                    "flatten_single_directory": False,
                },
                "output": {
                    "root": str(output_root),
                    "common_root": str(common),
                },
            },
            precheck=[
                {"name": "size_range", "enabled": True, "gte": 0},
                {"name": "seven_zip_structure_accept", "enabled": True},
            ],
            scoring=[{"name": "seven_zip_structure_identity", "enabled": True}],
        )
    )

    engine = PipelineEngine(config)
    original_resolver = RelationsScheduler.resolve_volume_once_in_directory
    resolution_attempts = 0

    def counting_resolver(scheduler, current_paths, *, format_hint=""):
        nonlocal resolution_attempts
        resolution_attempts += 1
        return original_resolver(
            scheduler,
            current_paths,
            format_hint=format_hint,
        )

    monkeypatch.setattr(
        RelationsScheduler,
        "resolve_volume_once_in_directory",
        counting_resolver,
    )
    with engine:
        response = engine.submit([str(first)]).result(timeout=60)

    assert response.summary.success_count == 1
    assert response.summary.failed_tasks == []
    assert resolution_attempts == 0
    marker = next(output_root.rglob(cases["7z"].marker_name))
    assert marker.read_text(encoding="utf-8") == cases["7z"].marker_text


def test_real_strict_middle_gap_survives_structure_precheck_and_holds_watch(tmp_path):
    case = ArchiveFixtureFactory().create(
        tmp_path,
        "strict_middle_gap",
        "7z",
        split=True,
        payload_size=420 * 1024,
        split_volume_size=100 * 1024,
    )
    parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
    assert len(parts) >= 3
    parts[1].unlink()

    groups = RelationsScheduler().build_candidate_groups(
        DirectoryScanner(str(case.archive_dir)).scan()
    )
    group = next(group for group in groups if group.logical_name == "strict_middle_gap")

    assert group.split_group_complete is False
    assert group.split_missing_reason == "missing_middle"
    assert group.split_missing_indices == [2]
    assert group.split_completeness_status == "middle_gap"
    assert group.split_completeness_confidence == "strong"

    snapshot = WatchGroupCoordinator({}).resolve_head(str(parts[0]))
    assert snapshot is not None
    assert snapshot.missing_indices == (2,)
    assert snapshot.should_wait_for_relation_gap is True


def test_structure_resolution_recomputes_a_residual_middle_gap(tmp_path):
    case = ArchiveFixtureFactory().create(
        tmp_path,
        "residual_gap_source",
        "7z",
        split=True,
        payload_size=9 * MIB + MIB // 2,
        split_volume_size=2 * MIB,
    )
    original_parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
    assert len(original_parts) >= 5
    common = tmp_path / "residual_gap"
    common.mkdir()
    renamed = []
    for number, source in enumerate(original_parts, start=1):
        if number == 4:
            continue
        target = common / f"residual.alpha.7z.{number:03d}.noise.bin"
        source.replace(target)
        renamed.append(target)

    group = RelationsScheduler().resolve_volume_once(
        [str(renamed[0])],
        [str(path) for path in common.iterdir() if path.is_file()],
        format_hint="7z",
    )

    assert group is not None
    assert [volume.number for volume in group.split_volumes] == [1, 2, 3, 5]
    assert group.split_group_complete is False
    assert group.split_missing_reason == "missing_middle"
    assert group.split_missing_indices == [4]
    assert group.split_observed_missing_ranges == [(4, 4)]
    assert group.split_completeness_status == "middle_gap"
    assert group.split_completeness_confidence == "strong"


def _mixed_real_volume_directory(tmp_path: Path):
    factory = ArchiveFixtureFactory()
    common = tmp_path / "mixed"
    common.mkdir()
    cases = {}
    paths_by_format = {}
    payload_size = 9 * MIB + MIB // 2
    split_size = 2 * MIB

    for archive_format in ("7z", "zip", "rar"):
        case = factory.create(
            tmp_path,
            f"source_{archive_format}",
            archive_format,
            split=True,
            payload_size=payload_size,
            split_volume_size=split_size,
        )
        original_parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
        renamed = []
        for fallback_number, source in enumerate(original_parts, start=1):
            number = _source_volume_number(source.name, fallback_number)
            if archive_format == "rar":
                target_name = f"shared.gamma.part{number}.rar.trash.pkg"
            else:
                noise = "alpha" if archive_format == "7z" else "beta"
                suffix = "noise.bin" if archive_format == "7z" else "junk.dat"
                target_name = f"shared.{noise}.{archive_format}.{number:03d}.{suffix}"
            target = common / target_name
            source.replace(target)
            renamed.append(target)
        cases[archive_format] = case
        paths_by_format[archive_format] = sorted(renamed, key=lambda path: _source_volume_number(path.name, 0))

    for name in (
        "shared.alpha.7z.999.noise.bin",
        "shared.beta.zip.999.junk.dat",
    ):
        with (common / name).open("wb") as stream:
            stream.truncate(MIB + 1)

    return common, cases, paths_by_format


def _source_volume_number(name: str, fallback: int) -> int:
    for pattern in (r"\.part(\d+)", r"\.(\d{3})(?:\.|$)"):
        match = re.search(pattern, name, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return fallback
