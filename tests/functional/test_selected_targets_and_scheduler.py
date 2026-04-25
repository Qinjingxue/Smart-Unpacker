from pathlib import Path

from smart_unpacker.detection import DetectionScheduler
from smart_unpacker.extraction.scheduler import ConcurrencyScheduler


def test_selected_directory_and_file_inside_it_are_deduped(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK\x05\x06" + b"\0" * 18)

    bags = DetectionScheduler({}).build_candidate_fact_bags([str(tmp_path), str(archive)])

    matching = [bag for bag in bags if bag.get("file.path") == str(archive)]
    assert len(matching) == 1


def test_selected_split_member_scans_parent_and_returns_group(tmp_path):
    first = tmp_path / "payload.7z.001"
    second = tmp_path / "payload.7z.002"
    first.write_bytes(b"7z\xbc\xaf\x27\x1c")
    second.write_bytes(b"part")

    bags = DetectionScheduler({}).build_candidate_fact_bags([str(second)])

    assert len(bags) == 1
    assert bags[0].get("file.path") == str(first)
    assert str(second) in bags[0].get("file.split_members")


def test_scheduler_uses_current_backlog_floor_and_scale_up_step():
    scheduler = ConcurrencyScheduler(
        {
            "initial_concurrency_limit": 2,
            "scale_up_threshold_mb_s": 10,
            "scale_up_backlog_threshold_mb_s": 20,
            "scale_down_threshold_mb_s": 100,
            "scale_up_streak_required": 1,
            "scale_down_streak_required": 1,
            "medium_backlog_threshold": 2,
            "high_backlog_threshold": 4,
            "medium_floor_workers": 3,
            "high_floor_workers": 5,
        },
        current_limit=2,
        max_workers=8,
    )
    scheduler.pending_task_estimate = 40
    scheduler.adjust_once(0)

    assert scheduler.dynamic_floor_workers == 5
    assert scheduler.current_limit == 5
