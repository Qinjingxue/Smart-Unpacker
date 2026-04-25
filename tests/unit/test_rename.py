from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.rename.scheduler import RenameScheduler


def test_rename_planner_and_executor_apply_disguised_archive_extensions(tmp_path):
    split_first = tmp_path / "disguised.part1.rar.001"
    split_second = tmp_path / "disguised.part2.rar.002"
    fake_doc = tmp_path / "fake_doc.txt"
    split_first.touch()
    split_second.touch()
    fake_doc.touch()

    split_bag = FactBag()
    split_bag.set("file.path", str(split_first))
    split_bag.set("file.detected_ext", ".rar")
    split_bag.set("file.split_role", "first")

    single_bag = FactBag()
    single_bag.set("file.path", str(fake_doc))
    single_bag.set("file.detected_ext", ".zip")

    tasks = [
        ArchiveTask(fact_bag=split_bag, score=10),
        ArchiveTask(fact_bag=single_bag, score=10),
    ]

    scheduler = RenameScheduler()
    instructions = scheduler.plan(tasks)
    path_map = scheduler.execute(instructions)

    assert instructions
    assert (tmp_path / "disguised.part1.rar").exists()
    assert (tmp_path / "disguised.part2.rar").exists()
    assert (tmp_path / "fake_doc.zip").exists()
    assert str(split_first) in path_map
    assert str(fake_doc) in path_map


def test_rename_planner_keeps_embedded_carrier_extension(tmp_path):
    carrier = tmp_path / "carrier.jpg"
    carrier.touch()

    bag = FactBag()
    bag.set("file.path", str(carrier))
    bag.set("file.detected_ext", ".rar")
    bag.set("file.embedded_archive_found", True)
    bag.set("embedded_archive.analysis", {"found": True, "detected_ext": ".rar", "offset": 128})
    bag.set("archive.identity", {"offset": 128})

    instructions = RenameScheduler().plan([ArchiveTask(fact_bag=bag, score=10)])

    assert instructions == []
