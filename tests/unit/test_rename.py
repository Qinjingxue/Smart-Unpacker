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
        ArchiveTask(fact_bag=split_bag, score=10, main_path=str(split_first), all_parts=[str(split_first), str(split_second)]),
        ArchiveTask(fact_bag=single_bag, score=10, main_path=str(fake_doc), all_parts=[str(fake_doc)]),
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

    instructions = RenameScheduler().plan([ArchiveTask(fact_bag=bag, score=10, main_path=str(carrier), all_parts=[str(carrier)])])

    assert instructions == []


def test_output_dir_resolver_disambiguates_duplicate_task_outputs(tmp_path):
    seven_zip = tmp_path / "collision.7z"
    zip_file = tmp_path / "collision.zip"
    existing_output = tmp_path / "collision_7z"
    seven_zip.touch()
    zip_file.touch()
    existing_output.write_text("existing file", encoding="utf-8")

    first = ArchiveTask(fact_bag=FactBag(), score=10, main_path=str(seven_zip), logical_name="collision")
    second = ArchiveTask(fact_bag=FactBag(), score=10, main_path=str(zip_file), logical_name="collision")

    def default_output_dir(task):
        return str(tmp_path / task.logical_name)

    resolver = RenameScheduler().build_output_dir_resolver([first, second], default_output_dir)

    assert resolver(first) == str(tmp_path / "collision_7z_2")
    assert resolver(second) == str(tmp_path / "collision_zip")

