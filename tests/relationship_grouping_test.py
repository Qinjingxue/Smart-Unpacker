import json
import os
import shutil
import tempfile
from pathlib import Path

import edge_cases_test as helpers


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
MIN_NOISE_BYTES = 2 * 1024 * 1024 + 12345


def write_noise_file(path: Path, seed: str, exe_stub=False):
    rng = helpers.random.Random(seed)
    data = bytearray(rng.getrandbits(8) for _ in range(MIN_NOISE_BYTES))
    if exe_stub:
        data[:2] = b"MZ"
    path.write_bytes(data)


def summarize_tasks(engine, target_dir: Path):
    tasks = engine.scan_archives()
    summary = []
    for task in tasks:
        summary.append(
            {
                "key": str(Path(task.key).relative_to(target_dir)),
                "main": str(Path(task.main_path).relative_to(target_dir)),
                "parts": sorted(str(Path(path).relative_to(target_dir)) for path in task.all_parts),
                "group_score": task.group_info.group_score,
                "group_should_extract": task.group_info.group_should_extract,
            }
        )
    summary.sort(key=lambda item: item["key"])
    return summary


def run_scan(target_dir: Path):
    DecompressionEngine = helpers.load_engine_class()
    logs = []
    engine = DecompressionEngine(str(target_dir), [], logs.append, lambda: None)
    engine.max_workers_limit = 1
    engine.current_concurrency_limit = 1
    tasks = summarize_tasks(engine, target_dir)
    return tasks, logs


def task_parts_map(tasks):
    mapping = {}
    for task in tasks:
        mapping[task["key"]] = task["parts"]
    return mapping


def assert_exact_groups(tasks, expected_groups):
    actual = task_parts_map(tasks)
    if actual != expected_groups:
        return {
            "expected_groups": expected_groups,
            "actual_groups": actual,
        }
    return None


def scenario_similar_unrelated_not_grouped(base_dir: Path):
    scenario_dir = base_dir / "similar_unrelated_not_grouped"
    scenario_dir.mkdir(parents=True, exist_ok=True)

    source = scenario_dir / "src_alpha"
    helpers.write_payload(source, "relation_alpha")
    helpers.create_7z_archive(source, scenario_dir / "alpha.7z", split=True)
    write_noise_file(scenario_dir / "alpha.004", "alpha.004")
    (scenario_dir / "alpha.7z.notes.txt").write_text("not an archive member", encoding="utf-8")

    tasks, logs = run_scan(scenario_dir)
    expected = {
        "alpha": [
            "alpha.7z.001",
            "alpha.7z.002",
            "alpha.7z.003",
        ]
    }
    issue = assert_exact_groups(tasks, expected)
    return {
        "scenario": "同目录有相似但不相关文件，不能误组",
        "ok": issue is None,
        "issue": issue,
        "tasks": tasks,
        "logs_tail": logs[-60:],
    }


def scenario_similar_group_names_no_cross(base_dir: Path):
    scenario_dir = base_dir / "similar_group_names_no_cross"
    scenario_dir.mkdir(parents=True, exist_ok=True)

    source_a = scenario_dir / "src_story"
    source_b = scenario_dir / "src_story_alt"
    helpers.write_payload(source_a, "relation_story")
    helpers.write_payload(source_b, "relation_story_alt")
    helpers.create_7z_archive(source_a, scenario_dir / "story.7z", split=True)
    helpers.create_7z_archive(source_b, scenario_dir / "story_alt.7z", split=True)

    tasks, logs = run_scan(scenario_dir)
    expected = {
        "story": ["story.7z.001", "story.7z.002", "story.7z.003"],
        "story_alt": ["story_alt.7z.001", "story_alt.7z.002", "story_alt.7z.003"],
    }
    issue = assert_exact_groups(tasks, expected)
    return {
        "scenario": "两个不同归档组名字很像，不能串组",
        "ok": issue is None,
        "issue": issue,
        "tasks": tasks,
        "logs_tail": logs[-60:],
    }


def scenario_interleaved_multi_groups(base_dir: Path):
    scenario_dir = base_dir / "interleaved_multi_groups"
    scenario_dir.mkdir(parents=True, exist_ok=True)

    source_a = scenario_dir / "src_mix_a"
    source_b = scenario_dir / "src_mix_b"
    source_c = scenario_dir / "src_mix_c"
    helpers.write_payload(source_a, "relation_mix_a")
    helpers.write_payload(source_b, "relation_mix_b")
    helpers.write_payload(source_c, "relation_mix_c")
    helpers.create_7z_archive(source_a, scenario_dir / "mix_a.7z", split=True)
    helpers.create_zip_archive(source_b, scenario_dir / "mix_b.zip", split=True)
    helpers.create_rar_archive(source_c, scenario_dir / "mix_c.rar", split=True)

    tasks, logs = run_scan(scenario_dir)
    expected = {
        "mix_a": ["mix_a.7z.001", "mix_a.7z.002", "mix_a.7z.003"],
        "mix_b": ["mix_b.zip.001", "mix_b.zip.002", "mix_b.zip.003"],
        "mix_c": ["mix_c.part1.rar", "mix_c.part2.rar", "mix_c.part3.rar"],
    }
    issue = assert_exact_groups(tasks, expected)
    return {
        "scenario": "同目录多组分卷交错存在",
        "ok": issue is None,
        "issue": issue,
        "tasks": tasks,
        "logs_tail": logs[-60:],
    }


def scenario_disguised_exe_companion_with_regular_exe(base_dir: Path):
    scenario_dir = base_dir / "disguised_exe_companion_with_regular_exe"
    scenario_dir.mkdir(parents=True, exist_ok=True)

    source = scenario_dir / "src_bundle"
    helpers.write_payload(source, "relation_bundle")
    helpers.create_7z_archive(source, scenario_dir / "bundle.exe", split=True, sfx=True)

    for path in sorted(scenario_dir.glob("bundle.7z.0*")):
        path.rename(path.with_name(path.name + ".camouflage"))

    write_noise_file(scenario_dir / "helper.exe", "helper.exe", exe_stub=True)
    write_noise_file(scenario_dir / "helper.part1.rar", "helper.part1.rar")

    tasks, logs = run_scan(scenario_dir)
    expected = {
        "bundle": ["bundle.7z.001", "bundle.7z.002", "bundle.7z.003", "bundle.exe"],
    }
    issue = assert_exact_groups(tasks, expected)
    return {
        "scenario": "伪装 exe companion 和普通 exe 混在一起",
        "ok": issue is None,
        "issue": issue,
        "tasks": tasks,
        "logs_tail": logs[-60:],
    }


def scenario_missing_first_volume(base_dir: Path):
    scenario_dir = base_dir / "missing_first_volume"
    scenario_dir.mkdir(parents=True, exist_ok=True)

    source = scenario_dir / "src_losthead"
    helpers.write_payload(source, "relation_losthead")
    helpers.create_7z_archive(source, scenario_dir / "losthead.7z", split=True)
    (scenario_dir / "losthead.7z.001").unlink()

    tasks, logs = run_scan(scenario_dir)
    issue = None
    if tasks:
        issue = {
            "expected_groups": {},
            "actual_groups": task_parts_map(tasks),
        }
    return {
        "scenario": "成员齐全但首卷缺失",
        "ok": issue is None,
        "issue": issue,
        "tasks": tasks,
        "logs_tail": logs[-60:],
    }


def scenario_fake_disguised_part_files(base_dir: Path):
    scenario_dir = base_dir / "fake_disguised_part_files"
    scenario_dir.mkdir(parents=True, exist_ok=True)

    write_noise_file(scenario_dir / "trap.part1.rar.mask", "trap1")
    write_noise_file(scenario_dir / "trap.part2.rar.mask", "trap2")
    write_noise_file(scenario_dir / "trap.part3.rar.mask", "trap3")

    tasks, logs = run_scan(scenario_dir)
    issue = None
    if tasks:
        issue = {
            "expected_groups": {},
            "actual_groups": task_parts_map(tasks),
        }
    return {
        "scenario": "存在伪装 part 文件，但其实不是一组",
        "ok": issue is None,
        "issue": issue,
        "tasks": tasks,
        "logs_tail": logs[-60:],
    }


def main():
    helpers.ensure_prerequisites()

    with tempfile.TemporaryDirectory(prefix="relationship-grouping-", dir=str(ROOT)) as temp_dir:
        base_dir = Path(temp_dir)
        results = [
            scenario_similar_unrelated_not_grouped(base_dir),
            scenario_similar_group_names_no_cross(base_dir),
            scenario_interleaved_multi_groups(base_dir),
            scenario_disguised_exe_companion_with_regular_exe(base_dir),
            scenario_missing_first_volume(base_dir),
            scenario_fake_disguised_part_files(base_dir),
        ]

    overall_ok = all(item["ok"] for item in results)
    output = {
        "overall_ok": overall_ok,
        "total": len(results),
        "passed": sum(1 for item in results if item["ok"]),
        "failed": sum(1 for item in results if not item["ok"]),
        "results": results,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    raise SystemExit(0 if overall_ok else 1)


if __name__ == "__main__":
    main()
