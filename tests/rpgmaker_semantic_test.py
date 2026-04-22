import argparse
import json
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from smart_unpacker import DecompressionEngine

SOURCE_ARCHIVE = next(
    (path for path in (REPO_ROOT / "fixtures" / "rpgmakertest.7z", REPO_ROOT / "fixtures" / "samples" / "rpgmakertest.7z") if path.is_file()),
    REPO_ROOT / "fixtures" / "rpgmakertest.7z",
)
SEVEN_Z = next(
    (path for path in (REPO_ROOT / "tools" / "7z.exe", REPO_ROOT / "tools" / "7zip" / "7z.exe") if path.is_file()),
    REPO_ROOT / "tools" / "7z.exe",
)

RESOURCE_PREFIXES = (
    "www/audio",
    "www/data",
    "www/fonts",
    "www/icon",
    "www/img",
    "www/js",
    "www/movies",
    "www/save",
    "locales",
    "swiftshader",
)

ARCHIVE_RELATED_EXTS = {
    ".7z",
    ".rar",
    ".zip",
    ".gz",
    ".bz2",
    ".xz",
    ".pak",
    ".obb",
    ".apk",
    ".jar",
    ".ipa",
    ".exe",
    ".dll",
    ".bin",
    ".dat",
}


def load_engine_class():
    return DecompressionEngine


def ensure_prerequisites():
    missing = [str(path) for path in (SOURCE_ARCHIVE, SEVEN_Z) if not path.is_file()]
    return missing


def rel_posix(path: Path, base: Path) -> str:
    return str(path.relative_to(base)).replace("\\", "/")


def collect_inventory(base_dir: Path):
    files = []
    for path in sorted(base_dir.rglob("*")):
        if path.is_file():
            rel_path = rel_posix(path, base_dir)
            files.append(
                {
                    "path": rel_path,
                    "size": path.stat().st_size,
                    "suffix": path.suffix.lower(),
                    "top_level": rel_path.split("/", 1)[0],
                }
            )
    return files


def find_game_root(base_dir: Path):
    candidates = []
    for path in [base_dir] + sorted((p for p in base_dir.rglob("*") if p.is_dir()), key=lambda item: len(item.parts)):
        has_www = (path / "www").is_dir()
        has_game_exe = (path / "Game.exe").is_file()
        has_package_json = (path / "package.json").is_file()
        if has_www and (has_game_exe or has_package_json):
            candidates.append(path)
    return candidates[0] if candidates else None


def collect_semantic_candidates(engine, game_root: Path):
    scene_context = engine._detect_scene_context(str(game_root))
    candidates = []

    for root, _, files in os_walk_sorted(game_root):
        relations = engine._build_directory_relationships(str(root), files, scan_root=str(game_root))
        for filename in files:
            relation = relations[filename]
            info = engine.inspect_archive_candidate(relation.path, relation=relation, scene_context=scene_context)
            archive_like = (
                info.magic_matched
                or info.probe_detected_archive
                or info.detected_ext is not None
                or info.ext in ARCHIVE_RELATED_EXTS
                or info.ext in engine.STANDARD_EXTS
                or info.ext in engine.ZIP_CONTAINER_EXTS
            )
            interesting = (
                archive_like
                or info.decision != "not_archive"
            )
            if not interesting:
                continue

            rel_path = rel_posix(Path(relation.path), game_root)
            same_stem_dir = Path(relation.path).with_suffix("")
            extracted_neighbor_exists = same_stem_dir.exists() and same_stem_dir.is_dir()
            candidates.append(
                {
                    "path": rel_path,
                    "ext": info.ext,
                    "detected_ext": info.detected_ext,
                    "score": info.score,
                    "decision": info.decision,
                    "should_extract": info.should_extract,
                    "scene_role": info.scene_role,
                    "probe_detected_archive": info.probe_detected_archive,
                    "probe_offset": info.probe_offset,
                    "magic_matched": info.magic_matched,
                    "neighbor_extract_dir": rel_posix(same_stem_dir, game_root) if extracted_neighbor_exists else None,
                    "reasons": list(info.reasons),
                }
            )

    return scene_context, candidates


def os_walk_sorted(base_dir: Path):
    import os

    for root, dirs, files in os.walk(base_dir):
        dirs.sort()
        files.sort()
        yield Path(root), dirs, files


def summarize_inventory(files):
    suffix_counter = Counter(item["suffix"] or "<no_ext>" for item in files)
    top_level_counter = Counter(item["top_level"] for item in files)
    return {
        "file_count": len(files),
        "total_bytes": sum(item["size"] for item in files),
        "top_level_distribution": dict(sorted(top_level_counter.items())),
        "suffix_top20": dict(suffix_counter.most_common(20)),
    }


def summarize_nested_tasks(tasks, game_root: Path):
    summary = []
    for task in tasks:
        archive_path = Path(task.main_path)
        rel_path = rel_posix(archive_path, game_root)
        main_info = task.group_info.main_info
        in_resource_dir = any(
            rel_path == prefix or rel_path.startswith(prefix + "/")
            for prefix in RESOURCE_PREFIXES
        )
        summary.append(
            {
                "path": rel_path,
                "group_key": rel_posix(Path(task.key), game_root),
                "part_count": len(task.all_parts),
                "group_score": task.group_info.group_score,
                "decision": main_info.decision,
                "should_extract": task.group_info.group_should_extract,
                "scene_role": main_info.scene_role,
                "detected_ext": main_info.detected_ext,
                "in_resource_dir": in_resource_dir,
                "reasons": list(main_info.reasons),
            }
        )
    return summary


def build_analysis(game_root: Path, semantic_candidates, nested_task_summary):
    protected_candidates = [
        item
        for item in semantic_candidates
        if item["scene_role"] == "embedded_resource_archive"
        and (
            item["ext"] in ARCHIVE_RELATED_EXTS
            or item["detected_ext"] is not None
            or item["probe_detected_archive"]
            or item["magic_matched"]
        )
    ]
    planned_protected_tasks = [
        item
        for item in nested_task_summary
        if item["scene_role"] == "embedded_resource_archive" or item["in_resource_dir"]
    ]
    suspicious_neighbor_dirs = [
        item
        for item in protected_candidates
        if item["neighbor_extract_dir"] is not None
    ]

    return {
        "game_root": str(game_root),
        "protected_candidate_count": len(protected_candidates),
        "planned_protected_task_count": len(planned_protected_tasks),
        "suspicious_neighbor_extract_dir_count": len(suspicious_neighbor_dirs),
        "semantic_passed": not planned_protected_tasks and not suspicious_neighbor_dirs,
        "protected_candidates": protected_candidates,
        "planned_protected_tasks": planned_protected_tasks,
        "suspicious_neighbor_extract_dirs": suspicious_neighbor_dirs,
    }


def write_text_report(report, output_path: Path):
    lines = []
    lines.append("RPGMaker Semantic Test Report")
    lines.append("=" * 32)
    lines.append(f"Source archive: {report['source_archive']}")
    lines.append(f"Workspace: {report['workspace_dir']}")
    lines.append(f"Game root: {report['analysis']['game_root']}")
    lines.append(f"Scene type: {report['scene_context']['scene_type']}")
    lines.append("")
    lines.append("Inventory Summary")
    lines.append(f"- file_count: {report['inventory_summary']['file_count']}")
    lines.append(f"- total_bytes: {report['inventory_summary']['total_bytes']}")
    lines.append("")
    lines.append("Semantic Result")
    lines.append(f"- semantic_passed: {report['analysis']['semantic_passed']}")
    lines.append(f"- protected_candidate_count: {report['analysis']['protected_candidate_count']}")
    lines.append(f"- planned_protected_task_count: {report['analysis']['planned_protected_task_count']}")
    lines.append(f"- suspicious_neighbor_extract_dir_count: {report['analysis']['suspicious_neighbor_extract_dir_count']}")
    lines.append("")
    lines.append("Nested Extraction Tasks")
    if report["nested_task_summary"]:
        for item in report["nested_task_summary"]:
            lines.append(
                f"- {item['path']} | should_extract={item['should_extract']} | "
                f"scene_role={item['scene_role']} | group_score={item['group_score']}"
            )
    else:
        lines.append("- <none>")
    lines.append("")
    lines.append("Protected Archive-like Files")
    if report["analysis"]["protected_candidates"]:
        for item in report["analysis"]["protected_candidates"]:
            lines.append(
                f"- {item['path']} | decision={item['decision']} | "
                f"scene_role={item['scene_role']} | neighbor_extract_dir={item['neighbor_extract_dir'] or '<none>'}"
            )
    else:
        lines.append("- <none>")
    lines.append("")
    lines.append("Extracted Files")
    for item in report["inventory"]:
        lines.append(f"- {item['path']} | size={item['size']}")
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_semantic_test(keep_temp: bool):
    missing = ensure_prerequisites()
    if missing:
        reports_dir = REPO_ROOT / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        skip_report = {
            "status": "skipped",
            "reason": "Missing required local-only sample or binary.",
            "missing": missing,
            "source_archive": str(SOURCE_ARCHIVE),
            "seven_zip": str(SEVEN_Z),
        }
        json_report_path = reports_dir / "rpgmaker_semantic_test_report.json"
        text_report_path = reports_dir / "rpgmaker_semantic_test_report.txt"
        json_report_path.write_text(json.dumps(skip_report, ensure_ascii=False, indent=2), encoding="utf-8")
        text_report_path.write_text(
            "RPGMaker Semantic Test Report\n"
            "================================\n"
            "status: skipped\n"
            "reason: Missing required local-only sample or binary.\n"
            f"source_archive: {SOURCE_ARCHIVE}\n"
            f"seven_zip: {SEVEN_Z}\n"
            f"missing: {missing}\n",
            encoding="utf-8",
        )
        print(json.dumps(skip_report, ensure_ascii=False, indent=2))
        return 0

    DecompressionEngine = load_engine_class()
    logs = []

    temp_ctx = tempfile.TemporaryDirectory(prefix="rpgmaker-semantic-", dir=str(REPO_ROOT))
    try:
        workspace_dir = Path(temp_ctx.name)
        staged_archive = workspace_dir / SOURCE_ARCHIVE.name
        shutil.copy2(SOURCE_ARCHIVE, staged_archive)

        engine = DecompressionEngine(str(workspace_dir), [], logs.append, lambda: None)
        engine.max_workers_limit = 1
        engine.current_concurrency_limit = 1

        initial_tasks = engine.scan_archives()
        if not initial_tasks:
            raise RuntimeError("No initial extraction task was detected for rpgmakertest.7z")

        if len(initial_tasks) != 1:
            raise RuntimeError(f"Expected exactly 1 initial task, got {len(initial_tasks)}")

        engine.run()

        top_level_output = workspace_dir / SOURCE_ARCHIVE.stem
        game_root = None
        if top_level_output.exists():
            game_root = find_game_root(top_level_output)
        game_root = game_root or find_game_root(workspace_dir)
        if game_root is None:
            raise RuntimeError("Unable to locate extracted RPG Maker game root")

        protected_font_archive_rel = "www/fonts/jfdotfont-20150527.7z"
        protected_font_archive = game_root / Path(*protected_font_archive_rel.split("/"))
        protected_font_extract_dir = protected_font_archive.with_suffix("")

        scene_context, semantic_candidates = collect_semantic_candidates(engine, game_root)
        nested_tasks = engine.scan_archives(str(game_root))
        nested_task_summary = summarize_nested_tasks(nested_tasks, game_root)
        inventory = collect_inventory(game_root)
        inventory_summary = summarize_inventory(inventory)
        analysis = build_analysis(game_root, semantic_candidates, nested_task_summary)

        report = {
            "source_archive": str(SOURCE_ARCHIVE),
            "workspace_dir": str(workspace_dir),
            "scene_context": {
                "scene_type": scene_context.scene_type,
                "markers": sorted(scene_context.markers),
            },
            "initial_task_count": len(initial_tasks),
            "top_level_output": str(top_level_output),
            "protected_font_archive": {
                "path": protected_font_archive_rel,
                "exists_after_run": protected_font_archive.exists(),
                "unexpected_extract_dir_exists": protected_font_extract_dir.exists(),
                "extract_started_in_logs": any(
                    "[EXTRACT] 开始:" in line and "jfdotfont-20150527.7z" in line
                    for line in logs
                ),
                "extract_succeeded_in_logs": any(
                    "[EXTRACT] 成功:" in line and "jfdotfont-20150527.7z" in line
                    for line in logs
                ),
            },
            "inventory_summary": inventory_summary,
            "inventory": inventory,
            "semantic_candidates": semantic_candidates,
            "nested_task_summary": nested_task_summary,
            "analysis": analysis,
            "failed_tasks": list(engine.failed_tasks),
            "logs_tail": logs[-200:],
        }

        reports_dir = REPO_ROOT / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        json_report_path = reports_dir / "rpgmaker_semantic_test_report.json"
        text_report_path = reports_dir / "rpgmaker_semantic_test_report.txt"
        json_report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        write_text_report(report, text_report_path)

        print(
            json.dumps(
                {
                    "semantic_passed": analysis["semantic_passed"],
                    "game_root": str(game_root),
                    "file_count": inventory_summary["file_count"],
                    "protected_candidate_count": analysis["protected_candidate_count"],
                    "protected_font_archive_exists_after_run": protected_font_archive.exists(),
                    "protected_font_archive_extract_started": any(
                        "[EXTRACT] 开始:" in line and "jfdotfont-20150527.7z" in line
                        for line in logs
                    ),
                    "protected_font_archive_extract_dir_exists": protected_font_extract_dir.exists(),
                    "planned_protected_task_count": analysis["planned_protected_task_count"],
                    "suspicious_neighbor_extract_dir_count": analysis["suspicious_neighbor_extract_dir_count"],
                    "nested_task_count": len(nested_task_summary),
                    "json_report": str(json_report_path),
                    "text_report": str(text_report_path),
                    "workspace_dir": str(workspace_dir) if keep_temp else "<temporary workspace cleaned after exit>",
                },
                ensure_ascii=False,
                indent=2,
            )
        )

        if keep_temp:
            temp_ctx.cleanup = lambda: None
        return 0 if analysis["semantic_passed"] else 1
    finally:
        if not keep_temp:
            temp_ctx.cleanup()


def build_parser():
    parser = argparse.ArgumentParser(
        description="Run a semantic extraction test against rpgmakertest.7z and report whether RPG Maker resource archives would be unpacked."
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Keep the temporary workspace for manual inspection after the test finishes.",
    )
    return parser


if __name__ == "__main__":
    sys.exit(run_semantic_test(build_parser().parse_args().keep_temp))
