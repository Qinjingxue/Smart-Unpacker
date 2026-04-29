from sunpack.app.cli_parsers import CliHelpFormatter, build_common_parser, localize_help_action
from sunpack.app.cli_runtime import (
    resolve_common_root,
    resolve_target_paths,
    result_for_missing,
    scan_result_to_item,
)
from sunpack.app.cli_types import CliCommandResult
from sunpack.config.loader import load_config
from sunpack.coordinator.scanner import ScanOrchestrator

COMMAND = "scan"
ORDER = 20
TEXTS = {
    "en": {
        "help": "Scan candidate archives without changing files.",
        "paths": "Files or directories to scan.",
        "identified": "[CLI] Identified {count} extractable task(s).",
        "detected_ext": "  Detected Extension: {ext}",
        "matched_rules": "  Matched Rules: {rules}",
    },
    "zh": {
        "help": "只扫描候选归档，不修改文件系统。",
        "paths": "要扫描的文件或目录。",
        "identified": "[CLI] 识别到 {count} 个可解压任务。",
        "detected_ext": "  检测扩展名：{ext}",
        "matched_rules": "  命中规则：{rules}",
    },
}


def register(subparsers, ctx):
    parser = subparsers.add_parser(
        COMMAND,
        parents=[build_common_parser(ctx)],
        help=ctx.t(TEXTS, "help"),
        usage="sunpack scan [options] <paths...>",
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(parser, ctx)
    parser.add_argument("paths", nargs="+", help=ctx.t(TEXTS, "paths"))


def handle(args, ctx):
    reporter = ctx.reporter
    target_paths, missing_paths = resolve_target_paths(args.paths)
    if missing_paths:
        return result_for_missing(COMMAND, args, missing_paths)

    config = load_config()
    orchestrator = ScanOrchestrator(config)
    task_items = [scan_result_to_item(res) for res in orchestrator.scan_targets(target_paths)]
    task_items.sort(key=lambda item: item["main_path"].lower())

    summary = {
        "task_count": len(task_items),
        "encrypted_task_count": sum(1 for item in task_items if item["validation_encrypted"]),
        "split_task_count": sum(1 for item in task_items if len(item["all_parts"]) > 1),
    }
    if not args.json:
        reporter.info(ctx.t(TEXTS, "identified").format(count=summary["task_count"]))
        for item in task_items:
            reporter.info(f"- {item['main_path']}")
            reporter.info(f"  Decision={item['decision']} Score={item['score']} Parts={len(item['all_parts'])}")
            if item["detected_ext"]:
                reporter.info(ctx.t(TEXTS, "detected_ext").format(ext=item["detected_ext"]))
            if reporter.verbose and item["reasons"]:
                reporter.info(ctx.t(TEXTS, "matched_rules").format(rules=", ".join(item["reasons"])))

    return 0, CliCommandResult(
        command=COMMAND,
        inputs={"paths": target_paths, "common_root": resolve_common_root(target_paths), "config_overrides": {}},
        summary=summary,
        tasks=task_items,
    )
