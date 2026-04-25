from smart_unpacker.app.cli_constants import EXIT_TASK_FAILED, EXIT_USAGE
from smart_unpacker.app.cli_parsers import (
    CliHelpFormatter,
    build_common_parser,
    build_extract_config_override_parser,
    build_password_parser,
    localize_help_action,
)
from smart_unpacker.app.cli_runtime import (
    apply_runtime_config_overrides,
    build_password_summary,
    collect_cli_passwords,
    password_summary_item,
    resolve_common_root,
    resolve_target_paths,
    result_for_missing,
)
from smart_unpacker.app.cli_types import CliCommandResult
from smart_unpacker.config.loader import load_config
from smart_unpacker.coordinator.runner import PipelineRunner

COMMAND = "extract"
ORDER = 10
TEXTS = {
    "en": {
        "help": "Run precheck, scan, extraction, and cleanup.",
        "paths": "Files or directories to process.",
        "target_paths": "[CLI] Target paths:",
        "common_root": "[CLI] Common root: {root}",
    },
    "zh": {
        "help": "执行预检查、扫描、解压和清理。",
        "paths": "要处理的文件或目录。",
        "target_paths": "[CLI] 目标路径：",
        "common_root": "[CLI] 公共根目录：{root}",
    },
}


def register(subparsers, ctx):
    parser = subparsers.add_parser(
        COMMAND,
        parents=[build_common_parser(ctx), build_password_parser(ctx), build_extract_config_override_parser(ctx)],
        help=ctx.t(TEXTS, "help"),
        usage="sunpack extract [options] <paths...>",
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(parser, ctx)
    parser.add_argument("paths", nargs="+", help=ctx.t(TEXTS, "paths"))


def handle(args, ctx):
    reporter = ctx.reporter
    target_paths, missing_paths = resolve_target_paths(args.paths)
    if missing_paths:
        return result_for_missing(COMMAND, args, missing_paths)

    try:
        passwords = collect_cli_passwords(
            args,
            prompt_text=ctx.core_text("password_prompt"),
            input_prompt=ctx.core_text("password_input_prompt"),
        )
    except Exception as exc:
        return EXIT_USAGE, CliCommandResult(command=COMMAND, inputs={"paths": list(args.paths)}, summary={}, errors=[str(exc)])

    password_summary = build_password_summary(passwords, use_builtin_passwords=not args.no_builtin_passwords)
    config = load_config()
    config["user_passwords"] = password_summary.user_passwords
    config["builtin_passwords"] = password_summary.builtin_passwords
    config_overrides = apply_runtime_config_overrides(config, args)
    common_root = resolve_common_root(target_paths)

    reporter.info(ctx.t(TEXTS, "target_paths"))
    for path in target_paths:
        reporter.info(f"  - {path}")
    reporter.info(ctx.t(TEXTS, "common_root").format(root=common_root))

    runner = PipelineRunner(config)
    summary = runner.run_targets(target_paths)
    failed_tasks = list(summary.failed_tasks)
    processed_keys = list(summary.processed_keys)

    password_summary = build_password_summary(
        passwords,
        use_builtin_passwords=not args.no_builtin_passwords,
        recent_passwords=runner.recent_passwords,
    )

    result = CliCommandResult(
        command=COMMAND,
        inputs={
            "paths": target_paths,
            "common_root": common_root,
            "json": args.json,
            "quiet": args.quiet,
            "verbose": args.verbose,
            "config_overrides": config_overrides,
        },
        summary={
            "success_count": summary.success_count,
            "failed_count": len(failed_tasks),
            "processed_count": len(set(processed_keys)),
            "use_builtin_passwords": not args.no_builtin_passwords,
        },
        errors=failed_tasks,
        items=[password_summary_item(password_summary)],
    )
    return (EXIT_TASK_FAILED if failed_tasks else 0), result
