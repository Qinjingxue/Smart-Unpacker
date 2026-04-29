from packrelic.app.cli_constants import EXIT_USAGE
from packrelic.app.cli_parsers import CliHelpFormatter, build_json_parser, build_password_parser, localize_help_action
from packrelic.app.cli_runtime import build_password_summary, collect_cli_passwords, password_summary_item
from packrelic.app.cli_types import CliCommandResult

COMMAND = "passwords"
ORDER = 40
TEXTS = {
    "en": {
        "help": "Show the password list that would be tried.",
        "summary": "[CLI] Password source summary:",
        "user_input": "  User input: {value}",
        "recent": "  Recent: {value}",
        "builtin": "  Built-in: {value}",
        "final_order": "  Final order: {value}",
    },
    "zh": {
        "help": "查看当前会参与尝试的密码列表。",
        "summary": "[CLI] 密码来源汇总：",
        "user_input": "  用户输入：{value}",
        "recent": "  最近成功：{value}",
        "builtin": "  内置密码：{value}",
        "final_order": "  最终顺序：{value}",
    },
}


def register(subparsers, ctx):
    parser = subparsers.add_parser(
        COMMAND,
        parents=[build_json_parser(ctx), build_password_parser(ctx)],
        help=ctx.t(TEXTS, "help"),
        usage="pkrc passwords [options]",
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(parser, ctx)


def handle(args, ctx):
    reporter = ctx.reporter
    try:
        passwords = collect_cli_passwords(
            args,
            prompt_text=ctx.core_text("password_prompt"),
            input_prompt=ctx.core_text("password_input_prompt"),
        )
        password_summary = build_password_summary(passwords, use_builtin_passwords=not args.no_builtin_passwords)
    except Exception as exc:
        return EXIT_USAGE, CliCommandResult(command=COMMAND, inputs={}, summary={}, errors=[str(exc)])

    if not args.json:
        reporter.info(ctx.t(TEXTS, "summary"))
        reporter.info(ctx.t(TEXTS, "user_input").format(value=password_summary.user_passwords or []))
        reporter.info(ctx.t(TEXTS, "recent").format(value=password_summary.recent_passwords or []))
        reporter.info(ctx.t(TEXTS, "builtin").format(value=password_summary.builtin_passwords or []))
        reporter.info(ctx.t(TEXTS, "final_order").format(value=password_summary.combined_passwords or []))

    return 0, CliCommandResult(
        command=COMMAND,
        inputs={
            "json": args.json,
            "use_builtin_passwords": not args.no_builtin_passwords,
        },
        summary={
            "user_password_count": len(password_summary.user_passwords),
            "recent_password_count": len(password_summary.recent_passwords),
            "builtin_password_count": len(password_summary.builtin_passwords),
            "combined_password_count": len(password_summary.combined_passwords),
        },
        items=[password_summary_item(password_summary)],
    )
