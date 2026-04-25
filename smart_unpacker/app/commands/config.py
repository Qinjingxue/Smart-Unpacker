from smart_unpacker.app.cli_constants import EXIT_USAGE
from smart_unpacker.app.cli_parsers import CliHelpFormatter, build_config_output_parser, localize_help_action
from smart_unpacker.app.cli_types import CliCommandResult
from smart_unpacker.config.config_validator import validate_config_payload
from smart_unpacker.config.payload_io import read_config_payload
from smart_unpacker.support.json_format import to_json_text

COMMAND = "config"
ORDER = 50
TEXTS = {
    "en": {
        "help": "Show or validate smart_unpacker_config.json.",
        "show_help": "Print the current config file.",
        "validate_help": "Validate JSON, rules, rule config schemas, and fact schemas.",
        "valid_config": "[CONFIG] Configuration is valid.",
        "unknown_config_command": "Unknown config command: {action}",
    },
    "zh": {
        "help": "查看或校验 smart_unpacker_config.json。",
        "show_help": "打印当前配置文件。",
        "validate_help": "校验 JSON、规则、规则配置 schema 和 fact schema。",
        "valid_config": "[CONFIG] 配置有效。",
        "unknown_config_command": "未知配置命令：{action}",
    },
}


def register(subparsers, ctx):
    common_parser = build_config_output_parser(ctx)
    config_parser = subparsers.add_parser(
        COMMAND,
        parents=[common_parser],
        help=ctx.t(TEXTS, "help"),
        usage="sunpack config [options] <show|validate>",
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(config_parser, ctx)
    config_subparsers = config_parser.add_subparsers(dest="config_action", required=True)
    config_subparsers.add_parser("show", parents=[common_parser], help=ctx.t(TEXTS, "show_help"), formatter_class=CliHelpFormatter)
    config_subparsers.add_parser(
        "validate",
        parents=[common_parser],
        help=ctx.t(TEXTS, "validate_help"),
        formatter_class=CliHelpFormatter,
    )


def handle(args, ctx):
    reporter = ctx.reporter
    try:
        config_path, payload = read_config_payload()
        item = payload
        if args.config_action == "show":
            if not args.json and not args.quiet:
                print(to_json_text(payload), flush=True)
        elif args.config_action == "validate":
            item = validate_config_payload(payload)
            if not item["ok"]:
                for error in item["errors"]:
                    reporter.error(f"[CONFIG] {error}")
                return EXIT_USAGE, CliCommandResult(
                    command=COMMAND,
                    inputs={"action": args.config_action},
                    summary={"config_path": str(config_path), "changed": False, "valid": False},
                    errors=list(item["errors"]),
                    items=[item],
                )
            reporter.info(ctx.t(TEXTS, "valid_config"))
        else:
            return EXIT_USAGE, CliCommandResult(
                command=COMMAND,
                inputs={},
                summary={},
                errors=[ctx.t(TEXTS, "unknown_config_command").format(action=args.config_action)],
            )
    except Exception as exc:
        return EXIT_USAGE, CliCommandResult(command=COMMAND, inputs={}, summary={}, errors=[str(exc)])

    return 0, CliCommandResult(
        command=COMMAND,
        inputs={
            "action": args.config_action,
        },
        summary={"config_path": str(config_path), "changed": False},
        items=[item],
    )
