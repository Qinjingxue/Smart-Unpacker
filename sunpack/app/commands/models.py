from __future__ import annotations

from sunpack.app.cli_parsers import CliHelpFormatter, build_common_parser, localize_help_action
from sunpack.app.cli_types import CliCommandResult
from sunpack.model_runtime import get_model_asset_registry


COMMAND = "models"
ORDER = 55
TEXTS = {
    "en": {
        "help": "Inspect bundled model runtime assets.",
        "status_help": "Show model availability and optionally load each model.",
        "load": "Load models to verify runtime compatibility.",
    },
    "zh": {
        "help": "检查内置模型运行时资产。",
        "status_help": "显示模型可用性，并可实际加载模型。",
        "load": "实际加载模型以验证运行时兼容性。",
    },
}


def register(subparsers, ctx):
    common = build_common_parser(ctx)
    parser = subparsers.add_parser(
        COMMAND,
        parents=[common],
        help=ctx.t(TEXTS, "help"),
        usage="sunpack models [options] status",
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(parser, ctx)
    actions = parser.add_subparsers(dest="models_action", required=True)
    status = actions.add_parser("status", parents=[common], help=ctx.t(TEXTS, "status_help"), formatter_class=CliHelpFormatter)
    status.add_argument("--load", action="store_true", help=ctx.t(TEXTS, "load"))


def handle(args, ctx):
    payload = get_model_asset_registry(refresh=True).status(
        load=bool(getattr(args, "load", False)),
        device="cpu",
    )
    errors = [] if payload["ok"] else ["one or more model assets are unavailable"]
    return (0 if payload["ok"] else 1), CliCommandResult(
        command=COMMAND,
        inputs={"action": args.models_action, "load": bool(getattr(args, "load", False))},
        summary={"ok": payload["ok"], "supported_formats": payload["supported_formats"]},
        errors=errors,
        items=[payload],
    )
