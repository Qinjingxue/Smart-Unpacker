from smart_unpacker.app.cli_parsers import CliHelpFormatter, build_common_parser, localize_help_action
from smart_unpacker.app.cli_runtime import (
    build_effective_config,
    inspect_result_to_item,
    resolve_common_root,
    resolve_target_paths,
    result_for_missing,
)
from smart_unpacker.app.cli_types import CliCommandResult
from smart_unpacker.config.loader import load_config
from smart_unpacker.coordinator.inspector import InspectOrchestrator
from smart_unpacker.support.json_format import to_json_text

COMMAND = "inspect"
ORDER = 30
TEXTS = {
    "en": {
        "help": "Show file inspection details without changing files.",
        "paths": "Files or directories to inspect.",
        "archives_only": "Only output files that are classified as extractable archives.",
        "complete": "[CLI] Inspection complete: total={total} archive={archive} maybe={maybe} not_archive={not_archive}.",
        "effective_config": "[CLI] Effective config:",
        "matched_rules": "  Matched Rules: {rules}",
        "decision_trace": "  Stage={stage} DiscardedAt={discarded_at} Rule={rule}",
        "stop_reason": "  Reason: {reason}",
        "score_breakdown": "  Score Breakdown: {breakdown}",
        "confirmation": "  Confirmation: {confirmation}",
        "fact_errors": "  Fact Errors: {errors}",
    },
    "zh": {
        "help": "输出文件检测详情，不修改文件系统。",
        "paths": "要检测的文件或目录。",
        "archives_only": "只输出被判定为可解压压缩包的文件。",
        "complete": "[CLI] 检测完成：总数={total} archive={archive} maybe={maybe} not_archive={not_archive}。",
        "effective_config": "[CLI] 生效配置：",
        "matched_rules": "  命中规则：{rules}",
        "decision_trace": "  阶段={stage} 丢弃位置={discarded_at} 规则={rule}",
        "stop_reason": "  原因：{reason}",
        "score_breakdown": "  打分明细：{breakdown}",
        "confirmation": "  确认层：{confirmation}",
        "fact_errors": "  Fact 错误：{errors}",
    },
}


def register(subparsers, ctx):
    parser = subparsers.add_parser(
        COMMAND,
        parents=[build_common_parser(ctx)],
        help=ctx.t(TEXTS, "help"),
        usage="sunpack inspect [options] <paths...>",
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(parser, ctx)
    parser.add_argument("--archives-only", action="store_true", help=ctx.t(TEXTS, "archives_only"))
    parser.add_argument("paths", nargs="+", help=ctx.t(TEXTS, "paths"))


def handle(args, ctx):
    reporter = ctx.reporter
    target_paths, missing_paths = resolve_target_paths(args.paths)
    if missing_paths:
        return result_for_missing(COMMAND, args, missing_paths)

    config = load_config()
    effective_config = build_effective_config(config)
    results = InspectOrchestrator(config).inspect(target_paths)
    all_items = [inspect_result_to_item(res) for res in results]
    all_items.sort(key=lambda item: item["path"].lower())
    items = [item for item in all_items if item["should_extract"]] if args.archives_only else all_items
    summary = {
        "total_items": len(all_items),
        "displayed_items": len(items),
        "archive_items": sum(1 for item in all_items if item["decision"] == "archive"),
        "maybe_archive_items": sum(1 for item in all_items if item["decision"] == "maybe_archive"),
        "not_archive_items": sum(1 for item in all_items if item["decision"] == "not_archive"),
        "extractable_items": sum(1 for item in all_items if item["should_extract"]),
        "encrypted_items": 0,
        "archives_only": bool(args.archives_only),
    }
    if not args.json:
        reporter.info(
            ctx.t(TEXTS, "complete").format(
                total=summary["total_items"],
                archive=summary["archive_items"],
                maybe=summary["maybe_archive_items"],
                not_archive=summary["not_archive_items"],
            )
        )
        if reporter.verbose:
            reporter.info(ctx.t(TEXTS, "effective_config"))
            reporter.info(to_json_text(effective_config))
        for item in items:
            reporter.info(f"- {item['path']}")
            reporter.info(
                f"  Decision={item['decision']} Extract={'Yes' if item['should_extract'] else 'No'} "
                f"Score={item['score']} Detected={item['detected_ext'] or '-'}"
            )
            reporter.info(ctx.t(TEXTS, "decision_trace").format(
                stage=item.get("decision_stage") or "-",
                discarded_at=item.get("discarded_at") or "-",
                rule=item.get("deciding_rule") or "-",
            ))
            if item.get("stop_reason"):
                reporter.info(ctx.t(TEXTS, "stop_reason").format(reason=item["stop_reason"]))
            if reporter.verbose and item["reasons"]:
                reporter.info(ctx.t(TEXTS, "matched_rules").format(rules=", ".join(item["reasons"])))
            if reporter.verbose and item.get("score_breakdown"):
                reporter.info(ctx.t(TEXTS, "score_breakdown").format(
                    breakdown=to_json_text(item["score_breakdown"], pretty=False)
                ))
            if reporter.verbose and item.get("confirmation"):
                reporter.info(ctx.t(TEXTS, "confirmation").format(
                    confirmation=to_json_text(item["confirmation"], pretty=False)
                ))
            if reporter.verbose and item.get("fact_errors"):
                reporter.info(ctx.t(TEXTS, "fact_errors").format(errors=to_json_text(item["fact_errors"], pretty=False)))

    return 0, CliCommandResult(
        command=COMMAND,
        inputs={
            "paths": target_paths,
            "common_root": resolve_common_root(target_paths),
            "config_overrides": {},
            "archives_only": bool(args.archives_only),
            "effective_config": effective_config,
            "detection": effective_config["detection"],
        },
        summary=summary,
        items=items,
    )
