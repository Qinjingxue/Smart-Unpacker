from packrelic.app.cli_parsers import CliHelpFormatter, build_common_parser, localize_help_action
from packrelic.app.cli_runtime import (
    build_effective_config,
    inspect_result_to_item,
    resolve_common_root,
    resolve_target_paths,
    result_for_missing,
)
from packrelic.app.cli_types import CliCommandResult
from packrelic.contracts.detection import FactBag
from packrelic.contracts.tasks import ArchiveTask
from packrelic.config.loader import load_config
from packrelic.coordinator.analysis_stage import ArchiveAnalysisStage
from packrelic.coordinator.inspector import InspectOrchestrator
from packrelic.support.json_format import to_json_text

COMMAND = "inspect"
ORDER = 30
TEXTS = {
    "en": {
        "help": "Show file inspection details without changing files.",
        "paths": "Files or directories to inspect.",
        "archives_only": "Only output files that are classified as extractable archives.",
        "analyze": "Run archive analysis and include a compact analysis summary.",
        "complete": "[CLI] Inspection complete: total={total} archive={archive} maybe={maybe} not_archive={not_archive}.",
        "analysis": "  Analysis: status={status} selected={selected} confidence={confidence} segment={segment} damage={damage}",
        "analysis_candidates": "  Analysis Candidates: {candidates}",
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
        "analyze": "运行归档分析层，并输出精简分析摘要。",
        "complete": "[CLI] 检测完成：总数={total} archive={archive} maybe={maybe} not_archive={not_archive}。",
        "analysis": "  分析层：状态={status} 选中={selected} 置信度={confidence} 片段={segment} 损坏={damage}",
        "analysis_candidates": "  分析候选：{candidates}",
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
        usage="pkrc inspect [options] <paths...>",
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(parser, ctx)
    parser.add_argument("--archives-only", action="store_true", help=ctx.t(TEXTS, "archives_only"))
    parser.add_argument("--analyze", action="store_true", help=ctx.t(TEXTS, "analyze"))
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
    if args.analyze:
        analyses = _analysis_by_path(results, config)
        for item in all_items:
            item["analysis"] = analyses.get(item["path"])
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
        "analyze": bool(args.analyze),
        "analyzed_items": sum(1 for item in all_items if item.get("analysis")),
        "analysis_extractable_items": sum(1 for item in all_items if (item.get("analysis") or {}).get("has_extractable")),
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
            if args.analyze and item.get("analysis"):
                analysis = item["analysis"]
                reporter.info(ctx.t(TEXTS, "analysis").format(
                    status=analysis.get("status") or "-",
                    selected=analysis.get("selected_format") or "-",
                    confidence=_confidence_label(analysis.get("selected_confidence")),
                    segment=_segment_label(analysis.get("primary_segment")),
                    damage=", ".join(analysis.get("damage_flags") or []) or "-",
                ))
                candidates = _candidate_label(analysis.get("candidates") or [])
                if candidates:
                    reporter.info(ctx.t(TEXTS, "analysis_candidates").format(candidates=candidates))
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
            "analyze": bool(args.analyze),
            "effective_config": effective_config,
            "detection": effective_config["detection"],
        },
        summary=summary,
        items=items,
    )


def _analysis_by_path(results, config: dict) -> dict[str, dict]:
    stage = ArchiveAnalysisStage(config)
    output = {}
    for result in results:
        if not _should_analyze_result(result):
            continue
        task = _task_from_inspect_result(result)
        report = stage.analyze_task(task)
        output[result.path] = _analysis_summary(task, report)
    return output


def _should_analyze_result(result) -> bool:
    return bool(getattr(result, "should_extract", False) or getattr(result, "decision", "") == "maybe_archive")


def _task_from_inspect_result(result) -> ArchiveTask:
    bag = _clone_fact_bag(result.fact_bag)
    return ArchiveTask.from_fact_bag(bag, int(result.score or 0))


def _clone_fact_bag(source) -> FactBag:
    cloned = FactBag()
    if source is not None and hasattr(source, "to_dict"):
        for key, value in source.to_dict().items():
            cloned.set(key, value)
    return cloned


def _analysis_summary(task: ArchiveTask, report) -> dict:
    if report is None:
        return {
            "status": task.fact_bag.get("analysis.status") or "error",
            "error": task.fact_bag.get("analysis.error") or "",
            "has_extractable": False,
            "selected_format": "",
            "selected_confidence": 0.0,
            "primary_segment": None,
            "damage_flags": [],
            "candidates": [],
        }
    selected = list(report.selected or [])
    primary = selected[0] if selected else None
    segment = primary.segments[0] if primary and primary.segments else None
    candidates = [
        _evidence_summary(evidence)
        for evidence in sorted(report.evidences, key=lambda item: item.confidence, reverse=True)[:3]
    ]
    damage_flags = _dedupe([
        flag
        for evidence in selected[:2]
        for segment_item in evidence.segments[:2]
        for flag in segment_item.damage_flags
    ])
    return {
        "status": task.fact_bag.get("analysis.status") or ("extractable" if report.has_extractable else "not_extractable"),
        "has_extractable": bool(report.has_extractable),
        "selected_format": getattr(primary, "format", "") if primary else "",
        "selected_confidence": float(getattr(primary, "confidence", 0.0) or 0.0) if primary else 0.0,
        "selected_status": getattr(primary, "status", "") if primary else "",
        "primary_segment": _segment_summary(segment),
        "damage_flags": damage_flags,
        "candidate_count": len(report.evidences),
        "candidates": candidates,
        "read_bytes": int(report.read_bytes or 0),
        "cache_hits": int(report.cache_hits or 0),
    }


def _evidence_summary(evidence) -> dict:
    damage_flags = _dedupe([
        flag
        for segment in evidence.segments[:2]
        for flag in segment.damage_flags
    ])
    return {
        "format": evidence.format,
        "status": evidence.status,
        "confidence": float(evidence.confidence or 0.0),
        "segments": len(evidence.segments or []),
        "damage_flags": damage_flags,
        "warnings": list(evidence.warnings[:3]),
    }


def _segment_summary(segment) -> dict | None:
    if segment is None:
        return None
    end = segment.end_offset
    length = None if end is None else max(0, int(end) - int(segment.start_offset))
    return {
        "start": int(segment.start_offset),
        "end": int(end) if end is not None else None,
        "length": length,
        "confidence": float(segment.confidence or 0.0),
        "role": segment.role,
    }


def _segment_label(segment: dict | None) -> str:
    if not segment:
        return "-"
    end = segment.get("end")
    end_text = "?" if end is None else str(end)
    length = segment.get("length")
    length_text = "" if length is None else f" len={length}"
    return f"{segment.get('start', 0)}-{end_text}{length_text}"


def _candidate_label(candidates: list[dict]) -> str:
    parts = []
    for candidate in candidates:
        parts.append(
            f"{candidate.get('format') or '?'}:{candidate.get('status') or '?'}@{_confidence_label(candidate.get('confidence'))}"
        )
    return ", ".join(parts)


def _confidence_label(value) -> str:
    try:
        return f"{float(value or 0.0):.2f}"
    except (TypeError, ValueError):
        return "0.00"


def _dedupe(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
