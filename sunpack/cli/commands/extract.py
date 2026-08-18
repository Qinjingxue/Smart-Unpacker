import json

from sunpack.cli.cli_constants import EXIT_TASK_FAILED, EXIT_USAGE
from sunpack.cli.cli_parsers import (
    CliHelpFormatter,
    build_common_parser,
    build_detection_parser,
    build_extract_config_override_parser,
    build_password_parser,
    localize_help_action,
)
from sunpack.cli.cli_runtime import (
    apply_runtime_config_overrides,
    build_password_summary,
    collect_clipboard_passwords,
    collect_cli_passwords_async,
    password_summary_item,
    prompt_for_passwords_async,
    resolve_common_root,
    resolve_target_paths,
    result_for_missing,
)
from sunpack.cli.cli_types import CliCommandResult
from sunpack.cli.persistent_runtime import load_request_config, pipeline_engine, request_config_source_key
from sunpack.cli.runtime_state import server_runtime_active
from sunpack.contracts.failures import FailureInfo
from sunpack.passwords import dedupe_passwords
from sunpack.support.collections import dedupe_values
from sunpack.detection.options import DetectionOptions

COMMAND = "extract"
ORDER = 10


def register(subparsers, ctx):
    parser = subparsers.add_parser(
        COMMAND,
        parents=[build_common_parser(ctx), build_detection_parser(ctx), build_password_parser(ctx), build_extract_config_override_parser(ctx)],
        help=ctx.t("cli.extract.help"),
        usage="sunpack extract [options] <paths...>",
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(parser, ctx)
    parser.add_argument("--direct-file", dest="direct_file", action="store_true", help=ctx.t("cli.extract.direct_file"))
    parser.add_argument("paths", nargs="+", help=ctx.t("cli.extract.paths"))


async def handle(args, ctx):
    reporter = ctx.reporter
    target_paths, missing_paths = resolve_target_paths(args.paths, base_dir=ctx.cwd)
    if missing_paths:
        return result_for_missing(COMMAND, args, missing_paths)

    config = load_request_config(ctx.cwd)
    config_overrides = apply_runtime_config_overrides(config, args, base_dir=ctx.cwd)
    try:
        passwords = await collect_cli_passwords_async(
            args,
            ctx,
            prompt_text=ctx.t("cli.password_prompt"),
            input_prompt=ctx.t("cli.password_input_prompt"),
        )
        clipboard_passwords = collect_clipboard_passwords(config)
    except Exception as exc:
        return EXIT_USAGE, CliCommandResult(command=COMMAND, inputs={"paths": list(args.paths)}, summary={}, errors=[str(exc)])

    common_root = resolve_common_root(target_paths)
    config.setdefault("output", {})["common_root"] = common_root

    if len(target_paths) == 1:
        reporter.info(ctx.t("cli.extract.single_target", path=target_paths[0]))
    else:
        reporter.info(ctx.t("cli.extract.target_paths", count=len(target_paths)))
        for path in target_paths:
            reporter.detail(f"  - {path}")
    reporter.detail(ctx.t("cli.extract.common_root", root=common_root))

    attempts = []
    retry_count = 0
    initial_password_summary = build_password_summary(
        passwords,
        use_builtin_passwords=not args.no_builtin_passwords,
        clipboard_passwords=clipboard_passwords,
    )
    run_config = _extract_run_config(
        config,
        initial_password_summary,
        quiet=bool(getattr(reporter, "quiet", False) or getattr(reporter, "json_mode", False)),
        verbose=bool(getattr(reporter, "verbose", False)),
    )
    deep_detect = bool(getattr(args, "deep_detect", False))
    engine_options = {"source_key": request_config_source_key(ctx.cwd)} if server_runtime_active() else {}
    engine_context = (
        pipeline_engine(
            run_config,
            detection_options=DetectionOptions(deep_scan=True),
            **engine_options,
        )
        if deep_detect
        else pipeline_engine(run_config, **engine_options)
    )
    async with engine_context as engine:
        while True:
            password_summary = build_password_summary(
                passwords,
                use_builtin_passwords=not args.no_builtin_passwords,
                clipboard_passwords=clipboard_passwords,
            )
            run_config["user_passwords"] = dedupe_passwords(
                password_summary.user_passwords + password_summary.clipboard_passwords
            )
            run_config["builtin_passwords"] = list(password_summary.builtin_passwords)
            response = await engine.run(
                target_paths,
                direct=bool(getattr(args, "direct_file", False)),
                request_config=run_config,
                stdout=ctx.stderr if args.json else ctx.stdout,
                stderr=ctx.stderr,
            )
            summary = response.summary
            failed_tasks = list(summary.failed_tasks)
            failures = list(summary.failures)
            processed_keys = list(summary.processed_keys)
            attempts.append({
                "success_count": summary.success_count,
                "failed_count": len(failed_tasks),
                "processed_count": len(set(processed_keys)),
                "partial_success_count": getattr(summary, "partial_success_count", 0),
                "recovered_outputs": list(getattr(summary, "recovered_outputs", []) or []),
                "wrong_password_failure": has_password_failure(failures),
                "failures": [failure.to_dict() for failure in failures],
            })
            _emit_verbose_recovery_details(reporter, summary, ctx)
            if not _should_retry_password_failure(args, failures):
                break
            if not await _confirm_password_retry(ctx):
                break
            try:
                new_passwords = await prompt_for_passwords_async(
                    ctx,
                    prompt_text=ctx.t("cli.password_prompt"),
                    input_prompt=ctx.t("cli.password_input_prompt"),
                )
            except (EOFError, KeyboardInterrupt):
                break
            if not new_passwords:
                reporter.info(ctx.t("cli.extract.retry_no_passwords"))
                break
            passwords = _dedupe([*passwords, *new_passwords])
            retry_count += 1
            reporter.info(ctx.t("cli.extract.retry_round"))
        recent_passwords = engine.recent_passwords

    password_summary = build_password_summary(
        passwords,
        use_builtin_passwords=not args.no_builtin_passwords,
        recent_passwords=recent_passwords,
        clipboard_passwords=clipboard_passwords,
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
            "direct_file": bool(getattr(args, "direct_file", False)),
            "deep_detect": deep_detect,
        },
        summary={
            "success_count": summary.success_count,
            "failed_count": len(failed_tasks),
            "processed_count": len(set(processed_keys)),
            "partial_success_count": getattr(summary, "partial_success_count", 0),
            "recovered_outputs": list(getattr(summary, "recovered_outputs", []) or []),
            "use_builtin_passwords": not args.no_builtin_passwords,
            "password_retry_count": retry_count,
        },
        errors=failed_tasks,
        items=[password_summary_item(password_summary)],
        tasks=attempts,
    )
    if failed_tasks:
        return EXIT_TASK_FAILED, result
    return 0, result


def _extract_run_config(
    config: dict,
    password_summary,
    *,
    quiet: bool = False,
    verbose: bool = False,
) -> dict:
    run_config = dict(config)
    run_config["cli"] = {
        **(config.get("cli", {}) if isinstance(config.get("cli"), dict) else {}),
        "quiet": quiet,
        "verbose": verbose,
    }
    run_config["extraction"] = {
        **(config.get("extraction", {}) if isinstance(config.get("extraction"), dict) else {}),
        "quiet": not verbose,
    }
    run_config["user_passwords"] = dedupe_passwords(
        password_summary.user_passwords + password_summary.clipboard_passwords
    )
    run_config["builtin_passwords"] = password_summary.builtin_passwords
    return run_config


def has_password_failure(failures: list[FailureInfo]) -> bool:
    return any(failure.is_password_failure for failure in failures)


def _emit_verbose_recovery_details(reporter, summary, ctx) -> None:
    recovered = list(getattr(summary, "recovered_outputs", []) or [])
    if not recovered or not getattr(reporter, "verbose", False):
        return
    for item in recovered:
        report_path = str(item.get("recovery_report") or "")
        report = _read_recovery_report(report_path)
        files = [file for file in report.get("files") or [] if isinstance(file, dict)]
        selected = report.get("selected_attempt") if isinstance(report.get("selected_attempt"), dict) else {}
        comparison = report.get("comparison") if isinstance(report.get("comparison"), dict) else {}
        if selected:
            reporter.detail(_selected_attempt_label(item, selected, comparison, ctx))
        rejected = [entry for entry in report.get("rejected_attempts") or [] if isinstance(entry, dict)]
        for entry in rejected[:5]:
            reporter.detail(_rejected_attempt_label(entry, ctx))
        if not files:
            continue
        reporter.detail(ctx.t("cli.extract.recovery_files", archive=item.get("archive", "")))
        for file in files:
            name = file.get("archive_path") or file.get("output_path") or ctx.t("common.unknown")
            status = file.get("status") or "unverified"
            size = _file_size_label(file)
            action = file.get("user_action") or "inspect_manually"
            reporter.detail(ctx.t("cli.extract.recovery_file", status=status, name=name, size=size, action=action))


def _read_recovery_report(path: str) -> dict:
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _selected_attempt_label(item: dict, selected: dict, comparison: dict, ctx) -> str:
    vector = selected.get("rank_vector") if isinstance(selected.get("rank_vector"), dict) else {}
    reasons = selected.get("reasons") if isinstance(selected.get("reasons"), list) else []
    reason_label = ", ".join(_reason_label(reason) for reason in reasons[:3] if isinstance(reason, dict))
    stop_reason = comparison.get("stop_reason") or ""
    score = selected.get("rank_score")
    try:
        score_label = f"{float(score):.3f}"
    except (TypeError, ValueError):
        score_label = str(score or "")
    return ctx.t("cli.extract.selected_attempt", archive=item.get("archive", ""), decision=selected.get("decision", "selected"), score=score_label, source=vector.get("source", "verification"), stop=stop_reason, reasons=f" ({reason_label})" if reason_label else "")


def _rejected_attempt_label(entry: dict, ctx) -> str:
    rank = entry.get("rank") if isinstance(entry.get("rank"), dict) else {}
    vector = rank.get("rank_vector") if isinstance(rank.get("rank_vector"), dict) else {}
    coverage = entry.get("archive_coverage") if isinstance(entry.get("archive_coverage"), dict) else {}
    return ctx.t("cli.extract.rejected_attempt", source=entry.get("source", ""), module=entry.get("repair_module", ""), decision=rank.get("decision", ""), completeness=coverage.get("completeness", ""), complete_files=coverage.get("complete_files", ""), failed_missing=vector.get("failed_missing_files", ""))


def _reason_label(reason: dict) -> str:
    code = str(reason.get("code") or "")
    value = reason.get("value")
    if isinstance(value, float):
        value = f"{value:.3f}"
    return f"{code}={value}"


def _file_size_label(file: dict) -> str:
    written = int(file.get("bytes_written", 0) or 0)
    expected = file.get("expected_size")
    if expected is None or expected == "":
        return f" {written} B" if written else ""
    try:
        expected_int = int(expected)
    except (TypeError, ValueError):
        return f" {written} B" if written else ""
    return f" {written}/{expected_int} B"


def _should_retry_password_failure(args, failures: list[FailureInfo]) -> bool:
    return (
        has_password_failure(failures)
        and not getattr(args, "json", False)
        and not getattr(args, "quiet", False)
    )


async def _confirm_password_retry(ctx) -> bool:
    while True:
        try:
            answer = (await ctx.readline(ctx.t("cli.password_retry_prompt"))).strip().lower()
        except EOFError:
            return False
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no", ""}:
            return False
        print(ctx.t("cli.answer_yes_no"), file=ctx.stdout, flush=True)


_dedupe = dedupe_values
