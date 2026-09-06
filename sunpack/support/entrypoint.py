import sys


def main() -> int:
    # Registration and COM activation enter the main runtime directly and do
    # not start an extraction engine or a watch service.
    if sys.argv[1:2] and sys.argv[1] in {"--register-toast", "--unregister-toast", "--toast-activated"}:
        from sunpack.platform.windows.toast_host import handle_toast_argv

        return handle_toast_argv(sys.argv[1:])

    from sunpack.support.runtime_identity import consume_runtime_id

    try:
        public_argv = consume_runtime_id(sys.argv[1:])
    except ValueError as exc:
        from sunpack.config.cli_settings import load_cli_language_from_config
        from sunpack.i18n import I18nContext

        i18n = I18nContext(load_cli_language_from_config())
        print(i18n.t("cli.startup_failed", error=exc), file=sys.stderr, flush=True)
        return 2
    # Existing CLI and GUI entry points read sys.argv directly. Remove the
    # process-local private bootstrap arguments before either is entered.
    sys.argv[:] = [sys.argv[0], *public_argv]

    from sunpack.cli.persistent_process import handle_early_argv

    early_result = handle_early_argv(sys.argv[1:])
    if early_result is not None:
        return early_result
    from sunpack.cli.cli import main as cli_main

    return cli_main()
