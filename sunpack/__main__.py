import sys

from sunpack.cli.persistent_process import handle_early_argv


if __name__ == "__main__":
    early_result = handle_early_argv(sys.argv[1:])
    if early_result is not None:
        raise SystemExit(early_result)
    from sunpack.cli.cli import main

    raise SystemExit(main())
