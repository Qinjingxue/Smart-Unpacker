from smart_unpacker.app.cli import build_cli_parser
from smart_unpacker.app.cli_commands import discover_command_modules
from smart_unpacker.app.cli_context import CliContext


def test_cli_discovers_builtin_command_modules_in_order():
    modules = discover_command_modules()

    assert [module.COMMAND for module in modules] == ["extract", "scan", "inspect", "passwords", "config"]


def test_cli_command_modules_declare_required_contract():
    for module in discover_command_modules():
        assert isinstance(module.COMMAND, str) and module.COMMAND
        assert isinstance(module.TEXTS, dict)
        assert callable(module.register)
        assert callable(module.handle)


def test_cli_parser_registers_discovered_commands():
    ctx = CliContext(language="en")
    parser = build_cli_parser(ctx)

    command_args = {
        "extract": ["extract", "."],
        "scan": ["scan", "."],
        "inspect": ["inspect", "."],
        "passwords": ["passwords"],
        "config": ["config", "show"],
    }

    for command, args in command_args.items():
        assert parser.parse_args(args).command == command


def test_cli_parser_uses_command_module_language_text():
    ctx = CliContext(language="zh")
    parser = build_cli_parser(ctx)
    help_text = parser.format_help()

    assert "执行预检查、扫描、解压和清理" in help_text
    assert "查看或校验 smart_unpacker_config.json" in help_text
    assert "选项" in help_text
