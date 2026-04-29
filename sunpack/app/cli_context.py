from dataclasses import dataclass
from types import ModuleType

from sunpack.app.cli_reporter import CliReporter
from sunpack.config.cli_settings import DEFAULT_CLI_LANG

CORE_TEXTS = {
    "en": {
        "description": "SunPack command line interface.",
        "usage": "sunpack [-h] <command> [command options] [paths...]",
        "json": "Output results as JSON.",
        "quiet": "Reduce terminal output to essentials.",
        "verbose": "Show more detailed terminal output.",
        "color": "Control colored terminal output: auto, always, never.",
        "no_pause": "Do not wait for a key press before exit.",
        "pause": "Wait for a key press before exit.",
        "password": "Archive password. Can be passed multiple times.",
        "password_file": "Path to a password list file, one password per line.",
        "prompt_passwords": "Prompt for passwords in the terminal.",
        "password_prompt": "[CLI] Enter passwords, one per line. Submit an empty line to finish.",
        "password_input_prompt": "password> ",
        "password_retry_prompt": "[CLI] Wrong password failure detected. Enter new passwords and run another extraction round? (y/n): ",
        "no_builtin_passwords": "Disable built-in common passwords.",
        "recursive_extract": "Recursive extraction mode: positive integer rounds, * for infinite, or ? for prompt.",
        "scheduler_profile": "Concurrency scheduler profile.",
        "archive_cleanup_mode": "Archive cleanup: d delete, r recycle, k keep.",
        "output_dir": "Project output root directory. Defaults to the current directory.",
        "flatten": "Flatten a single top-level output directory after extraction.",
        "no_flatten": "Keep the extracted directory structure unchanged.",
        "write_manifest": "Write internal extraction_manifest.json files under output .sunpack directories.",
        "runtime_failure": "[CLI] Runtime failure: {error}",
        "unknown_command": "Unknown command: {command}",
        "pause_prompt": "Press any key to exit...",
    },
    "zh": {
        "description": "智能解压工具命令行界面。",
        "usage": "sunpack [-h] <command> [command options] [paths...]",
        "json": "以 JSON 格式输出结果。",
        "quiet": "减少终端输出，仅保留必要信息。",
        "verbose": "输出更详细的终端信息。",
        "color": "控制终端彩色输出：auto、always、never。",
        "no_pause": "命令结束后不暂停。",
        "pause": "命令结束后等待按键退出。",
        "password": "解压密码，可重复传入多次。",
        "password_file": "密码列表文件路径，按每行一个密码读取。",
        "prompt_passwords": "通过终端交互输入密码列表。",
        "password_prompt": "[CLI] 请输入密码，每行一个；输入空行结束。",
        "password_input_prompt": "密码> ",
        "password_retry_prompt": "[CLI] 检测到密码错误，是否重新输入密码并再解压一轮？(y/n)：",
        "no_builtin_passwords": "禁用内置高频密码表。",
        "recursive_extract": "递归解压模式：正整数表示固定轮数，* 表示无限递归，? 表示提示模式。",
        "scheduler_profile": "并发调度配置档。",
        "archive_cleanup_mode": "原压缩包处理：d 删除，r 回收站，k 不动。",
        "output_dir": "项目输出根目录，默认当前目录。",
        "flatten": "解压后扁平化单一顶层目录。",
        "no_flatten": "保留原始解压目录结构。",
        "write_manifest": "在输出目录的 .sunpack 中写入内部 extraction_manifest.json 文件。",
        "runtime_failure": "[CLI] 运行失败：{error}",
        "unknown_command": "未知命令：{command}",
        "pause_prompt": "按任意键退出...",
    },
}

@dataclass
class CliContext:
    language: str = DEFAULT_CLI_LANG
    reporter: CliReporter | None = None
    commands: dict[str, ModuleType] | None = None

    def t(self, texts: dict[str, dict[str, str]], key: str) -> str:
        lang_texts = texts.get(self.language) or texts.get(DEFAULT_CLI_LANG) or {}
        default_texts = texts.get(DEFAULT_CLI_LANG) or {}
        return lang_texts.get(key, default_texts.get(key, key))

    def core_text(self, key: str) -> str:
        return self.t(CORE_TEXTS, key)
