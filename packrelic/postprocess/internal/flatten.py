from packrelic_native import flatten_single_branch_directories as _native_flatten_single_branch_directories


class DirectoryFlattener:
    def __init__(self, language: str = "en"):
        self.language = "zh" if str(language or "").strip().lower() == "zh" else "en"

    def text(self, en: str, zh: str) -> str:
        return zh if self.language == "zh" else en

    def flatten_dirs(self, base: str):
        print(self.text(
            "\n[CLEAN] Flattening single-branch directories...",
            "\n[CLEAN] 正在压平单子目录...",
        ))
        _native_flatten_single_branch_directories(str(base))
