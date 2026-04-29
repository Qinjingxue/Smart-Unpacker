class RecursionController:
    def __init__(self, mode: str, max_rounds: int = 1, language: str = "en"):
        self.mode = mode # "fixed", "prompt", "infinite"
        self.max_rounds = max_rounds
        self.language = "zh" if str(language or "").strip().lower() == "zh" else "en"

    def text(self, en: str, zh: str) -> str:
        return zh if self.language == "zh" else en

    def should_continue(self, round_index: int, new_roots_found: bool) -> bool:
        if not new_roots_found:
            return False
            
        if self.mode == "fixed":
            return round_index < self.max_rounds
            
        if self.mode == "prompt":
            return True
                    
        return True # infinite

    def prompt_continue(self, round_index: int) -> bool:
        while True:
            try:
                ans = input(self.text(
                    f"[CLI] Round {round_index} finished. Continue recursive extraction? (y/n): ",
                    f"[CLI] 第 {round_index} 轮已完成。是否继续递归解压？(y/n)：",
                )).strip().lower()
            except EOFError:
                print(self.text(
                    "[CLI] No input available, stopping recursive extraction.",
                    "[CLI] 没有可用输入，停止递归解压。",
                ), flush=True)
                return False
            except KeyboardInterrupt:
                print(self.text(
                    "[CLI] User cancelled, stopping recursive extraction.",
                    "[CLI] 用户已取消，停止递归解压。",
                ), flush=True)
                return False
            if ans in {"y", "yes"}:
                return True
            if ans in {"n", "no", ""}:
                return False
            print(self.text("Please enter y or n.", "请输入 y 或 n。"), flush=True)
