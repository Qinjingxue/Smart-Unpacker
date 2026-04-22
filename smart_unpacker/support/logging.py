from __future__ import annotations

from typing import Callable


class CallbackLogger:
    def __init__(self, callback: Callable[[str], None] | None):
        self.callback = callback

    def log(self, message: str) -> None:
        if self.callback:
            self.callback(message)
