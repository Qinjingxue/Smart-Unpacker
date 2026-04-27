from dataclasses import dataclass, field
from typing import List

from smart_unpacker.passwords.internal.lists import dedupe_passwords, read_password_file


@dataclass
class PasswordStore:
    user_passwords: List[str] = field(default_factory=list)
    builtin_passwords: List[str] = field(default_factory=list)
    recent_passwords: List[str] = field(default_factory=list)

    @classmethod
    def from_sources(
        cls,
        *,
        cli_passwords: List[str] | None = None,
        builtin_passwords: List[str] | None = None,
        builtin_passwords_file: str | None = None,
        recent_passwords: List[str] | None = None,
    ) -> "PasswordStore":
        if builtin_passwords is None and builtin_passwords_file:
            try:
                builtin_passwords = read_password_file(builtin_passwords_file)
            except Exception:
                builtin_passwords = []
        return cls(
            user_passwords=dedupe_passwords(cli_passwords or []),
            builtin_passwords=dedupe_passwords(builtin_passwords or []),
            recent_passwords=dedupe_passwords(recent_passwords or []),
        )

    def candidates(self) -> List[str]:
        return dedupe_passwords(
            list(self.recent_passwords)
            + list(self.user_passwords)
            + list(self.builtin_passwords)
        )

    def has_candidates(self) -> bool:
        return bool(self.recent_passwords or self.user_passwords or self.builtin_passwords)

    def remember_success(self, password: str) -> None:
        if not password:
            return
        self.recent_passwords = [item for item in self.recent_passwords if item != password]
        self.recent_passwords.insert(0, password)
