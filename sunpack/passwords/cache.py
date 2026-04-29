from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PasswordAttemptCache:
    _successes: dict[str, str] = field(default_factory=dict)
    _negative: set[tuple[str, str]] = field(default_factory=set)

    def get_success(self, fingerprint_key: str) -> str | None:
        return self._successes.get(fingerprint_key)

    def remember_success(self, fingerprint_key: str, password: str) -> None:
        self._successes[fingerprint_key] = password

    def has_negative(self, fingerprint_key: str, password: str) -> bool:
        return (fingerprint_key, password) in self._negative

    def remember_negative(self, fingerprint_key: str, password: str) -> None:
        self._negative.add((fingerprint_key, password))

    def remember_negative_batch(self, fingerprint_key: str, passwords: list[str]) -> None:
        for password in passwords:
            self.remember_negative(fingerprint_key, password)
