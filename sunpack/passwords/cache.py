from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock


@dataclass
class PasswordAttemptCache:
    _successes: dict[str, str] = field(default_factory=dict)
    _negative: set[tuple[str, str]] = field(default_factory=set)
    _lock: RLock = field(default_factory=RLock, repr=False)

    def get_success(self, fingerprint_key: str) -> str | None:
        with self._lock:
            return self._successes.get(fingerprint_key)

    def remember_success(self, fingerprint_key: str, password: str) -> None:
        with self._lock:
            self._successes[fingerprint_key] = password

    def has_negative(self, fingerprint_key: str, password: str) -> bool:
        with self._lock:
            return (fingerprint_key, password) in self._negative

    def remember_negative(self, fingerprint_key: str, password: str) -> None:
        with self._lock:
            self._negative.add((fingerprint_key, password))

    def remember_negative_batch(self, fingerprint_key: str, passwords: list[str]) -> None:
        with self._lock:
            self._negative.update((fingerprint_key, password) for password in passwords)
