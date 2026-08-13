from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


BLOCKER_MISSING_VOLUME = "missing_volume"
BLOCKER_PASSWORD = "password"


@dataclass(frozen=True)
class WatchGroupSnapshot:
    group_id: str
    directory: str
    logical_name: str
    split_family: str
    head_path: str
    input_paths: tuple[str, ...]
    companion_paths: tuple[str, ...]
    owned_paths: tuple[str, ...]
    input_fingerprint: str
    ownership_fingerprint: str
    complete: bool | None
    missing_reason: str = ""
    missing_indices: tuple[int, ...] = ()
    candidate_substitution: bool = False
    completeness_status: str = "ambiguous"
    completeness_confidence: str = "hint"
    completeness_basis: tuple[str, ...] = ()
    encrypted_unresolved: bool = False

    @property
    def has_head(self) -> bool:
        return bool(self.head_path)

    @property
    def has_observed_gap(self) -> bool:
        return self.complete is False

    @property
    def should_wait_for_relation_gap(self) -> bool:
        return (
            self.has_head
            and self.completeness_status in {"middle_gap", "tail_missing"}
            and self.completeness_confidence in {"strong", "proven"}
        )


@dataclass
class WatchGroupState:
    group_id: str
    directory: str
    logical_name: str
    split_family: str
    head_path: str
    input_paths: list[str] = field(default_factory=list)
    owned_paths: list[str] = field(default_factory=list)
    status: str = "waiting"
    blockers: list[str] = field(default_factory=list)
    input_fingerprint: str = ""
    ownership_fingerprint: str = ""
    last_attempted_input_fingerprint: str = ""
    password_generation: int = 0
    missing_reason: str = ""
    missing_indices: list[int] = field(default_factory=list)
    failure_payload: dict[str, Any] = field(default_factory=dict)
    attempt_count: int = 0
    updated_at: float = 0.0

    def has_blocker(self, blocker: str) -> bool:
        return blocker in self.blockers

    def retry_ready(self, snapshot: WatchGroupSnapshot, password_generation: int) -> bool:
        if self.status == "running":
            return snapshot.input_fingerprint != self.last_attempted_input_fingerprint
        input_changed = snapshot.input_fingerprint != self.last_attempted_input_fingerprint
        password_changed = self.has_blocker(BLOCKER_PASSWORD) and password_generation > self.password_generation
        missing_ready = not self.has_blocker(BLOCKER_MISSING_VOLUME) or input_changed
        # A password failure only describes the bytes from the previous
        # attempt. A changed split-group input fingerprint means that a new volume
        # (or new bytes for an existing volume) arrived, so the old password
        # verdict must not prevent one attempt against the new input.
        password_ready = not self.has_blocker(BLOCKER_PASSWORD) or password_changed or input_changed
        if self.blockers:
            return missing_ready and password_ready
        return input_changed
