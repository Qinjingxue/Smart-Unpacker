from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SceneContext:
    target_dir: str
    scene_type: str
    markers: set[str] = field(default_factory=set)


@dataclass
class InspectionResult:
    path: str
    score: int = 0
    detected_ext: str | None = None
    container_type: str = "unknown"
    decision: str = "not_archive"
    should_extract: bool = False
    reasons: list[str] = field(default_factory=list)
    size: int = 0
    ext: str = ""
    magic_matched: bool = False
    is_split_candidate: bool = False
    probe_detected_archive: bool = False
    probe_offset: int = 0
    scene_role: str = "unknown"
    validation_ok: bool = False
    validation_skipped: bool = False
    validation_encrypted: bool = False
    skipped_by_size_limit: bool = False


@dataclass
class AppConfig:
    min_inspection_size_bytes: int = 1 * 1024 * 1024
    scheduler_profile: str = "auto"
    max_workers_override: int = 0
    initial_concurrency_limit: int = 4
    scheduler_poll_interval_ms: int = 1000
    scheduler_scale_up_threshold_mb_s: int = 20
    scheduler_scale_up_backlog_threshold_mb_s: int = 40
    scheduler_scale_down_threshold_mb_s: int = 140
    scheduler_scale_up_streak_required: int = 2
    scheduler_scale_down_streak_required: int = 3
    scheduler_medium_backlog_threshold: int = 8
    scheduler_high_backlog_threshold: int = 24
    scheduler_medium_floor_workers: int = 2
    scheduler_high_floor_workers: int = 3


@dataclass
class FileRelation:
    root: str
    filename: str
    path: str
    base: str
    ext: str
    relative_path: str
    split_role: str | None
    is_split_member: bool
    has_generic_001_head: bool
    is_plain_numeric_member: bool
    has_split_companions: bool
    is_split_exe_companion: bool
    is_disguised_split_exe_companion: bool
    is_split_related: bool
    match_rar_disguised: Any
    match_rar_head: Any
    match_001_head: Any


@dataclass
class RenameInstruction:
    kind: str
    root: str
    source: str | None = None
    target: str | None = None
    prefix: str | None = None
    separator: str | None = None
    new_ext_suffix: str | None = None


@dataclass
class GroupDecision:
    group_score: int
    group_should_extract: bool
    main_info: InspectionResult
    inspections: list[InspectionResult]
    reasons: list[str] = field(default_factory=list)


@dataclass
class ArchiveTask:
    key: str
    main_path: str
    all_parts: list[str]
    group_info: GroupDecision


@dataclass
class RunSummary:
    success_count: int
    failed_tasks: list[str]
    processed_keys: list[str]


@dataclass
class CliPasswordSummary:
    user_passwords: list[str]
    recent_passwords: list[str]
    builtin_passwords: list[str]
    combined_passwords: list[str]
    use_builtin_passwords: bool


@dataclass
class CliScanItem:
    key: str
    main_path: str
    all_parts: list[str]
    decision: str
    score: int
    detected_ext: str | None
    validation_ok: bool
    validation_skipped: bool
    validation_encrypted: bool
    scene_role: str
    reasons: list[str] = field(default_factory=list)
    group_reasons: list[str] = field(default_factory=list)


@dataclass
class CliInspectItem:
    path: str
    decision: str
    should_extract: bool
    score: int
    ext: str
    detected_ext: str | None
    container_type: str
    scene_role: str
    validation_ok: bool
    validation_skipped: bool
    validation_encrypted: bool
    probe_detected_archive: bool
    probe_offset: int
    is_split_candidate: bool
    reasons: list[str] = field(default_factory=list)


@dataclass
class CliCommandResult:
    command: str
    inputs: dict[str, Any]
    summary: dict[str, Any]
    errors: list[str] = field(default_factory=list)
    items: list[dict[str, Any]] = field(default_factory=list)
    tasks: list[dict[str, Any]] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
