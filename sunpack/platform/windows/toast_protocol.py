from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from enum import IntEnum


PROTOCOL_MAGIC = 0x4E545053  # "SPTN" in a little-endian frame.
PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 64 * 1024
_HEADER = struct.Struct("<IHHIQ")


class ToastMessageType(IntEnum):
    HELLO = 1
    SNAPSHOT = 2
    CLEAR = 3
    PING = 4
    SHUTDOWN = 5


class ToastSnapshotKind(IntEnum):
    PROGRESS = 1
    SUCCESS = 2
    FAILURE = 3
    MIXED = 4


class ToastProgressMode(IntEnum):
    NONE = 0
    DETERMINATE = 1
    INDETERMINATE = 2


class ToastActionKind(IntEnum):
    OPEN_DIRECTORY = 1
    OPEN_LOG = 2


@dataclass(frozen=True)
class ToastAction:
    kind: ToastActionKind
    label: str
    target: str


@dataclass(frozen=True)
class ToastSnapshot:
    kind: ToastSnapshotKind
    batch_id: str
    title: str
    body: str = ""
    progress_mode: ToastProgressMode = ToastProgressMode.NONE
    progress_value: float = 0.0
    progress_title: str = ""
    progress_status: str = ""
    progress_value_text: str = ""
    actions: tuple[ToastAction, ...] = ()
    ttl_ms: int = 0


def encode_hello(session_token: str, sequence: int) -> bytes:
    return encode_frame(ToastMessageType.HELLO, _encode_string(session_token), sequence)


def encode_snapshot(snapshot: ToastSnapshot, sequence: int) -> bytes:
    actions = tuple(snapshot.actions[:2])
    progress = float(snapshot.progress_value)
    if not math.isfinite(progress):
        progress = 0.0
    progress = min(1.0, max(0.0, progress))
    payload = bytearray(struct.pack(
        "<BBBBdI",
        int(snapshot.kind),
        int(snapshot.progress_mode),
        len(actions),
        0,
        progress,
        max(0, min(0xFFFFFFFF, int(snapshot.ttl_ms))),
    ))
    for value in (
        snapshot.batch_id,
        snapshot.title,
        snapshot.body,
        snapshot.progress_title,
        snapshot.progress_status,
        snapshot.progress_value_text,
    ):
        payload.extend(_encode_string(value))
    for action in actions:
        payload.append(int(action.kind))
        payload.extend(_encode_string(action.label))
        payload.extend(_encode_string(action.target))
    return encode_frame(ToastMessageType.SNAPSHOT, bytes(payload), sequence)


def encode_frame(message_type: ToastMessageType, payload: bytes, sequence: int) -> bytes:
    body = bytes(payload)
    if len(body) > MAX_FRAME_BYTES - _HEADER.size:
        raise ValueError("toast IPC frame exceeds the 64 KiB protocol limit")
    return _HEADER.pack(
        PROTOCOL_MAGIC,
        PROTOCOL_VERSION,
        int(message_type),
        len(body),
        max(0, int(sequence)),
    ) + body


def _encode_string(value: str) -> bytes:
    encoded = str(value or "").encode("utf-8", errors="strict")
    if len(encoded) > 0xFFFFFFFF:
        raise ValueError("toast IPC string is too large")
    return struct.pack("<I", len(encoded)) + encoded

