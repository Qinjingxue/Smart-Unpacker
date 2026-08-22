from __future__ import annotations

import struct

import pytest

from sunpack.platform.windows.toast_protocol import (
    MAX_FRAME_BYTES,
    PROTOCOL_MAGIC,
    PROTOCOL_VERSION,
    ToastAction,
    ToastActionKind,
    ToastMessageType,
    ToastProgressMode,
    ToastSnapshot,
    ToastSnapshotKind,
    encode_frame,
    encode_hello,
    encode_snapshot,
)


def _header(frame):
    return struct.unpack_from("<IHHIQ", frame)


def test_hello_frame_has_versioned_header_and_utf8_session():
    frame = encode_hello("会话-token", 7)
    magic, version, message_type, payload_size, sequence = _header(frame)
    assert magic == PROTOCOL_MAGIC
    assert version == PROTOCOL_VERSION
    assert message_type == ToastMessageType.HELLO
    assert sequence == 7
    payload = frame[20:]
    length = struct.unpack_from("<I", payload)[0]
    assert payload[4:4 + length].decode("utf-8") == "会话-token"
    assert payload_size == len(payload)


def test_snapshot_frame_clamps_progress_and_limits_actions():
    actions = tuple(
        ToastAction(ToastActionKind.OPEN_LOG, f"log-{index}", f"C:\\logs\\{index}.txt")
        for index in range(3)
    )
    frame = encode_snapshot(
        ToastSnapshot(
            kind=ToastSnapshotKind.FAILURE,
            batch_id="batch",
            title="failed",
            progress_mode=ToastProgressMode.DETERMINATE,
            progress_value=2.0,
            actions=actions,
            ttl_ms=1234,
        ),
        9,
    )
    _, _, message_type, payload_size, sequence = _header(frame)
    payload = frame[20:]
    kind, mode, action_count, reserved, progress, ttl = struct.unpack_from("<BBBBdI", payload)
    assert message_type == ToastMessageType.SNAPSHOT
    assert payload_size == len(payload)
    assert sequence == 9
    assert kind == ToastSnapshotKind.FAILURE
    assert mode == ToastProgressMode.DETERMINATE
    assert action_count == 2
    assert reserved == 0
    assert progress == 1.0
    assert ttl == 1234


def test_protocol_rejects_frames_over_64_kib():
    with pytest.raises(ValueError, match="64 KiB"):
        encode_frame(ToastMessageType.SNAPSHOT, b"x" * MAX_FRAME_BYTES, 1)
