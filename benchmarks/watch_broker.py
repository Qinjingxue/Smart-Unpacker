from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SERVICE_ENV = "SUNPACK_WATCH_BROKER_SERVICE_NAME"
PIPE_ENV = "SUNPACK_WATCH_BROKER_PIPE_NAME"
BINARY_ENV = "SUNPACK_WATCH_BROKER_BINARY_PATH"
HASH_ENV = "SUNPACK_WATCH_BROKER_BINARY_SHA256"
TEST_SERVICE_PREFIX = "SunPackWatchBrokerTest_"
TEST_PIPE_PREFIX = r"\\.\pipe\SunPack.WatchBroker.Test."


def isolated_broker_environment() -> bool:
    return (
        os.environ.get(SERVICE_ENV, "").startswith(TEST_SERVICE_PREFIX)
        and os.environ.get(PIPE_ENV, "").startswith(TEST_PIPE_PREFIX)
    )


def _binary_sha256(path: str) -> str:
    declared = os.environ.get(HASH_ENV, "").strip().lower()
    if declared:
        return declared
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@contextmanager
def watch_broker_lease() -> Iterator[dict[str, object]]:
    if not isolated_broker_environment():
        raise RuntimeError(
            "watch benchmarks require the isolated Broker launcher; "
            "run them with `python -m benchmarks watch <scenario>`"
        )
    from sunpack_native import (
        watch_broker_acquire,
        watch_broker_is_connected,
        watch_broker_release,
    )

    watch_broker_acquire()
    try:
        connected = bool(watch_broker_is_connected())
        if not connected:
            raise RuntimeError("isolated Watch Broker did not connect")
        binary_path = os.environ.get(BINARY_ENV, "")
        yield {
            "service_name": os.environ[SERVICE_ENV],
            "pipe_name": os.environ[PIPE_ENV],
            "binary_path": binary_path,
            "binary_sha256": _binary_sha256(binary_path) if binary_path else "",
            "connected": connected,
        }
    finally:
        watch_broker_release()
