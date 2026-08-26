from __future__ import annotations

import pytest


@pytest.fixture(scope="session", autouse=True)
def installed_watch_broker_lease():
    from sunpack_native import watch_broker_acquire, watch_broker_release

    watch_broker_acquire()
    try:
        yield
    finally:
        watch_broker_release()
