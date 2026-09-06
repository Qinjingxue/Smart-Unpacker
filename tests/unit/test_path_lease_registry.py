import asyncio

from sunpack.coordinator.engine import _PathLeaseRegistry


def test_conflicting_path_lease_is_woken_by_release(tmp_path):
    async def scenario() -> None:
        registry = _PathLeaseRegistry()
        path = tmp_path / "shared.zip"
        await registry.acquire("first", (path,))

        waiting = asyncio.create_task(registry.acquire("second", (path,)))
        await asyncio.sleep(0)
        assert not waiting.done()

        await registry.release("first")
        await asyncio.wait_for(waiting, timeout=0.1)
        assert registry._owned == {"second": {str(path)}}

    asyncio.run(scenario())


def test_replacing_path_lease_notifies_waiters_for_released_paths(tmp_path):
    async def scenario() -> None:
        registry = _PathLeaseRegistry()
        first_path = tmp_path / "first.zip"
        second_path = tmp_path / "second.zip"
        await registry.acquire("first", (first_path,))

        waiting = asyncio.create_task(registry.acquire("second", (first_path,)))
        await asyncio.sleep(0)
        assert not waiting.done()

        await registry.replace("first", (second_path,))
        await asyncio.wait_for(waiting, timeout=0.1)
        assert registry._owned == {
            "first": {str(second_path)},
            "second": {str(first_path)},
        }

    asyncio.run(scenario())
