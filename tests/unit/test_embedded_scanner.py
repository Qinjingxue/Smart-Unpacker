import time
from concurrent.futures import ThreadPoolExecutor

from sunpack.analysis import scan_embedded_archives
from sunpack.support.global_cache_manager import clear_cache_namespace


def test_shared_embedded_scanner_is_single_flight_per_file_identity(monkeypatch):
    calls = 0

    class Session:
        def scan_embedded_archives(self):
            nonlocal calls
            calls += 1
            time.sleep(0.03)
            return {
                "complete": True,
                "candidates": [{
                    "format": "zip",
                    "detected_ext": ".zip",
                    "offset": 128,
                    "end_offset": 512,
                    "confidence": 0.99,
                    "validation": "zip_structure",
                }],
                "hits": [{"name": "zip_local", "offset": 128}],
                "read_bytes": 1024,
                "file_size": 1024,
            }

    clear_cache_namespace("embedded_archive_scan_v1")
    monkeypatch.setattr("sunpack.analysis.embedded.scanner.get_archive_session", lambda path: Session())
    identity = ("same-file", 1024, 1)
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(
            lambda _: scan_embedded_archives("same-file", expected_size=1024, identity=identity),
            range(8),
        ))

    assert calls == 1
    assert all(result.candidates[0].offset == 128 for result in results)
