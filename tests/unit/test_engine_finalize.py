from __future__ import annotations

import contextlib

import pytest

import sunpack.coordinator.engine as engine_module
from sunpack.contracts.pipeline import PipelineArtifacts, PipelineResponse
from sunpack.contracts.results import RunSummary


@pytest.mark.parametrize(
    ("cleanup_mode", "flatten_enabled", "expected_roots"),
    [
        ("keep", False, ()),
        ("delete", False, ("archive.zip",)),
        ("keep", True, ("output",)),
        ("recycle", True, ("output", "archive.zip")),
    ],
)
def test_finalize_response_gates_only_paths_that_will_be_mutated(
    tmp_path,
    monkeypatch,
    cleanup_mode,
    flatten_enabled,
    expected_roots,
):
    archive = tmp_path / "archive.zip"
    output = tmp_path / "output"
    response = PipelineResponse(
        request_id="finalize-roots",
        summary=RunSummary(success_count=1, failed_tasks=[], processed_keys=[]),
        artifacts=PipelineArtifacts(
            archives_to_clean=((str(archive),),),
            flatten_targets=(str(output),),
        ),
    )
    barrier_calls: list[tuple[str, ...]] = []
    apply_calls: list[dict] = []

    @contextlib.contextmanager
    def recording_barrier(roots, **_kwargs):
        barrier_calls.append(tuple(roots))
        yield

    class RecordingActions:
        def __init__(self, *_args, **_kwargs):
            pass

        def apply(self, **kwargs):
            apply_calls.append(kwargs)

    monkeypatch.setattr(engine_module, "promotion_barrier", recording_barrier)
    monkeypatch.setattr(engine_module, "PostProcessActions", RecordingActions)
    monkeypatch.setattr(engine_module, "notify_shell_directories_updated", lambda _paths: None)

    engine_module._finalize_response(
        {
            "post_extract": {
                "archive_cleanup_mode": cleanup_mode,
                "flatten_single_directory": flatten_enabled,
            }
        },
        response,
    )

    expected = tuple(str(tmp_path / name) for name in expected_roots)
    assert barrier_calls == ([expected] if expected else [])
    assert apply_calls == [
        {
            "archives_to_clean": [[str(archive)]],
            "flatten_targets": [str(output)],
        }
    ]
