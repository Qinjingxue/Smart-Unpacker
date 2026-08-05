from __future__ import annotations

import uuid
from types import SimpleNamespace

from sunpack.contracts.pipeline import PipelineArtifacts, PipelineResponse


class FakePipelineEngine:
    """Synchronous Engine test double backed by a lightweight runner factory."""

    def __init__(self, runner_factory):
        self.runner_factory = runner_factory
        self.user_passwords = []
        self.builtin_passwords = []
        self._recent_passwords = []

    def start(self):
        return self

    def close(self, *, graceful=True):
        return None

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc, traceback):
        self.close()

    @property
    def recent_passwords(self):
        return list(self._recent_passwords)

    def update_password_sources(self, *, user_passwords, builtin_passwords):
        self.user_passwords = list(user_passwords)
        self.builtin_passwords = list(builtin_passwords)

    def submit(self, targets, *, direct=False, defer_postprocess=False):
        paths = [target.path if hasattr(target, "path") else str(target) for target in targets]
        output = dict(targets[0].output) if targets and hasattr(targets[0], "output") else {}
        config = {
            "output": output,
            "user_passwords": list(self.user_passwords),
            "builtin_passwords": list(self.builtin_passwords),
        }
        runner = self.runner_factory(config)
        summary = runner.run_targets(paths)
        self._recent_passwords = list(getattr(runner, "recent_passwords", ()) or ())
        context = getattr(runner, "context", SimpleNamespace(flatten_candidates=(), unpacked_archives=()))
        recovered_outputs = getattr(context, "recovered_outputs", ()) or ()
        generated_outputs = [
            str(item.get("out_dir") or "")
            for item in recovered_outputs
            if isinstance(item, dict) and item.get("out_dir")
        ]
        response = PipelineResponse(
            request_id=uuid.uuid4().hex,
            summary=summary,
            artifacts=PipelineArtifacts(
                archives_to_clean=tuple(tuple(parts) for parts in getattr(context, "unpacked_archives", ()) or ()),
                flatten_targets=tuple([*(getattr(context, "flatten_candidates", ()) or ()), *generated_outputs]),
            ),
            recent_passwords=tuple(self._recent_passwords),
        )
        return _FakeHandle(runner, response)


class _FakeHandle:
    def __init__(self, runner, response):
        self.runner = runner
        self.response = response

    def result(self, timeout=None):
        return self.response

    def done(self):
        return True

    def add_done_callback(self, callback):
        callback(self)

    def finalize(self, output_path_map=None):
        callback = getattr(self.runner, "apply_deferred_postprocess", None)
        if callable(callback):
            callback(dict(output_path_map or {}))
        return self.response
