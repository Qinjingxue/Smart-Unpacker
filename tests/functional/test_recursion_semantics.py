from smart_unpacker.coordinator.runner import PipelineRunner
from tests.helpers.detection_config import with_detection_pipeline


def _config(recursive_extract):
    return with_detection_pipeline({
        "recursive_extract": recursive_extract,
        "post_extract": {
            "archive_cleanup_mode": "keep",
            "flatten_single_directory": False,
        },
    })


def test_non_prompt_recursion_applies_postprocess_once_after_all_rounds(tmp_path, monkeypatch):
    runner = PipelineRunner(_config({"mode": "fixed", "max_rounds": 2}))
    calls = []

    monkeypatch.setattr(runner, "_scan_targets", lambda roots: list(roots))

    def fake_execute(tasks):
        calls.append(("execute", list(tasks)))
        if len(calls) == 1:
            return [str(tmp_path / "nested")]
        return []

    monkeypatch.setattr(runner, "_execute_tasks", fake_execute)
    monkeypatch.setattr(runner, "_apply_postprocess_actions", lambda: calls.append(("postprocess", [])))
    monkeypatch.setattr(runner.logger, "log_final_summary", lambda *args, **kwargs: None)

    runner.run_targets([str(tmp_path)])

    assert calls == [
        ("execute", [str(tmp_path)]),
        ("execute", [str(tmp_path / "nested")]),
        ("postprocess", []),
    ]


def test_prompt_recursion_applies_postprocess_before_prompt_each_round(tmp_path, monkeypatch):
    runner = PipelineRunner(_config({"mode": "prompt", "max_rounds": 999}))
    calls = []

    monkeypatch.setattr(runner, "_scan_targets", lambda roots: list(roots))
    monkeypatch.setattr(runner, "_execute_tasks", lambda tasks: calls.append(("execute", list(tasks))) or [str(tmp_path / "nested")])
    monkeypatch.setattr(runner, "_apply_postprocess_actions", lambda: calls.append(("postprocess", [])))

    def fake_prompt(round_index):
        calls.append(("prompt", [round_index]))
        return False

    monkeypatch.setattr(runner.recursion, "prompt_continue", fake_prompt)
    monkeypatch.setattr(runner.logger, "log_final_summary", lambda *args, **kwargs: None)

    runner.run_targets([str(tmp_path)])

    assert calls == [
        ("execute", [str(tmp_path)]),
        ("postprocess", []),
        ("prompt", [1]),
    ]
