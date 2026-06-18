from types import SimpleNamespace

from sunpack.coordinator.runner import PipelineRunner


def test_direct_file_mode_feeds_nested_roots_back_into_recursion(tmp_path):
    runner = PipelineRunner.__new__(PipelineRunner)
    runner.language = "en"
    runner.context = SimpleNamespace(
        success_count=2,
        failed_tasks=[],
        processed_keys={"outer", "inner"},
        partial_success_count=0,
        recovered_outputs=[],
    )
    runner.space_guard = SimpleNamespace(bind_root=lambda _root: None, disk_monitor=None)
    runner.disk_monitor = None
    runner.recursion = SimpleNamespace(
        mode="fixed",
        should_continue=lambda round_index, has_new: round_index < 2 and has_new,
    )
    runner.logger = SimpleNamespace(log_final_summary=lambda *args, **kwargs: None)
    runner.extractor = SimpleNamespace(close=lambda: None)
    runner._direct_file_tasks = lambda paths: ["outer-task"]
    runner._scan_targets = lambda roots: ["inner-task"] if roots == ["nested-root"] else []
    executed = []

    def execute(tasks):
        executed.append(list(tasks))
        return ["nested-root"] if tasks == ["outer-task"] else []

    runner._execute_tasks = execute
    runner._apply_postprocess_actions = lambda: None

    summary = runner.run_direct_files([str(tmp_path / "outer.zip")])

    assert executed == [["outer-task"], ["inner-task"]]
    assert summary.success_count == 2
