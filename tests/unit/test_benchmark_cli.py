from __future__ import annotations

from benchmarks import cli


def test_clean_removes_only_selected_regenerable_roots(tmp_path, monkeypatch) -> None:
    cache = tmp_path / ".cache"
    work = tmp_path / ".work"
    results = tmp_path / "results"
    cache.mkdir()
    work.mkdir()
    results.mkdir()
    (cache / "cached.bin").write_text("cache", encoding="utf-8")
    (work / "workspace.bin").write_text("work", encoding="utf-8")
    (results / "report.json").write_text("report", encoding="utf-8")
    monkeypatch.setattr(cli, "BENCHMARK_CACHE_ROOT", cache)
    monkeypatch.setattr(cli, "BENCHMARK_WORK_ROOT", work)

    assert cli.main(["clean", "--cache", "--work"]) == 0

    assert not cache.exists()
    assert not work.exists()
    assert (results / "report.json").read_text(encoding="utf-8") == "report"


def test_clean_requires_an_explicit_target() -> None:
    try:
        cli.main(["clean"])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("clean without a target must fail")


def test_watch_scenario_runs_in_a_subprocess(monkeypatch) -> None:
    observed: dict[str, object] = {}

    def fake_run(module: str, arguments: list[str], timeout: float) -> int:
        observed["module"] = module
        observed["arguments"] = arguments
        observed["timeout"] = timeout
        return 17

    monkeypatch.setattr(cli, "_run_scenario_in_subprocess", fake_run)

    assert cli.main(["--timeout", "12", "watch", "real-file", "--runs", "2"]) == 17
    assert observed == {
        "module": "benchmarks.scenarios.watch_real_file",
        "arguments": ["--runs", "2"],
        "timeout": 12.0,
    }
