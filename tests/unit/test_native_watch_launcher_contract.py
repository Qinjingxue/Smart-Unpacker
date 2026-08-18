from __future__ import annotations

from pathlib import Path


def test_native_launcher_routes_watch_start_directly_to_watch_executable():
    source = (Path(__file__).resolve().parents[2] / "native" / "sevenzip_bridge" / "src" / "launcher.cpp").read_text(
        encoding="utf-8"
    )

    assert 'L"\\\\sunpack-watch.exe"' in source
    assert 'wcscmp(argv[1], L"watch") == 0' in source
    assert 'wcscmp(argv[2], L"start") == 0' in source
    assert "spawn_watch(watch_arguments, !once" in source
    assert "CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS" in source


def test_native_launcher_starts_watch_only_after_watch_add_succeeds():
    source = (Path(__file__).resolve().parents[2] / "native" / "sevenzip_bridge" / "src" / "launcher.cpp").read_text(
        encoding="utf-8"
    )

    assert 'wcscmp(argv[2], L"add") == 0' in source
    assert 'wcscmp(argv[index], L"--start") == 0' in source
    assert "request(request_arguments, shutdown, code, invocation_cwd)" in source
    assert "if (ok && code == 0 && start_after_add && !spawn_watch" in source
    assert "spawn_watch({}, true, nullptr, launcher_cwd)" in source
    assert "spawn_runtime(forwarded, false, &code, invocation_cwd)" not in source


def test_native_launcher_uses_named_pipes_for_all_short_commands():
    root = Path(__file__).resolve().parents[2]
    source = (root / "native" / "sevenzip_bridge" / "src" / "launcher.cpp").read_text(encoding="utf-8")
    cmake = (root / "native" / "sevenzip_bridge" / "CMakeLists.txt").read_text(encoding="utf-8")

    assert "CreateFileW(pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE" in source
    assert "WaitNamedPipeW" in source
    assert "WSAStartup" not in source
    assert "Ws2_32" not in cmake


def test_native_launcher_reports_any_runtime_exit_before_pipe_ready():
    source = (Path(__file__).resolve().parents[2] / "native" / "sevenzip_bridge" / "src" / "launcher.cpp").read_text(
        encoding="utf-8"
    )

    assert "runtime_failed = true;" in source
    assert "SunPack runtime exited before becoming ready, exit code " in source
