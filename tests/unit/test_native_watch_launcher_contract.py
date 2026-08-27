from __future__ import annotations

from pathlib import Path


def test_native_launcher_routes_watch_start_through_the_shared_runtime_pipe():
    source = (Path(__file__).resolve().parents[2] / "native" / "sevenzip_bridge" / "src" / "launcher.cpp").read_text(
        encoding="utf-8"
    )

    assert source.count('L"\\\\sunpack-runtime.exe"') == 2
    assert "runtime_binary_stamp" in source
    assert '--_sunpack-mode=watch' not in source
    assert "sunpack-watch.exe" not in source
    assert "request(context, request_arguments, shutdown, code, invocation_cwd)" in source
    assert "--_sunpack-runtime-id=" in source


def test_native_launcher_has_one_runtime_lifecycle_for_cli_and_watch():
    source = (Path(__file__).resolve().parents[2] / "native" / "sevenzip_bridge" / "src" / "launcher.cpp").read_text(
        encoding="utf-8"
    )

    assert 'spawn_runtime(context, {L"--persistent-server"}, true' in source
    assert "spawn_watch" not in source
    assert "request(context, request_arguments, shutdown, code, invocation_cwd)" in source


def test_native_launcher_forwards_watch_add_start_atomically():
    source = (Path(__file__).resolve().parents[2] / "native" / "sevenzip_bridge" / "src" / "launcher.cpp").read_text(
        encoding="utf-8"
    )

    assert "request(context, request_arguments, shutdown, code, invocation_cwd)" in source
    assert "spawn_watch" not in source


def test_native_launcher_has_one_install_identity_context():
    source = (Path(__file__).resolve().parents[2] / "native" / "sevenzip_bridge" / "src" / "launcher.cpp").read_text(
        encoding="utf-8"
    )

    assert "struct InstallContext" in source
    assert "GetFinalPathNameByHandleW" not in source
    assert "normalized_final_path" not in source
    assert "const InstallContext context = install_context();" in source
    assert "state_path(const InstallContext& context)" in source
    assert "std::wstring state_path()" not in source


def test_native_launcher_uses_named_pipes_for_all_short_commands():
    root = Path(__file__).resolve().parents[2]
    source = (root / "native" / "sevenzip_bridge" / "src" / "launcher.cpp").read_text(encoding="utf-8")
    cmake = (root / "native" / "sevenzip_bridge" / "CMakeLists.txt").read_text(encoding="utf-8")

    assert "CreateFileW(pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE" in source
    assert "WaitNamedPipeW" in source
    assert "WSAStartup" not in source
    assert "Ws2_32" not in cmake


def test_native_launcher_detects_runtime_exit_before_pipe_ready():
    source = (Path(__file__).resolve().parents[2] / "native" / "sevenzip_bridge" / "src" / "launcher.cpp").read_text(
        encoding="utf-8"
    )

    assert "runtime_failed = true;" in source
    assert "WaitForSingleObject(runtime_process, 0)" in source
