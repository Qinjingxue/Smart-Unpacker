import sunpack.support.entrypoint as entrypoint
import sunpack.gui.main as gui_main
import sunpack.support.resources as resources
from sunpack.support import runtime_identity


def test_nuitka_watch_executable_uses_gui_entrypoint(monkeypatch):
    monkeypatch.setattr(entrypoint.sys, "executable", r"C:\\Python310\\python.exe")
    monkeypatch.setattr(entrypoint.sys, "argv", [r"C:\\package\\sunpack-watch.exe"])
    monkeypatch.setattr(gui_main, "main", lambda: 17)

    assert entrypoint.main() == 17


def test_entrypoint_consumes_private_runtime_identity_before_gui(monkeypatch):
    monkeypatch.setattr(entrypoint.sys, "executable", r"C:\\Python310\\python.exe")
    monkeypatch.setattr(
        entrypoint.sys,
        "argv",
        [r"C:\\package\\sunpack-watch.exe", "--_sunpack-runtime-id=v2-0123456789abcdef", "--once"],
    )

    def fake_main():
        assert entrypoint.sys.argv[1:] == ["--once"]
        assert runtime_identity.runtime_id() == "v2-0123456789abcdef"
        return 19

    monkeypatch.setattr(gui_main, "main", fake_main)

    assert entrypoint.main() == 19


def test_frozen_watch_executable_uses_gui_entrypoint(monkeypatch):
    monkeypatch.setattr(entrypoint.sys, "executable", r"C:\\package\\sunpack-watch.exe")
    monkeypatch.setattr(entrypoint.sys, "argv", [r"C:\\package\\sunpack-runtime.exe"])
    monkeypatch.setattr(gui_main, "main", lambda: 23)

    assert entrypoint.main() == 23


def test_nuitka_resource_lookup_starts_at_the_executable_directory(tmp_path, monkeypatch):
    executable = tmp_path / "sunpack-runtime.exe"
    monkeypatch.setattr(resources.sys, "executable", str(executable))
    monkeypatch.setattr(resources, "__compiled__", object(), raising=False)

    assert executable.parent.resolve() == resources.candidate_resource_roots()[0]
