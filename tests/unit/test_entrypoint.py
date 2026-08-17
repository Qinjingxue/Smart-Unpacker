import sunpack.entrypoint as entrypoint
import sunpack.gui.main as gui_main
import sunpack.support.resources as resources


def test_nuitka_watch_executable_uses_gui_entrypoint(monkeypatch):
    monkeypatch.setattr(entrypoint.sys, "executable", r"C:\\Python310\\python.exe")
    monkeypatch.setattr(entrypoint.sys, "argv", [r"C:\\package\\sunpack-watch.exe"])
    monkeypatch.setattr(gui_main, "main", lambda: 17)

    assert entrypoint.main() == 17


def test_pyinstaller_watch_executable_uses_gui_entrypoint(monkeypatch):
    monkeypatch.setattr(entrypoint.sys, "executable", r"C:\\package\\sunpack-watch.exe")
    monkeypatch.setattr(entrypoint.sys, "argv", [r"C:\\package\\sunpack-runtime.exe"])
    monkeypatch.setattr(gui_main, "main", lambda: 23)

    assert entrypoint.main() == 23


def test_nuitka_resource_lookup_starts_at_the_executable_directory(tmp_path, monkeypatch):
    executable = tmp_path / "sunpack-runtime.exe"
    monkeypatch.setattr(resources.sys, "executable", str(executable))
    monkeypatch.setattr(resources, "__compiled__", object(), raising=False)

    assert executable.parent.resolve() == resources.candidate_resource_roots()[0]
