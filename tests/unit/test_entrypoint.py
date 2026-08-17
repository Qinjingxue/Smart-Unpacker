import sunpack.entrypoint as entrypoint
import sunpack.gui.main as gui_main
import sunpack.support.resources as resources


def test_nuitka_watch_executable_uses_gui_entrypoint(monkeypatch):
    monkeypatch.setattr(entrypoint.sys, "executable", r"C:\\package\\sunpack-watch.exe")
    monkeypatch.setattr(entrypoint, "__compiled__", object(), raising=False)
    monkeypatch.setattr(gui_main, "main", lambda: 17)

    assert entrypoint.main() == 17


def test_nuitka_resource_lookup_starts_at_the_executable_directory(tmp_path, monkeypatch):
    executable = tmp_path / "sunpack-runtime.exe"
    monkeypatch.setattr(resources.sys, "executable", str(executable))
    monkeypatch.setattr(resources, "__compiled__", object(), raising=False)

    assert executable.parent.resolve() == resources.candidate_resource_roots()[0]
