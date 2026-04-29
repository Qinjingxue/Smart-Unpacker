from pathlib import Path

from sunpack.support import resources
from sunpack.support import sevenzip_native


def test_arm64_tool_dir_candidates_prefer_arm64(monkeypatch):
    monkeypatch.setattr(resources.platform, "machine", lambda: "ARM64")

    assert resources.tool_dir_candidates() == (Path("tools-arm64"), Path("tools"))


def test_native_wrapper_path_uses_arch_specific_tool_dir(tmp_path, monkeypatch):
    wrapper = tmp_path / "tools-arm64" / "sevenzip_password_tester_capi.dll"
    wrapper.parent.mkdir()
    wrapper.write_bytes(b"placeholder")

    monkeypatch.setattr(resources.platform, "machine", lambda: "ARM64")
    monkeypatch.setattr(sevenzip_native, "candidate_resource_roots", lambda: [tmp_path])

    tester = sevenzip_native.NativePasswordTester.__new__(sevenzip_native.NativePasswordTester)

    assert tester._default_wrapper_path() == str(wrapper)
