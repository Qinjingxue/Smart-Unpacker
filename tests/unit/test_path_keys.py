import os

from packrelic.support.path_keys import absolute_path_key, normalized_path, path_key, safe_relative_path


def test_path_key_matches_normcase_normpath():
    raw = os.path.join("SomeDir", ".", "Archive.zip")

    assert normalized_path(raw) == os.path.normpath(raw)
    assert path_key(raw) == os.path.normcase(os.path.normpath(raw))


def test_absolute_path_key_matches_normcase_abspath(tmp_path):
    path = tmp_path / "child" / ".." / "archive.zip"

    assert absolute_path_key(path) == os.path.normcase(os.path.abspath(str(path)))


def test_safe_relative_path_preserves_existing_target_scan_semantics(tmp_path):
    root = tmp_path / "root"
    child = root / "nested" / "archive.zip"
    outside = tmp_path / "other" / "archive.zip"
    root.mkdir()
    child.parent.mkdir()
    outside.parent.mkdir()

    assert safe_relative_path(str(child), str(root)) == os.path.relpath(os.path.normpath(child), os.path.normpath(root))
    assert safe_relative_path(str(root), str(root)) is None
    assert safe_relative_path(str(outside), str(root)) is None
