from pathlib import Path
from types import SimpleNamespace

from smart_unpacker.rename.internal.volume_normalizer import SplitVolumeNormalizer
from smart_unpacker.relations.internal.group_builder import RelationsGroupBuilder


class FakeNativeTester:
    def __init__(self, ok: bool):
        self.ok = ok

    def test_archive(self, archive: str, part_paths=None):
        return SimpleNamespace(ok=self.ok)


def _stager_with_candidates(*, test_ok: bool) -> SplitVolumeNormalizer:
    stager = SplitVolumeNormalizer.__new__(SplitVolumeNormalizer)
    stager._relations = RelationsGroupBuilder()
    stager._native_tester = FakeNativeTester(test_ok)
    return stager


def _volumes(first: Path, candidate: Path) -> list[dict]:
    return [
        {
            "path": str(first),
            "number": 1,
            "role": "first",
            "source": "standard",
            "style": "numeric_suffix",
            "prefix": str(first).removesuffix(".001"),
            "width": 3,
        },
        {
            "path": str(candidate),
            "number": 2,
            "role": "member",
            "source": "candidate",
            "style": "numeric_suffix",
            "prefix": str(first).removesuffix(".001"),
            "width": 3,
        },
    ]


def test_unverified_misnamed_candidates_are_not_cleanup_parts(tmp_path):
    first = tmp_path / "bundle.7z.001"
    candidate = tmp_path / "bundle"
    first.write_bytes(b"first")
    candidate.write_bytes(b"candidate")

    staged = _stager_with_candidates(test_ok=False).normalize(
        str(first),
        [str(first)],
        volume_entries=_volumes(first, candidate),
    )

    assert staged.archive == str(first)
    assert staged.run_parts == [str(first)]
    assert staged.cleanup_parts == [str(first)]
    assert staged.candidate_parts == [str(candidate)]
    assert staged.verified_candidates is False


def test_verified_misnamed_candidates_become_cleanup_parts(tmp_path):
    first = tmp_path / "bundle.7z.001"
    candidate = tmp_path / "bundle"
    first.write_bytes(b"first")
    candidate.write_bytes(b"candidate")

    stager = _stager_with_candidates(test_ok=True)
    staged = stager.normalize(str(first), [str(first)], volume_entries=_volumes(first, candidate))

    assert Path(staged.archive).name == "bundle.7z.001"
    assert staged.archive != str(first)
    assert [Path(path).name for path in staged.run_parts] == ["bundle.7z.001", "bundle.7z.002"]
    assert staged.cleanup_parts == [str(first), str(candidate)]
    assert staged.candidate_parts == [str(candidate)]
    assert staged.verified_candidates is True

    temp_dir = staged.temp_dir
    assert temp_dir
    stager.cleanup(staged)
    assert not Path(temp_dir).exists()
