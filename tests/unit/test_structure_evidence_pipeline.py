import zipfile

from sunpack.contracts.detection import FactBag
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.modules.format_structure import structure_evidence


def _context(path, magic: bytes) -> FactProcessorContext:
    bag = FactBag()
    bag.set("file.path", str(path))
    bag.set("file.magic_bytes", magic)
    bag.set("candidate.entry_path", str(path))
    bag.set("candidate.member_paths", [str(path)])
    return FactProcessorContext(
        fact_bag=bag,
        output_fact="analysis.structure_evidence",
        config={},
        fact_config={},
    )


def test_known_media_magic_skips_structure_scheduler(tmp_path, monkeypatch):
    media = tmp_path / "sound.ogg"
    media.write_bytes(b"OggS" + b"x" * 4096)

    def fail_if_constructed(*_args, **_kwargs):
        raise AssertionError("structure scheduler must not run for known media")

    monkeypatch.setattr(structure_evidence, "ArchiveAnalysisScheduler", fail_if_constructed)

    result = structure_evidence.process_structure_evidence(_context(media, b"OggS"))

    assert result["analyzed"] is False
    assert result["read_bytes"] == 0


def test_disguised_zip_uses_detection_structure_processor(tmp_path):
    archive = tmp_path / "payload.unrelated"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("payload.txt", "payload")

    result = structure_evidence.process_structure_evidence(
        _context(archive, archive.read_bytes()[:16])
    )

    assert result["analyzed"] is True
    assert result["has_extractable"] is True
    assert result["selected"]["format"] == "zip"
    assert result["read_bytes"] > 0
