import random
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tests.helpers.tool_config import get_optional_rar, get_test_tools, require_7z


MINIMAL_JPEG_BYTES = bytes.fromhex(
    "ffd8ffe000104a46494600010100000100010000ffdb004300"
    "080606070605080707070909080a0c140d0c0b0b0c19120f13"
    "1d1a1f1e1d1a1c1c20242e2720222c231c1c2837292c303134"
    "34341f27393d38323c2e333432ffc0000b0800010001010111"
    "00ffc40014000100000000000000000000000000000008ffda"
    "0008010100003f00d2cf20ffd9"
)
MINIMAL_PNG_BYTES = bytes.fromhex(
    "89504e470d0a1a0a"
    "0000000d4948445200000001000000010802000000907753de"
    "0000000c49444154789c63f8ffff3f0005fe02fea7a6459b"
    "0000000049454e44ae426082"
)
MINIMAL_GIF_BYTES = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c"
    "000000000100010000020144003b"
)
MINIMAL_PDF_BYTES = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
)
MINIMAL_WEBP_BYTES = b"RIFF" + (16).to_bytes(4, "little") + b"WEBP" + b"VP8 " + (4).to_bytes(4, "little") + b"\0\0\0\0"
CORRUPT_TRUNCATE_BYTES = 16 * 1024
SUPPORTED_CARRIERS = {"jpg", "png", "gif", "pdf", "webp"}


@dataclass
class ArchiveCase:
    case_id: str
    archive_dir: Path
    entry_path: Path
    marker_name: str
    marker_text: str
    archive_format: str
    password: str | None = None
    split: bool = False
    sfx: bool = False
    carrier: str | None = None
    disguise_ext: str | None = None
    corruption: str | None = None
    split_issue: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __getitem__(self, key: str):
        return self.to_dict()[key]

    def __setitem__(self, key: str, value):
        if hasattr(self, key):
            setattr(self, key, value)
            return
        self.metadata[key] = value

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "archive_dir": self.archive_dir,
            "entry_path": self.entry_path,
            "marker_name": self.marker_name,
            "marker_text": self.marker_text,
            "archive_format": self.archive_format,
            "password": self.password,
            "split": self.split,
            "sfx": self.sfx,
            "carrier": self.carrier,
            "disguise_ext": self.disguise_ext,
            "corruption": self.corruption,
            "split_issue": self.split_issue,
            **self.metadata,
        }


class ArchiveFixtureFactory:
    def create(
        self,
        root: Path,
        case_id: str,
        archive_format: str = "7z",
        *,
        password: str | None = None,
        split: bool = False,
        sfx: bool = False,
        corruption: str | None = None,
        split_issue: str | None = None,
        carrier: str | None = None,
        disguise_ext: str | None = None,
        payload_size: int = 256 * 1024,
    ) -> ArchiveCase:
        if carrier and carrier not in SUPPORTED_CARRIERS:
            raise ValueError(f"Unsupported carrier: {carrier}")
        if split_issue and not split:
            raise ValueError("split_issue requires split=True")

        source_dir = root / f"{case_id}_src"
        payload = write_payload(source_dir, case_id, size_bytes=payload_size)
        archive_dir = root / case_id
        archive_dir.mkdir(parents=True, exist_ok=True)

        self._create_archive(
            source_dir,
            archive_dir,
            case_id,
            archive_format,
            password=password,
            split=split,
            sfx=sfx,
        )
        shutil.rmtree(source_dir, ignore_errors=True)

        entry_path = choose_entry_path(archive_dir, case_id, archive_format, sfx=sfx)
        case = ArchiveCase(
            case_id=case_id,
            archive_dir=archive_dir,
            entry_path=entry_path,
            marker_name=payload["marker_name"],
            marker_text=payload["marker_text"],
            archive_format=archive_format,
            password=password,
            split=split,
            sfx=sfx,
            carrier=carrier,
            disguise_ext=disguise_ext,
            corruption=corruption,
            split_issue=split_issue,
        )

        if carrier:
            case.entry_path = wrap_case_with_carrier(case, carrier)
        if disguise_ext:
            case.entry_path = disguise_case_entry(case, disguise_ext)
        if corruption:
            corrupt_file(case.entry_path, mode=corruption)
        if split_issue:
            apply_split_issue(case, split_issue)
        return case

    def _create_archive(
        self,
        source_dir: Path,
        archive_dir: Path,
        case_id: str,
        archive_format: str,
        *,
        password: str | None,
        split: bool,
        sfx: bool,
    ):
        if archive_format == "7z":
            archive_path = archive_dir / f"{case_id}{'.exe' if sfx else '.7z'}"
            create_7z_archive(source_dir, archive_path, password=password, split=split, sfx=sfx)
            return
        if archive_format == "zip":
            archive_path = archive_dir / f"{case_id}{'.exe' if sfx else '.zip'}"
            create_zip_archive(source_dir, archive_path, password=password, split=split, sfx=sfx)
            return
        if archive_format == "rar":
            archive_path = archive_dir / f"{case_id}{'.exe' if sfx else '.rar'}"
            create_rar_archive(source_dir, archive_path, password=password, split=split, sfx=sfx)
            return
        raise ValueError(f"Unsupported archive format: {archive_format}")


def run_cmd(cmd: list[str], cwd: Path):
    result = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(cmd)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def write_payload(source_dir: Path, case_id: str, size_bytes: int = 256 * 1024) -> dict[str, str]:
    source_dir.mkdir(parents=True, exist_ok=True)
    marker_name = f"{case_id}.marker.txt"
    marker_text = f"edge::{case_id}"
    (source_dir / marker_name).write_text(marker_text, encoding="utf-8")
    rng = random.Random(case_id)
    (source_dir / "payload.bin").write_bytes(bytes(rng.getrandbits(8) for _ in range(size_bytes)))
    return {"marker_name": marker_name, "marker_text": marker_text}


def create_7z_archive(source_dir: Path, output_path: Path, password: str | None = None, split: bool = False, sfx: bool = False):
    tools = get_test_tools()
    seven_zip = require_7z()
    cmd = [str(seven_zip), "a", str(output_path), str(source_dir), "-mx=0", "-y"]
    if password:
        cmd.extend([f"-p{password}", "-mhe=on"])
    if split:
        cmd.append("-v100k")
    if sfx:
        sfx_path = tools["seven_zip_sfx"]
        if not sfx_path or not sfx_path.is_file():
            raise FileNotFoundError("7z SFX module is required for SFX samples.")
        cmd.append(f"-sfx{sfx_path}")
    run_cmd(cmd, output_path.parent)


def create_zip_archive(source_dir: Path, output_path: Path, password: str | None = None, split: bool = False, sfx: bool = False):
    tools = get_test_tools()
    seven_zip = require_7z()
    cmd = [str(seven_zip), "a", str(output_path), str(source_dir), "-tzip", "-mx=0", "-y"]
    if password:
        cmd.append(f"-p{password}")
    if split:
        cmd.append("-v100k")
    if sfx:
        sfx_path = tools["seven_zip_sfx"]
        if not sfx_path or not sfx_path.is_file():
            raise FileNotFoundError("7z SFX module is required for ZIP SFX samples.")
        cmd.append(f"-sfx{sfx_path}")
    run_cmd(cmd, output_path.parent)


def create_rar_archive(source_dir: Path, output_path: Path, password: str | None = None, split: bool = False, sfx: bool = False):
    rar = get_optional_rar()
    if not rar:
        raise FileNotFoundError("RAR generator is not configured.")
    cmd = [str(rar), "a", "-ep1", "-r", "-idq", "-m0", "-ma5", "-y"]
    if password:
        cmd.append(f"-hp{password}")
    if split:
        cmd.append("-v100k")
    if sfx:
        cmd.append("-sfx")
    cmd.extend([str(output_path), str(source_dir)])
    run_cmd(cmd, output_path.parent)


def build_archive_case(
    root: Path,
    case_id: str,
    archive_format: str,
    password: str | None = None,
    split: bool = False,
    sfx: bool = False,
) -> dict:
    return ArchiveFixtureFactory().create(
        root,
        case_id,
        archive_format,
        password=password,
        split=split,
        sfx=sfx,
    ).to_dict()


def choose_entry_path(archive_dir: Path, case_id: str, archive_format: str, sfx: bool = False) -> Path:
    files = sorted(path for path in archive_dir.iterdir() if path.is_file())
    if not files:
        raise RuntimeError(f"No generated files for {case_id}")
    if archive_format == "rar":
        for path in files:
            lower = path.name.lower()
            if sfx and ".part1.exe" in lower:
                return path
            if ".part1.rar" in lower or lower.endswith(".rar"):
                return path
    if sfx:
        return archive_dir / f"{case_id}.exe"
    for path in files:
        lower = path.name.lower()
        if lower.endswith(".001") or lower.endswith(f".{archive_format}"):
            return path
    return files[0]


def corrupt_file(path: Path, truncate: bool = False, mode: str | None = None):
    raw = bytearray(path.read_bytes())
    effective_mode = mode or ("truncate" if truncate else "byte_flip")
    if effective_mode == "truncate":
        if len(raw) <= CORRUPT_TRUNCATE_BYTES:
            raise RuntimeError(f"File too small to truncate safely: {path}")
        path.write_bytes(raw[:-CORRUPT_TRUNCATE_BYTES])
        return
    if effective_mode == "header_damage":
        if len(raw) < 32:
            raw.extend(b"x" * (32 - len(raw)))
        raw[:16] = b"\0" * 16
        path.write_bytes(raw)
        return
    if effective_mode == "tail_damage":
        if len(raw) < 32:
            raw.extend(b"x" * (32 - len(raw)))
        raw[-16:] = b"\0" * 16
        path.write_bytes(raw)
        return
    if effective_mode != "byte_flip":
        raise ValueError(f"Unsupported corruption mode: {effective_mode}")
    if len(raw) < 128:
        raw.extend(b"x" * (128 - len(raw)))
    start = min(64, max(0, len(raw) - 32))
    raw[start : start + 16] = b"\0" * 16
    path.write_bytes(raw)


def remove_last_split_part(archive_dir: Path):
    files = sorted(path for path in archive_dir.iterdir() if path.is_file())
    if len(files) < 2:
        raise RuntimeError("Split archive did not generate multiple parts.")
    files[-1].unlink()


def corrupt_split_member(archive_dir: Path):
    parts = sorted(path for path in archive_dir.iterdir() if path.is_file())
    if len(parts) < 2:
        raise RuntimeError("Split archive did not generate multiple parts.")
    corrupt_file(parts[min(1, len(parts) - 1)], mode="byte_flip")


def apply_split_issue(case: ArchiveCase, issue: str):
    if issue == "missing_last":
        remove_last_split_part(case.archive_dir)
        return
    if issue == "corrupt_member":
        corrupt_split_member(case.archive_dir)
        return
    raise ValueError(f"Unsupported split issue: {issue}")


def disguise_case_entry(case: ArchiveCase, suffix_or_ext: str) -> Path:
    if suffix_or_ext.startswith("."):
        new_path = case.entry_path.with_name(f"{case.entry_path.name}{suffix_or_ext}")
    else:
        new_path = case.entry_path.with_name(f"{case.entry_path.name}.{suffix_or_ext}")
    case.entry_path.rename(new_path)
    return new_path


def wrap_case_with_carrier(case: ArchiveCase, carrier: str) -> Path:
    carrier_path = case.archive_dir / f"{case.case_id}.{carrier}"
    wrap_with_carrier_prefix(case.entry_path, carrier_path, carrier)
    case.entry_path.unlink()
    return carrier_path


def wrap_with_carrier_prefix(source_archive: Path, carrier_path: Path, carrier: str):
    prefixes = {
        "jpg": MINIMAL_JPEG_BYTES,
        "png": MINIMAL_PNG_BYTES,
        "gif": MINIMAL_GIF_BYTES,
        "pdf": MINIMAL_PDF_BYTES,
        "webp": MINIMAL_WEBP_BYTES,
    }
    carrier_path.write_bytes(prefixes[carrier] + source_archive.read_bytes())
