import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from smart_unpacker import DecompressionEngine

SEVEN_Z = next(
    (path for path in (REPO_ROOT / "tools" / "7z.exe", REPO_ROOT / "tools" / "7zip" / "7z.exe") if path.is_file()),
    REPO_ROOT / "tools" / "7z.exe",
)
SEVEN_Z_SFX = next(
    (path for path in (REPO_ROOT / "tools" / "7zCon.sfx", REPO_ROOT / "tools" / "7zip" / "7zCon.sfx") if path.is_file()),
    REPO_ROOT / "tools" / "7zCon.sfx",
)
RAR_EXE = Path(r"C:\portable\winrar\Rar.exe")

VOLUME_SIZE = "1m"
PAYLOAD_BYTES = 2 * 1024 * 1024 + 333 * 1024
CORRUPT_TRUNCATE_BYTES = 8192
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
MINIMAL_PDF_BYTES = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
    b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>\nendobj\n"
    b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
)
MINIMAL_GIF_BYTES = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c"
    "000000000100010000020144003b"
)

PASSWORD_123 = "123"
PASSWORD_456 = "456"
PASSWORD_789 = "789"

EXPECTED_SUCCESS = "success"
EXPECTED_PASSWORD = "密码错误"
EXPECTED_CORRUPTED = "压缩包损坏"
EXPECTED_MISSING_SPLIT = "分卷缺失或不完整"
EXPECTED_FATAL = "致命错误 (文件损坏或格式不支持)"

PASSWORD_SCENARIOS = [
    {"id": "no_password", "label": "不输入密码", "passwords": []},
    {"id": "pwd_123", "label": "输入密码123", "passwords": [PASSWORD_123]},
    {"id": "pwd_456", "label": "输入密码456", "passwords": [PASSWORD_456]},
    {"id": "pwd_789", "label": "输入密码789", "passwords": [PASSWORD_789]},
    {"id": "pwd_123_456_789", "label": "输入密码123、456、789", "passwords": [PASSWORD_123, PASSWORD_456, PASSWORD_789]},
]


def load_engine_class():
    return DecompressionEngine


def run_cmd(cmd, cwd):
    result = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(map(str, cmd))}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def ensure_prerequisites():
    missing = [str(path) for path in (SEVEN_Z, SEVEN_Z_SFX, RAR_EXE) if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"Missing required files: {missing}")


def write_payload(source_dir: Path, case_id: str):
    source_dir.mkdir(parents=True, exist_ok=True)
    marker_name = f"{case_id}.marker.txt"
    marker_text = f"acceptance::{case_id}"
    (source_dir / marker_name).write_text(marker_text, encoding="utf-8")
    (source_dir / "notes.txt").write_text(f"case={case_id}\n", encoding="utf-8")
    rng = random.Random(case_id)
    data = bytearray(rng.getrandbits(8) for _ in range(PAYLOAD_BYTES))
    (source_dir / "payload.bin").write_bytes(data)
    return {"marker_name": marker_name, "marker_text": marker_text}


def append_fake_suffix(path: Path, suffix_seed: str):
    fake_suffix = f".mix{abs(hash((path.name, suffix_seed))) % 100000:05d}"
    new_path = path.with_name(path.name + fake_suffix)
    path.rename(new_path)
    return new_path


def list_split_parts(base_dir: Path, prefix: str):
    return sorted(path for path in base_dir.glob(f"{prefix}*") if path.is_file())


def corrupt_file(path: Path, truncate=False, offset=4096, patch_size=4096):
    raw = bytearray(path.read_bytes())
    if truncate:
        if len(raw) <= CORRUPT_TRUNCATE_BYTES:
            raise RuntimeError(f"File too small to truncate safely: {path}")
        path.write_bytes(raw[:-CORRUPT_TRUNCATE_BYTES])
        return
    if len(raw) <= offset + patch_size:
        raise RuntimeError(f"File too small to patch safely: {path}")
    raw[offset : offset + patch_size] = b"\x00" * patch_size
    path.write_bytes(raw)


def create_7z_archive(source_dir: Path, output_path: Path, password=None, split=False, sfx=False):
    cmd = [str(SEVEN_Z), "a", str(output_path), str(source_dir), "-y"]
    if password:
        cmd.extend([f"-p{password}", "-mhe=on"])
    if split:
        cmd.append(f"-v{VOLUME_SIZE}")
    if sfx:
        cmd.append(f"-sfx{SEVEN_Z_SFX}")
    run_cmd(cmd, ROOT)


def create_zip_archive(source_dir: Path, output_path: Path, password=None, split=False):
    cmd = [str(SEVEN_Z), "a", str(output_path), str(source_dir), "-tzip", "-y"]
    if password:
        cmd.append(f"-p{password}")
    if split:
        cmd.append(f"-v{VOLUME_SIZE}")
    run_cmd(cmd, ROOT)


def create_rar_archive(source_dir: Path, output_path: Path, password=None, split=False, sfx=False):
    cmd = [str(RAR_EXE), "a", "-ep1", "-r", "-idq", "-m0", "-ma5", "-y"]
    if password:
        cmd.append(f"-hp{password}")
    if split:
        cmd.append(f"-v{VOLUME_SIZE}")
    if sfx:
        cmd.append("-sfx")
    cmd.extend([str(output_path), str(source_dir)])
    run_cmd(cmd, ROOT)


def wrap_archive_with_jpeg_prefix(archive_path: Path, output_path: Path):
    output_path.write_bytes(MINIMAL_JPEG_BYTES + archive_path.read_bytes())


def wrap_archive_with_png_prefix(archive_path: Path, output_path: Path):
    output_path.write_bytes(MINIMAL_PNG_BYTES + archive_path.read_bytes())


def wrap_archive_with_pdf_prefix(archive_path: Path, output_path: Path):
    output_path.write_bytes(MINIMAL_PDF_BYTES + archive_path.read_bytes())


def build_minimal_webp_bytes():
    chunk_payload = b"\x00\x00\x00\x00"
    chunk = b"VP8 " + len(chunk_payload).to_bytes(4, "little") + chunk_payload
    riff_size = 4 + len(chunk)
    return b"RIFF" + riff_size.to_bytes(4, "little") + b"WEBP" + chunk


MINIMAL_WEBP_BYTES = build_minimal_webp_bytes()


def wrap_archive_with_gif_prefix(archive_path: Path, output_path: Path):
    output_path.write_bytes(MINIMAL_GIF_BYTES + archive_path.read_bytes())


def wrap_archive_with_webp_prefix(archive_path: Path, output_path: Path):
    output_path.write_bytes(MINIMAL_WEBP_BYTES + archive_path.read_bytes())


def make_case(base_dir: Path, spec):
    case_dir = base_dir / spec["id"]
    source_dir = case_dir / "source"
    output_dir = case_dir / "archives"
    output_dir.mkdir(parents=True, exist_ok=True)

    payload = write_payload(source_dir, spec["id"])
    archive_name = spec["base_name"]

    if spec["format"] == "7z":
        archive_path = output_dir / f"{archive_name}{'.exe' if spec['family'] == 'sfx' else '.7z'}"
        create_7z_archive(
            source_dir=source_dir,
            output_path=archive_path,
            password=spec["password"],
            split=spec["family"] == "split",
            sfx=spec["family"] == "sfx",
        )
    elif spec["format"] == "zip":
        archive_path = output_dir / f"{archive_name}.zip"
        create_zip_archive(
            source_dir=source_dir,
            output_path=archive_path,
            password=spec["password"],
            split=spec["family"] == "split",
        )
    elif spec["format"] == "rar":
        archive_path = output_dir / f"{archive_name}{'.exe' if spec['family'] == 'sfx' else '.rar'}"
        create_rar_archive(
            source_dir=source_dir,
            output_path=archive_path,
            password=spec["password"],
            split=spec["family"] == "split",
            sfx=spec["family"] == "sfx",
        )
    else:
        raise ValueError(f"Unsupported format: {spec['format']}")

    if spec["family"] in {"jpeg_prefixed", "png_prefixed", "pdf_prefixed", "gif_prefixed", "webp_prefixed"}:
        if spec["family"] == "jpeg_prefixed":
            wrapped_path = output_dir / f"{archive_name}.jpg"
            wrap_archive_with_jpeg_prefix(archive_path, wrapped_path)
        elif spec["family"] == "png_prefixed":
            wrapped_path = output_dir / f"{archive_name}.png"
            wrap_archive_with_png_prefix(archive_path, wrapped_path)
        elif spec["family"] == "pdf_prefixed":
            wrapped_path = output_dir / f"{archive_name}.pdf"
            wrap_archive_with_pdf_prefix(archive_path, wrapped_path)
        elif spec["family"] == "gif_prefixed":
            wrapped_path = output_dir / f"{archive_name}.gif"
            wrap_archive_with_gif_prefix(archive_path, wrapped_path)
        else:
            wrapped_path = output_dir / f"{archive_name}.webp"
            wrap_archive_with_webp_prefix(archive_path, wrapped_path)
        archive_path.unlink()
        archive_path = wrapped_path

    if spec["family"] == "split":
        entry_path = choose_split_entry(output_dir, archive_name, spec["format"])
        all_paths = list_split_parts(output_dir, archive_name)
    else:
        entry_path = archive_path
        all_paths = [archive_path]

    if spec["fault"] == "corrupted":
        corrupt_file(entry_path, truncate=True)
    elif spec["fault"] == "missing_split":
        all_paths = list_split_parts(output_dir, archive_name)
        all_paths[-1].unlink()
        all_paths = [path for path in all_paths if path.exists()]
        entry_path = choose_split_entry(output_dir, archive_name, spec["format"])
    elif spec["fault"] == "partial_split_corrupted":
        all_paths = list_split_parts(output_dir, archive_name)
        target = all_paths[1] if len(all_paths) > 1 else all_paths[0]
        corrupt_file(target, truncate=False, offset=65536, patch_size=8192)
        entry_path = choose_split_entry(output_dir, archive_name, spec["format"])
    elif spec["fault"] == "none":
        pass
    else:
        raise ValueError(f"Unsupported fault: {spec['fault']}")

    files = sorted(path for path in output_dir.iterdir() if path.is_file())
    return {
        **spec,
        "marker_name": payload["marker_name"],
        "marker_text": payload["marker_text"],
        "files": [path.name for path in files],
        "entry_name": entry_path.name,
    }


def choose_split_entry(output_dir: Path, archive_name: str, archive_format: str):
    files = sorted(path for path in output_dir.iterdir() if path.is_file())
    if archive_format == "rar":
        for path in files:
            if ".part1.rar" in path.name.lower() or ".part01.rar" in path.name.lower():
                return path
    for path in files:
        lower = path.name.lower()
        if lower.endswith(".001") or lower.endswith(".7z.001") or lower.endswith(".zip.001") or lower.endswith(".rar.001"):
            return path
    raise RuntimeError(f"Unable to determine split entry for {archive_name}: {[p.name for p in files]}")


def build_case_specs():
    return [
        {"id": "plain_single_7z", "base_name": "plain_single_7z", "format": "7z", "family": "single", "password": None, "fault": "none"},
        {"id": "plain_single_rar", "base_name": "plain_single_rar", "format": "rar", "family": "single", "password": None, "fault": "none"},
        {"id": "plain_single_zip", "base_name": "plain_single_zip", "format": "zip", "family": "single", "password": None, "fault": "none"},
        {"id": "plain_split_7z", "base_name": "plain_split_7z", "format": "7z", "family": "split", "password": None, "fault": "none"},
        {"id": "plain_split_rar", "base_name": "plain_split_rar", "format": "rar", "family": "split", "password": None, "fault": "none"},
        {"id": "plain_split_zip", "base_name": "plain_split_zip", "format": "zip", "family": "split", "password": None, "fault": "none"},
        {"id": "plain_corrupted_7z", "base_name": "plain_corrupted_7z", "format": "7z", "family": "single", "password": None, "fault": "corrupted"},
        {"id": "plain_corrupted_rar", "base_name": "plain_corrupted_rar", "format": "rar", "family": "single", "password": None, "fault": "corrupted"},
        {"id": "plain_corrupted_zip", "base_name": "plain_corrupted_zip", "format": "zip", "family": "single", "password": None, "fault": "corrupted"},
        {"id": "plain_missing_split_7z", "base_name": "plain_missing_split_7z", "format": "7z", "family": "split", "password": None, "fault": "missing_split"},
        {"id": "plain_missing_split_rar", "base_name": "plain_missing_split_rar", "format": "rar", "family": "split", "password": None, "fault": "missing_split"},
        {"id": "plain_missing_split_zip", "base_name": "plain_missing_split_zip", "format": "zip", "family": "split", "password": None, "fault": "missing_split"},
        {"id": "plain_partial_split_7z", "base_name": "plain_partial_split_7z", "format": "7z", "family": "split", "password": None, "fault": "partial_split_corrupted"},
        {"id": "plain_partial_split_rar", "base_name": "plain_partial_split_rar", "format": "rar", "family": "split", "password": None, "fault": "partial_split_corrupted"},
        {"id": "plain_partial_split_zip", "base_name": "plain_partial_split_zip", "format": "zip", "family": "split", "password": None, "fault": "partial_split_corrupted"},
        {"id": "plain_sfx_7z", "base_name": "plain_sfx_7z", "format": "7z", "family": "sfx", "password": None, "fault": "none"},
        {"id": "plain_sfx_rar", "base_name": "plain_sfx_rar", "format": "rar", "family": "sfx", "password": None, "fault": "none"},
        {"id": "plain_jpeg_prefixed_rar", "base_name": "plain_jpeg_prefixed_rar", "format": "rar", "family": "jpeg_prefixed", "password": None, "fault": "none"},
        {"id": "plain_png_prefixed_rar", "base_name": "plain_png_prefixed_rar", "format": "rar", "family": "png_prefixed", "password": None, "fault": "none"},
        {"id": "plain_pdf_prefixed_zip", "base_name": "plain_pdf_prefixed_zip", "format": "zip", "family": "pdf_prefixed", "password": None, "fault": "none"},
        {"id": "plain_gif_prefixed_rar", "base_name": "plain_gif_prefixed_rar", "format": "rar", "family": "gif_prefixed", "password": None, "fault": "none"},
        {"id": "plain_webp_prefixed_7z", "base_name": "plain_webp_prefixed_7z", "format": "7z", "family": "webp_prefixed", "password": None, "fault": "none"},
        {"id": "plain_corrupted_sfx_7z", "base_name": "plain_corrupted_sfx_7z", "format": "7z", "family": "sfx", "password": None, "fault": "corrupted"},
        {"id": "plain_corrupted_sfx_rar", "base_name": "plain_corrupted_sfx_rar", "format": "rar", "family": "sfx", "password": None, "fault": "corrupted"},
        {"id": "pwd123_single_7z", "base_name": "pwd123_single_7z", "format": "7z", "family": "single", "password": PASSWORD_123, "fault": "none"},
        {"id": "pwd123_single_rar", "base_name": "pwd123_single_rar", "format": "rar", "family": "single", "password": PASSWORD_123, "fault": "none"},
        {"id": "pwd123_single_zip", "base_name": "pwd123_single_zip", "format": "zip", "family": "single", "password": PASSWORD_123, "fault": "none"},
        {"id": "pwd456_split_7z", "base_name": "pwd456_split_7z", "format": "7z", "family": "split", "password": PASSWORD_456, "fault": "none"},
        {"id": "pwd456_split_rar", "base_name": "pwd456_split_rar", "format": "rar", "family": "split", "password": PASSWORD_456, "fault": "none"},
        {"id": "pwd456_split_zip", "base_name": "pwd456_split_zip", "format": "zip", "family": "split", "password": PASSWORD_456, "fault": "none"},
        {"id": "pwd789_sfx_7z", "base_name": "pwd789_sfx_7z", "format": "7z", "family": "sfx", "password": PASSWORD_789, "fault": "none"},
        {"id": "pwd789_sfx_rar", "base_name": "pwd789_sfx_rar", "format": "rar", "family": "sfx", "password": PASSWORD_789, "fault": "none"},
        {"id": "pwd123_jpeg_prefixed_rar", "base_name": "pwd123_jpeg_prefixed_rar", "format": "rar", "family": "jpeg_prefixed", "password": PASSWORD_123, "fault": "none"},
        {"id": "pwd123_png_prefixed_rar", "base_name": "pwd123_png_prefixed_rar", "format": "rar", "family": "png_prefixed", "password": PASSWORD_123, "fault": "none"},
        {"id": "pwd123_pdf_prefixed_zip", "base_name": "pwd123_pdf_prefixed_zip", "format": "zip", "family": "pdf_prefixed", "password": PASSWORD_123, "fault": "none"},
        {"id": "pwd123_gif_prefixed_rar", "base_name": "pwd123_gif_prefixed_rar", "format": "rar", "family": "gif_prefixed", "password": PASSWORD_123, "fault": "none"},
        {"id": "pwd123_webp_prefixed_7z", "base_name": "pwd123_webp_prefixed_7z", "format": "7z", "family": "webp_prefixed", "password": PASSWORD_123, "fault": "none"},
        {"id": "pwd123_corrupted_7z", "base_name": "pwd123_corrupted_7z", "format": "7z", "family": "single", "password": PASSWORD_123, "fault": "corrupted"},
        {"id": "pwd123_corrupted_rar", "base_name": "pwd123_corrupted_rar", "format": "rar", "family": "single", "password": PASSWORD_123, "fault": "corrupted"},
        {"id": "pwd123_corrupted_zip", "base_name": "pwd123_corrupted_zip", "format": "zip", "family": "single", "password": PASSWORD_123, "fault": "corrupted"},
        {"id": "pwd456_missing_split_7z", "base_name": "pwd456_missing_split_7z", "format": "7z", "family": "split", "password": PASSWORD_456, "fault": "missing_split"},
        {"id": "pwd456_missing_split_rar", "base_name": "pwd456_missing_split_rar", "format": "rar", "family": "split", "password": PASSWORD_456, "fault": "missing_split"},
        {"id": "pwd456_missing_split_zip", "base_name": "pwd456_missing_split_zip", "format": "zip", "family": "split", "password": PASSWORD_456, "fault": "missing_split"},
        {"id": "pwd456_partial_split_7z", "base_name": "pwd456_partial_split_7z", "format": "7z", "family": "split", "password": PASSWORD_456, "fault": "partial_split_corrupted"},
        {"id": "pwd456_partial_split_rar", "base_name": "pwd456_partial_split_rar", "format": "rar", "family": "split", "password": PASSWORD_456, "fault": "partial_split_corrupted"},
        {"id": "pwd456_partial_split_zip", "base_name": "pwd456_partial_split_zip", "format": "zip", "family": "split", "password": PASSWORD_456, "fault": "partial_split_corrupted"},
        {"id": "pwd789_corrupted_sfx_7z", "base_name": "pwd789_corrupted_sfx_7z", "format": "7z", "family": "sfx", "password": PASSWORD_789, "fault": "corrupted"},
        {"id": "pwd789_corrupted_sfx_rar", "base_name": "pwd789_corrupted_sfx_rar", "format": "rar", "family": "sfx", "password": PASSWORD_789, "fault": "corrupted"},
    ]


def create_dataset(dataset_dir: Path):
    dataset_dir.mkdir(parents=True, exist_ok=True)
    cases = []
    for spec in build_case_specs():
        cases.append(make_case(dataset_dir, spec))
    return cases


def stage_corpus(dataset_dir: Path, scenario_dir: Path, disguised: bool):
    scenario_dir.mkdir(parents=True, exist_ok=True)
    staged_cases = []
    for case_root in sorted(path for path in dataset_dir.iterdir() if path.is_dir()):
        archive_dir = case_root / "archives"
        stage_case_dir = scenario_dir / case_root.name
        shutil.copytree(archive_dir, stage_case_dir)
        files = sorted(path for path in stage_case_dir.iterdir() if path.is_file())
        rename_map = {}
        if disguised and case_root.name not in {
            "plain_jpeg_prefixed_rar",
            "plain_png_prefixed_rar",
            "plain_pdf_prefixed_zip",
            "plain_gif_prefixed_rar",
            "plain_webp_prefixed_7z",
            "pwd123_jpeg_prefixed_rar",
            "pwd123_png_prefixed_rar",
            "pwd123_pdf_prefixed_zip",
            "pwd123_gif_prefixed_rar",
            "pwd123_webp_prefixed_7z",
        }:
            for path in files:
                new_path = append_fake_suffix(path, case_root.name)
                rename_map[path.name] = new_path.name
            files = sorted(path for path in stage_case_dir.iterdir() if path.is_file())
        metadata_path = dataset_dir / case_root.name / "source" / f"{case_root.name}.marker.txt"
        marker_text = metadata_path.read_text(encoding="utf-8")
        entry_name = determine_entry_name(files, case_root.name)
        staged_cases.append(
            {
                "id": case_root.name,
                "marker_name": f"{case_root.name}.marker.txt",
                "marker_text": marker_text,
                "files": [path.name for path in files],
                "entry_name": entry_name,
                "rename_map": rename_map,
            }
        )
    return staged_cases


def determine_entry_name(files, case_id: str):
    lower_map = {path.name.lower(): path.name for path in files}
    rar_candidates = [name for name in lower_map if ".part1.rar" in name or ".part01.rar" in name]
    if rar_candidates:
        return lower_map[sorted(rar_candidates)[0]]
    numbered = [name for name in lower_map if name.endswith(".001") or ".001." in name]
    if numbered:
        return lower_map[sorted(numbered)[0]]
    exe_candidates = [name for name in lower_map if name.startswith(case_id.lower()) and ".exe" in name]
    if exe_candidates:
        return lower_map[sorted(exe_candidates)[0]]
    return sorted(path.name for path in files)[0]


def expected_outcome(case_id: str, passwords):
    has_123 = PASSWORD_123 in passwords
    has_456 = PASSWORD_456 in passwords
    has_789 = PASSWORD_789 in passwords

    if case_id.startswith("plain_"):
        if "_missing_split_" in case_id:
            return EXPECTED_MISSING_SPLIT
        if "_partial_split_" in case_id:
            return EXPECTED_CORRUPTED
        if "_corrupted_" in case_id:
            return EXPECTED_CORRUPTED
        return EXPECTED_SUCCESS

    if case_id.startswith("pwd123_"):
        if not has_123:
            return EXPECTED_PASSWORD
        if "_corrupted_" in case_id:
            return EXPECTED_CORRUPTED
        return EXPECTED_SUCCESS

    if case_id.startswith("pwd456_"):
        if not has_456:
            return EXPECTED_PASSWORD
        if "_missing_split_" in case_id:
            return EXPECTED_MISSING_SPLIT
        if "_partial_split_" in case_id:
            return EXPECTED_CORRUPTED
        return EXPECTED_SUCCESS

    if case_id.startswith("pwd789_"):
        if not has_789:
            return EXPECTED_PASSWORD
        if "_corrupted_" in case_id:
            return EXPECTED_CORRUPTED
        return EXPECTED_SUCCESS

    raise ValueError(f"Unhandled case id: {case_id}")


def expected_error_options(case_id: str, passwords):
    expected = expected_outcome(case_id, passwords)
    if expected == EXPECTED_SUCCESS:
        return set()

    if case_id.startswith("plain_"):
        if "_missing_split_" in case_id:
            return {EXPECTED_MISSING_SPLIT, EXPECTED_CORRUPTED, EXPECTED_FATAL}
        if "_partial_split_" in case_id:
            return {EXPECTED_CORRUPTED, EXPECTED_MISSING_SPLIT, EXPECTED_FATAL}
        if "_corrupted_" in case_id:
            return {EXPECTED_CORRUPTED, EXPECTED_FATAL}

    if expected == EXPECTED_PASSWORD:
        return {EXPECTED_PASSWORD, EXPECTED_CORRUPTED, EXPECTED_MISSING_SPLIT, EXPECTED_FATAL}

    if expected == EXPECTED_MISSING_SPLIT:
        return {EXPECTED_MISSING_SPLIT, EXPECTED_CORRUPTED, EXPECTED_FATAL}

    if expected == EXPECTED_CORRUPTED:
        return {EXPECTED_CORRUPTED, EXPECTED_MISSING_SPLIT, EXPECTED_FATAL}

    return {expected}


def run_engine(workspace_dir: Path, passwords):
    DecompressionEngine = load_engine_class()
    logs = []
    engine = DecompressionEngine(str(workspace_dir), passwords, logs.append, lambda: None, use_builtin_passwords=False)
    engine.max_workers_limit = 1
    engine.current_concurrency_limit = 1
    engine.run()
    return {"failed_tasks": list(engine.failed_tasks), "logs": logs}


def case_success_detected(workspace_dir: Path, case_id: str, marker_name: str, marker_text: str):
    candidates = list(workspace_dir.rglob(marker_name))
    for candidate in candidates:
        try:
            if candidate.read_text(encoding="utf-8") == marker_text:
                return True, str(candidate.relative_to(workspace_dir))
        except Exception:
            continue
    return False, None


def case_error_detected(failed_tasks, case_id: str, allowed_errors):
    relevant = [item for item in failed_tasks if case_id in item]
    return any(any(error in item for error in allowed_errors) for item in relevant), relevant


def evaluate_run(workspace_dir: Path, passwords, staged_cases, disguised: bool):
    engine_result = run_engine(workspace_dir, passwords)
    case_results = []
    mismatches = []

    for case in staged_cases:
        expected = expected_outcome(case["id"], passwords)
        extracted, extracted_path = case_success_detected(
            workspace_dir=workspace_dir,
            case_id=case["id"],
            marker_name=case["marker_name"],
            marker_text=case["marker_text"],
        )
        matched_error, failure_lines = case_error_detected(
            failed_tasks=engine_result["failed_tasks"],
            case_id=case["id"],
            allowed_errors=expected_error_options(case["id"], passwords),
        )

        if expected == EXPECTED_SUCCESS:
            ok = extracted and not failure_lines
        else:
            ok = (not extracted) and matched_error

        if not ok:
            mismatches.append(
                {
                    "case_id": case["id"],
                    "expected": expected,
                    "entry_name": case["entry_name"],
                    "extracted": extracted,
                    "extracted_path": extracted_path,
                    "failure_lines": failure_lines,
                }
            )

        case_results.append(
            {
                "case_id": case["id"],
                "expected": expected,
                "ok": ok,
                "entry_name": case["entry_name"],
                "extracted": extracted,
                "extracted_path": extracted_path,
                "failure_lines": failure_lines,
                "disguised": disguised,
            }
        )

    return {
        "ok": not mismatches,
        "case_results": case_results,
        "mismatches": mismatches,
        "failed_tasks": engine_result["failed_tasks"],
        "logs_tail": engine_result["logs"][-120:],
    }


def run_scenario(dataset_dir: Path, scenario, disguised: bool):
    mode_label = "disguised" if disguised else "original"
    with tempfile.TemporaryDirectory(prefix=f"acceptance-{scenario['id']}-{mode_label}-", dir=str(ROOT)) as temp_dir:
        workspace_dir = Path(temp_dir)
        staged_cases = stage_corpus(dataset_dir, workspace_dir, disguised=disguised)
        result = evaluate_run(
            workspace_dir=workspace_dir,
            passwords=scenario["passwords"],
            staged_cases=staged_cases,
            disguised=disguised,
        )
        result.update(
            {
                "scenario_id": scenario["id"],
                "scenario_label": scenario["label"],
                "passwords": scenario["passwords"],
                "disguised": disguised,
                "workspace_dir": str(workspace_dir),
                "total_cases": len(staged_cases),
                "passed_cases": sum(1 for item in result["case_results"] if item["ok"]),
                "failed_cases": sum(1 for item in result["case_results"] if not item["ok"]),
            }
        )
        return result


def main():
    ensure_prerequisites()
    random.seed(20260421)

    with tempfile.TemporaryDirectory(prefix="acceptance-dataset-", dir=str(ROOT)) as dataset_temp_dir:
        dataset_dir = Path(dataset_temp_dir)
        cases = create_dataset(dataset_dir)

        scenario_results = []
        for disguised in (False, True):
            for scenario in PASSWORD_SCENARIOS:
                scenario_results.append(run_scenario(dataset_dir, scenario, disguised=disguised))

        overall_ok = all(item["ok"] for item in scenario_results)
        output = {
            "overall_ok": overall_ok,
            "case_count": len(cases),
            "scenario_count": len(scenario_results),
            "passed_scenarios": sum(1 for item in scenario_results if item["ok"]),
            "failed_scenarios": sum(1 for item in scenario_results if not item["ok"]),
            "scenarios": scenario_results,
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
        sys.exit(0 if overall_ok else 1)


if __name__ == "__main__":
    main()
