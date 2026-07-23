from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import register_processor


DEFAULT_SCAN_LIMIT_BYTES = 8 * 1024 * 1024
DEFAULT_CHUNK_BYTES = 1024 * 1024
QT_IFW_TAIL_WINDOW_BYTES = 1024 * 1024
QT_IFW_MAGIC_COOKIE = 0xC2630A1C99D668F8
QT_IFW_MAGIC_MARKERS = frozenset((0x12023233, 0x12023234, 0x12023235, 0x12023236))

# These signatures identify application or installer bundles, not archive formats.
# Keep profiles independent so new bundle types can be added without changing policy.
RUNTIME_STUB_PROFILES: tuple[tuple[str, tuple[bytes, ...]], ...] = (
    ("inno_setup", (b"Inno Setup Setup Data (", b"JR.Inno.Setup")),
    (
        "squirrel_windows",
        (
            "SquirrelAwareVersion".encode("utf-16le"),
            "SquirrelSetup.log".encode("utf-16le"),
        ),
    ),
    ("par_packer", (b"PAR::Packer", b"PAR_TEMP")),
    ("nuitka_onefile", (b"NUITKA_ONEFILE_PARENT",)),
)
PYINSTALLER_COOKIE = b"MEI\x0c\x0b\x0a\x0b\x0e"


def classify_executable_carrier(
    path: str,
    pe_overlay: dict[str, Any] | None,
    structure_evidence: dict[str, Any] | None = None,
    *,
    scan_limit_bytes: int = DEFAULT_SCAN_LIMIT_BYTES,
) -> dict[str, Any]:
    overlay = pe_overlay or {}
    if not overlay.get("is_pe"):
        return _result("none", "none", [], is_executable=False)

    evidence = ["pe:valid_headers"]
    runtime_profile = _runtime_bundle_profile(
        path,
        scan_limit_bytes,
        executable_image_end=int(overlay.get("overlay_offset") or 0),
    )
    if runtime_profile:
        evidence.append(f"runtime_packer:{runtime_profile}")
        return _result(
            "runtime_bundle",
            "high",
            evidence,
            is_executable=True,
            runtime_profile=runtime_profile,
            overlay=overlay,
        )

    if overlay.get("archive_like"):
        evidence.extend(str(item) for item in overlay.get("evidence") or [] if item)
        return _result(
            "self_extracting_archive",
            str(overlay.get("confidence") or "medium"),
            evidence,
            is_executable=True,
            overlay=overlay,
        )

    structure = structure_evidence or {}
    if structure.get("has_extractable"):
        selected = structure.get("selected") if isinstance(structure.get("selected"), dict) else {}
        archive_format = str(selected.get("format") or "")
        if archive_format:
            evidence.append(f"structure:{archive_format}")
        # An executable with a proven archive but no known SFX/runtime signature
        # remains eligible. This conservative class prevents unknown, encrypted,
        # damaged, or split SFX variants from being globally excluded.
        return _result(
            "executable_archive",
            "medium",
            evidence,
            is_executable=True,
            overlay=overlay,
        )

    return _result(
        "plain_executable",
        "high",
        evidence,
        is_executable=True,
        overlay=overlay,
    )


def _runtime_bundle_profile(path: str, scan_limit_bytes: int, *, executable_image_end: int) -> str:
    if not path or scan_limit_bytes <= 0:
        return ""
    # Stub signatures are searched only inside the PE image. Searching archive
    # payload bytes would reject a legitimate SFX merely because it contains a
    # packed executable as a member.
    image_scan_limit = min(scan_limit_bytes, executable_image_end) if executable_image_end > 0 else scan_limit_bytes
    patterns = tuple(pattern for _, profile in RUNTIME_STUB_PROFILES for pattern in profile)
    matched: set[bytes] = set()
    try:
        for sample in _iter_file_samples(path, image_scan_limit, patterns):
            for pattern in patterns:
                if pattern not in matched and pattern in sample:
                    matched.add(pattern)
            for name, required in RUNTIME_STUB_PROFILES:
                if all(pattern in matched for pattern in required):
                    return name
        if _qt_ifw_tail_layout_matches(path):
            return "qt_installer_framework"
        if _tail_contains(path, PYINSTALLER_COOKIE, window_bytes=256):
            return "pyinstaller"
    except OSError:
        return ""
    return ""


def _qt_ifw_tail_layout_matches(path: str) -> bool:
    cookie = QT_IFW_MAGIC_COOKIE.to_bytes(8, "little")
    with open(path, "rb") as handle:
        handle.seek(0, 2)
        file_size = handle.tell()
        window_start = max(0, file_size - QT_IFW_TAIL_WINDOW_BYTES)
        handle.seek(window_start)
        tail = handle.read(QT_IFW_TAIL_WINDOW_BYTES)

    offset = tail.find(cookie)
    while offset >= 0:
        if offset >= 16:
            marker = int.from_bytes(tail[offset - 8 : offset], "little")
            binary_content_size = int.from_bytes(tail[offset - 16 : offset - 8], "little")
            end_of_binary_content = window_start + offset + len(cookie)
            if marker in QT_IFW_MAGIC_MARKERS and 24 <= binary_content_size <= end_of_binary_content:
                return True
        offset = tail.find(cookie, offset + 1)
    return False


def _tail_contains(path: str, pattern: bytes, *, window_bytes: int) -> bool:
    with open(path, "rb") as handle:
        handle.seek(0, 2)
        size = handle.tell()
        handle.seek(max(0, size - window_bytes))
        return pattern in handle.read(window_bytes)


def _iter_file_samples(
    path: str,
    scan_limit_bytes: int,
    patterns: Iterable[bytes],
) -> Iterable[bytes]:
    overlap = max((len(pattern) for pattern in patterns), default=1) - 1
    remaining = scan_limit_bytes
    carry = b""
    with open(path, "rb") as handle:
        while remaining > 0:
            chunk = handle.read(min(DEFAULT_CHUNK_BYTES, remaining))
            if not chunk:
                break
            sample = carry + chunk
            yield sample
            carry = sample[-overlap:] if overlap else b""
            remaining -= len(chunk)


def _result(
    kind: str,
    confidence: str,
    evidence: list[str],
    *,
    is_executable: bool,
    runtime_profile: str = "",
    overlay: dict[str, Any] | None = None,
) -> dict[str, Any]:
    overlay = overlay or {}
    return {
        "kind": kind,
        "confidence": confidence,
        "evidence": list(dict.fromkeys(evidence)),
        "is_executable": is_executable,
        "runtime_profile": runtime_profile,
        "executable_image_end": int(overlay.get("overlay_offset") or 0),
        "payload_header_offset": int(overlay.get("archive_offset") or 0),
        "payload_format": str(overlay.get("format") or ""),
    }


@register_processor(
    "executable_carrier",
    input_facts=("file.path", "pe.overlay_structure"),
    output_facts={"executable.carrier"},
    schemas={
        "executable.carrier": {
            "type": "dict",
            "description": "Executable carrier classification separating SFX archives from application runtime bundles.",
        },
    },
)
def process_executable_carrier(context: FactProcessorContext) -> dict[str, Any]:
    facts = context.fact_bag
    return classify_executable_carrier(
        str(facts.get("file.path") or ""),
        facts.get("pe.overlay_structure") or {},
        facts.get("analysis.structure_evidence") or {},
        scan_limit_bytes=int(context.fact_config.get("scan_limit_bytes", DEFAULT_SCAN_LIMIT_BYTES) or 0),
    )
