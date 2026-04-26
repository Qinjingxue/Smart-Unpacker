import subprocess
import re
from typing import Dict, Any
from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor
from smart_unpacker.support.resources import get_7z_path
from smart_unpacker.support.external_command_cache import cached_readonly_command

EXECUTABLE_PROBE_TYPES = {"pe", "elf", "macho", "te"}
ENCRYPTED_SIGNALS = (
    "wrong password",
    "cannot open encrypted archive",
    "can not open encrypted archive",
)
DAMAGE_SIGNALS = (
    "unexpected end of data",
    "unexpected end of archive",
    "data error",
    "crc failed",
    "checksum error",
)

@register_processor(
    "seven_zip_probe",
    input_facts={"file.path"},
    output_facts={"7z.probe"},
    schemas={
        "7z.probe": {
            "type": "dict",
            "description": "Lightweight 7-Zip probe result with archive/container/encryption/offset fields.",
        },
    },
)
def process_7z_probe(context: FactProcessorContext) -> Dict[str, Any]:
    base_path = context.fact_bag.get("file.path") or ""
    seven_z_path = get_7z_path()
    
    cmd = [seven_z_path, "l", "-slt", base_path]
    
    si = None
    import sys
    if sys.platform == "win32":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    try:
        rt = cached_readonly_command(
            cmd,
            base_path,
            subprocess.run,
            capture_output=True,
            text=True,
            errors="replace",
            startupinfo=si,
            stdin=subprocess.DEVNULL,
        )
        out = f"{rt.stdout}\n{rt.stderr}"
    except FileNotFoundError:
        return {"error": "7z not found"}

    lower = out.lower()
    archive_type = None
    for line in out.splitlines():
        if line.lower().startswith("type = "):
            archive_type = line.split("=", 1)[1].strip().lower()
            break

    result = {
        "is_archive": False,
        "type": archive_type,
        "offset": 0,
        "is_encrypted": False,
        "is_broken": False,
        "checksum_error": "checksum error" in lower,
    }

    if rt.returncode == 0:
        result["is_archive"] = archive_type not in EXECUTABLE_PROBE_TYPES if archive_type else True
        result["is_encrypted"] = "encrypted = +" in lower
    else:
        type_match = re.search(r"open the file as \[([^\]]+)\] archive", lower)
        if type_match:
            result["type"] = type_match.group(1).strip().lower()
        if archive_type and "is not archive" not in lower:
            result["is_archive"] = True
        result["is_encrypted"] = any(signal in lower for signal in ENCRYPTED_SIGNALS)
        if not result["is_archive"] and "listing archive:" in lower and "enter password" in lower:
            result["is_archive"] = True
            result["is_encrypted"] = True
        
        result["is_broken"] = any(sig in lower for sig in DAMAGE_SIGNALS)

    m = re.search(r"offset = (\d+)", lower)
    if m:
        result["offset"] = int(m.group(1))

    return result
