import subprocess
import re
from typing import Dict, Any
from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor
from smart_unpacker.support.resources import get_7z_path
from smart_unpacker.support.external_command_cache import cached_readonly_command

EXECUTABLE_VALIDATION_TYPES = {"pe", "elf", "macho", "te"}
ENCRYPTED_SIGNALS = (
    "wrong password",
    "cannot open encrypted archive",
    "can not open encrypted archive",
    "enter password",
)


def _parse_7z_type(output: str) -> str:
    for line in output.splitlines():
        if line.lower().startswith("type = "):
            return line.split("=", 1)[1].strip().lower()
    return ""


def _parse_7z_warnings(output: str) -> list[str]:
    warnings = []
    for match in re.finditer(r"(?im)^warning\s*=\s*(.+)$", output):
        warning = match.group(1).strip()
        if warning:
            warnings.append(warning)
    return warnings


@register_processor(
    "seven_zip_validation",
    input_facts={"file.path"},
    output_facts={"7z.validation"},
    schemas={
        "7z.validation": {
            "type": "dict",
            "description": "7-Zip test result with ok/encrypted/error fields.",
        },
    },
)
def process_7z_validation(context: FactProcessorContext) -> Dict[str, Any]:
    base_path = context.fact_bag.get("file.path") or ""
    seven_z_path = get_7z_path()
    
    cmd = [seven_z_path, "t", base_path, "-y"]
    
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
        output = f"{rt.stdout}\n{rt.stderr}"
    except FileNotFoundError:
        return {"error": "7z not found"}

    output_lower = output.lower()
    validation_type = _parse_7z_type(output)
    warnings = _parse_7z_warnings(output)
    checksum_error = "checksum error" in output_lower
    is_executable_container = validation_type in EXECUTABLE_VALIDATION_TYPES
    result = {
        "ok": rt.returncode == 0 and not is_executable_container,
        "command_ok": rt.returncode == 0,
        "type": validation_type,
        "is_executable_container": is_executable_container,
        "warnings": warnings,
        "checksum_error": checksum_error,
        "encrypted": any(signal in output_lower for signal in ENCRYPTED_SIGNALS),
        "error_text": output_lower,
    }

    return result
