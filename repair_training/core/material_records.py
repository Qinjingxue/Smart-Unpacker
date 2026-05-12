from __future__ import annotations

from pathlib import Path
from typing import Any


def attach_split_volumes(source_input: dict[str, Any], record: dict[str, Any]) -> None:
    tags = record.get("zip_container_tags") or []
    profile_text = " ".join(str(record.get(key) or "") for key in ("damage_profile", "sample_id", "source_archive_id", "zip_variant")).lower()
    split_hint = bool(
        (isinstance(tags, list) and ("split" in tags or "multi_volume" in tags or "split_archive" in tags))
        or "split" in profile_text
        or isinstance(record.get("zip_split"), dict)
    )
    if not split_hint:
        return
    volumes: list[dict[str, Any]] = []
    split_payload = record.get("zip_split")
    if isinstance(split_payload, dict):
        for item in split_payload.get("volumes") or []:
            if isinstance(item, dict) and item.get("path"):
                volumes.append(dict(item))
    source_path = record.get("source_path") or ""
    source_name = record.get("source_archive_name") or ""
    if source_path:
        source_archive = Path(source_path)
    elif source_name:
        material_sample = record.get("material_sample_id") or ""
        material_format = record.get("material_format") or "zip"
        source_archive = Path("repair_training") / "material" / material_format / material_sample / source_name
    else:
        source_archive = None
    volumes_dir = source_archive.parent / (source_archive.name + ".volumes") if source_archive is not None else None
    if volumes_dir is not None and volumes_dir.is_dir():
        for vol in sorted(volumes_dir.iterdir()):
            if vol.is_file():
                volumes.append({"path": str(vol.resolve()), "role": "volume"})
    if not volumes:
        return
    source_input["parts"] = source_input.get("parts") or []
    source_input["ranges"] = source_input.get("ranges") or []
    existing = {str(p.get("path", "")) for p in source_input.get("parts", []) if isinstance(p, dict)}

    def volume_sort_key(item: dict[str, Any]) -> tuple[int, str]:
        try:
            return (int(item.get("index") or item.get("volume_number") or 0), str(item.get("path") or ""))
        except Exception:
            return (0, str(item.get("path") or ""))

    for vol in sorted(volumes, key=volume_sort_key):
        vol_path = str(Path(str(vol.get("path") or "")).resolve())
        if vol_path not in existing:
            source_input["parts"].append({"path": vol_path, "role": "volume"})
            source_input["ranges"].append({"path": vol_path, "start": 0, "end": None})
