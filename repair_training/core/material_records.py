from __future__ import annotations

from pathlib import Path
from typing import Any


def attach_split_volumes(source_input: dict[str, Any], record: dict[str, Any]) -> None:
    if source_input.get("parts"):
        _ensure_ranges_from_parts(source_input)
        source_input["split_sidecars_available"] = True
        return
    tags = []
    for key, value in record.items():
        if str(key).endswith("container_tags") and isinstance(value, list):
            tags.extend(str(item) for item in value if str(item))
    value = record.get("container_tags")
    if isinstance(value, list):
        tags.extend(str(item) for item in value if str(item))
    variant_values = [
        str(value)
        for key, value in record.items()
        if str(key).endswith("_variant") and value is not None
    ]
    profile_text = " ".join([
        str(record.get("damage_profile") or ""),
        str(record.get("sample_id") or ""),
        str(record.get("source_archive_id") or ""),
        *variant_values,
    ]).lower()
    damaged = record.get("damaged_input") if isinstance(record.get("damaged_input"), dict) else {}
    split_hint = bool(
        ("split" in tags or "multi_volume" in tags or "split_archive" in tags or "split_sidecars_available" in tags)
        or "split" in profile_text
        or isinstance(record.get("split"), dict)
        or isinstance(damaged.get("parts"), list)
    )
    if not split_hint:
        return
    volumes: list[dict[str, Any]] = []
    split_payload = record.get("split")
    if isinstance(split_payload, dict):
        for item in split_payload.get("volumes") or split_payload.get("parts") or []:
            if isinstance(item, dict) and item.get("path"):
                volumes.append(dict(item))
    for item in damaged.get("parts") or []:
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
    if source_input.get("parts"):
        source_input["split_sidecars_available"] = True


def _ensure_ranges_from_parts(source_input: dict[str, Any]) -> None:
    if source_input.get("ranges"):
        return
    ranges: list[dict[str, Any]] = []
    for item in source_input.get("parts") or []:
        if isinstance(item, dict) and item.get("path"):
            ranges.append({"path": str(item.get("path")), "start": int(item.get("start") or 0), "end": item.get("end")})
    if ranges:
        source_input["ranges"] = ranges
