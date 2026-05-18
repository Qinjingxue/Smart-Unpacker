from __future__ import annotations

from typing import Any


def damage_labels_for_row(row: dict[str, Any]) -> list[str]:
    target = row.get("damage_analysis_target") if isinstance(row.get("damage_analysis_target"), dict) else {}
    source = target.get("observed_labels") if isinstance(target.get("observed_labels"), list) else target.get("damage_labels")
    return _location_label_list(source)


def uncertain_labels_for_row(row: dict[str, Any]) -> list[str]:
    target = row.get("damage_analysis_target") if isinstance(row.get("damage_analysis_target"), dict) else {}
    return _location_label_list(target.get("uncertain_labels") or [])


def oracle_damage_labels_for_row(row: dict[str, Any]) -> list[str]:
    target = row.get("damage_analysis_target") if isinstance(row.get("damage_analysis_target"), dict) else {}
    return _location_label_list(target.get("damage_labels") or [])


def damage_location_labels_from_target(target: dict[str, Any]) -> list[str]:
    labels: list[str] = []
    for label in target.get("damage_labels") or []:
        text = str(label or "")
        if text.startswith(("zone:", "field:")):
            labels.append(text)
    for item in target.get("labels") or []:
        if not isinstance(item, dict):
            continue
        zone = item.get("zone") if isinstance(item.get("zone"), dict) else {}
        zone_label = _zone_label(zone)
        if zone_label:
            labels.append(f"zone:{zone_label}")
        field_label = _field_label(zone)
        if field_label:
            labels.append(f"field:{field_label}")
    return sorted(set(labels))


def _location_label_list(raw: Any) -> list[str]:
    labels: list[str] = []
    for label in raw or []:
        text = str(label or "")
        if text.startswith(("zone:", "field:")):
            labels.append(text)
    return sorted(set(labels))


def _zone_label(zone: dict[str, Any]) -> str:
    path = str(zone.get("path") or "").lower()
    kind = str(zone.get("kind") or "").lower()
    if kind == "flag":
        return ""
    text = f"{kind}.{path}"
    if "sfx" in text or "prefix" in text or "carrier" in text:
        return "sfx_prefix"
    if "missing_volume" in text or "split" in text or "volume" in text:
        return "split_volume"
    if "zip64" in text:
        return "zip64"
    if "eocd" in text:
        return "eocd"
    if "central_directory" in text or "central.dir" in text:
        return "central_directory"
    if "local_header" in text or "local.header" in text:
        return "local_header"
    if "data_descriptor" in text or "descriptor" in text or "bit3" in text:
        return "data_descriptor"
    if "extra" in text:
        return "extra_field"
    if "payload" in text or "file_data" in text:
        return "payload"
    if "tail" in text or "comment" in text:
        return "tail"
    return ""


def _field_label(zone: dict[str, Any]) -> str:
    path = str(zone.get("path") or "").lower().replace("-", "_")
    kind = str(zone.get("kind") or "").lower()
    if kind == "flag" or not path:
        return ""
    path = path.replace("zip.", "")
    path = path.replace("central.dir", "central_directory")
    mapping = (
        ("eocd.entry_counts", "eocd.entry_count"),
        ("eocd.entry_count_total", "eocd.entry_count"),
        ("eocd.entry_count_disk", "eocd.entry_count"),
        ("eocd.cd_offset", "eocd.cd_offset"),
        ("eocd.cd_size", "eocd.cd_size"),
        ("eocd.comment_length", "eocd.comment_length"),
        ("eocd.comment", "eocd.comment"),
        ("central_directory.local_header_offset", "central_directory.local_header_offset"),
        ("central_directory.external_attributes", "central_directory.external_attributes"),
        ("central_directory.compressed_size", "central_directory.compressed_size"),
        ("central_directory.extra_length", "central_directory.extra_length"),
        ("central_directory.filename", "central_directory.filename"),
        ("central_directory.flags", "central_directory.flags"),
        ("central_directory.crc", "central_directory.crc"),
        ("central_directory.extra", "central_directory.extra"),
        ("local_header.compressed_size", "local_header.compressed_size"),
        ("local_header.extra_length", "local_header.extra_length"),
        ("local_header.extra_field", "local_header.extra"),
        ("local_header.filename", "local_header.filename"),
        ("local_header.flags", "local_header.flags"),
        ("local_header.crc", "local_header.crc"),
        ("local_header.extra", "local_header.extra"),
        ("data_descriptor.crc", "data_descriptor.crc"),
        ("data_descriptor.size", "data_descriptor.size"),
        ("data_descriptor", "data_descriptor.record"),
        ("local_payload", "payload.compressed_data"),
        ("payload_hash_mismatch", "payload.crc_region"),
        ("crc_error", "payload.crc_region"),
        ("checksum_error", "payload.crc_region"),
        ("payload", "payload.compressed_data"),
        ("extra.zip64.uncompressed_size", "zip64.uncompressed_size"),
        ("extra.zip64.length", "zip64.extra_length"),
        ("zip64.locator", "zip64.locator"),
        ("zip64.eocd", "zip64.eocd"),
        ("archive.tail", "tail.trailing_bytes"),
        ("tail", "tail.trailing_bytes"),
        ("trailing_junk", "tail.trailing_bytes"),
        ("sfx.prefix", "sfx_prefix.bytes"),
        ("missing_volume", "split_volume.missing_range"),
    )
    for needle, label in mapping:
        if needle in path:
            return label
    return ""
