from typing import Any


FACT_SCHEMA: dict[str, dict[str, Any]] = {
    "file.path": {
        "type": "str",
        "producer": "facts.collectors.file_facts",
        "description": "Absolute or normalized path of the candidate file.",
    },
    "file.size": {
        "type": "int",
        "producer": "facts.collectors.file_facts",
        "description": "File size in bytes, or -1 if unavailable.",
    },
    "file.magic_bytes": {
        "type": "bytes",
        "producer": "facts.collectors.magic_bytes",
        "description": "First 16 bytes used by processors and rules for magic signature checks.",
    },
    "scene.context": {
        "type": "dict",
        "producer": "processors.scene_facts",
        "description": "Detected directory scene, including scene_type, target_dir, match_strength, and markers.",
    },
    "scene.relative_path": {
        "type": "str",
        "producer": "processors.scene_facts",
        "description": "Candidate path relative to the detected scene root.",
    },
    "scene.scene_type": {
        "type": "str",
        "producer": "processors.scene_facts",
        "description": "Detected scene type for the candidate path.",
    },
    "scene.match_strength": {
        "type": "str",
        "producer": "processors.scene_facts",
        "description": "Detected scene match strength.",
    },
    "scene.is_runtime_exact_path": {
        "type": "bool",
        "producer": "processors.scene_facts",
        "description": "Whether the candidate is a scene runtime exact path.",
    },
    "scene.is_protected_exact_path": {
        "type": "bool",
        "producer": "processors.scene_facts",
        "description": "Whether the candidate matches a protected exact scene path.",
    },
    "scene.is_protected_prefix_path": {
        "type": "bool",
        "producer": "processors.scene_facts",
        "description": "Whether the candidate is under a protected scene prefix.",
    },
    "scene.is_protected_path": {
        "type": "bool",
        "producer": "processors.scene_facts",
        "description": "Whether the candidate is in a protected scene path.",
    },
    "scene.protected_archive_ext_match": {
        "type": "bool",
        "producer": "processors.scene_facts",
        "description": "Whether the candidate extension is protected as a scene archive resource.",
    },
    "scene.is_runtime_resource_archive": {
        "type": "bool",
        "producer": "processors.scene_facts",
        "description": "Whether the candidate is a protected scene runtime resource archive.",
    },
    "7z.probe": {
        "type": "dict",
        "producer": "processors.seven_zip_probe",
        "description": "Lightweight 7-Zip probe result with archive/container/encryption/offset fields.",
    },
    "7z.validation": {
        "type": "dict",
        "producer": "processors.seven_zip_validation",
        "description": "7-Zip test result with ok/encrypted/error fields.",
    },
    "relation.is_split_related": {
        "type": "bool",
        "producer": "relations.group_builder",
        "description": "Whether the candidate belongs to a split-volume relation.",
    },
    "file.is_split_candidate": {
        "type": "bool",
        "producer": "relations.group_builder",
        "description": "Whether the candidate name looks like a split-volume member.",
    },
    "file.split_role": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Split relation role, such as first/member.",
    },
    "file.split_members": {
        "type": "list[str]",
        "producer": "relations.group_builder",
        "description": "Other paths that belong to the same split group.",
    },
    "file.logical_name": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Logical archive/group name derived from related paths.",
    },
    "candidate.kind": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Logical candidate kind, such as file or split_archive.",
    },
    "candidate.entry_path": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Entry path used for detection and extraction of the logical candidate.",
    },
    "candidate.member_paths": {
        "type": "list[str]",
        "producer": "relations.group_builder",
        "description": "All filesystem paths belonging to the logical candidate.",
    },
    "candidate.logical_name": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Logical display/group name for the candidate.",
    },
    "relation.split_entry_path": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Preferred entry path for the split relation.",
    },
    "relation.split_member_count": {
        "type": "int",
        "producer": "relations.group_builder",
        "description": "Number of paths in the split relation candidate.",
    },
    "relation.split_group_complete": {
        "type": "bool",
        "producer": "relations.group_builder",
        "description": "Whether the relation layer considers the split group complete enough to represent.",
    },
    "relation.split_family": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Split naming family, such as 7z_numbered, rar_part, or exe_companion.",
    },
    "relation.split_index": {
        "type": "int",
        "producer": "relations.group_builder",
        "description": "Numeric index of the entry volume when available.",
    },
    "relation.split_is_first": {
        "type": "bool",
        "producer": "relations.group_builder",
        "description": "Whether the logical candidate entry is the first split volume.",
    },
    "relation.split_volumes": {
        "type": "list",
        "producer": "relations.group_builder",
        "description": "Structured split volume entries with path, inferred number, role, and naming style.",
    },
    "file.detected_ext": {
        "type": "str",
        "producer": "rules.scoring",
        "description": "Archive extension inferred from magic/probe/embedded evidence.",
    },
    "file.magic_matched": {
        "type": "bool",
        "producer": "rules.scoring",
        "description": "Whether archive identity matched a strong magic signature.",
    },
    "file.container_type": {
        "type": "str",
        "producer": "rules.confirmation.seven_zip_probe",
        "description": "Container type reported by 7-Zip probe, such as pe/elf/macho.",
    },
    "file.probe_detected_archive": {
        "type": "bool",
        "producer": "rules.scoring",
        "description": "Whether probe-like evidence indicates an archive.",
    },
    "file.probe_offset": {
        "type": "int",
        "producer": "rules.scoring",
        "description": "Offset where embedded/probed archive payload starts.",
    },
    "file.validation_ok": {
        "type": "bool",
        "producer": "rules.confirmation.seven_zip_validation",
        "description": "Whether 7-Zip validation passed.",
    },
    "file.validation_encrypted": {
        "type": "bool",
        "producer": "rules.confirmation.seven_zip_validation",
        "description": "Whether 7-Zip validation reported an encrypted archive.",
    },
    "file.embedded_archive_found": {
        "type": "bool",
        "producer": "rules.scoring.embedded_payload_identity",
        "description": "Whether a carrier/ambiguous resource contains an embedded archive payload.",
    },
    "embedded_archive.analysis": {
        "type": "dict",
        "producer": "processors.embedded_archive",
        "description": "Embedded archive scan result including found, detected_ext, offset, mode, and ZIP plausibility.",
    },
    "zip.local_header": {
        "type": "dict",
        "producer": "processors.zip_structure",
        "description": "ZIP local header plausibility at the beginning of the candidate file.",
    },
    "zip.local_header_plausible": {
        "type": "bool",
        "producer": "processors.zip_structure",
        "description": "Whether the embedded ZIP local header at the detected offset looks structurally plausible.",
    },
    "zip.local_header_offset": {
        "type": "int",
        "producer": "processors.zip_structure",
        "description": "Offset of the ZIP local header checked for embedded archive plausibility.",
    },
    "zip.local_header_error": {
        "type": "str",
        "producer": "processors.zip_structure",
        "description": "Reason why the embedded ZIP local header plausibility check failed, if any.",
    },
    "zip.eocd_structure": {
        "type": "dict",
        "producer": "processors.zip_eocd_structure",
        "description": "ZIP EOCD and central directory structure check derived from the candidate file.",
    },
    "tar.header_structure": {
        "type": "dict",
        "producer": "processors.tar_header_structure",
        "description": "TAR header checksum and ustar marker structure check derived from the candidate file.",
    },
    "compression.stream_structure": {
        "type": "dict",
        "producer": "processors.compression_stream_structure",
        "description": "Lightweight gzip, bzip2, xz, or zstd stream structure check derived from the candidate file.",
    },
    "archive.container_structure": {
        "type": "dict",
        "producer": "processors.archive_container_structure",
        "description": "Lightweight CAB, ARJ, or CPIO container structure check derived from the candidate file.",
    },
    "pe.overlay_structure": {
        "type": "dict",
        "producer": "processors.pe_overlay_structure",
        "description": "PE header, overlay range, and archive-like overlay evidence derived from the candidate file.",
    },
    "7z.structure": {
        "type": "dict",
        "producer": "processors.seven_zip_structure",
        "description": "7z signature, version, start-header CRC, next-header range, CRC, and first-NID checks.",
    },
    "rar.structure": {
        "type": "dict",
        "producer": "processors.rar_structure",
        "description": "RAR4/RAR5 signature, main-header CRC, and optional second block/header walk checks.",
    },
}


def known_fact_names() -> set[str]:
    return set(FACT_SCHEMA)


def register_fact_schema(fact_name: str, schema: dict[str, Any]):
    FACT_SCHEMA[fact_name] = dict(schema)


def get_fact_schema(fact_name: str) -> dict[str, Any] | None:
    return FACT_SCHEMA.get(fact_name)


def matches_schema_type(value: Any, type_name: str | list[str] | None) -> bool:
    if type_name is None:
        return True
    type_names = type_name if isinstance(type_name, list) else [type_name]
    return any(_matches_one_type(value, name) for name in type_names)


def _matches_one_type(value: Any, type_name: str) -> bool:
    if type_name == "any":
        return True
    if type_name == "str":
        return isinstance(value, str)
    if type_name == "int":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "bool":
        return isinstance(value, bool)
    if type_name == "bytes":
        return isinstance(value, bytes)
    if type_name == "dict":
        return isinstance(value, dict)
    if type_name == "list":
        return isinstance(value, list)
    if type_name == "list[str]":
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    if type_name == "list[dict]":
        return isinstance(value, list) and all(isinstance(item, dict) for item in value)
    if type_name == "dict[str,int]":
        return isinstance(value, dict) and all(isinstance(key, str) and isinstance(val, int) for key, val in value.items())
    if type_name == "dict[str,str]":
        return isinstance(value, dict) and all(isinstance(key, str) and isinstance(val, str) for key, val in value.items())
    return True
