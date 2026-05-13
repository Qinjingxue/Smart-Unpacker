use flate2::read::GzDecoder;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use sevenz_rust2::{
    Archive, ArchiveEntry, ArchiveWriter, BlockDecoder, EncoderConfiguration, EncoderMethod,
    Password,
};
use std::fs::{self, File};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const COPY_CHUNK_SIZE: usize = 1024 * 1024;
const SEVEN_Z_MAGIC: &[u8] = b"7z\xbc\xaf\x27\x1c";
const SEVEN_Z_HEADER_SIZE: usize = 32;
const SZ_END: u8 = 0x00;
const SZ_HEADER: u8 = 0x01;
const SZ_MAIN_STREAMS_INFO: u8 = 0x04;
const SZ_FILES_INFO: u8 = 0x05;
const SZ_PACK_INFO: u8 = 0x06;
const SZ_UNPACK_INFO: u8 = 0x07;
const SZ_SUB_STREAMS_INFO: u8 = 0x08;
const SZ_SIZE: u8 = 0x09;
const SZ_CRC: u8 = 0x0A;
const SZ_EMPTY_STREAM: u8 = 0x0E;
const SZ_EMPTY_FILE: u8 = 0x0F;
const SZ_ANTI: u8 = 0x10;
const SZ_ENCODED_HEADER: u8 = 0x17;
const SEVEN_Z_MAX_HEADER_STREAMS: usize = 4096;
const SEVEN_Z_MAX_HEADER_FILES: u64 = 100_000;
const RAR4_MAGIC: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5_MAGIC: &[u8] = b"Rar!\x1a\x07\x01\x00";

#[pyfunction]
#[pyo3(signature = (
    source_input,
    format,
    workspace,
    max_input_size_mb=512.0,
    max_candidates=8
))]
pub(crate) fn archive_carrier_crop_recovery(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    format: &str,
    workspace: &str,
    max_input_size_mb: f64,
    max_candidates: usize,
) -> PyResult<Py<PyDict>> {
    let target = TargetFormat::from_name(format);
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(
                py,
                "skipped",
                "",
                target.name(),
                &message,
                &[],
                0,
                0,
                0,
                0.0,
                &[],
            )
        }
    };

    let candidates = scan_archive_signatures(&data, target, true, max_candidates.max(1));
    if candidates.is_empty() {
        return status_dict(
            py,
            "unrepairable",
            "",
            target.name(),
            "no embedded archive signature passed structural checks",
            &[],
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    };

    let mut written = Vec::new();
    let mut write_warnings = Vec::new();
    for candidate in candidates {
        let output_path = Path::new(workspace).join(format!(
            "archive_carrier_crop_{:08x}{}",
            candidate.offset,
            candidate.format.ext()
        ));
        let output_bytes = match write_slice_candidate(&data[candidate.offset..], &output_path) {
            Ok(bytes) => bytes,
            Err(err) => {
                write_warnings.push(format!(
                    "candidate at offset {} could not be written: {err}",
                    candidate.offset
                ));
                continue;
            }
        };
        let mut warnings = candidate.warnings.clone();
        if candidate.offset == 0 {
            warnings.push("archive starts at offset 0; carrier crop was not needed".to_string());
        }
        written.push(WrittenArchiveCandidate {
            name: format!("carrier_crop_{:08x}", candidate.offset),
            path: output_path.to_string_lossy().to_string(),
            format: candidate.format.name().to_string(),
            status: "repaired".to_string(),
            offset: candidate.offset as u64,
            end_offset: data.len() as u64,
            output_bytes,
            confidence: confidence_for_candidate(&candidate),
            actions: vec!["crop_embedded_archive_from_carrier".to_string()],
            warnings,
        });
    }
    let Some(selected) = written.first() else {
        return status_dict(
            py,
            "unrepairable",
            "",
            target.name(),
            "embedded archive candidates were found but none could be written",
            &write_warnings,
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    };
    status_dict_with_candidates(
        py,
        "repaired",
        &selected.path,
        &selected.format,
        "embedded archive candidate was cropped from carrier bytes",
        &selected.warnings,
        selected.offset,
        data.len() as u64,
        selected.output_bytes,
        selected.confidence,
        &["crop_embedded_archive_from_carrier"],
        &written,
    )
}

#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    max_input_size_mb=512.0,
    max_candidates=8
))]
pub(crate) fn rar_block_chain_trim_recovery(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_candidates: usize,
) -> PyResult<Py<PyDict>> {
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(py, "skipped", "", "rar", &message, &[], 0, 0, 0, 0.0, &[])
        }
    };
    let walks = rar_walks(&data, max_candidates.max(1));
    if walks.is_empty() {
        return status_dict(
            py,
            "unrepairable",
            "",
            "rar",
            "no RAR block chain with valid leading block CRCs was found",
            &[],
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    };

    let mut written = Vec::new();
    let mut write_warnings = Vec::new();
    for walk in walks {
        if walk.last_complete_end <= walk.offset
            || (walk.offset == 0 && walk.last_complete_end == data.len())
        {
            continue;
        }

        let output_path =
            Path::new(workspace).join(format!("rar_block_chain_trim_{:08x}.rar", walk.offset));
        let output_bytes =
            match write_slice_candidate(&data[walk.offset..walk.last_complete_end], &output_path) {
                Ok(bytes) => bytes,
                Err(err) => {
                    write_warnings.push(format!(
                        "candidate at offset {} could not be written: {err}",
                        walk.offset
                    ));
                    continue;
                }
            };
        let status = if walk.end_block_found {
            "repaired"
        } else {
            "partial"
        };
        let action = match walk.version {
            RarVersion::Rar4 => "walk_rar4_block_chain_trim_boundary",
            RarVersion::Rar5 => "walk_rar5_block_chain_trim_boundary",
        };
        written.push(WrittenArchiveCandidate {
            name: format!("block_chain_trim_{:08x}", walk.offset),
            path: output_path.to_string_lossy().to_string(),
            format: "rar".to_string(),
            status: status.to_string(),
            offset: walk.offset as u64,
            end_offset: walk.last_complete_end as u64,
            output_bytes,
            confidence: if walk.end_block_found { 0.9 } else { 0.72 },
            actions: vec![action.to_string()],
            warnings: walk.warnings,
        });
    }

    let Some(selected) = written.first() else {
        let warnings = write_warnings;
        return status_dict(
            py,
            "unrepairable",
            "",
            "rar",
            "RAR block chains already end at the input boundary",
            &warnings,
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    };
    let action_refs = selected
        .actions
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    status_dict_with_candidates(
        py,
        &selected.status,
        &selected.path,
        "rar",
        "RAR block chain was cropped to the last complete CRC-verified block",
        &selected.warnings,
        selected.offset,
        selected.end_offset,
        selected.output_bytes,
        selected.confidence,
        &action_refs,
        &written,
    )
}

#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    max_input_size_mb=512.0,
    max_candidates=8
))]
pub(crate) fn rar_end_block_repair(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_candidates: usize,
) -> PyResult<Py<PyDict>> {
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(py, "skipped", "", "rar", &message, &[], 0, 0, 0, 0.0, &[])
        }
    };
    let walks = rar_walks(&data, max_candidates.max(1));
    if walks.is_empty() {
        return status_dict(
            py,
            "unrepairable",
            "",
            "rar",
            "no RAR block chain with valid leading block CRCs was found",
            &[],
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    };

    let mut written = Vec::new();
    let mut skipped_warnings = Vec::new();
    for walk in walks {
        if walk.end_block_found || walk.missing_volume || !walk.last_block_can_precede_end {
            skipped_warnings.extend(walk.warnings);
            continue;
        }

        let mut candidate = data[walk.offset..walk.last_complete_end].to_vec();
        let end_block = match walk.version {
            RarVersion::Rar4 => rar4_end_block(),
            RarVersion::Rar5 => rar5_end_block(),
        };
        candidate.extend_from_slice(&end_block);
        let output_path =
            Path::new(workspace).join(format!("rar_end_block_repair_{:08x}.rar", walk.offset));
        let output_bytes = match write_slice_candidate(&candidate, &output_path) {
            Ok(bytes) => bytes,
            Err(err) => {
                skipped_warnings.push(format!(
                    "candidate at offset {} could not be written: {err}",
                    walk.offset
                ));
                continue;
            }
        };
        let action = match walk.version {
            RarVersion::Rar4 => "append_rar4_end_block",
            RarVersion::Rar5 => "append_rar5_end_block",
        };
        let mut actions = vec![action.to_string()];
        if walk.last_complete_end < data.len() {
            actions.push("crop_trailing_bytes_before_end_block".to_string());
        }
        written.push(WrittenArchiveCandidate {
            name: format!("end_block_repair_{:08x}", walk.offset),
            path: output_path.to_string_lossy().to_string(),
            format: "rar".to_string(),
            status: "repaired".to_string(),
            offset: walk.offset as u64,
            end_offset: (walk.last_complete_end + end_block.len()) as u64,
            output_bytes,
            confidence: 0.82,
            actions,
            warnings: walk.warnings,
        });
    }

    let Some(selected) = written.first() else {
        return status_dict(
            py,
            "unrepairable",
            "",
            "rar",
            "RAR block chain is not safe for canonical end block synthesis",
            &skipped_warnings,
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    };
    let action_refs = selected
        .actions
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    status_dict_with_candidates(
        py,
        "repaired",
        &selected.path,
        "rar",
        "canonical RAR end block was appended after a complete CRC-verified block chain",
        &selected.warnings,
        selected.offset,
        selected.end_offset,
        selected.output_bytes,
        selected.confidence,
        &action_refs,
        &written,
    )
}

fn seven_zip_salvage_solid_prefix_native(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
    max_entries: usize,
) -> PyResult<Py<PyDict>> {
    let password = extract_password(source_input);
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(py, "skipped", "", "7z", &message, &[], 0, 0, 0, 0.0, &[])
        }
    };
    let recovered = match recover_seven_zip_entries_by_block(&data, max_entries.max(1), password.as_deref()) {
        Ok(entries) => entries,
        Err(message) => {
            let residual = password_residual_fact(&message, password.is_some());
            let residual_refs = residual.iter().map(String::as_str).collect::<Vec<_>>();
            return seven_zip_atomic_status(py, "unrepairable", "solid_prefix", "7z", "", &message, &[], &[], &[], 0.0, &residual_refs, &[])
        }
    };
    if recovered.is_empty() {
        return status_dict(
            py,
            "unrepairable",
            "",
            "7z",
            "no decodable 7z block entries were recoverable",
            &[],
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    }
    let output_path = Path::new(workspace).join("seven_zip_salvage_solid_prefix.7z");
    let output_bytes =
        match write_stored_7z_entries(&recovered, &output_path, mb_to_bytes(max_output_size_mb)) {
            Ok(bytes) => bytes,
            Err(message) => {
                return status_dict(
                    py,
                    "unrepairable",
                    "",
                    "7z",
                    &message,
                    &[],
                    0,
                    data.len() as u64,
                    0,
                    0.0,
                    &[],
                )
            }
        };
    let selected = WrittenArchiveCandidate {
        name: "seven_zip_salvage_solid_prefix".to_string(),
        path: output_path.to_string_lossy().to_string(),
        format: "7z".to_string(),
        status: "partial".to_string(),
        offset: 0,
        end_offset: data.len() as u64,
        output_bytes,
        confidence: (0.58 + recovered.len() as f64 * 0.04).min(0.88),
        actions: vec![
            "parse_7z_next_header_blocks".to_string(),
            "decode_7z_blocks_independently".to_string(),
            "repack_recoverable_entries_as_7z".to_string(),
        ],
        warnings: vec!["7z partial salvage container contains recovered files only".to_string()],
    };
    let result = status_dict_with_candidates(
        py,
        "partial",
        &selected.path,
        "7z",
        "7z block-level salvage recovered decodable entries into a 7z partial candidate",
        &selected.warnings,
        0,
        data.len() as u64,
        output_bytes,
        selected.confidence,
        &[
            "parse_7z_next_header_blocks",
            "decode_7z_blocks_independently",
            "repack_recoverable_entries_as_7z",
        ],
        &[selected.clone()],
    )?;
    result.bind(py).set_item("recovered_entry_count", recovered.len())?;
    Ok(result)
}

fn seven_zip_salvage_non_solid_entries_native(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
    max_entries: usize,
) -> PyResult<Py<PyDict>> {
    let password = extract_password(source_input);
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(py, "skipped", "", "7z", &message, &[], 0, 0, 0, 0.0, &[])
        }
    };
    let recovered = match recover_seven_zip_entries_by_block(&data, max_entries.max(1), password.as_deref()) {
        Ok(entries) => entries,
        Err(message) => {
            let residual = password_residual_fact(&message, password.is_some());
            let residual_refs = residual.iter().map(String::as_str).collect::<Vec<_>>();
            return seven_zip_atomic_status(py, "unrepairable", "non_solid_entries", "7z", "", &message, &[], &[], &[], 0.0, &residual_refs, &[])
        }
    };
    if recovered.is_empty() {
        return status_dict(
            py,
            "unrepairable",
            "",
            "7z",
            "no independently decodable non-solid 7z entries were recoverable",
            &[],
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    }
    let output_path = Path::new(workspace).join("seven_zip_salvage_non_solid_entries.7z");
    let output_bytes =
        match write_stored_7z_entries(&recovered, &output_path, mb_to_bytes(max_output_size_mb)) {
            Ok(bytes) => bytes,
            Err(message) => {
                return status_dict(
                    py,
                    "unrepairable",
                    "",
                    "7z",
                    &message,
                    &[],
                    0,
                    data.len() as u64,
                    0,
                    0.0,
                    &[],
                )
            }
        };
    let selected = WrittenArchiveCandidate {
        name: "seven_zip_salvage_non_solid_entries".to_string(),
        path: output_path.to_string_lossy().to_string(),
        format: "7z".to_string(),
        status: "partial".to_string(),
        offset: 0,
        end_offset: data.len() as u64,
        output_bytes,
        confidence: (0.62 + recovered.len() as f64 * 0.05).min(0.92),
        actions: vec![
            "parse_7z_folder_streams".to_string(),
            "decode_independent_7z_entries".to_string(),
            "quarantine_failed_7z_entries".to_string(),
            "repack_recoverable_entries_as_7z".to_string(),
        ],
        warnings: vec![
            "7z partial salvage container contains recovered files only".to_string(),
        ],
    };
    let result = status_dict_with_candidates(
        py,
        "partial",
        &selected.path,
        "7z",
        "7z non-solid partial salvage recovered independently decodable entries into a 7z partial candidate",
        &selected.warnings,
        0,
        data.len() as u64,
        output_bytes,
        selected.confidence,
        &[
            "parse_7z_folder_streams",
            "decode_independent_7z_entries",
            "quarantine_failed_7z_entries",
            "repack_recoverable_entries_as_7z",
        ],
        &[selected.clone()],
    )?;
    result.bind(py).set_item("recovered_entry_count", recovered.len())?;
    Ok(result)
}

#[pyfunction]
#[pyo3(signature = (
    source_input,
    max_input_size_mb=512.0,
    max_scan_bytes=1048576,
    max_candidates=8
))]
pub(crate) fn seven_zip_scan_source(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    max_input_size_mb: f64,
    max_scan_bytes: usize,
    max_candidates: usize,
) -> PyResult<Py<PyDict>> {
    let password = extract_password(source_input);
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => return seven_zip_scan_error(py, "skipped", &message),
    };
    let password_status = seven_zip_password_status(&data, password.as_deref());
    let result = PyDict::new(py);
    result.set_item("status", "ok")?;
    result.set_item("native_key", "native_7z_scan_source")?;
    result.set_item("native_target", "seven_zip_scan_source")?;
    result.set_item("format", "7z")?;
    result.set_item("input_size", data.len() as u64)?;
    result.set_item("password_present", password.is_some())?;

    let offsets = find_all(&data, SEVEN_Z_MAGIC);
    result.set_item("signature_count", offsets.len())?;
    result.set_item("signature_offsets", PyList::new(py, offsets.iter().take(max_candidates.max(1)).copied().collect::<Vec<_>>())?)?;
    let Some(offset) = offsets.first().copied() else {
        result.set_item("route_evidence_flags", PyList::new(py, ["seven_zip_signature_missing"])?)?;
        result.set_item("structure", PyDict::new(py))?;
        result.set_item("candidates", PyList::empty(py))?;
        return Ok(result.unbind());
    };

    let loose = loose_seven_zip_header_facts(&data, offset);
    let header = parse_seven_zip_header(&data, offset);
    let candidates = scan_archive_signatures(&data, TargetFormat::SevenZip, false, max_candidates.max(1));
    let candidate_list = PyList::empty(py);
    for candidate in &candidates {
        let item = PyDict::new(py);
        item.set_item("offset", candidate.offset)?;
        item.set_item("archive_end", candidate.archive_end)?;
        item.set_item("start_crc_ok", candidate.start_crc_ok)?;
        item.set_item("next_header_crc_ok", candidate.next_header_crc_ok)?;
        item.set_item("warnings", PyList::new(py, &candidate.warnings)?)?;
        candidate_list.append(item)?;
    }
    result.set_item("candidates", candidate_list)?;

    let structure = PyDict::new(py);
    structure.set_item("password_present", password.is_some())?;
    structure.set_item("password_required", password_status.password_required)?;
    structure.set_item("password_rejected", password_status.password_rejected)?;
    structure.set_item("archive_readable_with_password", password_status.archive_readable)?;
    structure.set_item("encrypted_header", password_status.encrypted_header)?;
    if let Some(message) = password_status.message.as_ref() {
        structure.set_item("password_diagnostic", message)?;
    }
    structure.set_item("signature_offset", offset)?;
    if offset + 8 <= data.len() {
        let major = data[offset + 6];
        let minor = data[offset + 7];
        structure.set_item("signature_header_major_version", major)?;
        structure.set_item("signature_header_minor_version", minor)?;
        structure.set_item("signature_header_version_bad", major != 0 || minor > 4)?;
    }
    structure.set_item("carrier_prefix_bytes", offset)?;
    structure.set_item("has_carrier_prefix", offset > 0)?;
    structure.set_item("stored_next_header_offset", loose.next_header_offset)?;
    structure.set_item("stored_next_header_size", loose.next_header_size)?;
    structure.set_item("stored_start_crc", loose.stored_start_crc)?;
    structure.set_item("computed_start_crc", loose.computed_start_crc)?;
    structure.set_item("start_crc_ok", loose.start_crc_ok)?;
    structure.set_item("next_header_range_valid", loose.range_valid)?;
    structure.set_item("next_header_out_of_range", !loose.range_valid)?;
    if let Some(header) = &header {
        structure.set_item("archive_end", header.archive_end)?;
        structure.set_item("trailing_bytes", data.len().saturating_sub(header.archive_end))?;
        structure.set_item("next_header_start", header.next_header_start)?;
        structure.set_item("next_header_offset", header.next_header_offset)?;
        structure.set_item("next_header_size", header.next_header_size)?;
        structure.set_item("stored_next_header_crc", header.stored_next_header_crc)?;
        structure.set_item("computed_next_header_crc", header.computed_next_header_crc)?;
        structure.set_item("next_header_nid", header.next_header_nid)?;
        structure.set_item("next_header_crc_ok", header.next_header_crc_ok())?;
        structure.set_item("next_header_nid_valid", header.next_header_nid_valid)?;
        structure.set_item("encoded_header_present", header.next_header_nid == SZ_ENCODED_HEADER)?;
        let ast_for_scan = if header.next_header_nid == SZ_ENCODED_HEADER {
            parse_seven_zip_encoded_header_ast(&data, header)
        } else {
            parse_seven_zip_header_ast(&data, header)
        };
        if let Ok(ast) = ast_for_scan {
            if let Some(pack) = ast.pack_info.as_ref() {
                structure.set_item("pack_stream_count", pack.num_streams)?;
                structure.set_item("pack_stream_offset", pack.pack_pos.value)?;
                structure.set_item("pack_stream_offset_bad", pack.pack_pos.value != 0)?;
                let pack_sizes = pack.sizes.iter().map(|item| item.value).collect::<Vec<_>>();
                structure.set_item("pack_stream_sizes", PyList::new(py, pack_sizes)?)?;
                if pack.num_streams == 1 && pack.sizes.len() == 1 {
                    let expected_size = header.next_header_offset.checked_sub(pack.pack_pos.value).unwrap_or(0);
                    structure.set_item("pack_stream_size_expected", expected_size)?;
                    structure.set_item("pack_stream_size_bad", expected_size > 0 && expected_size != pack.sizes[0].value)?;
                    if pack.crc_values.len() == 1 && pack.crc_defined_all {
                        let stream_start = SEVEN_Z_HEADER_SIZE
                            .checked_add(usize::try_from(pack.pack_pos.value).unwrap_or(usize::MAX))
                            .unwrap_or(usize::MAX);
                        let stream_size = usize::try_from(pack.sizes[0].value).unwrap_or(usize::MAX);
                        let stream_end = stream_start.checked_add(stream_size).unwrap_or(usize::MAX);
                        if stream_start >= SEVEN_Z_HEADER_SIZE && stream_end <= data.len() && stream_end <= header.next_header_start {
                            let computed_crc = crc32(&data[stream_start..stream_end]);
                            structure.set_item("computed_stream_crc", computed_crc)?;
                            structure.set_item("stored_stream_crc", pack.crc_values[0].value)?;
                            if header.next_header_nid == SZ_ENCODED_HEADER {
                                structure.set_item("encoded_header_stream_crc_bad", computed_crc != pack.crc_values[0].value)?;
                            } else {
                                structure.set_item("stream_crc_bad", computed_crc != pack.crc_values[0].value)?;
                            }
                        }
                    }
                }
            }
            if let Some(files) = ast.files_info.as_ref() {
                structure.set_item("file_count_metadata", files.num_files.value)?;
                structure.set_item("empty_stream_property_present", files.empty_stream_property.is_some())?;
                structure.set_item("empty_file_property_present", files.empty_file_property.is_some())?;
                structure.set_item("anti_item_property_present", files.anti_property.is_some())?;
            }
        }
    } else {
        structure.set_item("archive_end", 0)?;
        structure.set_item("trailing_bytes", 0)?;
        structure.set_item("next_header_crc_ok", false)?;
        structure.set_item("next_header_nid_valid", false)?;
        structure.set_item("encoded_header_present", false)?;
    }
    let needs_header_candidate_scan = !loose.range_valid
        || header
            .as_ref()
            .is_none_or(|item| !item.next_header_nid_valid);
    if needs_header_candidate_scan {
        if let Some((offset_candidate, size_candidate)) = find_next_header_candidate(&data[offset..], max_scan_bytes.max(1)) {
            structure.set_item("encoded_header_candidate_found", true)?;
            structure.set_item("encoded_header_candidate_offset", offset_candidate)?;
            structure.set_item("encoded_header_candidate_size", size_candidate)?;
        } else {
            structure.set_item("encoded_header_candidate_found", false)?;
        }
    } else {
        structure.set_item("encoded_header_candidate_found", false)?;
    }
    structure.set_item("encoded_header_decodable", false)?;
    structure.set_item("encoded_header_stream_crc_bad", false)?;
    if !structure.contains("pack_stream_offset_bad")? {
        structure.set_item("pack_stream_offset_bad", false)?;
    }
    if !structure.contains("pack_stream_size_bad")? {
        structure.set_item("pack_stream_size_bad", false)?;
    }
    structure.set_item("unpack_size_bad", false)?;
    if !structure.contains("stream_crc_bad")? {
        structure.set_item("stream_crc_bad", false)?;
    }
    structure.set_item("substream_crc_bad", false)?;
    structure.set_item("empty_stream_flags_bad", false)?;
    structure.set_item("empty_file_flags_bad", false)?;
    structure.set_item("anti_item_flags_bad", false)?;
    structure.set_item("folder_bind_pairs_bad", false)?;
    structure.set_item("folder_stream_counts_bad", false)?;
    structure.set_item("file_count_metadata_bad", false)?;
    structure.set_item("file_names_utf16_bad", false)?;
    structure.set_item("unreferenced_folder", false)?;
    structure.set_item("unreferenced_file_record", false)?;
    structure.set_item("invalid_stream_crc_defined_flag", false)?;
    structure.set_item("bad_folder_detected", false)?;
    structure.set_item("verified_folder_available", false)?;
    result.set_item("structure", structure)?;

    let mut route_flags = seven_zip_route_flags(&data, offset, header.as_ref(), &loose);
    if password_status.password_required {
        push_unique_string(&mut route_flags, "password_required");
        push_unique_string(&mut route_flags, "encrypted_header");
    }
    if password_status.password_rejected {
        push_unique_string(&mut route_flags, "wrong_password");
        push_unique_string(&mut route_flags, "encrypted_header");
    }
    result.set_item("route_evidence_flags", PyList::new(py, &route_flags)?)?;
    result.set_item("container_tags", PyList::new(py, seven_zip_container_tags(offset, header.as_ref(), data.len()))?)?;
    Ok(result.unbind())
}

#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    target,
    max_input_size_mb=512.0,
    max_scan_bytes=1048576,
    max_output_size_mb=2048.0,
    max_entries=20000,
    max_candidates=8
))]
pub(crate) fn seven_zip_atomic_repair(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    target: &str,
    max_input_size_mb: f64,
    max_scan_bytes: usize,
    max_output_size_mb: f64,
    max_entries: usize,
    max_candidates: usize,
) -> PyResult<Py<PyDict>> {
    match target {
        "encoded_header_decode"
        | "unpack_size"
        | "bad_folder_quarantine"
        | "file_names_utf16"
        | "unreferenced_folder"
        | "unreferenced_file_record"
        | "stream_crc_defined_flag"
        | "folder_bind_pairs"
        | "folder_stream_counts"
        | "file_count_metadata" => return seven_zip_metadata_target_not_materialized(py, target),
        _ => {}
    }
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => return seven_zip_atomic_status(py, "skipped", target, "7z", "", &message, &[], &[], &[], 0.0, &[], &[]),
    };
    match target {
        "trailing_junk" => seven_zip_repair_boundary_target(py, &data, workspace, target, false, max_candidates),
        "carrier_prefix" => seven_zip_repair_boundary_target(py, &data, workspace, target, true, max_candidates),
        "signature_header_version" => seven_zip_repair_signature_header_version(py, &data, workspace, target),
        "start_header_crc" => seven_zip_repair_crc_target(py, &data, workspace, target),
        "next_header_crc" => seven_zip_repair_crc_target(py, &data, workspace, target),
        "next_header_offset" => seven_zip_repair_next_header_target(py, &data, workspace, target, max_scan_bytes),
        "next_header_size" => seven_zip_repair_next_header_target(py, &data, workspace, target, max_scan_bytes),
        "next_header_repoint" => seven_zip_repair_next_header_target(py, &data, workspace, target, max_scan_bytes),
        "pack_stream_offset"
        | "pack_stream_size"
        | "stream_crc"
        | "encoded_header_stream_crc"
        | "empty_stream_flags" => seven_zip_repair_metadata_target(py, &data, workspace, target),
        "non_solid_entries" => {
            let result = seven_zip_salvage_non_solid_entries_native(py, source_input, workspace, max_input_size_mb, max_output_size_mb, max_entries)?;
            set_seven_zip_atomic_fields(py, &result, target, &["salvaged_non_solid_entries", "source_format=7z", "output_container=7z", "partial=true", "repacked_recovered_entries_as_7z"], &["partial_recovery_remaining"])?;
            Ok(result)
        }
        "solid_prefix" => {
            let result = seven_zip_salvage_solid_prefix_native(py, source_input, workspace, max_input_size_mb, max_output_size_mb, max_entries)?;
            set_seven_zip_atomic_fields(py, &result, target, &["salvaged_solid_prefix", "source_format=7z", "output_container=7z", "partial=true", "repacked_recovered_entries_as_7z"], &["partial_recovery_remaining"])?;
            Ok(result)
        }
        _ => seven_zip_atomic_status(py, "target_mismatch", target, "7z", "", "unsupported 7z atomic repair target", &[], &[], &[], 0.0, &[], &[]),
    }
}

#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    max_input_size_mb=512.0,
    max_candidates=8
))]
pub(crate) fn rar_file_quarantine_rebuild(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_candidates: usize,
) -> PyResult<Py<PyDict>> {
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(py, "skipped", "", "rar", &message, &[], 0, 0, 0, 0.0, &[])
        }
    };
    let candidates =
        rebuild_rar_file_quarantine_candidates(&data, workspace, max_candidates.max(1));
    let Some(selected) = candidates.first() else {
        return status_dict(
            py,
            "unrepairable",
            "",
            "rar",
            "no complete RAR file blocks were available for quarantine rebuild",
            &[],
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    };
    let action_refs = selected
        .actions
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    status_dict_with_candidates(
        py,
        &selected.status,
        &selected.path,
        "rar",
        "RAR file-level quarantine produced a candidate with complete file blocks only",
        &selected.warnings,
        selected.offset,
        selected.end_offset,
        selected.output_bytes,
        selected.confidence,
        &action_refs,
        &candidates,
    )
}

#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    max_input_size_mb=512.0,
    max_candidates=8
))]
pub(crate) fn archive_nested_payload_salvage(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_candidates: usize,
) -> PyResult<Py<PyDict>> {
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(
                py,
                "skipped",
                "",
                "archive",
                &message,
                &[],
                0,
                0,
                0,
                0.0,
                &[],
            )
        }
    };
    let candidates = nested_archive_candidates(&data, workspace, max_candidates.max(1));
    let Some(selected) = candidates.first() else {
        return status_dict(
            py,
            "unrepairable",
            "",
            "archive",
            "no nested archive payload candidate was found",
            &[],
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    };
    let action_refs = selected
        .actions
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    status_dict_with_candidates(
        py,
        "partial",
        &selected.path,
        &selected.format,
        "nested archive payload was salvaged from a damaged container",
        &selected.warnings,
        selected.offset,
        selected.end_offset,
        selected.output_bytes,
        selected.confidence,
        &action_refs,
        &candidates,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetFormat {
    SevenZip,
    Rar,
    Zip,
    Any,
}

impl TargetFormat {
    fn from_name(value: &str) -> Self {
        match value
            .trim()
            .trim_start_matches('.')
            .to_ascii_lowercase()
            .as_str()
        {
            "7z" | "seven_zip" | "sevenzip" => Self::SevenZip,
            "rar" => Self::Rar,
            "zip" => Self::Zip,
            _ => Self::Any,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::SevenZip => "7z",
            Self::Rar => "rar",
            Self::Zip => "zip",
            Self::Any => "archive",
        }
    }

    fn ext(self) -> &'static str {
        match self {
            Self::SevenZip => ".7z",
            Self::Rar => ".rar",
            Self::Zip => ".zip",
            Self::Any => ".bin",
        }
    }
}

struct ArchiveCandidate {
    format: TargetFormat,
    offset: usize,
    archive_end: usize,
    start_crc_ok: bool,
    next_header_crc_ok: bool,
    warnings: Vec<String>,
}

struct SevenZipHeader {
    archive_end: usize,
    start_header: [u8; 20],
    next_header_start: usize,
    next_header_offset: u64,
    next_header_size: u64,
    next_header_nid: u8,
    stored_start_crc: u32,
    computed_start_crc: u32,
    stored_next_header_crc: u32,
    computed_next_header_crc: u32,
    next_header_nid_valid: bool,
}

struct SevenZipLooseHeaderFacts {
    stored_start_crc: u32,
    computed_start_crc: u32,
    start_crc_ok: bool,
    next_header_offset: u64,
    next_header_size: u64,
    range_valid: bool,
}

#[derive(Clone, Copy)]
struct SevenZipVintSpan {
    start: usize,
    end: usize,
    value: u64,
}

#[derive(Clone, Copy)]
struct SevenZipCrcSpan {
    start: usize,
    value: u32,
}

struct SevenZipPackInfoAst {
    pack_pos: SevenZipVintSpan,
    num_streams: usize,
    sizes: Vec<SevenZipVintSpan>,
    crc_values: Vec<SevenZipCrcSpan>,
    crc_defined_all: bool,
}

struct SevenZipFilesInfoAst {
    num_files: SevenZipVintSpan,
    empty_stream_property: Option<(usize, usize)>,
    empty_file_property: Option<(usize, usize)>,
    anti_property: Option<(usize, usize)>,
}

struct SevenZipHeaderAst {
    header: Vec<u8>,
    pack_info: Option<SevenZipPackInfoAst>,
    files_info: Option<SevenZipFilesInfoAst>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RarVersion {
    Rar4,
    Rar5,
}

struct RarWalk {
    version: RarVersion,
    offset: usize,
    last_complete_end: usize,
    end_block_found: bool,
    missing_volume: bool,
    last_block_can_precede_end: bool,
    warnings: Vec<String>,
}

#[derive(Clone)]
struct WrittenArchiveCandidate {
    name: String,
    path: String,
    format: String,
    status: String,
    offset: u64,
    end_offset: u64,
    output_bytes: u64,
    confidence: f64,
    actions: Vec<String>,
    warnings: Vec<String>,
}

fn scan_archive_signatures(
    data: &[u8],
    target: TargetFormat,
    require_carrier_offset: bool,
    max_candidates: usize,
) -> Vec<ArchiveCandidate> {
    let mut output = Vec::new();
    if matches!(target, TargetFormat::SevenZip | TargetFormat::Any) {
        for offset in find_all(data, SEVEN_Z_MAGIC) {
            if require_carrier_offset && offset == 0 {
                continue;
            }
            if let Some(candidate) = seven_zip_candidate(data, offset) {
                output.push(candidate);
                if output.len() >= max_candidates {
                    return output;
                }
            }
        }
    }
    if matches!(target, TargetFormat::Zip | TargetFormat::Any) {
        for offset in find_all(data, b"PK\x03\x04") {
            if require_carrier_offset && offset == 0 {
                continue;
            }
            if let Some(candidate) = zip_carrier_candidate(data, offset) {
                output.push(candidate);
                if output.len() >= max_candidates {
                    return output;
                }
            }
        }
    }
    if matches!(target, TargetFormat::Rar | TargetFormat::Any) {
        for offset in find_all(data, RAR4_MAGIC) {
            if require_carrier_offset && offset == 0 {
                continue;
            }
            if let Some(candidate) = rar4_candidate(data, offset) {
                output.push(candidate);
                if output.len() >= max_candidates {
                    return output;
                }
            }
        }
        for offset in find_all(data, RAR5_MAGIC) {
            if require_carrier_offset && offset == 0 {
                continue;
            }
            if let Some(candidate) = rar5_candidate(data, offset) {
                output.push(candidate);
                if output.len() >= max_candidates {
                    return output;
                }
            }
        }
    }
    output.sort_by_key(|candidate| candidate.offset);
    output
}

fn seven_zip_candidate(data: &[u8], offset: usize) -> Option<ArchiveCandidate> {
    let header = parse_seven_zip_header(data, offset)?;
    if !header.start_crc_ok() || !header.next_header_nid_valid {
        return None;
    }
    let mut warnings = Vec::new();
    if !header.next_header_crc_ok() {
        warnings.push(
            "7z NextHeader CRC is invalid; crop candidate requires later CRC repair".to_string(),
        );
    }
    Some(ArchiveCandidate {
        format: TargetFormat::SevenZip,
        offset,
        archive_end: header.archive_end,
        start_crc_ok: header.start_crc_ok(),
        next_header_crc_ok: header.next_header_crc_ok(),
        warnings,
    })
}

fn loose_seven_zip_header_facts(data: &[u8], offset: usize) -> SevenZipLooseHeaderFacts {
    if offset.checked_add(SEVEN_Z_HEADER_SIZE).is_none_or(|end| end > data.len()) {
        return SevenZipLooseHeaderFacts {
            stored_start_crc: 0,
            computed_start_crc: 0,
            start_crc_ok: false,
            next_header_offset: 0,
            next_header_size: 0,
            range_valid: false,
        };
    }
    let stored_start_crc = u32_le(data, offset + 8);
    let mut start_header = [0u8; 20];
    start_header.copy_from_slice(&data[offset + 12..offset + 32]);
    let computed_start_crc = crc32(&start_header);
    let next_header_offset = u64_le(&start_header, 0);
    let next_header_size = u64_le(&start_header, 8);
    let range_valid = (|| {
        let relative_end = (SEVEN_Z_HEADER_SIZE as u64)
            .checked_add(next_header_offset)?
            .checked_add(next_header_size)?;
        let archive_end = offset.checked_add(usize::try_from(relative_end).ok()?)?;
        if next_header_size == 0 || archive_end > data.len() {
            return None;
        }
        let next_header_start = offset
            .checked_add(SEVEN_Z_HEADER_SIZE)?
            .checked_add(usize::try_from(next_header_offset).ok()?)?;
        if next_header_start >= archive_end {
            return None;
        }
        Some(())
    })()
    .is_some();
    SevenZipLooseHeaderFacts {
        stored_start_crc,
        computed_start_crc,
        start_crc_ok: stored_start_crc == computed_start_crc,
        next_header_offset,
        next_header_size,
        range_valid,
    }
}

fn seven_zip_route_flags(
    data: &[u8],
    offset: usize,
    header: Option<&SevenZipHeader>,
    loose: &SevenZipLooseHeaderFacts,
) -> Vec<String> {
    let mut flags = vec!["seven_zip_signature_found".to_string()];
    if offset + 8 <= data.len() && (data[offset + 6] != 0 || data[offset + 7] > 4) {
        flags.push("signature_header_version_bad".to_string());
    }
    if offset > 0 {
        flags.extend([
            "carrier_prefix".to_string(),
            "carrier_archive".to_string(),
            "embedded_archive".to_string(),
        ]);
    }
    if !loose.start_crc_ok {
        flags.push("start_header_crc_bad".to_string());
    }
    if !loose.range_valid {
        flags.push("next_header_out_of_range".to_string());
    }
    if let Some(header) = header {
        if header.archive_end < data.len() {
            flags.push("trailing_junk".to_string());
        }
        if !header.next_header_crc_ok() {
            flags.push("next_header_crc_bad".to_string());
        }
        if header.next_header_nid == SZ_ENCODED_HEADER {
            flags.push("encoded_header_present".to_string());
        }
        if !header.next_header_nid_valid {
            flags.push("encoded_header_unreadable".to_string());
        }
        let ast_for_route = if header.next_header_nid == SZ_ENCODED_HEADER {
            parse_seven_zip_encoded_header_ast(data, header)
        } else {
            parse_seven_zip_header_ast(data, header)
        };
        if let Ok(ast) = ast_for_route {
            if let Some(pack) = ast.pack_info.as_ref() {
                if pack.pack_pos.value != 0 {
                    flags.push("pack_stream_offset_bad".to_string());
                }
                if pack.num_streams == 1 && pack.sizes.len() == 1 {
                    let expected_size = header.next_header_offset.checked_sub(pack.pack_pos.value).unwrap_or(0);
                    if expected_size > 0 && expected_size != pack.sizes[0].value {
                        flags.push("pack_stream_size_bad".to_string());
                    }
                    if pack.crc_values.len() == 1 && pack.crc_defined_all {
                        let stream_start = SEVEN_Z_HEADER_SIZE
                            .checked_add(usize::try_from(pack.pack_pos.value).unwrap_or(usize::MAX))
                            .unwrap_or(usize::MAX);
                        let stream_size = usize::try_from(pack.sizes[0].value).unwrap_or(usize::MAX);
                        let stream_end = stream_start.checked_add(stream_size).unwrap_or(usize::MAX);
                        if stream_start >= SEVEN_Z_HEADER_SIZE && stream_end <= data.len() && stream_end <= header.next_header_start {
                            let computed_crc = crc32(&data[stream_start..stream_end]);
                            if computed_crc != pack.crc_values[0].value {
                                if header.next_header_nid == SZ_ENCODED_HEADER {
                                    flags.push("encoded_header_stream_crc_bad".to_string());
                                } else {
                                    flags.push("stream_crc_bad".to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    flags
}

fn seven_zip_container_tags(offset: usize, header: Option<&SevenZipHeader>, input_len: usize) -> Vec<String> {
    let mut tags = vec!["7z".to_string()];
    if offset > 0 {
        tags.push("carrier_prefix".to_string());
        tags.push("embedded_archive".to_string());
    }
    if header.is_some_and(|item| item.archive_end < input_len) {
        tags.push("trailing_junk".to_string());
    }
    tags
}

fn rar4_candidate(data: &[u8], offset: usize) -> Option<ArchiveCandidate> {
    let first = offset.checked_add(RAR4_MAGIC.len())?;
    if first.checked_add(7)? > data.len() {
        return None;
    }
    let stored_crc = u16_le(data, first) as u32;
    let header_type = data[first + 2];
    let flags = u16_le(data, first + 3);
    let header_size = u16_le(data, first + 5) as usize;
    if !matches!(header_type, 0x73..=0x7b)
        || header_size < 7
        || first.checked_add(header_size)? > data.len()
    {
        return None;
    }
    let header = &data[first..first + header_size];
    if (crc32(&header[2..]) & 0xffff) != stored_crc {
        return None;
    }
    let mut archive_end = data.len();
    if flags & 0x8000 != 0 {
        if header_size < 11 {
            return None;
        }
        let add_size = u32_le(header, 7) as usize;
        archive_end = first.checked_add(header_size)?.checked_add(add_size)?;
        if archive_end > data.len() {
            return None;
        }
    }
    Some(ArchiveCandidate {
        format: TargetFormat::Rar,
        offset,
        archive_end,
        start_crc_ok: true,
        next_header_crc_ok: true,
        warnings: Vec::new(),
    })
}

fn zip_carrier_candidate(data: &[u8], offset: usize) -> Option<ArchiveCandidate> {
    // Verify a valid ZIP exists after the carrier prefix
    // by searching for the EOCD record to confirm archive bounds
    let eocd_pos = find_eocd_from(&data[offset..])?;
    let absolute_eocd = offset + eocd_pos;
    if absolute_eocd + 22 > data.len() {
        return None;
    }
    let cd_size = u32_le(data, absolute_eocd + 12) as usize;
    let cd_offset = u32_le(data, absolute_eocd + 16) as usize;
    let comment_len = u16_le(data, absolute_eocd + 20) as usize;
    let archive_end = absolute_eocd + 22 + comment_len;
    if archive_end > data.len() {
        return None;
    }
    let absolute_cd_offset = offset.checked_add(cd_offset)?;
    // ZIP EOCD central-directory offsets are relative to the embedded ZIP
    // start, not the outer carrier file.
    if absolute_cd_offset < offset || absolute_cd_offset.checked_add(cd_size)? > absolute_eocd {
        return None;
    }
    Some(ArchiveCandidate {
        format: TargetFormat::Zip,
        offset,
        archive_end,
        start_crc_ok: true,
        next_header_crc_ok: true,
        warnings: Vec::new(),
    })
}

fn find_eocd_from(data: &[u8]) -> Option<usize> {
    let needle = b"PK\x05\x06";
    let mut pos = data.len().checked_sub(needle.len())?;
    loop {
        if &data[pos..pos + needle.len()] == needle {
            return Some(pos);
        }
        if pos == 0 {
            return None;
        }
        pos -= 1;
    }
}

fn rar5_candidate(data: &[u8], offset: usize) -> Option<ArchiveCandidate> {
    let first = offset.checked_add(RAR5_MAGIC.len())?;
    if first.checked_add(6)? > data.len() {
        return None;
    }
    let stored_crc = u32_le(data, first);
    let (header_size, after_size) = read_vint(data, first + 4)?;
    let total_size = 4usize
        .checked_add(after_size.checked_sub(first + 4)?)?
        .checked_add(usize::try_from(header_size).ok()?)?;
    let end = first.checked_add(total_size)?;
    if header_size == 0 || end > data.len() {
        return None;
    }
    let header_data = &data[first + 4..end];
    if crc32(header_data) != stored_crc {
        return None;
    }
    let (header_type, _) = read_vint(data, after_size)?;
    if !matches!(header_type, 1..=5) {
        return None;
    }
    Some(ArchiveCandidate {
        format: TargetFormat::Rar,
        offset,
        archive_end: data.len(),
        start_crc_ok: true,
        next_header_crc_ok: true,
        warnings: Vec::new(),
    })
}

fn parse_seven_zip_header(data: &[u8], offset: usize) -> Option<SevenZipHeader> {
    if offset.checked_add(SEVEN_Z_HEADER_SIZE)? > data.len()
        || !data[offset..].starts_with(SEVEN_Z_MAGIC)
    {
        return None;
    }
    if data[offset + 6] != 0 {
        return None;
    }
    let stored_start_crc = u32_le(data, offset + 8);
    let mut start_header = [0u8; 20];
    start_header.copy_from_slice(&data[offset + 12..offset + 32]);
    let computed_start_crc = crc32(&start_header);
    let next_header_offset = u64_le(&start_header, 0);
    let next_header_size = u64_le(&start_header, 8);
    let stored_next_header_crc = u32_le(&start_header, 16);
    if next_header_size == 0 {
        return None;
    }
    let relative_end = (SEVEN_Z_HEADER_SIZE as u64)
        .checked_add(next_header_offset)?
        .checked_add(next_header_size)?;
    let archive_end = offset.checked_add(usize::try_from(relative_end).ok()?)?;
    if archive_end > data.len() {
        return None;
    }
    let next_header_start = offset
        .checked_add(SEVEN_Z_HEADER_SIZE)?
        .checked_add(usize::try_from(next_header_offset).ok()?)?;
    if next_header_start >= archive_end {
        return None;
    }
    let next_header = &data[next_header_start..archive_end];
    let computed_next_header_crc = crc32(next_header);
    let nid = next_header.first().copied().unwrap_or(0);
    Some(SevenZipHeader {
        archive_end,
        start_header,
        next_header_start,
        next_header_offset,
        next_header_size,
        next_header_nid: nid,
        stored_start_crc,
        computed_start_crc,
        stored_next_header_crc,
        computed_next_header_crc,
        next_header_nid_valid: nid == SZ_HEADER || nid == SZ_ENCODED_HEADER,
    })
}

impl SevenZipHeader {
    fn start_crc_ok(&self) -> bool {
        self.stored_start_crc == self.computed_start_crc
    }

    fn next_header_crc_ok(&self) -> bool {
        self.stored_next_header_crc == self.computed_next_header_crc
    }
}

fn read_sz_vint(data: &[u8], pos: &mut usize) -> Option<SevenZipVintSpan> {
    let start = *pos;
    let first = *data.get(*pos)?;
    *pos += 1;
    let mut mask = 0x80u8;
    let mut value = 0u64;
    for extra in 0..8 {
        if first & mask == 0 {
            let low_mask = mask.saturating_sub(1);
            value |= ((first & low_mask) as u64) << (8 * extra);
            return Some(SevenZipVintSpan {
                start,
                end: *pos,
                value,
            });
        }
        let byte = *data.get(*pos)? as u64;
        *pos += 1;
        value |= byte << (8 * extra);
        mask >>= 1;
    }
    Some(SevenZipVintSpan {
        start,
        end: *pos,
        value,
    })
}

fn write_sz_vint(mut value: u64) -> Vec<u8> {
    let mut first = 0u8;
    let mut mask = 0x80u8;
    let mut extra = 0usize;
    while extra < 8 {
        if value < (1u64 << (7 * (extra + 1))) {
            first |= (value >> (8 * extra)) as u8;
            break;
        }
        first |= mask;
        mask >>= 1;
        extra += 1;
    }
    let mut output = vec![first];
    while extra > 0 {
        output.push((value & 0xff) as u8);
        value >>= 8;
        extra -= 1;
    }
    output
}

fn replace_header_vint(header: &[u8], span: SevenZipVintSpan, value: u64) -> Vec<u8> {
    let mut output = Vec::with_capacity(header.len() + 4);
    output.extend_from_slice(&header[..span.start]);
    output.extend_from_slice(&write_sz_vint(value));
    output.extend_from_slice(&header[span.end..]);
    output
}

fn replace_header_u32_le(header: &[u8], start: usize, value: u32) -> Vec<u8> {
    let mut output = header.to_vec();
    if start + 4 <= output.len() {
        output[start..start + 4].copy_from_slice(&value.to_le_bytes());
    }
    output
}

fn parse_seven_zip_header_ast(data: &[u8], header: &SevenZipHeader) -> Result<SevenZipHeaderAst, String> {
    if header.next_header_nid != SZ_HEADER {
        return Err("7z next header is not a plain Header tree".to_string());
    }
    let raw = data
        .get(header.next_header_start..header.archive_end)
        .ok_or_else(|| "7z next header range is invalid".to_string())?;
    let mut pos = 0usize;
    if raw.get(pos).copied() != Some(SZ_HEADER) {
        return Err("7z Header NID is missing".to_string());
    }
    pos += 1;
    let mut pack_info = None;
    let mut files_info = None;
    loop {
        let Some(nid) = raw.get(pos).copied() else {
            return Err("7z Header tree ended before End NID".to_string());
        };
        pos += 1;
        match nid {
            SZ_END => break,
            SZ_MAIN_STREAMS_INFO => {
                pack_info = parse_seven_zip_streams_info(raw, &mut pos)?;
            }
            SZ_FILES_INFO => {
                files_info = Some(parse_seven_zip_files_info(raw, &mut pos)?);
            }
            _ => {
                return Err(format!("unsupported 7z Header NID 0x{nid:02x}"));
            }
        }
    }
    Ok(SevenZipHeaderAst {
        header: raw.to_vec(),
        pack_info,
        files_info,
    })
}

fn parse_seven_zip_encoded_header_ast(data: &[u8], header: &SevenZipHeader) -> Result<SevenZipHeaderAst, String> {
    if header.next_header_nid != SZ_ENCODED_HEADER {
        return Err("7z next header is not an EncodedHeader tree".to_string());
    }
    let raw = data
        .get(header.next_header_start..header.archive_end)
        .ok_or_else(|| "7z encoded header range is invalid".to_string())?;
    let mut pos = 0usize;
    if raw.get(pos).copied() != Some(SZ_ENCODED_HEADER) {
        return Err("7z EncodedHeader NID is missing".to_string());
    }
    pos += 1;
    let pack_info = parse_seven_zip_streams_info(raw, &mut pos)?;
    if raw.get(pos).copied() == Some(SZ_END) {
        pos += 1;
    }
    if pos != raw.len() {
        return Err("7z EncodedHeader has unsupported trailing metadata".to_string());
    }
    Ok(SevenZipHeaderAst {
        header: raw.to_vec(),
        pack_info,
        files_info: None,
    })
}

fn parse_seven_zip_streams_info(
    data: &[u8],
    pos: &mut usize,
) -> Result<Option<SevenZipPackInfoAst>, String> {
    let mut pack_info = None;
    loop {
        let Some(nid) = data.get(*pos).copied() else {
            return Err("7z StreamsInfo ended before End NID".to_string());
        };
        *pos += 1;
        match nid {
            SZ_END => break,
            SZ_PACK_INFO => {
                pack_info = Some(parse_seven_zip_pack_info(data, pos)?);
            }
            SZ_UNPACK_INFO => skip_seven_zip_unhandled_property_tree(data, pos, "UnpackInfo")?,
            SZ_SUB_STREAMS_INFO => skip_seven_zip_unhandled_property_tree(data, pos, "SubStreamsInfo")?,
            _ => return Err(format!("unsupported 7z StreamsInfo NID 0x{nid:02x}")),
        }
    }
    Ok(pack_info)
}

fn parse_seven_zip_pack_info(
    data: &[u8],
    pos: &mut usize,
) -> Result<SevenZipPackInfoAst, String> {
    let pack_pos = read_sz_vint(data, pos).ok_or_else(|| "7z PackInfo PackPos is truncated".to_string())?;
    let num_streams_raw = read_sz_vint(data, pos).ok_or_else(|| "7z PackInfo NumPackStreams is truncated".to_string())?;
    let num_streams = usize::try_from(num_streams_raw.value)
        .map_err(|_| "7z PackInfo stream count is too large".to_string())?;
    if num_streams > SEVEN_Z_MAX_HEADER_STREAMS {
        return Err("7z PackInfo stream count exceeds repair parser limit".to_string());
    }
    let mut sizes = Vec::new();
    let mut crc_values = Vec::new();
    let mut crc_defined_all = false;
    loop {
        let Some(nid) = data.get(*pos).copied() else {
            return Err("7z PackInfo ended before End NID".to_string());
        };
        *pos += 1;
        match nid {
            SZ_END => break,
            SZ_SIZE => {
                sizes.clear();
                for _ in 0..num_streams {
                    let span = read_sz_vint(data, pos)
                        .ok_or_else(|| "7z PackInfo PackSizes is truncated".to_string())?;
                    sizes.push(span);
                }
            }
            SZ_CRC => {
                let defined = parse_seven_zip_bool_vector(data, pos, num_streams)?;
                crc_defined_all = defined.iter().all(|item| *item);
                crc_values.clear();
                for is_defined in defined {
                    if is_defined {
                        if *pos + 4 > data.len() {
                            return Err("7z PackInfo CRC values are truncated".to_string());
                        }
                        let start = *pos;
                        let value = u32_le(data, *pos);
                        *pos += 4;
                        crc_values.push(SevenZipCrcSpan { start, value });
                    }
                }
            }
            _ => return Err(format!("unsupported 7z PackInfo NID 0x{nid:02x}")),
        }
    }
    Ok(SevenZipPackInfoAst {
        pack_pos,
        num_streams,
        sizes,
        crc_values,
        crc_defined_all,
    })
}

fn parse_seven_zip_bool_vector(
    data: &[u8],
    pos: &mut usize,
    count: usize,
) -> Result<Vec<bool>, String> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let all_defined = *data
        .get(*pos)
        .ok_or_else(|| "7z boolean vector is truncated".to_string())?;
    *pos += 1;
    if all_defined != 0 {
        return Ok(vec![true; count]);
    }
    let byte_count = (count + 7) / 8;
    if *pos + byte_count > data.len() {
        return Err("7z boolean bitset is truncated".to_string());
    }
    let mut output = Vec::with_capacity(count);
    for index in 0..count {
        let byte = data[*pos + index / 8];
        output.push((byte & (0x80 >> (index % 8))) != 0);
    }
    *pos += byte_count;
    Ok(output)
}

fn parse_seven_zip_files_info(
    data: &[u8],
    pos: &mut usize,
) -> Result<SevenZipFilesInfoAst, String> {
    let num_files = read_sz_vint(data, pos).ok_or_else(|| "7z FilesInfo file count is truncated".to_string())?;
    if num_files.value > SEVEN_Z_MAX_HEADER_FILES {
        return Err("7z FilesInfo file count exceeds repair parser limit".to_string());
    }
    let mut empty_stream_property = None;
    let mut empty_file_property = None;
    let mut anti_property = None;
    loop {
        let Some(nid) = data.get(*pos).copied() else {
            return Err("7z FilesInfo ended before End NID".to_string());
        };
        *pos += 1;
        if nid == SZ_END {
            break;
        }
        let size = read_sz_vint(data, pos)
            .ok_or_else(|| "7z FilesInfo property size is truncated".to_string())?;
        let prop_start = *pos;
        let prop_size = usize::try_from(size.value)
            .map_err(|_| "7z FilesInfo property size is too large".to_string())?;
        let prop_end = prop_start
            .checked_add(prop_size)
            .ok_or_else(|| "7z FilesInfo property range overflowed".to_string())?;
        if prop_end > data.len() {
            return Err("7z FilesInfo property is truncated".to_string());
        }
        match nid {
            SZ_EMPTY_STREAM => empty_stream_property = Some((prop_start, prop_end)),
            SZ_EMPTY_FILE => empty_file_property = Some((prop_start, prop_end)),
            SZ_ANTI => anti_property = Some((prop_start, prop_end)),
            _ => {}
        }
        *pos = prop_end;
    }
    Ok(SevenZipFilesInfoAst {
        num_files,
        empty_stream_property,
        empty_file_property,
        anti_property,
    })
}

fn skip_seven_zip_unhandled_property_tree(
    data: &[u8],
    pos: &mut usize,
    label: &str,
) -> Result<(), String> {
    loop {
        let Some(nid) = data.get(*pos).copied() else {
            return Err(format!("7z {label} ended before End NID"));
        };
        *pos += 1;
        if nid == SZ_END {
            return Ok(());
        }
        match nid {
            SZ_SIZE | SZ_CRC => {
                return Err(format!("7z {label} requires a full folder graph parser"));
            }
            _ => return Err(format!("unsupported 7z {label} NID 0x{nid:02x}")),
        }
    }
}

fn find_next_header_candidate(data: &[u8], max_scan: usize) -> Option<(u64, u64)> {
    if data.len() < 33 || !data.starts_with(SEVEN_Z_MAGIC) {
        return None;
    }
    let stored_offset = u64_le(data, 12);
    let stored_size = u64_le(data, 20);
    let stored_crc = u32_le(data, 28);
    let scan_end = data.len().min(SEVEN_Z_HEADER_SIZE + max_scan);
    let preferred_start = SEVEN_Z_HEADER_SIZE.checked_add(usize::try_from(stored_offset).ok()?)?;
    let mut starts = Vec::new();
    if preferred_start >= SEVEN_Z_HEADER_SIZE && preferred_start < scan_end {
        starts.push(preferred_start);
    }
    for index in (SEVEN_Z_HEADER_SIZE..scan_end).rev() {
        if matches!(data[index], SZ_HEADER | SZ_ENCODED_HEADER) && !starts.contains(&index) {
            starts.push(index);
            if starts.len() >= 64 {
                break;
            }
        }
    }
    let mut best: Option<(u64, u64)> = None;
    let mut best_score: Option<(u8, u64)> = None;
    for start in starts {
        for end in seven_zip_candidate_header_ends(data, start, scan_end, stored_size, max_scan) {
            if crc32(&data[start..end]) != stored_crc {
                continue;
            }
            let next_offset = (start - SEVEN_Z_HEADER_SIZE) as u64;
            let next_size = (end - start) as u64;
            if !next_header_semantically_plausible(
                &data[start..end],
                stored_offset,
                stored_size,
                next_offset,
                next_size,
            ) {
                continue;
            }
            let score = (
                if next_offset == stored_offset { 0 } else { 1 },
                next_size.abs_diff(stored_size),
            );
            if best_score.is_none_or(|current| score < current) {
                best = Some((next_offset, next_size));
                best_score = Some(score);
            }
        }
    }
    best
}

fn seven_zip_candidate_header_ends(
    data: &[u8],
    start: usize,
    scan_end: usize,
    stored_size: u64,
    max_scan: usize,
) -> Vec<usize> {
    let mut output = Vec::new();
    let max_candidate_bytes = max_scan.min(65_536).max(1);
    let max_end = data.len().min(scan_end).min(start.saturating_add(max_candidate_bytes));
    if start >= max_end {
        return output;
    }
    if stored_size > 0 {
        if let Ok(size) = usize::try_from(stored_size) {
            if let Some(end) = start.checked_add(size) {
                if end > start && end <= max_end {
                    output.push(end);
                }
            }
        }
    }
    let mut zero_ended = 0usize;
    for index in start + 1..=max_end {
        if data[index - 1] != SZ_END {
            continue;
        }
        if !output.contains(&index) {
            output.push(index);
            zero_ended += 1;
        }
        if zero_ended >= 32 {
            break;
        }
    }
    output.sort_unstable();
    output.dedup();
    output
}

fn next_header_semantically_plausible(
    candidate: &[u8],
    stored_offset: u64,
    stored_size: u64,
    next_offset: u64,
    next_size: u64,
) -> bool {
    if candidate.is_empty() || !matches!(candidate[0], 0x01 | 0x17) {
        return false;
    }
    if candidate.len() <= 16 && candidate.iter().all(|item| *item <= 0x19) {
        return true;
    }
    if *candidate.last().unwrap_or(&0xff) != 0 {
        return false;
    }
    if next_offset != stored_offset {
        let max_reasonable_growth = 4096u64.max(stored_size.saturating_mul(16));
        if next_size > max_reasonable_growth {
            return false;
        }
    }
    true
}

fn rar_walks(data: &[u8], max_candidates: usize) -> Vec<RarWalk> {
    let mut output = Vec::new();
    let mut candidates = find_all(data, RAR4_MAGIC)
        .into_iter()
        .map(|offset| (offset, RarVersion::Rar4))
        .chain(
            find_all(data, RAR5_MAGIC)
                .into_iter()
                .map(|offset| (offset, RarVersion::Rar5)),
        )
        .collect::<Vec<_>>();
    candidates.sort_by_key(|item| item.0);
    for (index, (offset, version)) in candidates.into_iter().enumerate() {
        if index >= max_candidates {
            break;
        }
        let walk = match version {
            RarVersion::Rar4 => walk_rar4_blocks(data, offset),
            RarVersion::Rar5 => walk_rar5_blocks(data, offset),
        };
        if let Some(walk) = walk {
            output.push(walk);
        }
    }
    output
}

fn walk_rar4_blocks(data: &[u8], offset: usize) -> Option<RarWalk> {
    if !data.get(offset..)?.starts_with(RAR4_MAGIC) {
        return None;
    }
    let mut pos = offset.checked_add(RAR4_MAGIC.len())?;
    let mut last_complete_end = pos;
    let mut blocks = 0usize;
    let mut missing_volume = false;
    let mut last_type = 0u8;
    let mut warnings = Vec::new();

    while pos < data.len() {
        if pos.checked_add(7)? > data.len() {
            warnings.push("RAR4 trailing block header is truncated".to_string());
            break;
        }
        let stored_crc = u16_le(data, pos) as u32;
        let header_type = data[pos + 2];
        let flags = u16_le(data, pos + 3);
        let header_size = u16_le(data, pos + 5) as usize;
        if !matches!(header_type, 0x73..=0x7b) {
            warnings.push("RAR4 block chain stopped before an unknown block type".to_string());
            break;
        }
        if header_size < 7 {
            warnings.push("RAR4 block chain stopped before an invalid header size".to_string());
            break;
        }
        let Some(header_end) = pos.checked_add(header_size) else {
            warnings.push("RAR4 block header size overflowed".to_string());
            break;
        };
        if header_end > data.len() {
            warnings.push("RAR4 block header is truncated".to_string());
            break;
        }
        let header = &data[pos..header_end];
        if (crc32(&header[2..]) & 0xffff) != stored_crc {
            warnings.push("RAR4 block chain stopped before a header CRC mismatch".to_string());
            break;
        }
        let add_size = if flags & 0x8000 != 0 {
            if header_size < 11 {
                warnings.push("RAR4 block add_size field is missing".to_string());
                break;
            }
            u32_le(header, 7) as usize
        } else {
            0
        };
        let Some(block_end) = header_end.checked_add(add_size) else {
            warnings.push("RAR4 block payload size overflowed".to_string());
            break;
        };
        if block_end > data.len() {
            warnings.push("RAR4 block payload is truncated".to_string());
            break;
        }
        if blocks == 0 && header_type == 0x73 && flags & 0x0001 != 0 {
            missing_volume = true;
        }
        blocks += 1;
        last_type = header_type;
        last_complete_end = block_end;
        pos = block_end;
        if header_type == 0x7b {
            return Some(RarWalk {
                version: RarVersion::Rar4,
                offset,
                last_complete_end,
                end_block_found: true,
                missing_volume,
                last_block_can_precede_end: true,
                warnings,
            });
        }
    }

    (blocks > 0).then_some(RarWalk {
        version: RarVersion::Rar4,
        offset,
        last_complete_end,
        end_block_found: false,
        missing_volume,
        last_block_can_precede_end: matches!(last_type, 0x74 | 0x7a),
        warnings,
    })
}

fn walk_rar5_blocks(data: &[u8], offset: usize) -> Option<RarWalk> {
    if !data.get(offset..)?.starts_with(RAR5_MAGIC) {
        return None;
    }
    let mut pos = offset.checked_add(RAR5_MAGIC.len())?;
    let mut last_complete_end = pos;
    let mut blocks = 0usize;
    let mut missing_volume = false;
    let mut last_type = 0u64;
    let mut warnings = Vec::new();

    while pos < data.len() {
        let Some(block) = parse_rar5_block(data, pos) else {
            warnings
                .push("RAR5 block chain stopped before a truncated or invalid block".to_string());
            break;
        };
        if block.end > data.len() {
            warnings.push("RAR5 block payload is truncated".to_string());
            break;
        }
        if !block.crc_ok {
            warnings.push("RAR5 block chain stopped before a header CRC mismatch".to_string());
            break;
        }
        if blocks == 0 && block.block_type == 1 && block.archive_flags & 0x0001 != 0 {
            missing_volume = true;
        }
        blocks += 1;
        last_type = block.block_type;
        last_complete_end = block.end;
        pos = block.end;
        if block.block_type == 5 {
            return Some(RarWalk {
                version: RarVersion::Rar5,
                offset,
                last_complete_end,
                end_block_found: true,
                missing_volume,
                last_block_can_precede_end: true,
                warnings,
            });
        }
    }

    (blocks > 0).then_some(RarWalk {
        version: RarVersion::Rar5,
        offset,
        last_complete_end,
        end_block_found: false,
        missing_volume,
        last_block_can_precede_end: matches!(last_type, 2 | 3),
        warnings,
    })
}

struct Rar5Block {
    block_type: u64,
    flags: u64,
    archive_flags: u64,
    end: usize,
    crc_ok: bool,
}

fn parse_rar5_block(data: &[u8], offset: usize) -> Option<Rar5Block> {
    if offset.checked_add(6)? > data.len() {
        return None;
    }
    let stored_crc = u32_le(data, offset);
    let (header_size, fields_start) = read_vint(data, offset + 4)?;
    let fields_end = fields_start.checked_add(usize::try_from(header_size).ok()?)?;
    if header_size == 0 || fields_end > data.len() {
        return None;
    }
    let (block_type, after_type) = read_vint(data, fields_start)?;
    if !matches!(block_type, 1..=5) {
        return None;
    }
    let (flags, after_flags) = read_vint(data, after_type)?;
    let mut cursor = after_flags;
    if flags & 0x0001 != 0 {
        let (_, after_extra_size) = read_vint(data, cursor)?;
        cursor = after_extra_size;
    }
    let mut data_size = 0usize;
    if flags & 0x0002 != 0 {
        let (value, after_data_size) = read_vint(data, cursor)?;
        data_size = usize::try_from(value).ok()?;
        cursor = after_data_size;
    }
    let archive_flags = if block_type == 1 && cursor < fields_end {
        read_vint(data, cursor).map(|item| item.0).unwrap_or(0)
    } else {
        0
    };
    let end = fields_end.checked_add(data_size)?;
    let crc_ok = crc32(&data[offset + 4..fields_end]) == stored_crc;
    Some(Rar5Block {
        block_type,
        flags,
        archive_flags,
        end,
        crc_ok,
    })
}

fn rar4_end_block() -> Vec<u8> {
    rar4_block(0x7b, 0, &[])
}

fn rar5_end_block() -> Vec<u8> {
    rar5_block(5, 0, &[])
}

fn rar5_main_block(archive_flags: u64) -> Vec<u8> {
    rar5_header_block(1, 0, &write_vint(archive_flags), &[])
}

fn rar4_block(header_type: u8, flags: u16, payload: &[u8]) -> Vec<u8> {
    let add_size = if payload.is_empty() {
        Vec::new()
    } else {
        (payload.len() as u32).to_le_bytes().to_vec()
    };
    let header_size = 7 + add_size.len();
    let mut body = Vec::with_capacity(5 + add_size.len());
    body.push(header_type);
    body.extend_from_slice(&flags.to_le_bytes());
    body.extend_from_slice(&(header_size as u16).to_le_bytes());
    body.extend_from_slice(&add_size);
    let header_crc = (crc32(&body) & 0xffff) as u16;
    let mut output = Vec::with_capacity(header_size + payload.len());
    output.extend_from_slice(&header_crc.to_le_bytes());
    output.extend_from_slice(&body);
    output.extend_from_slice(payload);
    output
}

fn rar5_block(block_type: u64, flags: u64, data: &[u8]) -> Vec<u8> {
    rar5_header_block(block_type, flags, &[], data)
}

fn rar5_header_block(block_type: u64, flags: u64, tail_fields: &[u8], data: &[u8]) -> Vec<u8> {
    let mut effective_flags = flags;
    let mut fields = Vec::new();
    fields.extend_from_slice(&write_vint(block_type));
    if !data.is_empty() {
        effective_flags |= 0x0002;
    }
    fields.extend_from_slice(&write_vint(effective_flags));
    if !data.is_empty() {
        fields.extend_from_slice(&write_vint(data.len() as u64));
    }
    fields.extend_from_slice(tail_fields);
    let mut header_data = write_vint(fields.len() as u64);
    header_data.extend_from_slice(&fields);
    let mut output = Vec::with_capacity(4 + header_data.len() + data.len());
    output.extend_from_slice(&crc32(&header_data).to_le_bytes());
    output.extend_from_slice(&header_data);
    output.extend_from_slice(data);
    output
}

#[derive(Clone)]
struct StoredZipEntry {
    name: Vec<u8>,
    data: Vec<u8>,
}

fn recover_seven_zip_entries_by_block(
    data: &[u8],
    max_entries: usize,
    password: Option<&str>,
) -> Result<Vec<StoredZipEntry>, String> {
    if !data.starts_with(SEVEN_Z_MAGIC) {
        return Err("input does not start with a 7z signature".to_string());
    }
    let mut cursor = Cursor::new(data.to_vec());
    let password = seven_zip_password(password);
    let archive = Archive::read(&mut cursor, &password).map_err(|err| err.to_string())?;
    let mut output = Vec::new();
    for file in &archive.files {
        if output.len() >= max_entries {
            break;
        }
        if file.is_directory || file.is_anti_item || file.has_stream || file.size != 0 {
            continue;
        }
        let name = sanitize_archive_name(file.name());
        if name.is_empty() {
            continue;
        }
        output.push(StoredZipEntry {
            name: name.into_bytes(),
            data: Vec::new(),
        });
    }
    for block_index in 0..archive.blocks.len() {
        if output.len() >= max_entries {
            break;
        }
        let mut source = Cursor::new(data.to_vec());
        let decoder = BlockDecoder::new(1, block_index, &archive, &password, &mut source);
        let _ = decoder.for_each_entries(&mut |entry, reader| {
            if output.len() >= max_entries {
                return Ok(false);
            }
            if entry.is_directory || entry.is_anti_item {
                return Ok(true);
            }
            let name = sanitize_archive_name(entry.name());
            if name.is_empty() {
                return Ok(true);
            }
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes)?;
            if entry.has_crc && crc32(&bytes) as u64 != entry.crc {
                return Ok(true);
            }
            output.push(StoredZipEntry {
                name: name.into_bytes(),
                data: bytes,
            });
            Ok(true)
        });
    }
    Ok(output)
}

fn rebuild_rar_file_quarantine_candidates(
    data: &[u8],
    workspace: &str,
    max_candidates: usize,
) -> Vec<WrittenArchiveCandidate> {
    let mut candidates = Vec::new();
    let offsets = find_all(data, RAR4_MAGIC)
        .into_iter()
        .map(|offset| (offset, RarVersion::Rar4))
        .chain(
            find_all(data, RAR5_MAGIC)
                .into_iter()
                .map(|offset| (offset, RarVersion::Rar5)),
        )
        .collect::<Vec<_>>();
    for (offset, version) in offsets {
        if candidates.len() >= max_candidates {
            break;
        }
        let rebuilt = match version {
            RarVersion::Rar4 => rebuild_rar4_quarantine(data, offset),
            RarVersion::Rar5 => rebuild_rar5_quarantine(data, offset),
        };
        let Some((bytes, kept, skipped, end_offset)) = rebuilt else {
            continue;
        };
        if kept == 0 || skipped == 0 {
            continue;
        }
        let output_path =
            Path::new(workspace).join(format!("rar_file_quarantine_{offset:08x}.rar"));
        let output_bytes = match write_slice_candidate(&bytes, &output_path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        candidates.push(WrittenArchiveCandidate {
            name: format!("rar_file_quarantine_{offset:08x}"),
            path: output_path.to_string_lossy().to_string(),
            format: "rar".to_string(),
            status: "partial".to_string(),
            offset: offset as u64,
            end_offset: end_offset as u64,
            output_bytes,
            confidence: (0.64 + kept as f64 * 0.04).min(0.88),
            actions: vec![
                "walk_rar_file_blocks".to_string(),
                "drop_incomplete_or_untrusted_file_blocks".to_string(),
                "rebuild_rar_with_recoverable_file_blocks".to_string(),
            ],
            warnings: vec![format!(
                "kept {kept} complete RAR file blocks and skipped {skipped}"
            )],
        });
    }
    candidates
}

fn rebuild_rar4_quarantine(data: &[u8], offset: usize) -> Option<(Vec<u8>, usize, usize, usize)> {
    if !data.get(offset..)?.starts_with(RAR4_MAGIC) {
        return None;
    }
    let mut pos = offset + RAR4_MAGIC.len();
    let mut output = data[offset..pos].to_vec();
    let mut kept = 0usize;
    let mut skipped = 0usize;
    let mut saw_main = false;
    let mut end_offset = pos;
    while pos + 7 <= data.len() {
        let stored_crc = u16_le(data, pos) as u32;
        let header_type = data[pos + 2];
        let flags = u16_le(data, pos + 3);
        let header_size = u16_le(data, pos + 5) as usize;
        if !matches!(header_type, 0x73..=0x7b) || header_size < 7 || pos + header_size > data.len()
        {
            break;
        }
        let header = &data[pos..pos + header_size];
        if (crc32(&header[2..]) & 0xffff) != stored_crc {
            skipped += 1;
            break;
        }
        let add_size = if flags & 0x8000 != 0 {
            if header_size < 11 {
                skipped += 1;
                break;
            }
            u32_le(header, 7) as usize
        } else {
            0
        };
        let block_end = pos.checked_add(header_size)?.checked_add(add_size)?;
        if block_end > data.len() {
            skipped += 1;
            break;
        }
        if header_type == 0x73 && !saw_main {
            output.extend_from_slice(&data[pos..block_end]);
            saw_main = true;
        } else if header_type == 0x74 {
            output.extend_from_slice(&data[pos..block_end]);
            kept += 1;
        } else if header_type == 0x7b {
            output.extend_from_slice(&data[pos..block_end]);
            end_offset = block_end;
            return Some((output, kept, skipped, end_offset));
        } else {
            skipped += 1;
        }
        end_offset = block_end;
        pos = block_end;
    }
    if saw_main && kept > 0 {
        output.extend_from_slice(&rar4_end_block());
        Some((output, kept, skipped.max(1), end_offset))
    } else {
        None
    }
}

fn rebuild_rar5_quarantine(data: &[u8], offset: usize) -> Option<(Vec<u8>, usize, usize, usize)> {
    if !data.get(offset..)?.starts_with(RAR5_MAGIC) {
        return None;
    }
    let mut pos = offset + RAR5_MAGIC.len();
    let mut output = data[offset..pos].to_vec();
    let mut kept = 0usize;
    let mut skipped = 0usize;
    let mut saw_main = false;
    let mut end_offset = pos;
    while pos < data.len() {
        let Some(block) = parse_rar5_block(data, pos) else {
            skipped += 1;
            if let Some(next_pos) = find_next_valid_rar5_block(data, pos.saturating_add(1)) {
                pos = next_pos;
                continue;
            }
            break;
        };
        if block.end > data.len() {
            skipped += 1;
            break;
        }
        if !block.crc_ok {
            skipped += 1;
            if let Some(next_pos) = find_next_valid_rar5_block(data, pos.saturating_add(1)) {
                pos = next_pos;
                continue;
            }
            break;
        }
        if block.block_type == 1 {
            if !saw_main {
                // Rebuild as a single-volume archive. Copying the original main
                // header from a split volume keeps the volume flag and makes the
                // quarantine candidate unopenable as a standalone RAR.
                output.extend_from_slice(&rar5_main_block(0));
            } else {
                skipped += 1;
            }
            saw_main = true;
        } else if block.block_type == 2 {
            if block.flags & 0x0018 != 0 {
                // RAR5 uses split-before/split-after block flags for file data
                // continued across volumes. Those blocks are not independently
                // extractable, so keep scanning for later complete file blocks.
                skipped += 1;
            } else {
                output.extend_from_slice(&data[pos..block.end]);
                kept += 1;
            }
        } else if block.block_type == 5 {
            end_offset = block.end;
            output.extend_from_slice(&rar5_end_block());
            return Some((output, kept, skipped, end_offset));
        } else {
            skipped += 1;
        }
        end_offset = block.end;
        pos = block.end;
    }
    if saw_main && kept > 0 {
        output.extend_from_slice(&rar5_end_block());
        Some((output, kept, skipped.max(1), end_offset))
    } else {
        None
    }
}

fn find_next_valid_rar5_block(data: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    while pos < data.len() {
        if let Some(block) = parse_rar5_block(data, pos) {
            if block.end <= data.len() && block.crc_ok {
                return Some(pos);
            }
        }
        pos = pos.saturating_add(1);
    }
    None
}

fn nested_archive_candidates(
    data: &[u8],
    workspace: &str,
    max_candidates: usize,
) -> Vec<WrittenArchiveCandidate> {
    let mut ranges = Vec::new();
    collect_nested_archive_ranges(data, &mut ranges, max_candidates);
    ranges.sort_by_key(|item| item.0);
    let mut output = Vec::new();
    for (offset, end, format, confidence) in ranges.into_iter().take(max_candidates) {
        if offset == 0 && end == data.len() {
            continue;
        }
        let ext = match format {
            "zip" => ".zip",
            "7z" => ".7z",
            "rar" => ".rar",
            "tar" => ".tar",
            "gzip" => ".gz",
            _ => ".bin",
        };
        let output_path =
            Path::new(workspace).join(format!("archive_nested_payload_{offset:08x}{ext}"));
        let output_bytes = match write_slice_candidate(&data[offset..end], &output_path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        output.push(WrittenArchiveCandidate {
            name: format!("nested_payload_{offset:08x}"),
            path: output_path.to_string_lossy().to_string(),
            format: format.to_string(),
            status: "partial".to_string(),
            offset: offset as u64,
            end_offset: end as u64,
            output_bytes,
            confidence,
            actions: vec!["scan_nested_archive_signatures".to_string(), "extract_nested_archive_payload".to_string()],
            warnings: vec!["candidate was carved from inside a damaged outer container".to_string()],
        });
    }
    output
}

fn collect_nested_archive_ranges<'a>(
    data: &'a [u8],
    output: &mut Vec<(usize, usize, &'a str, f64)>,
    max_candidates: usize,
) {
    for offset in find_all(data, b"PK\x03\x04") {
        if output.len() >= max_candidates {
            return;
        }
        if let Some(end) = nested_zip_end(data, offset) {
            output.push((offset, end, "zip", 0.86));
        }
    }
    for offset in find_all(data, SEVEN_Z_MAGIC) {
        if output.len() >= max_candidates {
            return;
        }
        if let Some(candidate) = seven_zip_candidate(data, offset) {
            output.push((offset, candidate.archive_end, "7z", 0.84));
        }
    }
    for offset in find_all(data, RAR4_MAGIC) {
        if output.len() >= max_candidates {
            return;
        }
        if let Some(walk) = walk_rar4_blocks(data, offset) {
            output.push((
                offset,
                walk.last_complete_end,
                "rar",
                if walk.end_block_found { 0.86 } else { 0.72 },
            ));
        }
    }
    for offset in find_all(data, RAR5_MAGIC) {
        if output.len() >= max_candidates {
            return;
        }
        if let Some(walk) = walk_rar5_blocks(data, offset) {
            output.push((
                offset,
                walk.last_complete_end,
                "rar",
                if walk.end_block_found { 0.86 } else { 0.72 },
            ));
        }
    }
    for offset in find_all(data, b"\x1f\x8b\x08") {
        if output.len() >= max_candidates {
            return;
        }
        if let Some(end) = nested_gzip_end(data, offset) {
            output.push((offset, end, "gzip", 0.78));
        }
    }
    for offset in (0..data.len().saturating_sub(512)).step_by(512) {
        if output.len() >= max_candidates {
            return;
        }
        if offset == 0 {
            continue;
        }
        if plausible_tar_header(&data[offset..offset + 512]) {
            if let Some(end) = nested_tar_end(data, offset) {
                output.push((offset, end, "tar", 0.74));
            }
        }
    }
}

fn nested_zip_end(data: &[u8], offset: usize) -> Option<usize> {
    let mut pos =
        memchr::memmem::find(&data[offset..], b"PK\x05\x06").map(|value| offset + value)?;
    loop {
        if pos + 22 <= data.len() {
            let comment_len = u16_le(data, pos + 20) as usize;
            let end = pos + 22 + comment_len;
            if end <= data.len() {
                return Some(end);
            }
        }
        let next = memchr::memmem::find(&data[pos + 4..], b"PK\x05\x06")?;
        pos = pos + 4 + next;
    }
}

fn nested_gzip_end(data: &[u8], offset: usize) -> Option<usize> {
    for end in offset + 18..=data.len().min(offset + 128 * 1024 * 1024) {
        let mut decoder = GzDecoder::new(Cursor::new(data[offset..end].to_vec()));
        let mut sink = Vec::new();
        if decoder.read_to_end(&mut sink).is_ok() {
            return Some(end);
        }
    }
    None
}

fn nested_tar_end(data: &[u8], offset: usize) -> Option<usize> {
    let mut pos = offset;
    while pos + 512 <= data.len() {
        let header = &data[pos..pos + 512];
        if header.iter().all(|byte| *byte == 0) {
            let end = (pos + 1024).min(data.len());
            return Some(end);
        }
        let size = parse_tar_number(&header[124..136])? as usize;
        let padded = size.checked_add(511)? / 512 * 512;
        pos = pos.checked_add(512)?.checked_add(padded)?;
    }
    None
}

fn write_stored_7z_entries(
    entries: &[StoredZipEntry],
    output: &Path,
    max_output_bytes: Option<u64>,
) -> Result<u64, String> {
    ensure_parent(output).map_err(|err| err.to_string())?;
    let recovered_payload_bytes = entries
        .iter()
        .try_fold(0u64, |total, entry| total.checked_add(entry.data.len() as u64))
        .ok_or_else(|| "recovered entry payload size overflow".to_string())?;
    if max_output_bytes.is_some_and(|limit| recovered_payload_bytes > limit) {
        return Err("candidate output exceeds repair.deep.max_output_size_mb".to_string());
    }

    let temp = temp_path(output);
    let result = (|| -> Result<u64, String> {
        let file = File::create(&temp).map_err(|err| err.to_string())?;
        let mut writer = ArchiveWriter::new(file).map_err(|err| err.to_string())?;
        writer.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::COPY)]);
        writer.set_encrypt_header(false);
        for entry in entries {
            let name = stored_7z_entry_name(entry);
            let archive_entry = ArchiveEntry::new_file(&name);
            if entry.data.is_empty() {
                writer
                    .push_archive_entry::<&[u8]>(archive_entry, None)
                    .map_err(|err| err.to_string())?;
            } else {
                writer
                    .push_archive_entry(archive_entry, Some(entry.data.as_slice()))
                    .map_err(|err| err.to_string())?;
            }
        }
        let mut file = writer.finish().map_err(|err| err.to_string())?;
        file.flush().map_err(|err| err.to_string())?;
        let size = file.stream_position().map_err(|err| err.to_string())?;
        if max_output_bytes.is_some_and(|limit| size > limit) {
            return Err("candidate output exceeds repair.deep.max_output_size_mb".to_string());
        }
        Ok(size)
    })();
    match result {
        Ok(size) => {
            if output.exists() {
                fs::remove_file(output).map_err(|err| err.to_string())?;
            }
            fs::rename(&temp, output).map_err(|err| err.to_string())?;
            Ok(size)
        }
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(err)
        }
    }
}

fn stored_7z_entry_name(entry: &StoredZipEntry) -> String {
    let name = String::from_utf8_lossy(&entry.name).replace('\\', "/");
    let name = name.trim_start_matches('/').trim_start_matches("./");
    if name.is_empty() {
        "recovered_entry".to_string()
    } else {
        name.to_string()
    }
}

fn sanitize_archive_name(name: &str) -> String {
    let normalized = name.replace('\\', "/");
    let parts = normalized
        .split('/')
        .filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .collect::<Vec<_>>();
    parts.join("/")
}

fn plausible_tar_header(header: &[u8]) -> bool {
    if header.len() != 512 {
        return false;
    }
    let name_end = header[0..100]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(100);
    if name_end == 0
        || !header[..name_end]
            .iter()
            .all(|byte| (0x20..=0x7e).contains(byte))
    {
        return false;
    }
    parse_tar_number(&header[124..136]).is_some()
}

fn parse_tar_number(field: &[u8]) -> Option<u64> {
    let mut value = 0u64;
    let mut seen = false;
    for byte in field {
        match *byte {
            b'0'..=b'7' => {
                seen = true;
                value = value.checked_mul(8)?.checked_add((byte - b'0') as u64)?;
            }
            b'\0' | b' ' => {}
            _ => return None,
        }
    }
    Some(if seen { value } else { 0 })
}

fn write_vint(mut value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return output;
        }
    }
}

fn read_source_input(
    source_input: &Bound<'_, PyDict>,
    max_bytes: Option<u64>,
) -> Result<Vec<u8>, String> {
    let kind = get_optional_string(source_input, "kind")
        .map_err(|err| err.to_string())?
        .unwrap_or_else(|| "file".to_string());
    match kind.as_str() {
        "bytes" | "memory" => {
            let data_obj = source_input
                .get_item("data")
                .map_err(|err| err.to_string())?
                .ok_or_else(|| "missing bytes repair input data".to_string())?;
            let data = data_obj
                .cast::<PyBytes>()
                .map_err(|err| err.to_string())?
                .as_bytes();
            if max_bytes.is_some_and(|limit| data.len() as u64 > limit) {
                return Err("archive deep repair input exceeds max_input_size_mb".to_string());
            }
            Ok(data.to_vec())
        }
        "file" => {
            let path = get_required_string(source_input, "path").map_err(|err| err.to_string())?;
            read_range_to_vec(&path, 0, None, max_bytes)
        }
        "file_range" => {
            let path = get_required_string(source_input, "path").map_err(|err| err.to_string())?;
            let start = get_optional_u64(source_input, "start")
                .map_err(|err| err.to_string())?
                .unwrap_or(0);
            let end = get_optional_u64(source_input, "end").map_err(|err| err.to_string())?;
            read_range_to_vec(&path, start, end, max_bytes)
        }
        "concat_ranges" => {
            let ranges_obj = source_input
                .get_item("ranges")
                .map_err(|err| err.to_string())?
                .ok_or_else(|| "missing ranges".to_string())?;
            let ranges = ranges_obj.cast::<PyList>().map_err(|err| err.to_string())?;
            let mut output = Vec::new();
            for item in ranges.iter() {
                let dict = item.cast::<PyDict>().map_err(|err| err.to_string())?;
                let path = get_required_string(dict, "path").map_err(|err| err.to_string())?;
                let start = get_optional_u64(dict, "start")
                    .map_err(|err| err.to_string())?
                    .unwrap_or(0);
                let end = get_optional_u64(dict, "end").map_err(|err| err.to_string())?;
                let remaining_limit =
                    max_bytes.map(|limit| limit.saturating_sub(output.len() as u64));
                let chunk = read_range_to_vec(&path, start, end, remaining_limit)?;
                output.extend_from_slice(&chunk);
                if max_bytes.is_some_and(|limit| output.len() as u64 > limit) {
                    return Err("archive deep repair input exceeds max_input_size_mb".to_string());
                }
            }
            Ok(output)
        }
        _ => Err(format!("unsupported repair input kind: {kind}")),
    }
}

fn read_range_to_vec(
    path: &str,
    start: u64,
    end: Option<u64>,
    max_bytes: Option<u64>,
) -> Result<Vec<u8>, String> {
    let mut file = File::open(path).map_err(|err| err.to_string())?;
    let file_size = file.seek(SeekFrom::End(0)).map_err(|err| err.to_string())?;
    if start > file_size {
        return Err("range start is beyond input size".to_string());
    }
    let effective_end = end.unwrap_or(file_size).min(file_size);
    if effective_end < start {
        return Err("range end is before range start".to_string());
    }
    let len = effective_end - start;
    if max_bytes.is_some_and(|limit| len > limit) {
        return Err("archive deep repair input exceeds max_input_size_mb".to_string());
    }
    let mut output = Vec::with_capacity(len.min(COPY_CHUNK_SIZE as u64) as usize);
    file.seek(SeekFrom::Start(start))
        .map_err(|err| err.to_string())?;
    let mut limited = file.take(len);
    limited
        .read_to_end(&mut output)
        .map_err(|err| err.to_string())?;
    Ok(output)
}

fn extract_password(source_input: &Bound<'_, PyDict>) -> Option<String> {
    source_input
        .get_item("password")
        .ok()
        .flatten()
        .and_then(|value| value.extract::<String>().ok())
        .filter(|value| !value.is_empty())
}

fn seven_zip_password(password: Option<&str>) -> Password {
    match password {
        Some(value) if !value.is_empty() => Password::from(value),
        _ => Password::empty(),
    }
}

struct SevenZipPasswordStatus {
    archive_readable: bool,
    password_required: bool,
    password_rejected: bool,
    encrypted_header: bool,
    message: Option<String>,
}

fn seven_zip_password_status(data: &[u8], password: Option<&str>) -> SevenZipPasswordStatus {
    if !data.starts_with(SEVEN_Z_MAGIC) {
        return SevenZipPasswordStatus {
            archive_readable: false,
            password_required: false,
            password_rejected: false,
            encrypted_header: false,
            message: None,
        };
    }
    if password.is_none() {
        return SevenZipPasswordStatus {
            archive_readable: false,
            password_required: false,
            password_rejected: false,
            encrypted_header: false,
            message: None,
        };
    }
    let mut cursor = Cursor::new(data.to_vec());
    match Archive::read(&mut cursor, &seven_zip_password(password)) {
        Ok(_) => SevenZipPasswordStatus {
            archive_readable: true,
            password_required: false,
            password_rejected: false,
            encrypted_header: false,
            message: None,
        },
        Err(err) => {
            let message = err.to_string();
            let password_related = is_password_related_error(&message);
            SevenZipPasswordStatus {
                archive_readable: false,
                password_required: password_related && password.is_none(),
                password_rejected: password_related && password.is_some(),
                encrypted_header: password_related,
                message: if password_related { Some(message) } else { None },
            }
        }
    }
}

fn is_password_related_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("password") || lower.contains("encrypted") || lower.contains("decrypt")
}

fn password_residual_fact(message: &str, password_present: bool) -> Vec<String> {
    if is_password_related_error(message) {
        if password_present {
            vec!["password_rejected".to_string()]
        } else {
            vec!["password_required".to_string(), "wrong_password".to_string()]
        }
    } else {
        Vec::new()
    }
}

fn push_unique_string(items: &mut Vec<String>, value: &str) {
    if !items.iter().any(|item| item == value) {
        items.push(value.to_string());
    }
}

fn write_slice_candidate(bytes: &[u8], output: &Path) -> std::io::Result<u64> {
    ensure_parent(output)?;
    let temp = temp_path(output);
    let result = (|| -> std::io::Result<u64> {
        let mut file = File::create(&temp)?;
        file.write_all(bytes)?;
        file.flush()?;
        Ok(bytes.len() as u64)
    })();
    match result {
        Ok(written) => {
            if output.exists() {
                fs::remove_file(output)?;
            }
            fs::rename(&temp, output)?;
            Ok(written)
        }
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(err)
        }
    }
}

fn seven_zip_scan_error(py: Python<'_>, status: &str, message: &str) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("native_key", "native_7z_scan_source")?;
    result.set_item("native_target", "seven_zip_scan_source")?;
    result.set_item("format", "7z")?;
    result.set_item("message", message)?;
    result.set_item("route_evidence_flags", PyList::empty(py))?;
    result.set_item("structure", PyDict::new(py))?;
    result.set_item("candidates", PyList::empty(py))?;
    Ok(result.unbind())
}

fn seven_zip_atomic_status(
    py: Python<'_>,
    status: &str,
    target: &str,
    format: &str,
    selected_path: &str,
    message: &str,
    warnings: &[String],
    actions: &[&str],
    patch_facts: &[&str],
    confidence: f64,
    residual_facts: &[&str],
    candidates: &[WrittenArchiveCandidate],
) -> PyResult<Py<PyDict>> {
    let output_bytes = if selected_path.is_empty() {
        0
    } else {
        fs::metadata(selected_path).map(|item| item.len()).unwrap_or(0)
    };
    let result = status_dict_with_candidates(
        py,
        status,
        selected_path,
        format,
        message,
        warnings,
        0,
        output_bytes,
        output_bytes,
        confidence,
        actions,
        candidates,
    )?;
    set_seven_zip_atomic_fields(py, &result, target, patch_facts, residual_facts)?;
    Ok(result)
}

fn set_seven_zip_atomic_fields(
    py: Python<'_>,
    result: &Py<PyDict>,
    target: &str,
    patch_facts: &[&str],
    residual_facts: &[&str],
) -> PyResult<()> {
    let bound = result.bind(py);
    bound.set_item("native_key", "native_7z_atomic_repair")?;
    bound.set_item("native_target", target)?;
    bound.set_item("candidate_status", status_to_candidate_status(&str_item(bound, "status")))?;
    let merged_patch_facts = merge_py_string_list(bound, "patch_facts", patch_facts);
    let merged_residual_facts = merge_py_string_list(bound, "residual_facts", residual_facts);
    bound.set_item("patch_facts", PyList::new(py, &merged_patch_facts)?)?;
    bound.set_item("residual_facts", PyList::new(py, &merged_residual_facts)?)?;
    let validation = PyDict::new(py);
    validation.set_item("target", target)?;
    validation.set_item("policy", target)?;
    bound.set_item("validation_details", validation)?;
    if let Ok(Some(candidates_obj)) = bound.get_item("candidates") {
        if let Ok(candidates) = candidates_obj.downcast::<PyList>() {
            for raw in candidates.iter() {
                if let Ok(item) = raw.downcast::<PyDict>() {
                    item.set_item("native_target", target)?;
                    item.set_item("candidate_status", status_to_candidate_status(&str_item(item, "status")))?;
                    let item_patch_facts = merge_py_string_list(item, "patch_facts", patch_facts);
                    let item_residual_facts = merge_py_string_list(item, "residual_facts", residual_facts);
                    item.set_item("patch_facts", PyList::new(py, &item_patch_facts)?)?;
                    item.set_item("residual_facts", PyList::new(py, &item_residual_facts)?)?;
                    let item_validation = PyDict::new(py);
                    item_validation.set_item("target", target)?;
                    item_validation.set_item("policy", target)?;
                    item.set_item("validation_details", item_validation)?;
                }
            }
        }
    }
    Ok(())
}

fn merge_py_string_list(dict: &Bound<'_, PyDict>, key: &str, extra: &[&str]) -> Vec<String> {
    let mut output = Vec::new();
    if let Ok(Some(value)) = dict.get_item(key) {
        if let Ok(items) = value.extract::<Vec<String>>() {
            for item in items {
                if !item.is_empty() && !output.iter().any(|existing| existing == &item) {
                    output.push(item);
                }
            }
        }
    }
    for item in extra {
        if !item.is_empty() && !output.iter().any(|existing| existing.as_str() == *item) {
            output.push((*item).to_string());
        }
    }
    output
}

fn status_to_candidate_status(status: &str) -> &str {
    match status {
        "repaired" => "complete",
        "partial" => "partial",
        "target_mismatch" => "target_mismatch",
        "validation_failed" => "validation_failed",
        "skipped" => "no_candidate",
        _ => "no_candidate",
    }
}

fn str_item(dict: &Bound<'_, PyDict>, key: &str) -> String {
    dict.get_item(key)
        .ok()
        .flatten()
        .and_then(|value| value.extract::<String>().ok())
        .unwrap_or_default()
}

fn seven_zip_repair_boundary_target(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    target: &str,
    require_prefix: bool,
    max_candidates: usize,
) -> PyResult<Py<PyDict>> {
    let mut written = Vec::new();
    let candidates = scan_archive_signatures(data, TargetFormat::SevenZip, require_prefix, max_candidates.max(1));
    for candidate in candidates.into_iter().filter(|candidate| {
        candidate.format == TargetFormat::SevenZip
            && candidate.archive_end > candidate.offset
            && candidate.next_header_crc_ok
            && if require_prefix { candidate.offset > 0 } else { candidate.offset == 0 && candidate.archive_end < data.len() }
    }) {
        let output_path = Path::new(workspace).join(format!("seven_zip_{target}_{:08x}.7z", candidate.offset));
        let output_bytes = match write_slice_candidate(&data[candidate.offset..candidate.archive_end], &output_path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        written.push(WrittenArchiveCandidate {
            name: format!("{target}_{:08x}", candidate.offset),
            path: output_path.to_string_lossy().to_string(),
            format: "7z".to_string(),
            status: "repaired".to_string(),
            offset: candidate.offset as u64,
            end_offset: candidate.archive_end as u64,
            output_bytes,
            confidence: if require_prefix { 0.94 } else { 0.88 },
            actions: vec![if require_prefix { "crop_7z_carrier_prefix" } else { "trim_7z_trailing_junk" }.to_string()],
            warnings: candidate.warnings,
        });
    }
    let Some(selected) = written.first() else {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "no matching 7z boundary candidate", &[], &[], &[], 0.0, &[], &[]);
    };
    let patch_fact = if require_prefix { "cropped_carrier_prefix" } else { "trimmed_trailing_junk" };
    let action = if require_prefix { "crop_7z_carrier_prefix" } else { "trim_7z_trailing_junk" };
    let result = status_dict_with_candidates(
        py,
        "repaired",
        &selected.path,
        "7z",
        if require_prefix { "7z carrier prefix was cropped" } else { "7z trailing junk was trimmed" },
        &selected.warnings,
        selected.offset,
        selected.end_offset,
        selected.output_bytes,
        selected.confidence,
        &[action],
        &written,
    )?;
    set_seven_zip_atomic_fields(py, &result, target, &[patch_fact, "source_format=7z"], &[])?;
    Ok(result)
}

fn seven_zip_repair_crc_target(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    target: &str,
) -> PyResult<Py<PyDict>> {
    let offset = if data.starts_with(SEVEN_Z_MAGIC) {
        0
    } else {
        find_all(data, SEVEN_Z_MAGIC).into_iter().next().unwrap_or(0)
    };
    let Some(header) = parse_seven_zip_header(data, offset) else {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z header is not readable for CRC repair", &[], &[], &[], 0.0, &["encoded_header_unreadable"], &[]);
    };
    let mut candidate = data[offset..header.archive_end].to_vec();
    let mut start_header = header.start_header;
    let (needed, action, patch_fact) = match target {
        "start_header_crc" => {
            let computed_start_crc = crc32(&start_header);
            if header.stored_start_crc == computed_start_crc {
                (false, "recompute_7z_start_header_crc", "fixed_field=start_header_crc")
            } else {
                candidate[8..12].copy_from_slice(&computed_start_crc.to_le_bytes());
                (true, "recompute_7z_start_header_crc", "fixed_field=start_header_crc")
            }
        }
        "next_header_crc" => {
            if header.stored_next_header_crc == header.computed_next_header_crc {
                (false, "recompute_7z_next_header_crc", "fixed_field=next_header_crc")
            } else {
                start_header[16..20].copy_from_slice(&header.computed_next_header_crc.to_le_bytes());
                candidate[28..32].copy_from_slice(&header.computed_next_header_crc.to_le_bytes());
                let computed_start_crc = crc32(&start_header);
                candidate[8..12].copy_from_slice(&computed_start_crc.to_le_bytes());
                (true, "recompute_7z_next_header_crc", "fixed_field=next_header_crc")
            }
        }
        _ => (false, "", ""),
    };
    if !needed || action.is_empty() {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z CRC target is already consistent or unsupported", &[], &[], &[], 0.0, &[], &[]);
    }
    let output_path = Path::new(workspace).join(format!("seven_zip_{target}.7z"));
    let output_bytes = match write_slice_candidate(&candidate, &output_path) {
        Ok(bytes) => bytes,
        Err(err) => return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", &format!("7z CRC candidate could not be written: {err}"), &[], &[], &[], 0.0, &[], &[]),
    };
    let selected = WrittenArchiveCandidate {
        name: target.to_string(),
        path: output_path.to_string_lossy().to_string(),
        format: "7z".to_string(),
        status: "repaired".to_string(),
        offset: 0,
        end_offset: candidate.len() as u64,
        output_bytes,
        confidence: 0.9,
        actions: vec![action.to_string()],
        warnings: Vec::new(),
    };
    let selected_path = selected.path.clone();
    let result = status_dict_with_candidates(py, "repaired", &selected_path, "7z", "7z CRC field was repaired", &[], 0, candidate.len() as u64, output_bytes, 0.9, &[action], &[selected])?;
    let mut facts = vec![patch_fact, "source_format=7z"];
    if target == "next_header_crc" {
        facts.push("updated_start_header_crc_after_next_header_crc");
    }
    set_seven_zip_atomic_fields(py, &result, target, &facts, &[])?;
    Ok(result)
}

fn seven_zip_repair_next_header_target(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    target: &str,
    max_scan_bytes: usize,
) -> PyResult<Py<PyDict>> {
    if data.len() < SEVEN_Z_HEADER_SIZE || !data.starts_with(SEVEN_Z_MAGIC) {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z signature is not at the current source start", &[], &[], &[], 0.0, &[], &[]);
    }
    let Some((next_offset, next_size)) = find_next_header_candidate(data, max_scan_bytes.max(1)) else {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z next header candidate could not be inferred", &[], &[], &[], 0.0, &["encoded_header_candidate_missing"], &[]);
    };
    let current_offset = u64_le(data, 12);
    let current_size = u64_le(data, 20);
    let offset_differs = current_offset != next_offset;
    let size_differs = current_size != next_size;
    let allowed = match target {
        "next_header_offset" => offset_differs && !size_differs,
        "next_header_size" => size_differs && !offset_differs,
        "next_header_repoint" => offset_differs && size_differs,
        _ => false,
    };
    if !allowed {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z next header inferred fields do not match requested atomic target", &[], &[], &[], 0.0, &[], &[]);
    }
    let next_crc = u32_le(data, 28);
    let mut start_header = [0u8; 20];
    start_header[0..8].copy_from_slice(&next_offset.to_le_bytes());
    start_header[8..16].copy_from_slice(&next_size.to_le_bytes());
    start_header[16..20].copy_from_slice(&next_crc.to_le_bytes());
    let start_crc = crc32(&start_header);
    let mut candidate = data.to_vec();
    candidate[8..12].copy_from_slice(&start_crc.to_le_bytes());
    candidate[12..20].copy_from_slice(&next_offset.to_le_bytes());
    candidate[20..28].copy_from_slice(&next_size.to_le_bytes());
    let output_path = Path::new(workspace).join(format!("seven_zip_{target}.7z"));
    let output_bytes = match write_slice_candidate(&candidate, &output_path) {
        Ok(bytes) => bytes,
        Err(err) => return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", &format!("7z next header candidate could not be written: {err}"), &[], &[], &[], 0.0, &[], &[]),
    };
    let action = match target {
        "next_header_offset" => "repair_7z_next_header_offset",
        "next_header_size" => "repair_7z_next_header_size",
        _ => "repoint_7z_next_header",
    };
    let selected = WrittenArchiveCandidate {
        name: target.to_string(),
        path: output_path.to_string_lossy().to_string(),
        format: "7z".to_string(),
        status: "repaired".to_string(),
        offset: 0,
        end_offset: candidate.len() as u64,
        output_bytes,
        confidence: 0.9,
        actions: vec![action.to_string(), "recompute_7z_start_header_crc".to_string()],
        warnings: Vec::new(),
    };
    let selected_path = selected.path.clone();
    let result = status_dict_with_candidates(py, "repaired", &selected_path, "7z", "7z next header field was repaired", &[], 0, candidate.len() as u64, output_bytes, 0.9, &[action, "recompute_7z_start_header_crc"], &[selected])?;
    let patch_fact = match target {
        "next_header_offset" => "fixed_field=next_header_offset",
        "next_header_size" => "fixed_field=next_header_size",
        _ => "fixed_field=next_header_repoint",
    };
    set_seven_zip_atomic_fields(py, &result, target, &[patch_fact, "updated_start_header_crc_after_next_header_field", "source_format=7z"], &[])?;
    Ok(result)
}

fn seven_zip_repair_signature_header_version(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    target: &str,
) -> PyResult<Py<PyDict>> {
    if data.len() < SEVEN_Z_HEADER_SIZE || !data.starts_with(SEVEN_Z_MAGIC) {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z signature header version repair requires the current source to start at the 7z signature", &[], &[], &[], 0.0, &["seven_zip_signature_missing"], &[]);
    }
    let major = data[6];
    let minor = data[7];
    if major == 0 && minor <= 4 {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z signature header version is already supported", &[], &[], &[], 0.0, &["signature_header_version_already_valid"], &[]);
    }
    let mut candidate = data.to_vec();
    candidate[6] = 0;
    candidate[7] = 4;
    let output_path = Path::new(workspace).join("seven_zip_signature_header_version.7z");
    let output_bytes = match write_slice_candidate(&candidate, &output_path) {
        Ok(bytes) => bytes,
        Err(err) => return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", &format!("7z signature header version candidate could not be written: {err}"), &[], &[], &[], 0.0, &[], &[]),
    };
    let action = "repair_7z_signature_header_version";
    let selected = WrittenArchiveCandidate {
        name: target.to_string(),
        path: output_path.to_string_lossy().to_string(),
        format: "7z".to_string(),
        status: "repaired".to_string(),
        offset: 0,
        end_offset: candidate.len() as u64,
        output_bytes,
        confidence: 0.9,
        actions: vec![action.to_string()],
        warnings: Vec::new(),
    };
    let selected_path = selected.path.clone();
    let result = status_dict_with_candidates(
        py,
        "repaired",
        &selected_path,
        "7z",
        "7z signature header version was normalized",
        &[],
        0,
        candidate.len() as u64,
        output_bytes,
        0.9,
        &[action],
        &[selected],
    )?;
    set_seven_zip_atomic_fields(
        py,
        &result,
        target,
        &["fixed_field=signature_header_version", "signature_header_version_normalized", "source_format=7z"],
        &[],
    )?;
    Ok(result)
}

fn seven_zip_repair_metadata_target(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    target: &str,
) -> PyResult<Py<PyDict>> {
    let offset = if data.starts_with(SEVEN_Z_MAGIC) {
        0
    } else if data.windows(SEVEN_Z_MAGIC.len()).any(|window| window == SEVEN_Z_MAGIC) {
        1
    } else {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z signature was not found", &[], &[], &[], 0.0, &["seven_zip_signature_missing"], &[]);
    };
    if offset != 0 {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z metadata writer requires the current source to start at the 7z signature", &[], &[], &[], 0.0, &["carrier_prefix_remaining"], &[]);
    }
    let Some(header) = parse_seven_zip_header(data, offset) else {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z start header could not be parsed", &[], &[], &[], 0.0, &["start_header_unreadable"], &[]);
    };
    let ast = match if target == "encoded_header_stream_crc" {
        parse_seven_zip_encoded_header_ast(data, &header)
    } else {
        parse_seven_zip_header_ast(data, &header)
    } {
        Ok(ast) => ast,
        Err(message) => {
            return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", &message, &[], &[], &[], 0.0, &["seven_zip_header_graph_unparsed"], &[]);
        }
    };
    let Some(pack) = ast.pack_info.as_ref() else {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z Header graph does not contain PackInfo metadata for this target", &[], &[], &[], 0.0, &["pack_info_missing"], &[]);
    };
    let (new_header, patch_fact, action, detail_fact) = match target {
        "pack_stream_offset" => {
            if pack.pack_pos.value == 0 {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z PackInfo offset is already canonical", &[], &[], &[], 0.0, &["pack_stream_offset_already_valid"], &[]);
            }
            (
                replace_header_vint(&ast.header, pack.pack_pos, 0),
                "fixed_field=pack_stream_offset",
                "repair_7z_pack_stream_offset",
                "pack_stream_offset_inferred_from_start_header",
            )
        }
        "pack_stream_size" => {
            if pack.num_streams != 1 || pack.sizes.len() != 1 {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z PackSizes repair requires exactly one pack stream", &[], &[], &[], 0.0, &["pack_stream_size_not_unique"], &[]);
            }
            let expected = header
                .next_header_offset
                .checked_sub(pack.pack_pos.value)
                .unwrap_or(0);
            if expected == 0 || expected == pack.sizes[0].value {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z PackSizes value is already valid or cannot be inferred", &[], &[], &[], 0.0, &["pack_stream_size_not_inferable"], &[]);
            }
            (
                replace_header_vint(&ast.header, pack.sizes[0], expected),
                "fixed_field=pack_stream_size",
                "repair_7z_pack_stream_size",
                "pack_stream_size_inferred_from_next_header_offset",
            )
        }
        "stream_crc" => {
            if pack.num_streams != 1 || pack.sizes.len() != 1 || pack.crc_values.len() != 1 || !pack.crc_defined_all {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z stream CRC repair requires one defined pack stream CRC", &[], &[], &[], 0.0, &["stream_crc_not_unique"], &[]);
            }
            let stream_start = SEVEN_Z_HEADER_SIZE
                .checked_add(usize::try_from(pack.pack_pos.value).unwrap_or(usize::MAX))
                .unwrap_or(usize::MAX);
            let stream_size = usize::try_from(pack.sizes[0].value).unwrap_or(usize::MAX);
            let stream_end = stream_start.checked_add(stream_size).unwrap_or(usize::MAX);
            if stream_start < SEVEN_Z_HEADER_SIZE || stream_end > data.len() || stream_end > header.next_header_start {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z stream CRC repair cannot read a unique pack stream range", &[], &[], &[], 0.0, &["stream_range_invalid"], &[]);
            }
            let computed = crc32(&data[stream_start..stream_end]);
            if computed == pack.crc_values[0].value {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z stream CRC metadata already matches payload", &[], &[], &[], 0.0, &["stream_crc_already_valid"], &[]);
            }
            (
                replace_header_u32_le(&ast.header, pack.crc_values[0].start, computed),
                "fixed_field=stream_crc",
                "repair_7z_stream_crc",
                "stream_crc_recomputed_from_payload",
            )
        }
        "encoded_header_stream_crc" => {
            if header.next_header_nid != SZ_ENCODED_HEADER {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z EncodedHeader stream CRC target requires an EncodedHeader", &[], &[], &[], 0.0, &["encoded_header_absent"], &[]);
            }
            if pack.num_streams != 1 || pack.sizes.len() != 1 || pack.crc_values.len() != 1 || !pack.crc_defined_all {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z EncodedHeader stream CRC repair requires one defined pack stream CRC", &[], &[], &[], 0.0, &["encoded_header_stream_crc_not_unique"], &[]);
            }
            let stream_start = SEVEN_Z_HEADER_SIZE
                .checked_add(usize::try_from(pack.pack_pos.value).unwrap_or(usize::MAX))
                .unwrap_or(usize::MAX);
            let stream_size = usize::try_from(pack.sizes[0].value).unwrap_or(usize::MAX);
            let stream_end = stream_start.checked_add(stream_size).unwrap_or(usize::MAX);
            if stream_start < SEVEN_Z_HEADER_SIZE || stream_end > data.len() || stream_end > header.next_header_start {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z EncodedHeader stream CRC repair cannot read a unique pack stream range", &[], &[], &[], 0.0, &["encoded_header_stream_range_invalid"], &[]);
            }
            let computed = crc32(&data[stream_start..stream_end]);
            if computed == pack.crc_values[0].value {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z EncodedHeader stream CRC metadata already matches payload", &[], &[], &[], 0.0, &["encoded_header_stream_crc_already_valid"], &[]);
            }
            (
                replace_header_u32_le(&ast.header, pack.crc_values[0].start, computed),
                "fixed_field=encoded_header_stream_crc",
                "repair_7z_encoded_header_stream_crc",
                "encoded_header_stream_crc_recomputed_from_payload",
            )
        }
        "empty_stream_flags" => {
            let Some(files) = ast.files_info.as_ref() else {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z FilesInfo is missing for EmptyStream flag repair", &[], &[], &[], 0.0, &["files_info_missing"], &[]);
            };
            let expected = (usize::try_from(files.num_files.value).unwrap_or(usize::MAX) + 7) / 8;
            let Some((start, end)) = files.empty_stream_property else {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z EmptyStream property is absent", &[], &[], &[], 0.0, &["empty_stream_flags_absent"], &[]);
            };
            if end.saturating_sub(start) == expected {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z EmptyStream flag length is already valid", &[], &[], &[], 0.0, &["empty_stream_flags_already_valid"], &[]);
            }
            return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z EmptyStream value repair needs unique file-to-stream mapping; length-only evidence is not sufficient", &[], &[], &[], 0.0, &["empty_stream_flags_not_unique"], &[]);
        }
        _ => return seven_zip_metadata_target_not_materialized(py, target),
    };
    seven_zip_materialize_header_graph_patch(
        py,
        data,
        workspace,
        &header,
        target,
        &new_header,
        action,
        patch_fact,
        detail_fact,
    )
}

fn seven_zip_materialize_header_graph_patch(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    header: &SevenZipHeader,
    target: &str,
    new_header: &[u8],
    action: &str,
    patch_fact: &str,
    detail_fact: &str,
) -> PyResult<Py<PyDict>> {
    let next_header_crc = crc32(new_header);
    let next_header_size = new_header.len() as u64;
    let mut candidate = Vec::with_capacity(data.len() + new_header.len());
    candidate.extend_from_slice(&data[..header.next_header_start]);
    candidate.extend_from_slice(new_header);
    candidate.extend_from_slice(&data[header.archive_end..]);
    candidate[20..28].copy_from_slice(&next_header_size.to_le_bytes());
    candidate[28..32].copy_from_slice(&next_header_crc.to_le_bytes());
    let mut start_header = [0u8; 20];
    start_header.copy_from_slice(&candidate[12..32]);
    let start_crc = crc32(&start_header);
    candidate[8..12].copy_from_slice(&start_crc.to_le_bytes());
    let output_path = Path::new(workspace).join(format!("seven_zip_{target}.7z"));
    let output_bytes = match write_slice_candidate(&candidate, &output_path) {
        Ok(bytes) => bytes,
        Err(err) => return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", &format!("7z header graph patch could not be written: {err}"), &[], &[], &[], 0.0, &[], &[]),
    };
    let selected = WrittenArchiveCandidate {
        name: target.to_string(),
        path: output_path.to_string_lossy().to_string(),
        format: "7z".to_string(),
        status: "repaired".to_string(),
        offset: 0,
        end_offset: candidate.len() as u64,
        output_bytes,
        confidence: 0.88,
        actions: vec![action.to_string(), "rewrite_7z_header_graph".to_string(), "recompute_7z_next_header_crc".to_string(), "recompute_7z_start_header_crc".to_string()],
        warnings: Vec::new(),
    };
    let selected_path = selected.path.clone();
    let result = status_dict_with_candidates(
        py,
        "repaired",
        &selected_path,
        "7z",
        "7z header graph metadata was repaired",
        &[],
        0,
        candidate.len() as u64,
        output_bytes,
        0.88,
        &[action, "rewrite_7z_header_graph", "recompute_7z_next_header_crc", "recompute_7z_start_header_crc"],
        &[selected],
    )?;
    set_seven_zip_atomic_fields(
        py,
        &result,
        target,
        &[patch_fact, detail_fact, "rewrote_7z_header_graph_ast", "updated_next_header_crc", "updated_start_header_crc", "source_format=7z"],
        &[],
    )?;
    Ok(result)
}

fn seven_zip_metadata_target_not_materialized(
    py: Python<'_>,
    target: &str,
) -> PyResult<Py<PyDict>> {
    let reason = match target {
        "encoded_header_decode" => "7z encoded header decode requires a decoded header writer",
        "encoded_header_stream_crc" => "7z encoded header stream CRC repair requires parsed stream metadata",
        "pack_stream_offset" => "7z PackInfo offset repair requires parsed pack stream metadata",
        "pack_stream_size" => "7z PackSizes repair requires parsed pack stream metadata",
        "unpack_size" => "7z UnpackSize repair requires parsed folder/substream metadata",
        "stream_crc" => "7z stream CRC repair requires verified decoded stream payloads",
        "bad_folder_quarantine" => "7z folder quarantine requires folder-level decode verification",
        "empty_stream_flags" => "7z empty stream flag repair requires parsed file table metadata",
        "folder_bind_pairs" => "7z folder bind pair repair requires parsed folder graph metadata",
        "folder_stream_counts" => "7z folder stream count repair requires parsed folder graph metadata",
        "file_count_metadata" => "7z file count repair requires parsed file table metadata",
        "file_names_utf16" => "7z UTF-16 filename repair requires parsed Names property graph metadata",
        "unreferenced_folder" => "7z unreferenced folder drop requires parsed folder-to-file graph metadata",
        "unreferenced_file_record" => "7z unreferenced file record drop requires parsed file-to-stream graph metadata",
        "stream_crc_defined_flag" => "7z CRC defined flag repair requires parsed CRC bitset and stream map metadata",
        _ => "unsupported 7z metadata repair target",
    };
    seven_zip_atomic_status(
        py,
        "unrepairable",
        target,
        "7z",
        "",
        reason,
        &[],
        &[],
        &[],
        0.0,
        &["seven_zip_metadata_writer_missing"],
        &[],
    )
}

fn status_dict(
    py: Python<'_>,
    status: &str,
    selected_path: &str,
    format: &str,
    message: &str,
    warnings: &[String],
    offset: u64,
    end_offset: u64,
    output_bytes: u64,
    confidence: f64,
    actions: &[&str],
) -> PyResult<Py<PyDict>> {
    status_dict_with_candidates(
        py,
        status,
        selected_path,
        format,
        message,
        warnings,
        offset,
        end_offset,
        output_bytes,
        confidence,
        actions,
        &[],
    )
}

fn status_dict_with_candidates(
    py: Python<'_>,
    status: &str,
    selected_path: &str,
    format: &str,
    message: &str,
    warnings: &[String],
    offset: u64,
    end_offset: u64,
    output_bytes: u64,
    confidence: f64,
    actions: &[&str],
    candidates: &[WrittenArchiveCandidate],
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("selected_path", selected_path)?;
    result.set_item("format", format)?;
    result.set_item("message", message)?;
    result.set_item("warnings", PyList::new(py, warnings)?)?;
    result.set_item("offset", offset)?;
    result.set_item("end_offset", end_offset)?;
    result.set_item("output_bytes", output_bytes)?;
    result.set_item("confidence", confidence)?;
    result.set_item("actions", PyList::new(py, actions)?)?;
    result.set_item("native_key", "native_archive_deep_repair")?;
    result.set_item("native_target", if format == "zip" { "archive_carrier_crop_zip" } else { "archive_carrier_crop" })?;
    result.set_item("candidate_status", status)?;
    result.set_item("materialized_path", selected_path)?;
    let patch_facts = carrier_crop_patch_facts(format, offset, end_offset);
    result.set_item("patch_facts", PyList::new(py, &patch_facts)?)?;
    let residual_facts = carrier_crop_residual_facts(format);
    result.set_item("residual_facts", PyList::new(py, &residual_facts)?)?;
    let validation = PyDict::new(py);
    validation.set_item("cropped_format", format)?;
    validation.set_item("cropped_start", offset)?;
    validation.set_item("cropped_end", end_offset)?;
    validation.set_item("source_digest_after_crop", candidate_crc32(selected_path))?;
    result.set_item("validation_details", validation)?;
    result.set_item(
        "workspace_paths",
        if !candidates.is_empty() {
            PyList::new(
                py,
                candidates
                    .iter()
                    .map(|candidate| candidate.path.as_str())
                    .collect::<Vec<_>>(),
            )?
        } else if selected_path.is_empty() {
            PyList::empty(py)
        } else {
            PyList::new(py, [selected_path])?
        },
    )?;
    let candidate_list = PyList::empty(py);
    for candidate in candidates {
        let item = PyDict::new(py);
        item.set_item("name", &candidate.name)?;
        item.set_item("path", &candidate.path)?;
        item.set_item("format", &candidate.format)?;
        item.set_item("status", &candidate.status)?;
        item.set_item("offset", candidate.offset)?;
        item.set_item("end_offset", candidate.end_offset)?;
        item.set_item("output_bytes", candidate.output_bytes)?;
        item.set_item("confidence", candidate.confidence)?;
        item.set_item("actions", PyList::new(py, &candidate.actions)?)?;
        item.set_item("warnings", PyList::new(py, &candidate.warnings)?)?;
        let item_patch_facts = carrier_crop_patch_facts(&candidate.format, candidate.offset, candidate.end_offset);
        item.set_item("patch_facts", PyList::new(py, &item_patch_facts)?)?;
        let item_residual_facts = carrier_crop_residual_facts(&candidate.format);
        item.set_item("residual_facts", PyList::new(py, &item_residual_facts)?)?;
        item.set_item("native_target", if candidate.format == "zip" { "archive_carrier_crop_zip" } else { "archive_carrier_crop" })?;
        item.set_item("candidate_status", &candidate.status)?;
        let item_validation = PyDict::new(py);
        item_validation.set_item("cropped_format", &candidate.format)?;
        item_validation.set_item("cropped_start", candidate.offset)?;
        item_validation.set_item("cropped_end", candidate.end_offset)?;
        item_validation.set_item("source_digest_after_crop", candidate_crc32(&candidate.path))?;
        item.set_item("validation_details", item_validation)?;
        candidate_list.append(item)?;
    }
    result.set_item("candidates", candidate_list)?;
    Ok(result.unbind())
}

fn confidence_for_candidate(candidate: &ArchiveCandidate) -> f64 {
    match candidate.format {
        TargetFormat::SevenZip if candidate.start_crc_ok && candidate.next_header_crc_ok => 0.92,
        TargetFormat::SevenZip if candidate.start_crc_ok => 0.82,
        TargetFormat::Rar => 0.86,
        TargetFormat::Zip => 0.88,
        _ => 0.7,
    }
}

fn carrier_crop_patch_facts(format: &str, offset: u64, end_offset: u64) -> Vec<String> {
    vec![
        "fixed_field=carrier_prefix_crop".to_string(),
        "after_archive_carrier_crop".to_string(),
        format!("cropped_format={format}"),
        format!("cropped_start={offset}"),
        format!("cropped_end={end_offset}"),
    ]
}

fn carrier_crop_residual_facts(format: &str) -> Vec<&'static str> {
    if format == "zip" {
        vec![
            "central_directory_bad",
            "content_integrity_bad_or_unknown",
            "payload_hash_mismatch",
        ]
    } else {
        Vec::new()
    }
}

fn candidate_crc32(path: &str) -> String {
    match fs::read(path) {
        Ok(bytes) => format!("{:08x}", crc32(&bytes)),
        Err(_) => String::new(),
    }
}

fn find_all(data: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || data.len() < needle.len() {
        return Vec::new();
    }
    let mut output = Vec::new();
    let mut start = 0usize;
    while start + needle.len() <= data.len() {
        let Some(index) = find_subslice(&data[start..], needle) else {
            break;
        };
        let absolute = start + index;
        output.push(absolute);
        start = absolute + 1;
    }
    output
}

fn find_subslice(data: &[u8], needle: &[u8]) -> Option<usize> {
    data.windows(needle.len())
        .position(|window| window == needle)
}

fn ensure_parent(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("candidate");
    path.with_file_name(format!(".{name}.tmp"))
}

fn get_required_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<String> {
    dict.get_item(key)?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(format!("missing {key}")))?
        .extract::<String>()
}

fn get_optional_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    match dict.get_item(key)? {
        Some(value) if !value.is_none() => Ok(Some(value.extract::<String>()?)),
        _ => Ok(None),
    }
}

fn get_optional_u64(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u64>> {
    match dict.get_item(key)? {
        Some(value) if !value.is_none() => Ok(Some(value.extract::<u64>()?)),
        _ => Ok(None),
    }
}

fn mb_to_bytes(value: f64) -> Option<u64> {
    if value <= 0.0 {
        None
    } else {
        Some((value * 1024.0 * 1024.0) as u64)
    }
}

fn u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn read_vint(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0;
    for index in offset..data.len().min(offset + 10) {
        let byte = data[index];
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
        shift += 7;
    }
    None
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precise_7z_boundary_finds_embedded_archive_end() {
        let archive = seven_zip_bytes();
        let data = [b"carrier".as_slice(), archive.as_slice(), b"junk"].concat();

        let candidates = scan_archive_signatures(&data, TargetFormat::SevenZip, false, 8);
        let selected = candidates.first().unwrap();

        assert_eq!(selected.offset, 7);
        assert_eq!(selected.archive_end, 7 + archive.len());
        assert!(selected.start_crc_ok);
        assert!(selected.next_header_crc_ok);
    }

    #[test]
    fn carrier_crop_ignores_archive_at_zero() {
        let archive = seven_zip_bytes();
        let candidates = scan_archive_signatures(&archive, TargetFormat::SevenZip, true, 8);

        assert!(candidates.is_empty());
    }

    fn seven_zip_bytes() -> Vec<u8> {
        let next_header = b"\x01";
        let gap = b"abcde";
        let start_header = [
            (gap.len() as u64).to_le_bytes().as_slice(),
            (next_header.len() as u64).to_le_bytes().as_slice(),
            crc32(next_header).to_le_bytes().as_slice(),
        ]
        .concat();
        [
            b"7z\xbc\xaf\x27\x1c".as_slice(),
            b"\x00\x04".as_slice(),
            crc32(&start_header).to_le_bytes().as_slice(),
            start_header.as_slice(),
            gap.as_slice(),
            next_header.as_slice(),
        ]
        .concat()
    }
}
