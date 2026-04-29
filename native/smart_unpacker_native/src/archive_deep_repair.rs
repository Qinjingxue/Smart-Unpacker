use flate2::read::GzDecoder;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use sevenz_rust2::{Archive, BlockDecoder, Password};
use std::fs::{self, File};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const COPY_CHUNK_SIZE: usize = 1024 * 1024;
const SEVEN_Z_MAGIC: &[u8] = b"7z\xbc\xaf\x27\x1c";
const SEVEN_Z_HEADER_SIZE: usize = 32;
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
            "no embedded 7z/RAR archive signature passed structural checks",
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
pub(crate) fn seven_zip_precise_boundary_repair(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_candidates: usize,
) -> PyResult<Py<PyDict>> {
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(py, "skipped", "", "7z", &message, &[], 0, 0, 0, 0.0, &[])
        }
    };
    let candidates =
        scan_archive_signatures(&data, TargetFormat::SevenZip, false, max_candidates.max(1));
    let mut written = Vec::new();
    let mut write_warnings = Vec::new();
    for candidate in candidates.into_iter().filter(|candidate| {
        candidate.format == TargetFormat::SevenZip
            && candidate.archive_end > candidate.offset
            && (candidate.offset > 0 || candidate.archive_end < data.len())
            && candidate.next_header_crc_ok
    }) {
        let output_path = Path::new(workspace).join(format!(
            "seven_zip_precise_boundary_repair_{:08x}.7z",
            candidate.offset
        ));
        let output_bytes = match write_slice_candidate(
            &data[candidate.offset..candidate.archive_end],
            &output_path,
        ) {
            Ok(bytes) => bytes,
            Err(err) => {
                write_warnings.push(format!(
                    "candidate at offset {} could not be written: {err}",
                    candidate.offset
                ));
                continue;
            }
        };
        written.push(WrittenArchiveCandidate {
            name: format!("precise_boundary_{:08x}", candidate.offset),
            path: output_path.to_string_lossy().to_string(),
            format: "7z".to_string(),
            status: "repaired".to_string(),
            offset: candidate.offset as u64,
            end_offset: candidate.archive_end as u64,
            output_bytes,
            confidence: 0.94,
            actions: vec!["crop_7z_to_precise_next_header_boundary".to_string()],
            warnings: candidate.warnings.clone(),
        });
    }
    let Some(selected) = written.first() else {
        let warnings = write_warnings;
        return status_dict(
            py,
            "unrepairable",
            "",
            "7z",
            "no 7z candidate had a trusted precise boundary to trim",
            &warnings,
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
        "7z",
        "7z archive was cropped to the exact NextHeader boundary",
        &selected.warnings,
        selected.offset,
        selected.end_offset,
        selected.output_bytes,
        selected.confidence,
        &["crop_7z_to_precise_next_header_boundary"],
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
pub(crate) fn seven_zip_crc_field_repair(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_candidates: usize,
) -> PyResult<Py<PyDict>> {
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(py, "skipped", "", "7z", &message, &[], 0, 0, 0, 0.0, &[])
        }
    };

    let mut checked = 0usize;
    let mut written = Vec::new();
    let mut write_warnings = Vec::new();
    for offset in find_all(&data, SEVEN_Z_MAGIC) {
        checked += 1;
        if checked > max_candidates.max(1) {
            break;
        }
        let Some(repair) = repair_seven_zip_crc_candidate(&data, offset) else {
            continue;
        };
        let output_path =
            Path::new(workspace).join(format!("seven_zip_crc_field_repair_{:08x}.7z", offset));
        let output_bytes = match write_slice_candidate(&repair.bytes, &output_path) {
            Ok(bytes) => bytes,
            Err(err) => {
                write_warnings.push(format!(
                    "candidate at offset {offset} could not be written: {err}"
                ));
                continue;
            }
        };
        written.push(WrittenArchiveCandidate {
            name: format!("crc_field_repair_{offset:08x}"),
            path: output_path.to_string_lossy().to_string(),
            format: "7z".to_string(),
            status: "repaired".to_string(),
            offset: offset as u64,
            end_offset: repair.archive_end as u64,
            output_bytes,
            confidence: 0.9,
            actions: repair.actions,
            warnings: repair.warnings,
        });
    }

    if let Some(selected) = written.first() {
        let action_refs = selected
            .actions
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        return status_dict_with_candidates(
            py,
            "repaired",
            &selected.path,
            "7z",
            "7z StartHeader/NextHeader CRC fields were recomputed from intact bytes",
            &selected.warnings,
            selected.offset,
            selected.end_offset,
            selected.output_bytes,
            selected.confidence,
            &action_refs,
            &written,
        );
    }

    status_dict(
        py,
        "unrepairable",
        "",
        "7z",
        "no 7z CRC field mismatch was safely repairable",
        &write_warnings,
        0,
        data.len() as u64,
        0,
        0.0,
        &[],
    )
}

#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    max_input_size_mb=512.0,
    max_scan_bytes=1048576
))]
pub(crate) fn seven_zip_next_header_field_repair(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_scan_bytes: usize,
) -> PyResult<Py<PyDict>> {
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(py, "skipped", "", "7z", &message, &[], 0, 0, 0, 0.0, &[])
        }
    };
    let Some((next_offset, next_size)) = find_next_header_candidate(&data, max_scan_bytes.max(1))
    else {
        return status_dict(
            py,
            "unrepairable",
            "",
            "7z",
            "7z next header offset/size could not be inferred from the stored next-header CRC",
            &[],
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    };
    let current_offset = u64_le(&data, 12);
    let current_size = u64_le(&data, 20);
    let next_crc = u32_le(&data, 28);
    let mut start_header = [0u8; 20];
    start_header[0..8].copy_from_slice(&next_offset.to_le_bytes());
    start_header[8..16].copy_from_slice(&next_size.to_le_bytes());
    start_header[16..20].copy_from_slice(&next_crc.to_le_bytes());
    let start_crc = crc32(&start_header);
    let current_start_crc = u32_le(&data, 8);
    if current_offset == next_offset && current_size == next_size && current_start_crc == start_crc
    {
        return status_dict(
            py,
            "unrepairable",
            "",
            "7z",
            "7z next header offset and size already match the inferred segment",
            &[],
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    }
    let mut candidate = data.clone();
    candidate[8..12].copy_from_slice(&start_crc.to_le_bytes());
    candidate[12..20].copy_from_slice(&next_offset.to_le_bytes());
    candidate[20..28].copy_from_slice(&next_size.to_le_bytes());
    let output_path = Path::new(workspace).join("seven_zip_next_header_field_repair.7z");
    let output_bytes = match write_slice_candidate(&candidate, &output_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return status_dict(
                py,
                "unrepairable",
                "",
                "7z",
                &format!("7z next header candidate could not be written: {err}"),
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
        name: "seven_zip_next_header_field_repair".to_string(),
        path: output_path.to_string_lossy().to_string(),
        format: "7z".to_string(),
        status: "repaired".to_string(),
        offset: 0,
        end_offset: candidate.len() as u64,
        output_bytes,
        confidence: 0.9,
        actions: vec![
            "repair_7z_next_header_offset_size".to_string(),
            "recompute_7z_start_header_crc".to_string(),
        ],
        warnings: Vec::new(),
    };
    status_dict_with_candidates(
        py,
        "repaired",
        &selected.path,
        "7z",
        "7z next header offset/size fields were inferred and rewritten by native repair",
        &[],
        0,
        candidate.len() as u64,
        output_bytes,
        0.9,
        &[
            "repair_7z_next_header_offset_size",
            "recompute_7z_start_header_crc",
        ],
        &[selected.clone()],
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

#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    max_input_size_mb=512.0,
    max_output_size_mb=2048.0,
    max_entries=20000
))]
pub(crate) fn seven_zip_solid_block_partial_salvage(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
    max_entries: usize,
) -> PyResult<Py<PyDict>> {
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(py, "skipped", "", "zip", &message, &[], 0, 0, 0, 0.0, &[])
        }
    };
    let recovered = match recover_seven_zip_entries_by_block(&data, max_entries.max(1)) {
        Ok(entries) => entries,
        Err(message) => {
            return status_dict(
                py,
                "unrepairable",
                "",
                "zip",
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
    if recovered.is_empty() {
        return status_dict(
            py,
            "unrepairable",
            "",
            "zip",
            "no decodable 7z block entries were recoverable",
            &[],
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    }
    let output_path = Path::new(workspace).join("seven_zip_solid_block_partial_salvage.zip");
    let output_bytes =
        match write_stored_zip_entries(&recovered, &output_path, mb_to_bytes(max_output_size_mb)) {
            Ok(bytes) => bytes,
            Err(message) => {
                return status_dict(
                    py,
                    "unrepairable",
                    "",
                    "zip",
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
        name: "seven_zip_solid_block_partial_salvage".to_string(),
        path: output_path.to_string_lossy().to_string(),
        format: "zip".to_string(),
        status: "partial".to_string(),
        offset: 0,
        end_offset: data.len() as u64,
        output_bytes,
        confidence: (0.58 + recovered.len() as f64 * 0.04).min(0.88),
        actions: vec![
            "parse_7z_next_header_blocks".to_string(),
            "decode_7z_blocks_independently".to_string(),
            "repack_recoverable_entries_as_zip".to_string(),
        ],
        warnings: vec!["7z salvage output is a ZIP containing recovered files only".to_string()],
    };
    status_dict_with_candidates(
        py,
        "partial",
        &selected.path,
        "zip",
        "7z block-level salvage recovered decodable entries into a ZIP candidate",
        &selected.warnings,
        0,
        data.len() as u64,
        output_bytes,
        selected.confidence,
        &[
            "parse_7z_next_header_blocks",
            "decode_7z_blocks_independently",
            "repack_recoverable_entries_as_zip",
        ],
        &[selected.clone()],
    )
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
            _ => Self::Any,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::SevenZip => "7z",
            Self::Rar => "rar",
            Self::Any => "archive",
        }
    }

    fn ext(self) -> &'static str {
        match self {
            Self::SevenZip => ".7z",
            Self::Rar => ".rar",
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
    stored_start_crc: u32,
    computed_start_crc: u32,
    stored_next_header_crc: u32,
    computed_next_header_crc: u32,
    next_header_nid_valid: bool,
}

struct SevenZipCrcRepair {
    bytes: Vec<u8>,
    archive_end: usize,
    actions: Vec<String>,
    warnings: Vec<String>,
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
        stored_start_crc,
        computed_start_crc,
        stored_next_header_crc,
        computed_next_header_crc,
        next_header_nid_valid: nid == 0x01 || nid == 0x17,
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

fn repair_seven_zip_crc_candidate(data: &[u8], offset: usize) -> Option<SevenZipCrcRepair> {
    let header = parse_seven_zip_header(data, offset)?;
    if !header.next_header_nid_valid {
        return None;
    }
    let mut candidate = data[offset..header.archive_end].to_vec();
    let mut start_header = header.start_header;
    let mut actions = Vec::new();
    if header.stored_next_header_crc != header.computed_next_header_crc {
        start_header[16..20].copy_from_slice(&header.computed_next_header_crc.to_le_bytes());
        candidate[28..32].copy_from_slice(&header.computed_next_header_crc.to_le_bytes());
        actions.push("recompute_7z_next_header_crc".to_string());
    }
    let computed_start_crc = crc32(&start_header);
    if header.stored_start_crc != computed_start_crc {
        candidate[8..12].copy_from_slice(&computed_start_crc.to_le_bytes());
        actions.push("recompute_7z_start_header_crc".to_string());
    }
    if actions.is_empty() {
        return None;
    }
    let repaired_header = parse_seven_zip_header(&candidate, 0)?;
    if !repaired_header.start_crc_ok() || !repaired_header.next_header_crc_ok() {
        return None;
    }
    let mut warnings = Vec::new();
    if offset > 0 || header.archive_end < data.len() {
        warnings.push(
            "CRC repair output also cropped carrier or trailing bytes around the 7z archive"
                .to_string(),
        );
    }
    Some(SevenZipCrcRepair {
        bytes: candidate,
        archive_end: header.archive_end,
        actions,
        warnings,
    })
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
    for index in SEVEN_Z_HEADER_SIZE..scan_end {
        if matches!(data[index], 0x01 | 0x17) && !starts.contains(&index) {
            starts.push(index);
        }
    }
    let mut best: Option<(u64, u64)> = None;
    let mut best_score: Option<(u8, u64)> = None;
    for start in starts {
        let max_end = data.len().min(start.saturating_add(max_scan));
        for end in start + 1..=max_end {
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
    crc32: u32,
}

fn recover_seven_zip_entries_by_block(
    data: &[u8],
    max_entries: usize,
) -> Result<Vec<StoredZipEntry>, String> {
    if !data.starts_with(SEVEN_Z_MAGIC) {
        return Err("input does not start with a 7z signature".to_string());
    }
    let mut cursor = Cursor::new(data.to_vec());
    let archive = Archive::read(&mut cursor, &Password::empty()).map_err(|err| err.to_string())?;
    let password = Password::empty();
    let mut output = Vec::new();
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
                crc32: crc32(&bytes),
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

fn write_stored_zip_entries(
    entries: &[StoredZipEntry],
    output: &Path,
    max_output_bytes: Option<u64>,
) -> Result<u64, String> {
    ensure_parent(output).map_err(|err| err.to_string())?;
    let temp = temp_path(output);
    let result = (|| -> Result<u64, String> {
        let mut file = File::create(&temp).map_err(|err| err.to_string())?;
        let mut cd = Vec::new();
        for entry in entries {
            if entry.name.len() > u16::MAX as usize || entry.data.len() > u32::MAX as usize {
                return Err("recovered entry exceeds ZIP32 limits".to_string());
            }
            let local_offset = file.stream_position().map_err(|err| err.to_string())?;
            file.write_all(&0x0403_4B50u32.to_le_bytes())
                .map_err(|err| err.to_string())?;
            file.write_all(&20u16.to_le_bytes())
                .map_err(|err| err.to_string())?;
            file.write_all(&0u16.to_le_bytes())
                .map_err(|err| err.to_string())?;
            file.write_all(&0u16.to_le_bytes())
                .map_err(|err| err.to_string())?;
            file.write_all(&0u16.to_le_bytes())
                .map_err(|err| err.to_string())?;
            file.write_all(&0u16.to_le_bytes())
                .map_err(|err| err.to_string())?;
            file.write_all(&entry.crc32.to_le_bytes())
                .map_err(|err| err.to_string())?;
            file.write_all(&(entry.data.len() as u32).to_le_bytes())
                .map_err(|err| err.to_string())?;
            file.write_all(&(entry.data.len() as u32).to_le_bytes())
                .map_err(|err| err.to_string())?;
            file.write_all(&(entry.name.len() as u16).to_le_bytes())
                .map_err(|err| err.to_string())?;
            file.write_all(&0u16.to_le_bytes())
                .map_err(|err| err.to_string())?;
            file.write_all(&entry.name).map_err(|err| err.to_string())?;
            file.write_all(&entry.data).map_err(|err| err.to_string())?;
            append_stored_zip_cd(&mut cd, entry, local_offset as u32);
            if max_output_bytes
                .is_some_and(|limit| file.stream_position().unwrap_or(u64::MAX) > limit)
            {
                return Err("candidate output exceeds repair.deep.max_output_size_mb".to_string());
            }
        }
        let cd_offset = file.stream_position().map_err(|err| err.to_string())?;
        file.write_all(&cd).map_err(|err| err.to_string())?;
        file.write_all(&0x0605_4B50u32.to_le_bytes())
            .map_err(|err| err.to_string())?;
        file.write_all(&0u16.to_le_bytes())
            .map_err(|err| err.to_string())?;
        file.write_all(&0u16.to_le_bytes())
            .map_err(|err| err.to_string())?;
        file.write_all(&(entries.len() as u16).to_le_bytes())
            .map_err(|err| err.to_string())?;
        file.write_all(&(entries.len() as u16).to_le_bytes())
            .map_err(|err| err.to_string())?;
        file.write_all(&(cd.len() as u32).to_le_bytes())
            .map_err(|err| err.to_string())?;
        file.write_all(&(cd_offset as u32).to_le_bytes())
            .map_err(|err| err.to_string())?;
        file.write_all(&0u16.to_le_bytes())
            .map_err(|err| err.to_string())?;
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

fn append_stored_zip_cd(output: &mut Vec<u8>, entry: &StoredZipEntry, local_offset: u32) {
    output.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
    output.extend_from_slice(&20u16.to_le_bytes());
    output.extend_from_slice(&20u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&entry.crc32.to_le_bytes());
    output.extend_from_slice(&(entry.data.len() as u32).to_le_bytes());
    output.extend_from_slice(&(entry.data.len() as u32).to_le_bytes());
    output.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&local_offset.to_le_bytes());
    output.extend_from_slice(&entry.name);
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
        _ => 0.7,
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
    fn crc_field_repair_fixes_next_header_and_start_crc() {
        let mut data = seven_zip_bytes();
        data[8..12].copy_from_slice(&0u32.to_le_bytes());
        data[28..32].copy_from_slice(&0u32.to_le_bytes());

        let repair = repair_seven_zip_crc_candidate(&data, 0).unwrap();

        assert_eq!(repair.bytes, seven_zip_bytes());
        assert_eq!(
            repair.actions,
            vec![
                "recompute_7z_next_header_crc".to_string(),
                "recompute_7z_start_header_crc".to_string()
            ]
        );
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
