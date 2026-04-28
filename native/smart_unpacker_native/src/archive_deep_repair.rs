use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
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
                write_warnings.push(format!("candidate at offset {} could not be written: {err}", candidate.offset));
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
    let candidates = scan_archive_signatures(&data, TargetFormat::SevenZip, false, max_candidates.max(1));
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
        let output_bytes = match write_slice_candidate(&data[candidate.offset..candidate.archive_end], &output_path) {
            Ok(bytes) => bytes,
            Err(err) => {
                write_warnings.push(format!("candidate at offset {} could not be written: {err}", candidate.offset));
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
                write_warnings.push(format!("candidate at offset {offset} could not be written: {err}"));
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
                    write_warnings.push(format!("candidate at offset {} could not be written: {err}", walk.offset));
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
                skipped_warnings.push(format!("candidate at offset {} could not be written: {err}", walk.offset));
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
    let mut header_data = write_vint(fields.len() as u64);
    header_data.extend_from_slice(&fields);
    let mut output = Vec::with_capacity(4 + header_data.len() + data.len());
    output.extend_from_slice(&crc32(&header_data).to_le_bytes());
    output.extend_from_slice(&header_data);
    output.extend_from_slice(data);
    output
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
            let data = data_obj.cast::<PyBytes>().map_err(|err| err.to_string())?.as_bytes();
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
