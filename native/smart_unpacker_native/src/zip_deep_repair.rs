use flate2::{Decompress, FlushDecompress, Status};
use memchr::memmem;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const LFH_SIG: &[u8] = b"PK\x03\x04";
const DD_SIG: &[u8] = b"PK\x07\x08";
const CD_SIG: &[u8] = b"PK\x01\x02";
const EOCD_SIG: &[u8] = b"PK\x05\x06";
const ZIP64_EOCD_SIG: &[u8] = b"PK\x06\x06";
const ZIP64_LOCATOR_SIG: &[u8] = b"PK\x06\x07";
const LOCAL_HEADER_LEN: usize = 30;
const COPY_CHUNK_SIZE: usize = 1024 * 1024;
const MAX_NAME_LEN: usize = 4096;

#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    max_candidates=3,
    max_entries=20000,
    max_input_size_mb=512.0,
    max_output_size_mb=2048.0,
    max_entry_uncompressed_mb=512.0,
    max_seconds=30.0,
    verify_candidates=true
))]
pub(crate) fn zip_deep_partial_recovery(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_candidates: usize,
    max_entries: usize,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
    max_entry_uncompressed_mb: f64,
    max_seconds: f64,
    verify_candidates: bool,
) -> PyResult<Py<PyDict>> {
    let started = Instant::now();
    let options = DeepZipOptions {
        max_candidates: max_candidates.max(1),
        max_entries: max_entries.max(1),
        max_input_bytes: mb_to_bytes(max_input_size_mb),
        max_output_bytes: mb_to_bytes(max_output_size_mb),
        max_entry_uncompressed_bytes: mb_to_bytes(max_entry_uncompressed_mb),
        max_duration: duration_from_seconds(max_seconds),
        verify_candidates,
    };
    let data = match read_source_input(source_input, options.max_input_bytes) {
        Ok(data) => data,
        Err(message) => return status_dict(py, "skipped", "", &message, &[], &[], 0, 0, 0.0),
    };
    let scan = scan_entries(&data, &options, started);
    let plans = candidate_plans(&scan, &options);
    if plans.is_empty() {
        return status_dict(
            py,
            "unrepairable",
            "",
            "no recoverable ZIP entries were found",
            &scan.warnings,
            &[],
            scan.skipped_offsets.len(),
            scan.encrypted_entries,
            0.0,
        );
    }

    let mut written = Vec::new();
    let workspace = Path::new(workspace);
    for plan in plans.into_iter().take(options.max_candidates) {
        let output_path = workspace.join(format!("{}.zip", plan.name));
        match write_candidate_zip(
            &data,
            &scan.entries,
            &plan,
            &output_path,
            options.max_output_bytes,
        ) {
            Ok(stats) => written.push(WrittenCandidate {
                name: plan.name,
                path: output_path.to_string_lossy().to_string(),
                confidence: plan.confidence,
                actions: plan.actions,
                entries: stats.entries,
                verified_entries: stats.verified_entries,
                descriptor_entries: stats.descriptor_entries,
                passthrough_entries: stats.passthrough_entries,
                size: stats.size,
                rank_score: plan.rank_score,
            }),
            Err(message) => {
                let mut warnings = scan.warnings.clone();
                warnings.push(format!("{}: {message}", plan.name));
                if written.is_empty() {
                    return status_dict(
                        py,
                        "unrepairable",
                        "",
                        "candidate ZIP could not be written",
                        &warnings,
                        &[],
                        scan.skipped_offsets.len(),
                        scan.encrypted_entries,
                        0.0,
                    );
                }
            }
        }
    }
    let Some(selected) = written.iter().max_by_key(|item| item.rank_score) else {
        return status_dict(
            py,
            "unrepairable",
            "",
            "candidate ZIP could not be written",
            &scan.warnings,
            &[],
            scan.skipped_offsets.len(),
            scan.encrypted_entries,
            0.0,
        );
    };

    let result = PyDict::new(py);
    result.set_item("status", "partial")?;
    result.set_item("selected_path", &selected.path)?;
    result.set_item("selected_candidate", selected.name)?;
    result.set_item("confidence", selected.confidence)?;
    result.set_item("format", "zip")?;
    result.set_item("message", "ZIP deep partial recovery produced a candidate")?;
    result.set_item("actions", PyList::new(py, &selected.actions)?)?;
    result.set_item("warnings", PyList::new(py, &scan.warnings)?)?;
    result.set_item("skipped_entries", scan.skipped_offsets.len())?;
    result.set_item("encrypted_entries", scan.encrypted_entries)?;
    result.set_item("unsupported_entries", scan.unsupported_entries)?;
    result.set_item("recovered_entries", selected.entries)?;
    result.set_item("verified_entries", selected.verified_entries)?;
    result.set_item("descriptor_entries", selected.descriptor_entries)?;
    result.set_item("passthrough_entries", selected.passthrough_entries)?;
    let candidates = PyList::empty(py);
    for candidate in &written {
        let item = PyDict::new(py);
        item.set_item("name", candidate.name)?;
        item.set_item("path", &candidate.path)?;
        item.set_item("confidence", candidate.confidence)?;
        item.set_item("entries", candidate.entries)?;
        item.set_item("verified_entries", candidate.verified_entries)?;
        item.set_item("descriptor_entries", candidate.descriptor_entries)?;
        item.set_item("passthrough_entries", candidate.passthrough_entries)?;
        item.set_item("size", candidate.size)?;
        item.set_item("actions", PyList::new(py, &candidate.actions)?)?;
        candidates.append(item)?;
    }
    result.set_item("candidates", candidates)?;
    result.set_item(
        "workspace_paths",
        PyList::new(
            py,
            written
                .iter()
                .map(|item| item.path.as_str())
                .collect::<Vec<_>>(),
        )?,
    )?;
    Ok(result.unbind())
}

#[pyfunction]
#[pyo3(signature = (
    source_input,
    output_path,
    require_data_descriptor=false,
    max_entries=20000,
    max_input_size_mb=512.0,
    max_output_size_mb=2048.0,
    verify_candidates=true
))]
pub(crate) fn zip_rebuild_from_local_headers(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    output_path: &str,
    require_data_descriptor: bool,
    max_entries: usize,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
    verify_candidates: bool,
) -> PyResult<Py<PyDict>> {
    let started = Instant::now();
    let options = DeepZipOptions {
        max_candidates: 1,
        max_entries: max_entries.max(1),
        max_input_bytes: mb_to_bytes(max_input_size_mb),
        max_output_bytes: mb_to_bytes(max_output_size_mb),
        max_entry_uncompressed_bytes: None,
        max_duration: None,
        verify_candidates,
    };
    let data = match read_source_input(source_input, options.max_input_bytes) {
        Ok(data) => data,
        Err(message) => {
            return rebuild_status_dict(py, "skipped", "", &message, &[], 0, 0, 0, 0, 0, false)
        }
    };
    let scan = scan_entries(&data, &options, started);
    let indices = scan
        .entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            (!require_data_descriptor || entry.descriptor).then_some(index)
        })
        .collect::<Vec<_>>();
    if indices.is_empty() {
        return rebuild_status_dict(
            py,
            "unrepairable",
            "",
            if require_data_descriptor {
                "no recoverable ZIP data descriptor entries were found"
            } else {
                "no recoverable ZIP local file headers were found"
            },
            &scan.warnings,
            scan.skipped_offsets.len(),
            scan.encrypted_entries,
            scan.descriptor_entries,
            0,
            0,
            scan.timed_out,
        );
    }
    let plan = make_plan(
        "zip_rebuild_from_local_headers",
        indices,
        &scan.entries,
        if require_data_descriptor { 0.86 } else { 0.84 },
        if require_data_descriptor {
            vec![
                "scan_zip_data_descriptors",
                "materialize_descriptor_sizes",
                "write_repaired_zip",
            ]
        } else {
            vec![
                "scan_local_file_headers",
                "rebuild_zip_central_directory",
                "write_repaired_zip",
            ]
        },
    );
    match write_candidate_zip(
        &data,
        &scan.entries,
        &plan,
        Path::new(output_path),
        options.max_output_bytes,
    ) {
        Ok(stats) => rebuild_status_dict(
            py,
            if scan.skipped_offsets.is_empty() && scan.encrypted_entries == 0 && !scan.timed_out {
                "repaired"
            } else {
                "partial"
            },
            output_path,
            "ZIP local headers were rebuilt",
            &scan.warnings,
            scan.skipped_offsets.len(),
            scan.encrypted_entries,
            scan.descriptor_entries,
            stats.entries,
            stats.verified_entries,
            scan.timed_out,
        ),
        Err(message) => rebuild_status_dict(
            py,
            "unrepairable",
            "",
            &message,
            &scan.warnings,
            scan.skipped_offsets.len(),
            scan.encrypted_entries,
            scan.descriptor_entries,
            0,
            0,
            scan.timed_out,
        ),
    }
}

#[pyfunction]
#[pyo3(signature = (source_input, workspace, repair_name, max_input_size_mb=512.0))]
pub(crate) fn zip_directory_field_repair(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    repair_name: &str,
    max_input_size_mb: f64,
) -> PyResult<Py<PyDict>> {
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => return simple_repair_status(py, "skipped", "zip", "", &message, &[], 0.0),
    };
    let result = match repair_name {
        "zip_comment_length_fix" => repair_zip_comment_length(&data),
        "zip_central_directory_count_fix" => repair_zip_cd_count(&data),
        "zip_central_directory_offset_fix" => repair_zip_cd_offset(&data),
        "zip_trailing_junk_trim" => repair_zip_trailing_junk(&data),
        "zip_eocd_repair" => repair_zip_eocd(&data),
        "zip_local_header_field_repair" => repair_zip_local_header_fields(&data),
        "zip64_field_repair" => repair_zip64_fields(&data),
        _ => Err(format!(
            "unsupported ZIP directory field repair: {repair_name}"
        )),
    };
    let repair = match result {
        Ok(repair) => repair,
        Err(message) => {
            return simple_repair_status(py, "unrepairable", "zip", "", &message, &[], 0.0)
        }
    };
    let output_path = Path::new(workspace).join(format!("{repair_name}.zip"));
    if let Err(message) = write_bytes_atomic(&repair.bytes, &output_path) {
        return simple_repair_status(
            py,
            "unrepairable",
            "zip",
            "",
            &format!("ZIP repaired candidate could not be written: {message}"),
            &[],
            0.0,
        );
    }
    let result = PyDict::new(py);
    result.set_item("status", "repaired")?;
    result.set_item("format", "zip")?;
    result.set_item("selected_path", output_path.to_string_lossy().to_string())?;
    result.set_item("confidence", repair.confidence)?;
    result.set_item("message", repair.message)?;
    result.set_item("actions", PyList::new(py, &repair.actions)?)?;
    result.set_item(
        "workspace_paths",
        PyList::new(py, &[output_path.to_string_lossy().to_string()])?,
    )?;
    if let Some(truncate_at) = repair.truncate_at {
        result.set_item("truncate_at", truncate_at)?;
    }
    let patches = PyList::empty(py);
    for patch in &repair.patches {
        let item = PyDict::new(py);
        item.set_item("offset", patch.offset)?;
        item.set_item("data", PyBytes::new(py, &patch.data))?;
        patches.append(item)?;
    }
    result.set_item("patches", patches)?;
    Ok(result.unbind())
}

#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    max_entries=20000,
    max_input_size_mb=512.0,
    max_output_size_mb=2048.0,
    max_entry_uncompressed_mb=512.0,
    verify_candidates=true
))]
pub(crate) fn zip_conflict_resolver_rebuild(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_entries: usize,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
    max_entry_uncompressed_mb: f64,
    verify_candidates: bool,
) -> PyResult<Py<PyDict>> {
    let options = DeepZipOptions {
        max_candidates: 1,
        max_entries: max_entries.max(1),
        max_input_bytes: mb_to_bytes(max_input_size_mb),
        max_output_bytes: mb_to_bytes(max_output_size_mb),
        max_entry_uncompressed_bytes: mb_to_bytes(max_entry_uncompressed_mb),
        max_duration: None,
        verify_candidates,
    };
    let data = match read_source_input(source_input, options.max_input_bytes) {
        Ok(data) => data,
        Err(message) => return status_dict(py, "skipped", "", &message, &[], &[], 0, 0, 0.0),
    };
    let scan = scan_entries(&data, &options, Instant::now());
    if scan.entries.is_empty() {
        return status_dict(
            py,
            "unrepairable",
            "",
            "no recoverable ZIP entries were available for conflict resolution",
            &scan.warnings,
            &[],
            scan.skipped_offsets.len(),
            scan.encrypted_entries,
            0.0,
        );
    }
    let selected_indices = select_conflict_free_zip_entries(&scan.entries);
    if selected_indices.is_empty() {
        return status_dict(
            py,
            "unrepairable",
            "",
            "ZIP conflict resolver could not select any non-overlapping entry",
            &scan.warnings,
            &[],
            scan.skipped_offsets.len(),
            scan.encrypted_entries,
            0.0,
        );
    }
    let conflict_count = scan.entries.len().saturating_sub(selected_indices.len());
    if conflict_count == 0 && scan.skipped_offsets.is_empty() {
        return status_dict(
            py,
            "unrepairable",
            "",
            "ZIP entries already look conflict-free",
            &scan.warnings,
            &[],
            scan.skipped_offsets.len(),
            scan.encrypted_entries,
            0.0,
        );
    }
    let plan = make_plan(
        "zip_conflict_resolver_rebuild",
        selected_indices,
        &scan.entries,
        0.91,
        vec![
            "build_zip_entry_conflict_graph",
            "select_best_non_overlapping_entries",
            "rebuild_clean_zip",
        ],
    );
    let output_path = Path::new(workspace).join("zip_conflict_resolver_rebuild.zip");
    let stats = match write_candidate_zip(
        &data,
        &scan.entries,
        &plan,
        &output_path,
        options.max_output_bytes,
    ) {
        Ok(stats) => stats,
        Err(message) => {
            return status_dict(
                py,
                "unrepairable",
                "",
                &message,
                &scan.warnings,
                &[],
                scan.skipped_offsets.len(),
                scan.encrypted_entries,
                0.0,
            )
        }
    };
    let mut warnings = scan.warnings.clone();
    warnings.push(format!(
        "ZIP conflict resolver dropped {conflict_count} duplicate or overlapping entries"
    ));
    let selected = WrittenCandidate {
        name: "zip_conflict_resolver_rebuild",
        path: output_path.to_string_lossy().to_string(),
        confidence: 0.91,
        actions: plan.actions.clone(),
        entries: stats.entries,
        verified_entries: stats.verified_entries,
        descriptor_entries: stats.descriptor_entries,
        passthrough_entries: stats.passthrough_entries,
        size: stats.size,
        rank_score: plan.rank_score,
    };
    status_dict(
        py,
        "partial",
        &selected.path,
        "ZIP duplicate/overlapping entry conflicts were resolved into a clean candidate",
        &warnings,
        &[selected.clone()],
        scan.skipped_offsets.len(),
        scan.encrypted_entries,
        0.91,
    )
}

#[derive(Debug, Clone)]
struct DeepZipOptions {
    max_candidates: usize,
    max_entries: usize,
    max_input_bytes: Option<u64>,
    max_output_bytes: Option<u64>,
    max_entry_uncompressed_bytes: Option<u64>,
    max_duration: Option<Duration>,
    verify_candidates: bool,
}

#[derive(Debug, Clone)]
struct RecoveredEntry {
    name: Vec<u8>,
    version_needed: u16,
    flags: u16,
    method: u16,
    mod_time: u16,
    mod_date: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    data_start: usize,
    data_end: usize,
    verified: bool,
    descriptor: bool,
    passthrough: bool,
}

#[derive(Debug, Default)]
struct ScanResult {
    entries: Vec<RecoveredEntry>,
    warnings: Vec<String>,
    skipped_offsets: Vec<usize>,
    encrypted_entries: usize,
    unsupported_entries: usize,
    descriptor_entries: usize,
    timed_out: bool,
}

#[derive(Debug)]
struct CandidatePlan {
    name: &'static str,
    indices: Vec<usize>,
    confidence: f64,
    actions: Vec<&'static str>,
    rank_score: i64,
}

#[derive(Debug)]
struct WriteStats {
    entries: usize,
    verified_entries: usize,
    descriptor_entries: usize,
    passthrough_entries: usize,
    size: u64,
}

#[derive(Debug, Clone)]
struct WrittenCandidate {
    name: &'static str,
    path: String,
    confidence: f64,
    actions: Vec<&'static str>,
    entries: usize,
    verified_entries: usize,
    descriptor_entries: usize,
    passthrough_entries: usize,
    size: u64,
    rank_score: i64,
}

#[derive(Debug)]
struct DeflateInfo {
    consumed: usize,
    uncompressed_size: u64,
    crc32: u32,
}

fn scan_entries(data: &[u8], options: &DeepZipOptions, started: Instant) -> ScanResult {
    let mut result = ScanResult::default();
    for offset in memmem::find_iter(data, LFH_SIG).take(options.max_entries) {
        if timed_out(started, options.max_duration) {
            result.timed_out = true;
            result
                .warnings
                .push("ZIP deep recovery time budget reached".to_string());
            break;
        }
        match parse_entry(data, offset, options) {
            EntryOutcome::Recovered(entry) => {
                if entry.descriptor {
                    result.descriptor_entries += 1;
                }
                if entry.passthrough {
                    result.unsupported_entries += 1;
                }
                result.entries.push(entry);
            }
            EntryOutcome::Encrypted => result.encrypted_entries += 1,
            EntryOutcome::Skipped(message) => {
                result.skipped_offsets.push(offset);
                if result.warnings.len() < 32 {
                    result.warnings.push(format!("offset {offset}: {message}"));
                }
            }
        }
    }
    dedupe(&mut result.warnings);
    result
}

enum EntryOutcome {
    Recovered(RecoveredEntry),
    Encrypted,
    Skipped(String),
}

fn parse_entry(data: &[u8], offset: usize, options: &DeepZipOptions) -> EntryOutcome {
    if offset + LOCAL_HEADER_LEN > data.len() {
        return EntryOutcome::Skipped("short local header".to_string());
    }
    let version_needed = u16_le(data, offset + 4);
    let flags = u16_le(data, offset + 6);
    let method = u16_le(data, offset + 8);
    let mod_time = u16_le(data, offset + 10);
    let mod_date = u16_le(data, offset + 12);
    let header_crc32 = u32_le(data, offset + 14);
    let header_compressed = u32_le(data, offset + 18);
    let header_uncompressed = u32_le(data, offset + 22);
    let name_len = u16_le(data, offset + 26) as usize;
    let extra_len = u16_le(data, offset + 28) as usize;
    if version_needed > 63 {
        return EntryOutcome::Skipped("unsupported ZIP version".to_string());
    }
    if flags & 0x01 != 0 {
        return EntryOutcome::Encrypted;
    }
    if name_len == 0 || name_len > MAX_NAME_LEN {
        return EntryOutcome::Skipped("invalid filename length".to_string());
    }
    let name_start = offset + LOCAL_HEADER_LEN;
    let extra_start = name_start + name_len;
    let data_start = extra_start + extra_len;
    if data_start > data.len() {
        return EntryOutcome::Skipped("local header exceeds input size".to_string());
    }
    let name = data[name_start..extra_start].to_vec();
    if name.iter().any(|byte| *byte == 0) {
        return EntryOutcome::Skipped("filename contains NUL".to_string());
    }
    let extra = &data[extra_start..data_start];
    if flags & 0x08 != 0 {
        return parse_descriptor_entry(
            data,
            data_start,
            name,
            version_needed,
            flags,
            method,
            mod_time,
            mod_date,
            options,
        );
    }

    let (compressed_size, uncompressed_size) =
        match zip64_sizes(extra, header_compressed, header_uncompressed) {
            Some(sizes) => sizes,
            None => return EntryOutcome::Skipped("ZIP64 local sizes are incomplete".to_string()),
        };
    if compressed_size > u32::MAX as u64 || uncompressed_size > u32::MAX as u64 {
        return EntryOutcome::Skipped(
            "ZIP64-sized entries are not rewritten by deep recovery yet".to_string(),
        );
    }
    let Some(data_end) = data_start.checked_add(compressed_size as usize) else {
        return EntryOutcome::Skipped("compressed size overflows input range".to_string());
    };
    if data_end > data.len() {
        return EntryOutcome::Skipped("entry payload is truncated".to_string());
    }
    classify_entry(
        data,
        data_start,
        data_end,
        name,
        version_needed,
        flags,
        method,
        mod_time,
        mod_date,
        header_crc32,
        compressed_size,
        uncompressed_size,
        false,
        options,
    )
}

#[allow(clippy::too_many_arguments)]
fn parse_descriptor_entry(
    data: &[u8],
    data_start: usize,
    name: Vec<u8>,
    version_needed: u16,
    flags: u16,
    method: u16,
    mod_time: u16,
    mod_date: u16,
    options: &DeepZipOptions,
) -> EntryOutcome {
    if method == 8 {
        match verify_deflate(
            &data[data_start..],
            None,
            None,
            options.max_entry_uncompressed_bytes,
            false,
        ) {
            Ok(info) => {
                let data_end = data_start + info.consumed;
                let _descriptor = descriptor_at(
                    data,
                    data_end,
                    info.crc32,
                    info.consumed as u64,
                    info.uncompressed_size,
                );
                return EntryOutcome::Recovered(RecoveredEntry {
                    name,
                    version_needed,
                    flags,
                    method,
                    mod_time,
                    mod_date,
                    crc32: info.crc32,
                    compressed_size: info.consumed as u64,
                    uncompressed_size: info.uncompressed_size,
                    data_start,
                    data_end,
                    verified: true,
                    descriptor: true,
                    passthrough: false,
                });
            }
            Err(_) => {}
        }
    }

    let Some((descriptor_start, crc32, compressed_size, uncompressed_size)) =
        descriptor_before_next_record(data, data_start)
    else {
        return EntryOutcome::Skipped("data descriptor could not be recovered".to_string());
    };
    let data_end = descriptor_start;
    if method == 0 {
        return classify_entry(
            data,
            data_start,
            data_end,
            name,
            version_needed,
            flags,
            method,
            mod_time,
            mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            true,
            options,
        );
    }
    if compressed_size > u32::MAX as u64 || uncompressed_size > u32::MAX as u64 {
        return EntryOutcome::Skipped("ZIP64-sized descriptor entry is too large".to_string());
    }
    EntryOutcome::Recovered(RecoveredEntry {
        name,
        version_needed,
        flags,
        method,
        mod_time,
        mod_date,
        crc32,
        compressed_size,
        uncompressed_size,
        data_start,
        data_end,
        verified: false,
        descriptor: true,
        passthrough: true,
    })
}

#[allow(clippy::too_many_arguments)]
fn classify_entry(
    data: &[u8],
    data_start: usize,
    data_end: usize,
    name: Vec<u8>,
    version_needed: u16,
    flags: u16,
    method: u16,
    mod_time: u16,
    mod_date: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    descriptor: bool,
    options: &DeepZipOptions,
) -> EntryOutcome {
    let payload = &data[data_start..data_end];
    let verified = match method {
        0 => {
            payload.len() as u64 == uncompressed_size
                && compressed_size == uncompressed_size
                && crc32_bytes(payload) == crc32
        }
        8 if options.verify_candidates => {
            match verify_deflate(
                payload,
                Some(crc32),
                Some(uncompressed_size),
                options.max_entry_uncompressed_bytes,
                true,
            ) {
                Ok(info) => info.consumed == payload.len(),
                Err(_) => false,
            }
        }
        8 => false,
        _ => false,
    };
    if !verified && matches!(method, 0 | 8) && options.verify_candidates {
        return EntryOutcome::Skipped("entry failed payload verification".to_string());
    }
    if !verified && !known_zip_method(method) {
        return EntryOutcome::Recovered(RecoveredEntry {
            name,
            version_needed,
            flags,
            method,
            mod_time,
            mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            data_start,
            data_end,
            verified: false,
            descriptor,
            passthrough: true,
        });
    }
    if !verified && !options.verify_candidates {
        return EntryOutcome::Recovered(RecoveredEntry {
            name,
            version_needed,
            flags,
            method,
            mod_time,
            mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            data_start,
            data_end,
            verified: false,
            descriptor,
            passthrough: true,
        });
    }
    EntryOutcome::Recovered(RecoveredEntry {
        name,
        version_needed,
        flags,
        method,
        mod_time,
        mod_date,
        crc32,
        compressed_size,
        uncompressed_size,
        data_start,
        data_end,
        verified,
        descriptor,
        passthrough: !verified,
    })
}

fn candidate_plans(scan: &ScanResult, options: &DeepZipOptions) -> Vec<CandidatePlan> {
    let strict = scan
        .entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| (entry.verified && !entry.descriptor).then_some(index))
        .collect::<Vec<_>>();
    let descriptor = scan
        .entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| entry.verified.then_some(index))
        .collect::<Vec<_>>();
    let passthrough = scan
        .entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| (entry.verified || entry.passthrough).then_some(index))
        .collect::<Vec<_>>();
    let mut plans = Vec::new();
    if !strict.is_empty() {
        plans.push(make_plan(
            "zip_deep_strict_verified",
            strict,
            &scan.entries,
            0.78,
            vec![
                "deep_scan_local_headers",
                "verify_entry_payloads",
                "write_strict_verified_zip",
            ],
        ));
    }
    if descriptor.len() > plans.first().map(|plan| plan.indices.len()).unwrap_or(0) {
        plans.push(make_plan(
            "zip_deep_descriptor_recovered",
            descriptor,
            &scan.entries,
            0.84,
            vec![
                "deep_scan_local_headers",
                "recover_data_descriptors",
                "verify_entry_payloads",
                "write_descriptor_recovered_zip",
            ],
        ));
    }
    if passthrough.len()
        > plans
            .iter()
            .map(|plan| plan.indices.len())
            .max()
            .unwrap_or(0)
    {
        plans.push(make_plan(
            "zip_deep_passthrough_rebuilt",
            passthrough,
            &scan.entries,
            if options.verify_candidates {
                0.70
            } else {
                0.62
            },
            vec![
                "deep_scan_local_headers",
                "recover_data_descriptors",
                "preserve_trusted_compressed_payloads",
                "write_passthrough_rebuilt_zip",
            ],
        ));
    }
    plans.sort_by_key(|plan| std::cmp::Reverse(plan.rank_score));
    plans
}

fn make_plan(
    name: &'static str,
    mut indices: Vec<usize>,
    entries: &[RecoveredEntry],
    confidence: f64,
    actions: Vec<&'static str>,
) -> CandidatePlan {
    indices.sort_by_key(|index| entries[*index].data_start);
    let verified = indices
        .iter()
        .filter(|index| entries[**index].verified)
        .count() as i64;
    let descriptor = indices
        .iter()
        .filter(|index| entries[**index].descriptor)
        .count() as i64;
    let passthrough = indices
        .iter()
        .filter(|index| entries[**index].passthrough)
        .count() as i64;
    CandidatePlan {
        name,
        indices,
        confidence,
        actions,
        rank_score: verified * 100
            + descriptor * 15
            + passthrough * 45
            + (confidence * 10.0) as i64,
    }
}

fn select_conflict_free_zip_entries(entries: &[RecoveredEntry]) -> Vec<usize> {
    let mut order = (0..entries.len()).collect::<Vec<_>>();
    order.sort_by(|left, right| {
        zip_entry_score(&entries[*right])
            .cmp(&zip_entry_score(&entries[*left]))
            .then_with(|| entries[*left].data_start.cmp(&entries[*right].data_start))
    });
    let mut selected = Vec::new();
    let mut used_names = std::collections::HashSet::new();
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for index in order {
        let entry = &entries[index];
        let Some(name_key) = conflict_safe_name_key(&entry.name) else {
            continue;
        };
        if !used_names.insert(name_key) {
            continue;
        }
        if ranges
            .iter()
            .any(|(start, end)| entry.data_start < *end && entry.data_end > *start)
        {
            continue;
        }
        ranges.push((entry.data_start, entry.data_end));
        selected.push(index);
    }
    selected.sort_by_key(|index| entries[*index].data_start);
    selected
}

fn conflict_safe_name_key(name: &[u8]) -> Option<String> {
    let raw = String::from_utf8_lossy(name).replace('\\', "/");
    if raw.is_empty()
        || raw.contains('\0')
        || raw.starts_with('/')
        || has_windows_drive_prefix(&raw)
    {
        return None;
    }
    let mut key_parts = Vec::new();
    for part in raw.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return None;
        }
        if part.ends_with(' ') || part.ends_with('.') {
            return None;
        }
        if is_windows_reserved_name(part) {
            return None;
        }
        let folded = fold_conflict_component(part);
        if folded.is_empty() {
            return None;
        }
        key_parts.push(folded);
    }
    if key_parts.is_empty() {
        None
    } else {
        Some(key_parts.join("/"))
    }
}

fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()
}

fn is_windows_reserved_name(part: &str) -> bool {
    let base = part
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches([' ', '.'])
        .to_ascii_uppercase();
    matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (base.len() == 4
            && (base.starts_with("COM") || base.starts_with("LPT"))
            && base.as_bytes()[3].is_ascii_digit()
            && base.as_bytes()[3] != b'0')
}

fn fold_conflict_component(part: &str) -> String {
    let mut out = String::new();
    for ch in part.chars() {
        if ('\u{0300}'..='\u{036f}').contains(&ch) {
            continue;
        }
        for lower in ch.to_lowercase() {
            match lower {
                'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ā' | 'ă' | 'ą' => out.push('a'),
                'ç' | 'ć' | 'ĉ' | 'ċ' | 'č' => out.push('c'),
                'ď' | 'đ' => out.push('d'),
                'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ĕ' | 'ė' | 'ę' | 'ě' => out.push('e'),
                'ì' | 'í' | 'î' | 'ï' | 'ĩ' | 'ī' | 'ĭ' | 'į' | 'ı' => out.push('i'),
                'ñ' | 'ń' | 'ņ' | 'ň' => out.push('n'),
                'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ō' | 'ŏ' | 'ő' => out.push('o'),
                'ŕ' | 'ŗ' | 'ř' => out.push('r'),
                'ś' | 'ŝ' | 'ş' | 'š' => out.push('s'),
                'ť' | 'ţ' | 'ŧ' => out.push('t'),
                'ù' | 'ú' | 'û' | 'ü' | 'ũ' | 'ū' | 'ŭ' | 'ů' | 'ű' | 'ų' => {
                    out.push('u')
                }
                'ý' | 'ÿ' | 'ŷ' => out.push('y'),
                'ź' | 'ż' | 'ž' => out.push('z'),
                _ => out.push(lower),
            }
        }
    }
    out
}

fn zip_entry_score(entry: &RecoveredEntry) -> i64 {
    let mut score = 0i64;
    if entry.verified {
        score += 1000;
    }
    if entry.method == 0 || entry.method == 8 {
        score += 100;
    } else if entry.passthrough {
        score += 20;
    }
    if entry.descriptor {
        score += 40;
    }
    score += (entry.uncompressed_size.min(16 * 1024 * 1024) / 4096) as i64;
    score
}

fn write_candidate_zip(
    source: &[u8],
    entries: &[RecoveredEntry],
    plan: &CandidatePlan,
    output: &Path,
    max_output_bytes: Option<u64>,
) -> Result<WriteStats, String> {
    ensure_parent(output).map_err(|err| err.to_string())?;
    let temp = temp_path(output);
    let result = (|| -> Result<WriteStats, String> {
        let mut file = File::create(&temp).map_err(|err| err.to_string())?;
        let mut central_directory = Vec::new();
        let mut verified_entries = 0usize;
        let mut descriptor_entries = 0usize;
        let mut passthrough_entries = 0usize;
        for index in &plan.indices {
            let entry = &entries[*index];
            if entry.compressed_size > u32::MAX as u64 || entry.uncompressed_size > u32::MAX as u64
            {
                return Err("entry exceeds ZIP32 size limits".to_string());
            }
            let local_offset = file.stream_position().map_err(|err| err.to_string())?;
            if local_offset > u32::MAX as u64 {
                return Err("candidate exceeds ZIP32 offset limits".to_string());
            }
            let payload = &source[entry.data_start..entry.data_end];
            write_local_header(&mut file, entry).map_err(|err| err.to_string())?;
            file.write_all(payload).map_err(|err| err.to_string())?;
            append_central_directory(&mut central_directory, entry, local_offset as u32);
            if entry.verified {
                verified_entries += 1;
            }
            if entry.descriptor {
                descriptor_entries += 1;
            }
            if entry.passthrough {
                passthrough_entries += 1;
            }
            enforce_output_limit(&file, max_output_bytes)?;
        }
        let cd_offset = file.stream_position().map_err(|err| err.to_string())?;
        file.write_all(&central_directory)
            .map_err(|err| err.to_string())?;
        write_eocd(
            &mut file,
            plan.indices.len(),
            central_directory.len(),
            cd_offset,
        )
        .map_err(|err| err.to_string())?;
        file.flush().map_err(|err| err.to_string())?;
        enforce_output_limit(&file, max_output_bytes)?;
        let size = file.stream_position().map_err(|err| err.to_string())?;
        Ok(WriteStats {
            entries: plan.indices.len(),
            verified_entries,
            descriptor_entries,
            passthrough_entries,
            size,
        })
    })();
    match result {
        Ok(stats) => {
            if output.exists() {
                fs::remove_file(output).map_err(|err| err.to_string())?;
            }
            fs::rename(&temp, output).map_err(|err| err.to_string())?;
            Ok(stats)
        }
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(err)
        }
    }
}

fn write_local_header(file: &mut File, entry: &RecoveredEntry) -> std::io::Result<()> {
    let flags = entry.flags & !0x08;
    file.write_all(&0x0403_4B50u32.to_le_bytes())?;
    file.write_all(&entry.version_needed.to_le_bytes())?;
    file.write_all(&flags.to_le_bytes())?;
    file.write_all(&entry.method.to_le_bytes())?;
    file.write_all(&entry.mod_time.to_le_bytes())?;
    file.write_all(&entry.mod_date.to_le_bytes())?;
    file.write_all(&entry.crc32.to_le_bytes())?;
    file.write_all(&(entry.compressed_size as u32).to_le_bytes())?;
    file.write_all(&(entry.uncompressed_size as u32).to_le_bytes())?;
    file.write_all(&(entry.name.len() as u16).to_le_bytes())?;
    file.write_all(&0u16.to_le_bytes())?;
    file.write_all(&entry.name)?;
    Ok(())
}

fn append_central_directory(output: &mut Vec<u8>, entry: &RecoveredEntry, local_offset: u32) {
    let flags = entry.flags & !0x08;
    output.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
    output.extend_from_slice(&20u16.to_le_bytes());
    output.extend_from_slice(&entry.version_needed.to_le_bytes());
    output.extend_from_slice(&flags.to_le_bytes());
    output.extend_from_slice(&entry.method.to_le_bytes());
    output.extend_from_slice(&entry.mod_time.to_le_bytes());
    output.extend_from_slice(&entry.mod_date.to_le_bytes());
    output.extend_from_slice(&entry.crc32.to_le_bytes());
    output.extend_from_slice(&(entry.compressed_size as u32).to_le_bytes());
    output.extend_from_slice(&(entry.uncompressed_size as u32).to_le_bytes());
    output.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&local_offset.to_le_bytes());
    output.extend_from_slice(&entry.name);
}

fn write_eocd(
    file: &mut File,
    entries: usize,
    cd_size: usize,
    cd_offset: u64,
) -> std::io::Result<()> {
    file.write_all(&0x0605_4B50u32.to_le_bytes())?;
    file.write_all(&0u16.to_le_bytes())?;
    file.write_all(&0u16.to_le_bytes())?;
    file.write_all(&(entries as u16).to_le_bytes())?;
    file.write_all(&(entries as u16).to_le_bytes())?;
    file.write_all(&(cd_size as u32).to_le_bytes())?;
    file.write_all(&(cd_offset as u32).to_le_bytes())?;
    file.write_all(&0u16.to_le_bytes())?;
    Ok(())
}

fn verify_deflate(
    input: &[u8],
    expected_crc32: Option<u32>,
    expected_size: Option<u64>,
    max_output_bytes: Option<u64>,
    require_exact_input: bool,
) -> Result<DeflateInfo, String> {
    let mut decompressor = Decompress::new(false);
    let mut output = Vec::with_capacity(64 * 1024);
    let mut crc = Crc32::new();
    loop {
        let before_in = decompressor.total_in();
        let before_out = decompressor.total_out();
        let before_len = output.len();
        let input_offset = before_in as usize;
        if input_offset > input.len() {
            return Err("deflate input offset exceeded payload".to_string());
        }
        let status = decompressor
            .decompress_vec(&input[input_offset..], &mut output, FlushDecompress::None)
            .map_err(|err| format!("deflate decode failed: {err}"))?;
        if output.len() > before_len {
            crc.update(&output[before_len..]);
        }
        if let Some(limit) = max_output_bytes {
            if decompressor.total_out() > limit {
                return Err("deflate output exceeds deep repair entry budget".to_string());
            }
        }
        if status == Status::StreamEnd {
            let consumed = decompressor.total_in() as usize;
            if require_exact_input && consumed != input.len() {
                return Err("deflate stream ended before compressed payload boundary".to_string());
            }
            let computed_crc = crc.finish();
            if expected_crc32.is_some_and(|value| value != computed_crc) {
                return Err("deflate CRC mismatch".to_string());
            }
            if expected_size.is_some_and(|value| value != decompressor.total_out()) {
                return Err("deflate uncompressed size mismatch".to_string());
            }
            return Ok(DeflateInfo {
                consumed,
                uncompressed_size: decompressor.total_out(),
                crc32: computed_crc,
            });
        }
        if decompressor.total_in() as usize >= input.len() {
            return Err("deflate stream did not reach end marker".to_string());
        }
        if before_in == decompressor.total_in() && before_out == decompressor.total_out() {
            return Err("deflate decoder made no progress".to_string());
        }
        if output.len() > COPY_CHUNK_SIZE {
            output.clear();
        }
    }
}

fn descriptor_at(
    data: &[u8],
    offset: usize,
    expected_crc32: u32,
    expected_compressed: u64,
    expected_uncompressed: u64,
) -> bool {
    descriptor_at_impl(
        data,
        offset,
        expected_crc32,
        expected_compressed,
        expected_uncompressed,
    )
    .is_some()
}

fn descriptor_at_impl(
    data: &[u8],
    offset: usize,
    expected_crc32: u32,
    expected_compressed: u64,
    expected_uncompressed: u64,
) -> Option<usize> {
    for (len, has_sig, zip64) in [
        (16usize, true, false),
        (24, true, true),
        (12, false, false),
        (20, false, true),
    ] {
        if offset + len > data.len() {
            continue;
        }
        let base = if has_sig {
            if &data[offset..offset + 4] != DD_SIG {
                continue;
            }
            offset + 4
        } else {
            offset
        };
        let crc32 = u32_le(data, base);
        let (compressed, uncompressed) = if zip64 {
            (u64_le(data, base + 4), u64_le(data, base + 12))
        } else {
            (u32_le(data, base + 4) as u64, u32_le(data, base + 8) as u64)
        };
        if crc32 == expected_crc32
            && compressed == expected_compressed
            && uncompressed == expected_uncompressed
        {
            return Some(offset + len);
        }
    }
    None
}

fn descriptor_before_next_record(data: &[u8], data_start: usize) -> Option<(usize, u32, u64, u64)> {
    let next = find_next_zip_record(data, data_start)?;
    for (len, has_sig, zip64) in [
        (24usize, true, true),
        (20, false, true),
        (16, true, false),
        (12, false, false),
    ] {
        let descriptor_start = next.checked_sub(len)?;
        if descriptor_start < data_start {
            continue;
        }
        let base = if has_sig {
            if &data[descriptor_start..descriptor_start + 4] != DD_SIG {
                continue;
            }
            descriptor_start + 4
        } else {
            descriptor_start
        };
        let crc32 = u32_le(data, base);
        let (compressed, uncompressed) = if zip64 {
            (u64_le(data, base + 4), u64_le(data, base + 12))
        } else {
            (u32_le(data, base + 4) as u64, u32_le(data, base + 8) as u64)
        };
        if compressed == (descriptor_start - data_start) as u64 {
            return Some((descriptor_start, crc32, compressed, uncompressed));
        }
    }
    None
}

fn find_next_zip_record(data: &[u8], start: usize) -> Option<usize> {
    [LFH_SIG, CD_SIG, EOCD_SIG, ZIP64_EOCD_SIG, ZIP64_LOCATOR_SIG]
        .iter()
        .filter_map(|sig| memmem::find(&data[start..], sig).map(|index| start + index))
        .min()
}

fn zip64_sizes(extra: &[u8], compressed: u32, uncompressed: u32) -> Option<(u64, u64)> {
    let need_uncompressed = uncompressed == u32::MAX;
    let need_compressed = compressed == u32::MAX;
    if !need_uncompressed && !need_compressed {
        return Some((compressed as u64, uncompressed as u64));
    }
    let mut cursor = 0usize;
    while cursor + 4 <= extra.len() {
        let header_id = u16_le(extra, cursor);
        let size = u16_le(extra, cursor + 2) as usize;
        cursor += 4;
        if cursor + size > extra.len() {
            return None;
        }
        if header_id == 0x0001 {
            let mut field = cursor;
            let zip64_uncompressed = if need_uncompressed {
                if field + 8 > cursor + size {
                    return None;
                }
                let value = u64_le(extra, field);
                field += 8;
                value
            } else {
                uncompressed as u64
            };
            let zip64_compressed = if need_compressed {
                if field + 8 > cursor + size {
                    return None;
                }
                u64_le(extra, field)
            } else {
                compressed as u64
            };
            return Some((zip64_compressed, zip64_uncompressed));
        }
        cursor += size;
    }
    None
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
                return Err("ZIP deep repair input exceeds max_input_size_mb".to_string());
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
                    return Err("ZIP deep repair input exceeds max_input_size_mb".to_string());
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
        return Err("ZIP deep repair input exceeds max_input_size_mb".to_string());
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

fn status_dict(
    py: Python<'_>,
    status: &str,
    selected_path: &str,
    message: &str,
    warnings: &[String],
    candidates: &[WrittenCandidate],
    skipped_entries: usize,
    encrypted_entries: usize,
    confidence: f64,
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("selected_path", selected_path)?;
    result.set_item("selected_candidate", "")?;
    result.set_item("confidence", confidence)?;
    result.set_item("format", "zip")?;
    result.set_item("message", message)?;
    result.set_item("actions", PyList::empty(py))?;
    result.set_item("warnings", PyList::new(py, warnings)?)?;
    result.set_item("skipped_entries", skipped_entries)?;
    result.set_item("encrypted_entries", encrypted_entries)?;
    result.set_item("unsupported_entries", 0)?;
    result.set_item("recovered_entries", 0)?;
    result.set_item("verified_entries", 0)?;
    result.set_item("descriptor_entries", 0)?;
    result.set_item("passthrough_entries", 0)?;
    result.set_item("candidates", PyList::empty(py))?;
    result.set_item(
        "workspace_paths",
        PyList::new(
            py,
            candidates
                .iter()
                .map(|item| item.path.as_str())
                .collect::<Vec<_>>(),
        )?,
    )?;
    Ok(result.unbind())
}

#[allow(clippy::too_many_arguments)]
fn rebuild_status_dict(
    py: Python<'_>,
    status: &str,
    path: &str,
    message: &str,
    warnings: &[String],
    skipped_entries: usize,
    encrypted_entries: usize,
    descriptor_entries: usize,
    recovered_entries: usize,
    verified_entries: usize,
    timed_out: bool,
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("path", path)?;
    result.set_item("message", message)?;
    result.set_item("warnings", PyList::new(py, warnings)?)?;
    result.set_item("skipped_entries", skipped_entries)?;
    result.set_item("encrypted_entries", encrypted_entries)?;
    result.set_item("descriptor_entries", descriptor_entries)?;
    result.set_item("recovered_entries", recovered_entries)?;
    result.set_item("verified_entries", verified_entries)?;
    result.set_item("timed_out", timed_out)?;
    Ok(result.unbind())
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

fn enforce_output_limit(file: &File, max_output_bytes: Option<u64>) -> Result<(), String> {
    if let Some(limit) = max_output_bytes {
        let size = file.metadata().map_err(|err| err.to_string())?.len();
        if size > limit {
            return Err("candidate output exceeds repair.deep.max_output_size_mb".to_string());
        }
    }
    Ok(())
}

fn known_zip_method(method: u16) -> bool {
    matches!(method, 0 | 8 | 1 | 6 | 9 | 12 | 14 | 93 | 95 | 96 | 98 | 99)
}

fn timed_out(started: Instant, max_duration: Option<Duration>) -> bool {
    max_duration.is_some_and(|duration| started.elapsed() >= duration)
}

fn duration_from_seconds(value: f64) -> Option<Duration> {
    (value > 0.0).then(|| Duration::from_secs_f64(value))
}

fn mb_to_bytes(value: f64) -> Option<u64> {
    if value <= 0.0 {
        None
    } else {
        Some((value * 1024.0 * 1024.0) as u64)
    }
}

fn dedupe(values: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn crc32_bytes(bytes: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(bytes);
    crc.finish()
}

struct Crc32 {
    value: u32,
}

impl Crc32 {
    fn new() -> Self {
        Self { value: 0xFFFF_FFFF }
    }

    fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.value ^= *byte as u32;
            for _ in 0..8 {
                let mask = (self.value & 1).wrapping_neg();
                self.value = (self.value >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
    }

    fn finish(self) -> u32 {
        !self.value
    }
}

struct DirectoryFieldRepair {
    bytes: Vec<u8>,
    patches: Vec<BytePatch>,
    truncate_at: Option<u64>,
    confidence: f64,
    actions: Vec<String>,
    message: String,
}

struct BytePatch {
    offset: u64,
    data: Vec<u8>,
}

#[derive(Clone, Copy)]
struct EocdInfo {
    offset: usize,
    end: usize,
    disk_entries: u16,
    total_entries: u16,
    cd_size: u32,
    cd_offset: u32,
}

#[derive(Clone, Copy)]
struct CdWalk {
    offset: usize,
    end: usize,
    count: usize,
    valid: bool,
}

struct CentralEntry {
    flags: u16,
    method: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    name_len: u16,
    extra_len: u16,
    name: Vec<u8>,
    extra: Vec<u8>,
    extra_offset: usize,
    local_header_offset: u32,
}

struct LocalHeader {
    offset: usize,
    flags: u16,
    method: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    name: Vec<u8>,
    extra: Vec<u8>,
    extra_offset: usize,
    name_len: u16,
    extra_len: u16,
}

struct Zip64Extra {
    values: Vec<u64>,
    values_offset: usize,
}

#[derive(Clone, Copy)]
struct Zip64Eocd {
    offset: usize,
    end: usize,
    cd_size: u64,
    cd_offset: u64,
}

#[derive(Clone, Copy)]
struct Zip64Locator {
    offset: usize,
    end: usize,
    zip64_eocd_offset: u64,
    total_disks: u32,
}

fn repair_zip_comment_length(data: &[u8]) -> Result<DirectoryFieldRepair, String> {
    let eocd = find_eocd_record(data, true)
        .ok_or_else(|| "EOCD fixed header was not found".to_string())?;
    let cd = walk_central_directory_range(
        data,
        eocd.cd_offset as usize,
        Some(eocd.cd_offset as usize + eocd.cd_size as usize),
    );
    if !cd.valid {
        return Err("central directory range is not trusted".to_string());
    }
    let actual_comment_len = data.len().saturating_sub(eocd.offset + 22);
    if actual_comment_len > u16::MAX as usize {
        return Err("actual ZIP comment length is out of range".to_string());
    }
    let stored_comment_len = u16_le(data, eocd.offset + 20) as usize;
    if stored_comment_len == actual_comment_len {
        return Err("ZIP comment length already matches file length".to_string());
    }
    let patch = BytePatch {
        offset: (eocd.offset + 20) as u64,
        data: (actual_comment_len as u16).to_le_bytes().to_vec(),
    };
    let mut bytes = data.to_vec();
    bytes[eocd.offset + 20..eocd.offset + 22].copy_from_slice(&patch.data);
    Ok(DirectoryFieldRepair {
        bytes,
        patches: vec![patch],
        truncate_at: None,
        confidence: 0.86,
        actions: vec!["patch_zip_eocd_comment_length".to_string()],
        message: "ZIP EOCD comment length was patched by native repair".to_string(),
    })
}

fn repair_zip_cd_count(data: &[u8]) -> Result<DirectoryFieldRepair, String> {
    let eocd =
        find_eocd_record(data, false).ok_or_else(|| "trusted EOCD was not found".to_string())?;
    let cd = walk_central_directory_range(
        data,
        eocd.cd_offset as usize,
        Some(eocd.cd_offset as usize + eocd.cd_size as usize),
    );
    if !cd.valid {
        return Err("central directory range is not trusted".to_string());
    }
    if eocd.disk_entries as usize == cd.count && eocd.total_entries as usize == cd.count {
        return Err("central directory count already matches walked entries".to_string());
    }
    if cd.count > u16::MAX as usize {
        return Err("ZIP64 central directory count patch is not supported here".to_string());
    }
    let value = (cd.count as u16).to_le_bytes().to_vec();
    let patches = vec![
        BytePatch {
            offset: (eocd.offset + 8) as u64,
            data: value.clone(),
        },
        BytePatch {
            offset: (eocd.offset + 10) as u64,
            data: value,
        },
    ];
    let mut bytes = data.to_vec();
    for patch in &patches {
        let offset = patch.offset as usize;
        bytes[offset..offset + patch.data.len()].copy_from_slice(&patch.data);
    }
    Ok(DirectoryFieldRepair {
        bytes,
        patches,
        truncate_at: None,
        confidence: 0.88,
        actions: vec!["patch_zip_eocd_entry_counts".to_string()],
        message: "ZIP EOCD central directory counts were patched by native repair".to_string(),
    })
}

fn repair_zip_cd_offset(data: &[u8]) -> Result<DirectoryFieldRepair, String> {
    let eocd = find_eocd_record(data, true)
        .ok_or_else(|| "EOCD or central directory is missing".to_string())?;
    let cd = find_valid_central_directory(data)
        .ok_or_else(|| "EOCD or central directory is missing".to_string())?;
    if eocd.cd_offset as usize == cd.offset
        && eocd.cd_size as usize == cd.end - cd.offset
        && eocd.total_entries as usize == cd.count
    {
        return Err(
            "central directory offset already matches parsed central directory".to_string(),
        );
    }
    if cd.count > u16::MAX as usize
        || cd.end - cd.offset > u32::MAX as usize
        || cd.offset > u32::MAX as usize
    {
        return Err("ZIP64 central directory rewrite is not supported here".to_string());
    }
    let mut tail = Vec::new();
    tail.extend_from_slice(EOCD_SIG);
    tail.extend_from_slice(&0u16.to_le_bytes());
    tail.extend_from_slice(&0u16.to_le_bytes());
    tail.extend_from_slice(&(cd.count as u16).to_le_bytes());
    tail.extend_from_slice(&(cd.count as u16).to_le_bytes());
    tail.extend_from_slice(&((cd.end - cd.offset) as u32).to_le_bytes());
    tail.extend_from_slice(&(cd.offset as u32).to_le_bytes());
    let comment_len = eocd.end.saturating_sub(eocd.offset + 22);
    tail.extend_from_slice(&(comment_len as u16).to_le_bytes());
    if comment_len > 0 && eocd.offset + 22 + comment_len <= data.len() {
        tail.extend_from_slice(&data[eocd.offset + 22..eocd.offset + 22 + comment_len]);
    }
    let mut bytes = data[..cd.end].to_vec();
    bytes.extend_from_slice(&tail);
    Ok(DirectoryFieldRepair {
        bytes,
        patches: vec![BytePatch {
            offset: cd.end as u64,
            data: tail,
        }],
        truncate_at: Some(cd.end as u64),
        confidence: 0.9,
        actions: vec![
            "scan_central_directory".to_string(),
            "rewrite_eocd_cd_offset_size_count".to_string(),
        ],
        message: "ZIP EOCD central directory offset/size/count were rewritten by native repair"
            .to_string(),
    })
}

fn repair_zip_trailing_junk(data: &[u8]) -> Result<DirectoryFieldRepair, String> {
    let eocd = find_eocd_record(data, true).ok_or_else(|| "EOCD was not found".to_string())?;
    if eocd.end == data.len() {
        return Err("no trailing bytes after EOCD".to_string());
    }
    Ok(DirectoryFieldRepair {
        bytes: data[..eocd.end].to_vec(),
        patches: Vec::new(),
        truncate_at: Some(eocd.end as u64),
        confidence: 0.88,
        actions: vec!["trim_after_eocd".to_string()],
        message: "ZIP trailing junk was trimmed by native repair".to_string(),
    })
}

fn repair_zip_eocd(data: &[u8]) -> Result<DirectoryFieldRepair, String> {
    if let Some(eocd) = find_eocd_record(data, true) {
        let cd = walk_central_directory_range(
            data,
            eocd.cd_offset as usize,
            Some(eocd.cd_offset as usize + eocd.cd_size as usize),
        );
        if cd.valid && eocd.end < data.len() {
            return Ok(DirectoryFieldRepair {
                bytes: data[..eocd.end].to_vec(),
                patches: Vec::new(),
                truncate_at: Some(eocd.end as u64),
                confidence: 0.9,
                actions: vec!["trim_after_eocd".to_string()],
                message: "ZIP EOCD boundary was repaired by native trim".to_string(),
            });
        }
    }
    let cd = find_valid_central_directory(data)
        .ok_or_else(|| "no valid central directory was found for EOCD rebuild".to_string())?;
    let tail = eocd_tail_for_cd(data, &cd, None)?;
    let mut bytes = data[..cd.end].to_vec();
    bytes.extend_from_slice(&tail);
    Ok(DirectoryFieldRepair {
        bytes,
        patches: vec![BytePatch {
            offset: cd.end as u64,
            data: tail,
        }],
        truncate_at: Some(cd.end as u64),
        confidence: 0.94,
        actions: vec![
            "scan_central_directory".to_string(),
            "rebuild_eocd".to_string(),
        ],
        message: "ZIP EOCD was rebuilt by native repair".to_string(),
    })
}

fn repair_zip_local_header_fields(data: &[u8]) -> Result<DirectoryFieldRepair, String> {
    let eocd =
        find_eocd_record(data, false).ok_or_else(|| "trusted EOCD was not found".to_string())?;
    let entries = parse_central_directory_entries(
        data,
        eocd.cd_offset as usize,
        eocd.cd_offset as usize + eocd.cd_size as usize,
    );
    if entries.is_empty() {
        return Err("no central directory entries were parseable".to_string());
    }
    let mut bytes = data.to_vec();
    let mut patches = Vec::new();
    for entry in entries {
        if entry.local_header_offset == 0xFFFF_FFFF {
            continue;
        }
        let Some(mut local) = parse_local_header(&bytes, entry.local_header_offset as usize) else {
            continue;
        };
        if local.name_len != entry.name_len {
            let local_name_start = local.offset + LOCAL_HEADER_LEN;
            let local_entry_name =
                bytes.get(local_name_start..local_name_start + entry.name_len as usize);
            if local_entry_name == Some(entry.name.as_slice()) {
                add_zip_patch(
                    &mut bytes,
                    &mut patches,
                    local.offset + 26,
                    &(entry.name_len).to_le_bytes(),
                );
                if let Some(updated) =
                    parse_local_header(&bytes, entry.local_header_offset as usize)
                {
                    local = updated;
                }
            }
        }
        if local.extra_len != entry.extra_len {
            let expected_start = local.offset + LOCAL_HEADER_LEN + entry.name_len as usize;
            let expected = bytes.get(expected_start..expected_start + entry.extra_len as usize);
            if expected == Some(entry.extra.as_slice()) {
                add_zip_patch(
                    &mut bytes,
                    &mut patches,
                    local.offset + 28,
                    &(entry.extra_len).to_le_bytes(),
                );
                if let Some(updated) =
                    parse_local_header(&bytes, entry.local_header_offset as usize)
                {
                    local = updated;
                }
            }
        }
        if local.flags != entry.flags {
            add_zip_patch(
                &mut bytes,
                &mut patches,
                local.offset + 6,
                &entry.flags.to_le_bytes(),
            );
        }
        if local.method != entry.method {
            add_zip_patch(
                &mut bytes,
                &mut patches,
                local.offset + 8,
                &entry.method.to_le_bytes(),
            );
        }
        if entry.flags & 0x08 == 0 {
            if local.crc32 != entry.crc32 {
                add_zip_patch(
                    &mut bytes,
                    &mut patches,
                    local.offset + 14,
                    &entry.crc32.to_le_bytes(),
                );
            }
            if entry.compressed_size != 0xFFFF_FFFF
                && local.compressed_size != entry.compressed_size
            {
                add_zip_patch(
                    &mut bytes,
                    &mut patches,
                    local.offset + 18,
                    &entry.compressed_size.to_le_bytes(),
                );
            }
            if entry.uncompressed_size != 0xFFFF_FFFF
                && local.uncompressed_size != entry.uncompressed_size
            {
                add_zip_patch(
                    &mut bytes,
                    &mut patches,
                    local.offset + 22,
                    &entry.uncompressed_size.to_le_bytes(),
                );
            }
        }
    }
    if patches.is_empty() {
        return Err("no ZIP local header field mismatch was safely repairable".to_string());
    }
    Ok(DirectoryFieldRepair {
        bytes,
        patches,
        truncate_at: None,
        confidence: 0.9,
        actions: vec!["reconcile_zip_local_header_fields_with_central_directory".to_string()],
        message: "ZIP local header fields were reconciled by native repair".to_string(),
    })
}

fn repair_zip64_fields(data: &[u8]) -> Result<DirectoryFieldRepair, String> {
    if let Some(repair) = repair_zip64_tail(data)? {
        return Ok(repair);
    }
    repair_zip64_central_extra(data)
}

fn repair_zip64_tail(data: &[u8]) -> Result<Option<DirectoryFieldRepair>, String> {
    let Some(eocd) = find_eocd_record(data, true) else {
        return Ok(None);
    };
    let Some(zip64) = find_zip64_eocd(data, eocd.offset) else {
        return Ok(None);
    };
    let mut cd = walk_central_directory_range(
        data,
        zip64.cd_offset as usize,
        Some(zip64.cd_offset as usize + zip64.cd_size as usize),
    );
    if !cd.valid {
        cd = match find_valid_central_directory(data) {
            Some(value) => value,
            None => return Ok(None),
        };
    }
    if !cd.valid {
        return Ok(None);
    }
    let mut record = data[zip64.offset..zip64.end].to_vec();
    let expected_record_size = (zip64.end - zip64.offset - 12) as u64;
    let mut actions = Vec::new();
    for (offset, value) in [
        (4usize, expected_record_size),
        (24, cd.count as u64),
        (32, cd.count as u64),
        (40, (cd.end - cd.offset) as u64),
        (48, cd.offset as u64),
    ] {
        let encoded = value.to_le_bytes();
        if record.get(offset..offset + 8) != Some(encoded.as_slice()) {
            record[offset..offset + 8].copy_from_slice(&encoded);
            actions.push("rewrite_zip64_eocd_fields".to_string());
        }
    }
    let expected_locator = zip64_locator_bytes(zip64.offset as u64);
    let locator = find_zip64_locator(data, eocd.offset);
    let locator_bytes = if locator
        .is_some_and(|item| item.zip64_eocd_offset == zip64.offset as u64 && item.total_disks >= 1)
    {
        if data[locator.unwrap().offset..locator.unwrap().end] != expected_locator {
            actions.push("normalize_zip64_eocd_locator".to_string());
            expected_locator
        } else {
            data[locator.unwrap().offset..locator.unwrap().end].to_vec()
        }
    } else {
        actions.push("rewrite_zip64_eocd_locator".to_string());
        expected_locator
    };
    dedupe(&mut actions);
    if actions.is_empty() {
        return Ok(None);
    }
    let tail_start = zip64.offset;
    let mut tail = record;
    tail.extend_from_slice(&locator_bytes);
    tail.extend_from_slice(&data[eocd.offset..eocd.end]);
    let mut bytes = data[..tail_start].to_vec();
    bytes.extend_from_slice(&tail);
    Ok(Some(DirectoryFieldRepair {
        bytes,
        patches: vec![BytePatch {
            offset: tail_start as u64,
            data: tail,
        }],
        truncate_at: Some(tail_start as u64),
        confidence: 0.98,
        actions,
        message: "ZIP64 tail fields were rewritten by native repair".to_string(),
    }))
}

fn repair_zip64_central_extra(data: &[u8]) -> Result<DirectoryFieldRepair, String> {
    let eocd =
        find_eocd_record(data, true).ok_or_else(|| "trusted EOCD was not found".to_string())?;
    let (cd_offset, cd_end) = if let Some(zip64) = find_zip64_eocd(data, eocd.offset) {
        (
            zip64.cd_offset as usize,
            (zip64.cd_offset + zip64.cd_size) as usize,
        )
    } else {
        (
            eocd.cd_offset as usize,
            eocd.cd_offset as usize + eocd.cd_size as usize,
        )
    };
    let entries = parse_central_directory_entries(data, cd_offset, cd_end);
    if entries.is_empty() {
        return Err("no ZIP64 central directory entries were parseable".to_string());
    }
    let mut bytes = data.to_vec();
    let mut patches = Vec::new();
    for entry in entries {
        let Some(local) = find_local_for_central(data, &entry) else {
            continue;
        };
        let Some(central_zip64) = parse_zip64_extra(&entry.extra, entry.extra_offset) else {
            continue;
        };
        let Some(local_zip64) = parse_zip64_extra(&local.extra, local.extra_offset) else {
            continue;
        };
        let Some(expected) = expected_zip64_values(&entry, &local, &local_zip64) else {
            continue;
        };
        if central_zip64.values.len() < expected.len() {
            continue;
        }
        for (index, value) in expected.into_iter().enumerate() {
            if central_zip64.values[index] == value {
                continue;
            }
            let offset = central_zip64.values_offset + index * 8;
            add_zip_patch(&mut bytes, &mut patches, offset, &value.to_le_bytes());
        }
    }
    if patches.is_empty() {
        return Err("no ZIP64 tail or extra field mismatch was safely repairable".to_string());
    }
    Ok(DirectoryFieldRepair {
        bytes,
        patches,
        truncate_at: None,
        confidence: 0.96,
        actions: vec!["reconcile_zip64_central_extra_fields".to_string()],
        message: "ZIP64 central extra fields were reconciled by native repair".to_string(),
    })
}

fn find_eocd_record(data: &[u8], allow_trailing_junk: bool) -> Option<EocdInfo> {
    let mut pos = data
        .windows(EOCD_SIG.len())
        .rposition(|window| window == EOCD_SIG)?;
    loop {
        if pos + 22 <= data.len() {
            let comment_len = u16_le(data, pos + 20) as usize;
            let end = pos + 22 + comment_len;
            if end <= data.len() && (allow_trailing_junk || end == data.len()) {
                return Some(EocdInfo {
                    offset: pos,
                    end,
                    disk_entries: u16_le(data, pos + 8),
                    total_entries: u16_le(data, pos + 10),
                    cd_size: u32_le(data, pos + 12),
                    cd_offset: u32_le(data, pos + 16),
                });
            }
        }
        if pos == 0 {
            return None;
        }
        pos = data[..pos]
            .windows(EOCD_SIG.len())
            .rposition(|window| window == EOCD_SIG)?;
    }
}

fn find_valid_central_directory(data: &[u8]) -> Option<CdWalk> {
    let mut pos = memmem::find(data, CD_SIG)?;
    let mut best: Option<CdWalk> = None;
    loop {
        let walk = walk_central_directory_range(data, pos, None);
        if walk.valid && best.is_none_or(|current| walk.count > current.count) {
            best = Some(walk);
        }
        let next_start = pos + 4;
        if next_start >= data.len() {
            break;
        }
        let Some(next) = memmem::find(&data[next_start..], CD_SIG) else {
            break;
        };
        pos = next_start + next;
    }
    best
}

fn walk_central_directory_range(data: &[u8], offset: usize, expected_end: Option<usize>) -> CdWalk {
    let mut pos = offset;
    let mut count = 0usize;
    while pos + 46 <= data.len() && &data[pos..pos + 4] == CD_SIG {
        let name_len = u16_le(data, pos + 28) as usize;
        let extra_len = u16_le(data, pos + 30) as usize;
        let comment_len = u16_le(data, pos + 32) as usize;
        let record_len = 46usize
            .saturating_add(name_len)
            .saturating_add(extra_len)
            .saturating_add(comment_len);
        if record_len < 46 || pos + record_len > data.len() {
            break;
        }
        pos += record_len;
        count += 1;
        if expected_end.is_some_and(|end| pos >= end) {
            break;
        }
    }
    CdWalk {
        offset,
        end: pos,
        count,
        valid: count > 0 && expected_end.is_none_or(|end| pos == end),
    }
}

fn parse_central_directory_entries(
    data: &[u8],
    offset: usize,
    expected_end: usize,
) -> Vec<CentralEntry> {
    let mut entries = Vec::new();
    let mut pos = offset;
    while pos + 46 <= data.len() && pos < expected_end && &data[pos..pos + 4] == CD_SIG {
        let name_len = u16_le(data, pos + 28);
        let extra_len = u16_le(data, pos + 30);
        let comment_len = u16_le(data, pos + 32) as usize;
        let name_start = pos + 46;
        let extra_start = name_start + name_len as usize;
        let comment_start = extra_start + extra_len as usize;
        let record_end = comment_start + comment_len;
        if record_end > data.len() || record_end > expected_end {
            break;
        }
        entries.push(CentralEntry {
            flags: u16_le(data, pos + 8),
            method: u16_le(data, pos + 10),
            crc32: u32_le(data, pos + 16),
            compressed_size: u32_le(data, pos + 20),
            uncompressed_size: u32_le(data, pos + 24),
            name_len,
            extra_len,
            name: data[name_start..extra_start].to_vec(),
            extra: data[extra_start..comment_start].to_vec(),
            extra_offset: extra_start,
            local_header_offset: u32_le(data, pos + 42),
        });
        pos = record_end;
    }
    entries
}

fn parse_local_header(data: &[u8], offset: usize) -> Option<LocalHeader> {
    if offset + LOCAL_HEADER_LEN > data.len() || &data[offset..offset + 4] != LFH_SIG {
        return None;
    }
    let name_len = u16_le(data, offset + 26);
    let extra_len = u16_le(data, offset + 28);
    let name_start = offset + LOCAL_HEADER_LEN;
    let extra_start = name_start.checked_add(name_len as usize)?;
    let data_start = extra_start.checked_add(extra_len as usize)?;
    if data_start > data.len() {
        return None;
    }
    Some(LocalHeader {
        offset,
        flags: u16_le(data, offset + 6),
        method: u16_le(data, offset + 8),
        crc32: u32_le(data, offset + 14),
        compressed_size: u32_le(data, offset + 18),
        uncompressed_size: u32_le(data, offset + 22),
        name: data[name_start..extra_start].to_vec(),
        extra: data[extra_start..data_start].to_vec(),
        extra_offset: extra_start,
        name_len,
        extra_len,
    })
}

fn parse_zip64_extra(extra: &[u8], absolute_extra_offset: usize) -> Option<Zip64Extra> {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let header_id = u16_le(extra, pos);
        let size = u16_le(extra, pos + 2) as usize;
        let value_start = pos + 4;
        let value_end = value_start.checked_add(size)?;
        if value_end > extra.len() {
            return None;
        }
        if header_id == 0x0001 {
            let mut values = Vec::new();
            let mut cursor = value_start;
            while cursor + 8 <= value_end {
                values.push(u64_le(extra, cursor));
                cursor += 8;
            }
            return Some(Zip64Extra {
                values,
                values_offset: absolute_extra_offset + value_start,
            });
        }
        pos = value_end;
    }
    None
}

fn find_zip64_eocd(data: &[u8], before: usize) -> Option<Zip64Eocd> {
    let pos = memmem::rfind(&data[..before.min(data.len())], ZIP64_EOCD_SIG)?;
    if pos + 56 > data.len() {
        return None;
    }
    let record_size = u64_le(data, pos + 4);
    let end = pos
        .checked_add(12)?
        .checked_add(usize::try_from(record_size).ok()?)?;
    if end > data.len() || end < pos + 56 {
        return None;
    }
    Some(Zip64Eocd {
        offset: pos,
        end,
        cd_size: u64_le(data, pos + 40),
        cd_offset: u64_le(data, pos + 48),
    })
}

fn find_zip64_locator(data: &[u8], eocd_offset: usize) -> Option<Zip64Locator> {
    let pos = memmem::rfind(&data[..eocd_offset.min(data.len())], ZIP64_LOCATOR_SIG)?;
    if pos + 20 > data.len() {
        return None;
    }
    Some(Zip64Locator {
        offset: pos,
        end: pos + 20,
        zip64_eocd_offset: u64_le(data, pos + 8),
        total_disks: u32_le(data, pos + 16),
    })
}

fn zip64_locator_bytes(zip64_offset: u64) -> Vec<u8> {
    let mut output = Vec::with_capacity(20);
    output.extend_from_slice(ZIP64_LOCATOR_SIG);
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&zip64_offset.to_le_bytes());
    output.extend_from_slice(&1u32.to_le_bytes());
    output
}

fn find_local_for_central(data: &[u8], entry: &CentralEntry) -> Option<LocalHeader> {
    let mut candidates = Vec::new();
    if entry.local_header_offset != 0xFFFF_FFFF {
        candidates.push(entry.local_header_offset as usize);
    }
    if let Some(zip64) = parse_zip64_extra(&entry.extra, entry.extra_offset) {
        if zip64.values.len() >= 3 {
            candidates.push(zip64.values[2] as usize);
        }
    }
    for offset in candidates {
        if let Some(local) = parse_local_header(data, offset) {
            if local.name == entry.name {
                return Some(local);
            }
        }
    }
    let mut pos = memmem::find(data, LFH_SIG)?;
    loop {
        if let Some(local) = parse_local_header(data, pos) {
            if local.name == entry.name {
                return Some(local);
            }
        }
        let next_start = pos + 4;
        if next_start >= data.len() {
            return None;
        }
        let Some(next) = memmem::find(&data[next_start..], LFH_SIG) else {
            return None;
        };
        pos = next_start + next;
    }
}

fn expected_zip64_values(
    entry: &CentralEntry,
    local: &LocalHeader,
    local_zip64: &Zip64Extra,
) -> Option<Vec<u64>> {
    let mut local_values = local_zip64.values.clone();
    let mut expected = Vec::new();
    if entry.uncompressed_size == 0xFFFF_FFFF {
        if local_values.is_empty() {
            return None;
        }
        expected.push(local_values.remove(0));
    }
    if entry.compressed_size == 0xFFFF_FFFF {
        if local_values.is_empty() {
            return None;
        }
        expected.push(local_values.remove(0));
    }
    if entry.local_header_offset == 0xFFFF_FFFF {
        expected.push(local.offset as u64);
    }
    Some(expected)
}

fn eocd_tail_for_cd(
    data: &[u8],
    cd: &CdWalk,
    source_eocd: Option<EocdInfo>,
) -> Result<Vec<u8>, String> {
    if cd.count > u16::MAX as usize
        || cd.end - cd.offset > u32::MAX as usize
        || cd.offset > u32::MAX as usize
    {
        return Err("ZIP64 central directory rewrite is not supported here".to_string());
    }
    let mut tail = Vec::new();
    tail.extend_from_slice(EOCD_SIG);
    tail.extend_from_slice(&0u16.to_le_bytes());
    tail.extend_from_slice(&0u16.to_le_bytes());
    tail.extend_from_slice(&(cd.count as u16).to_le_bytes());
    tail.extend_from_slice(&(cd.count as u16).to_le_bytes());
    tail.extend_from_slice(&((cd.end - cd.offset) as u32).to_le_bytes());
    tail.extend_from_slice(&(cd.offset as u32).to_le_bytes());
    let comment = source_eocd
        .and_then(|eocd| data.get(eocd.offset + 22..eocd.end))
        .unwrap_or(&[]);
    if comment.len() > u16::MAX as usize {
        return Err("ZIP comment length is out of range".to_string());
    }
    tail.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    tail.extend_from_slice(comment);
    Ok(tail)
}

fn add_zip_patch(bytes: &mut [u8], patches: &mut Vec<BytePatch>, offset: usize, payload: &[u8]) {
    if bytes.get(offset..offset + payload.len()) == Some(payload) {
        return;
    }
    bytes[offset..offset + payload.len()].copy_from_slice(payload);
    patches.push(BytePatch {
        offset: offset as u64,
        data: payload.to_vec(),
    });
}

fn write_bytes_atomic(data: &[u8], output: &Path) -> Result<u64, String> {
    ensure_parent(output).map_err(|err| err.to_string())?;
    let temp = temp_path(output);
    let result = (|| -> Result<(), String> {
        let mut file = File::create(&temp).map_err(|err| err.to_string())?;
        file.write_all(data).map_err(|err| err.to_string())?;
        file.flush().map_err(|err| err.to_string())?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            if output.exists() {
                fs::remove_file(output).map_err(|err| err.to_string())?;
            }
            fs::rename(&temp, output).map_err(|err| err.to_string())?;
            Ok(data.len() as u64)
        }
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(err)
        }
    }
}

fn simple_repair_status(
    py: Python<'_>,
    status: &str,
    format: &str,
    selected_path: &str,
    message: &str,
    actions: &[&str],
    confidence: f64,
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("format", format)?;
    result.set_item("selected_path", selected_path)?;
    result.set_item("message", message)?;
    result.set_item("confidence", confidence)?;
    result.set_item("actions", PyList::new(py, actions)?)?;
    result.set_item("warnings", PyList::empty(py))?;
    result.set_item("workspace_paths", PyList::empty(py))?;
    Ok(result.unbind())
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

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn scan_recovers_stored_entry_and_skips_bad_crc() {
        let mut data = Vec::new();
        append_local_stored(&mut data, b"good.txt", b"good", crc32_bytes(b"good"));
        append_local_stored(&mut data, b"bad.txt", b"bad", 0);
        let options = test_options();

        let scan = scan_entries(&data, &options, Instant::now());

        assert_eq!(scan.entries.len(), 1);
        assert_eq!(scan.entries[0].name, b"good.txt");
        assert!(!scan.skipped_offsets.is_empty());
    }

    #[test]
    fn scan_recovers_deflate_descriptor_entry() {
        let payload = b"descriptor payload";
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut data = Vec::new();
        append_local_descriptor_deflate(
            &mut data,
            b"dd.txt",
            &compressed,
            crc32_bytes(payload),
            payload.len() as u64,
        );
        data.extend_from_slice(CD_SIG);
        let options = test_options();

        let scan = scan_entries(&data, &options, Instant::now());

        assert_eq!(scan.entries.len(), 1);
        assert!(scan.entries[0].verified);
        assert!(scan.entries[0].descriptor);
    }

    fn test_options() -> DeepZipOptions {
        DeepZipOptions {
            max_candidates: 3,
            max_entries: 100,
            max_input_bytes: None,
            max_output_bytes: None,
            max_entry_uncompressed_bytes: Some(1024 * 1024),
            max_duration: None,
            verify_candidates: true,
        }
    }

    fn append_local_stored(output: &mut Vec<u8>, name: &[u8], payload: &[u8], crc32: u32) {
        output.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
        output.extend_from_slice(&20u16.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&crc32.to_le_bytes());
        output.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        output.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        output.extend_from_slice(&(name.len() as u16).to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(name);
        output.extend_from_slice(payload);
    }

    fn append_local_descriptor_deflate(
        output: &mut Vec<u8>,
        name: &[u8],
        compressed: &[u8],
        crc32: u32,
        uncompressed_size: u64,
    ) {
        output.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
        output.extend_from_slice(&20u16.to_le_bytes());
        output.extend_from_slice(&0x08u16.to_le_bytes());
        output.extend_from_slice(&8u16.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&0u32.to_le_bytes());
        output.extend_from_slice(&0u32.to_le_bytes());
        output.extend_from_slice(&0u32.to_le_bytes());
        output.extend_from_slice(&(name.len() as u16).to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(name);
        output.extend_from_slice(compressed);
        output.extend_from_slice(DD_SIG);
        output.extend_from_slice(&crc32.to_le_bytes());
        output.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        output.extend_from_slice(&(uncompressed_size as u32).to_le_bytes());
    }
}
