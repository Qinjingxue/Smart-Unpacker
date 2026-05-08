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

fn extract_password(source_input: &Bound<'_, PyDict>) -> Option<String> {
    source_input
        .get_item("password")
        .ok()
        .flatten()
        .and_then(|v| v.extract::<String>().ok())
}

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
    let password = extract_password(source_input);
    let options = DeepZipOptions {
        max_candidates: max_candidates.max(1),
        max_entries: max_entries.max(1),
        max_input_bytes: mb_to_bytes(max_input_size_mb),
        max_output_bytes: mb_to_bytes(max_output_size_mb),
        max_entry_uncompressed_bytes: mb_to_bytes(max_entry_uncompressed_mb),
        max_duration: duration_from_seconds(max_seconds),
        verify_candidates,
        allow_unverified_entries: false,
        password,
    };
    let data = match read_source_input(source_input, options.max_input_bytes) {
        Ok(data) => data,
        Err(message) => return status_dict(py, "skipped", "", &message, &[], &[], 0, 0, 0.0, None, Some("input_read_failed")),
    };
    let scan = scan_entries(&data, &options, started);
    let mut plans = candidate_plans(&scan, &options);
    if plans.is_empty() {
        if scan.entries.is_empty() {
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
                Some(&scan),
                Some("no_recoverable_entries"),
            );
        }
        let indices: Vec<usize> = (0..scan.entries.len()).collect();
        plans = vec![make_plan("zip_deep_partial_fallback", indices, &scan.entries, 0.55, vec!["scan_entries", "best_effort_rebuild", "write_partial_zip"])];
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
                policy: "",
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
                        Some(&scan),
                        Some("candidate_write_failed"),
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
            Some(&scan),
            Some("candidate_write_failed"),
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
    preserve_raw_names=false,
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
    preserve_raw_names: bool,
    max_entries: usize,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
    verify_candidates: bool,
) -> PyResult<Py<PyDict>> {
    let started = Instant::now();
    let password = extract_password(source_input);
    let logical_stream_built = get_optional_string(source_input, "kind")
        .ok()
        .flatten()
        .is_some_and(|kind| kind == "concat_ranges");
    let options = DeepZipOptions {
        max_candidates: 1,
        max_entries: max_entries.max(1),
        max_input_bytes: mb_to_bytes(max_input_size_mb),
        max_output_bytes: mb_to_bytes(max_output_size_mb),
        max_entry_uncompressed_bytes: None,
        max_duration: None,
        verify_candidates,
        allow_unverified_entries: preserve_raw_names,
        password,
    };
    let data = match read_source_input(source_input, options.max_input_bytes) {
        Ok(data) => data,
        Err(message) => {
            return rebuild_status_dict(py, "skipped", "", &message, &[], 0, 0, 0, 0, 0, false, None, Some("input_read_failed"))
        }
    };
    let scan = scan_entries(&data, &options, started);
    let mut indices = scan
        .entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            (!require_data_descriptor || entry.descriptor).then_some(index)
        })
        .collect::<Vec<_>>();
    if indices.is_empty() {
        if scan.entries.is_empty() {
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
                0, 0, scan.timed_out,
                Some(&scan),
                Some(if require_data_descriptor { "no_data_descriptor_entries" } else { "no_local_file_headers" }),
            );
        }
        indices = (0..scan.entries.len()).collect();
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
                if preserve_raw_names {
                    "preserve_raw_filename_bytes"
                } else {
                    "rebuild_zip_central_directory"
                },
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
        Ok(stats) => add_rebuild_target_metadata(py, rebuild_status_dict(
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
            Some(&scan),
            None,
        )?, preserve_raw_names, logical_stream_built),
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
            Some(&scan),
            Some("candidate_write_failed"),
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
        Err(message) => return simple_repair_status(py, "skipped", "zip", "", &message, &[], 0.0, Some(build_field_repair_diagnostics(py, "", false, 0, "input_read_failed")?)),
    };
    let result = match repair_name {
        "zip_comment_length_fix" => repair_zip_comment_length(&data),
        "zip_central_directory_count_fix" => repair_zip_cd_count(&data),
        "zip_central_directory_offset_fix" => repair_zip_cd_offset(&data),
        "zip_trailing_junk_trim" => repair_zip_trailing_junk(&data),
        "zip_eocd_repair" => repair_zip_eocd(&data),
        "zip_local_header_field_repair" => repair_zip_local_header_fields(&data),
        "zip64_extra_size" => repair_zip64_central_extra(&data),
        "zip64_locator" => repair_zip64_tail_target(&data, Zip64TailTarget::Locator),
        "zip64_eocd" => repair_zip64_tail_target(&data, Zip64TailTarget::Eocd),
        _ => Err(format!(
            "unsupported ZIP directory field repair: {repair_name}"
        )),
    };
    let repair = match result {
        Ok(repair) => repair,
        Err(message) => {
            let target = repair_name_to_target(repair_name);
            return simple_repair_status(py, "unrepairable", "zip", "", &message, &[], 0.0, Some(build_field_repair_diagnostics(py, target, false, 0, &message)?))
        }
    };
    let output_path = Path::new(workspace).join(format!("{repair_name}.zip"));
    if let Err(message) = write_bytes_atomic(&repair.bytes, &output_path) {
        let target = repair_name_to_target(repair_name);
        return simple_repair_status(
            py,
            "unrepairable",
            "zip",
            "",
            &format!("ZIP repaired candidate could not be written: {message}"),
            &[],
            0.0,
            Some(build_field_repair_diagnostics(py, target, false, 0, &message)?),
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
    let target = repair_name_to_target(repair_name);
    result.set_item("native_key", "native_zip_directory_field_repair")?;
    result.set_item("native_target", target)?;
    result.set_item("materialized_path", output_path.to_string_lossy().to_string())?;
    result.set_item("candidate_status", "complete")?;
    result.set_item("patch_facts", PyList::new(py, field_patch_facts(target))?)?;
    result.set_item("residual_facts", PyList::empty(py))?;
    result.set_item("validation_details", build_validation_details(py, target, true, &[])?)?;
    result.set_item(
        "diagnostics",
        build_field_repair_diagnostics(
            py,
            target,
            !repair.patches.is_empty(),
            repair.patches.len(),
            "",
        )?,
    )?;
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
    verify_candidates=true,
    policy="crc_match"
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
    policy: &str,
) -> PyResult<Py<PyDict>> {
    let password = extract_password(source_input);
    let options = DeepZipOptions {
        max_candidates: 1,
        max_entries: max_entries.max(1),
        max_input_bytes: mb_to_bytes(max_input_size_mb),
        max_output_bytes: mb_to_bytes(max_output_size_mb),
        max_entry_uncompressed_bytes: mb_to_bytes(max_entry_uncompressed_mb),
        max_duration: None,
        verify_candidates,
        allow_unverified_entries: false,
        password,
    };
    let data = match read_source_input(source_input, options.max_input_bytes) {
        Ok(data) => data,
        Err(message) => return status_dict(py, "skipped", "", &message, &[], &[], 0, 0, 0.0, None, Some("input_read_failed")),
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
            Some(&scan),
            Some("no_recoverable_entries"),
        );
    }
    let selected_indices = select_conflict_free_zip_entries_by_policy(&scan.entries, policy);
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
            Some(&scan),
            Some("no_conflict_free_entries"),
        );
    }
    let conflict_count = scan.entries.len().saturating_sub(selected_indices.len());
    if conflict_count == 0 && scan.skipped_offsets.is_empty() {
        let plan = make_plan("zip_conflict_resolver_rebuild", selected_indices.clone(), &scan.entries, 0.91, vec!["build_zip_entry_conflict_graph", "select_best_non_overlapping_entries", "rebuild_clean_zip"]);
        // When entries are already clean, still produce a candidate (iterative design: this round's "no-op" is still progress)
        let output_path = Path::new(workspace).join("zip_conflict_resolver_rebuild.zip");
        if let Ok(stats) = write_candidate_zip(&data, &scan.entries, &plan, &output_path, options.max_output_bytes) {
            let sel_path = output_path.to_string_lossy().into_owned();
            let sel = WrittenCandidate { name: "zip_conflict_resolver_rebuild", policy: "crc_match", path: sel_path.clone(), confidence: 0.91, actions: plan.actions.clone(), entries: stats.entries, verified_entries: stats.verified_entries, descriptor_entries: stats.descriptor_entries, passthrough_entries: stats.passthrough_entries, size: stats.size, rank_score: plan.rank_score };
            return add_conflict_target_metadata(py, status_dict(py, "partial", &sel_path, "ZIP entries are already conflict-free", &scan.warnings, &[sel], scan.skipped_offsets.len(), scan.encrypted_entries, 0.91, Some(&scan), None)?, policy, conflict_count, selected_indices.len());
        }
    }
    let policy_names: Vec<&'static str> = if policy == "crc_match" || policy == "all_candidates" {
        vec!["crc_match", "latest", "first", "largest_verified"]
    } else {
        vec![policy_name(policy)]
    };
    let mut written = Vec::new();
    for policy_name in policy_names {
        let indices = select_conflict_free_zip_entries_by_policy(&scan.entries, policy_name);
        if indices.is_empty() {
            continue;
        }
        let plan = make_plan(
            "zip_conflict_resolver_rebuild",
            indices,
            &scan.entries,
            if policy_name == "crc_match" { 0.91 } else { 0.86 },
            vec![
                "build_zip_entry_conflict_graph",
                "select_best_non_overlapping_entries",
                "rebuild_clean_zip",
            ],
        );
        let output_path = Path::new(workspace).join(format!("zip_conflict_resolver_rebuild_{policy_name}.zip"));
        if let Ok(stats) = write_candidate_zip(
            &data,
            &scan.entries,
            &plan,
            &output_path,
            options.max_output_bytes,
        ) {
            written.push(WrittenCandidate {
                name: "zip_conflict_resolver_rebuild",
                policy: policy_name,
                path: output_path.to_string_lossy().to_string(),
                confidence: plan.confidence,
                actions: plan.actions.clone(),
                entries: stats.entries,
                verified_entries: stats.verified_entries,
                descriptor_entries: stats.descriptor_entries,
                passthrough_entries: stats.passthrough_entries,
                size: stats.size,
                rank_score: plan.rank_score,
            });
        }
    }
    let Some(selected) = written.iter().max_by_key(|item| item.rank_score) else {
        return status_dict(
            py,
            "unrepairable",
            "",
            "ZIP conflict resolver could not write any policy candidate",
            &scan.warnings,
            &[],
            scan.skipped_offsets.len(),
            scan.encrypted_entries,
            0.0,
            Some(&scan),
            Some("candidate_write_failed"),
        );
    };
    let mut warnings = scan.warnings.clone();
    warnings.push(format!(
        "ZIP conflict resolver dropped {conflict_count} duplicate or overlapping entries"
    ));
    add_conflict_target_metadata(py, status_dict(
        py,
        "partial",
        &selected.path,
        "ZIP duplicate/overlapping entry conflicts were resolved into a clean candidate",
        &warnings,
        &written,
        scan.skipped_offsets.len(),
        scan.encrypted_entries,
        0.91,
        Some(&scan),
        None,
    )?, policy, conflict_count, selected.entries)
}

#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    repair_name,
    exclude_names,
    max_entries=20000,
    max_input_size_mb=512.0,
    max_output_size_mb=2048.0,
    max_entry_uncompressed_mb=512.0,
    max_seconds=30.0
))]
pub(crate) fn zip_verified_entry_salvage(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    repair_name: &str,
    exclude_names: Vec<String>,
    max_entries: usize,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
    max_entry_uncompressed_mb: f64,
    max_seconds: f64,
) -> PyResult<Py<PyDict>> {
    let started = Instant::now();
    let password = extract_password(source_input);
    let options = DeepZipOptions {
        max_candidates: 1,
        max_entries: max_entries.max(1),
        max_input_bytes: mb_to_bytes(max_input_size_mb),
        max_output_bytes: mb_to_bytes(max_output_size_mb),
        max_entry_uncompressed_bytes: mb_to_bytes(max_entry_uncompressed_mb),
        max_duration: duration_from_seconds(max_seconds),
        verify_candidates: true,
        allow_unverified_entries: false,
        password,
    };
    let data = match read_source_input(source_input, options.max_input_bytes) {
        Ok(data) => data,
        Err(message) => return status_dict(py, "skipped", "", &message, &[], &[], 0, 0, 0.0, None, Some("input_read_failed")),
    };
    let scan = scan_entries(&data, &options, started);
    let exclude = exclude_names
        .iter()
        .map(|name| normalize_zip_name_key(name))
        .collect::<std::collections::HashSet<_>>();
    let mut indices = scan
        .entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            if !entry.verified {
                return None;
            }
            if exclude.contains(&entry_name_key(&entry.name)) {
                return None;
            }
            Some(index)
        })
        .collect::<Vec<_>>();
    if indices.is_empty() {
        if scan.entries.is_empty() {
            return salvage_status_dict(
                py,
                "unrepairable",
                "",
                "no verified ZIP entries remained after salvage filters",
                &scan.warnings,
                scan.skipped_offsets.len(),
                scan.encrypted_entries,
                0,
                0,
                0,
                scan.timed_out,
                repair_name,
                central_local_mismatch_count(&data),
                exclude.len(),
                &scan,
            );
        }
        indices = (0..scan.entries.len()).collect();
    }
    let actions = match repair_name {
        "zip_cd_local_header_reconcile_rebuild" => vec![
            "cross_check_central_directory_against_local_headers",
            "ignore_untrusted_central_directory_offsets",
            "write_verified_local_header_zip",
        ],
        "zip_entry_quarantine_rebuild" => vec![
            "apply_verification_failed_entry_quarantine",
            "scan_local_file_headers",
            "write_verified_local_header_zip",
        ],
        _ => vec![
            "scan_local_file_headers",
            "skip_unverified_payloads",
            "write_verified_local_header_zip",
        ],
    };
    let plan = make_plan(
        "zip_verified_entry_salvage",
        indices,
        &scan.entries,
        0.91,
        actions,
    );
    let output_path = Path::new(workspace).join(format!("{repair_name}.zip"));
    match write_candidate_zip(
        &data,
        &scan.entries,
        &plan,
        &output_path,
        options.max_output_bytes,
    ) {
        Ok(stats) => salvage_status_dict(
            py,
            "partial",
            &output_path.to_string_lossy(),
            "ZIP verified entry salvage produced a candidate",
            &scan.warnings,
            scan.skipped_offsets.len(),
            scan.encrypted_entries,
            stats.entries,
            stats.verified_entries,
            stats.descriptor_entries,
            scan.timed_out,
            repair_name,
            central_local_mismatch_count(&data),
            exclude.len(),
            &scan,
        ),
        Err(message) => salvage_status_dict(
            py,
            "unrepairable",
            "",
            &message,
            &scan.warnings,
            scan.skipped_offsets.len(),
            scan.encrypted_entries,
            0,
            0,
            0,
            scan.timed_out,
            repair_name,
            central_local_mismatch_count(&data),
            exclude.len(),
            &scan,
        ),
    }
}

#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    max_entries=20000,
    max_input_size_mb=512.0,
    max_output_size_mb=2048.0,
    max_entry_uncompressed_mb=512.0,
    max_seconds=30.0
))]
pub(crate) fn zip_cd_local_header_reconcile_salvage(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_entries: usize,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
    max_entry_uncompressed_mb: f64,
    max_seconds: f64,
) -> PyResult<Py<PyDict>> {
    let started = Instant::now();
    let password = extract_password(source_input);
    let options = DeepZipOptions {
        max_candidates: 1,
        max_entries: max_entries.max(1),
        max_input_bytes: mb_to_bytes(max_input_size_mb),
        max_output_bytes: mb_to_bytes(max_output_size_mb),
        max_entry_uncompressed_bytes: mb_to_bytes(max_entry_uncompressed_mb),
        max_duration: duration_from_seconds(max_seconds),
        verify_candidates: true,
        allow_unverified_entries: false,
        password,
    };
    let data = match read_source_input(source_input, options.max_input_bytes) {
        Ok(data) => data,
        Err(message) => return status_dict(py, "skipped", "", &message, &[], &[], 0, 0, 0.0, None, Some("input_read_failed")),
    };
    let scan = scan_entries(&data, &options, started);
    let (indices, corrected_offsets) = cd_local_reconcile_indices(&data, &scan.entries);
    if indices.is_empty() {
        return salvage_status_dict(
            py,
            "unrepairable",
            "",
            "no verified ZIP entries could be reconciled against local headers",
            &scan.warnings,
            scan.skipped_offsets.len(),
            scan.encrypted_entries,
            0,
            0,
            0,
            scan.timed_out,
            "zip_cd_local_header_reconcile_rebuild",
            corrected_offsets,
            0,
            &scan,
        );
    }
    let plan = make_plan(
        "zip_cd_local_header_reconcile_rebuild",
        indices,
        &scan.entries,
        0.93,
        vec![
            "parse_central_directory_entries",
            "match_cd_entries_to_verified_local_headers",
            "rewrite_zip_from_reconciled_local_headers",
        ],
    );
    let output_path = Path::new(workspace).join("zip_cd_local_header_reconcile_rebuild.zip");
    match write_candidate_zip(
        &data,
        &scan.entries,
        &plan,
        &output_path,
        options.max_output_bytes,
    ) {
        Ok(stats) => salvage_status_dict(
            py,
            "partial",
            &output_path.to_string_lossy(),
            "ZIP central directory entries were reconciled against verified local headers",
            &scan.warnings,
            scan.skipped_offsets.len(),
            scan.encrypted_entries,
            stats.entries,
            stats.verified_entries,
            stats.descriptor_entries,
            scan.timed_out,
            "zip_cd_local_header_reconcile_rebuild",
            corrected_offsets,
            0,
            &scan,
        ),
        Err(message) => salvage_status_dict(
            py,
            "unrepairable",
            "",
            &message,
            &scan.warnings,
            scan.skipped_offsets.len(),
            scan.encrypted_entries,
            0,
            0,
            0,
            scan.timed_out,
            "zip_cd_local_header_reconcile_rebuild",
            corrected_offsets,
            0,
            &scan,
        ),
    }
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
    allow_unverified_entries: bool,
    password: Option<String>,
}

#[derive(Debug, Clone)]
struct RecoveredEntry {
    name: Vec<u8>,
    extra: Vec<u8>,
    local_header_offset: usize,
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
    payload_override: Option<Vec<u8>>,
    verified: bool,
    descriptor: bool,
    passthrough: bool,
    boundary_source: BoundarySource,
    experimental_deflate_resync: bool,
}

#[derive(Debug, Default)]
struct ScanResult {
    entries: Vec<RecoveredEntry>,
    warnings: Vec<String>,
    skipped_offsets: Vec<usize>,
    encrypted_entries: usize,
    unsupported_entries: usize,
    descriptor_entries: usize,
    lfh_scanned: usize,
    next_lfh_boundary_entries: usize,
    deflate_consumed_boundary_entries: usize,
    descriptor_signature_entries: usize,
    descriptor_no_signature_entries: usize,
    deflate_resync_partial_entries: usize,
    timed_out: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundarySource {
    HeaderSize,
    NextRecord,
    DeflateConsumed,
    Descriptor,
    DeflateResync,
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
    policy: &'static str,
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
        result.lfh_scanned += 1;
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
                if entry.boundary_source == BoundarySource::NextRecord {
                    result.next_lfh_boundary_entries += 1;
                }
                if entry.boundary_source == BoundarySource::DeflateConsumed {
                    result.deflate_consumed_boundary_entries += 1;
                }
                if entry.boundary_source == BoundarySource::Descriptor {
                    if descriptor_at(data, entry.data_end, entry.crc32, entry.compressed_size, entry.uncompressed_size) {
                        result.descriptor_signature_entries += 1;
                    } else {
                        result.descriptor_no_signature_entries += 1;
                    }
                }
                if entry.experimental_deflate_resync {
                    result.deflate_resync_partial_entries += 1;
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
    let is_encrypted = flags & 0x01 != 0;
    if is_encrypted && options.password.is_none() {
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
            offset,
            data_start,
            name,
            extra.to_vec(),
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
    let mut boundary_source = BoundarySource::HeaderSize;
    let data_end = match data_start.checked_add(compressed_size as usize) {
        Some(end) if end <= data.len() => end,
        Some(_) if method == 8 && options.verify_candidates => {
            match verified_deflate_payload_end(
                data,
                data_start,
                None,
                header_crc32,
                uncompressed_size,
                options,
            ) {
                Some((end, source)) => {
                    boundary_source = source;
                    end
                }
                None => return EntryOutcome::Skipped("entry payload is truncated".to_string()),
            }
        }
        Some(_) if method == 0 && options.verify_candidates => {
            match verified_store_payload_end(data, data_start, header_crc32, uncompressed_size) {
                Some((end, source)) => {
                    boundary_source = source;
                    end
                }
                None => return EntryOutcome::Skipped("stored entry payload is truncated".to_string()),
            }
        }
        Some(_) => return EntryOutcome::Skipped("entry payload is truncated".to_string()),
        None => {
            return EntryOutcome::Skipped("compressed size overflows input range".to_string());
        }
    };
    let entry_is_encrypted = flags & 0x01 != 0;
    let data_end = if entry_is_encrypted {
        data_end
    } else if method == 8 && options.verify_candidates {
        match verified_deflate_payload_end(
            data,
            data_start,
            Some(data_end),
            header_crc32,
            uncompressed_size,
            options,
        ) {
            Some((end, source)) => {
                boundary_source = source;
                end
            }
            None => data_end,
        }
    } else if method == 0 && options.verify_candidates {
        match verified_store_payload_end(data, data_start, header_crc32, uncompressed_size) {
            Some((end, source)) => {
                boundary_source = source;
                end
            }
            None => data_end,
        }
    } else {
        data_end
    };
    classify_entry(
        data,
        offset,
        data_start,
        data_end,
        name,
        extra.to_vec(),
        version_needed,
        flags,
        method,
        mod_time,
        mod_date,
        header_crc32,
        compressed_size,
        uncompressed_size,
        false,
        boundary_source,
        options,
    )
}

#[allow(clippy::too_many_arguments)]
fn parse_descriptor_entry(
    data: &[u8],
    local_header_offset: usize,
    data_start: usize,
    name: Vec<u8>,
    extra: Vec<u8>,
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
                    extra: extra.clone(),
                    local_header_offset,
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
                    payload_override: None,
                    verified: true,
                    descriptor: true,
                    passthrough: false,
                    boundary_source: BoundarySource::DeflateConsumed,
                    experimental_deflate_resync: false,
                });
            }
            Err(_) => {
                if let Some(entry) = deflate_resync_partial_entry(
                    data,
                    local_header_offset,
                    data_start,
                    name.clone(),
                    extra.clone(),
                    version_needed,
                    flags,
                    mod_time,
                    mod_date,
                    options,
                ) {
                    return EntryOutcome::Recovered(entry);
                }
            }
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
            local_header_offset,
            data_start,
            data_end,
            name,
            extra,
            version_needed,
            flags,
            method,
            mod_time,
            mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            true,
            BoundarySource::Descriptor,
            options,
        );
    }
    if compressed_size > u32::MAX as u64 || uncompressed_size > u32::MAX as u64 {
        return EntryOutcome::Skipped("ZIP64-sized descriptor entry is too large".to_string());
    }
    EntryOutcome::Recovered(RecoveredEntry {
        name,
        extra,
        local_header_offset,
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
        payload_override: None,
        verified: false,
        descriptor: true,
        passthrough: true,
        boundary_source: BoundarySource::Descriptor,
        experimental_deflate_resync: false,
    })
}

#[allow(clippy::too_many_arguments)]
fn classify_entry(
    data: &[u8],
    local_header_offset: usize,
    data_start: usize,
    data_end: usize,
    name: Vec<u8>,
    extra: Vec<u8>,
    version_needed: u16,
    flags: u16,
    method: u16,
    mod_time: u16,
    mod_date: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    descriptor: bool,
    boundary_source: BoundarySource,
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
    let is_encrypted_entry = flags & 0x01 != 0;
    if !verified
        && matches!(method, 0 | 8)
        && options.verify_candidates
        && !is_encrypted_entry
        && !options.allow_unverified_entries
    {
        return EntryOutcome::Skipped("entry failed payload verification".to_string());
    }
    if !verified && !known_zip_method(method) {
        return EntryOutcome::Recovered(RecoveredEntry {
            name: name.clone(),
            extra: extra.clone(),
            local_header_offset,
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
            payload_override: None,
            verified: false,
            descriptor,
            passthrough: true,
            boundary_source,
            experimental_deflate_resync: false,
        });
    }
    if !verified && !options.verify_candidates {
        return EntryOutcome::Recovered(RecoveredEntry {
            name: name.clone(),
            extra: extra.clone(),
            local_header_offset,
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
            payload_override: None,
            verified: false,
            descriptor,
            passthrough: true,
            boundary_source,
            experimental_deflate_resync: false,
        });
    }
    EntryOutcome::Recovered(RecoveredEntry {
        name,
        extra,
        local_header_offset,
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
        payload_override: None,
        verified,
        descriptor,
        passthrough: !verified,
        boundary_source,
        experimental_deflate_resync: false,
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

fn policy_name(policy: &str) -> &'static str {
    match policy {
        "latest" => "latest",
        "first" => "first",
        "largest_verified" => "largest_verified",
        _ => "crc_match",
    }
}

fn select_conflict_free_zip_entries_by_policy(entries: &[RecoveredEntry], policy: &str) -> Vec<usize> {
    let mut order = (0..entries.len()).collect::<Vec<_>>();
    match policy {
        "latest" => order.sort_by_key(|index| std::cmp::Reverse(entries[*index].data_start)),
        "first" => order.sort_by_key(|index| entries[*index].data_start),
        "largest_verified" => order.sort_by(|left, right| {
            let l = &entries[*left];
            let r = &entries[*right];
            (r.verified, r.uncompressed_size, std::cmp::Reverse(r.data_start))
                .cmp(&(l.verified, l.uncompressed_size, std::cmp::Reverse(l.data_start)))
        }),
        _ => order.sort_by(|left, right| {
            zip_entry_score(&entries[*right])
                .cmp(&zip_entry_score(&entries[*left]))
                .then_with(|| entries[*left].data_start.cmp(&entries[*right].data_start))
        }),
    }
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
            let payload = entry
                .payload_override
                .as_deref()
                .unwrap_or(&source[entry.data_start..entry.data_end]);
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
    file.write_all(&(entry.extra.len() as u16).to_le_bytes())?;
    file.write_all(&entry.name)?;
    file.write_all(&entry.extra)?;
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
    output.extend_from_slice(&(entry.extra.len() as u16).to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&local_offset.to_le_bytes());
    output.extend_from_slice(&entry.name);
    output.extend_from_slice(&entry.extra);
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

#[allow(clippy::too_many_arguments)]
fn deflate_resync_partial_entry(
    data: &[u8],
    local_header_offset: usize,
    data_start: usize,
    name: Vec<u8>,
    _extra: Vec<u8>,
    version_needed: u16,
    flags: u16,
    mod_time: u16,
    mod_date: u16,
    options: &DeepZipOptions,
) -> Option<RecoveredEntry> {
    let decoded = decode_deflate_prefix_for_partial(
        data.get(data_start..)?,
        options.max_entry_uncompressed_bytes,
        options.max_duration,
    )?;
    if decoded.len() < 4096 {
        return None;
    }
    let mut output_name = b"__sunpack_partial/".to_vec();
    output_name.extend_from_slice(&safe_partial_name(&name));
    output_name.extend_from_slice(b".partial");
    if output_name.len() > MAX_NAME_LEN {
        output_name.truncate(MAX_NAME_LEN);
    }
    let crc32 = crc32_bytes(&decoded);
    Some(RecoveredEntry {
        name: output_name,
        extra: Vec::new(),
        local_header_offset,
        version_needed: version_needed.max(20),
        flags: flags & !0x08,
        method: 0,
        mod_time,
        mod_date,
        crc32,
        compressed_size: decoded.len() as u64,
        uncompressed_size: decoded.len() as u64,
        data_start,
        data_end: data_start,
        payload_override: Some(decoded),
        verified: true,
        descriptor: false,
        passthrough: false,
        boundary_source: BoundarySource::DeflateResync,
        experimental_deflate_resync: true,
    })
}

fn decode_deflate_prefix_for_partial(
    input: &[u8],
    max_output_bytes: Option<u64>,
    max_duration: Option<Duration>,
) -> Option<Vec<u8>> {
    let started = Instant::now();
    let mut decompressor = Decompress::new(false);
    let mut output = Vec::with_capacity(64 * 1024);
    loop {
        if max_duration.is_some_and(|duration| started.elapsed() >= duration) {
            break;
        }
        let before_in = decompressor.total_in();
        let before_out = decompressor.total_out();
        let before_len = output.len();
        let input_offset = before_in as usize;
        if input_offset >= input.len() {
            break;
        }
        match decompressor.decompress_vec(&input[input_offset..], &mut output, FlushDecompress::None) {
            Ok(Status::StreamEnd) => break,
            Ok(_) => {
                if output.len() > before_len {
                    if let Some(limit) = max_output_bytes {
                        if output.len() as u64 > limit {
                            output.truncate(limit as usize);
                            break;
                        }
                    }
                }
                if decompressor.total_in() == before_in && decompressor.total_out() == before_out {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    (!output.is_empty()).then_some(output)
}

fn safe_partial_name(name: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(name.len());
    for byte in name {
        match *byte {
            b'/' | b'\\' => output.push(b'_'),
            0 | b':' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|' => output.push(b'_'),
            value if value < 0x20 => output.push(b'_'),
            value => output.push(value),
        }
    }
    if output.is_empty() {
        b"entry".to_vec()
    } else {
        output
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

fn verified_deflate_payload_end(
    data: &[u8],
    data_start: usize,
    header_end: Option<usize>,
    expected_crc32: u32,
    expected_size: u64,
    options: &DeepZipOptions,
) -> Option<(usize, BoundarySource)> {
    let mut ends = Vec::new();
    if let Some(end) = header_end.filter(|end| *end <= data.len() && *end > data_start) {
        ends.push((end, BoundarySource::HeaderSize));
    }
    if let Some(next) = find_next_zip_record(data, data_start) {
        if next > data_start && !ends.iter().any(|(end, _)| *end == next) {
            ends.push((next, BoundarySource::NextRecord));
        }
    }
    if data_start < data.len() && ends.is_empty() {
        ends.push((data.len(), BoundarySource::NextRecord));
    }
    for (end, source) in ends {
        let candidate = &data[data_start..end];
        if let Ok(info) = verify_deflate(
            candidate,
            Some(expected_crc32),
            Some(expected_size),
            options.max_entry_uncompressed_bytes,
            false,
        ) {
            if info.consumed > 0 && data_start + info.consumed <= end {
                let actual_end = data_start + info.consumed;
                let actual_source = if actual_end == end {
                    source
                } else {
                    BoundarySource::DeflateConsumed
                };
                return Some((actual_end, actual_source));
            }
        }
    }
    None
}

fn verified_store_payload_end(
    data: &[u8],
    data_start: usize,
    expected_crc32: u32,
    expected_size: u64,
) -> Option<(usize, BoundarySource)> {
    let expected_len = usize::try_from(expected_size).ok()?;
    if let Some(end) = data_start.checked_add(expected_len) {
        if end <= data.len() {
            let payload = &data[data_start..end];
            if crc32_bytes(payload) == expected_crc32 {
                return Some((end, BoundarySource::HeaderSize));
            }
        }
    }
    let next = find_next_zip_record(data, data_start)?;
    if next <= data_start {
        return None;
    }
    let payload = &data[data_start..next];
    if payload.len() as u64 == expected_size && crc32_bytes(payload) == expected_crc32 {
        Some((next, BoundarySource::NextRecord))
    } else {
        None
    }
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

fn build_scan_diagnostics(
    py: Python<'_>,
    scan: &ScanResult,
    fail_reason: Option<&str>,
) -> PyResult<Py<PyDict>> {
    let diag = PyDict::new(py);

    let scan_dict = PyDict::new(py);
    scan_dict.set_item("lfh_scanned", scan.lfh_scanned)?;
    scan_dict.set_item("entries_found", scan.entries.len())?;
    scan_dict.set_item(
        "entries_verified",
        scan.entries.iter().filter(|e| e.verified).count(),
    )?;
    scan_dict.set_item("entries_corrupt", scan.skipped_offsets.len())?;
    scan_dict.set_item("entries_encrypted", scan.encrypted_entries)?;
    scan_dict.set_item("entries_descriptor", scan.descriptor_entries)?;
    scan_dict.set_item("entries_unsupported", scan.unsupported_entries)?;
    scan_dict.set_item("boundary_next_record", scan.next_lfh_boundary_entries)?;
    scan_dict.set_item(
        "boundary_deflate_consumed",
        scan.deflate_consumed_boundary_entries,
    )?;
    scan_dict.set_item(
        "boundary_descriptor_sig",
        scan.descriptor_signature_entries,
    )?;
    scan_dict.set_item(
        "boundary_descriptor_no_sig",
        scan.descriptor_no_signature_entries,
    )?;
    scan_dict.set_item(
        "boundary_deflate_resync",
        scan.deflate_resync_partial_entries,
    )?;
    scan_dict.set_item("timed_out", scan.timed_out)?;
    diag.set_item("scan", scan_dict)?;

    if let Some(reason) = fail_reason {
        diag.set_item("fail_reason", reason)?;
    } else {
        diag.set_item("fail_reason", py.None())?;
    }

    Ok(diag.unbind())
}

fn build_field_repair_diagnostics(
    py: Python<'_>,
    target_field: &str,
    field_was_corrupt: bool,
    patches_applied: usize,
    fail_reason: &str,
) -> PyResult<Py<PyDict>> {
    let diag = PyDict::new(py);
    let scan_dict = PyDict::new(py);
    scan_dict.set_item("target_field", target_field)?;
    scan_dict.set_item("field_was_corrupt", field_was_corrupt)?;
    diag.set_item("scan", scan_dict)?;

    let repair_dict = PyDict::new(py);
    repair_dict.set_item("patches_applied", patches_applied)?;
    diag.set_item("repair", repair_dict)?;

    if fail_reason.is_empty() {
        diag.set_item("fail_reason", py.None())?;
    } else {
        diag.set_item("fail_reason", fail_reason)?;
    }

    Ok(diag.unbind())
}

fn repair_name_to_target(name: &str) -> &str {
    match name {
        "zip_comment_length_fix" => "comment_length",
        "zip_central_directory_count_fix" => "cd_count",
        "zip_central_directory_offset_fix" => "cd_offset",
        "zip_trailing_junk_trim" => "trailing_junk",
        "zip_eocd_repair" => "eocd",
        "zip_local_header_field_repair" => "local_header",
        "zip64_extra_size" => "zip64_extra_size",
        "zip64_locator" => "zip64_locator",
        "zip64_eocd" => "zip64_eocd",
        _ => "",
    }
}

fn field_patch_facts(target: &str) -> Vec<&'static str> {
    match target {
        "comment_length" => vec!["fixed_field=eocd_comment_length", "after_eocd_repair"],
        "cd_count" => vec!["fixed_field=central_directory_entry_count"],
        "cd_offset" => vec!["fixed_field=central_directory_offset"],
        "trailing_junk" => vec!["fixed_field=trailing_junk"],
        "eocd" => vec!["fixed_field=eocd_record", "after_eocd_repair"],
        "local_header" => vec!["fixed_field=local_header_fields", "after_local_header_repair"],
        "zip64_extra_size" => vec!["fixed_field=zip64_extra_size", "zip64_extra_reconciled"],
        "zip64_locator" => vec!["fixed_field=zip64_locator"],
        "zip64_eocd" => vec!["fixed_field=zip64_eocd"],
        _ => Vec::new(),
    }
}

fn build_validation_details(
    py: Python<'_>,
    target: &str,
    accepted: bool,
    mismatches: &[String],
) -> PyResult<Py<PyDict>> {
    let details = PyDict::new(py);
    details.set_item("native_target", target)?;
    details.set_item("accepted", accepted)?;
    details.set_item("entry_name_byte_mismatches", PyList::new(py, mismatches)?)?;
    if target == "rebuild_cd_preserve_raw_names" {
        details.set_item("raw_filename_bytes_preserved", accepted && mismatches.is_empty())?;
    }
    Ok(details.unbind())
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
    scan: Option<&ScanResult>,
    fail_reason: Option<&str>,
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("selected_path", selected_path)?;
    result.set_item("selected_candidate", "")?;
    result.set_item("confidence", confidence)?;
    result.set_item("format", "zip")?;
    result.set_item("message", message)?;
    result.set_item("actions", PyList::empty(py))?;
    result.set_item("candidate_status", status)?;
    result.set_item("native_target", "")?;
    result.set_item("patch_facts", PyList::empty(py))?;
    result.set_item("residual_facts", PyList::empty(py))?;
    result.set_item("validation_details", build_validation_details(py, "", status != "unrepairable", &[])?)?;
    result.set_item("warnings", PyList::new(py, warnings)?)?;
    result.set_item("skipped_entries", skipped_entries)?;
    result.set_item("encrypted_entries", encrypted_entries)?;
    result.set_item("unsupported_entries", 0)?;
    result.set_item("recovered_entries", 0)?;
    result.set_item("verified_entries", 0)?;
    result.set_item("descriptor_entries", 0)?;
    result.set_item("passthrough_entries", 0)?;
    let candidate_list = PyList::empty(py);
    for candidate in candidates {
        let item = PyDict::new(py);
        item.set_item("name", candidate.name)?;
        item.set_item("path", &candidate.path)?;
        item.set_item("status", status)?;
        item.set_item("confidence", candidate.confidence)?;
        item.set_item("entries", candidate.entries)?;
        item.set_item("verified_entries", candidate.verified_entries)?;
        item.set_item("descriptor_entries", candidate.descriptor_entries)?;
        item.set_item("passthrough_entries", candidate.passthrough_entries)?;
        item.set_item("size", candidate.size)?;
        item.set_item("rank_score", candidate.rank_score)?;
        item.set_item("policy", candidate.policy)?;
        item.set_item("actions", PyList::new(py, &candidate.actions)?)?;
        if !candidate.policy.is_empty() {
            let patch_facts = vec![
                "resolved_duplicate_entries".to_string(),
                format!("kept_entry_policy={}", candidate.policy),
            ];
            item.set_item(
                "patch_facts",
                PyList::new(py, &patch_facts)?,
            )?;
            item.set_item("native_target", "zip_conflict_resolver_rebuild")?;
            item.set_item("candidate_status", status)?;
            let details = PyDict::new(py);
            details.set_item("policy", candidate.policy)?;
            details.set_item("kept_entries", candidate.entries)?;
            details.set_item("crc_match_count", if candidate.policy == "crc_match" { candidate.verified_entries } else { 0 })?;
            item.set_item("validation_details", details)?;
        }
        candidate_list.append(item)?;
    }
    result.set_item("candidates", candidate_list)?;
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
    if let Some(s) = scan {
        result.set_item("diagnostics", build_scan_diagnostics(py, s, fail_reason)?)?;
    }
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
    scan: Option<&ScanResult>,
    fail_reason: Option<&str>,
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
    if let Some(s) = scan {
        result.set_item("diagnostics", build_scan_diagnostics(py, s, fail_reason)?)?;
    }
    Ok(result.unbind())
}

fn add_rebuild_target_metadata(
    py: Python<'_>,
    result: Py<PyDict>,
    preserve_raw_names: bool,
    logical_stream_built: bool,
) -> PyResult<Py<PyDict>> {
    let bound = result.bind(py);
    let target = if preserve_raw_names {
        "rebuild_cd_preserve_raw_names"
    } else {
        "rebuild_cd_from_local_headers"
    };
    let path = get_optional_string(bound, "path")?.unwrap_or_default();
    let status = get_optional_string(bound, "status")?.unwrap_or_else(|| "partial".to_string());
    bound.set_item("native_key", "native_zip_rebuild")?;
    bound.set_item("native_target", target)?;
    bound.set_item("materialized_path", path)?;
    bound.set_item("candidate_status", if status == "repaired" { "complete" } else { status.as_str() })?;
    bound.set_item(
        "patch_facts",
        PyList::new(py, rebuild_patch_facts(preserve_raw_names))?,
    )?;
    bound.set_item("residual_facts", PyList::empty(py))?;
    bound.set_item("logical_stream_built", logical_stream_built)?;
    bound.set_item("split_sidecars_available", logical_stream_built)?;
    bound.set_item(
        "validation_details",
        build_validation_details(py, target, true, &[])?,
    )?;
    Ok(result)
}

fn add_conflict_target_metadata(
    py: Python<'_>,
    result: Py<PyDict>,
    policy: &str,
    conflict_count: usize,
    kept_entries: usize,
) -> PyResult<Py<PyDict>> {
    let bound = result.bind(py);
    bound.set_item("native_target", "zip_conflict_resolver_rebuild")?;
    bound.set_item("candidate_status", "partial")?;
    bound.set_item(
        "patch_facts",
        PyList::new(py, &[
            "resolved_duplicate_entries",
            if policy == "crc_match" { "kept_entry_policy=crc_match" } else { "kept_entry_policy=deterministic" },
        ])?,
    )?;
    bound.set_item(
        "residual_facts",
        if conflict_count > 0 { PyList::empty(py) } else { PyList::new(py, &["duplicate_entries_remaining_unknown"])? },
    )?;
    let details = PyDict::new(py);
    details.set_item("policy", policy)?;
    details.set_item("duplicate_groups", conflict_count)?;
    details.set_item("kept_entries", kept_entries)?;
    details.set_item("dropped_entries", conflict_count)?;
    details.set_item("crc_match_count", if policy == "crc_match" { kept_entries } else { 0 })?;
    bound.set_item("validation_details", details)?;
    Ok(result)
}

fn rebuild_patch_facts(preserve_raw_names: bool) -> Vec<&'static str> {
    if preserve_raw_names {
        vec![
            "raw_name_bytes_preserved",
            "raw_name_source=local_header",
            "after_cd_rebuild",
            "entry_payload_unverified",
            "raw_name_entry_passthrough",
        ]
    } else {
        vec!["after_cd_rebuild"]
    }
}

#[allow(clippy::too_many_arguments)]
fn salvage_status_dict(
    py: Python<'_>,
    status: &str,
    path: &str,
    message: &str,
    warnings: &[String],
    skipped_entries: usize,
    encrypted_entries: usize,
    recovered_entries: usize,
    verified_entries: usize,
    descriptor_entries: usize,
    timed_out: bool,
    repair_name: &str,
    central_local_mismatches: usize,
    excluded_name_count: usize,
    scan: &ScanResult,
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("selected_path", path)?;
    result.set_item("path", path)?;
    result.set_item("selected_candidate", repair_name)?;
    result.set_item("confidence", if verified_entries > 0 { 0.91 } else { 0.0 })?;
    result.set_item("format", "zip")?;
    result.set_item("message", message)?;
    result.set_item("warnings", PyList::new(py, warnings)?)?;
    result.set_item("skipped_entries", skipped_entries)?;
    result.set_item("encrypted_entries", encrypted_entries)?;
    result.set_item("descriptor_entries", descriptor_entries)?;
    result.set_item("recovered_entries", recovered_entries)?;
    result.set_item("verified_entries", verified_entries)?;
    result.set_item("timed_out", timed_out)?;
    result.set_item("central_local_mismatches", central_local_mismatches)?;
    result.set_item("excluded_name_count", excluded_name_count)?;
    result.set_item("lfh_scanned", scan.lfh_scanned)?;
    result.set_item("next_lfh_boundary_entries", scan.next_lfh_boundary_entries)?;
    result.set_item(
        "deflate_consumed_boundary_entries",
        scan.deflate_consumed_boundary_entries,
    )?;
    result.set_item("descriptor_signature_entries", scan.descriptor_signature_entries)?;
    result.set_item(
        "descriptor_no_signature_entries",
        scan.descriptor_no_signature_entries,
    )?;
    result.set_item(
        "deflate_resync_experimental",
        scan.deflate_resync_partial_entries > 0,
    )?;
    result.set_item(
        "deflate_resync_partial_entries",
        scan.deflate_resync_partial_entries,
    )?;
    result.set_item(
        "actions",
        PyList::new(
            py,
            match repair_name {
                "zip_cd_local_header_reconcile_rebuild" => vec![
                    "cross_check_central_directory_against_local_headers",
                    "ignore_untrusted_central_directory_offsets",
                    "write_verified_local_header_zip",
                ],
                "zip_entry_quarantine_rebuild" => vec![
                    "apply_verification_failed_entry_quarantine",
                    "scan_local_file_headers",
                    "write_verified_local_header_zip",
                ],
                _ => vec![
                    "scan_local_file_headers",
                    "skip_unverified_payloads",
                    "write_verified_local_header_zip",
                ],
            },
        )?,
    )?;
    result.set_item("candidates", PyList::empty(py))?;
    let workspace_paths = if path.is_empty() {
        Vec::new()
    } else {
        vec![path]
    };
    result.set_item("workspace_paths", PyList::new(py, workspace_paths)?)?;
    result.set_item("diagnostics", build_scan_diagnostics(py, scan, if recovered_entries > 0 { None } else { Some("no_verified_entries") })?)?;
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
    size_offset: usize,
    stored_size: usize,
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

#[derive(Clone, Copy)]
enum Zip64TailTarget {
    Locator,
    Eocd,
}

fn repair_zip64_tail_target(
    data: &[u8],
    target: Zip64TailTarget,
) -> Result<DirectoryFieldRepair, String> {
    let Some(repair) = repair_zip64_tail(data)? else {
        return Err("no ZIP64 tail mismatch was safely repairable".to_string());
    };
    let allowed = match target {
        Zip64TailTarget::Locator => ["normalize_zip64_eocd_locator", "rewrite_zip64_eocd_locator"],
        Zip64TailTarget::Eocd => ["rewrite_zip64_eocd_fields", ""],
    };
    let matched = repair.actions.iter().any(|action| allowed.contains(&action.as_str()));
    let only_allowed = repair
        .actions
        .iter()
        .all(|action| allowed.contains(&action.as_str()));
    if !matched || !only_allowed {
        return Err("ZIP64 native target did not match requested atomic repair".to_string());
    }
    Ok(repair)
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
        let Some(central_zip64) = parse_zip64_extra_tolerant(&entry.extra, entry.extra_offset) else {
            continue;
        };
        let Some(local_zip64) = parse_zip64_extra_tolerant(&local.extra, local.extra_offset) else {
            continue;
        };
        let Some(expected) = expected_zip64_values(&entry, &local, &local_zip64) else {
            continue;
        };
        let expected_size = expected.len() * 8;
        if central_zip64.stored_size != expected_size {
            add_zip_patch(
                &mut bytes,
                &mut patches,
                central_zip64.size_offset,
                &(expected_size as u16).to_le_bytes(),
            );
        }
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

fn parse_zip64_extra_tolerant(extra: &[u8], absolute_extra_offset: usize) -> Option<Zip64Extra> {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let header_id = u16_le(extra, pos);
        let size = u16_le(extra, pos + 2) as usize;
        let value_start = pos + 4;
        let value_end = value_start.saturating_add(size).min(extra.len());
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
                size_offset: absolute_extra_offset + pos + 2,
                stored_size: size,
            });
        }
        let next = value_start.saturating_add(size);
        if next <= pos || next > extra.len() {
            break;
        }
        pos = next;
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
    if let Some(zip64) = parse_zip64_extra_tolerant(&entry.extra, entry.extra_offset) {
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

fn cd_local_reconcile_indices(data: &[u8], entries: &[RecoveredEntry]) -> (Vec<usize>, usize) {
    let verified = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.verified)
        .collect::<Vec<_>>();
    if verified.is_empty() {
        return (Vec::new(), 0);
    }
    let central_entries = parse_best_central_entries(data);
    if central_entries.is_empty() {
        return (
            verified.into_iter().map(|(index, _)| index).collect::<Vec<_>>(),
            0,
        );
    }
    let mut selected = Vec::new();
    let mut used = std::collections::HashSet::new();
    let mut corrected_offsets = 0usize;
    for central in &central_entries {
        let mut best: Option<(i64, usize, bool)> = None;
        for (index, local) in entries.iter().enumerate() {
            if !local.verified || used.contains(&index) {
                continue;
            }
            let score = reconcile_score(central, local);
            if score <= 0 {
                continue;
            }
            let corrected = central.local_header_offset as usize != local.local_header_offset;
            let key = (score, std::cmp::Reverse(local.local_header_offset));
            let replace = best
                .as_ref()
                .map(|(best_score, best_index, _)| {
                    key > (*best_score, std::cmp::Reverse(entries[*best_index].local_header_offset))
                })
                .unwrap_or(true);
            if replace {
                best = Some((score, index, corrected));
            }
        }
        if let Some((_, index, corrected)) = best {
            used.insert(index);
            selected.push(index);
            if corrected {
                corrected_offsets += 1;
            }
        }
    }
    if selected.is_empty() {
        selected = entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| entry.verified.then_some(index))
            .collect();
    }
    selected.sort_by_key(|index| entries[*index].local_header_offset);
    (selected, corrected_offsets)
}

fn parse_best_central_entries(data: &[u8]) -> Vec<CentralEntry> {
    if let Some(eocd) = find_eocd_record(data, true) {
        let cd_end = (eocd.cd_offset as usize).saturating_add(eocd.cd_size as usize);
        let entries = parse_central_directory_entries(data, eocd.cd_offset as usize, cd_end);
        if !entries.is_empty() {
            return entries;
        }
    }
    if let Some(cd) = find_valid_central_directory(data) {
        return parse_central_directory_entries(data, cd.offset, cd.end);
    }
    Vec::new()
}

fn reconcile_score(central: &CentralEntry, local: &RecoveredEntry) -> i64 {
    let mut score = 0i64;
    if central.name == local.name {
        score += 1000;
    } else if entry_name_key(&central.name) == entry_name_key(&local.name) {
        score += 700;
    } else {
        return 0;
    }
    if central.method == local.method {
        score += 120;
    }
    if central.crc32 == local.crc32 {
        score += 180;
    }
    if central.compressed_size as u64 == local.compressed_size {
        score += 80;
    }
    if central.uncompressed_size as u64 == local.uncompressed_size {
        score += 80;
    }
    if central.local_header_offset as usize == local.local_header_offset {
        score += 40;
    } else {
        score += 20;
    }
    if local.boundary_source == BoundarySource::DeflateConsumed
        || local.boundary_source == BoundarySource::NextRecord
    {
        score += 30;
    }
    score
}

fn central_local_mismatch_count(data: &[u8]) -> usize {
    let Some(eocd) = find_eocd_record(data, true) else {
        return 0;
    };
    let cd_end = (eocd.cd_offset as usize).saturating_add(eocd.cd_size as usize);
    let entries = parse_central_directory_entries(data, eocd.cd_offset as usize, cd_end);
    entries
        .iter()
        .filter(|entry| {
            let Some(local) = find_local_for_central(data, entry) else {
                return true;
            };
            local.name != entry.name
                || local.method != entry.method
                || (entry.flags & 0x08 == 0
                    && (local.crc32 != entry.crc32
                        || local.compressed_size != entry.compressed_size
                        || local.uncompressed_size != entry.uncompressed_size))
        })
        .count()
}

fn entry_name_key(raw: &[u8]) -> String {
    normalize_zip_name_key(&String::from_utf8_lossy(raw))
}

fn normalize_zip_name_key(name: &str) -> String {
    name.replace('\\', "/").trim_start_matches("./").to_lowercase()
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
    diagnostics: Option<Py<PyDict>>,
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
    if let Some(diag) = diagnostics {
        result.set_item("diagnostics", diag)?;
    }
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
            allow_unverified_entries: false,
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
