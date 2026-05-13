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
        "zip_extra_field_length_fix" => "extra_field_length",
        "zip_data_descriptor_flag_normalize" => "data_descriptor_flags",
        "zip_cd_entry_name_reconcile" => "cd_entry_names",
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
        "extra_field_length" => vec!["fixed_field=extra_field_length", "extra_field_length_reconciled"],
        "data_descriptor_flags" => vec!["fixed_field=data_descriptor_bit3_flags", "after_descriptor_flag_normalize"],
        "cd_entry_names" => vec!["fixed_field=central_directory_entry_names", "after_cd_entry_name_reconcile"],
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

