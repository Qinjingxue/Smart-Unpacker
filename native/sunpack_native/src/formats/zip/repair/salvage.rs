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
    let native_started = Instant::now();
    let started = native_started;
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
    let timing_read_started = Instant::now();
    let data = match read_source_input(source_input, options.max_input_bytes) {
        Ok(data) => data,
        Err(message) => return status_dict(py, "skipped", "", &message, &[], &[], 0, 0, 0.0, None, Some("input_read_failed")),
    };
    let read_seconds = timing_read_started.elapsed().as_secs_f64();
    let timing_scan_started = Instant::now();
    let scan = scan_entries(&data, &options, started);
    let scan_seconds = timing_scan_started.elapsed().as_secs_f64();
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
    let action_refs = plan.actions.to_vec();
    let timing_semantic_started = Instant::now();
    if let Some((patch_plan, stats)) = central_directory_suffix_patch_and_stats(
        py,
        repair_name,
        "zip",
        &data,
        &scan.entries,
        &plan,
        0.91,
        &action_refs,
        repair_name,
    )? {
        let semantic_seconds = timing_semantic_started.elapsed().as_secs_f64();
        let result = salvage_status_dict(
            py,
            "partial",
            "",
            "ZIP verified entry salvage produced a semantic BytePatch",
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
        )?;
        result.bind(py).set_item("patch_plan", patch_plan)?;
        result.bind(py).set_item("native_timing", native_timing_with_scan(py, &scan, &[
            ("read_source", read_seconds),
            ("scan_entries", scan_seconds),
            ("semantic_patch", semantic_seconds),
            ("total", native_started.elapsed().as_secs_f64()),
        ])?)?;
        return Ok(result);
    }
    let semantic_seconds = timing_semantic_started.elapsed().as_secs_f64();
    let output_path = Path::new(workspace).join(format!("{repair_name}.zip"));
    let timing_write_started = Instant::now();
    match write_candidate_zip(
        &data,
        &scan.entries,
        &plan,
        &output_path,
        options.max_output_bytes,
    ) {
        Ok(stats) => {
            let write_seconds = timing_write_started.elapsed().as_secs_f64();
            let result = salvage_status_dict(
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
            )?;
            let patch_plan = match cd_suffix_patch_plan_for_preserved_entries(
                py,
                repair_name,
                "zip",
                &data,
                &scan.entries,
                &plan,
                0.91,
                &action_refs,
                repair_name,
            )? {
                Some(plan) => Some(plan),
                None => fs::read(&output_path).ok().map(|bytes| {
                    logical_archive_replace_patch_plan(py, repair_name, "zip", &data, &bytes, 0.91, &action_refs, repair_name)
                }).transpose()?,
            };
            if let Some(patch_plan) = patch_plan {
                result.bind(py).set_item("patch_plan", patch_plan)?;
            }
            result.bind(py).set_item("native_timing", native_timing_with_scan(py, &scan, &[
                ("read_source", read_seconds),
                ("scan_entries", scan_seconds),
                ("semantic_patch", semantic_seconds),
                ("write_candidate", write_seconds),
                ("total", native_started.elapsed().as_secs_f64()),
            ])?)?;
            Ok(result)
        }
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
    let native_started = Instant::now();
    let started = native_started;
    let password = extract_password(source_input);
    let options = DeepZipOptions {
        max_candidates: 1,
        max_entries: max_entries.max(1),
        max_input_bytes: mb_to_bytes(max_input_size_mb),
        max_output_bytes: mb_to_bytes(max_output_size_mb),
        max_entry_uncompressed_bytes: mb_to_bytes(max_entry_uncompressed_mb),
        max_duration: duration_from_seconds(max_seconds),
        verify_candidates: false,
        allow_unverified_entries: true,
        password,
    };
    let timing_read_started = Instant::now();
    let data = match read_source_input(source_input, options.max_input_bytes) {
        Ok(data) => data,
        Err(message) => return status_dict(py, "skipped", "", &message, &[], &[], 0, 0, 0.0, None, Some("input_read_failed")),
    };
    let read_seconds = timing_read_started.elapsed().as_secs_f64();
    let timing_scan_started = Instant::now();
    let scan = scan_entries(&data, &options, started);
    let scan_seconds = timing_scan_started.elapsed().as_secs_f64();
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
    let action_refs = plan.actions.to_vec();
    let timing_semantic_started = Instant::now();
    if let Some((patch_plan, stats)) = central_directory_suffix_patch_and_stats(
        py,
        "zip_cd_local_header_reconcile_rebuild",
        "zip",
        &data,
        &scan.entries,
        &plan,
        0.93,
        &action_refs,
        "zip_cd_local_header_reconcile_rebuild",
    )? {
        let semantic_seconds = timing_semantic_started.elapsed().as_secs_f64();
        let result = salvage_status_dict(
            py,
            "partial",
            "",
            "ZIP central directory entries were reconciled as a semantic BytePatch",
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
        )?;
        result.bind(py).set_item("patch_plan", patch_plan)?;
        result.bind(py).set_item("native_timing", native_timing_with_scan(py, &scan, &[
            ("read_source", read_seconds),
            ("scan_entries", scan_seconds),
            ("semantic_patch", semantic_seconds),
            ("total", native_started.elapsed().as_secs_f64()),
        ])?)?;
        return Ok(result);
    }
    let semantic_seconds = timing_semantic_started.elapsed().as_secs_f64();
    let output_path = Path::new(workspace).join("zip_cd_local_header_reconcile_rebuild.zip");
    let timing_write_started = Instant::now();
    match write_candidate_zip(
        &data,
        &scan.entries,
        &plan,
        &output_path,
        options.max_output_bytes,
    ) {
        Ok(stats) => {
            let write_seconds = timing_write_started.elapsed().as_secs_f64();
            let result = salvage_status_dict(
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
            )?;
            let patch_plan = match cd_suffix_patch_plan_for_preserved_entries(
                py,
                "zip_cd_local_header_reconcile_rebuild",
                "zip",
                &data,
                &scan.entries,
                &plan,
                0.93,
                &action_refs,
                "zip_cd_local_header_reconcile_rebuild",
            )? {
                Some(plan) => Some(plan),
                None => fs::read(&output_path).ok().map(|bytes| {
                    logical_archive_replace_patch_plan(py, "zip_cd_local_header_reconcile_rebuild", "zip", &data, &bytes, 0.93, &action_refs, "zip_cd_local_header_reconcile_rebuild")
                }).transpose()?,
            };
            if let Some(patch_plan) = patch_plan {
                result.bind(py).set_item("patch_plan", patch_plan)?;
            }
            result.bind(py).set_item("native_timing", native_timing_with_scan(py, &scan, &[
                ("read_source", read_seconds),
                ("scan_entries", scan_seconds),
                ("semantic_patch", semantic_seconds),
                ("write_candidate", write_seconds),
                ("total", native_started.elapsed().as_secs_f64()),
            ])?)?;
            Ok(result)
        }
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

