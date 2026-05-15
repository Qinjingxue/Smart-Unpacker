#[pyfunction]
#[pyo3(signature = (
    source_input,
    max_entries=20000,
    max_input_size_mb=512.0,
    max_entry_uncompressed_mb=512.0,
    max_seconds=30.0,
    verify_candidates=true
))]
pub(crate) fn zip_scan_source(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    max_entries: usize,
    max_input_size_mb: f64,
    max_entry_uncompressed_mb: f64,
    max_seconds: f64,
    verify_candidates: bool,
) -> PyResult<Py<PyDict>> {
    let started = Instant::now();
    let password = extract_password(source_input);
    let options = DeepZipOptions {
        max_candidates: 1,
        max_entries: max_entries.max(1),
        max_input_bytes: mb_to_bytes(max_input_size_mb),
        max_output_bytes: Some(u64::MAX),
        max_entry_uncompressed_bytes: mb_to_bytes(max_entry_uncompressed_mb),
        max_duration: duration_from_seconds(max_seconds),
        verify_candidates,
        allow_unverified_entries: true,
        password,
    };
    let data = match read_source_input(source_input, options.max_input_bytes) {
        Ok(data) => data,
        Err(message) => {
            let result = PyDict::new(py);
            result.set_item("status", "skipped")?;
            result.set_item("native_target", "zip_scan_source")?;
            result.set_item("candidate_status", "no_candidate")?;
            result.set_item("message", message)?;
            result.set_item("zip_scan_artifact", true)?;
            result.set_item("zip_scan_artifact_miss_reason", "input_read_failed")?;
            return Ok(result.into());
        }
    };
    let scan = scan_entries(&data, &options, started);
    let result = PyDict::new(py);
    result.set_item("status", if scan.entries.is_empty() { "unrepairable" } else { "scanned" })?;
    result.set_item("native_target", "zip_scan_source")?;
    result.set_item("candidate_status", if scan.entries.is_empty() { "no_candidate" } else { "scan_artifact" })?;
    result.set_item("message", "ZIP source scan artifact was produced")?;
    result.set_item("zip_scan_artifact", true)?;
    result.set_item("entries", scan.entries.len())?;
    result.set_item("verified_entries", scan.entries.iter().filter(|entry| entry.verified).count())?;
    result.set_item("descriptor_entries", scan.descriptor_entries)?;
    result.set_item("encrypted_entries", scan.encrypted_entries)?;
    result.set_item("timed_out", scan.timed_out)?;
    result.set_item("diagnostics", build_scan_diagnostics(py, &scan, if scan.entries.is_empty() { Some("no_recoverable_entries") } else { None })?)?;
    result.set_item("patch_facts", PyList::new(py, ["zip_scan_artifact_available"])?)?;
    result.set_item("residual_facts", PyList::empty(py))?;
    Ok(result.into())
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
        if let Ok(bytes) = fs::read(&candidate.path) {
            let action_refs = candidate.actions.to_vec();
            item.set_item(
                "patch_plan",
                logical_archive_replace_patch_plan(
                    py,
                    candidate.name,
                    "zip",
                    &data,
                    &bytes,
                    candidate.confidence,
                    &action_refs,
                    "zip_deep_partial_recovery",
                )?,
            )?;
        }
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
        Ok(stats) => {
            let result = add_rebuild_target_metadata(py, rebuild_status_dict(
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
            )?, preserve_raw_names, logical_stream_built)?;
            if let Ok(bytes) = fs::read(output_path) {
                let action_refs = plan.actions.to_vec();
                let native_target = if preserve_raw_names {
                    "rebuild_cd_preserve_raw_names"
                } else {
                    "rebuild_cd_from_local_headers"
                };
                result.bind(py).set_item(
                    "patch_plan",
                    logical_archive_replace_patch_plan(
                        py,
                        "zip_rebuild_from_local_headers",
                        "zip",
                        &data,
                        &bytes,
                        plan.confidence,
                        &action_refs,
                        native_target,
                    )?,
                )?;
            }
            Ok(result)
        }
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

