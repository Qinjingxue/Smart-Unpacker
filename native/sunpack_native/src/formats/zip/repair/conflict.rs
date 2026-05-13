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

