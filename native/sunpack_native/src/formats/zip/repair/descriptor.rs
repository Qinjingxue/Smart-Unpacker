#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    max_candidates=3,
    max_entries=20000,
    max_input_size_mb=512.0,
    max_seconds=30.0
))]
pub(crate) fn zip_remove_spurious_data_descriptor(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_candidates: usize,
    max_entries: usize,
    max_input_size_mb: f64,
    max_seconds: f64,
) -> PyResult<Py<PyDict>> {
    let started = Instant::now();
    let max_input_bytes = mb_to_bytes(max_input_size_mb);
    let data = match read_source_input(source_input, max_input_bytes) {
        Ok(data) => data,
        Err(message) => return descriptor_delete_status_dict(py, "skipped", &message, &[], Some("input_read_failed")),
    };
    let candidates = spurious_descriptor_delete_candidates(
        &data,
        max_candidates.max(1),
        max_entries.max(1),
        duration_from_seconds(max_seconds),
        started,
    );
    if candidates.is_empty() {
        return descriptor_delete_status_dict(
            py,
            "unrepairable",
            "no safely removable spurious ZIP data descriptor was found",
            &[],
            Some("no_spurious_data_descriptor"),
        );
    }

    fs::create_dir_all(workspace).ok();
    let result = PyDict::new(py);
    result.set_item("status", "partial")?;
    result.set_item("selected_path", "")?;
    result.set_item("selected_candidate", "spurious_data_descriptor_delete")?;
    result.set_item("confidence", candidates[0].confidence)?;
    result.set_item("format", "zip")?;
    result.set_item("message", "spurious ZIP data descriptor delete patch was produced")?;
    result.set_item(
        "actions",
        PyList::new(py, ["detect_spurious_data_descriptor", "delete_descriptor_span"])?,
    )?;
    result.set_item("candidate_status", "partial")?;
    result.set_item("native_target", "spurious_data_descriptor_delete")?;
    result.set_item(
        "patch_facts",
        PyList::new(py, descriptor_delete_patch_facts(&candidates[0]))?,
    )?;
    result.set_item("residual_facts", PyList::empty(py))?;
    result.set_item(
        "validation_details",
        descriptor_delete_validation_details(py, &candidates[0])?,
    )?;
    result.set_item("warnings", PyList::empty(py))?;
    result.set_item("skipped_entries", 0)?;
    result.set_item("encrypted_entries", 0)?;
    result.set_item("unsupported_entries", 0)?;
    result.set_item("recovered_entries", 0)?;
    result.set_item("verified_entries", 0)?;
    result.set_item("descriptor_entries", candidates.len())?;
    result.set_item("passthrough_entries", 0)?;

    let candidate_list = PyList::empty(py);
    for (index, candidate) in candidates.iter().enumerate() {
        let item = PyDict::new(py);
        item.set_item("name", format!("spurious_data_descriptor_delete_{index}"))?;
        item.set_item("status", "partial")?;
        item.set_item("confidence", candidate.confidence)?;
        item.set_item("actions", PyList::new(py, ["detect_spurious_data_descriptor", "delete_descriptor_span"])?)?;
        item.set_item("native_target", "spurious_data_descriptor_delete")?;
        item.set_item("candidate_status", "partial")?;
        item.set_item("patch_facts", PyList::new(py, descriptor_delete_patch_facts(candidate))?)?;
        item.set_item("residual_facts", PyList::empty(py))?;
        item.set_item("validation_details", descriptor_delete_validation_details(py, candidate)?)?;
        item.set_item("patch_plan", descriptor_delete_patch_plan(py, candidate)?)?;
        candidate_list.append(item)?;
    }
    result.set_item("candidates", candidate_list)?;
    result.set_item("workspace_paths", PyList::empty(py))?;
    Ok(result.unbind())
}

