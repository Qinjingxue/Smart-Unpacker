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

