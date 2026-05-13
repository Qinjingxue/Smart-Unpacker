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
        "zip_extra_field_length_fix" => repair_zip_extra_field_length(&data),
        "zip_data_descriptor_flag_normalize" => repair_zip_data_descriptor_flags(&data),
        "zip_cd_entry_name_reconcile" => repair_zip_cd_entry_names_from_local_headers(&data),
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

