#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    repair_name,
    max_input_size_mb=512.0,
    max_output_size_mb=2048.0,
    max_entries=20000
))]
pub(crate) fn tar_boundary_repair(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    repair_name: &str,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
    max_entries: usize,
) -> PyResult<Py<PyDict>> {
    let options = StreamRepairOptions {
        max_input_bytes: mb_to_bytes(max_input_size_mb),
        max_output_bytes: mb_to_bytes(max_output_size_mb),
        max_duration: None,
    };
    let data = match read_source_input(source_input, options.max_input_bytes) {
        Ok(data) => data,
        Err(message) => return tar_repair_status(py, "skipped", "", &message, &[], None, &[], 0.0),
    };
    if let Err(message) = walk_tar_payload_end_limited(&data, max_entries.max(1)) {
        return tar_repair_status(py, "skipped", "", &message, &[], None, &[], 0.0);
    }
    let repair = match repair_name {
        "tar_trailing_junk_trim" => repair_tar_trailing_junk(&data),
        "tar_trailing_zero_block_repair" => repair_tar_trailing_zero_blocks(&data),
        _ => Err(format!("unsupported TAR boundary repair: {repair_name}")),
    };
    let repair = match repair {
        Ok(repair) => repair,
        Err(message) => {
            return tar_repair_status(py, "unrepairable", "", &message, &[], None, &[], 0.0)
        }
    };
    let output_path = Path::new(workspace).join(format!("{repair_name}.tar"));
    let output_bytes = match write_tar_repair_candidate(&data, &repair, &output_path) {
        Ok(bytes) => bytes,
        Err(message) => {
            return tar_repair_status(
                py,
                "unrepairable",
                "",
                &format!("TAR candidate could not be written: {message}"),
                &[],
                None,
                &[],
                0.0,
            )
        }
    };
    let result = tar_repair_status(
        py,
        "repaired",
        &output_path.to_string_lossy(),
        &repair.message,
        &repair.actions,
        repair.truncate_at,
        &repair.patches,
        repair.confidence,
    )?;
    let dict = result.bind(py);
    dict.set_item("output_bytes", output_bytes)?;
    if let Some(append_data) = &repair.append_data {
        dict.set_item("append_data", PyBytes::new(py, append_data))?;
    }
    Ok(result)
}

