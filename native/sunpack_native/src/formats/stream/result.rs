fn status_dict(
    py: Python<'_>,
    status: &str,
    selected_path: &str,
    decoder_error: &str,
    message: &str,
    warnings: &[String],
    format: &str,
    decoded_bytes: u64,
    output_bytes: u64,
    confidence: f64,
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("selected_path", selected_path)?;
    result.set_item("format", format)?;
    result.set_item("confidence", confidence)?;
    result.set_item("message", message)?;
    result.set_item("decoder_error", decoder_error)?;
    result.set_item("decoded_bytes", decoded_bytes)?;
    result.set_item("output_bytes", output_bytes)?;
    result.set_item(
        "actions",
        PyList::new(
            py,
            ["decode_recoverable_prefix", "recompress_partial_stream"],
        )?,
    )?;
    result.set_item("warnings", PyList::new(py, warnings)?)?;
    result.set_item(
        "workspace_paths",
        if selected_path.is_empty() {
            PyList::empty(py)
        } else {
            PyList::new(py, [selected_path])?
        },
    )?;
    Ok(result.unbind())
}

fn stream_trim_status(
    py: Python<'_>,
    status: &str,
    format: &str,
    selected_path: &str,
    message: &str,
    output_bytes: u64,
    input_bytes: u64,
    confidence: f64,
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("format", format)?;
    result.set_item("selected_path", selected_path)?;
    result.set_item("message", message)?;
    result.set_item("output_bytes", output_bytes)?;
    result.set_item("input_bytes", input_bytes)?;
    result.set_item("confidence", confidence)?;
    result.set_item("actions", PyList::empty(py))?;
    result.set_item("warnings", PyList::empty(py))?;
    result.set_item("workspace_paths", PyList::empty(py))?;
    Ok(result.unbind())
}

fn stream_salvage_status(
    py: Python<'_>,
    status: &str,
    format: &str,
    selected_path: &str,
    message: &str,
    recovered_offsets: &[u64],
    skipped_offsets: &[u64],
    output_bytes: u64,
    confidence: f64,
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("format", format)?;
    result.set_item("selected_path", selected_path)?;
    result.set_item("message", message)?;
    result.set_item("confidence", confidence)?;
    result.set_item("recovered_offsets", PyList::new(py, recovered_offsets)?)?;
    result.set_item("skipped_offsets", PyList::new(py, skipped_offsets)?)?;
    result.set_item("recovered_bytes", 0u64)?;
    result.set_item("output_bytes", output_bytes)?;
    result.set_item(
        "actions",
        if format == "zstd" {
            PyList::new(
                py,
                &[
                    "scan_zstd_frames",
                    "skip_bad_frames",
                    "recompress_recovered_payload",
                ],
            )?
        } else {
            PyList::new(
                py,
                &[
                    "scan_gzip_members",
                    "skip_bad_deflate_members",
                    "recompress_recovered_payload",
                ],
            )?
        },
    )?;
    let warnings = if skipped_offsets.is_empty() {
        Vec::new()
    } else {
        vec![format!(
            "skipped damaged {format} offsets: {:?}",
            &skipped_offsets[..skipped_offsets.len().min(8)]
        )]
    };
    result.set_item("warnings", PyList::new(py, &warnings)?)?;
    result.set_item(
        "workspace_paths",
        if selected_path.is_empty() {
            PyList::empty(py)
        } else {
            PyList::new(py, [selected_path])?
        },
    )?;
    Ok(result.unbind())
}

fn tar_repair_status(
    py: Python<'_>,
    status: &str,
    selected_path: &str,
    message: &str,
    actions: &[&str],
    truncate_at: Option<u64>,
    patches: &[TarBytePatch],
    confidence: f64,
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("format", "tar")?;
    result.set_item("selected_path", selected_path)?;
    result.set_item("message", message)?;
    result.set_item("confidence", confidence)?;
    result.set_item("actions", PyList::new(py, actions)?)?;
    result.set_item("warnings", PyList::empty(py))?;
    result.set_item(
        "workspace_paths",
        if selected_path.is_empty() {
            PyList::empty(py)
        } else {
            PyList::new(py, [selected_path])?
        },
    )?;
    if let Some(value) = truncate_at {
        result.set_item("truncate_at", value)?;
    }
    let patch_list = PyList::empty(py);
    for patch in patches {
        let item = PyDict::new(py);
        item.set_item("offset", patch.offset)?;
        item.set_item("data", PyBytes::new(py, &patch.data))?;
        patch_list.append(item)?;
    }
    result.set_item("patches", patch_list)?;
    Ok(result.unbind())
}

fn tar_status_dict(
    py: Python<'_>,
    status: &str,
    selected_path: &str,
    decoder_error: &str,
    message: &str,
    warnings: &[String],
    format: &str,
    outer_format: &str,
    decoded_bytes: u64,
    tar_bytes: u64,
    output_bytes: u64,
    members: u64,
    checksum_fixes: u64,
    truncated_members: u64,
    confidence: f64,
    actions: &[&str],
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("selected_path", selected_path)?;
    result.set_item("format", format)?;
    result.set_item("outer_format", outer_format)?;
    result.set_item("confidence", confidence)?;
    result.set_item("message", message)?;
    result.set_item("decoder_error", decoder_error)?;
    result.set_item("decoded_bytes", decoded_bytes)?;
    result.set_item("tar_bytes", tar_bytes)?;
    result.set_item("output_bytes", output_bytes)?;
    result.set_item("members", members)?;
    result.set_item("checksum_fixes", checksum_fixes)?;
    result.set_item("truncated_members", truncated_members)?;
    result.set_item("actions", PyList::new(py, actions)?)?;
    result.set_item("warnings", PyList::new(py, warnings)?)?;
    result.set_item(
        "workspace_paths",
        if selected_path.is_empty() {
            PyList::empty(py)
        } else {
            PyList::new(py, [selected_path])?
        },
    )?;
    Ok(result.unbind())
}

