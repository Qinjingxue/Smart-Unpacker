#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    max_input_size_mb=512.0,
    max_seconds=30.0,
    max_decode_size_mb=32.0
))]
pub(crate) fn gzip_footer_fix_repair(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_seconds: f64,
    max_decode_size_mb: f64,
) -> PyResult<Py<PyDict>> {
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => return stream_trim_status(py, "skipped", "gzip", "", &message, 0, 0, 0.0),
    };
    let repair = match repair_gzip_footer(
        &data,
        Instant::now(),
        duration_from_seconds(max_seconds),
        mb_to_bytes(max_decode_size_mb).unwrap_or(u64::MAX) as usize,
    ) {
        Ok(repair) => repair,
        Err(message) => {
            return stream_trim_status(
                py,
                "unrepairable",
                "gzip",
                "",
                &message,
                0,
                data.len() as u64,
                0.0,
            )
        }
    };
    let output_path = Path::new(workspace).join("gzip_footer_fix.gz");
    let output_bytes = match write_prefix_and_suffix_atomic(
        &data,
        repair.stream_end,
        &repair.footer,
        &output_path,
    ) {
        Ok(bytes) => bytes,
        Err(message) => {
            return stream_trim_status(
                py,
                "unrepairable",
                "gzip",
                "",
                &format!("gzip footer candidate could not be written: {message}"),
                0,
                data.len() as u64,
                0.0,
            )
        }
    };
    let result = PyDict::new(py);
    result.set_item("status", "repaired")?;
    result.set_item("format", "gzip")?;
    result.set_item("selected_path", output_path.to_string_lossy().to_string())?;
    result.set_item("confidence", 0.88)?;
    result.set_item("message", "gzip footer was recomputed by native repair")?;
    result.set_item(
        "actions",
        PyList::new(py, &["decode_deflate_payload", "rewrite_gzip_footer"])?,
    )?;
    result.set_item("warnings", PyList::empty(py))?;
    result.set_item(
        "workspace_paths",
        PyList::new(py, &[output_path.to_string_lossy().to_string()])?,
    )?;
    result.set_item("truncate_at", repair.stream_end as u64)?;
    result.set_item("append_data", PyBytes::new(py, &repair.footer))?;
    result.set_item("decoded_bytes", repair.decoded_bytes)?;
    result.set_item("output_bytes", output_bytes)?;
    Ok(result.unbind())
}

#[pyfunction]
#[pyo3(signature = (source_input, workspace, max_input_size_mb=512.0, max_output_size_mb=2048.0))]
pub(crate) fn gzip_deflate_member_resync_repair(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
) -> PyResult<Py<PyDict>> {
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return stream_salvage_status(py, "skipped", "gzip", "", &message, &[], &[], 0, 0.0)
        }
    };
    let repair = match salvage_gzip_members(&data) {
        Ok(repair) => repair,
        Err(message) => {
            return stream_salvage_status(
                py,
                "unrepairable",
                "gzip",
                "",
                &message,
                &[],
                &[],
                0,
                0.0,
            )
        }
    };
    let options = StreamRepairOptions {
        max_input_bytes: mb_to_bytes(max_input_size_mb),
        max_output_bytes: mb_to_bytes(max_output_size_mb),
        max_duration: None,
    };
    let output_path = Path::new(workspace).join("gzip_deflate_member_resync.gz");
    let output_bytes = match write_recompressed_stream(
        StreamFormat::Gzip,
        &repair.payload,
        &output_path,
        &options,
    ) {
        Ok(bytes) => bytes,
        Err(message) => {
            return stream_salvage_status(
                py,
                "unrepairable",
                "gzip",
                "",
                &message,
                &repair.recovered_offsets,
                &repair.skipped_offsets,
                0,
                0.0,
            )
        }
    };
    let confidence = (0.64 + 0.1 * repair.recovered_offsets.len() as f64).min(0.9);
    stream_salvage_status(
        py,
        "partial",
        "gzip",
        &output_path.to_string_lossy(),
        "damaged gzip members were skipped by native repair",
        &repair.recovered_offsets,
        &repair.skipped_offsets,
        output_bytes,
        confidence,
    )
}

