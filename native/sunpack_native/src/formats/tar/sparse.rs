#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    max_input_size_mb=512.0,
    max_output_size_mb=2048.0,
    max_entries=20000
))]
pub(crate) fn tar_sparse_pax_longname_repair(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
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
        Err(message) => return stream_trim_status(py, "skipped", "tar", "", &message, 0, 0, 0.0),
    };
    let repaired = match repair_tar_sparse_pax_longname(&data, &options, max_entries.max(1)) {
        Ok(repaired) => repaired,
        Err(message) => {
            return stream_trim_status(
                py,
                "unrepairable",
                "tar",
                "",
                &message,
                0,
                data.len() as u64,
                0.0,
            )
        }
    };
    let output_path = Path::new(workspace).join("tar_sparse_pax_longname_repair.tar");
    let output_bytes =
        match write_prefix_atomic(&repaired.bytes, repaired.bytes.len(), &output_path) {
            Ok(bytes) => bytes,
            Err(message) => {
                return stream_trim_status(
                    py,
                    "unrepairable",
                    "tar",
                    "",
                    &message,
                    0,
                    data.len() as u64,
                    0.0,
                )
            }
        };
    let result = PyDict::new(py);
    result.set_item("status", "partial")?;
    result.set_item("format", "tar")?;
    result.set_item("selected_path", output_path.to_string_lossy().to_string())?;
    result.set_item("confidence", 0.78)?;
    result.set_item(
        "message",
        "TAR PAX/GNU/sparse metadata was normalized by native repair",
    )?;
    result.set_item(
        "actions",
        PyList::new(
            py,
            &[
                "walk_tar_headers_with_resync",
                "drop_pax_gnu_sparse_metadata",
                "rewrite_tar_headers_with_safe_names",
                "append_tar_zero_blocks",
            ],
        )?,
    )?;
    result.set_item("warnings", PyList::new(py, &repaired.warnings)?)?;
    result.set_item(
        "workspace_paths",
        PyList::new(py, &[output_path.to_string_lossy().to_string()])?,
    )?;
    result.set_item("members", repaired.members)?;
    result.set_item("checksum_fixes", repaired.checksum_fixes)?;
    result.set_item("truncated_members", repaired.truncated_members)?;
    result.set_item("output_bytes", output_bytes)?;
    Ok(result.unbind())
}

