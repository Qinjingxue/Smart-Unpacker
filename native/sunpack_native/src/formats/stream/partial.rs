#[pyfunction]
#[pyo3(signature = (
    source_input,
    format,
    workspace,
    max_input_size_mb=512.0,
    max_output_size_mb=2048.0,
    max_seconds=30.0
))]
pub(crate) fn compression_stream_partial_recovery(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    format: &str,
    workspace: &str,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
    max_seconds: f64,
) -> PyResult<Py<PyDict>> {
    let Some(format) = StreamFormat::from_name(format) else {
        return status_dict(
            py,
            "unsupported",
            "",
            "",
            "unsupported compression stream format",
            &[],
            format,
            0,
            0,
            0.0,
        );
    };
    let options = StreamRepairOptions {
        max_input_bytes: mb_to_bytes(max_input_size_mb),
        max_output_bytes: mb_to_bytes(max_output_size_mb),
        max_duration: duration_from_seconds(max_seconds),
    };
    let data = match read_source_input(source_input, options.max_input_bytes) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(
                py,
                "skipped",
                "",
                "",
                &message,
                &[],
                format.name(),
                0,
                0,
                0.0,
            )
        }
    };
    let output_path = Path::new(workspace).join(format!(
        "{}_truncated_partial_recovery{}",
        format.name(),
        format.ext()
    ));
    match recover_stream_prefix(&data, format, &output_path, &options) {
        Ok(recovered) => status_dict(
            py,
            "partial",
            &output_path.to_string_lossy(),
            recovered.error.as_deref().unwrap_or(""),
            "compression stream truncated; recovered decodable prefix",
            &recovered.warnings,
            format.name(),
            recovered.decoded_bytes,
            recovered.output_bytes,
            confidence_for_size(recovered.decoded_bytes),
        ),
        Err(message) => status_dict(
            py,
            "unrepairable",
            "",
            "",
            &message,
            &[],
            format.name(),
            0,
            0,
            0.0,
        ),
    }
}

