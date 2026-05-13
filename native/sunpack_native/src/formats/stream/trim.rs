#[pyfunction]
#[pyo3(signature = (
    source_input,
    format,
    workspace,
    max_input_size_mb=512.0,
    max_probe_junk_bytes=1048576,
    max_seconds=30.0,
    max_probe_attempts=32,
    max_decode_size_mb=64.0
))]
pub(crate) fn compression_stream_trailing_junk_trim(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    format: &str,
    workspace: &str,
    max_input_size_mb: f64,
    max_probe_junk_bytes: usize,
    max_seconds: f64,
    max_probe_attempts: usize,
    max_decode_size_mb: f64,
) -> PyResult<Py<PyDict>> {
    let Some(format) = StreamFormat::from_name(format) else {
        return stream_trim_status(
            py,
            "unsupported",
            format,
            "",
            "unsupported compression stream format",
            0,
            0,
            0.0,
        );
    };
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return stream_trim_status(py, "skipped", format.name(), "", &message, 0, 0, 0.0)
        }
    };
    let deadline = duration_from_seconds(max_seconds);
    let max_decode_bytes = mb_to_bytes(max_decode_size_mb).unwrap_or(u64::MAX) as usize;
    let stream_end = match find_complete_stream_prefix(
        &data,
        format,
        max_probe_junk_bytes.max(1),
        Instant::now(),
        deadline,
        max_probe_attempts.max(1),
        max_decode_bytes,
    ) {
        StreamPrefixSearch::Found(end) => end,
        StreamPrefixSearch::TimedOut => {
            return stream_trim_status(
                py,
                "skipped",
                format.name(),
                "",
                &format!("{} stream trim probe exceeded budget", format.name()),
                0,
                data.len() as u64,
                0.0,
            )
        }
        StreamPrefixSearch::NotFound => {
            return stream_trim_status(
                py,
                "unrepairable",
                format.name(),
                "",
                &format!("no trailing junk after complete {} stream", format.name()),
                0,
                data.len() as u64,
                0.0,
            )
        }
    };
    if stream_end >= data.len() {
        return stream_trim_status(
            py,
            "unrepairable",
            format.name(),
            "",
            &format!("no trailing junk after complete {} stream", format.name()),
            0,
            data.len() as u64,
            0.0,
        );
    }
    let output_path = Path::new(workspace).join(format!(
        "{}_trailing_junk_trim{}",
        format.name(),
        format.ext()
    ));
    let output_bytes = match write_prefix_atomic(&data, stream_end, &output_path) {
        Ok(bytes) => bytes,
        Err(message) => {
            return stream_trim_status(
                py,
                "unrepairable",
                format.name(),
                "",
                &format!("trimmed stream candidate could not be written: {message}"),
                0,
                data.len() as u64,
                0.0,
            )
        }
    };
    let result = PyDict::new(py);
    result.set_item("status", "repaired")?;
    result.set_item("format", format.name())?;
    result.set_item("selected_path", output_path.to_string_lossy().to_string())?;
    result.set_item(
        "confidence",
        match format {
            StreamFormat::Zstd => 0.78,
            StreamFormat::Bzip2 => 0.84,
            _ => 0.86,
        },
    )?;
    result.set_item(
        "message",
        format!(
            "{} stream trailing junk was trimmed by native repair",
            format.name()
        ),
    )?;
    let action = format!("trim_after_{}_stream", format.name());
    result.set_item("actions", PyList::new(py, &[action])?)?;
    result.set_item("warnings", PyList::empty(py))?;
    result.set_item(
        "workspace_paths",
        PyList::new(py, &[output_path.to_string_lossy().to_string()])?,
    )?;
    result.set_item("truncate_at", stream_end as u64)?;
    result.set_item("input_bytes", data.len() as u64)?;
    result.set_item("output_bytes", output_bytes)?;
    Ok(result.unbind())
}

