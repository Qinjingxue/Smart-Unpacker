#[pyfunction]
#[pyo3(signature = (
    source_input,
    format,
    workspace,
    strategy="block_salvage",
    max_input_size_mb=512.0,
    max_output_size_mb=2048.0,
    max_seconds=30.0
))]
pub(crate) fn compression_stream_block_salvage(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    format: &str,
    workspace: &str,
    strategy: &str,
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
    let safe_strategy = sanitize_strategy_name(strategy);
    let output_path = Path::new(workspace).join(format!(
        "{}_{}{}",
        format.name(),
        safe_strategy,
        format.ext()
    ));
    match recover_stream_prefix(&data, format, &output_path, &options) {
        Ok(recovered) => {
            if !is_trusted_prefix_salvage(&recovered) {
                let _ = fs::remove_file(&output_path);
                return status_dict(
                    py,
                    "unrepairable",
                    "",
                    recovered.error.as_deref().unwrap_or(""),
                    "stream decoder reported data/checksum damage after emitting bytes; refusing an unverifiable corrupt-prefix candidate",
                    &recovered.warnings,
                    format.name(),
                    recovered.decoded_bytes,
                    0,
                    0.0,
                );
            }
            let result = PyDict::new(py);
            result.set_item("status", "partial")?;
            result.set_item("selected_path", output_path.to_string_lossy().to_string())?;
            result.set_item("format", format.name())?;
            result.set_item("confidence", confidence_for_size(recovered.decoded_bytes))?;
            result.set_item(
                "message",
                match safe_strategy.as_str() {
                    "deflate_prefix_salvage" => {
                        "gzip deflate prefix was salvaged before the damaged payload"
                    }
                    "block_salvage" => {
                        "compression stream block/prefix salvage produced a decodable candidate"
                    }
                    _ => "compression stream salvage produced a decodable candidate",
                },
            )?;
            result.set_item("decoder_error", recovered.error.as_deref().unwrap_or(""))?;
            result.set_item("decoded_bytes", recovered.decoded_bytes)?;
            result.set_item("output_bytes", recovered.output_bytes)?;
            let actions = match safe_strategy.as_str() {
                "deflate_prefix_salvage" => vec![
                    "decode_deflate_until_error",
                    "drop_damaged_deflate_suffix",
                    "recompress_recovered_prefix",
                ],
                "block_salvage" => vec![
                    "decode_stream_blocks_until_error",
                    "drop_damaged_stream_suffix",
                    "recompress_recovered_prefix",
                ],
                _ => vec![
                    "decode_stream_until_error",
                    "drop_damaged_suffix",
                    "recompress_recovered_prefix",
                ],
            };
            result.set_item("actions", PyList::new(py, actions)?)?;
            result.set_item("warnings", PyList::new(py, &recovered.warnings)?)?;
            result.set_item(
                "workspace_paths",
                PyList::new(py, &[output_path.to_string_lossy().to_string()])?,
            )?;
            Ok(result.unbind())
        }
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

