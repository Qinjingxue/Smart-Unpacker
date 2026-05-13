#[pyfunction]
#[pyo3(signature = (source_input, workspace, max_input_size_mb=512.0, max_output_size_mb=2048.0))]
pub(crate) fn zstd_frame_salvage_repair(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
) -> PyResult<Py<PyDict>> {
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return stream_salvage_status(py, "skipped", "zstd", "", &message, &[], &[], 0, 0.0)
        }
    };
    let repair = match salvage_zstd_frames(&data) {
        Ok(repair) => repair,
        Err(message) => {
            return stream_salvage_status(
                py,
                "unrepairable",
                "zstd",
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
    let output_path = Path::new(workspace).join("zstd_frame_salvage.zst");
    let output_bytes = match write_recompressed_stream(
        StreamFormat::Zstd,
        &repair.payload,
        &output_path,
        &options,
    ) {
        Ok(bytes) => bytes,
        Err(message) => {
            return stream_salvage_status(
                py,
                "unrepairable",
                "zstd",
                "",
                &message,
                &repair.recovered_offsets,
                &repair.skipped_offsets,
                0,
                0.0,
            )
        }
    };
    let confidence = (0.68 + 0.12 * repair.recovered_offsets.len() as f64).min(0.94);
    stream_salvage_status(
        py,
        "partial",
        "zstd",
        &output_path.to_string_lossy(),
        "damaged zstd frames were skipped by native repair",
        &repair.recovered_offsets,
        &repair.skipped_offsets,
        output_bytes,
        confidence,
    )
}

