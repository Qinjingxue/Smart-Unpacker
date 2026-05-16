const COPY_CHUNK_SIZE: usize = 1024 * 1024;
const RAR4_MAGIC: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5_MAGIC: &[u8] = b"Rar!\x1a\x07\x01\x00";

#[pyfunction]
#[pyo3(signature = (
    source_input,
    format,
    workspace,
    max_input_size_mb=512.0,
    max_candidates=8
))]
pub(crate) fn archive_carrier_crop_recovery(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    format: &str,
    workspace: &str,
    max_input_size_mb: f64,
    max_candidates: usize,
) -> PyResult<Py<PyDict>> {
    let native_started = std::time::Instant::now();
    let target = TargetFormat::from_name(format);
    let read_started = std::time::Instant::now();
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            let result_started = std::time::Instant::now();
            let result = status_dict(
                py,
                "skipped",
                "",
                target.name(),
                &message,
                &[],
                0,
                0,
                0,
                0.0,
                &[],
            )?;
            result.bind(py).set_item("native_timing", carrier_timing_dict(py, &[
                ("read_source", read_started.elapsed().as_secs_f64()),
                ("scan_signatures", 0.0),
                ("write_candidates", 0.0),
                ("result_build", result_started.elapsed().as_secs_f64()),
                ("total", native_started.elapsed().as_secs_f64()),
            ])?)?;
            return Ok(result);
        }
    };
    let read_seconds = read_started.elapsed().as_secs_f64();

    let scan_started = std::time::Instant::now();
    let candidates = scan_archive_signatures(&data, target, true, max_candidates.max(1));
    let scan_seconds = scan_started.elapsed().as_secs_f64();
    if candidates.is_empty() {
        let result_started = std::time::Instant::now();
        let result = status_dict(
            py,
            "unrepairable",
            "",
            target.name(),
            "no embedded archive signature passed structural checks",
            &[],
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        )?;
        result.bind(py).set_item("native_timing", carrier_timing_dict(py, &[
            ("read_source", read_seconds),
            ("scan_signatures", scan_seconds),
            ("write_candidates", 0.0),
            ("result_build", result_started.elapsed().as_secs_f64()),
            ("total", native_started.elapsed().as_secs_f64()),
        ])?)?;
        return Ok(result);
    };

    let mut written = Vec::new();
    let mut write_warnings = Vec::new();
    let write_started = std::time::Instant::now();
    for candidate in candidates {
        let output_path = Path::new(workspace).join(format!(
            "archive_carrier_crop_{:08x}{}",
            candidate.offset,
            candidate.format.ext()
        ));
        let output_bytes = match write_slice_candidate(&data[candidate.offset..], &output_path) {
            Ok(bytes) => bytes,
            Err(err) => {
                write_warnings.push(format!(
                    "candidate at offset {} could not be written: {err}",
                    candidate.offset
                ));
                continue;
            }
        };
        let mut warnings = candidate.warnings.clone();
        if candidate.offset == 0 {
            warnings.push("archive starts at offset 0; carrier crop was not needed".to_string());
        }
        written.push(WrittenArchiveCandidate {
            name: format!("carrier_crop_{:08x}", candidate.offset),
            path: output_path.to_string_lossy().to_string(),
            format: candidate.format.name().to_string(),
            status: "repaired".to_string(),
            offset: candidate.offset as u64,
            end_offset: data.len() as u64,
            output_bytes,
            confidence: confidence_for_candidate(&candidate),
            actions: vec!["crop_embedded_archive_from_carrier".to_string()],
            warnings,
        });
    }
    let write_seconds = write_started.elapsed().as_secs_f64();
    let Some(selected) = written.first() else {
        let result_started = std::time::Instant::now();
        let result = status_dict(
            py,
            "unrepairable",
            "",
            target.name(),
            "embedded archive candidates were found but none could be written",
            &write_warnings,
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        )?;
        result.bind(py).set_item("native_timing", carrier_timing_dict(py, &[
            ("read_source", read_seconds),
            ("scan_signatures", scan_seconds),
            ("write_candidates", write_seconds),
            ("result_build", result_started.elapsed().as_secs_f64()),
            ("total", native_started.elapsed().as_secs_f64()),
        ])?)?;
        return Ok(result);
    };
    let result_started = std::time::Instant::now();
    let result = status_dict_with_candidates(
        py,
        "repaired",
        &selected.path,
        &selected.format,
        "embedded archive candidate was cropped from carrier bytes",
        &selected.warnings,
        selected.offset,
        data.len() as u64,
        selected.output_bytes,
        selected.confidence,
        &["crop_embedded_archive_from_carrier"],
        &written,
    )?;
    result.bind(py).set_item("native_timing", carrier_timing_dict(py, &[
        ("read_source", read_seconds),
        ("scan_signatures", scan_seconds),
        ("write_candidates", write_seconds),
        ("result_build", result_started.elapsed().as_secs_f64()),
        ("total", native_started.elapsed().as_secs_f64()),
    ])?)?;
    Ok(result)
}

