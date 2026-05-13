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
    let target = TargetFormat::from_name(format);
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(
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
            )
        }
    };

    let candidates = scan_archive_signatures(&data, target, true, max_candidates.max(1));
    if candidates.is_empty() {
        return status_dict(
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
        );
    };

    let mut written = Vec::new();
    let mut write_warnings = Vec::new();
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
    let Some(selected) = written.first() else {
        return status_dict(
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
        );
    };
    status_dict_with_candidates(
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
    )
}

