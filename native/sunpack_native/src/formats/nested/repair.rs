#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    max_input_size_mb=512.0,
    max_candidates=8
))]
pub(crate) fn archive_nested_payload_salvage(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_candidates: usize,
) -> PyResult<Py<PyDict>> {
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(
                py,
                "skipped",
                "",
                "archive",
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
    let candidates = nested_archive_candidates(&data, workspace, max_candidates.max(1));
    let Some(selected) = candidates.first() else {
        return status_dict(
            py,
            "unrepairable",
            "",
            "archive",
            "no nested archive payload candidate was found",
            &[],
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    };
    let action_refs = selected
        .actions
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    status_dict_with_candidates(
        py,
        "partial",
        &selected.path,
        &selected.format,
        "nested archive payload was salvaged from a damaged container",
        &selected.warnings,
        selected.offset,
        selected.end_offset,
        selected.output_bytes,
        selected.confidence,
        &action_refs,
        &candidates,
    )
}

