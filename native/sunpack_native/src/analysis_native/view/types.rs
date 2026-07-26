#[pyclass]
pub(crate) struct AnalysisBinaryView {
    path: String,
    reader: ManagedReader,
}

#[pyclass]
pub(crate) struct AnalysisMultiVolumeView {
    path: String,
    reader: ManagedReader,
}
