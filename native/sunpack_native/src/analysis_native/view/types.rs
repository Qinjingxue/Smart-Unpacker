#[pyclass]
pub(crate) struct AnalysisBinaryView {
    pub(crate) path: String,
    pub(crate) reader: ManagedReader,
}

#[pyclass]
pub(crate) struct AnalysisMultiVolumeView {
    path: String,
    reader: ManagedReader,
}
