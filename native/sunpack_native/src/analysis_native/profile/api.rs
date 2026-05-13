#[pyfunction]
#[pyo3(signature = (
    paths,
    window_bytes=65536,
    max_windows=8,
    max_sample_bytes=1048576,
    entropy_high_threshold=6.8,
    entropy_low_threshold=3.5,
    entropy_jump_threshold=1.25,
    ngram_top_k=8,
    max_ngram_sample_bytes=262144
))]
pub(crate) fn fuzzy_binary_profile_for_paths(
    py: Python<'_>,
    paths: Vec<String>,
    window_bytes: usize,
    max_windows: usize,
    max_sample_bytes: usize,
    entropy_high_threshold: f64,
    entropy_low_threshold: f64,
    entropy_jump_threshold: f64,
    ngram_top_k: usize,
    max_ngram_sample_bytes: usize,
) -> PyResult<Py<PyDict>> {
    let volumes = LogicalVolumes::new(paths)?;
    let window_bytes = window_bytes.max(1024);
    let config = BinaryProfileConfig {
        window_bytes,
        max_windows: max_windows.max(1),
        max_sample_bytes: max_sample_bytes.max(window_bytes),
        entropy_high_threshold,
        entropy_low_threshold,
        entropy_jump_threshold,
        ngram_top_k: ngram_top_k.max(1),
        max_ngram_sample_bytes,
    };
    fuzzy_binary_profile(
        py,
        volumes.size,
        |offset, size| volumes.read_at(offset, size),
        config,
    )
}
