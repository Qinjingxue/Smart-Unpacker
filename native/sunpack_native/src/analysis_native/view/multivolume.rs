#[pymethods]
impl AnalysisMultiVolumeView {
    #[new]
    #[pyo3(signature = (paths, cache_bytes=67108864, max_read_bytes=None, max_concurrent_reads=1))]
    fn new(
        paths: Vec<String>,
        cache_bytes: usize,
        max_read_bytes: Option<u64>,
        max_concurrent_reads: usize,
    ) -> PyResult<Self> {
        let paths = paths
            .into_iter()
            .filter(|path| !path.is_empty())
            .collect::<Vec<_>>();
        if paths.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "AnalysisMultiVolumeView requires at least one volume",
            ));
        }
        let mut cursor = 0u64;
        let mut volumes = Vec::with_capacity(paths.len());
        for path in &paths {
            let size = std::fs::metadata(path)?.len();
            let end = cursor.checked_add(size).ok_or_else(|| {
                pyo3::exceptions::PyOverflowError::new_err("multi-volume archive size overflow")
            })?;
            volumes.push(VolumeRange {
                start: cursor,
                end,
                path: path.clone(),
            });
            cursor = end;
        }
        Ok(Self {
            inner: Mutex::new(AnalysisMultiVolumeViewInner {
                path: paths[0].clone(),
                size: cursor,
                volumes,
                cache_bytes,
                max_read_bytes,
                cache: HashMap::new(),
                order: VecDeque::new(),
                cache_size: 0,
                read_bytes: 0,
                cache_hits: 0,
            }),
            read_gate: ReadGate {
                limit: max_concurrent_reads.max(1),
                active: Mutex::new(0),
                available: Condvar::new(),
            },
        })
    }

    #[getter]
    fn size(&self) -> PyResult<u64> {
        Ok(self.lock()?.size)
    }

    #[getter]
    fn path(&self) -> PyResult<String> {
        Ok(self.lock()?.path.clone())
    }

    fn read_at<'py>(
        &self,
        py: Python<'py>,
        offset: u64,
        size: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let data = self.read_at_bytes(offset, size)?;
        Ok(PyBytes::new(py, &data))
    }

    fn read_tail<'py>(&self, py: Python<'py>, size: usize) -> PyResult<Bound<'py, PyBytes>> {
        let view_size = self.lock()?.size;
        let read_size = size.min(view_size as usize);
        let offset = view_size.saturating_sub(read_size as u64);
        let data = self.read_at_bytes(offset, read_size)?;
        Ok(PyBytes::new(py, &data))
    }

    fn stats(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let inner = self.lock()?;
        let dict = PyDict::new(py);
        dict.set_item("read_bytes", inner.read_bytes)?;
        dict.set_item("cache_hits", inner.cache_hits)?;
        Ok(dict.unbind())
    }

    #[pyo3(signature = (
        window_bytes=65536,
        max_windows=8,
        max_sample_bytes=1048576,
        entropy_high_threshold=6.8,
        entropy_low_threshold=3.5,
        entropy_jump_threshold=1.25,
        ngram_top_k=8,
        max_ngram_sample_bytes=262144
    ))]
    fn fuzzy_binary_profile(
        &self,
        py: Python<'_>,
        window_bytes: usize,
        max_windows: usize,
        max_sample_bytes: usize,
        entropy_high_threshold: f64,
        entropy_low_threshold: f64,
        entropy_jump_threshold: f64,
        ngram_top_k: usize,
        max_ngram_sample_bytes: usize,
    ) -> PyResult<Py<PyDict>> {
        let file_size = self.lock()?.size;
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
        build_fuzzy_binary_profile(
            py,
            file_size,
            |offset, size| self.read_at_bytes(offset, size),
            config,
        )
    }

    #[pyo3(signature = (head_bytes=1048576, tail_bytes=1048576))]
    fn signature_prepass(
        &self,
        py: Python<'_>,
        head_bytes: usize,
        tail_bytes: usize,
    ) -> PyResult<Py<PyDict>> {
        let size = self.lock()?.size;
        let head_len = head_bytes.min(size as usize);
        let tail_len = tail_bytes.min(size as usize);
        let tail_start = size.saturating_sub(tail_len as u64);
        let head_end = head_len as u64;
        let mut hits = Vec::new();
        let scanned_head = head_len;
        let scanned_tail = tail_len;

        if tail_start <= head_end {
            let data = self.read_at_bytes(0, size as usize)?;
            collect_signature_hits(&mut hits, 0, &data);
        } else {
            let head = self.read_at_bytes(0, head_len)?;
            collect_signature_hits(&mut hits, 0, &head);
            let tail = self.read_at_bytes(tail_start, tail_len)?;
            collect_signature_hits(&mut hits, tail_start, &tail);
        }
        hits.sort_by_key(|(_, offset)| *offset);
        hits.dedup();

        let dict = PyDict::new(py);
        let py_hits = PyList::empty(py);
        let mut formats = Vec::new();
        for (name, offset) in hits {
            let hit = PyDict::new(py);
            hit.set_item("name", name)?;
            hit.set_item("offset", offset)?;
            py_hits.append(hit)?;
            let format = format_for_hit(name);
            if !formats.contains(&format) {
                formats.push(format);
            }
        }
        formats.sort();
        dict.set_item("hits", py_hits)?;
        dict.set_item("formats", formats)?;
        dict.set_item("head_bytes", scanned_head)?;
        dict.set_item("tail_bytes", scanned_tail)?;
        Ok(dict.unbind())
    }
}
