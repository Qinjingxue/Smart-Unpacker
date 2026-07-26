use memmap2::{Mmap, MmapOptions};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyDict, PyList};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fs::{File, Metadata};
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Seek, SeekFrom};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::SystemTime;

#[cfg(test)]
thread_local! {
    static THREAD_PHYSICAL_READS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

const BLOCK_SIZE: usize = 64 * 1024;
const DEFAULT_SHARED_CACHE_BYTES: usize = 256 * 1024 * 1024;
const CACHE_SHARDS: usize = 64;
const HOT_CACHE_FRACTION: usize = 4;
const HOT_EDGE_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_HANDLE_CAPACITY: usize = 256;
const MAX_CACHEABLE_READ_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct CachedSlice {
    data: Arc<[u8]>,
    start: usize,
    end: usize,
}

impl Deref for CachedSlice {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data[self.start..self.end]
    }
}

pub(crate) enum CachedBytes {
    Slice(CachedSlice),
    Owned(Vec<u8>),
}

impl Deref for CachedBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Slice(slice) => slice,
            Self::Owned(data) => data,
        }
    }
}

pub(crate) trait ByteSource: Send + Sync {
    fn len(&self) -> u64;
    /// Reads at most `len` bytes. A range crossing EOF is shortened.
    fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>>;
    fn read_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        let data = self.read_at(offset, buffer.len())?;
        buffer[..data.len()].copy_from_slice(&data);
        Ok(data.len())
    }
    fn read_slices_at(&self, offset: u64, len: usize) -> io::Result<Vec<CachedSlice>> {
        let data: Arc<[u8]> = Arc::from(self.read_at(offset, len)?);
        let end = data.len();
        Ok((end > 0)
            .then_some(CachedSlice {
                data,
                start: 0,
                end,
            })
            .into_iter()
            .collect())
    }
    fn prefetch(&self, _ranges: &[(u64, usize)]) -> io::Result<()> {
        Ok(())
    }
    fn read_direct_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        self.read_at(offset, len)
    }
    fn read_direct_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        let data = self.read_direct_at(offset, buffer.len())?;
        buffer[..data.len()].copy_from_slice(&data);
        Ok(data.len())
    }
    fn map_read_only(&self) -> io::Result<Option<Mmap>> {
        Ok(None)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ReaderConfig {
    pub(crate) cache_bytes: usize,
    pub(crate) max_read_bytes: Option<u64>,
    pub(crate) max_concurrent_reads: usize,
}

impl Default for ReaderConfig {
    fn default() -> Self {
        Self {
            cache_bytes: 0,
            max_read_bytes: None,
            max_concurrent_reads: usize::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ReaderStats {
    pub(crate) read_bytes: u64,
    pub(crate) cache_hits: u64,
}

#[derive(Clone)]
pub(crate) struct ManagedReader {
    source: Arc<dyn ByteSource>,
    state: Arc<ReaderState>,
}

struct ReaderState {
    config: ReaderConfig,
    inner: Mutex<ReaderInner>,
    uncached_read_bytes: AtomicU64,
    gate: ReadGate,
}

#[derive(Default)]
struct ReaderInner {
    cache: HashMap<(u64, usize), Arc<[u8]>>,
    order: VecDeque<(u64, usize)>,
    cache_size: usize,
    stats: ReaderStats,
}

struct ReadGate {
    limit: usize,
    active: Mutex<usize>,
    available: Condvar,
}

struct ReadPermit<'a> {
    gate: Option<&'a ReadGate>,
}

impl ManagedReader {
    pub(crate) fn new(source: Arc<dyn ByteSource>, config: ReaderConfig) -> Self {
        Self {
            source,
            state: Arc::new(ReaderState {
                gate: ReadGate {
                    limit: config.max_concurrent_reads.max(1),
                    active: Mutex::new(0),
                    available: Condvar::new(),
                },
                config,
                inner: Mutex::new(ReaderInner::default()),
                uncached_read_bytes: AtomicU64::new(0),
            }),
        }
    }

    pub(crate) fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open_with_config(path, ReaderConfig::default())
    }

    pub(crate) fn open_with_config(
        path: impl AsRef<Path>,
        config: ReaderConfig,
    ) -> io::Result<Self> {
        let source = manager().open_file(path.as_ref())?;
        Ok(Self::new(source, config))
    }

    pub(crate) fn open_volumes(paths: &[String], config: ReaderConfig) -> io::Result<Self> {
        let source = MultiVolumeSource::open(paths)?;
        Ok(Self::new(Arc::new(source), config))
    }

    pub(crate) fn with_config(&self, config: ReaderConfig) -> Self {
        Self::new(Arc::clone(&self.source), config)
    }

    pub(crate) fn len(&self) -> u64 {
        self.source.len()
    }

    /// Reads a range and shortens it at EOF, matching `Read`/positional-read semantics.
    pub(crate) fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if offset >= self.len() || len == 0 {
            return Ok(Vec::new());
        }
        let read_len = len.min((self.len() - offset) as usize);
        if !self.uses_request_state() {
            let _permit = self.state.gate.acquire()?;
            let data = self.source.read_at(offset, read_len)?;
            self.state
                .uncached_read_bytes
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            return Ok(data);
        }
        let key = (offset, read_len);
        {
            let mut inner = self.lock_inner()?;
            if let Some(data) = inner.cache.get(&key).cloned() {
                inner.stats.cache_hits += 1;
                return Ok(data.as_ref().to_vec());
            }
            if self
                .state
                .config
                .max_read_bytes
                .is_some_and(|limit| inner.stats.read_bytes + read_len as u64 > limit)
            {
                return Err(io::Error::other("archive analysis read budget exceeded"));
            }
        }

        let _permit = self.state.gate.acquire()?;
        let data = self.source.read_at(offset, read_len)?;
        let mut inner = self.lock_inner()?;
        inner.stats.read_bytes += data.len() as u64;
        inner.store_cache_entry(key, Arc::from(data.clone()), self.state.config.cache_bytes);
        Ok(data)
    }

    pub(crate) fn read_exact_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let data = self.read_at(offset, len)?;
        if data.len() != len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            ));
        }
        Ok(data)
    }

    /// Reads through the shared cache directly into a caller-owned buffer.
    /// This is the allocation-free hot path used by `SourceCursor`.
    pub(crate) fn read_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len() || buffer.is_empty() {
            return Ok(0);
        }
        let read_len = buffer.len().min((self.len() - offset) as usize);
        if !self.uses_request_state() {
            let _permit = self.state.gate.acquire()?;
            let count = self.source.read_into_at(offset, &mut buffer[..read_len])?;
            self.state
                .uncached_read_bytes
                .fetch_add(count as u64, Ordering::Relaxed);
            return Ok(count);
        }
        let key = (offset, read_len);
        {
            let mut inner = self.lock_inner()?;
            if let Some(data) = inner.cache.get(&key).cloned() {
                inner.stats.cache_hits += 1;
                buffer[..data.len()].copy_from_slice(&data);
                return Ok(data.len());
            }
            if self
                .state
                .config
                .max_read_bytes
                .is_some_and(|limit| inner.stats.read_bytes + read_len as u64 > limit)
            {
                return Err(io::Error::other("archive analysis read budget exceeded"));
            }
        }

        let _permit = self.state.gate.acquire()?;
        let count = self.source.read_into_at(offset, &mut buffer[..read_len])?;
        let mut inner = self.lock_inner()?;
        inner.stats.read_bytes += count as u64;
        if self.state.config.cache_bytes > 0 {
            inner.store_cache_entry(
                key,
                Arc::from(&buffer[..count]),
                self.state.config.cache_bytes,
            );
        }
        Ok(count)
    }

    pub(crate) fn read_all(&self) -> io::Result<Vec<u8>> {
        let len = usize::try_from(self.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "file is too large for memory")
        })?;
        self.read_at(0, len)
    }

    /// Returns cache-backed slices without copying when the request is served
    /// by fixed blocks. Callers that require contiguous storage can use
    /// `read_at`; parsers that only inspect fields can consume these directly.
    pub(crate) fn read_slices_at(&self, offset: u64, len: usize) -> io::Result<Vec<CachedSlice>> {
        if offset >= self.len() || len == 0 {
            return Ok(Vec::new());
        }
        let read_len = len.min((self.len() - offset) as usize);
        if self.uses_request_state() {
            let data: Arc<[u8]> = Arc::from(self.read_at(offset, read_len)?);
            let end = data.len();
            return Ok(vec![CachedSlice {
                data,
                start: 0,
                end,
            }]);
        }
        let _permit = self.state.gate.acquire()?;
        let slices = self.source.read_slices_at(offset, read_len)?;
        let count = slices.iter().map(|slice| slice.len()).sum::<usize>();
        self.state
            .uncached_read_bytes
            .fetch_add(count as u64, Ordering::Relaxed);
        Ok(slices)
    }

    pub(crate) fn read_cached_at(&self, offset: u64, len: usize) -> io::Result<CachedBytes> {
        let mut slices = self.read_slices_at(offset, len)?;
        if slices.len() == 1 {
            return Ok(CachedBytes::Slice(slices.remove(0)));
        }
        let total = slices.iter().map(|slice| slice.len()).sum();
        let mut data = Vec::with_capacity(total);
        for slice in slices {
            data.extend_from_slice(&slice);
        }
        Ok(CachedBytes::Owned(data))
    }

    /// Warms every fixed block touched by the supplied ranges. Overlapping
    /// ranges are coalesced by the source before physical I/O.
    pub(crate) fn prefetch(&self, ranges: &[(u64, usize)]) -> io::Result<()> {
        let _permit = self.state.gate.acquire()?;
        self.source.prefetch(ranges)
    }

    pub(crate) fn read_many(&self, ranges: &[(u64, usize)]) -> io::Result<Vec<Vec<u8>>> {
        self.prefetch(ranges)?;
        ranges
            .iter()
            .map(|&(offset, len)| self.read_at(offset, len))
            .collect()
    }

    pub(crate) fn stats(&self) -> io::Result<ReaderStats> {
        let mut stats = self.lock_inner()?.stats;
        stats.read_bytes = stats
            .read_bytes
            .saturating_add(self.state.uncached_read_bytes.load(Ordering::Relaxed));
        Ok(stats)
    }

    pub(crate) fn cursor(&self) -> SourceCursor {
        SourceCursor {
            reader: self.clone(),
            position: 0,
            streaming: false,
        }
    }

    /// Sequential scans bypass the shared block cache to avoid cache pollution
    /// and preserve the existing large-buffer read pipeline.
    pub(crate) fn stream_cursor(&self) -> SourceCursor {
        SourceCursor {
            reader: self.clone(),
            position: 0,
            streaming: true,
        }
    }

    /// Maps a single immutable file for a high-throughput full-stream scan.
    /// Multi-volume and non-file sources return `None` and keep using the
    /// ordinary Reader streaming path.
    pub(crate) fn map_read_only(&self) -> io::Result<Option<Mmap>> {
        if self.uses_request_state() {
            return Ok(None);
        }
        let _permit = self.state.gate.acquire()?;
        let mapped = self.source.map_read_only()?;
        if let Some(ref data) = mapped {
            self.state
                .uncached_read_bytes
                .fetch_add(data.len() as u64, Ordering::Relaxed);
        }
        Ok(mapped)
    }

    pub(crate) fn read_direct_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        let _permit = self.state.gate.acquire()?;
        self.source.read_direct_into_at(offset, buffer)
    }

    fn lock_inner(&self) -> io::Result<MutexGuard<'_, ReaderInner>> {
        self.state
            .inner
            .lock()
            .map_err(|_| io::Error::other("managed reader lock poisoned"))
    }

    fn uses_request_state(&self) -> bool {
        self.state.config.cache_bytes > 0 || self.state.config.max_read_bytes.is_some()
    }
}

#[pyclass]
pub(crate) struct NativeArchiveSession {
    path: String,
    reader: ManagedReader,
    seven_zip_password_probe:
        OnceLock<Option<Arc<crate::formats::seven_zip::SevenZipPasswordProbe>>>,
}

#[pymethods]
impl NativeArchiveSession {
    #[new]
    fn new(path: String) -> PyResult<Self> {
        let reader = ManagedReader::open(&path)?;
        Ok(Self {
            path,
            reader,
            seven_zip_password_probe: OnceLock::new(),
        })
    }

    #[getter]
    fn path(&self) -> &str {
        &self.path
    }

    #[getter]
    fn size(&self) -> u64 {
        self.reader.len()
    }

    fn read_at<'py>(
        &self,
        py: Python<'py>,
        offset: u64,
        len: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let data = self.reader.read_at(offset, len)?;
        Ok(PyBytes::new(py, &data))
    }

    fn prefetch(&self, ranges: Vec<(u64, usize)>) -> PyResult<()> {
        self.reader.prefetch(&ranges)?;
        Ok(())
    }

    #[pyo3(signature = (cache_bytes=67108864, max_read_bytes=None, max_concurrent_reads=1))]
    fn analysis_view(
        &self,
        cache_bytes: usize,
        max_read_bytes: Option<u64>,
        max_concurrent_reads: usize,
    ) -> crate::analysis_native::AnalysisBinaryView {
        crate::analysis_native::AnalysisBinaryView {
            path: self.path.clone(),
            reader: self.reader.with_config(ReaderConfig {
                cache_bytes,
                max_read_bytes,
                max_concurrent_reads,
            }),
        }
    }

    fn stats(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let stats = self.reader.stats()?;
        let dict = PyDict::new(py);
        dict.set_item("read_bytes", stats.read_bytes)?;
        dict.set_item("cache_hits", stats.cache_hits)?;
        Ok(dict.unbind())
    }

    fn zip_fast_verify_passwords(
        &self,
        py: Python<'_>,
        passwords: &Bound<'_, PyList>,
    ) -> PyResult<Py<PyAny>> {
        crate::password::zip::zip_fast_verify_passwords_with_reader(py, &self.reader, passwords)
    }

    fn seven_zip_fast_verify_passwords(
        &self,
        py: Python<'_>,
        passwords: &Bound<'_, PyList>,
    ) -> PyResult<Py<PyAny>> {
        crate::password::seven_zip::seven_zip_fast_verify_passwords_with_probe_cache(
            py,
            &self.reader,
            passwords,
            &self.seven_zip_password_probe,
        )
    }

    fn rar_fast_verify_passwords(
        &self,
        py: Python<'_>,
        passwords: &Bound<'_, PyList>,
    ) -> PyResult<Py<PyAny>> {
        crate::password::rar::rar_fast_verify_passwords_with_reader(py, &self.reader, passwords)
    }

    fn scan_embedded_archives(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        crate::scan::embedded::scan_embedded_archives_with_reader(py, &self.reader)
    }
}

impl ReaderInner {
    fn store_cache_entry(&mut self, key: (u64, usize), data: Arc<[u8]>, capacity: usize) {
        if capacity == 0 || data.len() > capacity {
            return;
        }
        if let Some(old) = self.cache.insert(key, data) {
            self.cache_size = self.cache_size.saturating_sub(old.len());
            self.order.retain(|existing| *existing != key);
        }
        self.cache_size += self.cache.get(&key).map(|value| value.len()).unwrap_or(0);
        self.order.push_back(key);
        while self.cache_size > capacity {
            let Some(old_key) = self.order.pop_front() else {
                break;
            };
            if let Some(old) = self.cache.remove(&old_key) {
                self.cache_size = self.cache_size.saturating_sub(old.len());
            }
        }
    }
}

impl ReadGate {
    fn acquire(&self) -> io::Result<ReadPermit<'_>> {
        if self.limit == usize::MAX {
            return Ok(ReadPermit { gate: None });
        }
        let mut active = self
            .active
            .lock()
            .map_err(|_| io::Error::other("reader gate lock poisoned"))?;
        while *active >= self.limit {
            active = self
                .available
                .wait(active)
                .map_err(|_| io::Error::other("reader gate wait poisoned"))?;
        }
        *active += 1;
        Ok(ReadPermit { gate: Some(self) })
    }
}

impl Drop for ReadPermit<'_> {
    fn drop(&mut self) {
        let Some(gate) = self.gate else {
            return;
        };
        if let Ok(mut active) = gate.active.lock() {
            *active = active.saturating_sub(1);
            gate.available.notify_one();
        }
    }
}

pub(crate) struct SourceCursor {
    reader: ManagedReader,
    position: u64,
    streaming: bool,
}

impl Read for SourceCursor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = if self.streaming {
            self.reader.read_direct_into_at(self.position, buf)?
        } else {
            self.reader.read_into_at(self.position, buf)?
        };
        self.position = self.position.saturating_add(count as u64);
        Ok(count)
    }
}

impl Seek for SourceCursor {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(value) => value as i128,
            SeekFrom::End(value) => self.reader.len() as i128 + value as i128,
            SeekFrom::Current(value) => self.position as i128 + value as i128,
        };
        if target < 0 || target > u64::MAX as i128 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid seek"));
        }
        self.position = target as u64;
        Ok(self.position)
    }
}

#[derive(Clone, Eq, PartialEq, Hash)]
struct FileIdentity {
    path: PathBuf,
    len: u64,
    modified: Option<SystemTime>,
}

struct FileSource {
    identity: FileIdentity,
    file: File,
    block_loads: Mutex<HashMap<u64, Arc<Mutex<()>>>>,
}

impl ByteSource for FileSource {
    fn len(&self) -> u64 {
        self.identity.len
    }

    fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if offset >= self.len() || len == 0 {
            return Ok(Vec::new());
        }
        let len = len.min((self.len() - offset) as usize);
        if len > MAX_CACHEABLE_READ_BYTES {
            let data = read_file_at(&self.file, offset, len, &manager().metrics)?;
            manager()
                .metrics
                .logical_bytes
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            return Ok(data);
        }

        let first = offset / BLOCK_SIZE as u64;
        let last = (offset + len as u64 - 1) / BLOCK_SIZE as u64;
        let mut output = Vec::with_capacity(len);
        for index in first..=last {
            let block = manager().read_block(self, index)?;
            let block_start = index * BLOCK_SIZE as u64;
            let from = offset.saturating_sub(block_start) as usize;
            let request_end = offset + len as u64;
            let to = (request_end.min(block_start + block.len() as u64) - block_start) as usize;
            if from < to && from < block.len() {
                output.extend_from_slice(&block[from..to.min(block.len())]);
            }
        }
        manager()
            .metrics
            .logical_bytes
            .fetch_add(output.len() as u64, Ordering::Relaxed);
        Ok(output)
    }

    fn read_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len() || buffer.is_empty() {
            return Ok(0);
        }
        let len = buffer.len().min((self.len() - offset) as usize);
        if len > MAX_CACHEABLE_READ_BYTES {
            manager()
                .metrics
                .physical_reads
                .fetch_add(1, Ordering::Relaxed);
            let count = positional_read(&self.file, &mut buffer[..len], offset)?;
            manager()
                .metrics
                .physical_bytes
                .fetch_add(count as u64, Ordering::Relaxed);
            manager()
                .metrics
                .logical_bytes
                .fetch_add(count as u64, Ordering::Relaxed);
            return Ok(count);
        }

        let first = offset / BLOCK_SIZE as u64;
        let last = (offset + len as u64 - 1) / BLOCK_SIZE as u64;
        let mut written = 0usize;
        for index in first..=last {
            let block = manager().read_block(self, index)?;
            let block_start = index * BLOCK_SIZE as u64;
            let from = offset.saturating_sub(block_start) as usize;
            let request_end = offset + len as u64;
            let to = (request_end.min(block_start + block.len() as u64) - block_start) as usize;
            if from < to && from < block.len() {
                let chunk = &block[from..to.min(block.len())];
                buffer[written..written + chunk.len()].copy_from_slice(chunk);
                written += chunk.len();
            }
        }
        manager()
            .metrics
            .logical_bytes
            .fetch_add(written as u64, Ordering::Relaxed);
        Ok(written)
    }

    fn read_slices_at(&self, offset: u64, len: usize) -> io::Result<Vec<CachedSlice>> {
        if offset >= self.len() || len == 0 {
            return Ok(Vec::new());
        }
        let len = len.min((self.len() - offset) as usize);
        if len > MAX_CACHEABLE_READ_BYTES {
            let data: Arc<[u8]> = Arc::from(self.read_direct_at(offset, len)?);
            let end = data.len();
            return Ok(vec![CachedSlice {
                data,
                start: 0,
                end,
            }]);
        }
        let first = offset / BLOCK_SIZE as u64;
        let last = (offset + len as u64 - 1) / BLOCK_SIZE as u64;
        let request_end = offset + len as u64;
        let mut slices = Vec::with_capacity((last - first + 1) as usize);
        for index in first..=last {
            let block = manager().read_block(self, index)?;
            let block_start = index * BLOCK_SIZE as u64;
            let start = offset.saturating_sub(block_start) as usize;
            let end = (request_end.min(block_start + block.len() as u64) - block_start) as usize;
            if start < end && start < block.len() {
                slices.push(CachedSlice {
                    data: block,
                    start,
                    end,
                });
            }
        }
        manager()
            .metrics
            .logical_bytes
            .fetch_add(len as u64, Ordering::Relaxed);
        Ok(slices)
    }

    fn prefetch(&self, ranges: &[(u64, usize)]) -> io::Result<()> {
        let mut blocks = BTreeSet::new();
        for &(offset, len) in ranges {
            if offset >= self.len() || len == 0 {
                continue;
            }
            let len = len.min((self.len() - offset) as usize);
            if len > MAX_CACHEABLE_READ_BYTES {
                continue;
            }
            let first = offset / BLOCK_SIZE as u64;
            let last = (offset + len as u64 - 1) / BLOCK_SIZE as u64;
            blocks.extend(first..=last);
        }
        manager().prefetch_blocks(self, blocks.into_iter().collect())
    }

    fn read_direct_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if offset >= self.len() || len == 0 {
            return Ok(Vec::new());
        }
        let len = len.min((self.len() - offset) as usize);
        let data = read_file_at(&self.file, offset, len, &manager().metrics)?;
        manager()
            .metrics
            .logical_bytes
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        Ok(data)
    }

    fn read_direct_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len() || buffer.is_empty() {
            return Ok(0);
        }
        let len = buffer.len().min((self.len() - offset) as usize);
        let count = positional_read(&self.file, &mut buffer[..len], offset)?;
        manager()
            .metrics
            .physical_reads
            .fetch_add(1, Ordering::Relaxed);
        manager()
            .metrics
            .physical_bytes
            .fetch_add(count as u64, Ordering::Relaxed);
        manager()
            .metrics
            .logical_bytes
            .fetch_add(count as u64, Ordering::Relaxed);
        Ok(count)
    }

    fn map_read_only(&self) -> io::Result<Option<Mmap>> {
        if self.len() == 0 {
            return Ok(None);
        }
        // SAFETY: FileSource keeps the file handle alive, the pipeline treats
        // archive bytes as immutable, and Mmap owns the mapping until drop.
        let mapped = match unsafe { MmapOptions::new().map(&self.file) } {
            Ok(mapped) => mapped,
            Err(_) => return Ok(None),
        };
        manager()
            .metrics
            .logical_bytes
            .fetch_add(mapped.len() as u64, Ordering::Relaxed);
        Ok(Some(mapped))
    }
}

struct Volume {
    start: u64,
    end: u64,
    source: Arc<FileSource>,
}

struct MultiVolumeSource {
    len: u64,
    volumes: Vec<Volume>,
}

impl MultiVolumeSource {
    fn open(paths: &[String]) -> io::Result<Self> {
        if paths.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "multi-volume reader requires at least one volume",
            ));
        }
        let mut cursor = 0u64;
        let mut volumes = Vec::with_capacity(paths.len());
        for path in paths {
            let source = manager().open_file(path.as_ref())?;
            let end = cursor.checked_add(source.len()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "multi-volume size overflow")
            })?;
            volumes.push(Volume {
                start: cursor,
                end,
                source,
            });
            cursor = end;
        }
        Ok(Self {
            len: cursor,
            volumes,
        })
    }
}

impl ByteSource for MultiVolumeSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if offset >= self.len || len == 0 {
            return Ok(Vec::new());
        }
        let len = len.min((self.len - offset) as usize);
        let end = offset + len as u64;
        let mut output = Vec::with_capacity(len);
        for volume in &self.volumes {
            if offset >= volume.end || end <= volume.start {
                continue;
            }
            let logical_start = offset.max(volume.start);
            let logical_end = end.min(volume.end);
            let chunk = volume.source.read_at(
                logical_start - volume.start,
                (logical_end - logical_start) as usize,
            )?;
            output.extend_from_slice(&chunk);
        }
        Ok(output)
    }

    fn read_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len || buffer.is_empty() {
            return Ok(0);
        }
        let len = buffer.len().min((self.len - offset) as usize);
        let end = offset + len as u64;
        let mut written = 0usize;
        for volume in &self.volumes {
            if offset >= volume.end || end <= volume.start {
                continue;
            }
            let logical_start = offset.max(volume.start);
            let logical_end = end.min(volume.end);
            let chunk_len = (logical_end - logical_start) as usize;
            let count = volume.source.read_into_at(
                logical_start - volume.start,
                &mut buffer[written..written + chunk_len],
            )?;
            written += count;
            if count != chunk_len {
                break;
            }
        }
        Ok(written)
    }

    fn read_slices_at(&self, offset: u64, len: usize) -> io::Result<Vec<CachedSlice>> {
        if offset >= self.len || len == 0 {
            return Ok(Vec::new());
        }
        let len = len.min((self.len - offset) as usize);
        let end = offset + len as u64;
        let mut slices = Vec::new();
        for volume in &self.volumes {
            if offset >= volume.end || end <= volume.start {
                continue;
            }
            let logical_start = offset.max(volume.start);
            let logical_end = end.min(volume.end);
            slices.extend(volume.source.read_slices_at(
                logical_start - volume.start,
                (logical_end - logical_start) as usize,
            )?);
        }
        Ok(slices)
    }

    fn prefetch(&self, ranges: &[(u64, usize)]) -> io::Result<()> {
        for volume in &self.volumes {
            let mapped = ranges
                .iter()
                .filter_map(|&(offset, len)| {
                    let end = offset.saturating_add(len as u64).min(self.len);
                    if offset >= volume.end || end <= volume.start {
                        return None;
                    }
                    let start = offset.max(volume.start);
                    let end = end.min(volume.end);
                    Some((start - volume.start, (end - start) as usize))
                })
                .collect::<Vec<_>>();
            volume.source.prefetch(&mapped)?;
        }
        Ok(())
    }

    fn read_direct_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if offset >= self.len || len == 0 {
            return Ok(Vec::new());
        }
        let len = len.min((self.len - offset) as usize);
        let end = offset + len as u64;
        let mut output = Vec::with_capacity(len);
        for volume in &self.volumes {
            if offset >= volume.end || end <= volume.start {
                continue;
            }
            let logical_start = offset.max(volume.start);
            let logical_end = end.min(volume.end);
            let chunk = volume.source.read_direct_at(
                logical_start - volume.start,
                (logical_end - logical_start) as usize,
            )?;
            output.extend_from_slice(&chunk);
        }
        Ok(output)
    }
}

#[derive(Clone, Eq, PartialEq, Hash)]
struct BlockKey {
    identity: FileIdentity,
    index: u64,
}

#[derive(Clone, Copy)]
enum CacheTier {
    Hot,
    General,
}

struct CacheShard {
    entries: HashMap<BlockKey, Arc<[u8]>>,
    hot_order: VecDeque<BlockKey>,
    general_order: VecDeque<BlockKey>,
    hot_size: usize,
    general_size: usize,
    hot_capacity: usize,
    general_capacity: usize,
}

struct HandleEntry {
    source: Arc<FileSource>,
    generation: u64,
}

struct HandlePool {
    entries: HashMap<FileIdentity, HandleEntry>,
    by_path: HashMap<PathBuf, FileIdentity>,
    order: VecDeque<(FileIdentity, u64)>,
    generation: u64,
    capacity: usize,
}

struct ReaderManager {
    handles: Mutex<HandlePool>,
    cache_shards: Box<[Mutex<CacheShard>]>,
    metrics: ManagerMetrics,
}

#[derive(Default)]
struct ManagerMetrics {
    logical_bytes: AtomicU64,
    physical_bytes: AtomicU64,
    physical_reads: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    hot_cache_hits: AtomicU64,
    handle_hits: AtomicU64,
    opens: AtomicU64,
    evictions: AtomicU64,
}

impl ReaderManager {
    fn clear_resources(&self) -> io::Result<(usize, usize, usize)> {
        let mut removed_entries = 0usize;
        let mut removed_bytes = 0usize;
        for shard in &self.cache_shards {
            let mut shard = shard
                .lock()
                .map_err(|_| io::Error::other("shared reader cache shard poisoned"))?;
            removed_entries += shard.entries.len();
            removed_bytes += shard.hot_size + shard.general_size;
            shard.entries.clear();
            shard.hot_order.clear();
            shard.general_order.clear();
            shard.hot_size = 0;
            shard.general_size = 0;
        }
        let mut handles = self
            .handles
            .lock()
            .map_err(|_| io::Error::other("reader manager handle lock poisoned"))?;
        let removed_handles = handles.entries.len();
        handles.entries.clear();
        handles.by_path.clear();
        handles.order.clear();
        Ok((removed_handles, removed_entries, removed_bytes))
    }

    fn open_file(&self, path: &Path) -> io::Result<Arc<FileSource>> {
        let metadata = std::fs::metadata(path)?;
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        {
            let mut handles = self
                .handles
                .lock()
                .map_err(|_| io::Error::other("reader manager handle lock poisoned"))?;
            if let Some(identity) = handles.by_path.get(&canonical).cloned() {
                if identity.len == metadata.len() && identity.modified == metadata.modified().ok() {
                    if let Some(source) = handles.touch(&identity) {
                        self.metrics.handle_hits.fetch_add(1, Ordering::Relaxed);
                        return Ok(source);
                    }
                } else {
                    handles.by_path.remove(&canonical);
                }
            }
        }
        let file = open_reader_file(path)?;
        let metadata = file.metadata()?;
        let identity = file_identity(canonical, &metadata);
        let mut handles = self
            .handles
            .lock()
            .map_err(|_| io::Error::other("reader manager handle lock poisoned"))?;
        if let Some(existing) = handles.touch(&identity) {
            self.metrics.handle_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(existing);
        }
        let source = Arc::new(FileSource {
            identity: identity.clone(),
            file,
            block_loads: Mutex::new(HashMap::new()),
        });
        handles.insert(identity, Arc::clone(&source));
        self.metrics.opens.fetch_add(1, Ordering::Relaxed);
        Ok(source)
    }

    fn read_block(&self, source: &FileSource, index: u64) -> io::Result<Arc<[u8]>> {
        let key = BlockKey {
            identity: source.identity.clone(),
            index,
        };
        let tier = cache_tier(source, index);
        if let Some(block) = self.cached_block(&key, tier)? {
            return Ok(block);
        }

        // Coalesce concurrent misses for the same physical block without
        // serializing unrelated offsets or files.
        let load_gate = {
            let mut loads = source
                .block_loads
                .lock()
                .map_err(|_| io::Error::other("reader block-load lock poisoned"))?;
            Arc::clone(
                loads
                    .entry(index)
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        let _load = load_gate
            .lock()
            .map_err(|_| io::Error::other("reader block-load gate poisoned"))?;
        if let Some(block) = self.cached_block(&key, tier)? {
            return Ok(block);
        }
        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
        let offset = index * BLOCK_SIZE as u64;
        let len = BLOCK_SIZE.min(source.len().saturating_sub(offset) as usize);
        let data: Arc<[u8]> = Arc::from(read_file_at(&source.file, offset, len, &self.metrics)?);
        let data = self.insert_block(key, data, tier)?;
        drop(_load);
        if let Ok(mut loads) = source.block_loads.lock() {
            loads.remove(&index);
        }
        Ok(data)
    }

    /// Loads adjacent missing blocks with one positional read. This is used by
    /// `read_many` so callers that already know several offsets do not pay one
    /// syscall and one miss-coordination round trip per 64 KiB block.
    fn prefetch_blocks(&self, source: &FileSource, blocks: Vec<u64>) -> io::Result<()> {
        let mut missing = Vec::with_capacity(blocks.len());
        for index in blocks {
            let key = BlockKey {
                identity: source.identity.clone(),
                index,
            };
            if !self.contains_block(&key)? {
                missing.push(index);
            }
        }

        let max_blocks = (MAX_CACHEABLE_READ_BYTES / BLOCK_SIZE).max(1) as u64;
        let mut cursor = 0usize;
        while cursor < missing.len() {
            let start = missing[cursor];
            let mut end = start;
            cursor += 1;
            while cursor < missing.len()
                && missing[cursor] == end + 1
                && missing[cursor] - start < max_blocks
            {
                end = missing[cursor];
                cursor += 1;
            }
            if start == end {
                self.read_block(source, start)?;
                continue;
            }

            let offset = start * BLOCK_SIZE as u64;
            let requested = ((end - start + 1) * BLOCK_SIZE as u64)
                .min(source.len().saturating_sub(offset)) as usize;
            let data = read_file_at(&source.file, offset, requested, &self.metrics)?;
            self.metrics
                .cache_misses
                .fetch_add(end - start + 1, Ordering::Relaxed);
            for index in start..=end {
                let from = ((index - start) * BLOCK_SIZE as u64) as usize;
                if from >= data.len() {
                    break;
                }
                let to = (from + BLOCK_SIZE).min(data.len());
                let key = BlockKey {
                    identity: source.identity.clone(),
                    index,
                };
                self.insert_block(key, Arc::from(&data[from..to]), cache_tier(source, index))?;
            }
        }
        Ok(())
    }

    fn contains_block(&self, key: &BlockKey) -> io::Result<bool> {
        let shard_index = cache_shard_index(key);
        let shard = self.cache_shards[shard_index]
            .lock()
            .map_err(|_| io::Error::other("shared reader cache shard poisoned"))?;
        Ok(shard.entries.contains_key(key))
    }

    fn cached_block(&self, key: &BlockKey, tier: CacheTier) -> io::Result<Option<Arc<[u8]>>> {
        let shard_index = cache_shard_index(key);
        let shard = self.cache_shards[shard_index]
            .lock()
            .map_err(|_| io::Error::other("shared reader cache shard poisoned"))?;
        let block = shard.entries.get(key).cloned();
        if block.is_some() {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            if matches!(tier, CacheTier::Hot) {
                self.metrics.hot_cache_hits.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(block)
    }

    fn insert_block(
        &self,
        key: BlockKey,
        data: Arc<[u8]>,
        tier: CacheTier,
    ) -> io::Result<Arc<[u8]>> {
        let shard_index = cache_shard_index(&key);
        let mut shard = self.cache_shards[shard_index]
            .lock()
            .map_err(|_| io::Error::other("shared reader cache shard poisoned"))?;
        if let Some(existing) = shard.entries.get(&key) {
            return Ok(Arc::clone(existing));
        }
        shard.entries.insert(key.clone(), Arc::clone(&data));
        match tier {
            CacheTier::Hot => {
                shard.hot_size += data.len();
                shard.hot_order.push_back(key);
                while shard.hot_size > shard.hot_capacity {
                    let Some(old_key) = shard.hot_order.pop_front() else {
                        break;
                    };
                    if let Some(old) = shard.entries.remove(&old_key) {
                        shard.hot_size = shard.hot_size.saturating_sub(old.len());
                        self.metrics.evictions.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            CacheTier::General => {
                shard.general_size += data.len();
                shard.general_order.push_back(key);
                while shard.general_size > shard.general_capacity {
                    let Some(old_key) = shard.general_order.pop_front() else {
                        break;
                    };
                    if let Some(old) = shard.entries.remove(&old_key) {
                        shard.general_size = shard.general_size.saturating_sub(old.len());
                        self.metrics.evictions.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        Ok(data)
    }

    fn cache_totals(&self) -> io::Result<(usize, usize, usize)> {
        let mut entries = 0usize;
        let mut hot_bytes = 0usize;
        let mut general_bytes = 0usize;
        for shard in &self.cache_shards {
            let shard = shard
                .lock()
                .map_err(|_| io::Error::other("shared reader cache shard poisoned"))?;
            entries += shard.entries.len();
            hot_bytes += shard.hot_size;
            general_bytes += shard.general_size;
        }
        Ok((entries, hot_bytes, general_bytes))
    }
}

impl HandlePool {
    fn touch(&mut self, identity: &FileIdentity) -> Option<Arc<FileSource>> {
        let source = Arc::clone(&self.entries.get(identity)?.source);
        self.generation = self.generation.wrapping_add(1);
        let generation = self.generation;
        self.entries.get_mut(identity)?.generation = generation;
        self.order.push_back((identity.clone(), generation));
        Some(source)
    }

    fn insert(&mut self, identity: FileIdentity, source: Arc<FileSource>) {
        self.generation = self.generation.wrapping_add(1);
        let generation = self.generation;
        self.by_path.insert(identity.path.clone(), identity.clone());
        self.entries
            .insert(identity.clone(), HandleEntry { source, generation });
        self.order.push_back((identity, generation));
        while self.entries.len() > self.capacity {
            let Some((old_identity, old_generation)) = self.order.pop_front() else {
                break;
            };
            let current = self
                .entries
                .get(&old_identity)
                .map(|entry| entry.generation);
            if current != Some(old_generation) {
                continue;
            }
            self.entries.remove(&old_identity);
            if self.by_path.get(&old_identity.path) == Some(&old_identity) {
                self.by_path.remove(&old_identity.path);
            }
        }
    }
}

fn cache_shard_index(key: &BlockKey) -> usize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish() as usize & (CACHE_SHARDS - 1)
}

fn cache_tier(source: &FileSource, index: u64) -> CacheTier {
    let offset = index * BLOCK_SIZE as u64;
    if offset < HOT_EDGE_BYTES
        || offset.saturating_add(BLOCK_SIZE as u64) >= source.len().saturating_sub(HOT_EDGE_BYTES)
    {
        CacheTier::Hot
    } else {
        CacheTier::General
    }
}

#[pyfunction]
pub(crate) fn reader_cache_stats(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let manager = manager();
    let (entries, hot_bytes, general_bytes) = manager.cache_totals()?;
    let handles = manager
        .handles
        .lock()
        .map_err(|_| io::Error::other("reader manager handle lock poisoned"))?
        .entries
        .len();
    let dict = PyDict::new(py);
    dict.set_item(
        "logical_bytes",
        manager.metrics.logical_bytes.load(Ordering::Relaxed),
    )?;
    dict.set_item(
        "physical_bytes",
        manager.metrics.physical_bytes.load(Ordering::Relaxed),
    )?;
    dict.set_item(
        "physical_reads",
        manager.metrics.physical_reads.load(Ordering::Relaxed),
    )?;
    dict.set_item(
        "cache_hits",
        manager.metrics.cache_hits.load(Ordering::Relaxed),
    )?;
    dict.set_item(
        "hot_cache_hits",
        manager.metrics.hot_cache_hits.load(Ordering::Relaxed),
    )?;
    dict.set_item(
        "cache_misses",
        manager.metrics.cache_misses.load(Ordering::Relaxed),
    )?;
    dict.set_item(
        "handle_hits",
        manager.metrics.handle_hits.load(Ordering::Relaxed),
    )?;
    dict.set_item("opens", manager.metrics.opens.load(Ordering::Relaxed))?;
    dict.set_item(
        "evictions",
        manager.metrics.evictions.load(Ordering::Relaxed),
    )?;
    dict.set_item("cache_entries", entries)?;
    dict.set_item("hot_cache_bytes", hot_bytes)?;
    dict.set_item("general_cache_bytes", general_bytes)?;
    dict.set_item("open_handles", handles)?;
    dict.set_item("cache_shards", CACHE_SHARDS)?;
    Ok(dict.unbind())
}

#[pyfunction]
pub(crate) fn clear_reader_resources(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let (handles, cache_entries, cache_bytes) = manager().clear_resources()?;
    let dict = PyDict::new(py);
    dict.set_item("handles", handles)?;
    dict.set_item("cache_entries", cache_entries)?;
    dict.set_item("cache_bytes", cache_bytes)?;
    Ok(dict.unbind())
}

#[pyfunction]
pub(crate) fn release_reader_handles_under(path: &str) -> PyResult<usize> {
    let root = std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
    let mut handles = manager()
        .handles
        .lock()
        .map_err(|_| io::Error::other("reader manager handle lock poisoned"))?;
    let identities = handles
        .entries
        .keys()
        .filter(|identity| identity.path.starts_with(&root))
        .cloned()
        .collect::<Vec<_>>();
    for identity in &identities {
        handles.entries.remove(identity);
        if handles.by_path.get(&identity.path) == Some(identity) {
            handles.by_path.remove(&identity.path);
        }
    }
    Ok(identities.len())
}

fn manager() -> &'static ReaderManager {
    static MANAGER: OnceLock<ReaderManager> = OnceLock::new();
    MANAGER.get_or_init(|| {
        let shard_capacity = DEFAULT_SHARED_CACHE_BYTES / CACHE_SHARDS;
        let hot_capacity = shard_capacity / HOT_CACHE_FRACTION;
        let cache_shards = (0..CACHE_SHARDS)
            .map(|_| {
                Mutex::new(CacheShard {
                    entries: HashMap::new(),
                    hot_order: VecDeque::new(),
                    general_order: VecDeque::new(),
                    hot_size: 0,
                    general_size: 0,
                    hot_capacity,
                    general_capacity: shard_capacity - hot_capacity,
                })
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        ReaderManager {
            handles: Mutex::new(HandlePool {
                entries: HashMap::new(),
                by_path: HashMap::new(),
                order: VecDeque::new(),
                generation: 0,
                capacity: DEFAULT_HANDLE_CAPACITY,
            }),
            cache_shards,
            metrics: ManagerMetrics::default(),
        }
    })
}

fn file_identity(path: PathBuf, metadata: &Metadata) -> FileIdentity {
    FileIdentity {
        path,
        len: metadata.len(),
        modified: metadata.modified().ok(),
    }
}

fn read_file_at(
    file: &File,
    offset: u64,
    len: usize,
    metrics: &ManagerMetrics,
) -> io::Result<Vec<u8>> {
    let mut data = vec![0u8; len];
    let mut read = 0usize;
    while read < len {
        metrics.physical_reads.fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        THREAD_PHYSICAL_READS.with(|reads| reads.set(reads.get() + 1));
        let count = positional_read(file, &mut data[read..], offset + read as u64)?;
        if count == 0 {
            data.truncate(read);
            break;
        }
        read += count;
    }
    metrics
        .physical_bytes
        .fetch_add(data.len() as u64, Ordering::Relaxed);
    Ok(data)
}

#[cfg(windows)]
fn open_reader_file(path: &Path) -> io::Result<File> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    const SHARE_READ: u32 = 0x0000_0001;
    const SHARE_WRITE: u32 = 0x0000_0002;
    const SHARE_DELETE: u32 = 0x0000_0004;
    OpenOptions::new()
        .read(true)
        .share_mode(SHARE_READ | SHARE_WRITE | SHARE_DELETE)
        .open(path)
}

#[cfg(not(windows))]
fn open_reader_file(path: &Path) -> io::Result<File> {
    File::open(path)
}

#[cfg(unix)]
fn positional_read(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.read_at(buffer, offset)
}

#[cfg(windows)]
fn positional_read(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_read(buffer, offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_file;

    #[test]
    fn short_and_exact_reads_preserve_eof_semantics() {
        let path = temp_file("managed_reader_eof", b"abcdef");
        let reader = ManagedReader::open(&path).unwrap();
        assert_eq!(reader.read_at(4, 8).unwrap(), b"ef");
        assert_eq!(
            reader.read_exact_at(4, 8).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(reader.stats().unwrap().read_bytes, 4);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn request_cache_preserves_budget_and_hit_stats() {
        let path = temp_file("managed_reader_stats", b"abcdefgh");
        let reader = ManagedReader::open_with_config(
            &path,
            ReaderConfig {
                cache_bytes: 8,
                max_read_bytes: Some(4),
                max_concurrent_reads: 1,
            },
        )
        .unwrap();
        assert_eq!(reader.read_at(0, 4).unwrap(), b"abcd");
        assert_eq!(reader.read_at(0, 4).unwrap(), b"abcd");
        assert!(reader.read_at(4, 1).is_err());
        let stats = reader.stats().unwrap();
        assert_eq!(stats.read_bytes, 4);
        assert_eq!(stats.cache_hits, 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn read_into_preserves_request_cache_and_budget_semantics() {
        let path = temp_file("managed_reader_into_stats", b"abcdefgh");
        let reader = ManagedReader::open_with_config(
            &path,
            ReaderConfig {
                cache_bytes: 8,
                max_read_bytes: Some(4),
                max_concurrent_reads: 1,
            },
        )
        .unwrap();
        let mut buffer = [0u8; 4];
        assert_eq!(reader.read_into_at(0, &mut buffer).unwrap(), 4);
        assert_eq!(&buffer, b"abcd");
        buffer.fill(0);
        assert_eq!(reader.read_into_at(0, &mut buffer).unwrap(), 4);
        assert_eq!(&buffer, b"abcd");
        assert!(reader.read_into_at(4, &mut buffer[..1]).is_err());
        let stats = reader.stats().unwrap();
        assert_eq!(stats.read_bytes, 4);
        assert_eq!(stats.cache_hits, 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn multi_volume_reads_across_boundary() {
        let first = temp_file("managed_reader_part1", b"abc");
        let second = temp_file("managed_reader_part2", b"def");
        let paths = vec![
            first.to_string_lossy().into_owned(),
            second.to_string_lossy().into_owned(),
        ];
        let reader = ManagedReader::open_volumes(&paths, ReaderConfig::default()).unwrap();
        assert_eq!(reader.read_at(2, 3).unwrap(), b"cde");
        let mut cursor = reader.cursor();
        cursor.seek(SeekFrom::Start(2)).unwrap();
        let mut data = [0u8; 3];
        cursor.read_exact(&mut data).unwrap();
        assert_eq!(&data, b"cde");
        let _ = std::fs::remove_file(first);
        let _ = std::fs::remove_file(second);
    }

    #[test]
    fn readers_share_file_handle_and_block_cache() {
        let path = temp_file("managed_reader_shared", b"abcdefgh");
        let first = manager().open_file(&path).unwrap();
        assert_eq!(first.read_at(0, 4).unwrap(), b"abcd");
        let key = BlockKey {
            identity: first.identity.clone(),
            index: 0,
        };
        assert!(manager()
            .cached_block(&key, cache_tier(&first, 0))
            .unwrap()
            .is_some());
        let second = manager().open_file(&path).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(second.read_at(2, 4).unwrap(), b"cdef");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn handle_pool_keeps_recent_file_source_alive_between_readers() {
        let path = temp_file("managed_reader_handle_pool", b"abcdefgh");
        let first = manager().open_file(&path).unwrap();
        let first_ptr = Arc::as_ptr(&first);
        drop(first);
        let second = manager().open_file(&path).unwrap();
        assert_eq!(first_ptr, Arc::as_ptr(&second));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cached_slices_and_batch_reads_preserve_requested_bytes() {
        let data = vec![0x5au8; BLOCK_SIZE + 32];
        let path = temp_file("managed_reader_slices", &data);
        let reader = ManagedReader::open(&path).unwrap();
        let slices = reader.read_slices_at(BLOCK_SIZE as u64 - 8, 16).unwrap();
        assert_eq!(slices.len(), 2);
        assert_eq!(slices.iter().map(|slice| slice.len()).sum::<usize>(), 16);
        let cached = reader.read_cached_at(4, 8).unwrap();
        assert!(matches!(cached, CachedBytes::Slice(_)));
        assert_eq!(&*cached, &[0x5a; 8]);
        let many = reader.read_many(&[(0, 4), (BLOCK_SIZE as u64, 4)]).unwrap();
        assert_eq!(many, vec![vec![0x5a; 4], vec![0x5a; 4]]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn batch_prefetch_coalesces_adjacent_blocks_into_one_physical_read() {
        let data = vec![0x6bu8; BLOCK_SIZE * 3];
        let path = temp_file("managed_reader_batch_prefetch", &data);
        let reader = ManagedReader::open(&path).unwrap();
        let before = THREAD_PHYSICAL_READS.with(std::cell::Cell::get);

        let ranges = [(BLOCK_SIZE as u64 - 4, 8), ((BLOCK_SIZE * 2) as u64 - 4, 8)];
        let many = reader.read_many(&ranges).unwrap();
        let after = THREAD_PHYSICAL_READS.with(std::cell::Cell::get);

        assert_eq!(many, vec![vec![0x6b; 8], vec![0x6b; 8]]);
        assert_eq!(after - before, 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn changed_file_gets_a_new_identity() {
        let path = temp_file("managed_reader_identity", b"old");
        let first = ManagedReader::open(&path).unwrap();
        assert_eq!(first.read_all().unwrap(), b"old");
        std::fs::write(&path, b"new-data").unwrap();
        let second = ManagedReader::open(&path).unwrap();
        assert_eq!(second.read_all().unwrap(), b"new-data");
        let _ = std::fs::remove_file(path);
    }
}
