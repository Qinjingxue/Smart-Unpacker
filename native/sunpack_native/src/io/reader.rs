use std::collections::{HashMap, VecDeque};
use std::fs::{File, Metadata};
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak};
use std::time::SystemTime;

const BLOCK_SIZE: usize = 64 * 1024;
const DEFAULT_SHARED_CACHE_BYTES: usize = 256 * 1024 * 1024;
const MAX_CACHEABLE_READ_BYTES: usize = 4 * 1024 * 1024;

pub(crate) trait ByteSource: Send + Sync {
    fn len(&self) -> u64;
    /// Reads at most `len` bytes. A range crossing EOF is shortened.
    fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>>;
    fn read_direct_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        self.read_at(offset, len)
    }
    fn read_direct_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        let data = self.read_direct_at(offset, buffer.len())?;
        buffer[..data.len()].copy_from_slice(&data);
        Ok(data.len())
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
    gate: &'a ReadGate,
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

    pub(crate) fn len(&self) -> u64 {
        self.source.len()
    }

    /// Reads a range and shortens it at EOF, matching `Read`/positional-read semantics.
    pub(crate) fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if offset >= self.len() || len == 0 {
            return Ok(Vec::new());
        }
        let read_len = len.min((self.len() - offset) as usize);
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

    pub(crate) fn read_all(&self) -> io::Result<Vec<u8>> {
        let len = usize::try_from(self.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "file is too large for memory")
        })?;
        self.read_at(0, len)
    }

    pub(crate) fn stats(&self) -> io::Result<ReaderStats> {
        Ok(self.lock_inner()?.stats)
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
        Ok(ReadPermit { gate: self })
    }
}

impl Drop for ReadPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.gate.active.lock() {
            *active = active.saturating_sub(1);
            self.gate.available.notify_one();
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
            let data = self.reader.read_at(self.position, buf.len())?;
            buf[..data.len()].copy_from_slice(&data);
            data.len()
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

#[derive(Clone, Eq)]
struct FileIdentity {
    path: PathBuf,
    len: u64,
    modified: Option<SystemTime>,
    platform_id: u128,
}

impl PartialEq for FileIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
            && self.len == other.len
            && self.modified == other.modified
            && self.platform_id == other.platform_id
    }
}

impl Hash for FileIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
        self.len.hash(state);
        self.modified.hash(state);
        self.platform_id.hash(state);
    }
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
            .physical_bytes
            .fetch_add(count as u64, Ordering::Relaxed);
        manager()
            .metrics
            .logical_bytes
            .fetch_add(count as u64, Ordering::Relaxed);
        Ok(count)
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

struct SharedCache {
    entries: HashMap<BlockKey, Arc<[u8]>>,
    order: VecDeque<BlockKey>,
    size: usize,
    capacity: usize,
}

struct ReaderManager {
    files: Mutex<HashMap<FileIdentity, Weak<FileSource>>>,
    cache: Mutex<SharedCache>,
    metrics: ManagerMetrics,
}

#[derive(Default)]
struct ManagerMetrics {
    logical_bytes: AtomicU64,
    physical_bytes: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    opens: AtomicU64,
    evictions: AtomicU64,
}

impl ReaderManager {
    fn open_file(&self, path: &Path) -> io::Result<Arc<FileSource>> {
        let metadata = std::fs::metadata(path)?;
        let preliminary_identity = file_identity(path, &metadata);
        {
            let files = self
                .files
                .lock()
                .map_err(|_| io::Error::other("reader manager file lock poisoned"))?;
            if let Some(existing) = files.get(&preliminary_identity).and_then(Weak::upgrade) {
                return Ok(existing);
            }
        }
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let identity = file_identity(path, &metadata);
        let mut files = self
            .files
            .lock()
            .map_err(|_| io::Error::other("reader manager file lock poisoned"))?;
        if let Some(existing) = files.get(&identity).and_then(Weak::upgrade) {
            return Ok(existing);
        }
        let source = Arc::new(FileSource {
            identity: identity.clone(),
            file,
            block_loads: Mutex::new(HashMap::new()),
        });
        files.retain(|_, value| value.strong_count() > 0);
        files.insert(identity, Arc::downgrade(&source));
        self.metrics.opens.fetch_add(1, Ordering::Relaxed);
        Ok(source)
    }

    fn read_block(&self, source: &FileSource, index: u64) -> io::Result<Arc<[u8]>> {
        let key = BlockKey {
            identity: source.identity.clone(),
            index,
        };
        {
            let cache = self
                .cache
                .lock()
                .map_err(|_| io::Error::other("shared reader cache lock poisoned"))?;
            if let Some(block) = cache.entries.get(&key) {
                self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(Arc::clone(block));
            }
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
        {
            let cache = self
                .cache
                .lock()
                .map_err(|_| io::Error::other("shared reader cache lock poisoned"))?;
            if let Some(block) = cache.entries.get(&key) {
                self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(Arc::clone(block));
            }
        }
        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
        let offset = index * BLOCK_SIZE as u64;
        let len = BLOCK_SIZE.min(source.len().saturating_sub(offset) as usize);
        let data: Arc<[u8]> = Arc::from(read_file_at(&source.file, offset, len, &self.metrics)?);
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| io::Error::other("shared reader cache lock poisoned"))?;
        if let Some(existing) = cache.entries.get(&key) {
            return Ok(Arc::clone(existing));
        }
        cache.size += data.len();
        cache.entries.insert(key.clone(), Arc::clone(&data));
        cache.order.push_back(key);
        while cache.size > cache.capacity {
            let Some(old_key) = cache.order.pop_front() else {
                break;
            };
            if let Some(old) = cache.entries.remove(&old_key) {
                cache.size = cache.size.saturating_sub(old.len());
                self.metrics.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
        drop(cache);
        drop(_load);
        if let Ok(mut loads) = source.block_loads.lock() {
            loads.remove(&index);
        }
        Ok(data)
    }
}

fn manager() -> &'static ReaderManager {
    static MANAGER: OnceLock<ReaderManager> = OnceLock::new();
    MANAGER.get_or_init(|| ReaderManager {
        files: Mutex::new(HashMap::new()),
        cache: Mutex::new(SharedCache {
            entries: HashMap::new(),
            order: VecDeque::new(),
            size: 0,
            capacity: DEFAULT_SHARED_CACHE_BYTES,
        }),
        metrics: ManagerMetrics::default(),
    })
}

fn file_identity(path: &Path, metadata: &Metadata) -> FileIdentity {
    FileIdentity {
        path: std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()),
        len: metadata.len(),
        modified: metadata.modified().ok(),
        platform_id: platform_file_id(metadata),
    }
}

#[cfg(unix)]
fn platform_file_id(metadata: &Metadata) -> u128 {
    use std::os::unix::fs::MetadataExt;
    ((metadata.dev() as u128) << 64) | metadata.ino() as u128
}

#[cfg(not(unix))]
fn platform_file_id(_metadata: &Metadata) -> u128 {
    0
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
    fn multi_volume_reads_across_boundary() {
        let first = temp_file("managed_reader_part1", b"abc");
        let second = temp_file("managed_reader_part2", b"def");
        let paths = vec![
            first.to_string_lossy().into_owned(),
            second.to_string_lossy().into_owned(),
        ];
        let reader = ManagedReader::open_volumes(&paths, ReaderConfig::default()).unwrap();
        assert_eq!(reader.read_at(2, 3).unwrap(), b"cde");
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
        assert!(manager().cache.lock().unwrap().entries.contains_key(&key));
        let second = manager().open_file(&path).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(second.read_at(2, 4).unwrap(), b"cdef");
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
