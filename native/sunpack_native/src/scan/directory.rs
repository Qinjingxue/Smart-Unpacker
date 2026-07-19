use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use regex::{RegexSet, RegexSetBuilder};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectoryEntryRecord {
    path: String,
    is_dir: bool,
    size: Option<u64>,
    mtime_ns: Option<u64>,
}

#[pyclass(module = "sunpack_native", frozen)]
pub(crate) struct NativeDirectorySnapshot {
    paths: Vec<String>,
    is_dirs: Vec<bool>,
    sizes: Vec<Option<u64>>,
    mtimes_ns: Vec<Option<u64>>,
}

impl NativeDirectorySnapshot {
    fn from_records(records: Vec<DirectoryEntryRecord>) -> Self {
        let mut snapshot = Self {
            paths: Vec::with_capacity(records.len()),
            is_dirs: Vec::with_capacity(records.len()),
            sizes: Vec::with_capacity(records.len()),
            mtimes_ns: Vec::with_capacity(records.len()),
        };
        for record in records {
            snapshot.paths.push(record.path);
            snapshot.is_dirs.push(record.is_dir);
            snapshot.sizes.push(record.size);
            snapshot.mtimes_ns.push(record.mtime_ns);
        }
        snapshot
    }

    pub(crate) fn file_records(&self) -> impl Iterator<Item = (&str, Option<u64>)> {
        self.paths
            .iter()
            .zip(&self.is_dirs)
            .zip(&self.sizes)
            .filter_map(|((path, is_dir), size)| (!is_dir).then_some((path.as_str(), *size)))
    }
}

#[pymethods]
impl NativeDirectorySnapshot {
    fn __len__(&self) -> usize {
        self.paths.len()
    }

    fn __bool__(&self) -> bool {
        !self.paths.is_empty()
    }

    fn has_files(&self) -> bool {
        self.is_dirs.iter().any(|is_dir| !is_dir)
    }

    fn materialize_columns(&self) -> (Vec<String>, Vec<bool>, Vec<Option<u64>>, Vec<Option<u64>>) {
        (
            self.paths.clone(),
            self.is_dirs.clone(),
            self.sizes.clone(),
            self.mtimes_ns.clone(),
        )
    }

    fn file_columns(&self) -> (Vec<String>, Vec<Option<u64>>, Vec<Option<u64>>) {
        let mut paths = Vec::new();
        let mut sizes = Vec::new();
        let mut mtimes_ns = Vec::new();
        for index in 0..self.paths.len() {
            if self.is_dirs[index] {
                continue;
            }
            paths.push(self.paths[index].clone());
            sizes.push(self.sizes[index]);
            mtimes_ns.push(self.mtimes_ns[index]);
        }
        (paths, sizes, mtimes_ns)
    }

    fn file_columns_for_directories(
        &self,
        directories: Vec<String>,
    ) -> (Vec<String>, Vec<Option<u64>>, Vec<Option<u64>>) {
        let directories: HashSet<String> = directories
            .into_iter()
            .map(|directory| directory.to_ascii_lowercase())
            .collect();
        let mut paths = Vec::new();
        let mut sizes = Vec::new();
        let mut mtimes_ns = Vec::new();
        for index in 0..self.paths.len() {
            if self.is_dirs[index] {
                continue;
            }
            let parent = Path::new(&self.paths[index])
                .parent()
                .map(|value| value.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if !directories.contains(&parent) {
                continue;
            }
            paths.push(self.paths[index].clone());
            sizes.push(self.sizes[index]);
            mtimes_ns.push(self.mtimes_ns[index]);
        }
        (paths, sizes, mtimes_ns)
    }

    fn identity_rows(&self) -> Vec<(String, bool, u64, u64)> {
        self.paths
            .iter()
            .zip(&self.is_dirs)
            .zip(&self.sizes)
            .zip(&self.mtimes_ns)
            .map(|(((path, is_dir), size), mtime_ns)| {
                (
                    Path::new(path)
                        .file_name()
                        .map(|name| name.to_string_lossy().to_ascii_lowercase())
                        .unwrap_or_default(),
                    *is_dir,
                    size.unwrap_or(0),
                    mtime_ns.unwrap_or(0),
                )
            })
            .collect()
    }
}

struct DirectoryScanOptions {
    patterns: RegexSet,
    prune_dir_names: HashSet<String>,
    prune_dir_patterns: RegexSet,
    whitelist_rules: Vec<WhitelistRule>,
    blocked_extensions: HashSet<String>,
    blocked_file_names: HashSet<String>,
    size_ranges: Vec<NativeNumericRange>,
    mtime_ranges: Vec<NativeNumericRange>,
}

struct WhitelistRule {
    path_patterns: RegexSet,
    prune_dir_patterns: RegexSet,
    file_patterns: RegexSet,
    allowed_extensions: HashSet<String>,
}

#[derive(Clone, Copy)]
struct NativeNumericRange {
    gt: Option<u64>,
    gte: Option<u64>,
    lt: Option<u64>,
    lte: Option<u64>,
    eq: Option<u64>,
}

type NumericRangeTuple = (
    Option<u64>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
);
type WhitelistRuleTuple = (Vec<String>, Vec<String>, Vec<String>, Vec<String>);

impl NativeNumericRange {
    fn from_tuple(value: NumericRangeTuple) -> Self {
        Self {
            gt: value.0,
            gte: value.1,
            lt: value.2,
            lte: value.3,
            eq: value.4,
        }
    }

    fn allows(&self, value: Option<u64>) -> bool {
        let Some(value) = value else {
            return false;
        };
        self.eq.is_none_or(|expected| value == expected)
            && self.gt.is_none_or(|minimum| value > minimum)
            && self.gte.is_none_or(|minimum| value >= minimum)
            && self.lt.is_none_or(|maximum| value < maximum)
            && self.lte.is_none_or(|maximum| value <= maximum)
    }
}

#[derive(Default)]
struct DirectoryScanProfile {
    directory_enumeration: Duration,
    metadata_reads: Duration,
    path_matching: Duration,
    record_building: Duration,
    traversal_overhead: Duration,
    scan_total: Duration,
    directories_opened: usize,
    entries_seen: usize,
    metadata_read_count: usize,
    accepted_entries: usize,
    pruned_directories: usize,
    rejected_files: usize,
}

#[derive(Clone, Copy)]
enum ProfileBucket {
    DirectoryEnumeration,
    MetadataReads,
    PathMatching,
    RecordBuilding,
    TraversalOverhead,
}

impl DirectoryScanProfile {
    fn add_elapsed(&mut self, bucket: ProfileBucket, started: Instant) {
        let elapsed = started.elapsed();
        match bucket {
            ProfileBucket::DirectoryEnumeration => self.directory_enumeration += elapsed,
            ProfileBucket::MetadataReads => self.metadata_reads += elapsed,
            ProfileBucket::PathMatching => self.path_matching += elapsed,
            ProfileBucket::RecordBuilding => self.record_building += elapsed,
            ProfileBucket::TraversalOverhead => self.traversal_overhead += elapsed,
        }
    }

    fn into_py_dict(
        self,
        py: Python<'_>,
        options_compile: Duration,
        snapshot_building: Duration,
        profiled_call_total: Duration,
    ) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("options_compile_ns", duration_ns(options_compile))?;
        dict.set_item(
            "directory_enumeration_ns",
            duration_ns(self.directory_enumeration),
        )?;
        dict.set_item("metadata_reads_ns", duration_ns(self.metadata_reads))?;
        dict.set_item("path_matching_ns", duration_ns(self.path_matching))?;
        dict.set_item("record_building_ns", duration_ns(self.record_building))?;
        dict.set_item(
            "traversal_overhead_ns",
            duration_ns(self.traversal_overhead),
        )?;
        dict.set_item("scan_total_ns", duration_ns(self.scan_total))?;
        dict.set_item("snapshot_building_ns", duration_ns(snapshot_building))?;
        dict.set_item("profiled_call_total_ns", duration_ns(profiled_call_total))?;
        dict.set_item("directories_opened", self.directories_opened)?;
        dict.set_item("entries_seen", self.entries_seen)?;
        dict.set_item("metadata_read_count", self.metadata_read_count)?;
        dict.set_item("accepted_entries", self.accepted_entries)?;
        dict.set_item("pruned_directories", self.pruned_directories)?;
        dict.set_item("rejected_files", self.rejected_files)?;
        Ok(dict.unbind())
    }
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn measure<const ENABLED: bool, T>(
    profile: &mut Option<&mut DirectoryScanProfile>,
    bucket: ProfileBucket,
    operation: impl FnOnce() -> T,
) -> T {
    if !ENABLED {
        return operation();
    }
    let Some(profile) = profile.as_deref_mut() else {
        return operation();
    };
    let started = Instant::now();
    let result = operation();
    profile.add_elapsed(bucket, started);
    result
}

impl DirectoryEntryRecord {
    fn into_py_dict(self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("path", self.path)?;
        dict.set_item("is_dir", self.is_dir)?;
        dict.set_item("size", self.size)?;
        dict.set_item("mtime_ns", self.mtime_ns)?;
        Ok(dict.unbind())
    }
}

impl DirectoryScanOptions {
    fn new(
        patterns: Vec<String>,
        prune_dir_globs: Vec<String>,
        blocked_extensions: Vec<String>,
        blocked_file_names: Vec<String>,
        size_ranges: Vec<NumericRangeTuple>,
        mtime_ranges: Vec<NumericRangeTuple>,
        whitelist_rules: Vec<WhitelistRuleTuple>,
    ) -> PyResult<Self> {
        let (prune_dir_names, prune_dir_patterns) = compile_prune_dirs(prune_dir_globs)?;
        Ok(Self {
            patterns: compile_case_insensitive_regex_set(patterns)?,
            prune_dir_names,
            prune_dir_patterns,
            whitelist_rules: whitelist_rules
                .into_iter()
                .map(
                    |(path_patterns, prune_dir_patterns, file_patterns, extensions)| {
                        Ok(WhitelistRule {
                            path_patterns: compile_case_insensitive_regex_set(path_patterns)?,
                            prune_dir_patterns: compile_case_insensitive_regex_set(
                                prune_dir_patterns,
                            )?,
                            file_patterns: compile_case_insensitive_regex_set(file_patterns)?,
                            allowed_extensions: normalize_extensions(extensions),
                        })
                    },
                )
                .collect::<PyResult<Vec<_>>>()?,
            blocked_extensions: normalize_extensions(blocked_extensions),
            blocked_file_names: blocked_file_names
                .into_iter()
                .map(|name| name.trim().to_ascii_lowercase())
                .filter(|name| !name.is_empty())
                .collect(),
            size_ranges: size_ranges
                .into_iter()
                .map(NativeNumericRange::from_tuple)
                .collect(),
            mtime_ranges: mtime_ranges
                .into_iter()
                .map(NativeNumericRange::from_tuple)
                .collect(),
        })
    }
}

#[pyfunction]
#[pyo3(signature = (root_path, max_depth, patterns, prune_dir_globs, blocked_extensions, blocked_file_names, size_ranges, mtime_ranges, whitelist_rules))]
pub(crate) fn scan_directory_snapshot(
    py: Python<'_>,
    root_path: &str,
    max_depth: Option<usize>,
    patterns: Vec<String>,
    prune_dir_globs: Vec<String>,
    blocked_extensions: Vec<String>,
    blocked_file_names: Vec<String>,
    size_ranges: Vec<NumericRangeTuple>,
    mtime_ranges: Vec<NumericRangeTuple>,
    whitelist_rules: Vec<WhitelistRuleTuple>,
) -> PyResult<Py<NativeDirectorySnapshot>> {
    let options = DirectoryScanOptions::new(
        patterns,
        prune_dir_globs,
        blocked_extensions,
        blocked_file_names,
        size_ranges,
        mtime_ranges,
        whitelist_rules,
    )?;
    let records = scan_directory(root_path, max_depth, &options)?;
    Py::new(py, NativeDirectorySnapshot::from_records(records))
}

#[pyfunction]
pub(crate) fn directory_snapshot_from_columns(
    py: Python<'_>,
    paths: Vec<String>,
    is_dirs: Vec<bool>,
    sizes: Vec<Option<u64>>,
    mtimes_ns: Vec<Option<u64>>,
) -> PyResult<Py<NativeDirectorySnapshot>> {
    let length = paths.len();
    if is_dirs.len() != length || sizes.len() != length || mtimes_ns.len() != length {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "directory snapshot columns must have equal lengths",
        ));
    }
    Py::new(
        py,
        NativeDirectorySnapshot {
            paths,
            is_dirs,
            sizes,
            mtimes_ns,
        },
    )
}

#[pyfunction]
#[pyo3(signature = (root_path, max_depth, patterns, prune_dir_globs, blocked_extensions, blocked_file_names, size_ranges, mtime_ranges, whitelist_rules))]
pub(crate) fn profile_directory_scan(
    py: Python<'_>,
    root_path: &str,
    max_depth: Option<usize>,
    patterns: Vec<String>,
    prune_dir_globs: Vec<String>,
    blocked_extensions: Vec<String>,
    blocked_file_names: Vec<String>,
    size_ranges: Vec<NumericRangeTuple>,
    mtime_ranges: Vec<NumericRangeTuple>,
    whitelist_rules: Vec<WhitelistRuleTuple>,
) -> PyResult<(Py<NativeDirectorySnapshot>, Py<PyDict>)> {
    let call_started = Instant::now();
    let options_started = Instant::now();
    let options = DirectoryScanOptions::new(
        patterns,
        prune_dir_globs,
        blocked_extensions,
        blocked_file_names,
        size_ranges,
        mtime_ranges,
        whitelist_rules,
    )?;
    let options_compile = options_started.elapsed();

    let mut profile = DirectoryScanProfile::default();
    let entries = scan_directory_impl::<true>(root_path, max_depth, &options, Some(&mut profile))?;

    let snapshot_started = Instant::now();
    let snapshot = Py::new(py, NativeDirectorySnapshot::from_records(entries))?;
    let snapshot_building = snapshot_started.elapsed();
    let profiled_call_total = call_started.elapsed();
    let profile =
        profile.into_py_dict(py, options_compile, snapshot_building, profiled_call_total)?;
    Ok((snapshot, profile))
}

#[pyfunction]
#[pyo3(signature = (root_path, paths, sizes, patterns, prune_dir_globs, blocked_extensions, blocked_file_names, size_ranges, whitelist_rules))]
pub(crate) fn filter_inventory_file_indices(
    root_path: &str,
    paths: Vec<String>,
    sizes: Vec<u64>,
    patterns: Vec<String>,
    prune_dir_globs: Vec<String>,
    blocked_extensions: Vec<String>,
    blocked_file_names: Vec<String>,
    size_ranges: Vec<NumericRangeTuple>,
    whitelist_rules: Vec<WhitelistRuleTuple>,
) -> PyResult<Vec<usize>> {
    let options = DirectoryScanOptions::new(
        patterns,
        prune_dir_globs,
        blocked_extensions,
        blocked_file_names,
        size_ranges,
        Vec::new(),
        whitelist_rules,
    )?;
    let root = PathBuf::from(root_path);
    let mut accepted = Vec::new();
    let mut directory_rejections = HashMap::new();
    for (index, path) in paths.into_iter().enumerate() {
        let size = sizes.get(index).copied().unwrap_or(0);
        let path = PathBuf::from(path);
        if !numeric_ranges_allow(&options.size_ranges, Some(size))
            || file_rejected_by_path(&path, &root, &options)
            || file_under_rejected_directory(&path, &root, &options, &mut directory_rejections)
        {
            continue;
        }
        accepted.push(index);
    }
    Ok(accepted)
}

#[pyfunction]
pub(crate) fn list_regular_files_in_directory(
    py: Python<'_>,
    directory: &str,
) -> PyResult<Vec<Py<PyDict>>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(_) => return Ok(Vec::new()),
    };
    let mut records = Vec::new();
    for item in entries {
        let Ok(entry) = item else {
            continue;
        };
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if !metadata.is_file() {
            continue;
        }
        records.push(DirectoryEntryRecord {
            path: path_to_string(&path),
            is_dir: false,
            size: Some(metadata.len()),
            mtime_ns: metadata_mtime_ns(&metadata),
        });
    }
    records
        .into_iter()
        .map(|entry| entry.into_py_dict(py))
        .collect()
}

#[pyfunction]
#[pyo3(signature = (paths, magic_size=16))]
pub(crate) fn batch_file_head_facts(
    py: Python<'_>,
    paths: Vec<String>,
    magic_size: usize,
) -> PyResult<Vec<Py<PyDict>>> {
    let records = py.detach(|| {
        paths
            .into_iter()
            .map(|path| file_head_record(path, magic_size))
            .collect::<Vec<_>>()
    });
    records
        .into_iter()
        .map(|record| record.into_py_dict(py))
        .collect()
}

#[pyfunction]
pub(crate) fn scan_output_tree(py: Python<'_>, output_dir: &str) -> PyResult<Py<PyDict>> {
    let root = PathBuf::from(output_dir);
    let result = PyDict::new(py);
    result.set_item("exists", root.exists())?;
    result.set_item("is_dir", root.is_dir())?;
    result.set_item("file_count", 0usize)?;
    result.set_item("dir_count", 0usize)?;
    result.set_item("total_size", 0u64)?;
    result.set_item("transient_file_count", 0usize)?;
    result.set_item("unreadable_count", 0usize)?;
    result.set_item("files", PyList::empty(py))?;
    if !root.is_dir() {
        return Ok(result.unbind());
    }

    let mut stats = OutputTreeStats::default();
    walk_output_tree(py, &root, &root, &mut stats)?;
    result.set_item("file_count", stats.file_count)?;
    result.set_item("dir_count", stats.dir_count)?;
    result.set_item("total_size", stats.total_size)?;
    result.set_item("transient_file_count", stats.transient_file_count)?;
    result.set_item("unreadable_count", stats.unreadable_count)?;
    result.set_item("files", PyList::new(py, stats.files)?)?;
    Ok(result.unbind())
}

struct FileHeadRecord {
    path: String,
    exists: bool,
    is_file: bool,
    size: Option<u64>,
    mtime_ns: Option<u64>,
    magic: Vec<u8>,
}

impl FileHeadRecord {
    fn into_py_dict(self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("path", self.path)?;
        dict.set_item("exists", self.exists)?;
        dict.set_item("is_file", self.is_file)?;
        dict.set_item("size", self.size)?;
        dict.set_item("mtime_ns", self.mtime_ns)?;
        dict.set_item("magic", pyo3::types::PyBytes::new(py, &self.magic))?;
        Ok(dict.unbind())
    }
}

fn file_head_record(path: String, magic_size: usize) -> FileHeadRecord {
    let path_buf = PathBuf::from(&path);
    let metadata = fs::metadata(&path_buf).ok();
    let is_file = metadata
        .as_ref()
        .map(|item| item.is_file())
        .unwrap_or(false);
    let mut magic = Vec::new();
    if is_file && magic_size > 0 {
        if let Ok(mut handle) = fs::File::open(&path_buf) {
            let limit = magic_size.min(1024 * 1024);
            let mut buffer = vec![0u8; limit];
            if let Ok(count) = handle.read(&mut buffer) {
                buffer.truncate(count);
                magic = buffer;
            }
        }
    }
    FileHeadRecord {
        path,
        exists: metadata.is_some(),
        is_file,
        size: metadata.as_ref().map(|item| item.len()),
        mtime_ns: metadata.as_ref().and_then(metadata_mtime_ns),
        magic,
    }
}

#[derive(Default)]
struct OutputTreeStats {
    file_count: usize,
    dir_count: usize,
    total_size: u64,
    transient_file_count: usize,
    unreadable_count: usize,
    files: Vec<Py<PyDict>>,
}

fn walk_output_tree(
    py: Python<'_>,
    root: &Path,
    current: &Path,
    stats: &mut OutputTreeStats,
) -> PyResult<()> {
    let entries = match fs::read_dir(current) {
        Ok(entries) => entries,
        Err(_) => {
            stats.unreadable_count += 1;
            return Ok(());
        }
    };
    for item in entries {
        let Ok(entry) = item else {
            stats.unreadable_count += 1;
            continue;
        };
        let path = entry.path();
        let file_name = entry.file_name().to_string_lossy().to_string();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                stats.unreadable_count += 1;
                continue;
            }
        };
        if metadata.is_dir() {
            if file_name == ".sunpack" {
                continue;
            }
            stats.dir_count += 1;
            walk_output_tree(py, root, &path, stats)?;
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        stats.file_count += 1;
        let size = metadata.len();
        stats.total_size = stats.total_size.saturating_add(size);
        if is_transient_file_name(&file_name) {
            stats.transient_file_count += 1;
        }
        let relative = path
            .strip_prefix(root)
            .map(path_to_string)
            .unwrap_or_else(|_| file_name.clone());
        let dict = PyDict::new(py);
        dict.set_item("path", normalize_path_separator(relative))?;
        dict.set_item("abs_path", path_to_string(&path))?;
        dict.set_item("size", size)?;
        stats.files.push(dict.unbind());
    }
    Ok(())
}

fn is_transient_file_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [".tmp", ".temp", ".part", ".partial", ".crdownload"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

fn compile_case_insensitive_regex_set(patterns: Vec<String>) -> PyResult<RegexSet> {
    RegexSetBuilder::new(patterns)
        .case_insensitive(true)
        .build()
        .map_err(|err| pyo3::exceptions::PyValueError::new_err(err.to_string()))
}

fn compile_prune_dirs(patterns: Vec<String>) -> PyResult<(HashSet<String>, RegexSet)> {
    let mut exact_names = HashSet::new();
    let mut wildcard_patterns = Vec::new();
    for pattern in patterns {
        let normalized = pattern
            .trim()
            .replace('\\', "/")
            .trim_matches('/')
            .to_string();
        if normalized.is_empty() {
            continue;
        }
        if normalized.contains('*') || normalized.contains('?') {
            wildcard_patterns.push(directory_glob_regex(&normalized));
        } else {
            exact_names.insert(normalized.to_ascii_lowercase());
        }
    }
    Ok((
        exact_names,
        compile_case_insensitive_regex_set(wildcard_patterns)?,
    ))
}

fn directory_glob_regex(pattern: &str) -> String {
    let mut result = String::from("^");
    for character in pattern.chars() {
        match character {
            '*' => result.push_str("[^/]*"),
            '?' => result.push_str("[^/]"),
            _ => result.push_str(&regex::escape(&character.to_string())),
        }
    }
    result.push('$');
    result
}

fn normalize_extensions(extensions: Vec<String>) -> HashSet<String> {
    extensions
        .into_iter()
        .filter_map(|ext| {
            let ext = ext.trim().to_ascii_lowercase();
            if ext.is_empty() {
                None
            } else if ext.starts_with('.') {
                Some(ext)
            } else {
                Some(format!(".{ext}"))
            }
        })
        .collect()
}

fn scan_directory(
    root_path: &str,
    max_depth: Option<usize>,
    options: &DirectoryScanOptions,
) -> PyResult<Vec<DirectoryEntryRecord>> {
    scan_directory_impl::<false>(root_path, max_depth, options, None)
}

fn scan_directory_impl<const PROFILE: bool>(
    root_path: &str,
    max_depth: Option<usize>,
    options: &DirectoryScanOptions,
    mut profile: Option<&mut DirectoryScanProfile>,
) -> PyResult<Vec<DirectoryEntryRecord>> {
    let scan_started = Instant::now();
    let root = PathBuf::from(root_path);
    if !root.exists() {
        if PROFILE {
            if let Some(profile) = profile.as_deref_mut() {
                profile.scan_total = scan_started.elapsed();
            }
        }
        return Ok(Vec::new());
    }
    if root.is_file() {
        let match_root = root.parent().unwrap_or_else(|| Path::new(""));
        let result = file_record_if_accepted(&root, match_root, options)
            .into_iter()
            .collect();
        if PROFILE {
            if let Some(profile) = profile.as_deref_mut() {
                profile.scan_total = scan_started.elapsed();
            }
        }
        return Ok(result);
    }

    let mut records = Vec::new();
    let mut stack = vec![(root.clone(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let read_dir =
            match measure::<PROFILE, _>(&mut profile, ProfileBucket::DirectoryEnumeration, || {
                fs::read_dir(&dir)
            }) {
                Ok(entries) => entries,
                Err(_) => continue,
            };
        if PROFILE {
            if let Some(profile) = profile.as_deref_mut() {
                profile.directories_opened += 1;
            }
        }
        let mut child_dirs = Vec::new();
        let mut read_dir = read_dir;
        loop {
            let item =
                measure::<PROFILE, _>(&mut profile, ProfileBucket::DirectoryEnumeration, || {
                    read_dir.next()
                });
            let Some(item) = item else {
                break;
            };
            let Ok(entry) = item else {
                continue;
            };
            if PROFILE {
                if let Some(profile) = profile.as_deref_mut() {
                    profile.entries_seen += 1;
                }
            }
            let path =
                measure::<PROFILE, _>(&mut profile, ProfileBucket::DirectoryEnumeration, || {
                    entry.path()
                });
            let metadata =
                match measure::<PROFILE, _>(&mut profile, ProfileBucket::MetadataReads, || {
                    entry.metadata()
                }) {
                    Ok(metadata) => metadata,
                    Err(_) => continue,
                };
            if PROFILE {
                if let Some(profile) = profile.as_deref_mut() {
                    profile.metadata_read_count += 1;
                }
            }

            if metadata.is_dir() {
                let rejected =
                    measure::<PROFILE, _>(&mut profile, ProfileBucket::PathMatching, || {
                        max_depth.is_some_and(|limit| depth >= limit)
                            || dir_rejected(&path, &root, options)
                    });
                if rejected {
                    if PROFILE {
                        if let Some(profile) = profile.as_deref_mut() {
                            profile.pruned_directories += 1;
                        }
                    }
                    continue;
                }
                measure::<PROFILE, _>(&mut profile, ProfileBucket::RecordBuilding, || {
                    records.push(DirectoryEntryRecord {
                        path: path_to_string(&path),
                        is_dir: true,
                        size: None,
                        mtime_ns: None,
                    });
                    child_dirs.push(path);
                });
                if PROFILE {
                    if let Some(profile) = profile.as_deref_mut() {
                        profile.accepted_entries += 1;
                    }
                }
                continue;
            }

            let size = metadata.len();
            let mtime_ns = metadata_mtime_ns(&metadata);
            let rejected = measure::<PROFILE, _>(&mut profile, ProfileBucket::PathMatching, || {
                !metadata.is_file()
                    || file_rejected_by_path(&path, &root, options)
                    || !numeric_ranges_allow(&options.size_ranges, Some(size))
                    || !numeric_ranges_allow(&options.mtime_ranges, mtime_ns)
            });
            if rejected {
                if PROFILE {
                    if let Some(profile) = profile.as_deref_mut() {
                        profile.rejected_files += 1;
                    }
                }
                continue;
            }
            measure::<PROFILE, _>(&mut profile, ProfileBucket::RecordBuilding, || {
                records.push(DirectoryEntryRecord {
                    path: path_to_string(&path),
                    is_dir: false,
                    size: Some(size),
                    mtime_ns,
                });
            });
            if PROFILE {
                if let Some(profile) = profile.as_deref_mut() {
                    profile.accepted_entries += 1;
                }
            }
        }

        measure::<PROFILE, _>(&mut profile, ProfileBucket::TraversalOverhead, || {
            child_dirs.sort();
            for child in child_dirs.into_iter().rev() {
                stack.push((child, depth + 1));
            }
        });
    }
    if PROFILE {
        if let Some(profile) = profile.as_deref_mut() {
            profile.scan_total = scan_started.elapsed();
        }
    }
    Ok(records)
}

fn file_record_if_accepted(
    path: &Path,
    root: &Path,
    options: &DirectoryScanOptions,
) -> Option<DirectoryEntryRecord> {
    if file_rejected_by_path(path, root, options) {
        return None;
    }
    let metadata = fs::metadata(path).ok()?;
    let size = metadata.len();
    let mtime_ns = metadata_mtime_ns(&metadata);
    if !numeric_ranges_allow(&options.size_ranges, Some(size))
        || !numeric_ranges_allow(&options.mtime_ranges, mtime_ns)
    {
        return None;
    }
    Some(DirectoryEntryRecord {
        path: path_to_string(path),
        is_dir: false,
        size: Some(size),
        mtime_ns,
    })
}

fn dir_rejected(path: &Path, root: &Path, options: &DirectoryScanOptions) -> bool {
    let name = normalized_file_name(path);
    if options.prune_dir_names.contains(&name) || options.prune_dir_patterns.is_match(&name) {
        return true;
    }
    let candidates = path_candidates(path, root);
    regex_set_matches(&options.patterns, &candidates)
        || !dir_allowed_by_whitelist(&candidates, options)
}

fn file_rejected_by_path(path: &Path, root: &Path, options: &DirectoryScanOptions) -> bool {
    if options
        .blocked_file_names
        .contains(&normalized_file_name(path))
    {
        return true;
    }
    if let Some(ext) = path.extension().and_then(|value| value.to_str()) {
        let ext = format!(".{}", ext.to_ascii_lowercase());
        if options.blocked_extensions.contains(&ext) {
            return true;
        }
    }
    let candidates = path_candidates(path, root);
    regex_set_matches(&options.patterns, &candidates)
        || !file_allowed_by_whitelist(path, &candidates, options)
}

fn file_under_rejected_directory(
    path: &Path,
    root: &Path,
    options: &DirectoryScanOptions,
    cache: &mut HashMap<PathBuf, bool>,
) -> bool {
    path.parent()
        .is_some_and(|directory| directory_rejected_cached(directory, root, options, cache))
}

fn directory_rejected_cached(
    directory: &Path,
    root: &Path,
    options: &DirectoryScanOptions,
    cache: &mut HashMap<PathBuf, bool>,
) -> bool {
    if directory == root {
        return false;
    }
    if !directory.starts_with(root) {
        return true;
    }
    if let Some(rejected) = cache.get(directory) {
        return *rejected;
    }
    let rejected = directory
        .parent()
        .is_some_and(|parent| directory_rejected_cached(parent, root, options, cache))
        || dir_rejected(directory, root, options);
    cache.insert(directory.to_path_buf(), rejected);
    rejected
}

fn dir_allowed_by_whitelist(candidates: &[String], options: &DirectoryScanOptions) -> bool {
    options.whitelist_rules.iter().all(|rule| {
        regex_field_allows(&rule.path_patterns, candidates)
            && regex_field_allows(&rule.prune_dir_patterns, candidates)
    })
}

fn file_allowed_by_whitelist(
    path: &Path,
    candidates: &[String],
    options: &DirectoryScanOptions,
) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!(".{}", value.to_ascii_lowercase()));
    options.whitelist_rules.iter().all(|rule| {
        regex_field_allows(&rule.path_patterns, candidates)
            && regex_field_allows(&rule.file_patterns, candidates)
            && (rule.allowed_extensions.is_empty()
                || extension
                    .as_ref()
                    .is_some_and(|ext| rule.allowed_extensions.contains(ext)))
    })
}

fn regex_field_allows(regexes: &RegexSet, candidates: &[String]) -> bool {
    regexes.is_empty() || regex_set_matches(regexes, candidates)
}

fn numeric_ranges_allow(ranges: &[NativeNumericRange], value: Option<u64>) -> bool {
    ranges.iter().all(|range| range.allows(value))
}

fn regex_set_matches(regexes: &RegexSet, candidates: &[String]) -> bool {
    candidates
        .iter()
        .any(|candidate| regexes.is_match(candidate))
}

fn normalized_file_name(path: &Path) -> String {
    path.file_name()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

fn path_candidates(path: &Path, root: &Path) -> Vec<String> {
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_default();
    let relative = path
        .strip_prefix(root)
        .map(path_to_string)
        .unwrap_or_else(|_| name.clone());
    vec![name, normalize_path_separator(relative)]
}

fn normalize_path_separator(path: String) -> String {
    path.replace('\\', "/")
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn metadata_mtime_ns(metadata: &fs::Metadata) -> Option<u64> {
    let modified = metadata.modified().ok()?;
    let duration = modified.duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(duration.as_nanos()).ok()
}
