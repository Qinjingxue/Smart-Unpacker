use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

const WATCH_ARCHIVE_SUFFIXES: &[&str] = &[
    ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".zst", ".tar", ".tgz", ".tbz", ".tbz2", ".txz",
    ".tzst", ".001", ".exe",
];

#[pyfunction]
#[pyo3(signature = (roots, recursive=true))]
pub(crate) fn scan_watch_candidates(
    py: Python<'_>,
    roots: Vec<String>,
    recursive: bool,
) -> PyResult<Py<PyList>> {
    let mut candidates: Vec<(String, Py<PyDict>)> = Vec::new();
    for root in roots {
        let path = PathBuf::from(root);
        if path.is_file() {
            if let Some(candidate) = watch_candidate_dict(py, &path)? {
                candidates.push((normalize_path(&path), candidate));
            }
            continue;
        }
        if !path.is_dir() {
            continue;
        }
        if recursive {
            scan_watch_dir_recursive(py, &path, &mut candidates)?;
        } else {
            scan_watch_dir_shallow(py, &path, &mut candidates)?;
        }
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    let values = candidates
        .into_iter()
        .map(|(_, candidate)| candidate)
        .collect::<Vec<_>>();
    Ok(PyList::new(py, values)?.unbind())
}

#[pyfunction]
pub(crate) fn watch_candidate_for_path(py: Python<'_>, path: &str) -> PyResult<Option<Py<PyDict>>> {
    watch_candidate_dict(py, Path::new(path))
}

#[pyfunction]
pub(crate) fn flatten_single_branch_directories(
    py: Python<'_>,
    base: &str,
) -> PyResult<Py<PyDict>> {
    let base_path = PathBuf::from(base);
    let result = PyDict::new(py);
    result.set_item("moved", 0usize)?;
    result.set_item("removed_dirs", 0usize)?;
    result.set_item("errors", PyList::empty(py))?;
    if !base_path.is_dir() {
        return Ok(result.unbind());
    }

    let mut stats = FlattenStats::default();
    flatten_dir_bottom_up(&base_path, &mut stats);
    result.set_item("moved", stats.moved)?;
    result.set_item("removed_dirs", stats.removed_dirs)?;
    result.set_item("errors", PyList::new(py, stats.errors)?)?;
    Ok(result.unbind())
}

#[pyfunction]
pub(crate) fn delete_files_batch(py: Python<'_>, paths: Vec<String>) -> PyResult<Py<PyList>> {
    let results = PyList::empty(py);
    for raw in paths {
        let path = PathBuf::from(&raw);
        let item = PyDict::new(py);
        item.set_item("path", normalize_path(&path))?;
        item.set_item(
            "filename",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(""),
        )?;
        if !path.exists() {
            item.set_item("status", "missing")?;
            item.set_item("error", "")?;
        } else {
            match fs::remove_file(&path) {
                Ok(()) => {
                    item.set_item("status", "deleted")?;
                    item.set_item("error", "")?;
                }
                Err(error) => {
                    item.set_item("status", "error")?;
                    item.set_item("error", error.to_string())?;
                }
            }
        }
        results.append(item)?;
    }
    Ok(results.unbind())
}

fn scan_watch_dir_recursive(
    py: Python<'_>,
    root: &Path,
    candidates: &mut Vec<(String, Py<PyDict>)>,
) -> PyResult<()> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.is_dir() {
            scan_watch_dir_recursive(py, &path, candidates)?;
        } else if metadata.is_file() {
            if let Some(candidate) = watch_candidate_from_metadata(py, &path, &metadata)? {
                candidates.push((normalize_path(&path), candidate));
            }
        }
    }
    Ok(())
}

fn scan_watch_dir_shallow(
    py: Python<'_>,
    root: &Path,
    candidates: &mut Vec<(String, Py<PyDict>)>,
) -> PyResult<()> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.is_file() {
            if let Some(candidate) = watch_candidate_from_metadata(py, &path, &metadata)? {
                candidates.push((normalize_path(&path), candidate));
            }
        }
    }
    Ok(())
}

fn watch_candidate_dict(py: Python<'_>, path: &Path) -> PyResult<Option<Py<PyDict>>> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !looks_like_archive_name(&file_name) {
        return Ok(None);
    }
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(None),
    };
    if !metadata.is_file() {
        return Ok(None);
    }
    watch_candidate_from_metadata(py, path, &metadata)
}

fn watch_candidate_from_metadata(
    py: Python<'_>,
    path: &Path,
    metadata: &fs::Metadata,
) -> PyResult<Option<Py<PyDict>>> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !looks_like_archive_name(&file_name) {
        return Ok(None);
    }
    if metadata.len() == 0 {
        return Ok(None);
    }
    let dict = PyDict::new(py);
    dict.set_item("path", normalize_path(path))?;
    dict.set_item("size", metadata.len())?;
    dict.set_item("mtime", mtime_seconds(metadata))?;
    Ok(Some(dict.unbind()))
}

fn looks_like_archive_name(name: &str) -> bool {
    WATCH_ARCHIVE_SUFFIXES
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

#[derive(Default)]
struct FlattenStats {
    moved: usize,
    removed_dirs: usize,
    errors: Vec<String>,
}

fn flatten_dir_bottom_up(root: &Path, stats: &mut FlattenStats) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            flatten_dir_bottom_up(&path, stats);
        }
    }
    flatten_single_branch(root, stats);
}

fn flatten_single_branch(root: &Path, stats: &mut FlattenStats) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let mut dirs = Vec::new();
    let mut files = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.metadata() {
            Ok(metadata) if metadata.is_dir() => dirs.push(path),
            Ok(metadata) if metadata.is_file() => files += 1,
            _ => {}
        }
    }
    if dirs.len() != 1 || files != 0 {
        return;
    }
    let child = dirs.remove(0);
    let Ok(child_entries) = fs::read_dir(&child) else {
        return;
    };
    for entry in child_entries.flatten() {
        let src = entry.path();
        let Some(name) = src.file_name() else {
            continue;
        };
        let dst = unique_destination(root, name);
        match fs::rename(&src, &dst) {
            Ok(()) => stats.moved += 1,
            Err(error) => stats.errors.push(format!(
                "{} -> {}: {}",
                normalize_path(&src),
                normalize_path(&dst),
                error
            )),
        }
    }
    match fs::remove_dir(&child) {
        Ok(()) => stats.removed_dirs += 1,
        Err(error) => stats
            .errors
            .push(format!("{}: {}", normalize_path(&child), error)),
    }
}

fn unique_destination(root: &Path, name: &std::ffi::OsStr) -> PathBuf {
    let direct = root.join(name);
    if !direct.exists() {
        return direct;
    }
    let path = Path::new(name);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("item");
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    for count in 1usize.. {
        let candidate_name = if extension.is_empty() {
            format!("{stem} ({count})")
        } else {
            format!("{stem} ({count}).{extension}")
        };
        let candidate = root.join(candidate_name);
        if !candidate.exists() {
            return candidate;
        }
    }
    direct
}

fn normalize_path(path: &Path) -> String {
    let text = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string();
    normalize_windows_extended_prefix(text)
}

fn normalize_windows_extended_prefix(path: String) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    if let Some(rest) = path.strip_prefix(r"\\?\") {
        return rest.to_string();
    }
    path
}

fn mtime_seconds(metadata: &fs::Metadata) -> f64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}
