use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
struct SceneEntryIndex {
    path_keys: HashSet<String>,
    files_by_parent: HashMap<String, HashSet<String>>,
    dirs_by_parent: HashMap<String, HashSet<String>>,
    dirs_by_key: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
struct SceneRule {
    scene_type: String,
    top_level_dir_markers: HashMap<String, String>,
    top_level_file_markers: HashMap<String, String>,
    top_level_glob_markers: Vec<(String, String)>,
    nested_path_markers: HashMap<String, String>,
    match_variants: Vec<SceneVariant>,
    weak_match_variants: Vec<SceneVariant>,
}

#[derive(Debug, Clone, Default)]
struct SceneVariant {
    all_of: HashSet<String>,
    any_of: HashSet<String>,
}

#[derive(Debug, Clone)]
struct SceneContext {
    scene_type: String,
}

#[pyfunction]
#[pyo3(signature = (root_path, entries, rules, prune_dir_globs=Vec::new()))]
pub(crate) fn scene_semantics_filter_entries(
    root_path: &str,
    entries: Vec<Bound<'_, PyDict>>,
    rules: Vec<Bound<'_, PyDict>>,
    prune_dir_globs: Vec<String>,
) -> PyResult<Vec<String>> {
    let rules = parse_rules(rules)?;
    let prune_dir_globs = prune_dir_globs
        .into_iter()
        .filter_map(|item| {
            let item = normalize_relative(&item).to_ascii_lowercase();
            if item.is_empty() {
                None
            } else {
                Some(item)
            }
        })
        .collect::<Vec<_>>();
    let (index, original_paths) = build_index(root_path, entries, &prune_dir_globs)?;
    let scene_roots = detect_scene_roots(&index, &rules);
    let root_keys = scene_roots;
    Ok(original_paths
        .into_iter()
        .filter(|path| !is_under_or_same_scene_root(&path_key(path), &root_keys))
        .collect())
}

fn parse_rules(rules: Vec<Bound<'_, PyDict>>) -> PyResult<Vec<SceneRule>> {
    let mut parsed = Vec::new();
    for rule in rules {
        parsed.push(SceneRule {
            scene_type: get_string(&rule, "scene_type")?.unwrap_or_else(|| "generic".to_string()),
            top_level_dir_markers: get_string_map(&rule, "top_level_dir_markers")?
                .into_iter()
                .map(|(key, value)| (key.to_ascii_lowercase(), value))
                .collect(),
            top_level_file_markers: get_string_map(&rule, "top_level_file_markers")?
                .into_iter()
                .map(|(key, value)| (key.to_ascii_lowercase(), value))
                .collect(),
            top_level_glob_markers: get_glob_markers(&rule, "top_level_glob_markers")?,
            nested_path_markers: get_string_map(&rule, "nested_path_markers")?
                .into_iter()
                .map(|(key, value)| (normalize_relative(&key).to_ascii_lowercase(), value))
                .collect(),
            match_variants: get_variants(&rule, "match_variants")?,
            weak_match_variants: get_variants(&rule, "weak_match_variants")?,
        });
    }
    Ok(parsed)
}

fn build_index(
    root_path: &str,
    entries: Vec<Bound<'_, PyDict>>,
    prune_dir_globs: &[String],
) -> PyResult<(SceneEntryIndex, Vec<String>)> {
    let root_path = normalize_path(root_path);
    let root_key = path_key(&root_path);
    let mut index = SceneEntryIndex {
        path_keys: HashSet::new(),
        files_by_parent: HashMap::new(),
        dirs_by_parent: HashMap::new(),
        dirs_by_key: HashMap::from([(root_key, root_path.clone())]),
    };
    let mut original_paths = Vec::new();

    for row in entries {
        let Some(path) = get_string(&row, "path")? else {
            continue;
        };
        let path = normalize_path(&path);
        original_paths.push(path.clone());
        if is_under_pruned_scene_dir(&path, &root_path, prune_dir_globs) {
            continue;
        }
        let key = path_key(&path);
        let parent = parent_path(&path);
        let parent_key = path_key(&parent);
        let name = basename(&path).to_ascii_lowercase();
        let is_dir = get_bool(&row, "is_dir")?.unwrap_or(false);
        index.path_keys.insert(key.clone());
        if is_dir {
            index
                .dirs_by_parent
                .entry(parent_key)
                .or_default()
                .insert(name);
            index.dirs_by_key.insert(key, path);
        } else {
            index
                .files_by_parent
                .entry(parent_key)
                .or_default()
                .insert(name);
        }
    }
    Ok((index, original_paths))
}

fn is_under_pruned_scene_dir(path: &str, root_path: &str, prune_dir_globs: &[String]) -> bool {
    if prune_dir_globs.is_empty() {
        return false;
    }
    let Some(rel_path) = relative_to(path, root_path) else {
        return false;
    };
    for part in normalize_relative(&rel_path)
        .to_ascii_lowercase()
        .split('/')
        .filter(|part| !part.is_empty())
    {
        if prune_dir_globs
            .iter()
            .any(|pattern| wildcard_match(pattern, part))
        {
            return true;
        }
    }
    false
}

fn collect_markers_for_directory(
    index: &SceneEntryIndex,
    directory_key: &str,
    rules: &[SceneRule],
) -> HashSet<String> {
    let mut markers = HashSet::new();
    let empty = HashSet::new();
    let top_level_dirs = index.dirs_by_parent.get(directory_key).unwrap_or(&empty);
    let top_level_files = index.files_by_parent.get(directory_key).unwrap_or(&empty);
    let top_level_exes: HashSet<&String> = top_level_files
        .iter()
        .filter(|name| name.ends_with(".exe"))
        .collect();

    for rule in rules {
        for name in top_level_dirs {
            if let Some(marker) = rule.top_level_dir_markers.get(name) {
                markers.insert(marker.clone());
            }
        }
        for name in top_level_files {
            if let Some(marker) = rule.top_level_file_markers.get(name) {
                markers.insert(marker.clone());
            }
            for (pattern, marker) in &rule.top_level_glob_markers {
                if wildcard_match(pattern, name) {
                    markers.insert(marker.clone());
                }
            }
        }
        for (rel_path, marker) in &rule.nested_path_markers {
            let nested_key = join_key(directory_key, rel_path);
            if index.path_keys.contains(&nested_key) {
                markers.insert(marker.clone());
            }
        }
    }

    if top_level_dirs.contains("www") {
        let www_key = join_key(directory_key, "www");
        let www_child_dirs = index.dirs_by_parent.get(&www_key).unwrap_or(&empty);
        let runtime_dirs = ["js", "data", "img", "audio", "fonts", "movies"];
        let present = runtime_dirs
            .iter()
            .filter(|name| www_child_dirs.contains(**name))
            .count();
        if present >= 2 {
            markers.insert(if top_level_exes.is_empty() {
                "www_runtime_layout".to_string()
            } else {
                "runtime_exe".to_string()
            });
        }
        for (dirname, marker) in [
            ("js", "js_dir"),
            ("data", "data_dir"),
            ("img", "img_dir"),
            ("audio", "audio_dir"),
            ("fonts", "fonts_dir"),
        ] {
            if www_child_dirs.contains(dirname) {
                markers.insert(marker.to_string());
            }
        }
    }
    if !top_level_exes.is_empty() {
        markers.insert("runtime_exe".to_string());
    }
    if top_level_dirs.contains("resources") && !top_level_exes.is_empty() {
        markers.insert("electron_runtime_layout".to_string());
    }
    if top_level_files.contains("package.nw") && !top_level_exes.is_empty() {
        markers.insert("nwjs_runtime_layout".to_string());
    }
    if top_level_dirs.contains("game")
        && (top_level_dirs.contains("renpy") || top_level_dirs.contains("lib"))
    {
        markers.insert("renpy_runtime_layout".to_string());
    }
    if !top_level_exes.is_empty() && top_level_files.iter().any(|name| name.ends_with(".pck")) {
        markers.insert("godot_runtime_layout".to_string());
    }
    markers
}

fn detect_scene_roots(index: &SceneEntryIndex, rules: &[SceneRule]) -> Vec<String> {
    let mut directory_keys = index.dirs_by_key.keys().cloned().collect::<Vec<_>>();
    directory_keys.sort_by_key(|key| (key.matches('/').count(), key.clone()));

    let mut roots: Vec<String> = Vec::new();
    for directory_key in directory_keys {
        if roots
            .iter()
            .any(|root_key| directory_key != *root_key && directory_key.starts_with(&format!("{root_key}/")))
        {
            continue;
        }

        let mut markers = collect_markers_for_directory(index, &directory_key, rules)
            .into_iter()
            .collect::<Vec<_>>();
        markers.sort();
        let context = context_from_markers(&markers, rules);
        if context.scene_type != "generic" {
            roots.push(directory_key);
        }
    }
    roots
}

fn is_under_or_same_scene_root(path_key: &str, root_keys: &[String]) -> bool {
    root_keys
        .iter()
        .any(|root_key| path_key == root_key || path_key.starts_with(&format!("{root_key}/")))
}

fn context_from_markers(markers: &[String], rules: &[SceneRule]) -> SceneContext {
    let marker_set: HashSet<String> = markers.iter().cloned().collect();
    for rule in rules {
        if rule
            .match_variants
            .iter()
            .any(|variant| variant_matches(&marker_set, variant))
        {
            return SceneContext {
                scene_type: rule.scene_type.clone(),
            };
        }
    }
    for rule in rules {
        if rule
            .weak_match_variants
            .iter()
            .any(|variant| variant_matches(&marker_set, variant))
        {
            return SceneContext {
                scene_type: rule.scene_type.clone(),
            };
        }
    }
    SceneContext {
        scene_type: "generic".to_string(),
    }
}

fn variant_matches(markers: &HashSet<String>, variant: &SceneVariant) -> bool {
    (variant.all_of.is_empty() || variant.all_of.is_subset(markers))
        && (variant.any_of.is_empty() || !variant.any_of.is_disjoint(markers))
}

fn get_string(row: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    Ok(row
        .get_item(key)?
        .and_then(|value| value.extract::<String>().ok()))
}

fn get_bool(row: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<bool>> {
    Ok(row
        .get_item(key)?
        .and_then(|value| value.extract::<bool>().ok()))
}

fn get_string_list(row: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<String>> {
    Ok(row
        .get_item(key)?
        .and_then(|value| value.extract::<Vec<String>>().ok())
        .unwrap_or_default())
}

fn get_string_map(row: &Bound<'_, PyDict>, key: &str) -> PyResult<HashMap<String, String>> {
    Ok(row
        .get_item(key)?
        .and_then(|value| value.extract::<HashMap<String, String>>().ok())
        .unwrap_or_default())
}

fn get_variants(row: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<SceneVariant>> {
    let Some(value) = row.get_item(key)? else {
        return Ok(Vec::new());
    };
    let Ok(items) = value.cast::<PyList>() else {
        return Ok(Vec::new());
    };
    let mut variants = Vec::new();
    for item in items.iter() {
        let Ok(dict) = item.cast::<PyDict>() else {
            continue;
        };
        variants.push(SceneVariant {
            all_of: get_string_list(dict, "all_of")?.into_iter().collect(),
            any_of: get_string_list(dict, "any_of")?.into_iter().collect(),
        });
    }
    Ok(variants)
}

fn get_glob_markers(row: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<(String, String)>> {
    let Some(value) = row.get_item(key)? else {
        return Ok(Vec::new());
    };
    let Ok(items) = value.cast::<PyList>() else {
        return Ok(Vec::new());
    };
    let mut markers = Vec::new();
    for item in items.iter() {
        if let Ok(pair) = item.extract::<(String, String)>() {
            markers.push((normalize_relative(&pair.0).to_ascii_lowercase(), pair.1));
            continue;
        }
        let Ok(list) = item.cast::<PyList>() else {
            continue;
        };
        if list.len() < 2 {
            continue;
        }
        let pattern = list.get_item(0)?.extract::<String>()?;
        let marker = list.get_item(1)?.extract::<String>()?;
        markers.push((normalize_relative(&pattern).to_ascii_lowercase(), marker));
    }
    Ok(markers)
}

fn normalize_path(value: &str) -> String {
    let mut value = value.replace('\\', "/");
    while value.len() > 3 && value.ends_with('/') {
        value.pop();
    }
    value
}

fn normalize_relative(value: &str) -> String {
    value
        .replace('\\', "/")
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>()
        .join("/")
}

fn path_key(value: &str) -> String {
    normalize_path(value).to_ascii_lowercase()
}

fn parent_path(value: &str) -> String {
    let value = normalize_path(value);
    if let Some(index) = value.rfind('/') {
        if index == 2 && value.as_bytes().get(1) == Some(&b':') {
            return value[..3].to_string();
        }
        return value[..index].to_string();
    }
    value
}

fn basename(value: &str) -> String {
    normalize_path(value)
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_string()
}

fn join_key(base_key: &str, rel_path: &str) -> String {
    let rel = normalize_relative(rel_path).to_ascii_lowercase();
    if rel.is_empty() {
        base_key.to_string()
    } else {
        format!("{}/{}", base_key.trim_end_matches('/'), rel)
    }
}

fn relative_to(path: &str, root: &str) -> Option<String> {
    let path_norm = normalize_path(path);
    let root_norm = normalize_path(root);
    let path_norm_key = path_key(&path_norm);
    let root_norm_key = path_key(&root_norm);
    if path_norm_key == root_norm_key {
        return Some(String::new());
    }
    let prefix = format!("{root_norm_key}/");
    if !path_norm_key.starts_with(&prefix) {
        return None;
    }
    let prefix_len = root_norm.len().saturating_add(1);
    path_norm.get(prefix_len..).map(|item| item.to_string())
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    wildcard_match_bytes(pattern.as_bytes(), value.as_bytes())
}

fn wildcard_match_bytes(pattern: &[u8], value: &[u8]) -> bool {
    let (mut p, mut v) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_value = 0usize;
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            star_value = v;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            star_value += 1;
            v = star_value;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}
