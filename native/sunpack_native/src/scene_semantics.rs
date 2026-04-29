use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
struct SceneEntryIndex {
    path_keys: HashSet<String>,
    files_by_parent: HashMap<String, HashSet<String>>,
    dirs_by_parent: HashMap<String, HashSet<String>>,
    dirs_by_key: HashMap<String, String>,
    files: Vec<String>,
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
    protected_prefixes: Vec<String>,
    protected_exact_paths: HashSet<String>,
    protected_archive_exts: HashSet<String>,
    runtime_exact_paths: HashSet<String>,
    runtime_glob_paths: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct SceneVariant {
    all_of: HashSet<String>,
    any_of: HashSet<String>,
}

#[derive(Debug, Clone)]
struct SceneContext {
    target_dir: String,
    scene_type: String,
    match_strength: String,
    markers: Vec<String>,
}

#[pyfunction]
#[pyo3(signature = (root_path, entries, rules, prune_dir_globs=Vec::new()))]
pub(crate) fn scene_semantics_payloads(
    py: Python<'_>,
    root_path: &str,
    entries: Vec<Bound<'_, PyDict>>,
    rules: Vec<Bound<'_, PyDict>>,
    prune_dir_globs: Vec<String>,
) -> PyResult<Py<PyDict>> {
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
    let index = build_index(root_path, entries, &prune_dir_globs)?;
    let result = PyDict::new(py);
    let active_scene_by_dir = detect_active_scene_contexts(&index, &rules);

    for file_path in &index.files {
        let parent_key = path_key(&parent_path(file_path));
        let Some(context) = active_scene_by_dir.get(&parent_key) else {
            continue;
        };
        if let Some(payload) = scene_payload(py, file_path, context, &rules)? {
            result.set_item(file_path, payload)?;
        }
    }
    Ok(result.unbind())
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
            protected_prefixes: get_string_list(&rule, "protected_prefixes")?
                .into_iter()
                .map(|item| normalize_relative(&item).to_ascii_lowercase())
                .collect(),
            protected_exact_paths: get_string_list(&rule, "protected_exact_paths")?
                .into_iter()
                .map(|item| normalize_relative(&item).to_ascii_lowercase())
                .collect(),
            protected_archive_exts: get_string_list(&rule, "protected_archive_exts")?
                .into_iter()
                .map(|item| normalize_extension(&item))
                .filter(|item| !item.is_empty())
                .collect(),
            runtime_exact_paths: get_string_list(&rule, "runtime_exact_paths")?
                .into_iter()
                .map(|item| normalize_relative(&item).to_ascii_lowercase())
                .collect(),
            runtime_glob_paths: get_string_list(&rule, "runtime_glob_paths")?
                .into_iter()
                .map(|item| normalize_relative(&item).to_ascii_lowercase())
                .collect(),
        });
    }
    Ok(parsed)
}

fn build_index(
    root_path: &str,
    entries: Vec<Bound<'_, PyDict>>,
    prune_dir_globs: &[String],
) -> PyResult<SceneEntryIndex> {
    let root_path = normalize_path(root_path);
    let root_key = path_key(&root_path);
    let mut index = SceneEntryIndex {
        path_keys: HashSet::new(),
        files_by_parent: HashMap::new(),
        dirs_by_parent: HashMap::new(),
        dirs_by_key: HashMap::from([(root_key, root_path.clone())]),
        files: Vec::new(),
    };

    for row in entries {
        let Some(path) = get_string(&row, "path")? else {
            continue;
        };
        let path = normalize_path(&path);
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
            index.files.push(path);
        }
    }
    Ok(index)
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

fn detect_active_scene_contexts(
    index: &SceneEntryIndex,
    rules: &[SceneRule],
) -> HashMap<String, SceneContext> {
    let mut directory_keys = index.dirs_by_key.keys().cloned().collect::<Vec<_>>();
    directory_keys.sort_by_key(|key| (key.matches('/').count(), key.clone()));

    let mut active: HashMap<String, SceneContext> = HashMap::new();
    for directory_key in directory_keys {
        let mut markers = collect_markers_for_directory(index, &directory_key, rules)
            .into_iter()
            .collect::<Vec<_>>();
        markers.sort();
        let target_dir = index
            .dirs_by_key
            .get(&directory_key)
            .cloned()
            .unwrap_or_else(|| directory_key.clone());
        let context = context_from_markers(target_dir, &markers, rules);
        if context.scene_type != "generic" {
            active.insert(directory_key, context);
            continue;
        }
        let parent_key = parent_path(&directory_key);
        if let Some(parent_context) = active.get(&parent_key).cloned() {
            active.insert(directory_key, parent_context);
        }
    }
    active
}

fn context_from_markers(target_dir: String, markers: &[String], rules: &[SceneRule]) -> SceneContext {
    let marker_set: HashSet<String> = markers.iter().cloned().collect();
    for rule in rules {
        if rule
            .match_variants
            .iter()
            .any(|variant| variant_matches(&marker_set, variant))
        {
            return SceneContext {
                target_dir,
                scene_type: rule.scene_type.clone(),
                match_strength: "strong".to_string(),
                markers: markers.to_vec(),
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
                target_dir,
                scene_type: rule.scene_type.clone(),
                match_strength: "weak".to_string(),
                markers: markers.to_vec(),
            };
        }
    }
    SceneContext {
        target_dir,
        scene_type: "generic".to_string(),
        match_strength: "none".to_string(),
        markers: markers.to_vec(),
    }
}

fn scene_payload(
    py: Python<'_>,
    path: &str,
    context: &SceneContext,
    rules: &[SceneRule],
) -> PyResult<Option<Py<PyDict>>> {
    let payload = PyDict::new(py);
    let context_dict = PyDict::new(py);
    context_dict.set_item("target_dir", &context.target_dir)?;
    context_dict.set_item("scene_type", &context.scene_type)?;
    context_dict.set_item("match_strength", &context.match_strength)?;
    context_dict.set_item("markers", PyList::new(py, &context.markers)?)?;
    payload.set_item("context", context_dict)?;
    payload.set_item("relative_path", "")?;
    payload.set_item("scene_type", &context.scene_type)?;
    payload.set_item("match_strength", &context.match_strength)?;
    payload.set_item("is_runtime_exact_path", false)?;
    payload.set_item("is_protected_exact_path", false)?;
    payload.set_item("is_protected_prefix_path", false)?;
    payload.set_item("is_protected_path", false)?;
    payload.set_item("protected_archive_ext_match", false)?;
    payload.set_item("is_runtime_resource_archive", false)?;

    if context.scene_type == "generic" {
        return Ok(None);
    }
    let Some(rule) = rules
        .iter()
        .find(|rule| rule.scene_type == context.scene_type)
    else {
        return Ok(None);
    };
    let Some(rel_path) = relative_to(path, &context.target_dir) else {
        return Ok(None);
    };
    let rel_lower = rel_path.to_ascii_lowercase();
    let ext = extension(path);
    let is_runtime_exact = rule.runtime_exact_paths.contains(&rel_lower)
        || rule
            .runtime_glob_paths
            .iter()
            .any(|pattern| wildcard_path_match(pattern, &rel_lower));
    let is_protected_exact = rule.protected_exact_paths.contains(&rel_lower);
    let is_protected_prefix = rule
        .protected_prefixes
        .iter()
        .any(|prefix| rel_lower == *prefix || rel_lower.starts_with(&format!("{prefix}/")));
    let protected_archive_ext_match = rule.protected_archive_exts.contains(&ext);
    let is_protected_path = is_protected_exact || is_protected_prefix;
    let is_runtime_resource_archive = !is_runtime_exact && is_protected_path && protected_archive_ext_match;
    if !is_runtime_exact && !is_runtime_resource_archive {
        return Ok(None);
    }

    payload.set_item("relative_path", rel_path)?;
    payload.set_item("is_runtime_exact_path", is_runtime_exact)?;
    payload.set_item("is_protected_exact_path", is_protected_exact)?;
    payload.set_item("is_protected_prefix_path", is_protected_prefix)?;
    payload.set_item("is_protected_path", is_protected_path)?;
    payload.set_item("protected_archive_ext_match", protected_archive_ext_match)?;
    payload.set_item("is_runtime_resource_archive", is_runtime_resource_archive)?;
    Ok(Some(payload.unbind()))
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

fn normalize_extension(value: &str) -> String {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() {
        String::new()
    } else if value.starts_with('.') {
        value
    } else {
        format!(".{value}")
    }
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

fn extension(value: &str) -> String {
    let name = basename(value);
    let Some(index) = name.rfind('.') else {
        return String::new();
    };
    if index == 0 {
        return String::new();
    }
    name[index..].to_ascii_lowercase()
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

fn wildcard_path_match(pattern: &str, value: &str) -> bool {
    wildcard_match(pattern, value)
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
