fn seven_zip_scan_error(py: Python<'_>, status: &str, message: &str) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("native_key", "native_7z_scan_source")?;
    result.set_item("native_target", "seven_zip_scan_source")?;
    result.set_item("format", "7z")?;
    result.set_item("message", message)?;
    result.set_item("route_evidence_flags", PyList::empty(py))?;
    result.set_item("structure", PyDict::new(py))?;
    result.set_item("candidates", PyList::empty(py))?;
    Ok(result.unbind())
}

fn seven_zip_atomic_status(
    py: Python<'_>,
    status: &str,
    target: &str,
    format: &str,
    selected_path: &str,
    message: &str,
    warnings: &[String],
    actions: &[&str],
    patch_facts: &[&str],
    confidence: f64,
    residual_facts: &[&str],
    candidates: &[WrittenArchiveCandidate],
) -> PyResult<Py<PyDict>> {
    let output_bytes = if selected_path.is_empty() {
        0
    } else {
        fs::metadata(selected_path).map(|item| item.len()).unwrap_or(0)
    };
    let result = status_dict_with_candidates(
        py,
        status,
        selected_path,
        format,
        message,
        warnings,
        0,
        output_bytes,
        output_bytes,
        confidence,
        actions,
        candidates,
    )?;
    set_seven_zip_atomic_fields(py, &result, target, patch_facts, residual_facts)?;
    Ok(result)
}

fn set_seven_zip_atomic_fields(
    py: Python<'_>,
    result: &Py<PyDict>,
    target: &str,
    patch_facts: &[&str],
    residual_facts: &[&str],
) -> PyResult<()> {
    let bound = result.bind(py);
    bound.set_item("native_key", "native_7z_atomic_repair")?;
    bound.set_item("native_target", target)?;
    bound.set_item("candidate_status", status_to_candidate_status(&str_item(bound, "status")))?;
    bound.set_item("patch_facts", PyList::new(py, patch_facts)?)?;
    bound.set_item("residual_facts", PyList::new(py, residual_facts)?)?;
    let validation = PyDict::new(py);
    validation.set_item("target", target)?;
    validation.set_item("policy", target)?;
    bound.set_item("validation_details", validation)?;
    if let Ok(Some(candidates_obj)) = bound.get_item("candidates") {
        if let Ok(candidates) = candidates_obj.downcast::<PyList>() {
            for raw in candidates.iter() {
                if let Ok(item) = raw.downcast::<PyDict>() {
                    item.set_item("native_target", target)?;
                    item.set_item("candidate_status", status_to_candidate_status(&str_item(item, "status")))?;
                    item.set_item("patch_facts", PyList::new(py, patch_facts)?)?;
                    item.set_item("residual_facts", PyList::new(py, residual_facts)?)?;
                    let item_validation = PyDict::new(py);
                    item_validation.set_item("target", target)?;
                    item_validation.set_item("policy", target)?;
                    item.set_item("validation_details", item_validation)?;
                }
            }
        }
    }
    Ok(())
}

fn seven_zip_patch_plan_dict(
    py: Python<'_>,
    module: &str,
    confidence: f64,
    actions: &[&str],
    operations: &[Py<PyDict>],
    native_target: &str,
) -> PyResult<Py<PyDict>> {
    let provenance = PyDict::new(py);
    provenance.set_item("module", module)?;
    provenance.set_item("native_target", native_target)?;
    provenance.set_item("actions", PyList::new(py, actions)?)?;

    let plan = PyDict::new(py);
    plan.set_item("kind", "patch_plan")?;
    plan.set_item("schema_version", 2)?;
    plan.set_item("module", module)?;
    plan.set_item("format", "7z")?;
    plan.set_item("action_type", "apply_patch")?;
    plan.set_item("operations", PyList::new(py, operations)?)?;
    plan.set_item("provenance", provenance)?;
    plan.set_item("confidence", confidence)?;
    Ok(plan.unbind())
}

fn seven_zip_delete_operation(
    py: Python<'_>,
    source: &[u8],
    offset: usize,
    size: usize,
    module: &str,
    native_target: &str,
) -> PyResult<Py<PyDict>> {
    let expected = source.get(offset..offset.saturating_add(size)).unwrap_or(&[]);
    let details = PyDict::new(py);
    details.set_item("module", module)?;
    details.set_item("native_target", native_target)?;

    let operation = PyDict::new(py);
    operation.set_item("schema_version", 2)?;
    operation.set_item("op", "delete")?;
    operation.set_item("target", "logical")?;
    operation.set_item("offset", offset)?;
    operation.set_item("size", size)?;
    operation.set_item("expected_b64", BASE64_STANDARD.encode(expected))?;
    operation.set_item("details", details)?;
    Ok(operation.unbind())
}

fn seven_zip_truncate_operation(
    py: Python<'_>,
    source: &[u8],
    offset: usize,
    module: &str,
    native_target: &str,
) -> PyResult<Py<PyDict>> {
    let expected = source.get(offset..).unwrap_or(&[]);
    let details = PyDict::new(py);
    details.set_item("module", module)?;
    details.set_item("native_target", native_target)?;

    let operation = PyDict::new(py);
    operation.set_item("schema_version", 2)?;
    operation.set_item("op", "truncate")?;
    operation.set_item("target", "logical")?;
    operation.set_item("offset", offset)?;
    operation.set_item("size", expected.len())?;
    operation.set_item("expected_sha256", format!("{:x}", sha2::Sha256::digest(expected)))?;
    operation.set_item("details", details)?;
    Ok(operation.unbind())
}

fn seven_zip_append_operation(
    py: Python<'_>,
    data: &[u8],
    module: &str,
    native_target: &str,
) -> PyResult<Py<PyDict>> {
    let details = PyDict::new(py);
    details.set_item("module", module)?;
    details.set_item("native_target", native_target)?;

    let operation = PyDict::new(py);
    operation.set_item("schema_version", 2)?;
    operation.set_item("op", "append")?;
    operation.set_item("target", "logical")?;
    operation.set_item("offset", 0)?;
    operation.set_item("size", data.len())?;
    operation.set_item("data_b64", BASE64_STANDARD.encode(data))?;
    operation.set_item("expected_b64", "")?;
    operation.set_item("details", details)?;
    Ok(operation.unbind())
}

fn seven_zip_replace_logical_archive_patch_plan(
    py: Python<'_>,
    module: &str,
    source: &[u8],
    replacement: &[u8],
    confidence: f64,
    actions: &[&str],
    native_target: &str,
) -> PyResult<Py<PyDict>> {
    let truncate = seven_zip_truncate_operation(py, source, 0, module, native_target)?;
    let append = seven_zip_append_operation(py, replacement, module, native_target)?;
    seven_zip_patch_plan_dict(py, module, confidence, actions, &[truncate, append], native_target)
}

fn add_seven_zip_candidate_replace_patch_plans(
    py: Python<'_>,
    result: &Py<PyDict>,
    source: &[u8],
    native_target: &str,
) -> PyResult<()> {
    let bound = result.bind(py);
    if let Ok(Some(candidates_obj)) = bound.get_item("candidates") {
        if let Ok(candidates) = candidates_obj.downcast::<PyList>() {
            for raw in candidates.iter() {
                if let Ok(item) = raw.downcast::<PyDict>() {
                    let path = str_item(item, "path");
                    if path.is_empty() || item.contains("patch_plan")? {
                        continue;
                    }
                    let Ok(bytes) = fs::read(&path) else {
                        continue;
                    };
                    let module = str_item(item, "name");
                    let module = if module.is_empty() { native_target.to_string() } else { module };
                    let confidence = item
                        .get_item("confidence")?
                        .and_then(|value| value.extract::<f64>().ok())
                        .unwrap_or(0.0);
                    let actions = seven_zip_string_list(item, "actions")?;
                    let action_refs = actions.iter().map(|item| item.as_str()).collect::<Vec<_>>();
                    item.set_item(
                        "patch_plan",
                        seven_zip_replace_logical_archive_patch_plan(
                            py,
                            &module,
                            source,
                            &bytes,
                            confidence,
                            &action_refs,
                            native_target,
                        )?,
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn seven_zip_string_list(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<String>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(Vec::new());
    };
    let Ok(list) = value.downcast::<PyList>() else {
        return Ok(Vec::new());
    };
    Ok(list
        .iter()
        .filter_map(|item| item.extract::<String>().ok())
        .collect())
}

fn status_to_candidate_status(status: &str) -> &str {
    match status {
        "repaired" => "complete",
        "partial" => "partial",
        "target_mismatch" => "target_mismatch",
        "validation_failed" => "validation_failed",
        "skipped" => "no_candidate",
        _ => "no_candidate",
    }
}

fn str_item(dict: &Bound<'_, PyDict>, key: &str) -> String {
    dict.get_item(key)
        .ok()
        .flatten()
        .and_then(|value| value.extract::<String>().ok())
        .unwrap_or_default()
}
fn status_dict(
    py: Python<'_>,
    status: &str,
    selected_path: &str,
    format: &str,
    message: &str,
    warnings: &[String],
    offset: u64,
    end_offset: u64,
    output_bytes: u64,
    confidence: f64,
    actions: &[&str],
) -> PyResult<Py<PyDict>> {
    status_dict_with_candidates(
        py,
        status,
        selected_path,
        format,
        message,
        warnings,
        offset,
        end_offset,
        output_bytes,
        confidence,
        actions,
        &[],
    )
}

fn status_dict_with_candidates(
    py: Python<'_>,
    status: &str,
    selected_path: &str,
    format: &str,
    message: &str,
    warnings: &[String],
    offset: u64,
    end_offset: u64,
    output_bytes: u64,
    confidence: f64,
    actions: &[&str],
    candidates: &[WrittenArchiveCandidate],
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("selected_path", selected_path)?;
    result.set_item("format", format)?;
    result.set_item("message", message)?;
    result.set_item("warnings", PyList::new(py, warnings)?)?;
    result.set_item("offset", offset)?;
    result.set_item("end_offset", end_offset)?;
    result.set_item("output_bytes", output_bytes)?;
    result.set_item("confidence", confidence)?;
    result.set_item("actions", PyList::new(py, actions)?)?;
    result.set_item("native_key", "native_archive_deep_repair")?;
    result.set_item("native_target", if format == "zip" { "archive_carrier_crop_zip" } else { "archive_carrier_crop" })?;
    result.set_item("candidate_status", status)?;
    result.set_item("materialized_path", selected_path)?;
    let patch_facts = carrier_crop_patch_facts(format, offset, end_offset);
    result.set_item("patch_facts", PyList::new(py, &patch_facts)?)?;
    let residual_facts = carrier_crop_residual_facts(format);
    result.set_item("residual_facts", PyList::new(py, &residual_facts)?)?;
    let validation = PyDict::new(py);
    validation.set_item("cropped_format", format)?;
    validation.set_item("cropped_start", offset)?;
    validation.set_item("cropped_end", end_offset)?;
    validation.set_item("source_digest_after_crop", candidate_crc32(selected_path))?;
    result.set_item("validation_details", validation)?;
    result.set_item(
        "workspace_paths",
        if !candidates.is_empty() {
            PyList::new(
                py,
                candidates
                    .iter()
                    .map(|candidate| candidate.path.as_str())
                    .collect::<Vec<_>>(),
            )?
        } else if selected_path.is_empty() {
            PyList::empty(py)
        } else {
            PyList::new(py, [selected_path])?
        },
    )?;
    let candidate_list = PyList::empty(py);
    for candidate in candidates {
        let item = PyDict::new(py);
        item.set_item("name", &candidate.name)?;
        item.set_item("path", &candidate.path)?;
        item.set_item("format", &candidate.format)?;
        item.set_item("status", &candidate.status)?;
        item.set_item("offset", candidate.offset)?;
        item.set_item("end_offset", candidate.end_offset)?;
        item.set_item("output_bytes", candidate.output_bytes)?;
        item.set_item("confidence", candidate.confidence)?;
        item.set_item("actions", PyList::new(py, &candidate.actions)?)?;
        item.set_item("warnings", PyList::new(py, &candidate.warnings)?)?;
        let item_patch_facts = carrier_crop_patch_facts(&candidate.format, candidate.offset, candidate.end_offset);
        item.set_item("patch_facts", PyList::new(py, &item_patch_facts)?)?;
        let item_residual_facts = carrier_crop_residual_facts(&candidate.format);
        item.set_item("residual_facts", PyList::new(py, &item_residual_facts)?)?;
        item.set_item("native_target", if candidate.format == "zip" { "archive_carrier_crop_zip" } else { "archive_carrier_crop" })?;
        item.set_item("candidate_status", &candidate.status)?;
        let item_validation = PyDict::new(py);
        item_validation.set_item("cropped_format", &candidate.format)?;
        item_validation.set_item("cropped_start", candidate.offset)?;
        item_validation.set_item("cropped_end", candidate.end_offset)?;
        item_validation.set_item("source_digest_after_crop", candidate_crc32(&candidate.path))?;
        item.set_item("validation_details", item_validation)?;
        candidate_list.append(item)?;
    }
    result.set_item("candidates", candidate_list)?;
    Ok(result.unbind())
}
