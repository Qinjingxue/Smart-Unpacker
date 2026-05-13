impl AnalysisBinaryView {
    fn lock(&self) -> PyResult<MutexGuard<'_, AnalysisBinaryViewInner>> {
        self.inner.lock().map_err(|_| {
            pyo3::exceptions::PyRuntimeError::new_err("analysis binary view lock poisoned")
        })
    }

    fn read_at_bytes(&self, offset: u64, size: usize) -> PyResult<Vec<u8>> {
        let (path, read_offset, read_size) = {
            let mut inner = self.lock()?;
            if offset >= inner.size || size == 0 {
                return Ok(Vec::new());
            }
            let read_size = size.min((inner.size - offset) as usize);
            let key = (offset, read_size);
            if let Some(data) = inner.cache.get(&key).cloned() {
                inner.cache_hits += 1;
                return Ok(data);
            }
            if let Some(max_read_bytes) = inner.max_read_bytes {
                if inner.read_bytes + read_size as u64 > max_read_bytes {
                    return Err(pyo3::exceptions::PyRuntimeError::new_err(
                        "archive analysis read budget exceeded",
                    ));
                }
            }
            (inner.path.clone(), offset, read_size)
        };

        let _permit = self.read_gate.acquire()?;
        let mut file = File::open(&path)?;
        file.seek(SeekFrom::Start(read_offset))?;
        let mut data = vec![0; read_size];
        file.read_exact(&mut data)?;

        let mut inner = self.lock()?;
        inner.read_bytes += data.len() as u64;
        inner.store_cache_entry((read_offset, read_size), data.clone());
        Ok(data)
    }

    fn read_tail_bytes(&self, size: usize) -> PyResult<Vec<u8>> {
        let view_size = self.lock()?.size;
        let read_size = size.min(view_size as usize);
        let offset = view_size.saturating_sub(read_size as u64);
        self.read_at_bytes(offset, read_size)
    }

    fn walk_zip_central_directory(
        &self,
        archive_offset: u64,
        physical_central_offset: u64,
        central_directory_size: u64,
        total_entries: usize,
        max_entries: usize,
    ) -> PyResult<(usize, bool, usize, bool, &'static str)> {
        let mut cursor = physical_central_offset;
        let end = physical_central_offset + central_directory_size;
        let limit = total_entries.min(max_entries);
        let mut links_checked = 0usize;
        for index in 0..limit {
            if cursor + 46 > end {
                return Ok((
                    index,
                    false,
                    links_checked,
                    false,
                    "central_directory_entry_out_of_range",
                ));
            }
            let header = self.read_at_bytes(cursor, 46)?;
            if header.len() < 46 || &header[0..4] != ZIP_CENTRAL {
                return Ok((
                    index,
                    false,
                    links_checked,
                    false,
                    "bad_central_directory_entry_signature",
                ));
            }
            let filename_len = u16_le(&header, 28) as u64;
            let extra_len = u16_le(&header, 30) as u64;
            let comment_len = u16_le(&header, 32) as u64;
            let local_header_offset = u32_le(&header, 42) as u64;
            let entry_size = 46 + filename_len + extra_len + comment_len;
            if cursor + entry_size > end {
                return Ok((
                    index,
                    false,
                    links_checked,
                    false,
                    "central_directory_variable_fields_out_of_range",
                ));
            }
            if links_checked < max_entries {
                let local_sig = self.read_at_bytes(archive_offset + local_header_offset, 4)?;
                if local_sig.len() < 4 || local_sig.as_slice() != ZIP_LOCAL {
                    return Ok((
                        index + 1,
                        true,
                        links_checked,
                        false,
                        "local_header_link_mismatch",
                    ));
                }
                links_checked += 1;
            }
            cursor += entry_size;
        }
        Ok((limit, true, links_checked, true, ""))
    }

    fn zip_content_integrity_warning(
        &self,
        archive_offset: u64,
        physical_central_offset: u64,
        total_entries: usize,
        max_entries: usize,
    ) -> PyResult<&'static str> {
        let mut cursor = physical_central_offset;
        for _ in 0..total_entries.min(max_entries).min(8) {
            let header = self.read_at_bytes(cursor, 46)?;
            if header.len() < 46 || &header[0..4] != ZIP_CENTRAL {
                return Ok("");
            }
            let cd_crc = u32_le(&header, 16);
            let filename_len = u16_le(&header, 28) as u64;
            let extra_len = u16_le(&header, 30) as u64;
            let comment_len = u16_le(&header, 32) as u64;
            let local_header_offset = u32_le(&header, 42) as u64;
            let local = self.read_at_bytes(archive_offset + local_header_offset, 30)?;
            if local.len() >= 30 && &local[0..4] == ZIP_LOCAL {
                let flags = u16_le(&local, 6);
                let local_crc = u32_le(&local, 14);
                if flags & 0x0008 != 0 {
                    return Ok("data_descriptor_or_deferred_crc");
                }
                if local_crc != cd_crc {
                    return Ok("local_header_crc_mismatch");
                }
            }
            cursor += 46 + filename_len + extra_len + comment_len;
        }
        Ok("")
    }

    fn probe_rar4(
        &self,
        py: Python<'_>,
        result: &Bound<'_, PyDict>,
        start_offset: u64,
        max_blocks: usize,
    ) -> PyResult<()> {
        let mut cursor = start_offset + RAR4.len() as u64;
        let size = self.lock()?.size;
        let evidence = PyList::empty(py);
        evidence.append("rar4:signature")?;
        for index in 0..max_blocks {
            if cursor + 7 > size {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar4_block_header_out_of_range")?;
                return Ok(());
            }
            let fixed = self.read_at_bytes(cursor, 7)?;
            let header_crc = u16_le(&fixed, 0);
            let header_type = fixed[2];
            let header_flags = u16_le(&fixed, 3);
            let header_size = u16_le(&fixed, 5) as u64;
            if !matches!(header_type, 0x72..=0x7B) {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar4_block_unknown_type")?;
                return Ok(());
            }
            if header_size < 7 || cursor + header_size > size {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar4_block_size_out_of_range")?;
                return Ok(());
            }
            let full_header = self.read_at_bytes(cursor, header_size as usize)?;
            if (crc32(&full_header[2..]) & 0xFFFF) != header_crc as u32 {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar4_block_crc_mismatch")?;
                return Ok(());
            }
            let mut block_size = header_size;
            if header_flags & 0x8000 != 0 {
                if header_size < 11 {
                    result.set_item("blocks_checked", index)?;
                    result.set_item("error", "rar4_block_add_size_missing")?;
                    return Ok(());
                }
                block_size += u32_le(&full_header, 7) as u64;
            }
            let next_cursor = cursor + block_size;
            if next_cursor > size {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar4_block_payload_out_of_range")?;
                return Ok(());
            }
            if index == 0 && header_type != 0x73 {
                result.set_item("blocks_checked", 1usize)?;
                result.set_item("error", "rar4_main_header_missing")?;
                return Ok(());
            }
            if index == 0 {
                evidence.append("rar4:main_header")?;
            }
            if header_type == 0x7B {
                evidence.append("rar4:end_block")?;
                result.set_item("plausible", true)?;
                result.set_item("strong_accept", true)?;
                result.set_item("blocks_checked", index + 1)?;
                result.set_item("end_block_found", true)?;
                result.set_item("segment_end", next_cursor)?;
                result.set_item("evidence", evidence)?;
                return Ok(());
            }
            cursor = next_cursor;
        }
        result.set_item("blocks_checked", max_blocks)?;
        result.set_item("segment_end", cursor)?;
        result.set_item("plausible", true)?;
        result.set_item("error", "rar4_block_walk_limit_reached")?;
        result.set_item("evidence", evidence)?;
        Ok(())
    }

    fn probe_rar5(
        &self,
        py: Python<'_>,
        result: &Bound<'_, PyDict>,
        start_offset: u64,
        max_blocks: usize,
    ) -> PyResult<()> {
        let mut cursor = start_offset + RAR5.len() as u64;
        let size = self.lock()?.size;
        let evidence = PyList::empty(py);
        evidence.append("rar5:signature")?;
        for index in 0..max_blocks {
            if cursor + 6 > size {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_block_header_out_of_range")?;
                return Ok(());
            }
            let first = self.read_at_bytes(cursor, 64)?;
            let Some((header_size, after_size)) = read_vint(&first, 4) else {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_header_size_vint_missing")?;
                return Ok(());
            };
            let header_total_size = 4 + (after_size - 4) as u64 + header_size;
            if header_size == 0 || cursor + header_total_size > size {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_header_size_out_of_range")?;
                return Ok(());
            }
            let full = self.read_at_bytes(cursor, header_total_size as usize)?;
            let Some((header_type, after_type)) = read_vint(&full, after_size) else {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_header_type_vint_missing")?;
                return Ok(());
            };
            let Some((header_flags, after_flags)) = read_vint(&full, after_type) else {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_header_flags_vint_missing")?;
                return Ok(());
            };
            if !matches!(header_type, 1..=5) {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_block_unknown_type")?;
                return Ok(());
            }
            let stored_crc = u32_le(&full, 0);
            if crc32(&full[4..]) != stored_crc {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_block_crc_mismatch")?;
                return Ok(());
            }
            let mut field_cursor = after_flags;
            if header_flags & 0x0001 != 0 {
                let Some((_, after_extra)) = read_vint(&full, field_cursor) else {
                    result.set_item("blocks_checked", index)?;
                    result.set_item("error", "rar5_extra_area_size_vint_missing")?;
                    return Ok(());
                };
                field_cursor = after_extra;
            }
            let mut data_size = 0u64;
            if header_flags & 0x0002 != 0 {
                let Some((value, _after_data)) = read_vint(&full, field_cursor) else {
                    result.set_item("blocks_checked", index)?;
                    result.set_item("error", "rar5_data_size_vint_missing")?;
                    return Ok(());
                };
                data_size = value;
            }
            let next_cursor = cursor + header_total_size + data_size;
            if next_cursor > size {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_block_payload_out_of_range")?;
                return Ok(());
            }
            if index == 0 && header_type != 1 {
                result.set_item("blocks_checked", 1usize)?;
                result.set_item("error", "rar5_main_header_missing")?;
                return Ok(());
            }
            if index == 0 {
                evidence.append("rar5:main_header")?;
            }
            if header_type == 5 {
                evidence.append("rar5:end_block")?;
                result.set_item("plausible", true)?;
                result.set_item("strong_accept", true)?;
                result.set_item("blocks_checked", index + 1)?;
                result.set_item("end_block_found", true)?;
                result.set_item("segment_end", next_cursor)?;
                result.set_item("evidence", evidence)?;
                return Ok(());
            }
            cursor = next_cursor;
        }
        result.set_item("blocks_checked", max_blocks)?;
        result.set_item("segment_end", cursor)?;
        result.set_item("plausible", true)?;
        result.set_item("error", "rar5_block_walk_limit_reached")?;
        result.set_item("evidence", evidence)?;
        Ok(())
    }

    fn walk_tar<'py>(
        &self,
        py: Python<'py>,
        start_offset: u64,
        max_entries: usize,
    ) -> PyResult<Bound<'py, PyDict>> {
        let result = PyDict::new(py);
        result.set_item("format", "tar")?;
        result.set_item("plausible", false)?;
        result.set_item("error", "")?;
        result.set_item("entries_checked", 0usize)?;
        result.set_item("entry_walk_ok", false)?;
        result.set_item("end_zero_blocks", false)?;
        result.set_item("segment_end", py.None())?;
        result.set_item("boundary_confidence", "none")?;
        result.set_item("integrity_confidence", "unknown")?;
        result.set_item("evidence", PyList::empty(py))?;

        let size = self.lock()?.size;
        let mut cursor = start_offset;
        let mut checked = 0usize;
        let mut zero_blocks = 0usize;
        while checked < max_entries && cursor + TAR_BLOCK_SIZE as u64 <= size {
            let header = self.read_at_bytes(cursor, TAR_BLOCK_SIZE)?;
            if header.len() < TAR_BLOCK_SIZE {
                result.set_item("error", "short_tar_header")?;
                break;
            }
            if header.iter().all(|byte| *byte == 0) {
                zero_blocks += 1;
                cursor += TAR_BLOCK_SIZE as u64;
                if zero_blocks >= 2 {
                    result.set_item("plausible", checked > 0)?;
                    result.set_item("entries_checked", checked)?;
                    result.set_item("entry_walk_ok", checked > 0)?;
                    result.set_item("end_zero_blocks", true)?;
                    result.set_item("segment_end", cursor)?;
                    result.set_item("boundary_confidence", "high")?;
                    result.set_item(
                        "evidence",
                        PyList::new(
                            py,
                            [
                                "tar:header_checksum",
                                "tar:block_walk",
                                "tar:end_zero_blocks",
                            ],
                        )?,
                    )?;
                    return Ok(result);
                }
                continue;
            }
            zero_blocks = 0;
            let (ok, error, member_size, ustar) = tar_header_plausible(&header);
            if !ok {
                result.set_item("entries_checked", checked)?;
                result.set_item("error", error)?;
                if checked > 0 {
                    result.set_item("plausible", true)?;
                    result.set_item("entry_walk_ok", true)?;
                    result.set_item("segment_end", cursor)?;
                    result.set_item("boundary_confidence", "medium")?;
                    result.set_item(
                        "evidence",
                        PyList::new(py, ["tar:header_checksum", "tar:block_walk_prefix"])?,
                    )?;
                }
                return Ok(result);
            }
            checked += 1;
            cursor += TAR_BLOCK_SIZE as u64 + member_size + tar_padding(member_size);
            result.set_item(
                "evidence",
                PyList::new(
                    py,
                    [
                        "tar:header_checksum",
                        if ustar {
                            "tar:ustar_magic"
                        } else {
                            "tar:v7_header"
                        },
                    ],
                )?,
            )?;
        }
        if checked > 0 {
            result.set_item("plausible", true)?;
            result.set_item("entries_checked", checked)?;
            result.set_item("entry_walk_ok", true)?;
            result.set_item("segment_end", cursor)?;
            result.set_item("boundary_confidence", "medium")?;
            result.set_item("error", "tar_end_zero_blocks_not_found")?;
            result.set_item(
                "evidence",
                PyList::new(py, ["tar:header_checksum", "tar:block_walk_prefix"])?,
            )?;
        }
        Ok(result)
    }

    fn probe_compression<'py>(
        &self,
        py: Python<'py>,
        format: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let result = PyDict::new(py);
        result.set_item("format", format)?;
        result.set_item("magic_matched", false)?;
        result.set_item("plausible", false)?;
        result.set_item("error", "")?;
        result.set_item("confidence", 0.0f64)?;
        result.set_item("boundary_confidence", "medium")?;
        result.set_item("integrity_confidence", "unknown")?;
        result.set_item("evidence", PyList::empty(py))?;
        let header = self.read_at_bytes(0, 64)?;
        match format {
            "gzip" => {
                if !header.starts_with(GZIP) {
                    result.set_item("error", "gzip_magic_not_found")?;
                    return Ok(result);
                }
                result.set_item("magic_matched", true)?;
                if header.len() < 10 || header[3] & 0xE0 != 0 {
                    result.set_item("error", "gzip_reserved_flags_set")?;
                    return Ok(result);
                }
                result.set_item("plausible", true)?;
                result.set_item("confidence", 0.90f64)?;
                let evidence = PyList::new(
                    py,
                    ["gzip:magic", "gzip:method:deflate", "gzip:flags_valid"],
                )?;
                if self.lock()?.size >= 18 {
                    let tail = self.read_tail_bytes(4)?;
                    if tail.len() == 4 {
                        result.set_item("isize", u32_le(&tail, 0))?;
                        evidence.append("gzip:trailer")?;
                    }
                }
                result.set_item("evidence", evidence)?;
            }
            "bzip2" => {
                if !header.starts_with(BZIP2) {
                    result.set_item("error", "bzip2_magic_not_found")?;
                    return Ok(result);
                }
                result.set_item("magic_matched", true)?;
                let ok = header.len() >= 10
                    && b"123456789".contains(&header[3])
                    && (&header[4..10] == b"\x31\x41\x59\x26\x53\x59"
                        || &header[4..10] == b"\x17\x72\x45\x38\x50\x90");
                if !ok {
                    result.set_item("error", "bzip2_block_marker_not_found")?;
                    return Ok(result);
                }
                result.set_item("plausible", true)?;
                result.set_item("confidence", 0.92f64)?;
                result.set_item(
                    "evidence",
                    PyList::new(py, ["bzip2:magic", "bzip2:block_marker"])?,
                )?;
            }
            "xz" => {
                if !header.starts_with(XZ) {
                    result.set_item("error", "xz_magic_not_found")?;
                    return Ok(result);
                }
                result.set_item("magic_matched", true)?;
                let footer = self.read_tail_bytes(12)?;
                if footer.len() == 12 && &footer[10..12] == b"YZ" {
                    result.set_item("plausible", true)?;
                    result.set_item("confidence", 0.95f64)?;
                    result.set_item("boundary_confidence", "high")?;
                    result.set_item(
                        "evidence",
                        PyList::new(py, ["xz:magic", "xz:footer_magic"])?,
                    )?;
                } else {
                    result.set_item("plausible", true)?;
                    result.set_item("confidence", 0.72f64)?;
                    result.set_item("error", "xz_footer_magic_not_found")?;
                    result.set_item("evidence", PyList::new(py, ["xz:magic"])?)?;
                }
            }
            "zstd" => {
                if !header.starts_with(ZSTD) {
                    result.set_item("error", "zstd_magic_not_found")?;
                    return Ok(result);
                }
                result.set_item("magic_matched", true)?;
                if header.len() < 6 || header[4] & 0x08 != 0 {
                    result.set_item("error", "zstd_reserved_bit_set")?;
                    return Ok(result);
                }
                result.set_item("plausible", true)?;
                result.set_item("confidence", 0.88f64)?;
                result.set_item(
                    "evidence",
                    PyList::new(py, ["zstd:magic", "zstd:frame_descriptor"])?,
                )?;
            }
            _ => {
                result.set_item("error", "unsupported_compression_format")?;
            }
        }
        Ok(result)
    }
}

impl AnalysisMultiVolumeView {
    fn lock(&self) -> PyResult<MutexGuard<'_, AnalysisMultiVolumeViewInner>> {
        self.inner.lock().map_err(|_| {
            pyo3::exceptions::PyRuntimeError::new_err("analysis multi-volume view lock poisoned")
        })
    }

    fn read_at_bytes(&self, offset: u64, size: usize) -> PyResult<Vec<u8>> {
        let (reads, read_offset, read_size) = {
            let mut inner = self.lock()?;
            if offset >= inner.size || size == 0 {
                return Ok(Vec::new());
            }
            let read_size = size.min((inner.size - offset) as usize);
            let key = (offset, read_size);
            if let Some(data) = inner.cache.get(&key).cloned() {
                inner.cache_hits += 1;
                return Ok(data);
            }
            if let Some(max_read_bytes) = inner.max_read_bytes {
                if inner.read_bytes + read_size as u64 > max_read_bytes {
                    return Err(pyo3::exceptions::PyRuntimeError::new_err(
                        "archive analysis read budget exceeded",
                    ));
                }
            }
            let end_offset = offset + read_size as u64;
            let mut reads = Vec::new();
            for volume in &inner.volumes {
                if offset >= volume.end || end_offset <= volume.start {
                    continue;
                }
                let local_start = offset.max(volume.start);
                let local_end = end_offset.min(volume.end);
                reads.push(VolumeRead {
                    path: volume.path.clone(),
                    start: local_start - volume.start,
                    size: (local_end - local_start) as usize,
                });
            }
            (reads, offset, read_size)
        };

        let _permit = self.read_gate.acquire()?;
        let mut data = Vec::with_capacity(read_size);
        for read in reads {
            let mut file = File::open(&read.path)?;
            file.seek(SeekFrom::Start(read.start))?;
            let mut chunk = vec![0; read.size];
            file.read_exact(&mut chunk)?;
            data.extend_from_slice(&chunk);
        }

        let mut inner = self.lock()?;
        inner.read_bytes += data.len() as u64;
        inner.store_cache_entry((read_offset, read_size), data.clone());
        Ok(data)
    }
}

impl AnalysisBinaryViewInner {
    fn store_cache_entry(&mut self, key: (u64, usize), data: Vec<u8>) {
        if self.cache_bytes == 0 || data.len() > self.cache_bytes {
            return;
        }
        if let Some(old) = self.cache.insert(key, data) {
            self.cache_size = self.cache_size.saturating_sub(old.len());
            self.order.retain(|existing| *existing != key);
        }
        self.cache_size += self.cache.get(&key).map(|value| value.len()).unwrap_or(0);
        self.order.push_back(key);
        while self.cache_size > self.cache_bytes {
            let Some(old_key) = self.order.pop_front() else {
                break;
            };
            if let Some(old) = self.cache.remove(&old_key) {
                self.cache_size = self.cache_size.saturating_sub(old.len());
            }
        }
    }
}

impl AnalysisMultiVolumeViewInner {
    fn store_cache_entry(&mut self, key: (u64, usize), data: Vec<u8>) {
        if self.cache_bytes == 0 || data.len() > self.cache_bytes {
            return;
        }
        if let Some(old) = self.cache.insert(key, data) {
            self.cache_size = self.cache_size.saturating_sub(old.len());
            self.order.retain(|existing| *existing != key);
        }
        self.cache_size += self.cache.get(&key).map(|value| value.len()).unwrap_or(0);
        self.order.push_back(key);
        while self.cache_size > self.cache_bytes {
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
    fn acquire(&self) -> PyResult<ReadPermit<'_>> {
        let mut active = self.active.lock().map_err(|_| {
            pyo3::exceptions::PyRuntimeError::new_err("analysis read gate lock poisoned")
        })?;
        while *active >= self.limit {
            active = self.available.wait(active).map_err(|_| {
                pyo3::exceptions::PyRuntimeError::new_err("analysis read gate lock poisoned")
            })?;
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
