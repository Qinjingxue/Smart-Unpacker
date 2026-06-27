fn rebuild_rar_file_quarantine_candidates(
    data: &[u8],
    workspace: &str,
    max_candidates: usize,
) -> Vec<WrittenArchiveCandidate> {
    let mut candidates = Vec::new();
    let offsets = find_all(data, RAR4_MAGIC)
        .into_iter()
        .map(|offset| (offset, RarVersion::Rar4))
        .chain(
            find_all(data, RAR5_MAGIC)
                .into_iter()
                .map(|offset| (offset, RarVersion::Rar5)),
        )
        .collect::<Vec<_>>();
    for (offset, version) in offsets {
        if candidates.len() >= max_candidates {
            break;
        }
        let rebuilt = match version {
            RarVersion::Rar4 => rebuild_rar4_quarantine(data, offset),
            RarVersion::Rar5 => rebuild_rar5_quarantine(data, offset),
        };
        let Some((bytes, kept, skipped, end_offset)) = rebuilt else {
            continue;
        };
        if kept == 0 || skipped == 0 {
            continue;
        }
        let output_path =
            Path::new(workspace).join(format!("rar_file_quarantine_{offset:08x}.rar"));
        let output_bytes = match write_slice_candidate(&bytes, &output_path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        candidates.push(WrittenArchiveCandidate {
            name: format!("rar_file_quarantine_{offset:08x}"),
            path: output_path.to_string_lossy().to_string(),
            format: "rar".to_string(),
            status: "partial".to_string(),
            offset: offset as u64,
            end_offset: end_offset as u64,
            output_bytes,
            confidence: (0.64 + kept as f64 * 0.04).min(0.88),
            actions: vec![
                "walk_rar_file_blocks".to_string(),
                "drop_incomplete_or_untrusted_file_blocks".to_string(),
                "rebuild_rar_with_recoverable_file_blocks".to_string(),
            ],
            warnings: vec![format!(
                "kept {kept} complete RAR file blocks and skipped {skipped}"
            )],
        });
    }
    candidates
}

fn rebuild_rar4_quarantine(data: &[u8], offset: usize) -> Option<(Vec<u8>, usize, usize, usize)> {
    if !data.get(offset..)?.starts_with(RAR4_MAGIC) {
        return None;
    }
    let mut pos = offset + RAR4_MAGIC.len();
    let mut output = data[offset..pos].to_vec();
    let mut kept = 0usize;
    let mut skipped = 0usize;
    let mut saw_main = false;
    let mut end_offset = pos;
    while pos + 7 <= data.len() {
        let stored_crc = u16_le(data, pos) as u32;
        let header_type = data[pos + 2];
        let flags = u16_le(data, pos + 3);
        let header_size = u16_le(data, pos + 5) as usize;
        if !matches!(header_type, 0x73..=0x7b) || header_size < 7 || pos + header_size > data.len()
        {
            break;
        }
        let header = &data[pos..pos + header_size];
        if (crc32(&header[2..]) & 0xffff) != stored_crc {
            skipped += 1;
            break;
        }
        let add_size = if flags & 0x8000 != 0 {
            if header_size < 11 {
                skipped += 1;
                break;
            }
            u32_le(header, 7) as usize
        } else {
            0
        };
        let block_end = pos.checked_add(header_size)?.checked_add(add_size)?;
        if block_end > data.len() {
            skipped += 1;
            break;
        }
        if header_type == 0x73 && !saw_main {
            output.extend_from_slice(&data[pos..block_end]);
            saw_main = true;
        } else if header_type == 0x74 {
            output.extend_from_slice(&data[pos..block_end]);
            kept += 1;
        } else if header_type == 0x7b {
            output.extend_from_slice(&data[pos..block_end]);
            end_offset = block_end;
            return Some((output, kept, skipped, end_offset));
        } else {
            skipped += 1;
        }
        end_offset = block_end;
        pos = block_end;
    }
    if saw_main && kept > 0 {
        output.extend_from_slice(&rar4_end_block());
        Some((output, kept, skipped.max(1), end_offset))
    } else {
        None
    }
}

fn rebuild_rar5_quarantine(data: &[u8], offset: usize) -> Option<(Vec<u8>, usize, usize, usize)> {
    if !data.get(offset..)?.starts_with(RAR5_MAGIC) {
        return None;
    }
    let mut pos = offset + RAR5_MAGIC.len();
    let mut output = data[offset..pos].to_vec();
    let mut kept = 0usize;
    let mut skipped = 0usize;
    let mut saw_main = false;
    let mut end_offset = pos;
    while pos < data.len() {
        let Some(block) = parse_rar5_block(data, pos) else {
            skipped += 1;
            if let Some(next_pos) = find_next_valid_rar5_block(data, pos.saturating_add(1)) {
                pos = next_pos;
                continue;
            }
            break;
        };
        if block.end > data.len() {
            skipped += 1;
            break;
        }
        if !block.crc_ok {
            skipped += 1;
            if let Some(next_pos) = find_next_valid_rar5_block(data, pos.saturating_add(1)) {
                pos = next_pos;
                continue;
            }
            break;
        }
        if block.block_type == 4 {
            // The following headers are AES-encrypted and cannot be safely
            // quarantined or resynchronized without the archive password.
            return None;
        }
        if block.block_type == 1 {
            if !saw_main {
                // Rebuild as a single-volume archive. Copying the original main
                // header from a split volume keeps the volume flag and makes the
                // quarantine candidate unopenable as a standalone RAR.
                output.extend_from_slice(&rar5_main_block(0));
            } else {
                skipped += 1;
            }
            saw_main = true;
        } else if block.block_type == 2 {
            if block.flags & 0x0018 != 0 {
                // RAR5 uses split-before/split-after block flags for file data
                // continued across volumes. Those blocks are not independently
                // extractable, so keep scanning for later complete file blocks.
                skipped += 1;
            } else {
                output.extend_from_slice(&data[pos..block.end]);
                kept += 1;
            }
        } else if block.block_type == 5 {
            end_offset = block.end;
            output.extend_from_slice(&rar5_end_block());
            return Some((output, kept, skipped, end_offset));
        } else {
            skipped += 1;
        }
        end_offset = block.end;
        pos = block.end;
    }
    if saw_main && kept > 0 {
        output.extend_from_slice(&rar5_end_block());
        Some((output, kept, skipped.max(1), end_offset))
    } else {
        None
    }
}

fn find_next_valid_rar5_block(data: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    while pos < data.len() {
        if let Some(block) = parse_rar5_block(data, pos) {
            if block.end <= data.len() && block.crc_ok {
                return Some(pos);
            }
        }
        pos = pos.saturating_add(1);
    }
    None
}

