use std::io::Cursor;

const FULL_STREAM_STRUCTURE_MAX_BYTES: u64 = 4 * 1024 * 1024;
const STREAM_STRUCTURE_HEAD_BYTES: usize = 256 * 1024;
const STREAM_STRUCTURE_TAIL_BYTES: usize = 1024 * 1024;
const STREAM_STRUCTURE_DECODE_MAX_BYTES: u64 = 8 * 1024 * 1024;

fn read_prefix(path: &str, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut data = Vec::with_capacity(limit);
    file.by_ref().take(limit as u64).read_to_end(&mut data)?;
    Ok(data)
}

fn read_suffix(path: &str, file_size: u64, limit: usize) -> std::io::Result<(u64, Vec<u8>)> {
    let start = file_size.saturating_sub(limit as u64);
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(start))?;
    let mut data = Vec::with_capacity((file_size - start) as usize);
    file.read_to_end(&mut data)?;
    Ok((start, data))
}

const GZIP_FIELDS: &[&str] = &[
    "member.header.magic",
    "member.header.compression_method",
    "member.header.flags",
    "member.header.mtime_xfl_os",
    "member.header.extra_length",
    "member.header.extra",
    "member.header.name",
    "member.header.comment",
    "member.header.crc16",
    "member.deflate.blocks",
    "member.deflate.final_block",
    "member.decoded_content",
    "member.trailer.crc32",
    "member.trailer.isize",
    "member.boundary",
    "member.next_member",
    "archive.trailing_data",
];
const BZIP2_FIELDS: &[&str] = &[
    "stream.magic",
    "stream.block_size_100k",
    "block.marker",
    "block.crc32",
    "block.randomized",
    "block.orig_ptr",
    "block.huffman_tables",
    "block.encoded_data",
    "block.decoded_content",
    "block.sequence",
    "stream.end_marker",
    "stream.combined_crc32",
    "archive.trailing_data",
];
const XZ_FIELDS: &[&str] = &[
    "stream.header.magic",
    "stream.header.flags",
    "stream.header.crc32",
    "block.header.size",
    "block.header.flags",
    "block.header.compressed_size",
    "block.header.uncompressed_size",
    "block.header.filters",
    "block.header.crc32",
    "block.compressed_data",
    "block.uncompressed_data",
    "block.padding",
    "block.check",
    "block.sequence",
    "index.indicator",
    "index.record_count",
    "index.records.unpadded_size",
    "index.records.uncompressed_size",
    "index.padding",
    "index.crc32",
    "stream.footer.crc32",
    "stream.footer.backward_size",
    "stream.footer.flags",
    "stream.footer.magic",
    "stream.padding",
    "archive.stream_sequence",
    "archive.trailing_data",
];
const ZSTD_FIELDS: &[&str] = &[
    "frame.magic",
    "frame.header.descriptor",
    "frame.header.content_size_flag",
    "frame.header.single_segment_flag",
    "frame.header.checksum_flag",
    "frame.header.dictionary_id_flag",
    "frame.header.window_descriptor",
    "frame.header.dictionary_id",
    "frame.header.content_size",
    "block.header.last_block",
    "block.header.type",
    "block.header.size",
    "block.content",
    "block.literals",
    "block.sequences",
    "block.previous_window",
    "block.previous_entropy_tables",
    "frame.decoded_content",
    "frame.content_checksum",
    "frame.sequence",
    "skippable.magic",
    "skippable.frame_size",
    "skippable.user_data",
    "archive.trailing_data",
];

fn compression_base<'py>(
    py: Python<'py>,
    format: &str,
    ext: &str,
    magic: bool,
) -> PyResult<Bound<'py, PyDict>> {
    let d = dict(py)?;
    d.set_item("plausible", false)?;
    d.set_item("error", "")?;
    d.set_item("magic_matched", magic)?;
    d.set_item("format", format)?;
    d.set_item("detected_ext", ext)?;
    d.set_item("confidence", "none")?;
    d.set_item("evidence", PyList::empty(py))?;
    Ok(d)
}

fn finish_fields(d: &Bound<'_, PyDict>, fields: &[&str]) -> PyResult<()> {
    let missing = PyList::empty(d.py());
    for field in fields {
        if !d.contains(field)? {
            d.set_item(field, "unavailable")?;
            missing.append(field)?;
        }
    }
    d.set_item("semantic_field_count", fields.len())?;
    d.set_item("semantic_fields", PyList::new(d.py(), fields)?)?;
    d.set_item("semantic_missing_fields", missing)?;
    Ok(())
}

fn compression_empty(
    py: Python<'_>,
    error: &str,
    format: &str,
    ext: &str,
    magic: bool,
) -> PyResult<Py<PyDict>> {
    let d = compression_base(py, format, ext, magic)?;
    d.set_item("error", error)?;
    Ok(d.unbind())
}

fn hex_bytes(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}

fn c_string(data: &[u8], cursor: &mut usize) -> Option<String> {
    let start = *cursor;
    let rel = data.get(start..)?.iter().position(|b| *b == 0)?;
    *cursor = start + rel + 1;
    Some(String::from_utf8_lossy(&data[start..start + rel]).into_owned())
}

fn parse_gzip_header(data: &[u8], start: usize) -> Result<(usize, u8), &'static str> {
    if data.len() < start + 10 {
        return Err("short_gzip_header");
    }
    if &data[start..start + 3] != b"\x1f\x8b\x08" {
        return Err("gzip_magic_not_found");
    }
    let flags = data[start + 3];
    if flags & 0xe0 != 0 {
        return Err("gzip_reserved_flags_set");
    }
    let mut cursor = start + 10;
    if flags & 0x04 != 0 {
        if data.len() < cursor + 2 {
            return Err("gzip_extra_length_missing");
        }
        let length = u16::from_le_bytes([data[cursor], data[cursor + 1]]) as usize;
        cursor += 2;
        if data.len() < cursor + length {
            return Err("gzip_extra_out_of_range");
        }
        cursor += length;
    }
    if flags & 0x08 != 0 {
        c_string(data, &mut cursor).ok_or("gzip_name_unterminated")?;
    }
    if flags & 0x10 != 0 {
        c_string(data, &mut cursor).ok_or("gzip_comment_unterminated")?;
    }
    if flags & 0x02 != 0 {
        if data.len() < cursor + 2 {
            return Err("gzip_header_crc_missing");
        }
        cursor += 2;
    }
    Ok((cursor, flags))
}

fn inspect_gzip_bounded(
    py: Python<'_>,
    path: &str,
    header: &[u8],
    file_size: u64,
) -> PyResult<Py<PyDict>> {
    let data = match read_prefix(path, STREAM_STRUCTURE_HEAD_BYTES) {
        Ok(data) => data,
        Err(_) => {
            return compression_empty(
                py,
                "os_error",
                "gzip",
                ".gz",
                header.starts_with(b"\x1f\x8b"),
            )
        }
    };
    let (_, tail) = read_suffix(path, file_size, 64).unwrap_or((file_size, Vec::new()));
    let magic = data.starts_with(b"\x1f\x8b\x08");
    let d = compression_base(py, "gzip", ".gz", magic)?;
    let mut damage_flags = Vec::new();
    d.set_item("validation_scope", "bounded_structure")?;
    d.set_item("validation_complete", false)?;
    d.set_item(
        "member.header.magic",
        hex_bytes(data.get(0..2).unwrap_or(&[])),
    )?;
    let (payload_start, flags) = match parse_gzip_header(&data, 0) {
        Ok(value) => value,
        Err(error) => {
            d.set_item("error", error)?;
            d.set_item("damage_flags", PyList::new(py, damage_flags)?)?;
            finish_fields(&d, GZIP_FIELDS)?;
            return Ok(d.unbind());
        }
    };
    d.set_item("member.header.compression_method", data[2])?;
    d.set_item("member.header.flags", flags)?;
    d.set_item(
        "member.header.mtime_xfl_os",
        format!("mtime={};xfl={};os={}", u32_le(&data, 4), data[8], data[9]),
    )?;
    let mut cursor = 10usize;
    if flags & 0x04 != 0 {
        let length = u16_le(&data, cursor) as usize;
        d.set_item("member.header.extra_length", length)?;
        cursor += 2;
        d.set_item(
            "member.header.extra",
            hex_bytes(data.get(cursor..cursor + length).unwrap_or(&[])),
        )?;
        cursor += length;
    } else {
        d.set_item("member.header.extra_length", 0)?;
        d.set_item("member.header.extra", "absent")?;
    }
    if flags & 0x08 != 0 {
        d.set_item(
            "member.header.name",
            c_string(&data, &mut cursor).unwrap_or_default(),
        )?;
    } else {
        d.set_item("member.header.name", "absent")?;
    }
    if flags & 0x10 != 0 {
        d.set_item(
            "member.header.comment",
            c_string(&data, &mut cursor).unwrap_or_default(),
        )?;
    } else {
        d.set_item("member.header.comment", "absent")?;
    }
    if flags & 0x02 != 0 {
        let stored = u16_le(&data, cursor);
        let computed = (crc32(&data[..cursor]) & 0xffff) as u16;
        let ok = stored == computed;
        d.set_item(
            "member.header.crc16",
            format!("stored={stored};computed={computed};ok={ok}"),
        )?;
        if !ok {
            damage_flags.push("gzip_header_crc_bad");
        }
    } else {
        d.set_item("member.header.crc16", "absent")?;
    }
    d.set_item(
        "member.deflate.blocks",
        format!("payload_offset={payload_start};validation=deferred"),
    )?;
    d.set_item("member.deflate.final_block", false)?;
    d.set_item("member.decoded_content", 0)?;
    if tail.len() >= 8 {
        let trailer = tail.len() - 8;
        d.set_item(
            "member.trailer.crc32",
            format!("stored={};computed=deferred", u32_le(&tail, trailer)),
        )?;
        d.set_item(
            "member.trailer.isize",
            format!("stored={};decoded_mod=deferred", u32_le(&tail, trailer + 4)),
        )?;
    }
    d.set_item("member.boundary", file_size)?;
    d.set_item("member.next_member", false)?;
    d.set_item("archive.trailing_data", 0)?;
    d.set_item("trailing_data_verified", false)?;
    d.set_item("plausible", magic)?;
    d.set_item("confidence", if magic { "medium" } else { "none" })?;
    d.set_item("damage_flags", PyList::new(py, damage_flags)?)?;
    d.set_item("file_size", file_size)?;
    finish_fields(&d, GZIP_FIELDS)?;
    Ok(d.unbind())
}

fn inspect_gzip(py: Python<'_>, path: &str, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size > FULL_STREAM_STRUCTURE_MAX_BYTES {
        return inspect_gzip_bounded(py, path, header, file_size);
    }
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(_) => {
            return compression_empty(
                py,
                "os_error",
                "gzip",
                ".gz",
                header.starts_with(b"\x1f\x8b"),
            )
        }
    };
    let d = compression_base(py, "gzip", ".gz", data.starts_with(b"\x1f\x8b"))?;
    let mut damage_flags = Vec::new();
    d.set_item(
        "member.header.magic",
        hex_bytes(data.get(0..2).unwrap_or(&[])),
    )?;
    let (payload_start, flags) = match parse_gzip_header(&data, 0) {
        Ok(value) => value,
        Err(error) => {
            d.set_item("error", error)?;
            finish_fields(&d, GZIP_FIELDS)?;
            return Ok(d.unbind());
        }
    };
    d.set_item("member.header.compression_method", data[2])?;
    d.set_item("member.header.flags", flags)?;
    d.set_item(
        "member.header.mtime_xfl_os",
        format!("mtime={};xfl={};os={}", u32_le(&data, 4), data[8], data[9]),
    )?;
    let mut cursor = 10usize;
    if flags & 0x04 != 0 {
        let length = u16_le(&data, cursor) as usize;
        d.set_item("member.header.extra_length", length)?;
        cursor += 2;
        d.set_item(
            "member.header.extra",
            hex_bytes(&data[cursor..cursor + length]),
        )?;
        cursor += length;
    } else {
        d.set_item("member.header.extra_length", 0)?;
        d.set_item("member.header.extra", "absent")?;
    }
    if flags & 0x08 != 0 {
        d.set_item(
            "member.header.name",
            c_string(&data, &mut cursor).unwrap_or_default(),
        )?;
    } else {
        d.set_item("member.header.name", "absent")?;
    }
    if flags & 0x10 != 0 {
        d.set_item(
            "member.header.comment",
            c_string(&data, &mut cursor).unwrap_or_default(),
        )?;
    } else {
        d.set_item("member.header.comment", "absent")?;
    }
    if flags & 0x02 != 0 {
        let stored = u16_le(&data, cursor);
        let computed = (crc32(&data[..cursor]) & 0xffff) as u16;
        let ok = stored == computed;
        d.set_item(
            "member.header.crc16",
            format!("stored={stored};computed={computed};ok={ok}"),
        )?;
        if !ok {
            damage_flags.push("gzip_header_crc_bad");
        }
    } else {
        d.set_item("member.header.crc16", "absent")?;
    }

    let inflater = flate2::read::DeflateDecoder::new(Cursor::new(&data[payload_start..]));
    let mut limited_inflater = inflater.take(STREAM_STRUCTURE_DECODE_MAX_BYTES + 1);
    let mut decoded = Vec::new();
    let status = limited_inflater.read_to_end(&mut decoded);
    let inflater = limited_inflater.into_inner();
    let decode_limited = decoded.len() as u64 > STREAM_STRUCTURE_DECODE_MAX_BYTES;
    let deflate_len = inflater.total_in() as usize;
    let boundary = payload_start.saturating_add(deflate_len).saturating_add(8);
    let stream_end = status.is_ok() && !decode_limited && boundary <= data.len();
    d.set_item(
        "member.deflate.blocks",
        format!("compressed_bytes={deflate_len};decoder_status={status:?}"),
    )?;
    d.set_item("member.deflate.final_block", stream_end)?;
    d.set_item("member.decoded_content", decoded.len())?;
    if stream_end && boundary <= data.len() && boundary >= 8 {
        let trailer = boundary - 8;
        let stored_crc = u32_le(&data, trailer);
        let stored_size = u32_le(&data, trailer + 4);
        let footer_ok = stored_crc == crc32(&decoded) && stored_size == decoded.len() as u32;
        d.set_item(
            "member.trailer.crc32",
            format!(
                "stored={stored_crc};computed={};ok={}",
                crc32(&decoded),
                stored_crc == crc32(&decoded)
            ),
        )?;
        d.set_item(
            "member.trailer.isize",
            format!(
                "stored={stored_size};decoded_mod={};ok={}",
                decoded.len() as u32,
                stored_size == decoded.len() as u32
            ),
        )?;
        if !footer_ok {
            damage_flags.push("gzip_footer_bad");
        }
    }
    d.set_item("validation_complete", stream_end)?;
    d.set_item("member.boundary", boundary.min(data.len()))?;
    let next_member =
        stream_end && boundary + 2 <= data.len() && &data[boundary..boundary + 2] == b"\x1f\x8b";
    d.set_item("member.next_member", next_member)?;
    let trailing = if decode_limited || next_member {
        0
    } else {
        data.len().saturating_sub(boundary)
    };
    d.set_item("archive.trailing_data", trailing)?;
    if trailing > 0 {
        damage_flags.push("trailing_junk");
    }
    d.set_item("trailing_data_verified", stream_end)?;
    d.set_item(
        "plausible",
        stream_end || (decode_limited && data.starts_with(b"\x1f\x8b\x08")),
    )?;
    d.set_item("confidence", if stream_end { "strong" } else { "medium" })?;
    if !stream_end && !decode_limited {
        d.set_item("error", "gzip_deflate_or_trailer_incomplete")?;
        damage_flags.push("probably_truncated");
    }
    d.set_item("damage_flags", PyList::new(py, damage_flags)?)?;
    d.set_item("file_size", file_size)?;
    finish_fields(&d, GZIP_FIELDS)?;
    Ok(d.unbind())
}

struct BitReader<'a> {
    data: &'a [u8],
    bit: usize,
}
impl<'a> BitReader<'a> {
    fn read(&mut self, bits: usize) -> Option<u64> {
        if self.bit + bits > self.data.len() * 8 {
            return None;
        }
        let mut value = 0u64;
        for _ in 0..bits {
            value = (value << 1) | ((self.data[self.bit / 8] >> (7 - self.bit % 8)) & 1) as u64;
            self.bit += 1;
        }
        Some(value)
    }
}

fn marker_positions(data: &[u8], marker: u64) -> Vec<usize> {
    let mut output = Vec::new();
    let mut window = 0u64;
    for bit in 0..data.len() * 8 {
        window = ((window << 1) | ((data[bit / 8] >> (7 - bit % 8)) & 1) as u64) & 0xffff_ffff_ffff;
        if bit >= 47 && window == marker {
            output.push(bit + 1 - 48);
        }
    }
    output
}

fn bzip_huffman_summary(data: &[u8], start_bit: usize) -> String {
    let mut reader = BitReader {
        data,
        bit: start_bit,
    };
    let mut groups = 0usize;
    if let Some(in_use16) = reader.read(16) {
        let mut symbols = 0usize;
        for group in 0..16 {
            if in_use16 & (1 << (15 - group)) != 0 {
                if let Some(bits) = reader.read(16) {
                    symbols += bits.count_ones() as usize;
                } else {
                    return "truncated".into();
                }
            }
        }
        groups = reader.read(3).unwrap_or(0) as usize;
        let selectors = reader.read(15).unwrap_or(0);
        return format!("symbols={symbols};groups={groups};selectors={selectors}");
    }
    format!("groups={groups};truncated")
}

fn inspect_bzip2_bounded(
    py: Python<'_>,
    path: &str,
    header: &[u8],
    file_size: u64,
) -> PyResult<Py<PyDict>> {
    let data = match read_prefix(path, STREAM_STRUCTURE_HEAD_BYTES) {
        Ok(data) => data,
        Err(_) => {
            return compression_empty(py, "os_error", "bzip2", ".bz2", header.starts_with(b"BZh"))
        }
    };
    let (tail_start, tail) = read_suffix(path, file_size, STREAM_STRUCTURE_TAIL_BYTES)
        .unwrap_or((file_size, Vec::new()));
    let magic = data.starts_with(b"BZh") && data.get(3).is_some_and(|v| b"123456789".contains(v));
    let d = compression_base(py, "bzip2", ".bz2", magic)?;
    let mut damage_flags = Vec::new();
    d.set_item("validation_scope", "bounded_structure")?;
    d.set_item("validation_complete", false)?;
    d.set_item(
        "stream.magic",
        String::from_utf8_lossy(data.get(0..3).unwrap_or(&[])).to_string(),
    )?;
    d.set_item(
        "stream.block_size_100k",
        data.get(3).map(|v| v.saturating_sub(b'0')).unwrap_or(0),
    )?;
    if !magic {
        d.set_item("error", "bzip2_magic_not_found")?;
        d.set_item("damage_flags", PyList::new(py, damage_flags)?)?;
        finish_fields(&d, BZIP2_FIELDS)?;
        return Ok(d.unbind());
    }
    let blocks = marker_positions(&data, 0x314159265359);
    let tail_ends = marker_positions(&tail, 0x177245385090);
    let global_end = tail_ends.first().map(|bit| tail_start as usize * 8 + *bit);
    d.set_item(
        "block.marker",
        blocks.first().map(|v| *v as u64).unwrap_or(u64::MAX),
    )?;
    d.set_item("block.sequence", blocks.len())?;
    if let Some(bit) = blocks.first() {
        let mut reader = BitReader {
            data: &data,
            bit: bit + 48,
        };
        d.set_item("block.crc32", reader.read(32).unwrap_or(0) as u32)?;
        d.set_item("block.randomized", reader.read(1).unwrap_or(0) != 0)?;
        d.set_item("block.orig_ptr", reader.read(24).unwrap_or(0))?;
        d.set_item(
            "block.huffman_tables",
            bzip_huffman_summary(&data, reader.bit),
        )?;
        d.set_item(
            "block.encoded_data",
            global_end
                .unwrap_or(file_size as usize * 8)
                .saturating_sub(reader.bit),
        )?;
    }
    d.set_item("stream.end_marker", global_end.is_some())?;
    if let Some(local_bit) = tail_ends.first() {
        let mut reader = BitReader {
            data: &tail,
            bit: *local_bit + 48,
        };
        d.set_item("stream.combined_crc32", reader.read(32).unwrap_or(0) as u32)?;
    }
    d.set_item("block.decoded_content", 0)?;
    let trailing = global_end
        .map(|bit| file_size.saturating_sub(((bit + 48 + 32 + 7) / 8) as u64))
        .unwrap_or(0);
    d.set_item("archive.trailing_data", trailing)?;
    d.set_item("trailing_data_verified", global_end.is_some())?;
    if trailing > 0 {
        damage_flags.push("trailing_junk");
    }
    let plausible = magic && !blocks.is_empty();
    d.set_item("plausible", plausible)?;
    d.set_item(
        "confidence",
        if global_end.is_some() {
            "medium"
        } else {
            "weak"
        },
    )?;
    d.set_item("damage_flags", PyList::new(py, damage_flags)?)?;
    d.set_item("file_size", file_size)?;
    finish_fields(&d, BZIP2_FIELDS)?;
    Ok(d.unbind())
}

fn inspect_bzip2(
    py: Python<'_>,
    path: &str,
    header: &[u8],
    file_size: u64,
) -> PyResult<Py<PyDict>> {
    if file_size > FULL_STREAM_STRUCTURE_MAX_BYTES {
        return inspect_bzip2_bounded(py, path, header, file_size);
    }
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(_) => {
            return compression_empty(py, "os_error", "bzip2", ".bz2", header.starts_with(b"BZh"))
        }
    };
    let magic = data.starts_with(b"BZh") && data.get(3).is_some_and(|v| b"123456789".contains(v));
    let d = compression_base(py, "bzip2", ".bz2", magic)?;
    let mut damage_flags = Vec::new();
    d.set_item(
        "stream.magic",
        String::from_utf8_lossy(data.get(0..3).unwrap_or(&[])).to_string(),
    )?;
    d.set_item(
        "stream.block_size_100k",
        data.get(3).map(|v| v.saturating_sub(b'0')).unwrap_or(0),
    )?;
    if !magic {
        d.set_item("error", "bzip2_magic_not_found")?;
        finish_fields(&d, BZIP2_FIELDS)?;
        return Ok(d.unbind());
    }
    let blocks = marker_positions(&data, 0x314159265359);
    let ends = marker_positions(&data, 0x177245385090);
    d.set_item(
        "block.marker",
        blocks.first().map(|v| *v as u64).unwrap_or(u64::MAX),
    )?;
    d.set_item("block.sequence", blocks.len())?;
    if let Some(bit) = blocks.first() {
        let mut reader = BitReader {
            data: &data,
            bit: bit + 48,
        };
        let block_crc = reader.read(32).unwrap_or(0) as u32;
        let randomized = reader.read(1).unwrap_or(0) != 0;
        let orig_ptr = reader.read(24).unwrap_or(0);
        d.set_item("block.crc32", block_crc)?;
        d.set_item("block.randomized", randomized)?;
        d.set_item("block.orig_ptr", orig_ptr)?;
        d.set_item(
            "block.huffman_tables",
            bzip_huffman_summary(&data, reader.bit),
        )?;
        let end_bit = blocks
            .get(1)
            .copied()
            .or_else(|| ends.first().copied())
            .unwrap_or(data.len() * 8);
        d.set_item("block.encoded_data", end_bit.saturating_sub(reader.bit))?;
    }
    d.set_item("stream.end_marker", !ends.is_empty())?;
    if let Some(bit) = ends.first() {
        let mut reader = BitReader {
            data: &data,
            bit: bit + 48,
        };
        d.set_item("stream.combined_crc32", reader.read(32).unwrap_or(0) as u32)?;
    }
    let decoder = bzip2::read::BzDecoder::new(Cursor::new(data.as_slice()));
    let mut limited_decoder = decoder.take(STREAM_STRUCTURE_DECODE_MAX_BYTES + 1);
    let mut decoded = Vec::new();
    let decode_status = limited_decoder.read_to_end(&mut decoded);
    let decoder = limited_decoder.into_inner();
    let decode_limited = decoded.len() as u64 > STREAM_STRUCTURE_DECODE_MAX_BYTES;
    let decode_ok = decode_status.is_ok() && !decode_limited;
    let marker_boundary = ends
        .first()
        .map(|bit| (bit + 48 + 32 + 7) / 8)
        .unwrap_or(data.len());
    let consumed = decoder.get_ref().position() as usize;
    d.set_item("block.decoded_content", decoded.len())?;
    let trailing = if decode_limited {
        0
    } else {
        data.len().saturating_sub(marker_boundary.min(consumed))
    };
    d.set_item("archive.trailing_data", trailing)?;
    if trailing > 0 {
        damage_flags.push("trailing_junk");
    }
    d.set_item("validation_complete", decode_ok)?;
    d.set_item("trailing_data_verified", decode_ok)?;
    d.set_item(
        "plausible",
        (decode_ok && !ends.is_empty()) || (decode_limited && magic),
    )?;
    d.set_item("confidence", if decode_ok { "strong" } else { "medium" })?;
    if ends.is_empty() && !decode_limited {
        damage_flags.push("probably_truncated");
    }
    if !decode_ok && !decode_limited {
        d.set_item("error", "bzip2_decode_failed")?;
        damage_flags.push("bzip2_block_bad");
    }
    d.set_item("damage_flags", PyList::new(py, damage_flags)?)?;
    d.set_item("file_size", file_size)?;
    finish_fields(&d, BZIP2_FIELDS)?;
    Ok(d.unbind())
}

fn read_vli(data: &[u8], cursor: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0usize;
    loop {
        let byte = *data.get(*cursor)?;
        *cursor += 1;
        if shift >= 63 || (shift > 0 && byte == 0) {
            return None;
        }
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
}

fn xz_check_size(check_type: u8) -> usize {
    match check_type {
        0 => 0,
        1 => 4,
        4 => 8,
        10 => 32,
        _ => 0,
    }
}

fn inspect_xz_bounded(
    py: Python<'_>,
    path: &str,
    header: &[u8],
    file_size: u64,
) -> PyResult<Py<PyDict>> {
    let data = match read_prefix(path, STREAM_STRUCTURE_HEAD_BYTES) {
        Ok(data) => data,
        Err(_) => {
            return compression_empty(py, "os_error", "xz", ".xz", header.starts_with(XZ_MAGIC))
        }
    };
    let (tail_start, tail) = read_suffix(path, file_size, STREAM_STRUCTURE_TAIL_BYTES)
        .unwrap_or((file_size, Vec::new()));
    let magic = data.starts_with(XZ_MAGIC);
    let d = compression_base(py, "xz", ".xz", magic)?;
    let mut damage_flags = Vec::new();
    d.set_item("validation_scope", "bounded_structure")?;
    d.set_item("validation_complete", false)?;
    d.set_item(
        "stream.header.magic",
        hex_bytes(data.get(..6).unwrap_or(&[])),
    )?;
    if data.len() < 12 || !magic {
        d.set_item("error", "xz_header_missing")?;
        d.set_item("damage_flags", PyList::new(py, damage_flags)?)?;
        finish_fields(&d, XZ_FIELDS)?;
        return Ok(d.unbind());
    }
    let flags = &data[6..8];
    let header_crc = u32_le(&data, 8);
    let header_crc_ok = header_crc == crc32(flags);
    d.set_item("stream.header.flags", hex_bytes(flags))?;
    d.set_item(
        "stream.header.crc32",
        format!(
            "stored={header_crc};computed={};ok={header_crc_ok}",
            crc32(flags)
        ),
    )?;
    if !header_crc_ok {
        damage_flags.push("xz_header_crc_bad");
    }
    let footer_local = (10..tail.len()).rev().find_map(|magic_end| {
        if tail.get(magic_end - 1..=magic_end) != Some(b"YZ".as_slice()) || magic_end + 1 < 12 {
            return None;
        }
        let start = magic_end + 1 - 12;
        let footer = &tail[start..start + 12];
        (u32_le(footer, 0) == crc32(&footer[4..10])).then_some(start)
    });
    let mut footer_valid = false;
    let mut trailing = 0u64;
    if let Some(local_start) = footer_local {
        let footer = &tail[local_start..local_start + 12];
        let footer_crc = u32_le(footer, 0);
        let backward_size = (u32_le(footer, 4) as u64 + 1) * 4;
        footer_valid = footer_crc == crc32(&footer[4..10]) && &footer[8..10] == flags;
        d.set_item(
            "stream.footer.crc32",
            format!(
                "stored={footer_crc};computed={};ok={}",
                crc32(&footer[4..10]),
                footer_crc == crc32(&footer[4..10])
            ),
        )?;
        d.set_item("stream.footer.backward_size", backward_size)?;
        d.set_item("stream.footer.flags", hex_bytes(&footer[8..10]))?;
        d.set_item("stream.footer.magic", hex_bytes(&footer[10..12]))?;
        let after_footer = local_start + 12;
        let zero_padding = tail[after_footer..].iter().take_while(|b| **b == 0).count();
        let aligned_padding = zero_padding - zero_padding % 4;
        d.set_item("stream.padding", aligned_padding)?;
        let global_after_padding = tail_start + (after_footer + aligned_padding) as u64;
        trailing = file_size.saturating_sub(global_after_padding);
        if &footer[8..10] != flags {
            damage_flags.push("xz_stream_flags_mismatch");
        }
    }
    if data.len() >= 14 {
        let block_cursor = 12usize;
        let header_size = (data[block_cursor] as usize + 1) * 4;
        if header_size >= 8 && block_cursor + header_size <= data.len() {
            let block_flags = data[block_cursor + 1];
            d.set_item("block.header.size", header_size)?;
            d.set_item("block.header.flags", block_flags)?;
            d.set_item(
                "block.header.crc32",
                format!(
                    "stored={};computed={}",
                    u32_le(&data, block_cursor + header_size - 4),
                    crc32(&data[block_cursor..block_cursor + header_size - 4])
                ),
            )?;
            d.set_item("block.header.filters", "bounded_header")?;
        }
    }
    d.set_item("block.header.compressed_size", 0)?;
    d.set_item("block.header.uncompressed_size", 0)?;
    d.set_item("block.compressed_data", file_size)?;
    d.set_item("block.uncompressed_data", 0)?;
    d.set_item("block.padding", 0)?;
    d.set_item(
        "block.check",
        format!(
            "type={};size={}",
            flags[1] & 0x0f,
            xz_check_size(flags[1] & 0x0f)
        ),
    )?;
    d.set_item("block.sequence", 1)?;
    d.set_item("index.indicator", footer_local.is_some())?;
    d.set_item("index.record_count", 0)?;
    d.set_item("index.records.unpadded_size", 0)?;
    d.set_item("index.records.uncompressed_size", 0)?;
    d.set_item("index.padding", 0)?;
    d.set_item("index.crc32", "deferred")?;
    d.set_item("archive.stream_sequence", 1)?;
    d.set_item("archive.trailing_data", trailing)?;
    d.set_item("trailing_data_verified", footer_local.is_some())?;
    if trailing > 0 {
        damage_flags.push("trailing_junk");
    }
    let valid = magic && header_crc_ok && footer_valid;
    d.set_item("plausible", valid)?;
    d.set_item("confidence", if valid { "medium" } else { "weak" })?;
    if footer_local.is_none() {
        d.set_item("error", "xz_footer_not_in_bounded_tail")?;
    }
    d.set_item("damage_flags", PyList::new(py, damage_flags)?)?;
    d.set_item("file_size", file_size)?;
    finish_fields(&d, XZ_FIELDS)?;
    Ok(d.unbind())
}

fn inspect_xz(py: Python<'_>, path: &str, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size > FULL_STREAM_STRUCTURE_MAX_BYTES {
        return inspect_xz_bounded(py, path, header, file_size);
    }
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(_) => {
            return compression_empty(py, "os_error", "xz", ".xz", header.starts_with(XZ_MAGIC))
        }
    };
    let d = compression_base(py, "xz", ".xz", data.starts_with(XZ_MAGIC))?;
    let mut damage_flags = Vec::new();
    d.set_item(
        "stream.header.magic",
        hex_bytes(data.get(..6).unwrap_or(&[])),
    )?;
    if data.len() < 24 || !data.starts_with(XZ_MAGIC) {
        d.set_item("error", "xz_header_or_footer_missing")?;
        finish_fields(&d, XZ_FIELDS)?;
        return Ok(d.unbind());
    }
    let flags = &data[6..8];
    let header_crc = u32_le(&data, 8);
    d.set_item("stream.header.flags", hex_bytes(flags))?;
    d.set_item(
        "stream.header.crc32",
        format!(
            "stored={header_crc};computed={};ok={}",
            crc32(flags),
            header_crc == crc32(flags)
        ),
    )?;
    if header_crc != crc32(flags) {
        damage_flags.push("xz_header_crc_bad");
    }

    let footer_start = (10..data.len())
        .rev()
        .find_map(|magic_end| {
            if data.get(magic_end - 1..=magic_end) != Some(b"YZ".as_slice()) || magic_end + 1 < 12 {
                return None;
            }
            let start = magic_end + 1 - 12;
            let footer = &data[start..start + 12];
            (u32_le(footer, 0) == crc32(&footer[4..10])).then_some(start)
        })
        .unwrap_or(data.len() - 12);
    let footer = &data[footer_start..];
    let footer_crc = u32_le(footer, 0);
    let backward_size = (u32_le(footer, 4) as u64 + 1) * 4;
    d.set_item(
        "stream.footer.crc32",
        format!(
            "stored={footer_crc};computed={};ok={}",
            crc32(&footer[4..10]),
            footer_crc == crc32(&footer[4..10])
        ),
    )?;
    if footer_crc != crc32(&footer[4..10]) {
        damage_flags.push("xz_footer_crc_bad");
    }
    if &footer[8..10] != flags {
        damage_flags.push("xz_stream_flags_mismatch");
    }
    d.set_item("stream.footer.backward_size", backward_size)?;
    d.set_item("stream.footer.flags", hex_bytes(&footer[8..10]))?;
    d.set_item("stream.footer.magic", hex_bytes(&footer[10..12]))?;
    let index_start = footer_start
        .checked_sub(backward_size as usize)
        .unwrap_or(0);
    let mut index_cursor = index_start;
    let index_valid_start = data.get(index_cursor) == Some(&0);
    d.set_item("index.indicator", index_valid_start)?;
    if !index_valid_start {
        damage_flags.push("xz_index_bad");
    }
    index_cursor = index_cursor.saturating_add(1);
    let record_count = read_vli(&data, &mut index_cursor).unwrap_or(0) as usize;
    d.set_item("index.record_count", record_count)?;
    let mut records = Vec::new();
    for _ in 0..record_count {
        let unpadded = read_vli(&data, &mut index_cursor).unwrap_or(0);
        let uncompressed = read_vli(&data, &mut index_cursor).unwrap_or(0);
        records.push((unpadded, uncompressed));
    }
    d.set_item(
        "index.records.unpadded_size",
        records.iter().map(|r| r.0).sum::<u64>(),
    )?;
    d.set_item(
        "index.records.uncompressed_size",
        records.iter().map(|r| r.1).sum::<u64>(),
    )?;
    let index_crc_pos = footer_start.saturating_sub(4);
    d.set_item("index.padding", index_crc_pos.saturating_sub(index_cursor))?;
    if index_crc_pos + 4 <= data.len() && index_start <= index_crc_pos {
        let stored = u32_le(&data, index_crc_pos);
        let ok = stored == crc32(&data[index_start..index_crc_pos]);
        d.set_item(
            "index.crc32",
            format!(
                "stored={stored};computed={};ok={ok}",
                crc32(&data[index_start..index_crc_pos])
            ),
        )?;
        if !ok {
            damage_flags.push("xz_index_bad");
        }
    }

    let mut block_cursor = 12usize;
    let mut block_count = 0usize;
    let mut total_compressed = 0u64;
    let mut total_padding = 0usize;
    let mut first_filters = String::new();
    let check_size = xz_check_size(flags[1] & 0x0f);
    for (unpadded, expected_uncompressed) in &records {
        if block_cursor >= index_start {
            break;
        }
        let header_size = (data[block_cursor] as usize + 1) * 4;
        if block_cursor + header_size > data.len() || header_size < 8 {
            break;
        }
        let block_flags = data[block_cursor + 1];
        let mut c = block_cursor + 2;
        let declared_compressed = if block_flags & 0x40 != 0 {
            read_vli(&data, &mut c)
        } else {
            None
        };
        let declared_uncompressed = if block_flags & 0x80 != 0 {
            read_vli(&data, &mut c)
        } else {
            None
        };
        let filter_count = (block_flags & 0x03) as usize + 1;
        let mut filters = Vec::new();
        for _ in 0..filter_count {
            let id = read_vli(&data, &mut c).unwrap_or(0);
            let prop_size = read_vli(&data, &mut c).unwrap_or(0) as usize;
            let props_end = c
                .saturating_add(prop_size)
                .min(block_cursor + header_size - 4);
            filters.push(format!("id={id}:props={}", hex_bytes(&data[c..props_end])));
            c = props_end;
        }
        if first_filters.is_empty() {
            first_filters = filters.join(",");
        }
        let stored_header_crc = u32_le(&data, block_cursor + header_size - 4);
        if block_count == 0 {
            d.set_item("block.header.size", header_size)?;
            d.set_item("block.header.flags", block_flags)?;
            d.set_item(
                "block.header.compressed_size",
                declared_compressed
                    .unwrap_or(unpadded.saturating_sub(header_size as u64 + check_size as u64)),
            )?;
            d.set_item(
                "block.header.uncompressed_size",
                declared_uncompressed.unwrap_or(*expected_uncompressed),
            )?;
            d.set_item(
                "block.header.crc32",
                format!(
                    "stored={stored_header_crc};computed={};ok={}",
                    crc32(&data[block_cursor..block_cursor + header_size - 4]),
                    stored_header_crc == crc32(&data[block_cursor..block_cursor + header_size - 4])
                ),
            )?;
        }
        let compressed_size = declared_compressed
            .unwrap_or(unpadded.saturating_sub(header_size as u64 + check_size as u64));
        total_compressed += compressed_size;
        let unpadded_actual = header_size as u64 + compressed_size + check_size as u64;
        let padding = ((4 - unpadded_actual % 4) % 4) as usize;
        total_padding += padding;
        block_cursor = block_cursor.saturating_add(unpadded_actual as usize + padding);
        block_count += 1;
    }
    d.set_item("block.header.filters", first_filters)?;
    d.set_item("block.compressed_data", total_compressed)?;
    d.set_item("block.padding", total_padding)?;
    d.set_item(
        "block.check",
        format!("type={};size={check_size}", flags[1] & 0x0f),
    )?;
    d.set_item("block.sequence", block_count)?;
    let decoder = xz2::read::XzDecoder::new(Cursor::new(data.as_slice()));
    let mut limited_decoder = decoder.take(STREAM_STRUCTURE_DECODE_MAX_BYTES + 1);
    let mut decoded = Vec::new();
    let decode_status = limited_decoder.read_to_end(&mut decoded);
    let decode_limited = decoded.len() as u64 > STREAM_STRUCTURE_DECODE_MAX_BYTES;
    let decode_ok = decode_status.is_ok() && !decode_limited;
    d.set_item("block.uncompressed_data", decoded.len())?;
    let stream_count = data.windows(6).filter(|w| *w == XZ_MAGIC).count();
    d.set_item("archive.stream_sequence", stream_count)?;
    let after_footer = footer_start + 12;
    let zero_padding = data[after_footer..].iter().take_while(|b| **b == 0).count();
    let aligned_padding = zero_padding - zero_padding % 4;
    d.set_item("stream.padding", aligned_padding)?;
    let trailing = data.len().saturating_sub(after_footer + aligned_padding);
    d.set_item("archive.trailing_data", trailing)?;
    if trailing > 0 {
        damage_flags.push("trailing_junk");
    }
    let valid = (decode_ok || decode_limited)
        && &footer[10..12] == b"YZ"
        && &footer[8..10] == flags
        && index_valid_start;
    d.set_item("validation_complete", decode_ok)?;
    d.set_item("plausible", valid)?;
    d.set_item("confidence", if valid { "strong" } else { "medium" })?;
    if !valid {
        d.set_item("error", "xz_structural_validation_failed")?;
    }
    d.set_item("damage_flags", PyList::new(py, damage_flags)?)?;
    d.set_item("file_size", file_size)?;
    finish_fields(&d, XZ_FIELDS)?;
    Ok(d.unbind())
}

fn zstd_field_size(flag: u8, single: bool, content_size: bool) -> usize {
    if !content_size {
        return 0;
    }
    match flag {
        0 if single => 1,
        0 => 0,
        1 => 2,
        2 => 4,
        _ => 8,
    }
}

fn little_uint(data: &[u8]) -> u64 {
    data.iter()
        .enumerate()
        .fold(0u64, |v, (i, b)| v | ((*b as u64) << (8 * i)))
}

fn inspect_zstd_bounded(
    py: Python<'_>,
    path: &str,
    header: &[u8],
    file_size: u64,
) -> PyResult<Py<PyDict>> {
    let data = match read_prefix(path, STREAM_STRUCTURE_HEAD_BYTES) {
        Ok(data) => data,
        Err(_) => {
            return compression_empty(
                py,
                "os_error",
                "zstd",
                ".zst",
                header.starts_with(ZSTD_MAGIC),
            )
        }
    };
    let magic = data.starts_with(ZSTD_MAGIC);
    let descriptor = data.get(4).copied().unwrap_or(0);
    let reserved_bit_clear = descriptor & 0x08 == 0;
    let d = compression_base(py, "zstd", ".zst", magic)?;
    d.set_item("validation_scope", "bounded_structure")?;
    d.set_item("validation_complete", false)?;
    d.set_item("frame.magic", hex_bytes(data.get(..4).unwrap_or(&[])))?;
    d.set_item("frame.header.descriptor", descriptor)?;
    d.set_item("frame.header.content_size_flag", descriptor >> 6)?;
    d.set_item("frame.header.single_segment_flag", descriptor & 0x20 != 0)?;
    d.set_item("frame.header.checksum_flag", descriptor & 0x04 != 0)?;
    d.set_item("frame.header.dictionary_id_flag", descriptor & 0x03)?;
    d.set_item("frame.decoded_content", 0)?;
    d.set_item("archive.trailing_data", 0)?;
    d.set_item("trailing_data_verified", false)?;
    d.set_item("plausible", magic && reserved_bit_clear)?;
    d.set_item(
        "confidence",
        if magic && reserved_bit_clear {
            "medium"
        } else {
            "none"
        },
    )?;
    d.set_item(
        "error",
        if reserved_bit_clear {
            ""
        } else {
            "zstd_reserved_bit_set"
        },
    )?;
    d.set_item(
        "damage_flags",
        PyList::new(
            py,
            if reserved_bit_clear {
                Vec::<&str>::new()
            } else {
                vec!["zstd_reserved_bit_set"]
            },
        )?,
    )?;
    d.set_item("file_size", file_size)?;
    finish_fields(&d, ZSTD_FIELDS)?;
    Ok(d.unbind())
}

fn inspect_zstd(py: Python<'_>, path: &str, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size > FULL_STREAM_STRUCTURE_MAX_BYTES {
        return inspect_zstd_bounded(py, path, header, file_size);
    }
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(_) => {
            return compression_empty(
                py,
                "os_error",
                "zstd",
                ".zst",
                header.starts_with(ZSTD_MAGIC),
            )
        }
    };
    let d = compression_base(py, "zstd", ".zst", data.starts_with(ZSTD_MAGIC))?;
    let mut damage_flags = Vec::new();
    d.set_item("frame.magic", hex_bytes(data.get(..4).unwrap_or(&[])))?;
    if data.len() < 6 || !data.starts_with(ZSTD_MAGIC) {
        d.set_item("error", "zstd_magic_or_header_missing")?;
        finish_fields(&d, ZSTD_FIELDS)?;
        return Ok(d.unbind());
    }
    let descriptor = data[4];
    let fcs_flag = descriptor >> 6;
    let single = descriptor & 0x20 != 0;
    let checksum = descriptor & 0x04 != 0;
    let dict_flag = descriptor & 0x03;
    d.set_item("frame.header.descriptor", descriptor)?;
    d.set_item("frame.header.content_size_flag", fcs_flag)?;
    d.set_item("frame.header.single_segment_flag", single)?;
    d.set_item("frame.header.checksum_flag", checksum)?;
    d.set_item("frame.header.dictionary_id_flag", dict_flag)?;
    let mut cursor = 5usize;
    if !single {
        let wd = data[cursor];
        cursor += 1;
        let exponent = (wd >> 3) as u32;
        let base = 1u64 << (10 + exponent);
        let window = base + (base / 8) * (wd & 7) as u64;
        d.set_item(
            "frame.header.window_descriptor",
            format!("raw={wd};window={window}"),
        )?;
    } else {
        d.set_item("frame.header.window_descriptor", "absent(single_segment)")?;
    }
    let dict_size = match dict_flag {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let dict_end = cursor.saturating_add(dict_size).min(data.len());
    d.set_item(
        "frame.header.dictionary_id",
        if dict_size == 0 {
            0
        } else {
            little_uint(&data[cursor..dict_end])
        },
    )?;
    cursor = dict_end;
    let fcs_size = zstd_field_size(fcs_flag, single, single || fcs_flag != 0);
    let fcs_end = cursor.saturating_add(fcs_size).min(data.len());
    let mut content_size = little_uint(&data[cursor..fcs_end]);
    if fcs_flag == 1 {
        content_size += 256;
    }
    d.set_item(
        "frame.header.content_size",
        if fcs_size == 0 {
            "absent".to_string()
        } else {
            content_size.to_string()
        },
    )?;
    cursor = fcs_end;
    let mut blocks = 0usize;
    let mut total_content = 0usize;
    let mut last = false;
    let mut first_type = 0u8;
    let mut first_size = 0usize;
    while cursor + 3 <= data.len() && !last {
        let h =
            data[cursor] as u32 | (data[cursor + 1] as u32) << 8 | (data[cursor + 2] as u32) << 16;
        cursor += 3;
        last = h & 1 != 0;
        let block_type = ((h >> 1) & 3) as u8;
        let block_size = (h >> 3) as usize;
        if blocks == 0 {
            first_type = block_type;
            first_size = block_size;
        }
        let stored_size = if block_type == 1 { 1 } else { block_size };
        if block_type == 3 || cursor + stored_size > data.len() {
            break;
        }
        total_content += stored_size;
        cursor += stored_size;
        blocks += 1;
    }
    d.set_item("block.header.last_block", last)?;
    d.set_item("block.header.type", first_type)?;
    d.set_item("block.header.size", first_size)?;
    d.set_item("block.content", total_content)?;
    d.set_item(
        "block.literals",
        if first_type == 2 {
            "compressed_block_literals_section"
        } else {
            "not_compressed_layout"
        },
    )?;
    d.set_item(
        "block.sequences",
        if first_type == 2 {
            "compressed_block_sequences_section"
        } else {
            "not_compressed_layout"
        },
    )?;
    d.set_item(
        "block.previous_window",
        if dict_size > 0 {
            "dictionary_or_previous_block"
        } else {
            "previous_blocks"
        },
    )?;
    d.set_item(
        "block.previous_entropy_tables",
        if first_type == 2 {
            "repeat_mode_possible"
        } else {
            "not_used"
        },
    )?;
    if checksum && cursor + 4 <= data.len() {
        d.set_item("frame.content_checksum", u32_le(&data, cursor))?;
        cursor += 4;
    } else {
        d.set_item("frame.content_checksum", "absent")?;
    }
    let mut decoded = Vec::new();
    let (decode_ok, decode_limited) =
        match zstd::stream::read::Decoder::new(Cursor::new(&data[..cursor])) {
            Ok(decoder) => {
                let mut limited_decoder = decoder.take(STREAM_STRUCTURE_DECODE_MAX_BYTES + 1);
                let status = limited_decoder.read_to_end(&mut decoded);
                let limited = decoded.len() as u64 > STREAM_STRUCTURE_DECODE_MAX_BYTES;
                (status.is_ok() && !limited, limited)
            }
            Err(_) => (false, false),
        };
    d.set_item("frame.decoded_content", decoded.len())?;
    d.set_item(
        "frame.sequence",
        data.windows(4).filter(|w| *w == ZSTD_MAGIC).count(),
    )?;
    let mut skippable_count = 0usize;
    let mut skip_size = 0usize;
    let mut skip_data = 0usize;
    let mut scan = 0usize;
    while scan + 8 <= data.len() {
        let magic = u32_le(&data, scan);
        if (0x184d2a50..=0x184d2a5f).contains(&magic) {
            let size = u32_le(&data, scan + 4) as usize;
            skippable_count += 1;
            skip_size += size;
            skip_data += size.min(data.len().saturating_sub(scan + 8));
            scan = scan.saturating_add(8 + size);
            continue;
        }
        scan += 1;
    }
    d.set_item("skippable.magic", skippable_count)?;
    d.set_item("skippable.frame_size", skip_size)?;
    d.set_item("skippable.user_data", skip_data)?;
    let trailing = data.len().saturating_sub(cursor);
    d.set_item("archive.trailing_data", trailing)?;
    if trailing > 0 {
        damage_flags.push("trailing_junk");
    }
    let valid = (decode_ok || decode_limited) && last && descriptor & 0x08 == 0;
    d.set_item("validation_complete", decode_ok)?;
    d.set_item("plausible", valid)?;
    d.set_item("confidence", if valid { "strong" } else { "medium" })?;
    if descriptor & 0x08 != 0 {
        d.set_item("error", "zstd_reserved_bit_set")?;
        damage_flags.push("zstd_reserved_bit_set");
    } else if !valid {
        d.set_item("error", "zstd_frame_validation_failed")?;
        damage_flags.push(if !last {
            "probably_truncated"
        } else {
            "zstd_frame_bad"
        });
    }
    d.set_item("damage_flags", PyList::new(py, damage_flags)?)?;
    d.set_item("file_size", file_size)?;
    finish_fields(&d, ZSTD_FIELDS)?;
    Ok(d.unbind())
}
