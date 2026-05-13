struct SevenZipEncodedHeaderCoder {
    method_id: Vec<u8>,
    properties: Vec<u8>,
    num_in_streams: u64,
    num_out_streams: u64,
}

struct SevenZipEncodedHeaderFolder {
    coders: Vec<SevenZipEncodedHeaderCoder>,
    unpack_size: u64,
    unpack_sizes: Vec<u64>,
}

fn decode_seven_zip_encoded_header_payload(data: &[u8], header: &SevenZipHeader, password: Option<&str>) -> Result<Vec<u8>, String> {
    if header.next_header_nid != SZ_ENCODED_HEADER {
        return Err("encoded_header_absent".to_string());
    }
    let raw = data
        .get(header.next_header_start..header.archive_end)
        .ok_or_else(|| "encoded_header_range_invalid".to_string())?;
    let mut pos = 0usize;
    if raw.get(pos).copied() != Some(SZ_ENCODED_HEADER) {
        return Err("encoded_header_nid_missing".to_string());
    }
    pos += 1;
    let mut pack_info = None;
    let mut folder = None;
    loop {
        let Some(nid) = raw.get(pos).copied() else {
            return Err("encoded_header_tree_truncated".to_string());
        };
        pos += 1;
        match nid {
            SZ_END => break,
            SZ_PACK_INFO => pack_info = Some(parse_seven_zip_pack_info(raw, &mut pos)?),
            SZ_UNPACK_INFO => folder = Some(parse_seven_zip_encoded_header_unpack_info(raw, &mut pos)?),
            SZ_SUB_STREAMS_INFO => skip_seven_zip_unhandled_property_tree(raw, &mut pos, "EncodedHeader SubStreamsInfo")?,
            _ => return Err(format!("encoded_header_unsupported_streams_nid_0x{nid:02x}")),
        }
    }
    let pack = pack_info.ok_or_else(|| "encoded_header_pack_info_missing".to_string())?;
    let folder = folder.ok_or_else(|| "encoded_header_unpack_info_missing".to_string())?;
    if pack.num_streams != 1 || pack.sizes.len() != 1 {
        return Err("encoded_header_pack_stream_not_unique".to_string());
    }
    let stream_start = SEVEN_Z_HEADER_SIZE
        .checked_add(usize::try_from(pack.pack_pos.value).unwrap_or(usize::MAX))
        .unwrap_or(usize::MAX);
    let stream_size = usize::try_from(pack.sizes[0].value).unwrap_or(usize::MAX);
    let stream_end = stream_start.checked_add(stream_size).unwrap_or(usize::MAX);
    if stream_start < SEVEN_Z_HEADER_SIZE || stream_end > data.len() || stream_end > header.next_header_start {
        return Err("encoded_header_stream_range_invalid".to_string());
    }
    let decoded = decode_seven_zip_encoded_folder(&data[stream_start..stream_end], &folder, password)?;
    if decoded.first().copied() != Some(SZ_HEADER) {
        return Err("encoded_header_ast_write_failed".to_string());
    }
    Ok(decoded)
}

fn lzma2_dict_size(prop: u8) -> Option<u32> {
    let bits = u32::from(prop);
    if (bits & !0x3f) != 0 || bits > 40 {
        return None;
    }
    if bits == 40 {
        return Some(u32::MAX);
    }
    Some((2 | (bits & 1)) << (bits / 2 + 11))
}

fn decode_seven_zip_encoded_folder(data: &[u8], folder: &SevenZipEncodedHeaderFolder, password: Option<&str>) -> Result<Vec<u8>, String> {
    if folder.coders.is_empty() {
        return Err("encoded_header_decoder_unsupported_method".to_string());
    }
    let decode_chain = |coders: Vec<(usize, &SevenZipEncodedHeaderCoder)>| -> Result<Vec<u8>, String> {
        let mut current = data.to_vec();
        for (index, coder) in coders {
            if coder.num_in_streams != 1 || coder.num_out_streams != 1 {
                return Err("encoded_header_decoder_unsupported_method".to_string());
            }
            let unpack_size = folder
                .unpack_sizes
                .get(index)
                .copied()
                .unwrap_or(folder.unpack_size);
            current = decode_seven_zip_encoded_coder(&current, coder, password, unpack_size)?;
        }
        Ok(current)
    };
    let direct_order: Vec<_> = folder.coders.iter().enumerate().collect();
    match decode_chain(direct_order) {
        Ok(decoded) if decoded.first().copied() == Some(SZ_HEADER) => return Ok(decoded),
        Ok(_) | Err(_) if folder.coders.len() > 1 => {}
        Ok(decoded) => return Ok(decoded),
        Err(err) => return Err(err),
    }
    let reverse_order: Vec<_> = folder.coders.iter().enumerate().rev().collect();
    let decoded = decode_chain(reverse_order)?;
    if decoded.first().copied() == Some(SZ_HEADER) {
        return Ok(decoded);
    }
    Err("encoded_header_ast_write_failed".to_string())
}

fn decode_seven_zip_encoded_coder(data: &[u8], coder: &SevenZipEncodedHeaderCoder, password: Option<&str>, unpack_size: u64) -> Result<Vec<u8>, String> {
    if coder.method_id.as_slice() == EncoderMethod::ID_COPY {
        return Ok(data.to_vec());
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_AES256_SHA256 {
        return decrypt_seven_zip_aes256_sha256(data, &coder.properties, password);
    }
    let compressed = Cursor::new(data.to_vec());
    let mut decoded = Vec::with_capacity(usize::try_from(unpack_size).unwrap_or(0).min(16 * 1024 * 1024));
    if coder.method_id.as_slice() == EncoderMethod::ID_LZMA {
        if coder.properties.len() < 5 {
            return Err("encoded_header_decoder_unsupported_method".to_string());
        }
        let dict_size = u32::from_le_bytes([
            coder.properties[1],
            coder.properties[2],
            coder.properties[3],
            coder.properties[4],
        ]);
        let mut reader = LzmaReader::new_with_props(
            compressed,
            unpack_size,
            coder.properties[0],
            dict_size,
            None,
        )
        .map_err(|err| format!("encoded_header_decoder_unsupported_method:{err}"))?;
        reader
            .read_to_end(&mut decoded)
            .map_err(|err| format!("encoded_header_payload_crc_bad:{err}"))?;
        return Ok(decoded);
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_LZMA2 {
        let Some(prop) = coder.properties.first().copied() else {
            return Err("encoded_header_decoder_unsupported_method".to_string());
        };
        let dict_size = lzma2_dict_size(prop)
            .ok_or_else(|| "encoded_header_decoder_unsupported_method".to_string())?;
        let mut reader = Lzma2Reader::new(compressed, dict_size, None);
        reader
            .read_to_end(&mut decoded)
            .map_err(|err| format!("encoded_header_payload_crc_bad:{err}"))?;
        return Ok(decoded);
    }
    Err("encoded_header_decoder_unsupported_method".to_string())
}

fn decrypt_seven_zip_aes256_sha256(data: &[u8], properties: &[u8], password: Option<&str>) -> Result<Vec<u8>, String> {
    let Some(password) = password.filter(|value| !value.is_empty()) else {
        return Err("encoded_header_decode_password_required".to_string());
    };
    let password_bytes = seven_zip_password(Some(password));
    let (key, iv) = seven_zip_aes_key_iv(properties, password_bytes.as_slice())?;
    if data.len() % 16 != 0 {
        return Err("encoded_header_payload_crc_bad:aes_block_size".to_string());
    }
    let mut output = data.to_vec();
    let decrypted = Aes256CbcDec::new(&key.into(), &iv.into())
        .decrypt_padded::<NoPadding>(&mut output)
        .map_err(|_| "encoded_header_decode_password_rejected".to_string())?;
    Ok(decrypted.to_vec())
}

fn seven_zip_aes_key_iv(properties: &[u8], password: &[u8]) -> Result<([u8; 32], [u8; 16]), String> {
    if properties.is_empty() {
        return Err("encoded_header_decoder_unsupported_method".to_string());
    }
    let mut expanded;
    let properties = if properties.len() == 1 {
        expanded = vec![0u8; 2];
        expanded[0] = properties[0];
        expanded.as_slice()
    } else {
        properties
    };
    let b0 = properties[0];
    let num_cycles_power = b0 & 63;
    let b1 = properties[1];
    let iv_size = usize::from(((b0 >> 6) & 1) + (b1 & 15));
    let salt_size = usize::from(((b0 >> 7) & 1) + (b1 >> 4));
    if 2 + salt_size + iv_size > properties.len() {
        return Err("encoded_header_decoder_unsupported_method".to_string());
    }
    let salt = &properties[2..2 + salt_size];
    let mut iv = [0u8; 16];
    iv[..iv_size].copy_from_slice(&properties[2 + salt_size..2 + salt_size + iv_size]);
    if password.is_empty() {
        return Err("encoded_header_decode_password_required".to_string());
    }
    let key = if num_cycles_power == 0x3f {
        let mut key = [0u8; 32];
        key[..salt_size].copy_from_slice(salt);
        let n = password.len().min(key.len().saturating_sub(salt_size));
        key[salt_size..salt_size + n].copy_from_slice(&password[..n]);
        key
    } else {
        let mut sha = sha2::Sha256::default();
        let mut extra = [0u8; 8];
        for _ in 0..(1u32 << num_cycles_power) {
            sha.update(salt);
            sha.update(password);
            sha.update(extra);
            for item in &mut extra {
                *item = item.wrapping_add(1);
                if *item != 0 {
                    break;
                }
            }
        }
        sha.finalize().into()
    };
    Ok((key, iv))
}

fn parse_seven_zip_encoded_header_unpack_info(data: &[u8], pos: &mut usize) -> Result<SevenZipEncodedHeaderFolder, String> {
    let mut coders = None;
    let mut folder_output_stream_count = 0u64;
    let mut unpack_sizes = Vec::new();
    loop {
        let Some(nid) = data.get(*pos).copied() else {
            return Err("encoded_header_unpack_info_truncated".to_string());
        };
        *pos += 1;
        match nid {
            SZ_END => break,
            SZ_FOLDER => {
                let (parsed_coders, output_stream_count) = parse_seven_zip_encoded_header_folder(data, pos)?;
                folder_output_stream_count = output_stream_count;
                coders = Some(parsed_coders);
            }
            SZ_CODERS_UNPACK_SIZE => {
                let count = usize::try_from(folder_output_stream_count.max(1))
                    .map_err(|_| "encoded_header_unpack_size_count_too_large".to_string())?;
                unpack_sizes.clear();
                for _ in 0..count {
                    let span = read_sz_vint(data, pos)
                        .ok_or_else(|| "encoded_header_unpack_size_truncated".to_string())?;
                    unpack_sizes.push(span.value);
                }
            }
            SZ_CRC => {
                let defined = parse_seven_zip_bool_vector(data, pos, 1)?;
                for is_defined in defined {
                    if is_defined {
                        if *pos + 4 > data.len() {
                            return Err("encoded_header_crc_truncated".to_string());
                        }
                        *pos += 4;
                    }
                }
            }
            _ => return Err(format!("encoded_header_unsupported_unpack_nid_0x{nid:02x}")),
        }
    }
    let unpack_size = unpack_sizes
        .last()
        .copied()
        .ok_or_else(|| "encoded_header_unpack_size_missing".to_string())?;
    Ok(SevenZipEncodedHeaderFolder {
        coders: coders.ok_or_else(|| "encoded_header_folder_missing".to_string())?,
        unpack_size,
        unpack_sizes,
    })
}

fn parse_seven_zip_encoded_header_folder(data: &[u8], pos: &mut usize) -> Result<(Vec<SevenZipEncodedHeaderCoder>, u64), String> {
    let num_folders = read_sz_vint(data, pos)
        .ok_or_else(|| "encoded_header_folder_count_truncated".to_string())?
        .value;
    if num_folders != 1 {
        return Err("encoded_header_folder_not_unique".to_string());
    }
    let external = *data.get(*pos).ok_or_else(|| "encoded_header_folder_external_flag_missing".to_string())?;
    *pos += 1;
    if external != 0 {
        return Err("encoded_header_external_folder_unsupported".to_string());
    }
    let num_coders = read_sz_vint(data, pos)
        .ok_or_else(|| "encoded_header_coder_count_truncated".to_string())?
        .value;
    if num_coders == 0 || num_coders > 8 {
        return Err("encoded_header_decoder_unsupported_method".to_string());
    }
    let mut output = Vec::with_capacity(usize::try_from(num_coders).unwrap_or(0));
    let mut total_in = 0u64;
    let mut total_out = 0u64;
    for _ in 0..num_coders {
        let flags = *data.get(*pos).ok_or_else(|| "encoded_header_coder_flags_missing".to_string())?;
        *pos += 1;
        let id_size = usize::from(flags & 0x0f);
        if id_size == 0 || *pos + id_size > data.len() {
            return Err("encoded_header_coder_id_truncated".to_string());
        }
        let method_id = data[*pos..*pos + id_size].to_vec();
        *pos += id_size;
        let (num_in_streams, num_out_streams) = if flags & 0x10 != 0 {
            let in_streams = read_sz_vint(data, pos)
                .ok_or_else(|| "encoded_header_coder_in_streams_truncated".to_string())?
                .value;
            let out_streams = read_sz_vint(data, pos)
                .ok_or_else(|| "encoded_header_coder_out_streams_truncated".to_string())?
                .value;
            (in_streams, out_streams)
        } else {
            (1, 1)
        };
        total_in = total_in.saturating_add(num_in_streams);
        total_out = total_out.saturating_add(num_out_streams);
        let mut properties = Vec::new();
        if flags & 0x20 != 0 {
            let prop_size = usize::try_from(
                read_sz_vint(data, pos)
                    .ok_or_else(|| "encoded_header_coder_properties_size_truncated".to_string())?
                    .value,
            )
            .unwrap_or(usize::MAX);
            if *pos + prop_size > data.len() {
                return Err("encoded_header_coder_properties_truncated".to_string());
            }
            properties.extend_from_slice(&data[*pos..*pos + prop_size]);
            *pos += prop_size;
        }
        if flags & 0x80 != 0 {
            return Err("encoded_header_decoder_unsupported_method".to_string());
        }
        output.push(SevenZipEncodedHeaderCoder {
            method_id,
            properties,
            num_in_streams,
            num_out_streams,
        });
    }
    if total_in == 0 || total_out == 0 || total_in < total_out.saturating_sub(1) {
        return Err("encoded_header_decoder_unsupported_method".to_string());
    }
    let bind_pairs = total_out.saturating_sub(1);
    for _ in 0..bind_pairs {
        read_sz_vint(data, pos).ok_or_else(|| "encoded_header_bind_pair_in_truncated".to_string())?;
        read_sz_vint(data, pos).ok_or_else(|| "encoded_header_bind_pair_out_truncated".to_string())?;
    }
    let packed_streams = total_in.saturating_sub(bind_pairs);
    if packed_streams == 0 || packed_streams > 1 {
        return Err("encoded_header_decoder_unsupported_method".to_string());
    }
    if packed_streams > 1 {
        for _ in 0..packed_streams {
            read_sz_vint(data, pos).ok_or_else(|| "encoded_header_packed_stream_truncated".to_string())?;
        }
    }
    Ok((output, total_out))
}
