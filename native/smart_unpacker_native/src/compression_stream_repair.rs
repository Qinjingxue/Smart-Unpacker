use bzip2::read::BzDecoder;
use bzip2::write::BzEncoder;
use bzip2::Compression as Bzip2Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression as GzipCompression;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::fs::{self, File};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use xz2::read::XzDecoder;
use xz2::write::XzEncoder;
use zstd::stream::read::Decoder as ZstdDecoder;
use zstd::stream::write::Encoder as ZstdEncoder;

const COPY_CHUNK_SIZE: usize = 1024 * 1024;
const DECODE_CHUNK_SIZE: usize = 128 * 1024;

#[pyfunction]
#[pyo3(signature = (
    source_input,
    format,
    workspace,
    max_input_size_mb=512.0,
    max_output_size_mb=2048.0,
    max_seconds=30.0
))]
pub(crate) fn compression_stream_partial_recovery(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    format: &str,
    workspace: &str,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
    max_seconds: f64,
) -> PyResult<Py<PyDict>> {
    let Some(format) = StreamFormat::from_name(format) else {
        return status_dict(
            py,
            "unsupported",
            "",
            "",
            "unsupported compression stream format",
            &[],
            format,
            0,
            0,
            0.0,
        );
    };
    let options = StreamRepairOptions {
        max_input_bytes: mb_to_bytes(max_input_size_mb),
        max_output_bytes: mb_to_bytes(max_output_size_mb),
        max_duration: duration_from_seconds(max_seconds),
    };
    let data = match read_source_input(source_input, options.max_input_bytes) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(
                py,
                "skipped",
                "",
                "",
                &message,
                &[],
                format.name(),
                0,
                0,
                0.0,
            )
        }
    };
    let output_path = Path::new(workspace).join(format!(
        "{}_truncated_partial_recovery{}",
        format.name(),
        format.ext()
    ));
    match recover_stream_prefix(&data, format, &output_path, &options) {
        Ok(recovered) => status_dict(
            py,
            "partial",
            &output_path.to_string_lossy(),
            recovered.error.as_deref().unwrap_or(""),
            "compression stream truncated; recovered decodable prefix",
            &recovered.warnings,
            format.name(),
            recovered.decoded_bytes,
            recovered.output_bytes,
            confidence_for_size(recovered.decoded_bytes),
        ),
        Err(message) => status_dict(
            py,
            "unrepairable",
            "",
            "",
            &message,
            &[],
            format.name(),
            0,
            0,
            0.0,
        ),
    }
}

#[pyfunction]
#[pyo3(signature = (
    source_input,
    format,
    workspace,
    max_input_size_mb=512.0,
    max_output_size_mb=2048.0,
    max_seconds=30.0,
    max_entries=20000
))]
pub(crate) fn tar_compressed_partial_recovery(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    format: &str,
    workspace: &str,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
    max_seconds: f64,
    max_entries: usize,
) -> PyResult<Py<PyDict>> {
    let Some(format) = CompressedTarFormat::from_name(format) else {
        return tar_status_dict(
            py,
            "unsupported",
            "",
            "",
            "unsupported compressed TAR format",
            &[],
            format,
            "",
            0,
            0,
            0,
            0,
            0,
            0,
            0.0,
            &[],
        );
    };
    let options = StreamRepairOptions {
        max_input_bytes: mb_to_bytes(max_input_size_mb),
        max_output_bytes: mb_to_bytes(max_output_size_mb),
        max_duration: duration_from_seconds(max_seconds),
    };
    let data = match read_source_input(source_input, options.max_input_bytes) {
        Ok(data) => data,
        Err(message) => {
            return tar_status_dict(
                py,
                "skipped",
                "",
                "",
                &message,
                &[],
                format.name(),
                format.stream().name(),
                0,
                0,
                0,
                0,
                0,
                0,
                0.0,
                &[],
            )
        }
    };

    let decoded = match decode_stream_prefix_to_vec(&data, format.stream(), &options) {
        Ok(decoded) => decoded,
        Err(message) => {
            return tar_status_dict(
                py,
                "unrepairable",
                "",
                "",
                &message,
                &[],
                format.name(),
                format.stream().name(),
                0,
                0,
                0,
                0,
                0,
                0,
                0.0,
                &[],
            )
        }
    };

    let tar = match repair_tar_prefix(&decoded.bytes, &options, max_entries) {
        Ok(tar) => tar,
        Err(message) => {
            return tar_status_dict(
                py,
                "unrepairable",
                "",
                decoded.error.as_deref().unwrap_or(""),
                &message,
                &decoded.warnings,
                format.name(),
                format.stream().name(),
                decoded.decoded_bytes,
                0,
                0,
                0,
                0,
                0,
                0.0,
                &[],
            )
        }
    };

    if decoded.error.is_none() && !decoded.timed_out && !tar.changed {
        return tar_status_dict(
            py,
            "unrepairable",
            "",
            "",
            "compressed TAR decoded cleanly and inner TAR already looks canonical",
            &tar.warnings,
            format.name(),
            format.stream().name(),
            decoded.decoded_bytes,
            tar.tar_bytes,
            0,
            tar.members,
            tar.checksum_fixes,
            tar.truncated_members,
            0.0,
            &[],
        );
    }

    let output_path = Path::new(workspace).join(format!(
        "{}_truncated_partial_recovery{}",
        format.file_stem(),
        format.ext()
    ));
    let output_bytes =
        match write_recompressed_stream(format.stream(), &tar.bytes, &output_path, &options) {
            Ok(bytes) => bytes,
            Err(message) => {
                let mut warnings = decoded.warnings.clone();
                warnings.extend(tar.warnings.iter().cloned());
                return tar_status_dict(
                    py,
                    "unrepairable",
                    "",
                    decoded.error.as_deref().unwrap_or(""),
                    &message,
                    &warnings,
                    format.name(),
                    format.stream().name(),
                    decoded.decoded_bytes,
                    tar.tar_bytes,
                    0,
                    tar.members,
                    tar.checksum_fixes,
                    tar.truncated_members,
                    0.0,
                    &[],
                );
            }
        };

    let mut warnings = decoded.warnings.clone();
    warnings.extend(tar.warnings.iter().cloned());
    let status = if decoded.error.is_none() && !decoded.timed_out && tar.truncated_members == 0 {
        "repaired"
    } else {
        "partial"
    };
    let actions = [
        "decode_outer_stream_prefix",
        "repair_tar_headers",
        "append_tar_zero_blocks",
        "recompress_tar_stream",
    ];
    tar_status_dict(
        py,
        status,
        &output_path.to_string_lossy(),
        decoded.error.as_deref().unwrap_or(""),
        "compressed TAR recovery produced a canonical TAR stream candidate",
        &warnings,
        format.name(),
        format.stream().name(),
        decoded.decoded_bytes,
        tar.tar_bytes,
        output_bytes,
        tar.members,
        tar.checksum_fixes,
        tar.truncated_members,
        tar_confidence(tar.members, decoded.decoded_bytes),
        &actions,
    )
}

#[derive(Clone, Copy, Debug)]
enum StreamFormat {
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

impl StreamFormat {
    fn from_name(value: &str) -> Option<Self> {
        match value
            .trim()
            .trim_start_matches('.')
            .to_ascii_lowercase()
            .as_str()
        {
            "gzip" | "gz" => Some(Self::Gzip),
            "bzip2" | "bz2" => Some(Self::Bzip2),
            "xz" => Some(Self::Xz),
            "zstd" | "zst" => Some(Self::Zstd),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
        }
    }

    fn ext(self) -> &'static str {
        match self {
            Self::Gzip => ".gz",
            Self::Bzip2 => ".bz2",
            Self::Xz => ".xz",
            Self::Zstd => ".zst",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum CompressedTarFormat {
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

impl CompressedTarFormat {
    fn from_name(value: &str) -> Option<Self> {
        match value
            .trim()
            .trim_start_matches('.')
            .to_ascii_lowercase()
            .as_str()
        {
            "tar.gz" | "tgz" | "gzip" | "gz" => Some(Self::Gzip),
            "tar.bz2" | "tbz2" | "tbz" | "bzip2" | "bz2" => Some(Self::Bzip2),
            "tar.xz" | "txz" | "xz" => Some(Self::Xz),
            "tar.zst" | "tar.zstd" | "tzst" | "zstd" | "zst" => Some(Self::Zstd),
            _ => None,
        }
    }

    fn stream(self) -> StreamFormat {
        match self {
            Self::Gzip => StreamFormat::Gzip,
            Self::Bzip2 => StreamFormat::Bzip2,
            Self::Xz => StreamFormat::Xz,
            Self::Zstd => StreamFormat::Zstd,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Gzip => "tar.gz",
            Self::Bzip2 => "tar.bz2",
            Self::Xz => "tar.xz",
            Self::Zstd => "tar.zst",
        }
    }

    fn file_stem(self) -> &'static str {
        match self {
            Self::Gzip => "tar_gzip",
            Self::Bzip2 => "tar_bzip2",
            Self::Xz => "tar_xz",
            Self::Zstd => "tar_zstd",
        }
    }

    fn ext(self) -> &'static str {
        match self {
            Self::Gzip => ".tar.gz",
            Self::Bzip2 => ".tar.bz2",
            Self::Xz => ".tar.xz",
            Self::Zstd => ".tar.zst",
        }
    }
}

struct StreamRepairOptions {
    max_input_bytes: Option<u64>,
    max_output_bytes: Option<u64>,
    max_duration: Option<Duration>,
}

struct RecoveryStats {
    decoded_bytes: u64,
    output_bytes: u64,
    error: Option<String>,
    warnings: Vec<String>,
}

struct DecodedPrefix {
    bytes: Vec<u8>,
    decoded_bytes: u64,
    error: Option<String>,
    timed_out: bool,
    warnings: Vec<String>,
}

struct TarPrefixRepair {
    bytes: Vec<u8>,
    tar_bytes: u64,
    members: u64,
    checksum_fixes: u64,
    truncated_members: u64,
    changed: bool,
    warnings: Vec<String>,
}

enum CandidateEncoder {
    Gzip(GzEncoder<File>),
    Bzip2(BzEncoder<File>),
    Xz(XzEncoder<File>),
    Zstd(ZstdEncoder<'static, File>),
}

impl CandidateEncoder {
    fn new(format: StreamFormat, file: File) -> io::Result<Self> {
        match format {
            StreamFormat::Gzip => Ok(Self::Gzip(GzEncoder::new(file, GzipCompression::default()))),
            StreamFormat::Bzip2 => Ok(Self::Bzip2(BzEncoder::new(
                file,
                Bzip2Compression::default(),
            ))),
            StreamFormat::Xz => Ok(Self::Xz(XzEncoder::new(file, 6))),
            StreamFormat::Zstd => Ok(Self::Zstd(ZstdEncoder::new(file, 0)?)),
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Gzip(encoder) => encoder.write_all(bytes),
            Self::Bzip2(encoder) => encoder.write_all(bytes),
            Self::Xz(encoder) => encoder.write_all(bytes),
            Self::Zstd(encoder) => encoder.write_all(bytes),
        }
    }

    fn finish(self) -> io::Result<File> {
        match self {
            Self::Gzip(encoder) => encoder.finish(),
            Self::Bzip2(encoder) => encoder.finish(),
            Self::Xz(encoder) => encoder.finish(),
            Self::Zstd(encoder) => encoder.finish(),
        }
    }
}

fn decode_stream_prefix_to_vec(
    data: &[u8],
    format: StreamFormat,
    options: &StreamRepairOptions,
) -> Result<DecodedPrefix, String> {
    let started = Instant::now();
    let cursor = Cursor::new(data.to_vec());
    let mut decoder = decoder_for(format, cursor)?;
    let mut buffer = vec![0u8; DECODE_CHUNK_SIZE];
    let mut decoded = Vec::new();
    let mut error = None;
    let mut timed_out = false;

    loop {
        if timed_out_at(started, options.max_duration) {
            timed_out = true;
            break;
        }
        match decoder.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                decoded.extend_from_slice(&buffer[..read]);
                if options
                    .max_output_bytes
                    .is_some_and(|limit| decoded.len() as u64 > limit)
                {
                    return Err(
                        "decoded TAR stream exceeds repair.deep.max_output_size_mb".to_string()
                    );
                }
            }
            Err(err) => {
                error = Some(err.to_string());
                break;
            }
        }
    }

    if decoded.is_empty() {
        return Err(
            error.unwrap_or_else(|| "stream produced no recoverable TAR prefix".to_string())
        );
    }

    let mut warnings = Vec::new();
    if timed_out {
        warnings.push("compressed TAR decode time budget reached".to_string());
    }
    Ok(DecodedPrefix {
        decoded_bytes: decoded.len() as u64,
        bytes: decoded,
        error,
        timed_out,
        warnings,
    })
}

fn recover_stream_prefix(
    data: &[u8],
    format: StreamFormat,
    output: &Path,
    options: &StreamRepairOptions,
) -> Result<RecoveryStats, String> {
    ensure_parent(output).map_err(|err| err.to_string())?;
    let temp = temp_path(output);
    let started = Instant::now();
    let result = (|| -> Result<RecoveryStats, String> {
        let cursor = Cursor::new(data.to_vec());
        let mut decoder = decoder_for(format, cursor)?;
        let file = File::create(&temp).map_err(|err| err.to_string())?;
        let mut encoder = CandidateEncoder::new(format, file).map_err(|err| err.to_string())?;
        let mut buffer = vec![0u8; DECODE_CHUNK_SIZE];
        let mut decoded = 0u64;
        let mut error = None;
        let mut timed_out = false;

        loop {
            if timed_out_at(started, options.max_duration) {
                timed_out = true;
                break;
            }
            match decoder.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    decoded += read as u64;
                    if options
                        .max_output_bytes
                        .is_some_and(|limit| decoded > limit)
                    {
                        return Err(
                            "recovered stream prefix exceeds repair.deep.max_output_size_mb"
                                .to_string(),
                        );
                    }
                    encoder
                        .write_all(&buffer[..read])
                        .map_err(|err| err.to_string())?;
                }
                Err(err) => {
                    error = Some(err.to_string());
                    break;
                }
            }
        }

        if decoded == 0 {
            return Err(
                error.unwrap_or_else(|| "stream produced no recoverable prefix".to_string())
            );
        }
        if error.is_none() && !timed_out {
            return Err(
                "stream decoded completely; no truncated-prefix recovery needed".to_string(),
            );
        }
        let mut file = encoder.finish().map_err(|err| err.to_string())?;
        file.flush().map_err(|err| err.to_string())?;
        let output_bytes = file.seek(SeekFrom::End(0)).map_err(|err| err.to_string())?;
        if options
            .max_output_bytes
            .is_some_and(|limit| output_bytes > limit)
        {
            return Err("candidate output exceeds repair.deep.max_output_size_mb".to_string());
        }
        let mut warnings = Vec::new();
        if timed_out {
            warnings.push("compression stream partial recovery time budget reached".to_string());
        }
        Ok(RecoveryStats {
            decoded_bytes: decoded,
            output_bytes,
            error,
            warnings,
        })
    })();

    match result {
        Ok(stats) => {
            if output.exists() {
                fs::remove_file(output).map_err(|err| err.to_string())?;
            }
            fs::rename(&temp, output).map_err(|err| err.to_string())?;
            Ok(stats)
        }
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(err)
        }
    }
}

fn write_recompressed_stream(
    format: StreamFormat,
    data: &[u8],
    output: &Path,
    options: &StreamRepairOptions,
) -> Result<u64, String> {
    ensure_parent(output).map_err(|err| err.to_string())?;
    let temp = temp_path(output);
    let result = (|| -> Result<u64, String> {
        let file = File::create(&temp).map_err(|err| err.to_string())?;
        let mut encoder = CandidateEncoder::new(format, file).map_err(|err| err.to_string())?;
        encoder.write_all(data).map_err(|err| err.to_string())?;
        let mut file = encoder.finish().map_err(|err| err.to_string())?;
        file.flush().map_err(|err| err.to_string())?;
        let output_bytes = file.seek(SeekFrom::End(0)).map_err(|err| err.to_string())?;
        if options
            .max_output_bytes
            .is_some_and(|limit| output_bytes > limit)
        {
            return Err("candidate output exceeds repair.deep.max_output_size_mb".to_string());
        }
        Ok(output_bytes)
    })();

    match result {
        Ok(output_bytes) => {
            if output.exists() {
                fs::remove_file(output).map_err(|err| err.to_string())?;
            }
            fs::rename(&temp, output).map_err(|err| err.to_string())?;
            Ok(output_bytes)
        }
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(err)
        }
    }
}

fn repair_tar_prefix(
    data: &[u8],
    options: &StreamRepairOptions,
    max_entries: usize,
) -> Result<TarPrefixRepair, String> {
    let mut output = Vec::with_capacity(data.len().saturating_add(1024));
    let mut offset = 0usize;
    let mut members = 0u64;
    let mut checksum_fixes = 0u64;
    let mut truncated_members = 0u64;
    let mut warnings = Vec::new();

    while offset + 512 <= data.len() {
        if max_entries > 0 && members as usize >= max_entries {
            warnings.push("compressed TAR recovery reached repair.deep.max_entries".to_string());
            break;
        }

        let header = &data[offset..offset + 512];
        if is_zero_block(header) {
            break;
        }

        let Some(size) = parse_tar_number(&header[124..136]) else {
            if members == 0 {
                return Err("no plausible TAR header was found in decoded stream".to_string());
            }
            warnings.push("stopped before a TAR header with an invalid size field".to_string());
            break;
        };
        if !plausible_tar_header(header) {
            if members == 0 {
                return Err("decoded stream does not begin with a plausible TAR header".to_string());
            }
            warnings.push("stopped before an implausible TAR header".to_string());
            break;
        }

        let Some(payload_span) = padded_tar_payload_span(size) else {
            warnings.push("stopped before a TAR member with an oversized payload".to_string());
            break;
        };
        let Some(member_end) = offset
            .checked_add(512)
            .and_then(|value| value.checked_add(payload_span))
        else {
            warnings
                .push("stopped before a TAR member with an overflowing payload span".to_string());
            break;
        };
        if member_end > data.len() {
            truncated_members += 1;
            warnings.push("dropped a trailing TAR member whose payload is truncated".to_string());
            break;
        }

        let mut fixed_header = header.to_vec();
        let computed = tar_checksum(&fixed_header);
        let stored = parse_tar_number(&fixed_header[148..156]);
        if stored != Some(computed) {
            fixed_header[148..156].copy_from_slice(&format_tar_checksum(computed));
            checksum_fixes += 1;
        }

        output.extend_from_slice(&fixed_header);
        output.extend_from_slice(&data[offset + 512..member_end]);
        members += 1;
        offset = member_end;
    }

    if members == 0 {
        return Err("decoded stream contains no complete TAR members".to_string());
    }
    output.extend_from_slice(&[0u8; 1024]);
    if options
        .max_output_bytes
        .is_some_and(|limit| output.len() as u64 > limit)
    {
        return Err("repaired TAR stream exceeds repair.deep.max_output_size_mb".to_string());
    }
    let changed = output.as_slice() != data;
    Ok(TarPrefixRepair {
        tar_bytes: output.len() as u64,
        bytes: output,
        members,
        checksum_fixes,
        truncated_members,
        changed,
        warnings,
    })
}

fn decoder_for(format: StreamFormat, cursor: Cursor<Vec<u8>>) -> Result<Box<dyn Read>, String> {
    match format {
        StreamFormat::Gzip => Ok(Box::new(GzDecoder::new(cursor))),
        StreamFormat::Bzip2 => Ok(Box::new(BzDecoder::new(cursor))),
        StreamFormat::Xz => Ok(Box::new(XzDecoder::new(cursor))),
        StreamFormat::Zstd => Ok(Box::new(
            ZstdDecoder::new(cursor).map_err(|err| err.to_string())?,
        )),
    }
}

fn read_source_input(
    source_input: &Bound<'_, PyDict>,
    max_bytes: Option<u64>,
) -> Result<Vec<u8>, String> {
    let kind = get_optional_string(source_input, "kind")
        .map_err(|err| err.to_string())?
        .unwrap_or_else(|| "file".to_string());
    match kind.as_str() {
        "bytes" | "memory" => {
            let data_obj = source_input
                .get_item("data")
                .map_err(|err| err.to_string())?
                .ok_or_else(|| "missing bytes repair input data".to_string())?;
            let data = data_obj.cast::<PyBytes>().map_err(|err| err.to_string())?.as_bytes();
            if max_bytes.is_some_and(|limit| data.len() as u64 > limit) {
                return Err(
                    "compression stream repair input exceeds max_input_size_mb".to_string()
                );
            }
            Ok(data.to_vec())
        }
        "file" => {
            let path = get_required_string(source_input, "path").map_err(|err| err.to_string())?;
            read_range_to_vec(&path, 0, None, max_bytes)
        }
        "file_range" => {
            let path = get_required_string(source_input, "path").map_err(|err| err.to_string())?;
            let start = get_optional_u64(source_input, "start")
                .map_err(|err| err.to_string())?
                .unwrap_or(0);
            let end = get_optional_u64(source_input, "end").map_err(|err| err.to_string())?;
            read_range_to_vec(&path, start, end, max_bytes)
        }
        "concat_ranges" => {
            let ranges_obj = source_input
                .get_item("ranges")
                .map_err(|err| err.to_string())?
                .ok_or_else(|| "missing ranges".to_string())?;
            let ranges = ranges_obj.cast::<PyList>().map_err(|err| err.to_string())?;
            let mut output = Vec::new();
            for item in ranges.iter() {
                let dict = item.cast::<PyDict>().map_err(|err| err.to_string())?;
                let path = get_required_string(dict, "path").map_err(|err| err.to_string())?;
                let start = get_optional_u64(dict, "start")
                    .map_err(|err| err.to_string())?
                    .unwrap_or(0);
                let end = get_optional_u64(dict, "end").map_err(|err| err.to_string())?;
                let remaining_limit =
                    max_bytes.map(|limit| limit.saturating_sub(output.len() as u64));
                let chunk = read_range_to_vec(&path, start, end, remaining_limit)?;
                output.extend_from_slice(&chunk);
                if max_bytes.is_some_and(|limit| output.len() as u64 > limit) {
                    return Err(
                        "compression stream repair input exceeds max_input_size_mb".to_string()
                    );
                }
            }
            Ok(output)
        }
        _ => Err(format!("unsupported repair input kind: {kind}")),
    }
}

fn read_range_to_vec(
    path: &str,
    start: u64,
    end: Option<u64>,
    max_bytes: Option<u64>,
) -> Result<Vec<u8>, String> {
    let mut file = File::open(path).map_err(|err| err.to_string())?;
    let file_size = file.seek(SeekFrom::End(0)).map_err(|err| err.to_string())?;
    if start > file_size {
        return Err("range start is beyond input size".to_string());
    }
    let effective_end = end.unwrap_or(file_size).min(file_size);
    if effective_end < start {
        return Err("range end is before range start".to_string());
    }
    let len = effective_end - start;
    if max_bytes.is_some_and(|limit| len > limit) {
        return Err("compression stream repair input exceeds max_input_size_mb".to_string());
    }
    let mut output = Vec::with_capacity(len.min(COPY_CHUNK_SIZE as u64) as usize);
    file.seek(SeekFrom::Start(start))
        .map_err(|err| err.to_string())?;
    let mut limited = file.take(len);
    limited
        .read_to_end(&mut output)
        .map_err(|err| err.to_string())?;
    Ok(output)
}

fn status_dict(
    py: Python<'_>,
    status: &str,
    selected_path: &str,
    decoder_error: &str,
    message: &str,
    warnings: &[String],
    format: &str,
    decoded_bytes: u64,
    output_bytes: u64,
    confidence: f64,
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("selected_path", selected_path)?;
    result.set_item("format", format)?;
    result.set_item("confidence", confidence)?;
    result.set_item("message", message)?;
    result.set_item("decoder_error", decoder_error)?;
    result.set_item("decoded_bytes", decoded_bytes)?;
    result.set_item("output_bytes", output_bytes)?;
    result.set_item(
        "actions",
        PyList::new(
            py,
            ["decode_recoverable_prefix", "recompress_partial_stream"],
        )?,
    )?;
    result.set_item("warnings", PyList::new(py, warnings)?)?;
    result.set_item(
        "workspace_paths",
        if selected_path.is_empty() {
            PyList::empty(py)
        } else {
            PyList::new(py, [selected_path])?
        },
    )?;
    Ok(result.unbind())
}

fn tar_status_dict(
    py: Python<'_>,
    status: &str,
    selected_path: &str,
    decoder_error: &str,
    message: &str,
    warnings: &[String],
    format: &str,
    outer_format: &str,
    decoded_bytes: u64,
    tar_bytes: u64,
    output_bytes: u64,
    members: u64,
    checksum_fixes: u64,
    truncated_members: u64,
    confidence: f64,
    actions: &[&str],
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("selected_path", selected_path)?;
    result.set_item("format", format)?;
    result.set_item("outer_format", outer_format)?;
    result.set_item("confidence", confidence)?;
    result.set_item("message", message)?;
    result.set_item("decoder_error", decoder_error)?;
    result.set_item("decoded_bytes", decoded_bytes)?;
    result.set_item("tar_bytes", tar_bytes)?;
    result.set_item("output_bytes", output_bytes)?;
    result.set_item("members", members)?;
    result.set_item("checksum_fixes", checksum_fixes)?;
    result.set_item("truncated_members", truncated_members)?;
    result.set_item("actions", PyList::new(py, actions)?)?;
    result.set_item("warnings", PyList::new(py, warnings)?)?;
    result.set_item(
        "workspace_paths",
        if selected_path.is_empty() {
            PyList::empty(py)
        } else {
            PyList::new(py, [selected_path])?
        },
    )?;
    Ok(result.unbind())
}

fn get_required_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<String> {
    dict.get_item(key)?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(format!("missing {key}")))?
        .extract::<String>()
}

fn get_optional_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    match dict.get_item(key)? {
        Some(value) if !value.is_none() => Ok(Some(value.extract::<String>()?)),
        _ => Ok(None),
    }
}

fn get_optional_u64(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u64>> {
    match dict.get_item(key)? {
        Some(value) if !value.is_none() => Ok(Some(value.extract::<u64>()?)),
        _ => Ok(None),
    }
}

fn ensure_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("candidate");
    path.with_file_name(format!(".{name}.tmp"))
}

fn timed_out_at(started: Instant, max_duration: Option<Duration>) -> bool {
    max_duration.is_some_and(|duration| started.elapsed() >= duration)
}

fn duration_from_seconds(value: f64) -> Option<Duration> {
    (value > 0.0).then(|| Duration::from_secs_f64(value))
}

fn mb_to_bytes(value: f64) -> Option<u64> {
    if value <= 0.0 {
        None
    } else {
        Some((value * 1024.0 * 1024.0) as u64)
    }
}

fn confidence_for_size(decoded_bytes: u64) -> f64 {
    if decoded_bytes >= 1024 * 1024 {
        0.78
    } else if decoded_bytes >= 64 * 1024 {
        0.72
    } else {
        0.62
    }
}

fn tar_confidence(members: u64, decoded_bytes: u64) -> f64 {
    if members >= 8 || decoded_bytes >= 4 * 1024 * 1024 {
        0.82
    } else if members >= 2 || decoded_bytes >= 512 * 1024 {
        0.76
    } else {
        0.68
    }
}

fn is_zero_block(block: &[u8]) -> bool {
    block.iter().all(|byte| *byte == 0)
}

fn plausible_tar_header(header: &[u8]) -> bool {
    if header.len() != 512 {
        return false;
    }
    if !plausible_tar_name(&header[0..100]) {
        return false;
    }
    if parse_tar_number(&header[100..108]).is_none()
        || parse_tar_number(&header[108..116]).is_none()
        || parse_tar_number(&header[116..124]).is_none()
        || parse_tar_number(&header[124..136]).is_none()
    {
        return false;
    }
    let typeflag = header[156];
    if typeflag != 0 && !(0x20..=0x7e).contains(&typeflag) {
        return false;
    }
    let magic = &header[257..263];
    if magic.iter().any(|byte| *byte != 0)
        && !magic.starts_with(b"ustar\0")
        && !magic.starts_with(b"ustar ")
    {
        return false;
    }
    true
}

fn plausible_tar_name(field: &[u8]) -> bool {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if end == 0 {
        return false;
    }
    field[..end]
        .iter()
        .all(|byte| *byte >= 0x20 && *byte != 0x7f)
}

fn parse_tar_number(field: &[u8]) -> Option<u64> {
    if field.is_empty() {
        return None;
    }
    if field[0] & 0x80 != 0 {
        let mut value = (field[0] & 0x7f) as u64;
        for byte in &field[1..] {
            value = value.checked_mul(256)?.checked_add(*byte as u64)?;
        }
        return Some(value);
    }

    let mut value = 0u64;
    let mut seen_digit = false;
    for byte in field {
        match *byte {
            b'0'..=b'7' => {
                seen_digit = true;
                value = value.checked_mul(8)?.checked_add((*byte - b'0') as u64)?;
            }
            b'\0' | b' ' => {}
            _ => return None,
        }
    }
    if seen_digit {
        Some(value)
    } else {
        Some(0)
    }
}

fn padded_tar_payload_span(size: u64) -> Option<usize> {
    let padded = size.checked_add(511)? / 512 * 512;
    usize::try_from(padded).ok()
}

fn tar_checksum(header: &[u8]) -> u64 {
    header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                b' ' as u64
            } else {
                *byte as u64
            }
        })
        .sum()
}

fn format_tar_checksum(value: u64) -> [u8; 8] {
    let text = format!("{value:06o}\0 ");
    let mut output = [0u8; 8];
    output.copy_from_slice(text.as_bytes());
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn gzip_truncated_stream_recompresses_recovered_prefix() {
        let payload = patterned_payload(512 * 1024);
        let mut encoded = Vec::new();
        {
            let mut encoder = GzEncoder::new(&mut encoded, GzipCompression::default());
            encoder.write_all(&payload).unwrap();
            encoder.finish().unwrap();
        }
        encoded.truncate(encoded.len() * 3 / 4);
        let output = temp_output("gzip_stream_partial.gz");

        let stats =
            recover_stream_prefix(&encoded, StreamFormat::Gzip, &output, &test_options()).unwrap();

        assert!(stats.decoded_bytes > 0);
        let recovered = fs::read(&output).unwrap();
        let mut decoder = GzDecoder::new(Cursor::new(recovered));
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert!(payload.starts_with(&decoded));
        assert!(decoded.len() < payload.len());
        let _ = fs::remove_file(output);
    }

    #[test]
    fn bzip2_truncated_stream_recompresses_recovered_prefix() {
        let payload = patterned_payload(2 * 1024 * 1024);
        let mut encoded = Vec::new();
        {
            let mut encoder = BzEncoder::new(&mut encoded, Bzip2Compression::default());
            encoder.write_all(&payload).unwrap();
            encoder.finish().unwrap();
        }
        encoded.truncate(encoded.len() * 9 / 10);
        let output = temp_output("bzip2_stream_partial.bz2");

        let stats =
            recover_stream_prefix(&encoded, StreamFormat::Bzip2, &output, &test_options()).unwrap();

        assert!(stats.decoded_bytes > 0);
        let recovered = fs::read(&output).unwrap();
        let mut decoder = BzDecoder::new(Cursor::new(recovered));
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert!(payload.starts_with(&decoded));
        let _ = fs::remove_file(output);
    }

    #[test]
    fn xz_truncated_stream_recompresses_recovered_prefix() {
        let payload = patterned_payload(1024 * 1024);
        let mut encoded = Vec::new();
        {
            let mut encoder = XzEncoder::new(&mut encoded, 6);
            encoder.write_all(&payload).unwrap();
            encoder.finish().unwrap();
        }
        encoded.truncate(encoded.len() * 9 / 10);
        let output = temp_output("xz_stream_partial.xz");

        let stats =
            recover_stream_prefix(&encoded, StreamFormat::Xz, &output, &test_options()).unwrap();

        assert!(stats.decoded_bytes > 0);
        let recovered = fs::read(&output).unwrap();
        let mut decoder = XzDecoder::new(Cursor::new(recovered));
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert!(payload.starts_with(&decoded));
        let _ = fs::remove_file(output);
    }

    #[test]
    fn zstd_truncated_stream_recompresses_recovered_prefix() {
        let payload = pseudo_random_payload(4 * 1024 * 1024);
        let encoded = zstd::stream::encode_all(Cursor::new(&payload), 0).unwrap();
        let mut truncated = encoded.clone();
        truncated.truncate(encoded.len() * 9 / 10);
        let output = temp_output("zstd_stream_partial.zst");

        let stats = recover_stream_prefix(&truncated, StreamFormat::Zstd, &output, &test_options())
            .unwrap();

        assert!(stats.decoded_bytes > 0);
        let recovered = fs::read(&output).unwrap();
        let decoded = zstd::stream::decode_all(Cursor::new(recovered)).unwrap();
        assert!(payload.starts_with(&decoded));
        let _ = fs::remove_file(output);
    }

    #[test]
    fn tar_prefix_repair_drops_truncated_member_and_appends_zero_blocks() {
        let first = tar_member("first.bin", b"first payload");
        let second = tar_member("second.bin", &patterned_payload(4096));
        let mut prefix = first.clone();
        prefix.extend_from_slice(&second[..512 + 32]);

        let repaired = repair_tar_prefix(&prefix, &test_options(), 20000).unwrap();

        assert_eq!(repaired.members, 1);
        assert_eq!(repaired.truncated_members, 1);
        assert_eq!(repaired.checksum_fixes, 0);
        assert_eq!(&repaired.bytes[..first.len()], first.as_slice());
        assert_eq!(&repaired.bytes[first.len()..], &[0u8; 1024]);
    }

    #[test]
    fn tar_prefix_repair_fixes_header_checksum() {
        let mut member = tar_member("payload.txt", b"payload");
        member[148] = b'7';

        let repaired = repair_tar_prefix(&member, &test_options(), 20000).unwrap();

        assert_eq!(repaired.members, 1);
        assert_eq!(repaired.checksum_fixes, 1);
        assert!(repaired.changed);
        assert_eq!(
            parse_tar_number(&repaired.bytes[148..156]),
            Some(tar_checksum(&repaired.bytes[..512]))
        );
    }

    #[test]
    fn gzip_tar_combo_recompresses_repaired_tar_prefix() {
        let first = tar_member("first.bin", &patterned_payload(2048));
        let second = tar_member("second.bin", &patterned_payload(4096));
        let mut tar_prefix = first.clone();
        tar_prefix.extend_from_slice(&second[..512 + 128]);
        let mut encoded = Vec::new();
        {
            let mut encoder = GzEncoder::new(&mut encoded, GzipCompression::default());
            encoder.write_all(&tar_prefix).unwrap();
            encoder.finish().unwrap();
        }
        encoded.truncate(encoded.len().saturating_sub(8));

        let decoded =
            decode_stream_prefix_to_vec(&encoded, StreamFormat::Gzip, &test_options()).unwrap();
        let tar = repair_tar_prefix(&decoded.bytes, &test_options(), 20000).unwrap();
        let output = temp_output("tar_gzip_combo.tar.gz");
        let output_bytes =
            write_recompressed_stream(StreamFormat::Gzip, &tar.bytes, &output, &test_options())
                .unwrap();

        assert!(output_bytes > 0);
        assert_eq!(tar.members, 1);
        let recovered = fs::read(&output).unwrap();
        let mut decoder = GzDecoder::new(Cursor::new(recovered));
        let mut repaired_tar = Vec::new();
        decoder.read_to_end(&mut repaired_tar).unwrap();
        assert_eq!(&repaired_tar[..first.len()], first.as_slice());
        assert_eq!(&repaired_tar[first.len()..], &[0u8; 1024]);
        let _ = fs::remove_file(output);
    }

    fn test_options() -> StreamRepairOptions {
        StreamRepairOptions {
            max_input_bytes: None,
            max_output_bytes: Some(10 * 1024 * 1024),
            max_duration: None,
        }
    }

    fn patterned_payload(size: usize) -> Vec<u8> {
        (0..size).map(|index| (index % 251) as u8).collect()
    }

    fn pseudo_random_payload(size: usize) -> Vec<u8> {
        let mut value = 0x1234_5678u32;
        let mut output = Vec::with_capacity(size);
        for _ in 0..size {
            value ^= value << 13;
            value ^= value >> 17;
            value ^= value << 5;
            output.push((value & 0xFF) as u8);
        }
        output
    }

    fn temp_output(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough for tests")
            .as_nanos();
        std::env::temp_dir().join(format!("smart_unpacker_native_{name}_{nonce}"))
    }

    fn tar_member(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        header[0..name.len()].copy_from_slice(name.as_bytes());
        write_tar_octal(&mut header[100..108], 0o644);
        write_tar_octal(&mut header[108..116], 0);
        write_tar_octal(&mut header[116..124], 0);
        write_tar_octal(&mut header[124..136], payload.len() as u64);
        write_tar_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = tar_checksum(&header);
        header[148..156].copy_from_slice(&format_tar_checksum(checksum));

        let mut output = header.to_vec();
        output.extend_from_slice(payload);
        let padding = (512 - (payload.len() % 512)) % 512;
        output.extend(std::iter::repeat(0).take(padding));
        output
    }

    fn write_tar_octal(field: &mut [u8], value: u64) {
        let width = field.len() - 1;
        let text = format!("{:0width$o}\0", value, width = width);
        field.copy_from_slice(text.as_bytes());
    }
}
