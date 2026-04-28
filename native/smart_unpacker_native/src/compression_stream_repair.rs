use bzip2::read::BzDecoder;
use bzip2::write::BzEncoder;
use bzip2::Compression as Bzip2Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression as GzipCompression;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
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
}
