use crate::password_input::{parse_ranges, VirtualRangeReader};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use sevenz_rust2::{Archive, Error as SevenZipError, Password};
use std::fs::File;
use std::io::{Read, Seek};

const SEVEN_Z_SIGNATURE: &[u8] = b"7z\xbc\xaf\x27\x1c";

#[pyfunction]
pub(crate) fn seven_zip_fast_verify_passwords(
    py: Python<'_>,
    archive_path: String,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let candidates = passwords
        .iter()
        .map(|item| item.extract::<String>())
        .collect::<PyResult<Vec<_>>>()?;

    let Ok(mut probe_file) = File::open(&archive_path) else {
        return status(py, "damaged", -1, 0, "7z archive could not be opened");
    };
    let mut signature = [0u8; 6];
    if std::io::Read::read_exact(&mut probe_file, &mut signature).is_err() {
        return status(py, "damaged", -1, 0, "7z archive is too small");
    }
    if signature != SEVEN_Z_SIGNATURE {
        return status(py, "unsupported_method", -1, 0, "7z signature not found");
    }

    match read_archive_header(&archive_path, "") {
        HeaderRead::Ok => {
            return status(py, "unsupported_method", -1, 0, "7z header is readable without password");
        }
        HeaderRead::WrongPasswordOrPasswordRequired => {}
        HeaderRead::Unsupported(message) => {
            return status(py, "unknown_need_fallback", -1, 0, &message);
        }
        HeaderRead::Damaged(message) => {
            return status(py, "damaged", -1, 0, &message);
        }
    }

    for (index, password) in candidates.iter().enumerate() {
        match read_archive_header(&archive_path, password) {
            HeaderRead::Ok => {
                return status(py, "match", index as i32, (index + 1) as i32, "7z encrypted header opened");
            }
            HeaderRead::WrongPasswordOrPasswordRequired => {}
            HeaderRead::Unsupported(message) => {
                return status(py, "unknown_need_fallback", -1, index as i32, &message);
            }
            HeaderRead::Damaged(message) => {
                return status(py, "damaged", -1, index as i32, &message);
            }
        }
    }

    status(py, "no_match", -1, candidates.len() as i32, "7z encrypted header did not open")
}

#[pyfunction]
pub(crate) fn seven_zip_fast_verify_passwords_from_ranges(
    py: Python<'_>,
    ranges: &Bound<'_, PyList>,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let candidates = passwords
        .iter()
        .map(|item| item.extract::<String>())
        .collect::<PyResult<Vec<_>>>()?;
    let parsed = parse_ranges(ranges)?;

    let mut probe_reader = VirtualRangeReader::new(parsed.clone());
    let mut signature = [0u8; 6];
    if std::io::Read::read_exact(&mut probe_reader, &mut signature).is_err() {
        return status(py, "damaged", -1, 0, "7z archive is too small");
    }
    if signature != SEVEN_Z_SIGNATURE {
        return status(py, "unsupported_method", -1, 0, "7z signature not found");
    }

    match read_archive_header_from_reader(VirtualRangeReader::new(parsed.clone()), "") {
        HeaderRead::Ok => {
            return status(py, "unsupported_method", -1, 0, "7z header is readable without password");
        }
        HeaderRead::WrongPasswordOrPasswordRequired => {}
        HeaderRead::Unsupported(message) => {
            return status(py, "unknown_need_fallback", -1, 0, &message);
        }
        HeaderRead::Damaged(message) => {
            return status(py, "damaged", -1, 0, &message);
        }
    }

    for (index, password) in candidates.iter().enumerate() {
        match read_archive_header_from_reader(VirtualRangeReader::new(parsed.clone()), password) {
            HeaderRead::Ok => {
                return status(py, "match", index as i32, (index + 1) as i32, "7z encrypted header opened");
            }
            HeaderRead::WrongPasswordOrPasswordRequired => {}
            HeaderRead::Unsupported(message) => {
                return status(py, "unknown_need_fallback", -1, index as i32, &message);
            }
            HeaderRead::Damaged(message) => {
                return status(py, "damaged", -1, index as i32, &message);
            }
        }
    }

    status(py, "no_match", -1, candidates.len() as i32, "7z encrypted header did not open")
}

enum HeaderRead {
    Ok,
    WrongPasswordOrPasswordRequired,
    Unsupported(String),
    Damaged(String),
}

fn read_archive_header(path: &str, password: &str) -> HeaderRead {
    let Ok(mut file) = File::open(path) else {
        return HeaderRead::Damaged("7z archive could not be opened".to_string());
    };
    read_archive_header_from_reader(&mut file, password)
}

fn read_archive_header_from_reader<R: Read + Seek>(mut reader: R, password: &str) -> HeaderRead {
    match Archive::read(&mut reader, &Password::from(password)) {
        Ok(_) => HeaderRead::Ok,
        Err(SevenZipError::PasswordRequired) | Err(SevenZipError::MaybeBadPassword(_)) => {
            HeaderRead::WrongPasswordOrPasswordRequired
        }
        Err(SevenZipError::BadSignature(_))
        | Err(SevenZipError::UnsupportedVersion { .. })
        | Err(SevenZipError::NextHeaderCrcMismatch) => HeaderRead::Damaged("7z header is damaged".to_string()),
        Err(SevenZipError::Unsupported(message)) => HeaderRead::Unsupported(message.to_string()),
        Err(SevenZipError::UnsupportedCompressionMethod(message)) => HeaderRead::Unsupported(message),
        Err(SevenZipError::ExternalUnsupported) => {
            HeaderRead::Unsupported("7z external compression method is unsupported".to_string())
        }
        Err(error) => HeaderRead::Unsupported(format!("7z header-only verifier could not classify error: {error}")),
    }
}

fn status(py: Python<'_>, status: &str, matched_index: i32, attempts: i32, message: &str) -> PyResult<Py<PyAny>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("matched_index", matched_index)?;
    result.set_item("attempts", attempts)?;
    result.set_item("message", message)?;
    Ok(result.into())
}
