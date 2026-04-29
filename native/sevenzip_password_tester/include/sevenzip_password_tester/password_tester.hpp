#pragma once

#include <string>
#include <vector>
#include <functional>

namespace sunpack::sevenzip {

enum class PasswordTestStatus {
    Ok,
    WrongPassword,
    Damaged,
    Unsupported,
    BackendUnavailable,
    Error,
};

struct PasswordTestResult {
    PasswordTestStatus status = PasswordTestStatus::BackendUnavailable;
    bool backend_available = false;
    int matched_index = -1;
    int attempts = 0;
    unsigned long long archive_offset = 0;
    std::wstring archive_type;
    std::string message;
};

struct ExtractProgressEvent {
    std::string event;
    unsigned long long completed_bytes = 0;
    unsigned long long total_bytes = 0;
    unsigned int item_index = 0;
    std::wstring item_path;
};

struct ExtractHandlerAttempt {
    std::wstring format;
    int create_hresult = 0;
    int open_hresult = 0;
    bool created = false;
    bool opened = false;
};

struct ExtractInputTrace {
    std::wstring mode;
    unsigned long long virtual_size = 0;
    unsigned long long position = 0;
    unsigned long long max_position_seen = 0;
    unsigned long long total_bytes_returned = 0;
    unsigned long long last_read_virtual_offset = 0;
    unsigned long long last_read_source_offset = 0;
    unsigned long long last_seek_new_position = 0;
    unsigned int last_read_requested = 0;
    unsigned int last_read_returned = 0;
    unsigned int last_seek_origin = 0;
    unsigned int last_range_index = 0;
    long long last_seek_offset = 0;
    int last_hresult = 0;
    int last_win32_error = 0;
    bool read_error = false;
    std::wstring last_source_path;
};

struct ExtractOutputItemTrace {
    unsigned int index = 0;
    unsigned long long bytes_written = 0;
    int operation_result = 0;
    int hresult = 0;
    int win32_error = 0;
    bool is_dir = false;
    bool done = false;
    bool failed = false;
    std::wstring path;
};

struct ExtractOutputTrace {
    unsigned long long total_bytes_written = 0;
    unsigned long long current_item_bytes_written = 0;
    unsigned long long last_write_size = 0;
    unsigned int current_item_index = 0;
    int last_hresult = 0;
    int last_win32_error = 0;
    std::wstring current_item_path;
    std::vector<ExtractOutputItemTrace> items;
};

struct ExtractArchiveResult {
    PasswordTestStatus status = PasswordTestStatus::BackendUnavailable;
    bool backend_available = false;
    bool command_ok = false;
    bool encrypted = false;
    bool damaged = false;
    bool checksum_error = false;
    bool missing_volume = false;
    bool wrong_password = false;
    bool unsupported_method = false;
    int operation_result = 0;
    unsigned int item_count = 0;
    unsigned int files_written = 0;
    unsigned int dirs_written = 0;
    unsigned long long bytes_written = 0;
    unsigned int failed_item_index = 0;
    unsigned long long failed_item_bytes_written = 0;
    int hresult = 0;
    std::wstring archive_type;
    std::wstring failed_item;
    std::string failure_stage;
    std::string failure_kind;
    std::string message;
    ExtractInputTrace input_trace;
    ExtractOutputTrace output_trace;
    std::vector<ExtractHandlerAttempt> handler_attempts;
};

using ExtractProgressCallback = std::function<void(const ExtractProgressEvent&)>;

struct ExtractInputRange {
    std::wstring path;
    unsigned long long start = 0;
    unsigned long long end = 0;
    bool has_end = false;
};

struct ExtractPatchOperation {
    std::wstring op;
    std::wstring target = L"logical";
    unsigned long long offset = 0;
    unsigned long long size = 0;
    bool has_size = false;
    std::vector<unsigned char> data;
};

bool is_backend_available(const std::wstring& seven_zip_dll_path);

PasswordTestResult test_password(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::wstring& password
);

PasswordTestResult test_password_with_parts(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::wstring& password
);

PasswordTestResult test_passwords(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const wchar_t* const* passwords,
    int password_count
);

PasswordTestResult test_passwords_with_parts(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const wchar_t* const* passwords,
    int password_count
);

PasswordTestResult test_passwords_with_ranges(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<ExtractInputRange>& ranges,
    const std::wstring& format_hint,
    const wchar_t* const* passwords,
    int password_count
);

ExtractArchiveResult extract_archive_with_parts(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::wstring& format_hint,
    const std::wstring& password,
    const std::wstring& output_dir,
    ExtractProgressCallback progress = nullptr,
    bool dry_run = false
);

ExtractArchiveResult extract_archive_with_ranges(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<ExtractInputRange>& ranges,
    const std::wstring& format_hint,
    const std::wstring& password,
    const std::wstring& output_dir,
    ExtractProgressCallback progress = {},
    bool dry_run = false
);

ExtractArchiveResult extract_archive_with_patches(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::vector<ExtractInputRange>& ranges,
    const std::vector<ExtractPatchOperation>& patches,
    const std::wstring& format_hint,
    const std::wstring& password,
    const std::wstring& output_dir,
    ExtractProgressCallback progress = {},
    bool dry_run = false
);

const char* status_name(PasswordTestStatus status);

}  // namespace sunpack::sevenzip

#ifdef _WIN32
#ifdef SUP7Z_BUILD_DLL
#define SUP7Z_API extern "C" __declspec(dllexport)
#else
#define SUP7Z_API extern "C" __declspec(dllimport)
#endif

SUP7Z_API int sup7z_try_passwords(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* const* passwords,
    int password_count,
    int* matched_index,
    int* attempts,
    wchar_t* message,
    int message_chars
);

SUP7Z_API int sup7z_try_passwords_with_parts(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* const* part_paths,
    int part_count,
    const wchar_t* const* passwords,
    int password_count,
    int* matched_index,
    int* attempts,
    wchar_t* message,
    int message_chars
);

SUP7Z_API int sup7z_test_archive(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* password,
    int* command_ok,
    int* encrypted,
    int* checksum_error,
    wchar_t* archive_type,
    int archive_type_chars,
    wchar_t* message,
    int message_chars
);

SUP7Z_API int sup7z_test_archive_with_parts(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* const* part_paths,
    int part_count,
    const wchar_t* password,
    int* command_ok,
    int* encrypted,
    int* checksum_error,
    wchar_t* archive_type,
    int archive_type_chars,
    wchar_t* message,
    int message_chars
);

SUP7Z_API int sup7z_probe_archive(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    int* is_archive,
    int* is_encrypted,
    int* is_broken,
    int* checksum_error,
    unsigned long long* offset,
    int* item_count,
    wchar_t* archive_type,
    int archive_type_chars,
    wchar_t* message,
    int message_chars
);

struct Sup7zArchiveHealth {
    int status;
    int is_archive;
    int is_encrypted;
    int is_broken;
    int is_missing_volume;
    int is_wrong_password;
    int operation_result;
    wchar_t archive_type[32];
};

struct Sup7zArchiveResourceAnalysis {
    int status;
    int is_archive;
    int is_encrypted;
    int is_broken;
    int solid;
    int item_count;
    int file_count;
    int dir_count;
    unsigned long long archive_size;
    unsigned long long total_unpacked_size;
    unsigned long long total_packed_size;
    unsigned long long largest_item_size;
    unsigned long long largest_dictionary_size;
    wchar_t archive_type[32];
    wchar_t dominant_method[128];
};

enum Sup7zOperationKind {
    SUP7Z_OPERATION_PROBE = 1,
    SUP7Z_OPERATION_TEST = 2,
    SUP7Z_OPERATION_TRY_PASSWORDS = 3,
};

struct Sup7zInputRange {
    const wchar_t* path;
    unsigned long long start;
    unsigned long long end;
    int has_end;
};

struct Sup7zOperationRequest {
    int operation;
    const wchar_t* seven_zip_dll_path;
    const wchar_t* archive_path;
    const wchar_t* const* part_paths;
    int part_count;
    const Sup7zInputRange* ranges;
    int range_count;
    const wchar_t* format_hint;
    const wchar_t* password;
    const wchar_t* const* passwords;
    int password_count;
};

struct Sup7zOperationResult {
    int status;
    int command_ok;
    int is_archive;
    int is_encrypted;
    int is_broken;
    int checksum_error;
    int matched_index;
    int attempts;
    unsigned long long archive_offset;
    int item_count;
    wchar_t archive_type[64];
    wchar_t message[512];
};

SUP7Z_API int sup7z_run_operation(
    const Sup7zOperationRequest* request,
    Sup7zOperationResult* result
);

SUP7Z_API int sup7z_check_archive_health(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* password,
    Sup7zArchiveHealth* health,
    wchar_t* message,
    int message_chars
);

SUP7Z_API int sup7z_check_archive_health_with_parts(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* const* part_paths,
    int part_count,
    const wchar_t* password,
    Sup7zArchiveHealth* health,
    wchar_t* message,
    int message_chars
);

SUP7Z_API int sup7z_analyze_archive_resources(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* password,
    Sup7zArchiveResourceAnalysis* analysis,
    wchar_t* message,
    int message_chars
);

SUP7Z_API int sup7z_analyze_archive_resources_with_parts(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* const* part_paths,
    int part_count,
    const wchar_t* password,
    Sup7zArchiveResourceAnalysis* analysis,
    wchar_t* message,
    int message_chars
);

SUP7Z_API int sup7z_read_archive_crc_manifest(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* password,
    int max_items,
    wchar_t* manifest_json,
    int manifest_json_chars,
    wchar_t* message,
    int message_chars
);

SUP7Z_API int sup7z_read_archive_crc_manifest_with_parts(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* const* part_paths,
    int part_count,
    const wchar_t* password,
    int max_items,
    wchar_t* manifest_json,
    int manifest_json_chars,
    wchar_t* message,
    int message_chars
);
#endif
