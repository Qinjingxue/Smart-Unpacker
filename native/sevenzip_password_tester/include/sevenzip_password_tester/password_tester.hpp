#pragma once

#include <string>
#include <vector>

namespace smart_unpacker::sevenzip {

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
    std::string message;
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

const char* status_name(PasswordTestStatus status);

}  // namespace smart_unpacker::sevenzip

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
#endif
