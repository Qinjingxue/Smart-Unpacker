#include "sevenzip_password_tester/password_tester.hpp"

#ifdef _WIN32

#include "c_api_common.hpp"
#include "internal/archive_operations.hpp"

SUP7Z_API int sup7z_check_archive_health(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* password,
    Sup7zArchiveHealth* health,
    wchar_t* message,
    int message_chars
) {
    using namespace packrelic::sevenzip;
    using namespace packrelic::sevenzip::capi;
    if (health) {
        *health = Sup7zArchiveHealth{};
    }
    if (!seven_zip_dll_path || !archive_path) {
        copy_message(message, message_chars, "missing required path");
        if (health) {
            health->status = status_code(PasswordTestStatus::Error);
        }
        return status_code(PasswordTestStatus::Error);
    }

    const std::wstring archive_path_text(archive_path);
    const auto result = check_archive_health_with_parts(
        seven_zip_dll_path,
        archive_path_text,
        {archive_path_text},
        password ? password : L"");
    if (health) {
        health->status = status_code(result.status);
        health->is_archive = result.is_archive ? 1 : 0;
        health->is_encrypted = result.encrypted ? 1 : 0;
        health->is_broken = result.damaged ? 1 : 0;
        health->is_missing_volume = result.missing_volume ? 1 : 0;
        health->is_wrong_password = result.wrong_password ? 1 : 0;
        health->operation_result = result.operation_result;
        copy_wide(health->archive_type, 32, archive_type_for_path(archive_path_text));
    }
    copy_message(message, message_chars, result.message);
    return status_code(result.status);
}

SUP7Z_API int sup7z_check_archive_health_with_parts(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* const* part_paths,
    int part_count,
    const wchar_t* password,
    Sup7zArchiveHealth* health,
    wchar_t* message,
    int message_chars
) {
    using namespace packrelic::sevenzip;
    using namespace packrelic::sevenzip::capi;
    if (health) {
        *health = Sup7zArchiveHealth{};
    }
    if (!seven_zip_dll_path || !archive_path) {
        copy_message(message, message_chars, "missing required path");
        if (health) {
            health->status = status_code(PasswordTestStatus::Error);
        }
        return status_code(PasswordTestStatus::Error);
    }

    const std::wstring archive_path_text(archive_path);
    const auto result = check_archive_health_with_parts(
        seven_zip_dll_path,
        archive_path_text,
        collect_part_paths(archive_path, part_paths, part_count),
        password ? password : L"");
    if (health) {
        health->status = status_code(result.status);
        health->is_archive = result.is_archive ? 1 : 0;
        health->is_encrypted = result.encrypted ? 1 : 0;
        health->is_broken = result.damaged ? 1 : 0;
        health->is_missing_volume = result.missing_volume ? 1 : 0;
        health->is_wrong_password = result.wrong_password ? 1 : 0;
        health->operation_result = result.operation_result;
        copy_wide(health->archive_type, 32, archive_type_for_path(archive_path_text));
    }
    copy_message(message, message_chars, result.message);
    return status_code(result.status);
}

#endif
