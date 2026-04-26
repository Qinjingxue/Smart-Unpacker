#include "sevenzip_password_tester/password_tester.hpp"

#ifdef _WIN32

#include "c_api_common.hpp"
#include "internal/archive_operations.hpp"

namespace {

void fill_analysis(
    Sup7zArchiveResourceAnalysis* analysis,
    const smart_unpacker::sevenzip::ResourceAnalysisResult& result,
    const std::wstring& archive_path
) {
    using namespace smart_unpacker::sevenzip;
    using namespace smart_unpacker::sevenzip::capi;
    if (!analysis) {
        return;
    }
    analysis->status = status_code(result.status);
    analysis->is_archive = result.is_archive ? 1 : 0;
    analysis->is_encrypted = result.encrypted ? 1 : 0;
    analysis->is_broken = result.damaged ? 1 : 0;
    analysis->solid = result.solid ? 1 : 0;
    analysis->item_count = static_cast<int>(result.item_count);
    analysis->file_count = static_cast<int>(result.file_count);
    analysis->dir_count = static_cast<int>(result.dir_count);
    analysis->archive_size = result.archive_size;
    analysis->total_unpacked_size = result.total_unpacked_size;
    analysis->total_packed_size = result.total_packed_size;
    analysis->largest_item_size = result.largest_item_size;
    analysis->largest_dictionary_size = result.largest_dictionary_size;
    copy_wide(analysis->archive_type, 32, archive_type_for_path(archive_path));
    copy_wide(analysis->dominant_method, 128, result.dominant_method);
}

void fill_health(
    Sup7zArchiveHealth* health,
    const smart_unpacker::sevenzip::HealthProbeResult& result,
    const std::wstring& archive_path
) {
    using namespace smart_unpacker::sevenzip;
    using namespace smart_unpacker::sevenzip::capi;
    if (!health) {
        return;
    }
    health->status = status_code(result.status);
    health->is_archive = result.is_archive ? 1 : 0;
    health->is_encrypted = result.encrypted ? 1 : 0;
    health->is_broken = result.damaged ? 1 : 0;
    health->is_missing_volume = result.missing_volume ? 1 : 0;
    health->is_wrong_password = result.wrong_password ? 1 : 0;
    health->operation_result = result.operation_result;
    copy_wide(health->archive_type, 32, archive_type_for_path(archive_path));
}

}  // namespace

SUP7Z_API int sup7z_analyze_archive_resources(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* password,
    Sup7zArchiveResourceAnalysis* analysis,
    wchar_t* message,
    int message_chars
) {
    using namespace smart_unpacker::sevenzip;
    using namespace smart_unpacker::sevenzip::capi;
    if (analysis) {
        *analysis = Sup7zArchiveResourceAnalysis{};
    }
    if (!seven_zip_dll_path || !archive_path) {
        copy_message(message, message_chars, "missing required path");
        if (analysis) {
            analysis->status = status_code(PasswordTestStatus::Error);
        }
        return status_code(PasswordTestStatus::Error);
    }

    const std::wstring archive_path_text(archive_path);
    const auto result = analyze_archive_resources_with_parts(
        seven_zip_dll_path,
        archive_path_text,
        {archive_path_text},
        password ? password : L"");
    fill_analysis(analysis, result, archive_path_text);
    copy_message(message, message_chars, result.message);
    return status_code(result.status);
}

SUP7Z_API int sup7z_analyze_archive_resources_with_parts(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* const* part_paths,
    int part_count,
    const wchar_t* password,
    Sup7zArchiveResourceAnalysis* analysis,
    wchar_t* message,
    int message_chars
) {
    using namespace smart_unpacker::sevenzip;
    using namespace smart_unpacker::sevenzip::capi;
    if (analysis) {
        *analysis = Sup7zArchiveResourceAnalysis{};
    }
    if (!seven_zip_dll_path || !archive_path) {
        copy_message(message, message_chars, "missing required path");
        if (analysis) {
            analysis->status = status_code(PasswordTestStatus::Error);
        }
        return status_code(PasswordTestStatus::Error);
    }

    const std::wstring archive_path_text(archive_path);
    const auto result = analyze_archive_resources_with_parts(
        seven_zip_dll_path,
        archive_path_text,
        collect_part_paths(archive_path, part_paths, part_count),
        password ? password : L"");
    fill_analysis(analysis, result, archive_path_text);
    copy_message(message, message_chars, result.message);
    return status_code(result.status);
}

SUP7Z_API int sup7z_preflight_archive_resources_with_parts(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* const* part_paths,
    int part_count,
    const wchar_t* password,
    Sup7zArchivePreflightResources* preflight,
    wchar_t* message,
    int message_chars
) {
    using namespace smart_unpacker::sevenzip;
    using namespace smart_unpacker::sevenzip::capi;
    if (preflight) {
        *preflight = Sup7zArchivePreflightResources{};
    }
    if (!seven_zip_dll_path || !archive_path) {
        copy_message(message, message_chars, "missing required path");
        if (preflight) {
            preflight->health.status = status_code(PasswordTestStatus::Error);
            preflight->analysis.status = status_code(PasswordTestStatus::Error);
        }
        return status_code(PasswordTestStatus::Error);
    }

    const std::wstring archive_path_text(archive_path);
    const auto result = preflight_archive_resources_with_parts(
        seven_zip_dll_path,
        archive_path_text,
        collect_part_paths(archive_path, part_paths, part_count),
        password ? password : L"");
    if (preflight) {
        fill_health(&preflight->health, result.health, archive_path_text);
        fill_analysis(&preflight->analysis, result.analysis, archive_path_text);
        preflight->analysis_available = result.analysis_available ? 1 : 0;
    }
    copy_message(message, message_chars, result.health.message.empty() ? result.analysis.message : result.health.message);
    return status_code(result.health.status);
}

#endif
