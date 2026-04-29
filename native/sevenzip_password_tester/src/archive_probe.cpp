#include "sevenzip_password_tester/password_tester.hpp"

#ifdef _WIN32

#include <algorithm>
#include <cwchar>
#include <filesystem>
#include <string>

namespace {

std::wstring lower_extension(const std::wstring& path) {
    std::wstring ext = std::filesystem::path(path).extension().wstring();
    std::transform(ext.begin(), ext.end(), ext.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(::towlower(ch));
    });
    return ext;
}

std::wstring archive_type_for_path(const std::wstring& path) {
    const std::wstring ext = lower_extension(path);
    if (ext == L".zip" || ext == L".jar" || ext == L".docx" || ext == L".xlsx" || ext == L".apk") {
        return L"zip";
    }
    if (ext == L".7z" || ext == L".001") {
        return L"7z";
    }
    if (ext == L".rar" || ext == L".r00") {
        return L"rar";
    }
    if (ext == L".exe" || ext == L".dll") {
        return L"pe";
    }
    if (ext == L".tar") {
        return L"tar";
    }
    if (ext == L".gz" || ext == L".tgz") {
        return L"gzip";
    }
    if (ext == L".bz2" || ext == L".tbz" || ext == L".tbz2") {
        return L"bzip2";
    }
    if (ext == L".xz" || ext == L".txz") {
        return L"xz";
    }
    return L"";
}

bool is_archive_type(const std::wstring& type) {
    return !type.empty() && type != L"pe" && type != L"elf" && type != L"macho" && type != L"te";
}

void copy_text(wchar_t* destination, int destination_chars, const std::wstring& text) {
    if (!destination || destination_chars <= 0) {
        return;
    }
    const int count = static_cast<int>(std::min<std::size_t>(text.size(), static_cast<std::size_t>(destination_chars - 1)));
    std::wmemcpy(destination, text.c_str(), count);
    destination[count] = L'\0';
}

void copy_ascii(wchar_t* destination, int destination_chars, const std::string& text) {
    copy_text(destination, destination_chars, std::wstring(text.begin(), text.end()));
}

}  // namespace

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
) {
    if (is_archive) {
        *is_archive = 0;
    }
    if (is_encrypted) {
        *is_encrypted = 0;
    }
    if (is_broken) {
        *is_broken = 0;
    }
    if (checksum_error) {
        *checksum_error = 0;
    }
    if (offset) {
        *offset = 0;
    }
    if (item_count) {
        *item_count = 0;
    }
    if (!seven_zip_dll_path || !archive_path) {
        copy_ascii(message, message_chars, "missing required path");
        return static_cast<int>(sunpack::sevenzip::PasswordTestStatus::Error);
    }

    const std::wstring archive_path_text(archive_path);

    const auto result = sunpack::sevenzip::test_password(seven_zip_dll_path, archive_path_text, L"");
    const std::wstring type = result.archive_type.empty() ? archive_type_for_path(archive_path_text) : result.archive_type;
    copy_text(archive_type, archive_type_chars, type);
    const bool encrypted_result = result.status == sunpack::sevenzip::PasswordTestStatus::WrongPassword ||
        (result.status == sunpack::sevenzip::PasswordTestStatus::Unsupported && lower_extension(archive_path_text) == L".7z");
    const bool damaged_result = result.status == sunpack::sevenzip::PasswordTestStatus::Damaged;

    if (is_archive) {
        *is_archive = (result.status == sunpack::sevenzip::PasswordTestStatus::Ok ||
            encrypted_result ||
            damaged_result ||
            is_archive_type(type)) ? 1 : 0;
    }
    if (is_encrypted) {
        *is_encrypted = encrypted_result ? 1 : 0;
    }
    if (is_broken) {
        *is_broken = damaged_result ? 1 : 0;
    }
    if (checksum_error) {
        *checksum_error = damaged_result ? 1 : 0;
    }
    if (offset) {
        *offset = result.archive_offset;
    }
    if (item_count) {
        *item_count = result.status == sunpack::sevenzip::PasswordTestStatus::Ok ? 1 : 0;
    }
    copy_ascii(message, message_chars, result.message);
    return static_cast<int>(result.status);
}

#endif
