#include "operation_dispatch.hpp"

#include "archive_operations.hpp"

#include <algorithm>
#include <cwctype>
#include <filesystem>

namespace packrelic::sevenzip {

namespace {

std::wstring lower_extension(const std::wstring& path) {
    std::wstring ext = std::filesystem::path(path).extension().wstring();
    std::transform(ext.begin(), ext.end(), ext.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(::towlower(ch));
    });
    return ext;
}

bool is_archive_type(const std::wstring& type) {
    return !type.empty() && type != L"pe" && type != L"elf" && type != L"macho" && type != L"te";
}

std::vector<const wchar_t*> password_ptrs(const std::vector<std::wstring>& passwords, const std::wstring& fallback) {
    std::vector<const wchar_t*> pointers;
    if (passwords.empty()) {
        pointers.push_back(fallback.c_str());
        return pointers;
    }
    pointers.reserve(passwords.size());
    for (const auto& item : passwords) {
        pointers.push_back(item.c_str());
    }
    return pointers;
}

std::vector<std::wstring> effective_parts(const ArchiveOperationRequest& request) {
    if (!request.part_paths.empty()) {
        return request.part_paths;
    }
    return {request.archive_path};
}

std::wstring operation_archive_type(const ArchiveOperationRequest& request, const PasswordTestResult& result) {
    if (!result.archive_type.empty()) {
        return result.archive_type;
    }
    if (!request.format_hint.empty()) {
        return request.format_hint;
    }
    return archive_type_for_path(request.archive_path);
}

ArchiveOperationResult from_password_result(const ArchiveOperationRequest& request, const PasswordTestResult& result) {
    ArchiveOperationResult output;
    output.status = result.status;
    output.command_ok = result.status == PasswordTestStatus::Ok;
    output.is_encrypted = result.status == PasswordTestStatus::WrongPassword;
    output.is_broken = result.status == PasswordTestStatus::Damaged;
    output.checksum_error = result.status == PasswordTestStatus::Damaged;
    output.matched_index = result.matched_index;
    output.attempts = result.attempts;
    output.archive_offset = result.archive_offset;
    output.archive_type = operation_archive_type(request, result);
    output.item_count = result.status == PasswordTestStatus::Ok ? 1 : 0;
    output.message = result.message;
    return output;
}

PasswordTestResult run_password_attempts(const ArchiveOperationRequest& request) {
    const std::wstring fallback_password;
    const auto pointers = password_ptrs(request.passwords, fallback_password);
    if (!request.ranges.empty()) {
        return test_passwords_with_ranges(
            request.seven_zip_dll_path,
            request.archive_path,
            request.ranges,
            request.format_hint,
            pointers.data(),
            static_cast<int>(pointers.size()));
    }
    return test_passwords_with_parts(
        request.seven_zip_dll_path,
        request.archive_path,
        effective_parts(request),
        pointers.data(),
        static_cast<int>(pointers.size()));
}

PasswordTestResult run_single_test(const ArchiveOperationRequest& request) {
    if (!request.ranges.empty()) {
        const auto pointers = password_ptrs({}, request.password);
        return test_passwords_with_ranges(
            request.seven_zip_dll_path,
            request.archive_path,
            request.ranges,
            request.format_hint,
            pointers.data(),
            static_cast<int>(pointers.size()));
    }
    return test_password_with_parts(
        request.seven_zip_dll_path,
        request.archive_path,
        effective_parts(request),
        request.password);
}

ArchiveOperationResult run_probe(const ArchiveOperationRequest& request) {
    ArchiveOperationRequest probe_request = request;
    probe_request.password.clear();
    probe_request.passwords.clear();
    const PasswordTestResult result = run_single_test(probe_request);
    ArchiveOperationResult output = from_password_result(request, result);
    const std::wstring type = output.archive_type;
    const bool encrypted_result = result.status == PasswordTestStatus::WrongPassword ||
        (result.status == PasswordTestStatus::Unsupported && lower_extension(request.archive_path) == L".7z");
    const bool damaged_result = result.status == PasswordTestStatus::Damaged;
    output.archive_type = type;
    output.is_archive = result.status == PasswordTestStatus::Ok ||
        encrypted_result ||
        damaged_result ||
        is_archive_type(type);
    output.is_encrypted = encrypted_result;
    output.is_broken = damaged_result;
    output.checksum_error = damaged_result;
    output.item_count = result.status == PasswordTestStatus::Ok ? 1 : 0;
    return output;
}

ArchiveOperationResult invalid_request(const std::string& message) {
    ArchiveOperationResult output;
    output.status = PasswordTestStatus::Error;
    output.message = message;
    return output;
}

}  // namespace

ArchiveOperationResult run_archive_operation(const ArchiveOperationRequest& request) {
    if (request.seven_zip_dll_path.empty() || request.archive_path.empty()) {
        return invalid_request("missing required path");
    }

    switch (request.operation) {
    case SUP7Z_OPERATION_PROBE:
        return run_probe(request);
    case SUP7Z_OPERATION_TEST:
        return from_password_result(request, run_single_test(request));
    case SUP7Z_OPERATION_TRY_PASSWORDS:
        return from_password_result(request, run_password_attempts(request));
    default:
        return invalid_request("unsupported operation");
    }
}

}  // namespace packrelic::sevenzip
