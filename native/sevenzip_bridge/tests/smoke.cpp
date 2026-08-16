#include "sevenzip_bridge/bridge.hpp"
#include "internal/sevenzip_paths.hpp"
#include "internal/sevenzip_status.hpp"
#include "internal/native_runtime_control.hpp"

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
namespace {

bool check_numbered_volume_paths() {
    const std::vector<std::wstring> zip_parts = {
        L"payload.zip.0002",
        L"payload.zip.0000",
        L"payload.zip.0001",
    };
    const auto sorted = sunpack::sevenzip::sorted_data_volume_paths(zip_parts);
    if (sorted.size() != 3 ||
        std::filesystem::path(sorted[0]).filename() != L"payload.zip.0000" ||
        std::filesystem::path(sorted[1]).filename() != L"payload.zip.0001" ||
        std::filesystem::path(sorted[2]).filename() != L"payload.zip.0002" ||
        sunpack::sevenzip::parse_volume_number(sorted[0]).value_or(-1) != 0) {
        return false;
    }

    const std::vector<std::wstring> seven_zip_parts = {
        L"payload.7z.002",
        L"payload.7z.001",
    };
    const auto seven_zip_sorted = sunpack::sevenzip::sorted_data_volume_paths(seven_zip_parts);
    return seven_zip_sorted.size() == 2 &&
        std::filesystem::path(seven_zip_sorted[0]).filename() == L"payload.7z.001" &&
        std::filesystem::path(seven_zip_sorted[1]).filename() == L"payload.7z.002";
}

bool check_wrong_password_evidence() {
    using sunpack::sevenzip::looks_wrong_password;
    using namespace sunpack::sevenzip;
    return
        looks_wrong_password(S_OK, kOpWrongPassword, false) &&
        !looks_wrong_password(S_FALSE, kOpOk, false) &&
        !looks_wrong_password(S_OK, kOpDataError, false) &&
        !looks_wrong_password(S_OK, kOpCrcError, false) &&
        looks_wrong_password(S_FALSE, kOpOk, true) &&
        looks_wrong_password(S_OK, kOpDataError, true) &&
        looks_wrong_password(S_OK, kOpCrcError, true);
}

bool check_password_probe_status_names() {
    return std::string(sunpack::sevenzip::status_name(
        sunpack::sevenzip::PasswordTestStatus::NeedsVolumeOrTailDamaged
    )) == "needs_volume_or_tail_damaged";
}

bool check_runtime_control_keeps_io_out_of_admission() {
    using namespace sunpack::sevenzip;
    NativeRuntimeConfig config;
    config.initial_active_jobs = 3;
    config.scale_down_streak_required = 1;
    config.cpu_scale_down_percent = 80.0;
    NativeRuntimeControl controller(4, 0, config);

    NativeRuntimeSample sample;
    sample.available_memory = 4ULL << 30;
    sample.cpu_percent = 90.0;
    controller.observe(sample, 1, 3, 3, 0, 0.1);
    const auto snapshot = controller.snapshot(3, 3, 0);
    return snapshot.cpu_limit == 2 && snapshot.memory_limit == 3 &&
        !controller.can_admit(3, 3, 0, 1, 0);
}

}  // namespace
#endif

int wmain(int argc, wchar_t** argv) {
#ifdef _WIN32
    if (!check_numbered_volume_paths()) {
        std::cerr << "numbered volume path check failed\n";
        return 2;
    }
    if (!check_wrong_password_evidence()) {
        std::cerr << "wrong password evidence check failed\n";
        return 3;
    }
    if (!check_password_probe_status_names()) {
        std::cerr << "password probe status name check failed\n";
        return 4;
    }
    if (!check_runtime_control_keeps_io_out_of_admission()) {
        std::cerr << "runtime control CPU/memory check failed\n";
        return 5;
    }
#endif

    std::wstring dll_path = L"tools\\7z.dll";
    if (argc > 1) {
        dll_path = argv[1];
    }

    const bool available = sunpack::sevenzip::is_backend_available(dll_path);
    const auto result = sunpack::sevenzip::test_password(dll_path, L"", L"");

    std::cout << "backend_available=" << (available ? "true" : "false") << "\n";
    std::cout << "status=" << sunpack::sevenzip::status_name(result.status) << "\n";
    std::cout << "message=" << result.message << "\n";

    return available == result.backend_available ? 0 : 1;
}
