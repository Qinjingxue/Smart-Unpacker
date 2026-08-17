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

bool check_runtime_control_resets_after_long_idle() {
    using namespace sunpack::sevenzip;
    NativeRuntimeConfig config;
    config.initial_active_jobs = 3;
    config.scale_up_streak_required = 1;
    NativeRuntimeControl controller(4, 0, config);

    NativeRuntimeSample sample;
    sample.available_memory = 4ULL << 30;
    sample.cpu_percent = 10.0;
    controller.observe(sample, 10, 3, 3, 0, 0.1);
    if (controller.snapshot(0, 0, 0).active_limit != 4) {
        return false;
    }

    controller.reset_after_long_idle();
    const auto snapshot = controller.snapshot(0, 0, 0);
    return snapshot.active_limit == 3 && snapshot.cpu_limit == 3 &&
        snapshot.memory_limit == 3;
}

bool check_runtime_control_recovers_limits_over_idle_window() {
    using namespace sunpack::sevenzip;
    NativeRuntimeConfig config;
    config.initial_active_jobs = 1;
    config.scale_up_streak_required = 1;
    config.idle_limit_recovery_seconds = 5.0;
    NativeRuntimeControl controller(4, 0, config);

    NativeRuntimeSample sample;
    sample.available_memory = 4ULL << 30;
    sample.cpu_percent = 10.0;
    controller.observe(sample, 10, 1, 1, 0, 0.1);
    controller.observe(sample, 10, 2, 2, 0, 0.1);
    controller.observe(sample, 10, 3, 3, 0, 0.1);
    if (controller.snapshot(0, 0, 0).active_limit != 4) {
        return false;
    }

    controller.recover_limits_after_idle(0.0);
    controller.recover_limits_after_idle(2.5);
    if (controller.snapshot(0, 0, 0).active_limit != 3) {
        return false;
    }
    controller.recover_limits_after_idle(5.0);
    const auto snapshot = controller.snapshot(0, 0, 0);
    return snapshot.active_limit == 1 && snapshot.cpu_limit == 1 &&
        snapshot.memory_limit == 1;
}

bool check_runtime_control_ignores_unprimed_cpu_sample() {
    using namespace sunpack::sevenzip;
    NativeRuntimeConfig config;
    config.initial_active_jobs = 1;
    config.scale_up_streak_required = 1;
    config.medium_backlog_threshold = 100;
    config.high_backlog_threshold = 200;
    NativeRuntimeControl controller(4, 0, config);

    NativeRuntimeSample sample;
    sample.cpu_percent_valid = false;
    sample.cpu_percent = 0.0;
    controller.observe(sample, 3, 1, 1, 0, 0.1);
    return controller.snapshot(1, 1, 0).cpu_limit == 1;
}

bool check_runtime_control_fast_scale_up_after_resume() {
    using namespace sunpack::sevenzip;
    NativeRuntimeConfig config;
    config.initial_active_jobs = 1;
    config.scale_up_streak_required = 2;
    config.medium_backlog_threshold = 100;
    config.high_backlog_threshold = 200;
    NativeRuntimeControl controller(4, 0, config);

    NativeRuntimeSample sample;
    sample.available_memory = 4ULL << 30;
    sample.cpu_percent = 10.0;
    controller.observe(sample, 3, 1, 1, 0, 0.1, true);
    const auto snapshot = controller.snapshot(1, 1, 0);
    return snapshot.active_limit == 2 && snapshot.cpu_limit == 2 &&
        snapshot.memory_limit == 2;
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
    if (!check_runtime_control_resets_after_long_idle()) {
        std::cerr << "runtime control idle reset check failed\n";
        return 6;
    }
    if (!check_runtime_control_recovers_limits_over_idle_window()) {
        std::cerr << "runtime control idle recovery check failed\n";
        return 7;
    }
    if (!check_runtime_control_ignores_unprimed_cpu_sample()) {
        std::cerr << "runtime control CPU baseline check failed\n";
        return 8;
    }
    if (!check_runtime_control_fast_scale_up_after_resume()) {
        std::cerr << "runtime control fast resume scale-up check failed\n";
        return 9;
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
