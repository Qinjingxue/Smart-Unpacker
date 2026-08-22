#include "internal/sevenzip_async_output.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
namespace {

using sunpack::sevenzip::AsyncFileWriter;

std::filesystem::path make_test_directory() {
    const auto directory = std::filesystem::temp_directory_path() /
        (L"sunpack-async-output-" + std::to_wstring(GetCurrentProcessId()) +
         L"-" + std::to_wstring(GetTickCount64()));
    std::filesystem::create_directories(directory);
    return directory;
}

bool write_same_file_concurrently(const std::filesystem::path& directory) {
    constexpr std::size_t payload_size = 8U << 20;
    std::vector<unsigned char> expected(payload_size);
    for (std::size_t index = 0; index < expected.size(); ++index) {
        expected[index] = static_cast<unsigned char>((index * 37U + index / 257U) & 0xFFU);
    }

    AsyncFileWriter writer;
    const auto job = writer.make_job();
    const auto file = writer.make_file(
        job, (directory / L"parallel.bin").wstring(), L"parallel.bin", 0, 0);
    std::uint32_t processed = 0;
    if (writer.write(file, expected.data(), static_cast<std::uint32_t>(expected.size()), &processed) != S_OK ||
        processed != expected.size()) {
        return false;
    }
    writer.record_operation_result(file, 0);
    writer.close_file(file, 0, false, {});
    if (writer.finish_job(job) != S_OK) {
        return false;
    }

    const auto snapshot = writer.snapshot_file(file);
    const auto metrics = writer.snapshot_metrics();
    if (snapshot.failed || !snapshot.closed || snapshot.accepted_bytes != expected.size() ||
        snapshot.written_bytes != expected.size() || snapshot.peak_active_data_writes < 2 ||
        metrics.accepted_bytes != expected.size() || metrics.written_bytes != expected.size() ||
        metrics.completed_files != 1 || metrics.completed_jobs != 1) {
        std::cerr << "parallel output state: accepted=" << snapshot.accepted_bytes
                  << " written=" << snapshot.written_bytes
                  << " peak=" << snapshot.peak_active_data_writes << "\n";
        return false;
    }

    std::ifstream input(directory / L"parallel.bin", std::ios::binary);
    std::vector<unsigned char> actual(
        (std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    return actual == expected;
}

bool write_zero_length_file(const std::filesystem::path& directory) {
    AsyncFileWriter writer;
    const auto job = writer.make_job();
    const auto file = writer.make_file(
        job, (directory / L"empty.bin").wstring(), L"empty.bin", 1, 1);
    writer.record_operation_result(file, 0);
    writer.close_file(file, 0, false, {});
    if (writer.finish_job(job) != S_OK) {
        return false;
    }
    const auto snapshot = writer.snapshot_file(file);
    std::error_code error;
    return !snapshot.failed && snapshot.closed && snapshot.written_bytes == 0 &&
        std::filesystem::file_size(directory / L"empty.bin", error) == 0 && !error;
}

bool closes_after_delayed_open_failure(const std::filesystem::path& directory) {
    const auto path = directory / L"existing.bin";
    {
        std::ofstream output(path, std::ios::binary);
        output << "existing";
    }

    AsyncFileWriter writer;
    const auto job = writer.make_job();
    const auto file = writer.make_file(job, path.wstring(), L"existing.bin", 2, 2);
    const unsigned char byte = 0xA5;
    std::uint32_t processed = 0;
    if (writer.write(file, &byte, 1, &processed) != S_OK || processed != 1) {
        return false;
    }
    writer.record_operation_result(file, 0);
    writer.close_file(file, 0, false, {});
    if (writer.finish_job(job) == S_OK) {
        return false;
    }
    const auto snapshot = writer.snapshot_file(file);
    std::ifstream input(path, std::ios::binary);
    std::string existing((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    return snapshot.failed && snapshot.closed && snapshot.written_bytes == 0 &&
        existing == "existing";
}

}  // namespace
#endif

int main() {
#ifdef _WIN32
    const auto directory = make_test_directory();
    const bool passed = write_same_file_concurrently(directory) &&
        write_zero_length_file(directory) &&
        closes_after_delayed_open_failure(directory);
    std::error_code error;
    std::filesystem::remove_all(directory, error);
    if (!passed) {
        std::cerr << "async output check failed\n";
        return 1;
    }
#endif
    return 0;
}
