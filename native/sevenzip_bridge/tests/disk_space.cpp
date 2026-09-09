#include "internal/sevenzip_async_output.hpp"
#include <iostream>
#include <stdexcept>
#include <thread>
using namespace sunpack::sevenzip;
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
std::shared_ptr<DiskSpaceVolume> fake(uint64_t free) {
    auto volume = std::make_shared<DiskSpaceVolume>();
    volume->provider = [free] { return DiskSpaceSample{free, 0}; };
    return volume;
}
int main() {
    try {
        DiskSpacePolicy policy{0, 64, 60000};
        auto volume = fake(100);
        {
            DiskSpaceLease first(volume, policy), second(volume, policy);
            require(first.consume(60), "first grant");
            require(!second.consume(50), "concurrent overcommit");
            require(second.error() == ERROR_DISK_FULL, "full classification");
            first.written(60);
            require(volume->balance == 36, "written bytes must not return credit");
        }
        require(volume->pending == 0 && volume->balance == 40, "release only unused credit");
        require(volume->queries == 1, "merge cached queries");
        auto other = fake(100);
        DiskSpaceLease independent(other, policy);
        require(independent.consume(90), "independent volume");
        auto broken = fake(100);
        broken->provider = [] { return DiskSpaceSample{0, ERROR_ACCESS_DENIED}; };
        DiskSpaceLease denied(broken, policy);
        require(!denied.consume(1) && denied.error() == ERROR_ACCESS_DENIED, "query errors");
        auto zero_volume = fake(0);
        DiskSpaceLease empty(zero_volume, policy);
        require(empty.check_total(0), "zero total is valid");
        auto known_too_large = fake(100);
        DiskSpaceLease rejected_total(known_too_large, policy);
        require(!rejected_total.check_total(101), "known total rejects early");
        require(known_too_large->rejections == 1, "known total rejection is counted");
        auto raced = fake(100);
        DiskSpaceLease producer(raced, policy);
        require(producer.consume(60), "race setup");
        raced->provider = [&] { producer.written(60); return DiskSpaceSample{100, 0}; };
        { std::lock_guard<std::mutex> lock(raced->mutex); raced->sampled = {}; }
        raced->refresh(0);
        require(raced->balance == 36, "sample race must charge completed writes");
        auto many = fake(640);
        std::vector<std::shared_ptr<DiskSpaceLease>> leases;
        for (int i=0;i<32;++i) leases.push_back(std::make_shared<DiskSpaceLease>(many, policy));
        std::atomic<int> admitted{0};
        std::vector<std::thread> threads;
        for (auto lease: leases) threads.emplace_back([lease,&admitted] { if (lease->consume(64)) ++admitted; });
        for (auto& thread: threads) thread.join();
        require(admitted == 10, "threaded grants");
        leases.clear();
        require(many->pending == 0 && many->balance == 640, "cancel reservations");
        auto directory = std::filesystem::temp_directory_path() / (L"sunpack-space-test-" + std::to_wstring(GetCurrentProcessId()));
        std::filesystem::create_directories(directory);
        {
            AsyncFileWriter writer;
            auto job = writer.make_job();
            auto limited = fake(4096);
            job->disk_space = std::make_shared<DiskSpaceLease>(limited, DiskSpacePolicy{0,4096,500});
            auto file = writer.make_file(job, (directory/L"partial.bin").wstring(), L"partial.bin", 0, 0);
            std::vector<char> payload(4096, 'x'); UInt32 count=0;
            require(writer.write(file,payload.data(),4096,&count)==S_OK && count==4096,"buffer charged");
            require(writer.write(file,payload.data(),4096,&count)==HRESULT_FROM_WIN32(ERROR_DISK_FULL),"reject excess");
            writer.close_file(file,0,false,{});
            require(writer.finish_job(job)!=S_OK,"failure after drain");
        }
        std::filesystem::remove_all(directory);
        std::cout << "disk space tests passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
