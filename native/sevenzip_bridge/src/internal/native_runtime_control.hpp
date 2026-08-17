#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <unordered_map>

namespace sunpack::sevenzip {

struct NativeRuntimeSample {
    double cpu_percent = 0.0;
    // Synthetic samples in tests and callers that populate cpu_percent directly
    // are valid by default. The Windows sampler clears this until it has two
    // system-time snapshots to compare.
    bool cpu_percent_valid = true;
    std::size_t available_memory = 0;
};

struct NativeRuntimeSnapshot {
    std::size_t active_limit = 1;
    std::size_t cpu_limit = 1;
    std::size_t memory_limit = 1;
    std::size_t memory_budget = 0;
    std::size_t active_jobs = 0;
    std::size_t active_cpu = 0;
    std::size_t active_memory = 0;
};

struct NativeProfileAdjustment {
    int cpu = 0;
    int memory = 0;
};

struct NativeRuntimeConfig {
    bool adaptive_enabled = true;
    std::size_t initial_active_jobs = 0;
    std::size_t throughput_window_size = 8;
    double throughput_regression_ratio = 0.95;
    std::size_t scale_up_streak_required = 2;
    std::size_t scale_down_streak_required = 3;
    double cpu_scale_up_percent = 65.0;
    double cpu_scale_down_percent = 88.0;
    std::size_t memory_scale_down_available = 1ULL << 30;
    std::size_t memory_scale_up_available = 2ULL << 30;
    std::size_t medium_backlog_threshold = 8;
    std::size_t high_backlog_threshold = 24;
    std::size_t medium_floor_jobs = 2;
    std::size_t high_floor_jobs = 3;
    double idle_decay_seconds = 30.0;
    double idle_limit_recovery_seconds = 5.0;
    double monitor_idle_stop_seconds = 10.0;
    double resume_warmup_seconds = 1.0;
    std::size_t profile_window_size = 4;
    std::size_t profile_calibration_min_parallel = 2;
    int profile_calibration_max_delta = 1;
    double profile_regression_ratio = 0.8;
    double profile_improvement_ratio = 1.2;
};

class NativeRuntimeControl final {
public:
    NativeRuntimeControl(
        std::size_t max_active_jobs,
        std::size_t memory_budget,
        bool adaptive_enabled = true,
        std::size_t initial_active_jobs = 0
    )
        : NativeRuntimeControl(
              max_active_jobs,
              memory_budget,
              NativeRuntimeConfig{adaptive_enabled, initial_active_jobs}) {}

    NativeRuntimeControl(
        std::size_t max_active_jobs,
        std::size_t memory_budget,
        NativeRuntimeConfig config
    )
        : max_active_jobs_((std::max)(std::size_t{1}, max_active_jobs)),
          memory_budget_(memory_budget),
          memory_capacity_(memory_budget),
          adaptive_enabled_(config.adaptive_enabled),
          throughput_window_size_((std::max)(std::size_t{4}, config.throughput_window_size)),
          throughput_regression_ratio_(config.throughput_regression_ratio),
          scale_up_streak_required_((std::max)(std::size_t{1}, config.scale_up_streak_required)),
          scale_down_streak_required_((std::max)(std::size_t{1}, config.scale_down_streak_required)),
          cpu_scale_up_percent_(config.cpu_scale_up_percent),
          cpu_scale_down_percent_(config.cpu_scale_down_percent),
          memory_scale_down_available_(config.memory_scale_down_available),
          memory_scale_up_available_(config.memory_scale_up_available),
          medium_backlog_threshold_((std::max)(std::size_t{1}, config.medium_backlog_threshold)),
          high_backlog_threshold_((std::max)(
              config.medium_backlog_threshold, config.high_backlog_threshold)),
          medium_floor_jobs_((std::max)(std::size_t{1}, config.medium_floor_jobs)),
          high_floor_jobs_((std::max)(config.medium_floor_jobs, config.high_floor_jobs)),
          idle_decay_seconds_((std::max)(0.0, config.idle_decay_seconds)),
          idle_limit_recovery_seconds_((std::max)(0.0, config.idle_limit_recovery_seconds)),
          monitor_idle_stop_seconds_((std::max)(0.0, config.monitor_idle_stop_seconds)),
          resume_warmup_seconds_((std::max)(0.0, config.resume_warmup_seconds)),
          profile_window_size_((std::max)(std::size_t{4}, config.profile_window_size)),
          profile_calibration_min_parallel_((std::max)(std::size_t{1}, config.profile_calibration_min_parallel)),
          profile_calibration_max_delta_((std::max)(0, config.profile_calibration_max_delta)),
          profile_regression_ratio_(config.profile_regression_ratio),
          profile_improvement_ratio_(config.profile_improvement_ratio) {
        const std::size_t initial = config.initial_active_jobs == 0
            ? (std::min)(max_active_jobs_, std::size_t{2})
            : config.initial_active_jobs;
        initial_active_jobs_ = (std::max)(std::size_t{1}, (std::min)(initial, max_active_jobs_));
        active_limit_ = initial_active_jobs_;
        cpu_limit_ = active_limit_;
        memory_limit_ = active_limit_;
    }

    NativeRuntimeControl(const NativeRuntimeControl&) = delete;
    NativeRuntimeControl& operator=(const NativeRuntimeControl&) = delete;

    bool can_admit(
        std::size_t active_jobs,
        std::size_t active_cpu,
        std::size_t active_memory,
        std::size_t cpu_weight,
        std::size_t memory_reserve
    ) const noexcept {
        if (active_jobs >= active_limit_) {
            return false;
        }

        const std::size_t memory_capacity = memory_capacity_ == 0
            ? (std::numeric_limits<std::size_t>::max)()
            : memory_capacity_;
        if (active_memory > memory_capacity ||
            memory_reserve > memory_capacity - (std::min)(active_memory, memory_capacity)) {
            // A single job is allowed to use the configured hard budget even
            // when the soft free-memory controller has temporarily reduced
            // concurrency.  It must never exceed the hard reservation.
            if (active_jobs != 0 || memory_budget_ != 0 && memory_reserve > memory_budget_) {
                return false;
            }
        }

        // A heavy job can run alone even when its weight is larger than the
        // current soft capacity.  Otherwise an estimate could permanently
        // strand a task in the queue.
        if (active_jobs == 0) {
            return memory_budget_ == 0 || memory_reserve <= memory_budget_;
        }
        if (active_cpu > cpu_limit_ || cpu_weight > cpu_limit_ - (std::min)(active_cpu, cpu_limit_)) {
            return false;
        }
        return true;
    }

    bool observe(
        const NativeRuntimeSample& sample,
        std::size_t queued_jobs,
        std::size_t active_jobs,
        std::size_t active_cpu,
        std::size_t active_memory,
        double elapsed_seconds = 0.0,
        bool fast_scale_up = false
    ) {
        if (!adaptive_enabled_) {
            return false;
        }

        const std::size_t old_active = active_limit_;
        const std::size_t old_cpu = cpu_limit_;
        const std::size_t old_memory = memory_limit_;
        const std::size_t old_memory_capacity = memory_capacity_;

        if (queued_jobs == 0 && active_jobs == 0) {
            idle_seconds_ += (std::max)(0.0, elapsed_seconds);
            if (idle_decay_seconds_ > 0.0 && idle_seconds_ >= idle_decay_seconds_) {
                cpu_limit_ = step_toward(cpu_limit_, initial_active_jobs_);
                memory_limit_ = step_toward(memory_limit_, initial_active_jobs_);
                active_limit_ = (std::min)(
                    max_active_jobs_, (std::max)(cpu_limit_, memory_limit_));
                cpu_scale_up_streak_ = 0;
                cpu_scale_down_streak_ = 0;
                memory_scale_up_streak_ = 0;
                memory_scale_down_streak_ = 0;
                throughput_samples_.clear();
                throughput_allows_scale_up_ = true;
                idle_seconds_ = 0.0;
            }
        } else {
            idle_seconds_ = 0.0;
        }

        if (memory_budget_ != 0 && sample.available_memory != 0) {
            if (sample.available_memory < memory_scale_down_available_) {
                memory_capacity_ = (std::max)(
                    (std::min)(memory_budget_, minimum_memory_reserve_),
                    memory_budget_ / 2);
                memory_limit_ = 1;
            } else if (sample.available_memory > memory_scale_up_available_) {
                memory_capacity_ = memory_budget_;
            }
        }

        const std::size_t dynamic_floor = queued_jobs >= (std::max)(
                high_backlog_threshold_, max_active_jobs_ * 4) && max_active_jobs_ >= 4
            ? (std::min)(max_active_jobs_, high_floor_jobs_)
            : queued_jobs >= (std::max)(medium_backlog_threshold_, max_active_jobs_ * 2)
                ? (std::min)(max_active_jobs_, medium_floor_jobs_)
                : std::size_t{1};
        const bool backlog_wants_more = queued_jobs > (std::max)(std::size_t{1}, active_limit_) * 2;

        if (sample.cpu_percent_valid &&
            backlog_wants_more && sample.cpu_percent < cpu_scale_up_percent_) {
            ++cpu_scale_up_streak_;
            cpu_scale_down_streak_ = 0;
        } else if (sample.cpu_percent_valid &&
                   sample.cpu_percent > cpu_scale_down_percent_ &&
                   active_cpu >= (std::max)(std::size_t{1}, cpu_limit_ - 1)) {
            ++cpu_scale_down_streak_;
            cpu_scale_up_streak_ = 0;
        } else {
            cpu_scale_up_streak_ = 0;
            cpu_scale_down_streak_ = 0;
        }

        if (backlog_wants_more && sample.available_memory > memory_scale_up_available_) {
            ++memory_scale_up_streak_;
            memory_scale_down_streak_ = 0;
        } else if (sample.available_memory != 0 &&
                   sample.available_memory < memory_scale_down_available_ &&
                   active_memory >= (std::max)(std::size_t{1}, memory_limit_ - 1)) {
            ++memory_scale_down_streak_;
            memory_scale_up_streak_ = 0;
        } else {
            memory_scale_up_streak_ = 0;
            memory_scale_down_streak_ = 0;
        }

        const std::size_t scale_up_streak_required = fast_scale_up
            ? std::size_t{1}
            : scale_up_streak_required_;
        if (cpu_scale_up_streak_ >= scale_up_streak_required) {
            cpu_limit_ = (std::min)(max_active_jobs_, cpu_limit_ + 1);
            cpu_scale_up_streak_ = 0;
        } else if (cpu_scale_down_streak_ >= scale_down_streak_required_) {
            cpu_limit_ = (std::max)(dynamic_floor, cpu_limit_ - 1);
            cpu_scale_down_streak_ = 0;
        }
        if (memory_scale_up_streak_ >= scale_up_streak_required) {
            memory_limit_ = (std::min)(max_active_jobs_, memory_limit_ + 1);
            memory_scale_up_streak_ = 0;
        } else if (memory_scale_down_streak_ >= scale_down_streak_required_) {
            memory_limit_ = (std::max)(std::size_t{1}, memory_limit_ - 1);
            memory_scale_down_streak_ = 0;
        }

        cpu_limit_ = (std::max)(dynamic_floor, (std::min)(cpu_limit_, max_active_jobs_));
        memory_limit_ = (std::max)(std::size_t{1}, (std::min)(memory_limit_, max_active_jobs_));
        active_limit_ = (std::min)(max_active_jobs_, (std::max)(cpu_limit_, memory_limit_));

        (void)active_jobs;
        return old_active != active_limit_ || old_cpu != cpu_limit_ ||
            old_memory != memory_limit_ || old_memory_capacity != memory_capacity_;
    }

    void set_throughput_allows_scale_up(bool value) noexcept {
        throughput_allows_scale_up_ = value;
    }

    void set_memory_reserve_floor(std::size_t value) noexcept {
        minimum_memory_reserve_ = (std::max)(std::size_t{1}, value);
    }

    NativeRuntimeSnapshot snapshot(
        std::size_t active_jobs,
        std::size_t active_cpu,
        std::size_t active_memory
    ) const noexcept {
        return NativeRuntimeSnapshot{
            active_limit_, cpu_limit_, memory_limit_, memory_capacity_,
            active_jobs, active_cpu, active_memory,
        };
    }

    double monitor_idle_stop_seconds() const noexcept {
        return monitor_idle_stop_seconds_;
    }

    double resume_warmup_seconds() const noexcept {
        return resume_warmup_seconds_;
    }

    bool recover_limits_after_idle(double elapsed_seconds) noexcept {
        if (!idle_recovery_started_) {
            idle_recovery_start_cpu_limit_ = cpu_limit_;
            idle_recovery_start_memory_limit_ = memory_limit_;
            idle_recovery_started_ = true;
            idle_recovery_completed_ = false;
        }
        if (idle_recovery_completed_) {
            return false;
        }

        const double fraction = idle_limit_recovery_seconds_ <= 0.0
            ? 1.0
            : (std::min)(
                1.0,
                (std::max)(0.0, elapsed_seconds) / idle_limit_recovery_seconds_);
        const std::size_t old_active = active_limit_;
        const std::size_t old_cpu = cpu_limit_;
        const std::size_t old_memory = memory_limit_;
        cpu_limit_ = interpolate_toward(
            idle_recovery_start_cpu_limit_, initial_active_jobs_, fraction);
        memory_limit_ = interpolate_toward(
            idle_recovery_start_memory_limit_, initial_active_jobs_, fraction);
        active_limit_ = (std::min)(max_active_jobs_, (std::max)(cpu_limit_, memory_limit_));
        if (fraction >= 1.0) {
            memory_capacity_ = memory_budget_;
            throughput_allows_scale_up_ = true;
            cpu_scale_up_streak_ = 0;
            cpu_scale_down_streak_ = 0;
            memory_scale_up_streak_ = 0;
            memory_scale_down_streak_ = 0;
            idle_seconds_ = 0.0;
            throughput_samples_.clear();
            profile_samples_.clear();
            idle_recovery_completed_ = true;
        }
        return old_active != active_limit_ || old_cpu != cpu_limit_ ||
            old_memory != memory_limit_;
    }

    void cancel_idle_limit_recovery() noexcept {
        idle_recovery_started_ = false;
        idle_recovery_completed_ = false;
    }

    void reset_after_long_idle() noexcept {
        memory_capacity_ = memory_budget_;
        active_limit_ = initial_active_jobs_;
        cpu_limit_ = initial_active_jobs_;
        memory_limit_ = initial_active_jobs_;
        throughput_allows_scale_up_ = true;
        cpu_scale_up_streak_ = 0;
        cpu_scale_down_streak_ = 0;
        memory_scale_up_streak_ = 0;
        memory_scale_down_streak_ = 0;
        idle_seconds_ = 0.0;
        throughput_samples_.clear();
        profile_samples_.clear();
        cancel_idle_limit_recovery();
    }

    NativeProfileAdjustment profile_adjustment(const std::string& profile_key) const noexcept {
        const auto found = profile_adjustments_.find(profile_key);
        return found == profile_adjustments_.end() ? NativeProfileAdjustment{} : found->second;
    }

    bool load_profile_cache(const std::string& path) {
        if (path.empty()) {
            return false;
        }
        std::ifstream input(path);
        if (!input) {
            return false;
        }
        std::string version;
        if (!std::getline(input, version) || version != "SUNPACK_NATIVE_PROFILE_V2") {
            return false;
        }
        std::string key;
        NativeProfileAdjustment adjustment;
        while (input >> std::quoted(key) >> adjustment.cpu >> adjustment.memory) {
            adjustment.cpu = (std::max)(-profile_calibration_max_delta_,
                (std::min)(profile_calibration_max_delta_, adjustment.cpu));
            adjustment.memory = (std::max)(-profile_calibration_max_delta_,
                (std::min)(profile_calibration_max_delta_, adjustment.memory));
            profile_adjustments_[key] = adjustment;
        }
        profile_adjustments_dirty_ = false;
        return true;
    }

    bool save_profile_cache(const std::string& path) const {
        if (path.empty()) {
            return true;
        }
        const std::string temporary_path = path + ".tmp";
        std::ofstream output(temporary_path, std::ios::trunc);
        if (!output) {
            return false;
        }
        output << "SUNPACK_NATIVE_PROFILE_V2\n";
        for (const auto& [key, adjustment] : profile_adjustments_) {
            output << std::quoted(key) << ' '
                   << adjustment.cpu << ' '
                   << adjustment.memory << '\n';
        }
        output.close();
        if (!output) {
            std::remove(temporary_path.c_str());
            return false;
        }
        std::remove(path.c_str());
        if (std::rename(temporary_path.c_str(), path.c_str()) != 0) {
            std::remove(temporary_path.c_str());
            return false;
        }
        return true;
    }

    bool profile_adjustments_dirty() const noexcept {
        return profile_adjustments_dirty_;
    }

    void record_job(
        const std::string& profile_key,
        std::uint64_t estimated_bytes,
        double duration_seconds,
        std::size_t active_jobs_at_start,
        bool success,
        std::size_t cpu_weight,
        std::size_t memory_reserve
    ) {
        if (!success || estimated_bytes == 0 || duration_seconds <= 0.0) {
            return;
        }
        const ProfileSample sample{
            static_cast<double>(estimated_bytes) / duration_seconds,
            (std::max)(std::size_t{1}, active_jobs_at_start),
            cpu_weight,
        };
        throughput_samples_.push_back(sample);
        while (throughput_samples_.size() > throughput_window_size_) {
            throughput_samples_.pop_front();
        }
        if (throughput_samples_.size() >= throughput_window_size_) {
            const std::size_t midpoint = throughput_samples_.size() / 2;
            double previous_total = 0.0;
            double recent_total = 0.0;
            double previous_workers = 0.0;
            double recent_workers = 0.0;
            for (std::size_t index = 0; index < throughput_samples_.size(); ++index) {
                const auto& current = throughput_samples_[index];
                const double total = current.throughput * static_cast<double>(current.active_jobs);
                if (index < midpoint) {
                    previous_total += total;
                    previous_workers += static_cast<double>(current.active_jobs);
                } else {
                    recent_total += total;
                    recent_workers += static_cast<double>(current.active_jobs);
                }
            }
            previous_total /= static_cast<double>(midpoint);
            recent_total /= static_cast<double>(throughput_samples_.size() - midpoint);
            previous_workers /= static_cast<double>(midpoint);
            recent_workers /= static_cast<double>(throughput_samples_.size() - midpoint);
            if (recent_workers <= previous_workers || previous_total <= 0.0) {
                throughput_allows_scale_up_ = true;
            } else {
                throughput_allows_scale_up_ = recent_total >=
                    previous_total * throughput_regression_ratio_;
            }
        }

        if (profile_key.empty()) {
            return;
        }
        if (memory_reserve >= (2ULL << 30)) {
            auto& memory_adjustment = profile_adjustments_[profile_key];
            const int before_memory = memory_adjustment.memory;
            memory_adjustment.memory = (std::min)(
                profile_calibration_max_delta_, memory_adjustment.memory + 1);
            if (memory_adjustment.memory != before_memory) {
                profile_adjustments_dirty_ = true;
            }
        }
        auto& samples = profile_samples_[profile_key];
        samples.push_back(sample);
        while (samples.size() > profile_window_size_) {
            samples.pop_front();
        }
        if (samples.size() < profile_window_size_) {
            return;
        }

        const std::size_t midpoint = samples.size() / 2;
        double previous_total = 0.0;
        double recent_total = 0.0;
        double previous_workers = 0.0;
        double recent_workers = 0.0;
        double average_cpu = 0.0;
        for (std::size_t index = 0; index < samples.size(); ++index) {
            const auto& sample = samples[index];
            const double total = sample.throughput * static_cast<double>(sample.active_jobs);
            if (index < midpoint) {
                previous_total += total;
                previous_workers += static_cast<double>(sample.active_jobs);
            } else {
                recent_total += total;
                recent_workers += static_cast<double>(sample.active_jobs);
            }
            average_cpu += static_cast<double>(sample.cpu_weight);
        }
        previous_total /= static_cast<double>(midpoint);
        recent_total /= static_cast<double>(samples.size() - midpoint);
        previous_workers /= static_cast<double>(midpoint);
        recent_workers /= static_cast<double>(samples.size() - midpoint);
        average_cpu /= static_cast<double>(samples.size());
        if (recent_workers <= previous_workers ||
            recent_workers < static_cast<double>(profile_calibration_min_parallel_) ||
            previous_total <= 0.0) {
            return;
        }

        auto& adjustment = profile_adjustments_[profile_key];
        const NativeProfileAdjustment before = adjustment;
        if (recent_total < previous_total * profile_regression_ratio_) {
            adjustment.cpu = (std::min)(profile_calibration_max_delta_, adjustment.cpu + 1);
            throughput_allows_scale_up_ = false;
        } else if (recent_total > previous_total * profile_improvement_ratio_) {
            if (average_cpu > 1.0) {
                adjustment.cpu = (std::max)(-1, adjustment.cpu - 1);
            }
            throughput_allows_scale_up_ = true;
        } else {
            throughput_allows_scale_up_ = true;
        }
        if (adjustment.cpu != before.cpu || adjustment.memory != before.memory) {
            profile_adjustments_dirty_ = true;
        }
    }

private:
    static std::size_t interpolate_toward(
        std::size_t start,
        std::size_t target,
        double fraction
    ) noexcept {
        const double clamped = (std::min)(1.0, (std::max)(0.0, fraction));
        if (start <= target) {
            return start + static_cast<std::size_t>(
                static_cast<double>(target - start) * clamped);
        }
        return start - static_cast<std::size_t>(
            static_cast<double>(start - target) * clamped);
    }

    static std::size_t step_toward(std::size_t value, std::size_t target) noexcept {
        if (value < target) {
            return value + 1;
        }
        if (value > target) {
            return value - 1;
        }
        return value;
    }

    struct ProfileSample {
        double throughput = 0.0;
        std::size_t active_jobs = 1;
        std::size_t cpu_weight = 1;
    };

    const std::size_t max_active_jobs_;
    const std::size_t memory_budget_;
    std::size_t memory_capacity_;
    const bool adaptive_enabled_;
    std::size_t initial_active_jobs_ = 1;
    std::size_t active_limit_ = 1;
    std::size_t cpu_limit_ = 1;
    std::size_t memory_limit_ = 1;
    std::size_t minimum_memory_reserve_ = 64U << 20;
    bool throughput_allows_scale_up_ = true;

    std::size_t cpu_scale_up_streak_ = 0;
    std::size_t cpu_scale_down_streak_ = 0;
    std::size_t memory_scale_up_streak_ = 0;
    std::size_t memory_scale_down_streak_ = 0;

    const std::size_t throughput_window_size_;
    const double throughput_regression_ratio_;
    const std::size_t scale_up_streak_required_;
    const std::size_t scale_down_streak_required_;
    const double cpu_scale_up_percent_;
    const double cpu_scale_down_percent_;
    const std::size_t memory_scale_down_available_;
    const std::size_t memory_scale_up_available_;
    const std::size_t medium_backlog_threshold_;
    const std::size_t high_backlog_threshold_;
    const std::size_t medium_floor_jobs_;
    const std::size_t high_floor_jobs_;
    const double idle_decay_seconds_;
    const double idle_limit_recovery_seconds_;
    const double monitor_idle_stop_seconds_;
    const double resume_warmup_seconds_;
    const std::size_t profile_window_size_;
    const std::size_t profile_calibration_min_parallel_;
    const int profile_calibration_max_delta_;
    const double profile_regression_ratio_;
    const double profile_improvement_ratio_;

    double idle_seconds_ = 0.0;
    std::size_t idle_recovery_start_cpu_limit_ = 1;
    std::size_t idle_recovery_start_memory_limit_ = 1;
    bool idle_recovery_started_ = false;
    bool idle_recovery_completed_ = false;
    std::deque<ProfileSample> throughput_samples_;
    std::unordered_map<std::string, std::deque<ProfileSample>> profile_samples_;
    std::unordered_map<std::string, NativeProfileAdjustment> profile_adjustments_;
    bool profile_adjustments_dirty_ = false;
};

} // namespace sunpack::sevenzip
