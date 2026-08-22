#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace sunpack::sevenzip {

struct NativeMachineResources {
    std::size_t logical_processors = 2;
    std::uint64_t total_memory_bytes = 0;
    std::uint64_t available_memory_bytes = 0;
};

struct NativeSizingOverrides {
    std::size_t thread_capacity = 0;
    std::size_t initial_active_jobs = 0;
    std::size_t memory_budget_bytes = 0;
    bool background = false;
};

struct NativeSizingTuning {
    std::size_t maximum_thread_capacity = 32;
    std::size_t foreground_cpu_divisor = 2;
    std::size_t background_cpu_divisor = 4;
    std::uint64_t memory_per_slot_bytes = 512ULL << 20;
    std::uint64_t memory_budget_numerator = 7;
    std::uint64_t memory_budget_denominator = 10;
};

struct NativeSizingPlan {
    std::size_t thread_capacity = 1;
    std::size_t initial_active_jobs = 1;
    std::size_t medium_floor_jobs = 1;
    std::size_t high_floor_jobs = 1;
    std::size_t memory_budget_bytes = 0;
    bool thread_capacity_overridden = false;
    bool initial_active_jobs_overridden = false;
    bool memory_budget_overridden = false;
};

inline std::size_t native_sizing_ceil_div(std::size_t value, std::size_t divisor) noexcept {
    if (divisor == 0) {
        return value;
    }
    return value / divisor + (value % divisor == 0 ? 0 : 1);
}

inline std::size_t native_sizing_memory_budget(
    const NativeMachineResources& resources,
    const NativeSizingOverrides& overrides,
    const NativeSizingTuning& tuning
) noexcept {
    if (overrides.memory_budget_bytes != 0) {
        return overrides.memory_budget_bytes;
    }
    if (resources.available_memory_bytes == 0 || tuning.memory_budget_denominator == 0) {
        // Unknown memory is represented as an unlimited hard budget. CPU still
        // bounds the executor, and every submitted job keeps its own reserve.
        return 0;
    }
    const std::uint64_t quotient =
        resources.available_memory_bytes / tuning.memory_budget_denominator;
    const std::uint64_t remainder =
        resources.available_memory_bytes % tuning.memory_budget_denominator;
    const std::uint64_t budget = quotient * tuning.memory_budget_numerator +
        remainder * tuning.memory_budget_numerator / tuning.memory_budget_denominator;
    return static_cast<std::size_t>((std::min)(
        budget,
        static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())));
}

inline NativeSizingPlan derive_native_sizing_plan(
    NativeMachineResources resources,
    const NativeSizingOverrides& overrides,
    NativeSizingTuning tuning = {}
) noexcept {
    resources.logical_processors = (std::max)(std::size_t{1}, resources.logical_processors);
    tuning.maximum_thread_capacity = (std::max)(std::size_t{1}, tuning.maximum_thread_capacity);
    tuning.memory_per_slot_bytes = (std::max)(std::uint64_t{1}, tuning.memory_per_slot_bytes);

    NativeSizingPlan plan;
    plan.thread_capacity_overridden = overrides.thread_capacity != 0;
    plan.initial_active_jobs_overridden = overrides.initial_active_jobs != 0;
    plan.memory_budget_overridden = overrides.memory_budget_bytes != 0;
    plan.memory_budget_bytes = native_sizing_memory_budget(resources, overrides, tuning);

    const std::size_t memory_slots = plan.memory_budget_bytes == 0
        ? tuning.maximum_thread_capacity
        : (std::max)(std::size_t{1}, (std::min)(
            tuning.maximum_thread_capacity,
            plan.memory_budget_bytes / static_cast<std::size_t>(tuning.memory_per_slot_bytes)));

    if (plan.thread_capacity_overridden) {
        plan.thread_capacity = (std::max)(std::size_t{1}, (std::min)(
            overrides.thread_capacity, tuning.maximum_thread_capacity));
    } else {
        plan.thread_capacity = (std::max)(std::size_t{1}, (std::min)({
            resources.logical_processors,
            memory_slots,
            tuning.maximum_thread_capacity,
        }));
    }

    if (plan.initial_active_jobs_overridden) {
        plan.initial_active_jobs = (std::max)(std::size_t{1}, (std::min)(
            overrides.initial_active_jobs, plan.thread_capacity));
    } else {
        const std::size_t divisor = overrides.background
            ? tuning.background_cpu_divisor
            : tuning.foreground_cpu_divisor;
        const std::size_t cpu_seed = native_sizing_ceil_div(
            resources.logical_processors,
            divisor);
        plan.initial_active_jobs = (std::max)(std::size_t{1}, (std::min)({
            cpu_seed,
            memory_slots,
            plan.thread_capacity,
        }));
    }

    plan.medium_floor_jobs = (std::min)(
        plan.thread_capacity,
        native_sizing_ceil_div(plan.initial_active_jobs, 2));
    plan.high_floor_jobs = (std::min)(
        plan.thread_capacity,
        (std::max)(
            plan.medium_floor_jobs,
            native_sizing_ceil_div(plan.initial_active_jobs * 3, 4)));
    return plan;
}

}  // namespace sunpack::sevenzip
