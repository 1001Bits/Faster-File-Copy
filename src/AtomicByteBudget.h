#pragma once

#include <atomic>
#include <cstdint>

class AtomicByteBudget
{
public:
    explicit AtomicByteBudget(std::uint64_t limit) noexcept : limit_(limit) {}

    [[nodiscard]] bool TryReserve(std::uint64_t bytes) noexcept
    {
        auto current = used_.load(std::memory_order_relaxed);
        for (;;) {
            if (current > limit_ || bytes > limit_ - current) {
                return false;
            }
            if (used_.compare_exchange_weak(
                    current, current + bytes,
                    std::memory_order_acq_rel, std::memory_order_relaxed)) {
                return true;
            }
        }
    }

    [[nodiscard]] bool Release(std::uint64_t bytes) noexcept
    {
        auto current = used_.load(std::memory_order_relaxed);
        for (;;) {
            if (bytes > current) {
                return false;
            }
            if (used_.compare_exchange_weak(
                    current, current - bytes,
                    std::memory_order_acq_rel, std::memory_order_relaxed)) {
                return true;
            }
        }
    }

    [[nodiscard]] std::uint64_t Used() const noexcept
    {
        return used_.load(std::memory_order_acquire);
    }

    [[nodiscard]] std::uint64_t Limit() const noexcept { return limit_; }

private:
    const std::uint64_t limit_;
    std::atomic<std::uint64_t> used_{ 0 };
};
