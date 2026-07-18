#include "AtomicByteBudget.h"

#include <atomic>
#include <cstdint>
#include <iostream>
#include <thread>
#include <vector>

namespace
{
bool Require(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << "FAILED: " << message << '\n';
    }
    return condition;
}
}

int main()
{
    bool ok = true;

    {
        AtomicByteBudget budget(100);
        ok &= Require(budget.TryReserve(100), "exact limit is accepted");
        ok &= Require(!budget.TryReserve(1), "limit plus one is rejected");
        ok &= Require(budget.Used() == 100, "failed reserve does not change usage");
        ok &= Require(budget.Release(40), "partial release succeeds");
        ok &= Require(budget.TryReserve(40), "released capacity can be reacquired");
        ok &= Require(!budget.Release(101), "underflowing release is rejected");
        ok &= Require(budget.Release(100) && budget.Used() == 0,
            "full release returns usage to zero");
    }

    {
        constexpr std::uint64_t limit = 64;
        AtomicByteBudget budget(limit);
        std::atomic<std::uint64_t> maxObserved{ 0 };
        std::atomic<bool> workersOk{ true };
        std::vector<std::thread> workers;
        for (int worker = 0; worker < 8; ++worker) {
            workers.emplace_back([&] {
                for (int i = 0; i < 20000; ++i) {
                    if (!budget.TryReserve(1)) {
                        std::this_thread::yield();
                        continue;
                    }
                    auto used = budget.Used();
                    auto observed = maxObserved.load(std::memory_order_relaxed);
                    while (observed < used &&
                           !maxObserved.compare_exchange_weak(
                               observed, used, std::memory_order_relaxed)) {
                    }
                    if (used > limit || !budget.Release(1)) {
                        workersOk.store(false, std::memory_order_relaxed);
                        return;
                    }
                }
            });
        }
        for (auto& worker : workers) {
            worker.join();
        }
        ok &= Require(workersOk.load(std::memory_order_relaxed),
            "concurrent reserve/release operations remain valid");
        ok &= Require(maxObserved.load(std::memory_order_relaxed) <= limit,
            "concurrent observed usage never exceeds the limit");
        ok &= Require(budget.Used() == 0, "concurrent test returns all reservations");
    }

    if (ok) {
        std::cout << "Atomic byte budget tests passed\n";
    }
    return ok ? 0 : 1;
}
