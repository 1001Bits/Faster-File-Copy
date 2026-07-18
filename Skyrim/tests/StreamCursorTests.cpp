#include "StreamCursor.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <iostream>
#include <limits>
#include <mutex>
#include <thread>
#include <vector>

namespace
{
bool Require(bool condition, const char* message)
{
    if (!condition)
        std::cerr << "FAILED: " << message << '\n';
    return condition;
}
}

int main()
{
    bool ok = true;

    {
        std::uint32_t cursor = 100;
        auto claim = StreamCursor::ClaimRange(cursor, 100, 25, 10);
        ok &= Require(claim.status == StreamCursor::ClaimStatus::kClaimed,
            "first range is claimed");
        ok &= Require(claim.relativeOffset == 0 && claim.size == 10 && cursor == 110,
            "first claim advances the absolute cursor");

        claim = StreamCursor::ClaimRange(cursor, 100, 25, 1000);
        ok &= Require(claim.relativeOffset == 10 && claim.size == 15 && cursor == 125,
            "claim clamps to end of stream");

        claim = StreamCursor::ClaimRange(cursor, 100, 25, 1);
        ok &= Require(claim.status == StreamCursor::ClaimStatus::kEndOfStream && claim.size == 0,
            "EOF is reported without moving the cursor");
    }

    {
        std::uint32_t cursor = (std::numeric_limits<std::uint32_t>::max)() - 2;
        const auto original = cursor;
        const auto claim = StreamCursor::ClaimRange(cursor, cursor, 4, 1);
        ok &= Require(claim.status == StreamCursor::ClaimStatus::kInvalid && cursor == original,
            "unrepresentable absolute end is rejected");
    }

    {
        constexpr std::uint32_t start = 4096;
        constexpr std::uint32_t count = 20000;
        std::uint32_t cursor = start;
        std::vector<std::uint32_t> offsets;
        offsets.reserve(count);
        std::mutex offsetsMutex;
        std::atomic<bool> workerOk{ true };

        std::vector<std::thread> workers;
        for (int i = 0; i < 8; ++i) {
            workers.emplace_back([&]() {
                for (;;) {
                    const auto claim = StreamCursor::ClaimRange(cursor, start, count, 1);
                    if (claim.status == StreamCursor::ClaimStatus::kEndOfStream)
                        break;
                    if (claim.status != StreamCursor::ClaimStatus::kClaimed || claim.size != 1) {
                        workerOk.store(false, std::memory_order_relaxed);
                        break;
                    }
                    std::lock_guard lock(offsetsMutex);
                    offsets.push_back(claim.relativeOffset);
                }
            });
        }
        for (auto& worker : workers)
            worker.join();

        std::sort(offsets.begin(), offsets.end());
        ok &= Require(workerOk.load(std::memory_order_relaxed), "all concurrent claims are valid");
        ok &= Require(offsets.size() == count, "concurrent claims cover the full stream");
        for (std::uint32_t i = 0; ok && i < count; ++i)
            ok &= Require(offsets[i] == i, "concurrent claims never overlap or skip");
    }

    {
        auto result = StreamCursor::ClampSeek(120, 100, 50, -30, StreamCursor::SeekOrigin::kCurrent);
        ok &= Require(result.valid && result.relativeOffset == 0 && result.absoluteOffset == 100,
            "negative seek clamps at the beginning");

        result = StreamCursor::ClampSeek(100, 100, 50, 1000, StreamCursor::SeekOrigin::kBegin);
        ok &= Require(result.valid && result.relativeOffset == 50 && result.absoluteOffset == 150,
            "positive seek clamps at the end");

        result = StreamCursor::ClampSeek(
            125, 100, 50, (std::numeric_limits<std::int64_t>::min)(), StreamCursor::SeekOrigin::kCurrent);
        ok &= Require(result.valid && result.relativeOffset == 0,
            "INT64_MIN displacement is handled without overflow");
    }

    if (ok)
        std::cout << "StreamCursor tests passed\n";
    return ok ? 0 : 1;
}
