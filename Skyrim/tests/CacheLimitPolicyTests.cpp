#include "CacheLimitPolicy.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>

namespace
{

constexpr std::uint64_t GiB(std::uint64_t value)
{
    return value * 1024ull * 1024ull * 1024ull;
}

void Require(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << "FAILED: " << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}

}  // namespace

int main()
{
    using CacheLimitPolicy::Mode;

    {
        const auto value = CacheLimitPolicy::Decide(0, GiB(32));
        Require(value.effectiveBytes == GiB(8), "auto uses 25% of 32 GiB");
        Require(value.mode == Mode::kAutomatic, "auto mode");
    }
    {
        const auto value = CacheLimitPolicy::Decide(2048, GiB(16));
        Require(value.effectiveBytes == GiB(2), "2 GiB remains below quarter RAM");
        Require(value.mode == Mode::kConfigured, "configured mode");
    }
    {
        const auto value = CacheLimitPolicy::Decide(8192, GiB(16));
        Require(value.effectiveBytes == GiB(4), "8 GiB clamps on 16 GiB system");
        Require(value.mode == Mode::kClamped, "clamped mode");
    }
    {
        const auto value = CacheLimitPolicy::Decide(2048, GiB(8));
        Require(value.effectiveBytes == GiB(2), "exact quarter boundary");
        Require(value.mode == Mode::kConfigured, "equality is not reported as clamp");
    }
    {
        constexpr std::uint64_t oddTotal = GiB(8) + 3;
        const auto value = CacheLimitPolicy::Decide(0, oddTotal);
        Require(value.effectiveBytes == oddTotal / 4, "quarter calculation floors bytes");
        Require(value.effectiveBytes * 4 <= oddTotal, "effective never exceeds quarter");
    }
    {
        const auto value = CacheLimitPolicy::Decide(0, 0);
        Require(!value, "unknown physical RAM fails closed");
        Require(value.mode == Mode::kUnavailable, "unavailable mode");
    }
    {
        constexpr auto max = (std::numeric_limits<std::uint64_t>::max)();
        Require(CacheLimitPolicy::MiBToBytesSaturating(max) == max,
            "MiB multiplication saturates");
        const auto value = CacheLimitPolicy::Decide(max, GiB(16));
        Require(value.effectiveBytes == GiB(4), "overflowing config still clamps");
    }
    {
        constexpr auto cap = 2048ull * CacheLimitPolicy::kBytesPerMiB;
        constexpr auto pending = 0ull;
        constexpr auto entry = 200ull * CacheLimitPolicy::kBytesPerMiB;
        const auto required = CacheLimitPolicy::RequiredHeadroom(
            cap, pending, entry);
        Require(required == entry, "headroom reserves complete rejected entry");
        Require(CacheLimitPolicy::EvictionTarget(cap, required) ==
                1848ull * CacheLimitPolicy::kBytesPerMiB,
            "near-cap rejection evicts enough for a later retry");
    }
    {
        constexpr auto max = (std::numeric_limits<std::uint64_t>::max)();
        Require(CacheLimitPolicy::RequiredHeadroom(max, max - 10, 20) == max,
            "headroom demand saturates without overflow");
        Require(CacheLimitPolicy::EvictionTarget(100, 150) == 0,
            "headroom cannot underflow target");
    }

    std::cout << "Cache limit policy tests passed\n";
    return EXIT_SUCCESS;
}
