#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>

namespace CacheLimitPolicy
{

inline constexpr std::uint64_t kBytesPerMiB = 1024ull * 1024ull;

enum class Mode : std::uint8_t
{
    kUnavailable,
    kAutomatic,
    kConfigured,
    kClamped
};

struct Decision
{
    std::uint64_t configuredMiB{ 0 };
    std::uint64_t configuredBytes{ 0 };
    std::uint64_t physicalBytes{ 0 };
    std::uint64_t automaticCeilingBytes{ 0 };
    std::uint64_t effectiveBytes{ 0 };
    Mode mode{ Mode::kUnavailable };

    [[nodiscard]] constexpr explicit operator bool() const noexcept
    {
        return effectiveBytes > 0 && mode != Mode::kUnavailable;
    }
};

[[nodiscard]] constexpr std::uint64_t MiBToBytesSaturating(
    std::uint64_t a_mib) noexcept
{
    constexpr auto max = (std::numeric_limits<std::uint64_t>::max)();
    return a_mib > max / kBytesPerMiB ? max : a_mib * kBytesPerMiB;
}

[[nodiscard]] constexpr std::uint64_t AddSaturating(
    std::uint64_t a_lhs, std::uint64_t a_rhs) noexcept
{
    constexpr auto max = (std::numeric_limits<std::uint64_t>::max)();
    return a_rhs > max - a_lhs ? max : a_lhs + a_rhs;
}

// Pending bytes will shortly become committed disk bytes. To make a rejected
// admission fit after that commit, eviction must reserve the complete pending
// plus new demand, rather than only the current arithmetic deficit.
[[nodiscard]] constexpr std::uint64_t RequiredHeadroom(
    std::uint64_t a_capBytes, std::uint64_t a_pendingBytes,
    std::uint64_t a_newBytes) noexcept
{
    return (std::min)(a_capBytes, AddSaturating(a_pendingBytes, a_newBytes));
}

[[nodiscard]] constexpr std::uint64_t EvictionTarget(
    std::uint64_t a_capBytes, std::uint64_t a_requiredHeadroom) noexcept
{
    return a_capBytes - (std::min)(a_requiredHeadroom, a_capBytes);
}

// A zero configured value means "automatic": use the complete 25%-of-RAM
// allowance. Positive values are user ceilings but can never exceed it.
[[nodiscard]] constexpr Decision Decide(
    std::uint64_t a_configuredMiB,
    std::uint64_t a_totalPhysicalBytes) noexcept
{
    Decision result;
    result.configuredMiB = a_configuredMiB;
    result.configuredBytes = MiBToBytesSaturating(a_configuredMiB);
    result.physicalBytes = a_totalPhysicalBytes;
    result.automaticCeilingBytes = a_totalPhysicalBytes / 4u;

    if (result.automaticCeilingBytes == 0) {
        return result;
    }
    if (a_configuredMiB == 0) {
        result.effectiveBytes = result.automaticCeilingBytes;
        result.mode = Mode::kAutomatic;
        return result;
    }

    result.effectiveBytes = (std::min)(
        result.configuredBytes, result.automaticCeilingBytes);
    result.mode = result.configuredBytes > result.automaticCeilingBytes
        ? Mode::kClamped
        : Mode::kConfigured;
    return result;
}

}  // namespace CacheLimitPolicy
