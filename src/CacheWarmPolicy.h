#pragma once

#include <algorithm>
#include <cstdint>

namespace CacheWarmPolicy
{

// True only when the complete non-empty payload is structurally committed and
// lies inside the contiguous prefix touched by the managed warmer.
[[nodiscard]] constexpr bool IsRangeWarm(
    std::uint64_t a_offset, std::uint64_t a_size,
    std::uint64_t a_committedBytes, std::uint64_t a_warmedBytes) noexcept
{
    if (a_size == 0 || a_offset > a_committedBytes ||
        a_size > a_committedBytes - a_offset)
        return false;
    const auto warmed = (std::min)(a_warmedBytes, a_committedBytes);
    return a_offset <= warmed && a_size <= warmed - a_offset;
}

}  // namespace CacheWarmPolicy
