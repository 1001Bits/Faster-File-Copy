#pragma once

// Dependency-light helpers for claiming ranges from Skyrim's 32-bit absolute
// stream cursor.  Keeping the arithmetic here makes the concurrency and
// overflow rules testable without linking CommonLibSSE or loading the game.

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <limits>

namespace StreamCursor
{

enum class ClaimStatus : std::uint8_t
{
    kClaimed,
    kEndOfStream,
    kInvalid
};

struct RangeClaim
{
    ClaimStatus   status{ ClaimStatus::kInvalid };
    std::uint32_t absoluteOffset{ 0 };
    std::uint32_t relativeOffset{ 0 };
    std::uint32_t size{ 0 };

    [[nodiscard]] constexpr bool IsValid() const noexcept
    {
        return status != ClaimStatus::kInvalid;
    }
};

namespace detail
{

template <class AtomicCursor>
[[nodiscard]] inline RangeClaim ClaimRangeImpl(
    AtomicCursor& cursor,
    std::uint32_t  startOffset,
    std::uint32_t  totalSize,
    std::uint64_t  requested) noexcept
{
    const auto end64 = static_cast<std::uint64_t>(startOffset) + totalSize;
    if (end64 > (std::numeric_limits<std::uint32_t>::max)()) {
        return {};
    }
    const auto endOffset = static_cast<std::uint32_t>(end64);
    auto observed = cursor.load(std::memory_order_acquire);

    for (;;) {
        if (observed < startOffset || observed > endOffset) {
            return {};
        }

        const auto remaining = endOffset - observed;
        const auto size = static_cast<std::uint32_t>(
            (std::min)(requested, static_cast<std::uint64_t>(remaining)));

        if (size == 0) {
            return RangeClaim{
                observed == endOffset ? ClaimStatus::kEndOfStream : ClaimStatus::kClaimed,
                observed,
                observed - startOffset,
                0
            };
        }

        const auto next = static_cast<std::uint32_t>(observed + size);
        const auto claimedOffset = observed;
        if (cursor.compare_exchange_weak(
                observed, next,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            return RangeClaim{
                ClaimStatus::kClaimed,
                claimedOffset,
                claimedOffset - startOffset,
                size
            };
        }
    }
}

}  // namespace detail

// Atomically reserves a non-overlapping [cursor, cursor + size) range.
// The cursor is absolute while totalSize and relativeOffset are entry-relative.
// Invalid/corrupt ranges never modify cursorStorage.
[[nodiscard]] inline RangeClaim ClaimRange(
    std::uint32_t& cursorStorage,
    std::uint32_t  startOffset,
    std::uint32_t  totalSize,
    std::uint64_t  requested) noexcept
{
    std::atomic_ref<std::uint32_t> cursor{ cursorStorage };
    return detail::ClaimRangeImpl(cursor, startOffset, totalSize, requested);
}

// Overload for side-state cursors that are explicitly atomic rather than an
// atomic view over an engine-owned aligned field.
[[nodiscard]] inline RangeClaim ClaimRange(
    std::atomic<std::uint32_t>& cursor,
    std::uint32_t               startOffset,
    std::uint32_t               totalSize,
    std::uint64_t               requested) noexcept
{
    return detail::ClaimRangeImpl(cursor, startOffset, totalSize, requested);
}

enum class SeekOrigin : std::uint8_t
{
    kBegin,
    kCurrent,
    kEnd
};

struct SeekResult
{
    bool          valid{ false };
    std::uint32_t absoluteOffset{ 0 };
    std::uint32_t relativeOffset{ 0 };
};

// Computes a clamped seek without signed overflow.  This mirrors the cursor
// representation used by ClaimRange and is intentionally side-effect free.
[[nodiscard]] constexpr SeekResult ClampSeek(
    std::uint32_t currentAbsolute,
    std::uint32_t startOffset,
    std::uint32_t totalSize,
    std::int64_t  displacement,
    SeekOrigin    origin) noexcept
{
    const auto end64 = static_cast<std::uint64_t>(startOffset) + totalSize;
    if (end64 > (std::numeric_limits<std::uint32_t>::max)() ||
        currentAbsolute < startOffset || currentAbsolute > end64) {
        return {};
    }

    std::uint64_t base = 0;
    switch (origin) {
    case SeekOrigin::kBegin:
        base = 0;
        break;
    case SeekOrigin::kCurrent:
        base = currentAbsolute - startOffset;
        break;
    case SeekOrigin::kEnd:
        base = totalSize;
        break;
    default:
        return {};
    }

    std::uint64_t relative = 0;
    if (displacement >= 0) {
        const auto positive = static_cast<std::uint64_t>(displacement);
        relative = positive > static_cast<std::uint64_t>(totalSize) -
                                  (std::min)(base, static_cast<std::uint64_t>(totalSize))
            ? totalSize
            : base + positive;
    } else {
        // -(INT64_MIN) is undefined, so convert its magnitude without negating it.
        const auto magnitude = static_cast<std::uint64_t>(-(displacement + 1)) + 1;
        relative = magnitude > base ? 0 : base - magnitude;
    }

    relative = (std::min)(relative, static_cast<std::uint64_t>(totalSize));
    return SeekResult{
        true,
        static_cast<std::uint32_t>(static_cast<std::uint64_t>(startOffset) + relative),
        static_cast<std::uint32_t>(relative)
    };
}

}  // namespace StreamCursor
