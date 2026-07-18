#pragma once

#include <cstdint>
#include <limits>

namespace CompressedReadPolicy
{
struct Progress
{
    bool valid{ false };
    std::uint32_t cursorAfter{ 0 };
};

[[nodiscard]] constexpr bool SeekMoved(
    std::uint32_t before, std::uint64_t after) noexcept
{
    return after != before;
}

// A size of zero means the decompressed size is not known yet. It does not
// relax cursor-overflow, caller-buffer, or requested/read-result validation.
[[nodiscard]] constexpr Progress ValidateNativeProgress(
    bool cursorKnown, std::uint32_t cursorBefore, std::uint32_t knownSize,
    std::uint64_t requested, std::uint64_t read,
    bool succeeded, bool bufferAvailable) noexcept
{
    if (!cursorKnown || !succeeded || read > requested ||
        (read > 0 && !bufferAvailable) ||
        read > (std::numeric_limits<std::uint32_t>::max)() - cursorBefore) {
        return { false, cursorBefore };
    }
    if (knownSize > 0 &&
        (cursorBefore > knownSize ||
         read > static_cast<std::uint64_t>(knownSize - cursorBefore))) {
        return { false, cursorBefore };
    }
    return { true, cursorBefore + static_cast<std::uint32_t>(read) };
}

}  // namespace CompressedReadPolicy
