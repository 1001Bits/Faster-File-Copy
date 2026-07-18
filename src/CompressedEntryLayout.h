#pragma once

// Dependency-light helpers for locating the decompressed-size prefix of a
// compressed BSA data block. BSA archives with kEmbedFileNames store a one-byte
// name length and that many name bytes before the little-endian size field.

#include <array>
#include <cstdint>
#include <limits>
#include <optional>

namespace CompressedEntryLayout
{
[[nodiscard]] constexpr std::optional<std::uint64_t> SizeFieldOffset(
    std::uint64_t startOffset, std::uint64_t archiveSize,
    bool hasEmbeddedFileNames, std::uint8_t embeddedNameLength = 0) noexcept
{
    constexpr auto kSizeBytes = sizeof(std::uint32_t);
    std::uint64_t prefixOffset = startOffset;
    if (hasEmbeddedFileNames) {
        // A flagged data block must contain an actual embedded path. Treat a
        // zero length as malformed instead of interpreting arbitrary following
        // bytes as a decompressed-size declaration.
        if (embeddedNameLength == 0) {
            return std::nullopt;
        }
        constexpr std::uint64_t kLengthByte = 1;
        const auto skip = kLengthByte + embeddedNameLength;
        if (prefixOffset > (std::numeric_limits<std::uint64_t>::max)() - skip) {
            return std::nullopt;
        }
        prefixOffset += skip;
    }
    if (kSizeBytes > archiveSize || prefixOffset > archiveSize - kSizeBytes) {
        return std::nullopt;
    }
    return prefixOffset;
}

[[nodiscard]] constexpr bool IsUsableDeclaredSize(
    std::uint32_t declaredSize) noexcept
{
    return declaredSize != 0;
}

[[nodiscard]] constexpr std::uint32_t DecodeLittleEndianSize(
    const std::array<std::uint8_t, 4>& bytes) noexcept
{
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8) |
           (static_cast<std::uint32_t>(bytes[2]) << 16) |
           (static_cast<std::uint32_t>(bytes[3]) << 24);
}
}  // namespace CompressedEntryLayout
