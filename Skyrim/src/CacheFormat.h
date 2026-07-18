#pragma once

// Dependency-light, header-only definition and validator for persistent
// decompression-cache files. This intentionally includes no Skyrim/CommonLib
// headers so malformed-input tests and fuzz harnesses can use it directly.

#include <bit>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

namespace BSA::CacheFormat
{

inline constexpr char          kMagic[4]{ 'B', 'S', 'D', 'C' };
// v6 learned StreamBase's stored/compressed byte count as if it were the
// decompressed payload length. Every v6 file is therefore rejected rather than
// risking delivery of a checksummed but truncated resource.
inline constexpr std::uint32_t kVersion = 7;
inline constexpr std::uint32_t kMaxPayloadSize = 256u * 1024u * 1024u;
inline constexpr std::uint32_t kMaxIndexCapacity = 1'000'000u;

#pragma pack(push, 1)
struct Header
{
    char          magic[4];
    std::uint32_t version;
    std::uint64_t bsaFileSize;
    std::uint64_t bsaLastWrite;
    std::uint64_t bsaFingerprint;  // file identity + bounded content samples
    std::uint32_t bsaEntryCount;
    std::uint32_t indexCapacity;
    std::uint32_t entryCount;
};

struct Entry
{
    std::uint32_t startOffset;
    std::uint32_t decompSize;
    std::uint64_t cacheOffset;
    std::uint32_t checksum;
};
#pragma pack(pop)

static_assert(sizeof(Header) == 44);
static_assert(sizeof(Entry) == 20);

struct ArchiveIdentity
{
    std::uint64_t fileSize;
    std::uint64_t lastWrite;
    std::uint64_t fingerprint;
    std::uint32_t entryCount;
};

enum class ValidationMode : std::uint8_t
{
    // Startup-safe: validates every byte range and all format invariants but
    // does not read payload pages. Entries are checksum-verified on first use.
    StructuralOnly,
    // Intended for tests/tools and freshly written files, not bulk startup.
    FullPayload
};

enum class ValidationError : std::uint8_t
{
    None,
    NullData,
    FileTooSmall,
    BadMagic,
    UnsupportedVersion,
    ArchiveMismatch,
    InvalidEntryCount,
    IndexOutOfBounds,
    EmptyPayload,
    PayloadTooLarge,
    NonContiguousPayload,
    PayloadOutOfBounds,
    PayloadChecksumMismatch,
    TrailingData,
    DuplicateStartOffset
};

struct ValidationResult
{
    ValidationError error{ ValidationError::None };
    Header          header{};
    std::uint64_t   dataStart{ 0 };
    std::uint64_t   validSize{ 0 };
    std::uint32_t   invalidEntry{ (std::numeric_limits<std::uint32_t>::max)() };

    explicit operator bool() const noexcept { return error == ValidationError::None; }
};

// XXH32, seed 0. Unlike the old 64-byte FNV window, every payload byte is
// covered. The cache version bump prevents old partial checksums from being
// mistaken for this format.
inline std::uint32_t Checksum(const void* a_data, std::size_t a_size) noexcept
{
    constexpr std::uint32_t p1 = 0x9E3779B1u;
    constexpr std::uint32_t p2 = 0x85EBCA77u;
    constexpr std::uint32_t p3 = 0xC2B2AE3Du;
    constexpr std::uint32_t p4 = 0x27D4EB2Fu;
    constexpr std::uint32_t p5 = 0x165667B1u;

    static constexpr std::uint8_t empty = 0;
    if (!a_data && a_size != 0)
        return 0;
    const auto* p = a_data ? static_cast<const std::uint8_t*>(a_data) : &empty;
    const auto* const end = p + a_size;
    std::uint32_t h = 0;

    auto read32 = [](const std::uint8_t* a_p) noexcept {
        std::uint32_t value;
        std::memcpy(&value, a_p, sizeof(value));
        return value;
    };
    auto round = [](std::uint32_t a_acc, std::uint32_t a_input) noexcept {
        a_acc += a_input * p2;
        a_acc = std::rotl(a_acc, 13);
        return a_acc * p1;
    };

    if (a_size >= 16) {
        std::uint32_t v1 = p1 + p2;
        std::uint32_t v2 = p2;
        std::uint32_t v3 = 0;
        std::uint32_t v4 = 0u - p1;
        const auto* const limit = end - 16;
        do {
            v1 = round(v1, read32(p)); p += 4;
            v2 = round(v2, read32(p)); p += 4;
            v3 = round(v3, read32(p)); p += 4;
            v4 = round(v4, read32(p)); p += 4;
        } while (p <= limit);
        h = std::rotl(v1, 1) + std::rotl(v2, 7) +
            std::rotl(v3, 12) + std::rotl(v4, 18);
    } else {
        h = p5;
    }

    h += static_cast<std::uint32_t>(a_size);
    while (static_cast<std::size_t>(end - p) >= 4) {
        h += read32(p) * p3;
        h = std::rotl(h, 17) * p4;
        p += 4;
    }
    while (p < end) {
        h += static_cast<std::uint32_t>(*p++) * p5;
        h = std::rotl(h, 11) * p1;
    }
    h ^= h >> 15;
    h *= p2;
    h ^= h >> 13;
    h *= p3;
    h ^= h >> 16;
    return h;
}

inline ValidationResult Validate(
    const void* a_data,
    std::size_t a_size,
    const ArchiveIdentity* a_expected = nullptr,
    ValidationMode a_mode = ValidationMode::StructuralOnly,
    bool a_allowTrailingData = false)
{
    ValidationResult result;
    if (!a_data) {
        result.error = ValidationError::NullData;
        return result;
    }
    if (a_size < sizeof(Header)) {
        result.error = ValidationError::FileTooSmall;
        return result;
    }

    const auto* bytes = static_cast<const std::uint8_t*>(a_data);
    std::memcpy(&result.header, bytes, sizeof(result.header));
    if (std::memcmp(result.header.magic, kMagic, sizeof(kMagic)) != 0) {
        result.error = ValidationError::BadMagic;
        return result;
    }
    if (result.header.version != kVersion) {
        result.error = ValidationError::UnsupportedVersion;
        return result;
    }
    if (a_expected &&
        (result.header.bsaFileSize != a_expected->fileSize ||
         result.header.bsaLastWrite != a_expected->lastWrite ||
         result.header.bsaFingerprint != a_expected->fingerprint ||
         result.header.bsaEntryCount != a_expected->entryCount)) {
        result.error = ValidationError::ArchiveMismatch;
        return result;
    }
    if (result.header.indexCapacity == 0 ||
        result.header.indexCapacity > kMaxIndexCapacity ||
        result.header.entryCount == 0 ||
        result.header.entryCount > result.header.indexCapacity ||
        (a_expected &&
         (result.header.indexCapacity != a_expected->entryCount ||
          result.header.entryCount > a_expected->entryCount))) {
        result.error = ValidationError::InvalidEntryCount;
        return result;
    }

    const std::size_t bytesAfterHeader = a_size - sizeof(Header);
    if (result.header.indexCapacity > bytesAfterHeader / sizeof(Entry)) {
        result.error = ValidationError::IndexOutOfBounds;
        return result;
    }
    const std::size_t indexBytes =
        static_cast<std::size_t>(result.header.indexCapacity) * sizeof(Entry);
    const std::size_t dataStart = sizeof(Header) + indexBytes;
    result.dataStart = dataStart;

    std::uint64_t cursor = dataStart;
    std::vector<std::uint32_t> startOffsets;
    startOffsets.reserve(result.header.entryCount);
    for (std::uint32_t i = 0; i < result.header.entryCount; ++i) {
        Entry entry{};
        std::memcpy(
            &entry,
            bytes + sizeof(Header) + static_cast<std::size_t>(i) * sizeof(Entry),
            sizeof(entry));
        result.invalidEntry = i;

        startOffsets.push_back(entry.startOffset);
        if (entry.decompSize == 0) {
            result.error = ValidationError::EmptyPayload;
            return result;
        }
        if (entry.decompSize > kMaxPayloadSize) {
            result.error = ValidationError::PayloadTooLarge;
            return result;
        }
        if (entry.cacheOffset != cursor) {
            result.error = ValidationError::NonContiguousPayload;
            return result;
        }
        if (cursor > a_size || entry.decompSize > a_size - cursor) {
            result.error = ValidationError::PayloadOutOfBounds;
            return result;
        }
        if (a_mode == ValidationMode::FullPayload &&
            Checksum(bytes + static_cast<std::size_t>(cursor), entry.decompSize) !=
                entry.checksum) {
            result.error = ValidationError::PayloadChecksumMismatch;
            return result;
        }
        cursor += entry.decompSize;
    }
    std::sort(startOffsets.begin(), startOffsets.end());
    if (std::adjacent_find(startOffsets.begin(), startOffsets.end()) !=
        startOffsets.end()) {
        result.error = ValidationError::DuplicateStartOffset;
        return result;
    }
    result.validSize = cursor;
    if (cursor != a_size && !a_allowTrailingData) {
        result.error = ValidationError::TrailingData;
        return result;
    }

    result.invalidEntry = (std::numeric_limits<std::uint32_t>::max)();
    return result;
}

inline const char* ErrorName(ValidationError a_error) noexcept
{
    switch (a_error) {
    case ValidationError::None: return "none";
    case ValidationError::NullData: return "null data";
    case ValidationError::FileTooSmall: return "file too small";
    case ValidationError::BadMagic: return "bad magic";
    case ValidationError::UnsupportedVersion: return "unsupported version";
    case ValidationError::ArchiveMismatch: return "archive identity mismatch";
    case ValidationError::InvalidEntryCount: return "invalid entry count";
    case ValidationError::IndexOutOfBounds: return "index out of bounds";
    case ValidationError::EmptyPayload: return "empty payload";
    case ValidationError::PayloadTooLarge: return "payload too large";
    case ValidationError::NonContiguousPayload: return "non-contiguous payload";
    case ValidationError::PayloadOutOfBounds: return "payload out of bounds";
    case ValidationError::PayloadChecksumMismatch: return "payload checksum mismatch";
    case ValidationError::TrailingData: return "trailing data";
    case ValidationError::DuplicateStartOffset: return "duplicate start offset";
    }
    return "unknown";
}

}  // namespace BSA::CacheFormat
