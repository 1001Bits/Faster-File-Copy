#include "CacheFormat.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

namespace
{
using BSA::CacheFormat::ArchiveIdentity;
using BSA::CacheFormat::Entry;
using BSA::CacheFormat::Header;
using BSA::CacheFormat::ValidationError;
using BSA::CacheFormat::ValidationMode;

constexpr ArchiveIdentity kIdentity{ 50'000, 123'456, 0x1122334455667788ull, 4 };

bool Require(bool condition, const char* message)
{
    if (!condition)
        std::cerr << "FAILED: " << message << '\n';
    return condition;
}

template <class T>
void Store(std::vector<std::uint8_t>& bytes, std::size_t offset, const T& value)
{
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

std::vector<std::uint8_t> MakeValidCache()
{
    constexpr std::array<std::uint8_t, 3> first{ 1, 2, 3 };
    constexpr std::array<std::uint8_t, 5> second{ 9, 8, 7, 6, 5 };
    constexpr std::uint32_t capacity = 4;
    const std::size_t dataStart = sizeof(Header) + capacity * sizeof(Entry);

    std::vector<std::uint8_t> bytes(dataStart + first.size() + second.size(), 0);
    Header header{};
    std::memcpy(header.magic, BSA::CacheFormat::kMagic, sizeof(header.magic));
    header.version = BSA::CacheFormat::kVersion;
    header.bsaFileSize = kIdentity.fileSize;
    header.bsaLastWrite = kIdentity.lastWrite;
    header.bsaFingerprint = kIdentity.fingerprint;
    header.bsaEntryCount = kIdentity.entryCount;
    header.indexCapacity = capacity;
    header.entryCount = 2;
    Store(bytes, 0, header);

    Entry entry{};
    entry.startOffset = 100;
    entry.decompSize = static_cast<std::uint32_t>(first.size());
    entry.cacheOffset = dataStart;
    entry.checksum = BSA::CacheFormat::Checksum(first.data(), first.size());
    Store(bytes, sizeof(Header), entry);

    entry.startOffset = 20;  // Append order need not match BSA offset order.
    entry.decompSize = static_cast<std::uint32_t>(second.size());
    entry.cacheOffset = dataStart + first.size();
    entry.checksum = BSA::CacheFormat::Checksum(second.data(), second.size());
    Store(bytes, sizeof(Header) + sizeof(Entry), entry);

    std::memcpy(bytes.data() + dataStart, first.data(), first.size());
    std::memcpy(bytes.data() + dataStart + first.size(), second.data(), second.size());
    return bytes;
}
}

int main()
{
    bool ok = true;

    ok &= Require(BSA::CacheFormat::Checksum(nullptr, 0) == 0x02CC5D05u,
        "XXH32 empty vector matches the reference value");
    constexpr std::array<std::uint8_t, 3> abc{ 'a', 'b', 'c' };
    ok &= Require(BSA::CacheFormat::Checksum(abc.data(), abc.size()) == 0x32D153FFu,
        "XXH32 abc vector matches the reference value");

    const auto valid = MakeValidCache();
    auto result = BSA::CacheFormat::Validate(
        valid.data(), valid.size(), &kIdentity, ValidationMode::FullPayload);
    ok &= Require(static_cast<bool>(result), "valid cache passes full validation");
    ok &= Require(result.validSize == valid.size(), "validator reports committed file size");

    {
        auto bytes = valid;
        bytes.back() ^= 0x80;
        result = BSA::CacheFormat::Validate(
            bytes.data(), bytes.size(), &kIdentity, ValidationMode::StructuralOnly);
        ok &= Require(static_cast<bool>(result),
            "structural validation does not fault cold payload pages for checksums");
        result = BSA::CacheFormat::Validate(
            bytes.data(), bytes.size(), &kIdentity, ValidationMode::FullPayload);
        ok &= Require(result.error == ValidationError::PayloadChecksumMismatch,
            "full validation detects tail corruption");
    }

    {
        auto bytes = valid;
        Header header{};
        std::memcpy(&header, bytes.data(), sizeof(header));
        header.version = 6;
        Store(bytes, 0, header);
        result = BSA::CacheFormat::Validate(bytes.data(), bytes.size(), &kIdentity);
        ok &= Require(result.error == ValidationError::UnsupportedVersion,
            "unsafe v6 caches are unconditionally rejected");
    }

    {
        auto wrongIdentity = kIdentity;
        wrongIdentity.fingerprint ^= 1;
        result = BSA::CacheFormat::Validate(valid.data(), valid.size(), &wrongIdentity);
        ok &= Require(result.error == ValidationError::ArchiveMismatch,
            "sampled BSA fingerprint participates in invalidation");
    }

    {
        auto bytes = valid;
        Header header{};
        std::memcpy(&header, bytes.data(), sizeof(header));
        header.entryCount = header.indexCapacity + 1;
        Store(bytes, 0, header);
        result = BSA::CacheFormat::Validate(bytes.data(), bytes.size(), &kIdentity);
        ok &= Require(result.error == ValidationError::InvalidEntryCount,
            "committed count cannot exceed reserved index capacity");
    }

    {
        auto bytes = valid;
        Entry first{}, second{};
        std::memcpy(&first, bytes.data() + sizeof(Header), sizeof(first));
        std::memcpy(&second, bytes.data() + sizeof(Header) + sizeof(Entry), sizeof(second));
        second.startOffset = first.startOffset;
        Store(bytes, sizeof(Header) + sizeof(Entry), second);
        result = BSA::CacheFormat::Validate(bytes.data(), bytes.size(), &kIdentity);
        ok &= Require(result.error == ValidationError::DuplicateStartOffset,
            "duplicate archive offsets are rejected");
    }

    {
        auto bytes = valid;
        Entry first{};
        std::memcpy(&first, bytes.data() + sizeof(Header), sizeof(first));
        ++first.cacheOffset;
        Store(bytes, sizeof(Header), first);
        result = BSA::CacheFormat::Validate(bytes.data(), bytes.size(), &kIdentity);
        ok &= Require(result.error == ValidationError::NonContiguousPayload,
            "payload holes and overlapping offsets are rejected");
    }

    {
        auto bytes = valid;
        Entry first{};
        std::memcpy(&first, bytes.data() + sizeof(Header), sizeof(first));
        first.decompSize = BSA::CacheFormat::kMaxPayloadSize + 1;
        Store(bytes, sizeof(Header), first);
        result = BSA::CacheFormat::Validate(bytes.data(), bytes.size(), &kIdentity);
        ok &= Require(result.error == ValidationError::PayloadTooLarge,
            "implausibly large entry payloads are rejected before checksum access");
    }

    {
        auto bytes = valid;
        bytes.insert(bytes.end(), { 0xAA, 0xBB, 0xCC });
        result = BSA::CacheFormat::Validate(bytes.data(), bytes.size(), &kIdentity);
        ok &= Require(result.error == ValidationError::TrailingData,
            "unexpected trailing data is rejected normally");
        result = BSA::CacheFormat::Validate(
            bytes.data(), bytes.size(), &kIdentity,
            ValidationMode::StructuralOnly, true);
        ok &= Require(static_cast<bool>(result) && result.validSize == valid.size(),
            "crash recovery identifies and can truncate an uncommitted append");
    }

    {
        std::array<std::uint8_t, sizeof(Header) - 1> truncated{};
        result = BSA::CacheFormat::Validate(truncated.data(), truncated.size(), nullptr);
        ok &= Require(result.error == ValidationError::FileTooSmall,
            "truncated header is rejected before dereference");
    }

    if (ok)
        std::cout << "CacheFormat tests passed\n";
    return ok ? 0 : 1;
}
