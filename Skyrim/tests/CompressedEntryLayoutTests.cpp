#include "CompressedEntryLayout.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <limits>

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

    const auto plain = CompressedEntryLayout::SizeFieldOffset(
        0x2F355C89ull, 0x40000000ull, false);
    ok &= Require(plain && *plain == 0x2F355C89ull,
        "ordinary BSA entry size starts at dataOffset");

    const auto embedded = CompressedEntryLayout::SizeFieldOffset(
        1148, 8192, true, 40);
    ok &= Require(embedded && *embedded == 1189,
        "embedded filename length and bytes are skipped");
    ok &= Require(!CompressedEntryLayout::SizeFieldOffset(
        400, 405, true, 0),
        "empty embedded filenames fail closed");

    ok &= Require(!CompressedEntryLayout::SizeFieldOffset(
        100, 103, false), "truncated four-byte prefix is rejected");
    ok &= Require(!CompressedEntryLayout::SizeFieldOffset(
        (std::numeric_limits<std::uint64_t>::max)() - 4,
        (std::numeric_limits<std::uint64_t>::max)(), true, 255),
        "embedded-name offset overflow is rejected");
    ok &= Require(CompressedEntryLayout::IsUsableDeclaredSize(29966),
        "positive declared decompressed size is usable");
    ok &= Require(!CompressedEntryLayout::IsUsableDeclaredSize(0),
        "zero declared decompressed size fails closed");
    ok &= Require(CompressedEntryLayout::DecodeLittleEndianSize(
        std::array<std::uint8_t, 4>{ 0x0E, 0x75, 0x00, 0x00 }) == 29966,
        "BSA little-endian prefix is decoded explicitly");

    if (ok) {
        std::cout << "Compressed entry layout tests passed\n";
    }
    return ok ? 0 : 1;
}
