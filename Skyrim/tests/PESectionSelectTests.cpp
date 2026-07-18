#include "PESectionSelect.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <limits>

namespace
{
constexpr std::uint32_t kRead = 0x40000000u;
constexpr std::uint32_t kWrite = 0x80000000u;
constexpr std::uint32_t kExecute = 0x20000000u;

constexpr std::array<std::uint8_t, 8> Name(const char* value)
{
    std::array<std::uint8_t, 8> result{};
    for (std::size_t i = 0; value[i] != '\0' && i < result.size(); ++i) {
        result[i] = static_cast<std::uint8_t>(value[i]);
    }
    return result;
}

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
    constexpr std::uintptr_t base = 0x140000000ull;

    {
        // AE 1.6.1170 shape: the later exact .text is writable data, not code.
        PESectionSelect::AddressRange selected;
        constexpr auto primary = Name(".text");
        constexpr auto later = Name(".text");
        ok &= Require(PESectionSelect::Consider(selected, base, primary.data(),
            ".text", 0x1000, 0x174D938, kRead | kExecute, kExecute),
            "primary executable text is eligible");
        ok &= Require(!PESectionSelect::Consider(selected, base, later.data(),
            ".text", 0x3752000, 0x1908, kRead | kWrite, kExecute),
            "later writable text is rejected when execute is required");
        ok &= Require(selected.begin == base + 0x1000 &&
            selected.virtualSize == 0x174D938,
            "later AE data section cannot replace primary code");
    }

    {
        PESectionSelect::AddressRange selected;
        constexpr auto prefix = Name(".textX");
        ok &= Require(!PESectionSelect::Consider(selected, base, prefix.data(),
            ".text", 0x1000, 0x2000, kRead | kExecute, kExecute),
            "section names are exact rather than prefix matches");

        constexpr auto rdata = Name(".rdata");
        ok &= Require(PESectionSelect::Consider(selected, base, rdata.data(),
            ".rdata", 0x3000, 0x1000, kRead, kRead),
            "read-only data candidate is accepted");
        ok &= Require(PESectionSelect::Consider(selected, base, rdata.data(),
            ".rdata", 0x8000, 0x4000, kRead, kRead),
            "second readable data candidate is eligible");
        ok &= Require(selected.begin == base + 0x8000 &&
            selected.virtualSize == 0x4000,
            "largest exact readable section wins");
    }

    {
        PESectionSelect::AddressRange selected;
        constexpr auto rdata = Name(".rdata");
        const auto nearEnd = (std::numeric_limits<std::uintptr_t>::max)() - 4;
        ok &= Require(!PESectionSelect::Consider(selected, nearEnd, rdata.data(),
            ".rdata", 8, 16, kRead, kRead),
            "overflowing image base plus RVA is rejected");
        ok &= Require(!selected, "overflow cannot publish a range");
    }

    if (ok) {
        std::cout << "PE section selection tests passed\n";
    }
    return ok ? 0 : 1;
}
