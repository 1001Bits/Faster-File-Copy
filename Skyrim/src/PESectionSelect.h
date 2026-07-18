#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>

namespace PESectionSelect
{
inline constexpr std::size_t kShortNameSize = 8;

struct AddressRange
{
    std::uintptr_t begin{ 0 };
    std::uintptr_t end{ 0 };
    std::uint32_t virtualSize{ 0 };

    [[nodiscard]] constexpr explicit operator bool() const noexcept
    {
        return begin < end && virtualSize > 0;
    }
};

[[nodiscard]] constexpr bool ExactName(
    const std::uint8_t* name, std::string_view expected) noexcept
{
    if (!name || expected.empty() || expected.size() > kShortNameSize) {
        return false;
    }
    for (std::size_t i = 0; i < expected.size(); ++i) {
        if (name[i] != static_cast<std::uint8_t>(expected[i])) {
            return false;
        }
    }
    for (std::size_t i = expected.size(); i < kShortNameSize; ++i) {
        if (name[i] != 0) {
            return false;
        }
    }
    return true;
}

// Considers one PE section and retains the largest exact-name candidate with
// all required characteristics. Checked additions make malformed headers fail
// closed. First candidate wins size ties for deterministic selection.
[[nodiscard]] constexpr bool Consider(
    AddressRange& selected, std::uintptr_t imageBase,
    const std::uint8_t* name, std::string_view expectedName,
    std::uint32_t virtualAddress, std::uint32_t virtualSize,
    std::uint32_t characteristics,
    std::uint32_t requiredCharacteristics) noexcept
{
    if (!ExactName(name, expectedName) || virtualSize == 0 ||
        (characteristics & requiredCharacteristics) != requiredCharacteristics ||
        virtualAddress > (std::numeric_limits<std::uintptr_t>::max)() - imageBase) {
        return false;
    }
    const auto begin = imageBase + virtualAddress;
    if (virtualSize > (std::numeric_limits<std::uintptr_t>::max)() - begin) {
        return false;
    }
    const auto end = begin + virtualSize;
    if (begin >= end) {
        return false;
    }
    if (!selected || virtualSize > selected.virtualSize) {
        selected = { begin, end, virtualSize };
    }
    return true;
}
}  // namespace PESectionSelect
