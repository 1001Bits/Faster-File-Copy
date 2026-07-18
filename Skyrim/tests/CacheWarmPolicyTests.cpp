#include "CacheWarmPolicy.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>

namespace
{

void Require(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << "FAILED: " << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}

}  // namespace

int main()
{
    Require(CacheWarmPolicy::IsRangeWarm(100, 200, 1000, 300),
        "range ending exactly at warm prefix is eligible");
    Require(!CacheWarmPolicy::IsRangeWarm(100, 201, 1000, 300),
        "partially cold payload is rejected");
    Require(!CacheWarmPolicy::IsRangeWarm(100, 200, 1000, 0),
        "new mapping starts ineligible");
    Require(CacheWarmPolicy::IsRangeWarm(900, 100, 1000, 2000),
        "warm count clamps to committed prefix");
    Require(!CacheWarmPolicy::IsRangeWarm(900, 101, 1000, 1000),
        "payload beyond committed data is rejected");
    Require(!CacheWarmPolicy::IsRangeWarm(1000, 0, 1000, 1000),
        "empty payload is rejected");
    constexpr auto max = (std::numeric_limits<std::uint64_t>::max)();
    Require(!CacheWarmPolicy::IsRangeWarm(max - 4, 8, max, max),
        "range arithmetic cannot overflow");

    std::cout << "Cache warm policy tests passed\n";
    return EXIT_SUCCESS;
}
