#pragma once
// Non-temporal AVX2 copy for large cache serves (>= 128KB). Texel data won't
// be re-read on the CPU, so writing it through the cache hierarchy displaces
// hot data the game actually needs. _mm256_stream_si256 bypasses the cache
// and goes straight to memory, leaving L2 alone.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <immintrin.h>

#include "Settings.h"

namespace BA2
{

inline void FastCopyLarge(void* dst, const void* src, std::size_t n)
{
    constexpr std::size_t kNtThreshold = 128 * 1024;
    if (n < kNtThreshold || !Settings::bUseNonTemporalCopy) {
        std::memcpy(dst, src, n);
        return;
    }

    auto* d = static_cast<std::uint8_t*>(dst);
    const auto* s = static_cast<const std::uint8_t*>(src);

    auto misalign = reinterpret_cast<std::uintptr_t>(d) & 31;
    auto prefix = misalign ? (32 - misalign) : 0;
    if (prefix) {
        if (prefix > n) prefix = n;
        std::memcpy(d, s, prefix);
        d += prefix; s += prefix; n -= prefix;
    }

    std::size_t bulk = n & ~std::size_t(127);
    for (std::size_t off = 0; off < bulk; off += 128) {
        auto a = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(s + off));
        auto b = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(s + off + 32));
        auto c = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(s + off + 64));
        auto e = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(s + off + 96));
        _mm256_stream_si256(reinterpret_cast<__m256i*>(d + off), a);
        _mm256_stream_si256(reinterpret_cast<__m256i*>(d + off + 32), b);
        _mm256_stream_si256(reinterpret_cast<__m256i*>(d + off + 64), c);
        _mm256_stream_si256(reinterpret_cast<__m256i*>(d + off + 96), e);
    }
    _mm_sfence();

    d += bulk; s += bulk; n -= bulk;
    if (n > 0) std::memcpy(d, s, n);
}

}  // namespace BA2
