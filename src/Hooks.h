#pragma once
// BSA Memory Map — Hook layer
//
// Two-level interception of Skyrim's archive read pipeline:
//
// 1. Deep hook (GlobalLocations::DoCreateStream):
//    Replaces ArchiveStream with MmapStream for uncompressed entries in
//    mapped BSAs.  The entire resource pipeline then operates on pages
//    from the OS page cache.
//
// 2. Fallback hook (ArchiveStream::DoRead vtable):
//    Catches any ArchiveStream reads that slip past the deep hook.
//    For uncompressed entries: serves from mapped memory via memcpy.
//    For compressed entries: reads compressed bytes from mmap instead of ReadFile.
//
// Baseline mode: hooks installed but always call original — measures ReadFile cost.
// Both modes log identical timing stats for comparison.

#include <cstdint>

namespace Hooks
{

// Install all hooks.  Call once during plugin load.
void Install();

// Start the background stats logging thread (if stats enabled).
void StartStatsThread();

// Cumulative statistics (atomic, safe to read from any thread).
std::uint64_t GetMappedReadCount();
std::uint64_t GetMappedBytesServed();
std::uint64_t GetFallbackReadCount();
std::uint64_t GetStreamReplacements();

// Timing (QPC ticks accumulated in DoRead hooks).
std::uint64_t GetTotalReadTicks();
std::uint64_t GetTotalReadCount();

// Call after Data loaded to stop resolving new sources (prevents deadlocks).
void FreezeSourceCache();

}  // namespace Hooks
