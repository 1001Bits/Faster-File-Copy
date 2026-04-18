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

// Internal helper used by MmapStream to record cache-backed payload copies.
void RecordCacheRead(std::uint64_t a_bytes, std::uint64_t a_ticks);

// Cumulative statistics (atomic, safe to read from any thread).
// These counters represent final payload delivered to the engine.
std::uint64_t GetMappedReadCount();
std::uint64_t GetMappedBytesServed();
std::uint64_t GetFallbackReadCount();
std::uint64_t GetFallbackBytesServed();
std::uint64_t GetCacheServedCount();
std::uint64_t GetCacheBytesServed();
std::uint64_t GetDecompBytesServed();

// Raw archive-source bytes read before decompression. Diagnostic only.
std::uint64_t GetMappedSourceReadCount();
std::uint64_t GetMappedSourceBytes();
std::uint64_t GetFallbackSourceReadCount();
std::uint64_t GetFallbackSourceBytes();

// Timing (QPC ticks accumulated in DoRead hooks).
std::uint64_t GetTotalReadTicks();
std::uint64_t GetTotalReadCount();

// Call after Data loaded to stop resolving new sources (prevents deadlocks).
void FreezeSourceCache();

// Gameplay measurement — call SnapshotGameplayStart after save load + delay
// to begin measuring gameplay-only throughput.  LogGameplaySummary is called
// automatically by the stats thread on shutdown.
void SnapshotGameplayStart();
void LogGameplaySummary();

}  // namespace Hooks
