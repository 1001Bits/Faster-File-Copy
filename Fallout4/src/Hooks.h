#pragma once

#include <cstdint>
#include <filesystem>

namespace Hooks
{

void Install();
void InstallInflateHook();  // Deferred to F4SE kPostLoad — chains after FastDecompress
void BuildCompFingerprintIndexAsync(const std::filesystem::path& dataPath);  // Kick off texture fingerprint index build on a background thread (reads/writes sidecar under dataPath/F4SE/Plugins/FasterFileCopyFO4_cache/)
void StartStatsThread();
void FreezeSourceCache();
void RequestShutdown();  // Signal background threads to stop

// Save-load timing
void   OnPreLoadGame();
double OnPostLoadGame();  // returns save-load wall seconds (0 if no pending preload)

// Gameplay measurement — call after first save load settles
void SnapshotGameplayStart();
void LogGameplaySummary();

// Snapshot for delta measurement
struct Snapshot {
    std::uint64_t mmapReads;
    std::uint64_t mmapBytes;
    std::uint64_t fallbackReads;
    std::uint64_t fallbackBytes;
    std::uint64_t cacheServed;
    std::uint64_t cacheBytes;
    std::int64_t  ticksMmap;
    std::int64_t  ticksFallback;
    std::int64_t  ticksDecomp;
};
Snapshot TakeSnapshot();

// Cumulative statistics
std::uint64_t GetMappedReadCount();
std::uint64_t GetMappedBytesServed();
std::uint64_t GetFallbackReadCount();
std::uint64_t GetFallbackBytesServed();
std::uint64_t GetStreamReplacements();
std::uint64_t GetCacheServedCount();
std::uint64_t GetCacheBytesServed();

// QPC timing (seconds)
double GetMmapReadSeconds();
double GetFallbackReadSeconds();
double GetDecompSeconds();
double GetResolveSeconds();
double GetElapsedSeconds();

}  // namespace Hooks
