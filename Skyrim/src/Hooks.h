#pragma once
// BSA Memory Map — Hook layer
//
// Verified-vtable interception of Skyrim's archive read pipeline:
//
// 1. ArchiveStream::DoRead:
//    Atomically claims uncompressed entry ranges and copies them from the
//    mapped BSA, bypassing ReadFile without replacing engine stream objects.
//
// 2. CompressedArchiveStream lifecycle/read/seek vtable hooks:
//    Serve validated decompression-cache entries using the engine's canonical
//    behavior while tracking its private decompressed cursor in side state;
//    learn only exact contiguous decompressor output.
//
// Unknown executable layouts fail closed. There are no factory ABI hooks,
// instruction scanners, Detours, or custom replacement stream objects here.

#include <cstdint>

namespace Hooks
{

struct ReadPathStats
{
    std::uint64_t calls{ 0 };
    std::uint64_t requestedBytes{ 0 };
    std::uint64_t returnedBytes{ 0 };
    std::uint64_t failures{ 0 };
    std::uint64_t qpcTicks{ 0 };
};

// Logical output paths are mutually exclusive. Compressed-source paths are
// the lower-layer BSA bytes consumed inside native decompression and must not
// be added to logical payload totals.
struct IoStatsSnapshot
{
    ReadPathStats directMmap{};
    ReadPathStats directStock{};
    ReadPathStats cache{};
    ReadPathStats decompressor{};
    ReadPathStats compressedSourceMmap{};
    ReadPathStats compressedSourceStock{};
    std::uint64_t cacheAttachments{ 0 };
    std::uint64_t cacheSizeMismatches{ 0 };
    std::uint64_t cacheNotReady{ 0 };
    std::uint64_t cacheServeDisabled{ 0 };
    std::uint64_t loadPhaseUncompressedCalls{ 0 };
    std::uint64_t loadPhaseUncompressedRequestedBytes{ 0 };
    std::uint64_t loadPhaseCompressedCalls{ 0 };
    std::uint64_t loadPhaseCompressedRequestedBytes{ 0 };
    std::uint64_t loadPhaseGrandfatheredCacheCalls{ 0 };
};

// Install all hooks.  Call once during plugin load.
void Install();

// Start the background stats logging thread (if stats enabled).
void StartStatsThread();

// Publish the engine load phase to the hook layer. The benchmark-only
// bEnableDuringSaveLoad control uses it to suppress new acceleration choices;
// already cache-backed compressed streams remain cache-backed for correctness.
void SetLoadActive(bool a_active) noexcept;

// Cumulative statistics (atomic, safe to read from any thread).
// These counters represent final payload delivered to the engine.
std::uint64_t GetMappedBytesServed();
std::uint64_t GetFallbackBytesServed();
std::uint64_t GetCacheBytesServed();
std::uint64_t GetDecompBytesServed();
IoStatsSnapshot GetIoStatsSnapshot();

// Gameplay measurement — call SnapshotGameplayStart after save load + delay
// to begin measuring gameplay-only throughput.  LogGameplaySummary is called
// automatically by the stats thread on shutdown.
void SnapshotGameplayStart();
void LogGameplaySummary();

}  // namespace Hooks
