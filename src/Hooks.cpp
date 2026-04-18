#include "PCH.h"
#include "Hooks.h"
#include "ArchiveStream.h"
#include "BSAMemoryMap.h"
#include "DecompCache.h"
#include "MmapStream.h"
#include "Settings.h"

#include <thread>
#include <chrono>
#include <detours/detours.h>
#include <xmmintrin.h>  // _mm_prefetch

namespace Hooks
{

// ═══════════════════════════════════════════════════════════════════════════
// Lock-free source → MappedArchive cache
// ═══════════════════════════════════════════════════════════════════════════

// O(1) open-addressing hash table for source → archive lookups.
// 512 slots, power-of-2 for fast modulo. Only inserts, never deletes.
// Lock-free: reads are always safe after a release-store on the key.

static constexpr int kHashSlots = 512;
static constexpr int kHashMask = kHashSlots - 1;

struct SourceHashEntry {
    std::atomic<std::uintptr_t>            key{ 0 };    // source pointer as int (0 = empty)
    std::atomic<const BSA::MappedArchive*> archive{ nullptr };
};

static SourceHashEntry s_sourceHash[kHashSlots];
static std::atomic<int> s_sourceCacheCount{ 0 };
static std::atomic<bool> s_sourceCacheFrozen{ false };
static const auto kNoMappedArchive = reinterpret_cast<const BSA::MappedArchive*>(static_cast<std::uintptr_t>(1));

static bool SourceLookup(const void* source, const BSA::MappedArchive*& archive)
{
    if (!source) {
        archive = nullptr;
        return true;
    }

    auto k = reinterpret_cast<std::uintptr_t>(source);
    auto slot = static_cast<int>((k >> 4) & kHashMask);  // shift past alignment bits

    for (int i = 0; i < 16; ++i) {  // linear probe, max 16 steps
        auto stored = s_sourceHash[slot].key.load(std::memory_order_acquire);
        if (stored == k) {
            auto cached = s_sourceHash[slot].archive.load(std::memory_order_acquire);
            archive = (cached == kNoMappedArchive) ? nullptr : cached;
            return true;
        }
        if (stored == 0) {
            archive = nullptr;
            return false;  // empty slot = not found
        }
        slot = (slot + 1) & kHashMask;
    }

    archive = nullptr;
    return false;
}

static void SourceInsert(const void* source, const BSA::MappedArchive* archive)
{
    auto k = reinterpret_cast<std::uintptr_t>(source);
    auto storedArchive = archive ? archive : kNoMappedArchive;
    auto slot = static_cast<int>((k >> 4) & kHashMask);

    for (int i = 0; i < 16; ++i) {
        auto stored = s_sourceHash[slot].key.load(std::memory_order_relaxed);
        if (stored == k) return;  // already inserted
        if (stored == 0) {
            // Try to claim this slot — write archive AFTER key CAS succeeds
            std::uintptr_t expected = 0;
            if (s_sourceHash[slot].key.compare_exchange_strong(expected, k,
                    std::memory_order_relaxed, std::memory_order_relaxed)) {
                s_sourceHash[slot].archive.store(storedArchive, std::memory_order_release);
                s_sourceCacheCount.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            // Slot was taken by another thread, continue probing
        }
        slot = (slot + 1) & kHashMask;
    }
}

// Phase timing (QPC ticks)
static std::atomic<std::uint64_t> s_ticksMmapRead{ 0 };
static std::atomic<std::uint64_t> s_ticksFallbackRead{ 0 };
static std::atomic<std::uint64_t> s_ticksCache{ 0 };
static std::atomic<std::uint64_t> s_ticksResolve{ 0 };
static std::atomic<std::uint64_t> s_ticksDecomp{ 0 };
static std::atomic<std::uint64_t> s_decompBytes{ 0 };
static std::atomic<std::uint64_t> s_decompReads{ 0 };
static std::atomic<std::uint64_t> s_sourceMmapTicks{ 0 };
static std::atomic<std::uint64_t> s_sourceFallbackTicks{ 0 };
static std::atomic<std::uint64_t> s_sourceMmapReads{ 0 };
static std::atomic<std::uint64_t> s_sourceMmapBytes{ 0 };
static std::atomic<std::uint64_t> s_sourceFallbackReads{ 0 };
static std::atomic<std::uint64_t> s_sourceFallbackBytes{ 0 };

// Cached .rdata section range — computed once, used for vtable validation
static std::uintptr_t s_rdataStart = 0;
static std::uintptr_t s_rdataEnd = 0;

static void InitRdataRange()
{
    auto gameBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(nullptr));
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(gameBase);
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(gameBase + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(sec[i].Name, ".rdata", 6) == 0) {
            s_rdataStart = gameBase + sec[i].VirtualAddress;
            s_rdataEnd = s_rdataStart + sec[i].Misc.VirtualSize;
            break;
        }
    }
}

static const BSA::MappedArchive* ResolveSource(const void* source)
{
    const BSA::MappedArchive* cached = nullptr;
    if (SourceLookup(source, cached))
        return cached;

    if (s_sourceCacheFrozen.load(std::memory_order_acquire))
        return nullptr;

    LARGE_INTEGER t0; QueryPerformanceCounter(&t0);

    const BSA::MappedArchive* result = nullptr;
    try {
        auto* innerStream = *reinterpret_cast<void* const*>(
            static_cast<const char*>(source) + 0x28);
        // Validate pointer — must be in a valid committed memory region.
        // Sentinel values like -1 (INVALID_HANDLE_VALUE) or -2 are caught here.
        if (!innerStream || reinterpret_cast<std::uintptr_t>(innerStream) < 0x10000) {
            SourceInsert(source, nullptr);
            LARGE_INTEGER t1; QueryPerformanceCounter(&t1);
            s_ticksResolve.fetch_add(t1.QuadPart - t0.QuadPart, std::memory_order_relaxed);
            return nullptr;
        }
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(innerStream, &mbi, sizeof(mbi)) ||
                !(mbi.State & MEM_COMMIT) ||
                (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
                SourceInsert(source, nullptr);
                LARGE_INTEGER t1; QueryPerformanceCounter(&t1);
                s_ticksResolve.fetch_add(t1.QuadPart - t0.QuadPart, std::memory_order_relaxed);
                return nullptr;
            }
        }
        {
            // Validate vtable pointer — must be in the game's .rdata section
            // (where all vtables live). Calling DoGetName on an object with
            // an unknown vtable can execute arbitrary code and corrupt
            // heap/stack, causing delayed crashes in other mods.
            auto innerVtbl = *reinterpret_cast<std::uintptr_t*>(innerStream);
            if (innerVtbl < s_rdataStart || innerVtbl >= s_rdataEnd) {
                SourceInsert(source, nullptr);
                LARGE_INTEGER t1; QueryPerformanceCounter(&t1);
                s_ticksResolve.fetch_add(t1.QuadPart - t0.QuadPart, std::memory_order_relaxed);
                return nullptr;
            }

            auto** vtbl = reinterpret_cast<void**>(innerVtbl);
            using DoGetName_t = bool(*)(void*, RE::BSFixedString*);
            auto doGetName = reinterpret_cast<DoGetName_t>(vtbl[0x0A]);
            RE::BSFixedString name;
            if (doGetName(innerStream, &name)) {
                const char* str = name.c_str();
                if (str && str[0]) {
                    std::filesystem::path p(str);
                    result = BSA::MemoryMapManager::GetSingleton().FindByName(
                        p.filename().string());
                    if (result)
                        logger::info("BSAMmap: Source {:X} → {}",
                            reinterpret_cast<std::uintptr_t>(source), p.filename().string());
                }
            }
        }
    } catch (...) {}
    SourceInsert(source, result);

    LARGE_INTEGER t1; QueryPerformanceCounter(&t1);
    s_ticksResolve.fetch_add(t1.QuadPart - t0.QuadPart, std::memory_order_relaxed);
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// Statistics + Wall-clock timing
// ═══════════════════════════════════════════════════════════════════════════

static std::atomic<std::uint64_t> s_mmapReads{ 0 };
static std::atomic<std::uint64_t> s_mmapBytes{ 0 };
static std::atomic<std::uint64_t> s_cacheServed{ 0 };
static std::atomic<std::uint64_t> s_cacheBytes{ 0 };
static std::atomic<std::uint64_t> s_cacheSkipped{ 0 };
static std::atomic<std::uint64_t> s_fallbackReads{ 0 };
static std::atomic<std::uint64_t> s_fallbackBytes{ 0 };

// Inline-serve path decision counters (compat mode only). Used to diagnose
// why AE 1.6.1170 inline delivery is ~6 MB/s: suspect is that the identity
// check fails on most calls so every chunk falls through to the first-read
// path (ResolveSource + dcache.Lookup + re-park), instead of hitting the
// pure-memcpy continuation branch.
static std::atomic<std::uint64_t> s_inlineFastHits{ 0 };         // continuation: identity match, memcpy
static std::atomic<std::uint64_t> s_inlineIdentityMiss{ 0 };     // state existed but source/startOff didn't match
static std::atomic<std::uint64_t> s_inlineFirstReadHit{ 0 };     // no parked state, Lookup returned data
static std::atomic<std::uint64_t> s_inlineFirstReadMiss{ 0 };    // no parked state, Lookup found nothing

static void RecordMappedPayload(std::uint64_t bytes, std::uint64_t ticks)
{
    s_mmapReads.fetch_add(1, std::memory_order_relaxed);
    s_mmapBytes.fetch_add(bytes, std::memory_order_relaxed);
    s_ticksMmapRead.fetch_add(ticks, std::memory_order_relaxed);
}

static void RecordFallbackPayload(std::uint64_t bytes, std::uint64_t ticks)
{
    s_fallbackReads.fetch_add(1, std::memory_order_relaxed);
    s_fallbackBytes.fetch_add(bytes, std::memory_order_relaxed);
    s_ticksFallbackRead.fetch_add(ticks, std::memory_order_relaxed);
}

static void RecordCompressedPayload(std::uint64_t bytes, std::uint64_t ticks)
{
    s_decompReads.fetch_add(1, std::memory_order_relaxed);
    s_decompBytes.fetch_add(bytes, std::memory_order_relaxed);
    s_ticksDecomp.fetch_add(ticks, std::memory_order_relaxed);
}

static void RecordMappedSource(std::uint64_t bytes, std::uint64_t ticks)
{
    s_sourceMmapReads.fetch_add(1, std::memory_order_relaxed);
    s_sourceMmapBytes.fetch_add(bytes, std::memory_order_relaxed);
    s_sourceMmapTicks.fetch_add(ticks, std::memory_order_relaxed);
}

static void RecordFallbackSource(std::uint64_t bytes, std::uint64_t ticks)
{
    s_sourceFallbackReads.fetch_add(1, std::memory_order_relaxed);
    s_sourceFallbackBytes.fetch_add(bytes, std::memory_order_relaxed);
    s_sourceFallbackTicks.fetch_add(ticks, std::memory_order_relaxed);
}

void RecordCacheRead(std::uint64_t a_bytes, std::uint64_t a_ticks)
{
    s_cacheServed.fetch_add(1, std::memory_order_relaxed);
    s_cacheBytes.fetch_add(a_bytes, std::memory_order_relaxed);
    s_ticksCache.fetch_add(a_ticks, std::memory_order_relaxed);
}

// Timing shared by runtime stats and factory-mode setup logging

static LARGE_INTEGER s_qpcFreq;

void FreezeSourceCache()
{
    s_sourceCacheFrozen.store(true, std::memory_order_release);
}

std::uint64_t GetMappedReadCount()    { return s_mmapReads.load(std::memory_order_relaxed); }
std::uint64_t GetMappedBytesServed()  { return s_mmapBytes.load(std::memory_order_relaxed); }
std::uint64_t GetFallbackReadCount()  { return s_fallbackReads.load(std::memory_order_relaxed); }
std::uint64_t GetFallbackBytesServed(){ return s_fallbackBytes.load(std::memory_order_relaxed); }
std::uint64_t GetCacheServedCount()   { return s_cacheServed.load(std::memory_order_relaxed); }
std::uint64_t GetCacheBytesServed()   { return s_cacheBytes.load(std::memory_order_relaxed); }
std::uint64_t GetDecompBytesServed()  { return s_decompBytes.load(std::memory_order_relaxed); }
std::uint64_t GetMappedSourceReadCount() { return s_sourceMmapReads.load(std::memory_order_relaxed); }
std::uint64_t GetMappedSourceBytes()     { return s_sourceMmapBytes.load(std::memory_order_relaxed); }
std::uint64_t GetFallbackSourceReadCount() { return s_sourceFallbackReads.load(std::memory_order_relaxed); }
std::uint64_t GetFallbackSourceBytes()     { return s_sourceFallbackBytes.load(std::memory_order_relaxed); }
std::uint64_t GetTotalReadTicks()
{
    return s_ticksMmapRead.load(std::memory_order_relaxed)
         + s_ticksCache.load(std::memory_order_relaxed)
         + s_ticksFallbackRead.load(std::memory_order_relaxed)
         + s_ticksDecomp.load(std::memory_order_relaxed);
}
std::uint64_t GetTotalReadCount()
{
    return s_mmapReads.load(std::memory_order_relaxed)
         + s_cacheServed.load(std::memory_order_relaxed)
         + s_fallbackReads.load(std::memory_order_relaxed)
         + s_decompReads.load(std::memory_order_relaxed);
}

// ═══════════════════════════════════════════════════════════════════════════
// Stats thread
// ═══════════════════════════════════════════════════════════════════════════

static std::atomic<bool> s_statsRunning{ true };

// Gameplay measurement — snapshot counters after save load + delay
static std::atomic<bool>     s_gameplayActive{ false };
static std::atomic<int64_t>  s_gameplayStartQpc{ 0 };
static std::uint64_t s_gpStartMmap{}, s_gpStartCache{}, s_gpStartDecomp{}, s_gpStartFallback{};
static std::uint64_t s_gpStartSourceMmap{}, s_gpStartSourceFallback{};

void SnapshotGameplayStart()
{
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    s_gpStartMmap     = s_mmapBytes.load(std::memory_order_relaxed);
    s_gpStartCache    = s_cacheBytes.load(std::memory_order_relaxed);
    s_gpStartDecomp   = s_decompBytes.load(std::memory_order_relaxed);
    s_gpStartFallback = s_fallbackBytes.load(std::memory_order_relaxed);
    s_gpStartSourceMmap = s_sourceMmapBytes.load(std::memory_order_relaxed);
    s_gpStartSourceFallback = s_sourceFallbackBytes.load(std::memory_order_relaxed);
    s_gameplayStartQpc.store(now.QuadPart, std::memory_order_release);
    s_gameplayActive.store(true, std::memory_order_release);
    logger::info("BSAMmap: === GAMEPLAY MEASUREMENT START ===");
}

void LogGameplaySummary()
{
    if (!s_gameplayActive.load(std::memory_order_acquire)) return;

    LARGE_INTEGER now, freq;
    QueryPerformanceCounter(&now);
    QueryPerformanceFrequency(&freq);

    double sec = static_cast<double>(now.QuadPart - s_gameplayStartQpc.load(std::memory_order_acquire))
               / freq.QuadPart;

    auto mmapB   = s_mmapBytes.load(std::memory_order_relaxed)     - s_gpStartMmap;
    auto cacheB  = s_cacheBytes.load(std::memory_order_relaxed)    - s_gpStartCache;
    auto compB   = s_decompBytes.load(std::memory_order_relaxed)   - s_gpStartDecomp;
    auto nativeB = s_fallbackBytes.load(std::memory_order_relaxed) - s_gpStartFallback;
    auto totalB  = mmapB + cacheB + compB + nativeB;
    auto sourceMapB = s_sourceMmapBytes.load(std::memory_order_relaxed) - s_gpStartSourceMmap;
    auto sourceFbB = s_sourceFallbackBytes.load(std::memory_order_relaxed) - s_gpStartSourceFallback;

    double totalMB = totalB / (1024.0 * 1024.0);
    double throughput = (sec > 0.001) ? totalMB / sec : 0.0;

    double pMmap   = totalB > 0 ? (mmapB   * 100.0 / totalB) : 0;
    double pCache  = totalB > 0 ? (cacheB  * 100.0 / totalB) : 0;
    double pComp   = totalB > 0 ? (compB   * 100.0 / totalB) : 0;
    double pNative = totalB > 0 ? (nativeB * 100.0 / totalB) : 0;

    const char* mode = Settings::bBaselineMode ? "BASELINE" : "MMAP";

    logger::info("========================================");
    logger::info("[{}] GAMEPLAY THROUGHPUT: {:.1f}s measured", mode, sec);
    logger::info("[{}]   direct mmap:     {:.1f} MB ({:.0f}%)", mode, mmapB/(1024.*1024.), pMmap);
    logger::info("[{}]   cache:           {:.1f} MB ({:.0f}%)", mode, cacheB/(1024.*1024.), pCache);
    logger::info("[{}]   compressed path: {:.1f} MB ({:.0f}%)", mode, compB/(1024.*1024.), pComp);
    logger::info("[{}]   native direct:   {:.1f} MB ({:.0f}%)", mode, nativeB/(1024.*1024.), pNative);
    logger::info("[{}]   Total:    {:.1f} MB | {:.1f} MB/s", mode, totalMB, throughput);
    logger::info("[{}]   Raw source I/O: mapped {:.1f} MB + fallback {:.1f} MB", mode,
        sourceMapB/(1024.*1024.), sourceFbB/(1024.*1024.));
    logger::info("========================================");
}

static void StatsThreadFn()
{
    const int intervalSec = Settings::iStatsIntervalSec;
    std::uint64_t prevMmapB = 0, prevCacheB = 0, prevCompB = 0, prevNativeB = 0;
    std::uint64_t prevSourceMapB = 0, prevSourceFbB = 0;
    const char* mode = Settings::bBaselineMode ? "BASELINE" : "MMAP";

    while (s_statsRunning.load(std::memory_order_relaxed)) {
        // Sleep in 1-second increments so we can check shutdown flag
        for (int s = 0; s < intervalSec && s_statsRunning.load(std::memory_order_relaxed); ++s)
            std::this_thread::sleep_for(std::chrono::seconds(1));

        auto mmapB   = s_mmapBytes.load(std::memory_order_relaxed);
        auto cacheB  = s_cacheBytes.load(std::memory_order_relaxed);
        auto compB   = s_decompBytes.load(std::memory_order_relaxed);
        auto nativeB = s_fallbackBytes.load(std::memory_order_relaxed);
        auto sourceMapB = s_sourceMmapBytes.load(std::memory_order_relaxed);
        auto sourceFbB = s_sourceFallbackBytes.load(std::memory_order_relaxed);

        auto dMmapB   = mmapB   - prevMmapB;
        auto dCacheB  = cacheB  - prevCacheB;
        auto dCompB   = compB   - prevCompB;
        auto dNativeB = nativeB - prevNativeB;
        auto dSourceMapB = sourceMapB - prevSourceMapB;
        auto dSourceFbB = sourceFbB - prevSourceFbB;
        prevMmapB = mmapB;
        prevCacheB = cacheB;
        prevCompB = compB;
        prevNativeB = nativeB;
        prevSourceMapB = sourceMapB;
        prevSourceFbB = sourceFbB;

        auto dTotal = dMmapB + dCacheB + dCompB + dNativeB;
        if (dTotal == 0) continue;

        double elapsedSec = static_cast<double>(intervalSec);
        double throughput = dTotal / (1024. * 1024.) / elapsedSec;

        double pMmap   = dTotal > 0 ? (dMmapB   * 100.0 / dTotal) : 0;
        double pCache  = dTotal > 0 ? (dCacheB  * 100.0 / dTotal) : 0;
        double pComp   = dTotal > 0 ? (dCompB   * 100.0 / dTotal) : 0;
        double pNative = dTotal > 0 ? (dNativeB * 100.0 / dTotal) : 0;

        auto totalAll = mmapB + cacheB + compB + nativeB;

        logger::info("[{}] delta payload: direct {:.1f} MB ({:.0f}%), cache {:.1f} MB ({:.0f}%), "
                     "compressed {:.1f} MB ({:.0f}%), native {:.1f} MB ({:.0f}%) | {:.1f} MB/s | "
                     "total {:.1f} MB | raw source {:.1f}+{:.1f} MB",
            mode,
            dMmapB/(1024.*1024.), pMmap,
            dCacheB/(1024.*1024.), pCache,
            dCompB/(1024.*1024.), pComp,
            dNativeB/(1024.*1024.), pNative,
            throughput,
            totalAll/(1024.*1024.),
            dSourceMapB/(1024.*1024.),
            dSourceFbB/(1024.*1024.));

        // Compat-mode-only: inline path decision counters, to diagnose why
        // AE grinds to ~6 MB/s. If s_inlineIdentityMiss dominates on AE,
        // the parked state is getting invalidated between chunks and every
        // call falls through to first-read.
        if (Settings::bCompatibilityMode) {
            auto fast    = s_inlineFastHits.load(std::memory_order_relaxed);
            auto idMiss  = s_inlineIdentityMiss.load(std::memory_order_relaxed);
            auto frHit   = s_inlineFirstReadHit.load(std::memory_order_relaxed);
            auto frMiss  = s_inlineFirstReadMiss.load(std::memory_order_relaxed);
            logger::info("[COMPAT] inline: fast_hit={} id_miss={} first_hit={} first_miss={}",
                fast, idMiss, frHit, frMiss);
        }
    }

    // Log gameplay summary on shutdown
    LogGameplaySummary();
}

void StartStatsThread()
{
    if (!Settings::bMeasureStats) return;
    std::thread(StatsThreadFn).detach();
}

// ═══════════════════════════════════════════════════════════════════════════
// ReadFromSource Detours hook
//
// THE KEY FIX: ReadFromSource returns int (error code in eax).
// Previous version declared it void, causing eax to be clobbered by our
// atomic operations before returning → caller got garbage error code → freeze.
//
// Signature (AE 1.6.1170):
//   int __fastcall ReadFromSource(
//       void* source,           // rcx
//       void* buffer,           // rdx
//       uint32_t readOffset,    // r8  (absolute BSA offset)
//       uint64_t readSize,      // r9
//       uint64_t* bytesRead);   // [rsp+0x28]
// ═══════════════════════════════════════════════════════════════════════════

using ReadFromSource_t = int(__fastcall*)(
    void*, void*, std::uint32_t, std::uint64_t, std::uint64_t*);

static ReadFromSource_t s_origReadFromSource = nullptr;

static int __fastcall HookedReadFromSource(
    void*           a_source,
    void*           a_buffer,
    std::uint32_t   a_readOffset,
    std::uint64_t   a_readSize,
    std::uint64_t*  a_bytesRead)
{
    const bool measure = Settings::bMeasureStats;
    LARGE_INTEGER t0{}, t1{};
    if (measure) QueryPerformanceCounter(&t0);

    if (!Settings::bBaselineMode) {
        const auto* archive = ResolveSource(a_source);

        if (archive && archive->IsOpen()) {
            const auto fileSize = archive->GetFileSize();
            const std::uint64_t remaining =
                (a_readOffset < fileSize) ? (fileSize - a_readOffset) : 0;
            const std::uint64_t n = (a_readSize < remaining) ? a_readSize : remaining;

            if (n > 0) {
                const auto* src = archive->At(a_readOffset, n);
                if (src) {
                    std::memcpy(a_buffer, src, static_cast<std::size_t>(n));
                    if (a_bytesRead) *a_bytesRead = n;
                    if (measure) {
                        QueryPerformanceCounter(&t1);
                        RecordMappedSource(n, t1.QuadPart - t0.QuadPart);
                    }
                    return 0;  // success
                }
            }

            // mmap failed or zero-length read — fall through to original ReadFile
            // instead of returning 0 bytes (which causes null shader/texture objects)
        }
    }

    // Unknown source or baseline — call original, PRESERVE return value
    int ret = s_origReadFromSource(a_source, a_buffer, a_readOffset, a_readSize, a_bytesRead);
    if (measure) {
        QueryPerformanceCounter(&t1);
        if (a_bytesRead)
            RecordFallbackSource(*a_bytesRead, t1.QuadPart - t0.QuadPart);
    }
    return ret;
}

// ═══════════════════════════════════════════════════════════════════════════
// ArchiveStream::DoRead vtable hook — populates source cache during init
// ═══════════════════════════════════════════════════════════════════════════

static std::uintptr_t s_archiveStreamVtbl = 0;

using DoRead_t = RE::BSResource::ErrorCode(*)(
    const void*, void*, std::uint64_t, std::uint64_t&);

static DoRead_t s_originalDoRead = nullptr;

static RE::BSResource::ErrorCode __fastcall HookedDoRead(
    const void*     a_this,
    void*           a_buffer,
    std::uint64_t   a_toRead,
    std::uint64_t&  a_read)
{
    const bool measure = Settings::bMeasureStats;

    if (Settings::bBaselineMode || !Settings::bEnableMmap || Settings::bCompatibilityMode) {
        LARGE_INTEGER t0{}, t1{};
        if (measure) QueryPerformanceCounter(&t0);
        auto err = s_originalDoRead(a_this, a_buffer, a_toRead, a_read);
        if (measure && err == RE::BSResource::ErrorCode::kNone && a_read > 0) {
            QueryPerformanceCounter(&t1);
            RecordFallbackPayload(a_read, t1.QuadPart - t0.QuadPart);
        }
        return err;
    }

    // Serve uncompressed reads directly from mmap — bypasses the ENTIRE
    // source object chain (spinlock, buffered reader, ReadFromSource, ReadFile).
    auto* sourcePtr = BSResource::FieldAt<void* const>(a_this, BSResource::Field::Source);
    if (sourcePtr) {
        auto* archive = ResolveSource(sourcePtr);

        if (archive && archive->IsOpen()) {
            const auto startOff = BSResource::FieldAt<const std::uint32_t>(a_this, BSResource::Field::StartOffset);
            const auto curOff   = BSResource::FieldAt<const std::uint32_t>(a_this, BSResource::Field::CurrentOffset);
            const auto dataSize = BSResource::FieldAt<const std::uint32_t>(a_this, BSResource::Field::TotalSize);

            const std::uint64_t endPos = static_cast<std::uint64_t>(startOff) + dataSize;
            const std::uint64_t remaining = (curOff < endPos) ? (endPos - curOff) : 0;
            const std::uint64_t n = (a_toRead < remaining) ? a_toRead : remaining;

            if (n > 0) {
                const auto* src = archive->At(curOff, n);
                if (src) {
                    LARGE_INTEGER t0{}, t1{};
                    if (measure) QueryPerformanceCounter(&t0);
                    std::memcpy(a_buffer, src, static_cast<std::size_t>(n));
                    BSResource::FieldAt<std::uint32_t>(
                        const_cast<void*>(a_this), BSResource::Field::CurrentOffset) =
                        curOff + static_cast<std::uint32_t>(n);
                    a_read = n;
                    if (measure) {
                        QueryPerformanceCounter(&t1);
                        RecordMappedPayload(n, t1.QuadPart - t0.QuadPart);
                    }
                    return RE::BSResource::ErrorCode::kNone;
                }
            }
            if (remaining == 0) { a_read = 0; return RE::BSResource::ErrorCode::kNone; }
        }
    }

    return s_originalDoRead(a_this, a_buffer, a_toRead, a_read);
}

// ═══════════════════════════════════════════════════════════════════════════
// CompressedArchiveStream::DoRead vtable hook — populates source cache
// ═══════════════════════════════════════════════════════════════════════════

static std::uintptr_t s_compressedArchiveStreamVtbl = 0;

using CompDoRead_t = RE::BSResource::ErrorCode(*)(
    const void*, void*, std::uint64_t, std::uint64_t&);

static CompDoRead_t s_originalCompDoRead = nullptr;

// Per-stream accumulator — shared map with mutex (thread-local TLS
// initialization crashes on some game versions, so we use a shared map).
struct StreamAccum {
    const BSA::MappedArchive* archive = nullptr;
    std::uint32_t startOffset = 0;
    std::uint32_t totalSize = 0;
    std::uint32_t bytesAccum = 0;
    std::vector<std::uint8_t> buf;
};

// Per-stream inline cache state — tracks cursor for chunked reads
// when bCompatibilityMode is set (inline delivery via CompDoRead). The owner
// shared_ptr pins the underlying MappedView so a background cache rewrite
// can't unmap `data` between chunks of a single read sequence.
//
// source + startOffset are stored as an identity tag so we can detect
// stale entries left over from a recycled stream allocation. The engine's
// CompressedArchiveStream scalar-deleting dtor does NOT call DoClose
// (verified in Ghidra at SE 0x140c40c20), so HookedCompDoClose never
// fires on normal smart-pointer release — shard entries keyed on the
// stream memory address outlive their stream. When a new stream lands
// at the same address, we must recognize the mismatch and discard.
struct InlineCacheState {
    const std::uint8_t* data;
    std::uint32_t totalSize;
    std::uint32_t cursor;
    const void* source;
    std::uint32_t startOffset;
    std::shared_ptr<BSA::MappedView> owner;
};

// Sharded per-stream state — eliminates global mutex contention across
// unrelated streams. Keyed on (stream_ptr >> 4) & mask, matching the
// source-lookup table pattern. 16 shards chosen to match typical worker
// thread count while staying small enough to keep locks in L1/L2.
static constexpr std::size_t kStreamShardBits = 4;
static constexpr std::size_t kStreamShardCount = 1u << kStreamShardBits;
static constexpr std::size_t kStreamShardMask  = kStreamShardCount - 1;

struct AccumShard {
    std::unordered_map<const void*, StreamAccum> map;
    std::mutex mtx;
};
static AccumShard s_accumShards[kStreamShardCount];

// Map stores heap-allocated InlineCacheState* — stale pointers are LEAKED
// (never freed) rather than erased/overwritten in place, so any thread with
// a raw pointer from its thread-local cache can always read safely. An
// overwrite-in-place design is unsafe: operator= destructs the old
// InlineCacheState (including its shared_ptr<MappedView>), and if that drop
// releases the last ref, another thread mid-memcpy on `st->data` crashes
// when the view unmaps. Leaking is the cheapest safe fix — growth is
// bounded (~48 B per unique stream address per recycle).
struct InlineShard {
    std::unordered_map<const void*, InlineCacheState*> map;
    std::mutex mtx;
};
static InlineShard s_inlineShards[kStreamShardCount];

// Thread-local one-slot cache — the engine reads a single stream in sequential
// small chunks on a single thread before moving to the next stream, so the
// overwhelming majority of DoRead calls hit the same stream as the previous
// call on the same thread. Caching the raw InlineCacheState* lets the hot
// path skip the shard mutex + hashmap find entirely.
//
// Safety: these pointers are leaked, so they remain valid forever. Identity
// is verified against live (source, startOffset) on every call to reject
// recycled stream addresses.
thread_local const void*       t_lastInlineStream = nullptr;
thread_local InlineCacheState* t_lastInlineState  = nullptr;

static inline std::size_t ShardIndex(const void* p)
{
    return (reinterpret_cast<std::uintptr_t>(p) >> 4) & kStreamShardMask;
}

static void ClearCompressedStreamState(const void* stream)
{
    const auto idx = ShardIndex(stream);
    {
        auto& sh = s_accumShards[idx];
        std::lock_guard lk(sh.mtx);
        sh.map.erase(stream);
    }
    // Inline shard entries are intentionally not erased here — see the
    // thread_local comment above. Stale entries are overwritten in place
    // on the next identity-mismatched first read.
}

using CompDoClose_t = void(*)(void*);
static CompDoClose_t s_originalCompDoClose = nullptr;

static void __fastcall HookedCompDoClose(void* a_this)
{
    ClearCompressedStreamState(a_this);
    s_originalCompDoClose(a_this);
}

static RE::BSResource::ErrorCode __fastcall HookedCompDoRead(
    const void*     a_this,
    void*           a_buffer,
    std::uint64_t   a_toRead,
    std::uint64_t&  a_read)
{
    const bool measure = Settings::bMeasureStats;

    if (Settings::bBaselineMode) {
        LARGE_INTEGER t0{}, t1{};
        if (measure) QueryPerformanceCounter(&t0);
        auto err = s_originalCompDoRead(a_this, a_buffer, a_toRead, a_read);
        if (measure && err == RE::BSResource::ErrorCode::kNone && a_read > 0) {
            QueryPerformanceCounter(&t1);
            RecordCompressedPayload(a_read, t1.QuadPart - t0.QuadPart);
        }
        return err;
    }

    const auto shardIdx = ShardIndex(a_this);

    // ── Inline cache delivery (compatibility mode) ──────────────────────
    // Serve cached decompressed data directly from this hook, bypassing
    // the decompressor entirely. No MmapStream objects, no factory hook.
    if (Settings::bCompatibilityMode && Settings::bEnableDecompCache) {
        // ── Ultra-fast path: thread-local last-stream slot ──────────────
        // The engine reads a single stream in many small sequential chunks
        // on one thread before moving on, so the previous call's state is
        // almost always reusable. Using a thread-local raw pointer skips
        // the shard mutex, hashmap find, and (for the hot path) QPC calls
        // that were capping AE throughput at ~14 MB/s.
        //
        // Safety: the raw pointer is stable because we never erase inline
        // shard entries (stale ones are overwritten in place — see the
        // thread_local comment on t_lastInlineStream). Identity is still
        // verified against (source, startOffset) on every call so recycled
        // stream addresses don't serve the wrong data.
        if (a_this == t_lastInlineStream && t_lastInlineState) {
            auto* st = t_lastInlineState;
            auto* liveSource = BSResource::FieldAt<void* const>(
                a_this, BSResource::Field::Source);
            const auto liveStartOff = BSResource::FieldAt<const std::uint32_t>(
                a_this, BSResource::Field::StartOffset);
            if (liveSource == st->source && liveStartOff == st->startOffset) {
                s_inlineFastHits.fetch_add(1, std::memory_order_relaxed);
                const std::uint32_t cursor = st->cursor;
                const std::uint32_t remaining = (cursor < st->totalSize)
                    ? (st->totalSize - cursor) : 0;
                const std::uint32_t n = (a_toRead < remaining)
                    ? static_cast<std::uint32_t>(a_toRead) : remaining;
                if (n > 0) {
                    std::memcpy(a_buffer, st->data + cursor, n);
                    st->cursor = cursor + n;
                    s_cacheServed.fetch_add(1, std::memory_order_relaxed);
                    s_cacheBytes.fetch_add(n, std::memory_order_relaxed);
                }
                a_read = n;
                if (st->cursor >= st->totalSize) {
                    // Drained — clear thread-local so subsequent calls
                    // with a recycled pointer hit the shard path's
                    // identity check. Shard entry retained for future
                    // overwrites (never erased, see above).
                    t_lastInlineStream = nullptr;
                    t_lastInlineState  = nullptr;
                }
                return RE::BSResource::ErrorCode::kNone;
            }
            // Identity changed — thread-local is stale. Fall through to
            // shard path which will detect and overwrite.
            t_lastInlineStream = nullptr;
            t_lastInlineState  = nullptr;
        }

        // ── Shard path: first call on this thread for this stream ──────
        // Grab the raw pointer under lock, then release and operate on the
        // heap-allocated state without the shard mutex.
        InlineCacheState* statePtr = nullptr;
        {
            auto& sh = s_inlineShards[shardIdx];
            std::lock_guard lk(sh.mtx);
            auto it = sh.map.find(a_this);
            if (it != sh.map.end()) statePtr = it->second;
        }
        if (statePtr) {
            auto* liveSource = BSResource::FieldAt<void* const>(
                a_this, BSResource::Field::Source);
            const auto liveStartOff = BSResource::FieldAt<const std::uint32_t>(
                a_this, BSResource::Field::StartOffset);
            if (liveSource != statePtr->source || liveStartOff != statePtr->startOffset) {
                // Stale leaked entry — leave it in place; first-read path
                // below will allocate a fresh state and replace the map slot.
                s_inlineIdentityMiss.fetch_add(1, std::memory_order_relaxed);
            } else {
                s_inlineFastHits.fetch_add(1, std::memory_order_relaxed);
                const std::uint32_t cursor = statePtr->cursor;
                const std::uint32_t remaining = (cursor < statePtr->totalSize)
                    ? (statePtr->totalSize - cursor) : 0;
                const std::uint32_t n = (a_toRead < remaining)
                    ? static_cast<std::uint32_t>(a_toRead) : remaining;
                if (n > 0) {
                    const std::uint8_t* src = statePtr->data + cursor;
                    _mm_prefetch(reinterpret_cast<const char*>(src), _MM_HINT_T0);
                    if (n > 64)
                        _mm_prefetch(reinterpret_cast<const char*>(src + 64), _MM_HINT_T0);
                    std::memcpy(a_buffer, src, n);
                    statePtr->cursor = cursor + n;
                    s_cacheServed.fetch_add(1, std::memory_order_relaxed);
                    s_cacheBytes.fetch_add(n, std::memory_order_relaxed);
                }
                a_read = n;
                if (statePtr->cursor >= statePtr->totalSize) {
                    t_lastInlineStream = nullptr;
                    t_lastInlineState  = nullptr;
                } else {
                    t_lastInlineStream = a_this;
                    t_lastInlineState  = statePtr;
                }
                return RE::BSResource::ErrorCode::kNone;
            }
        }

        // First read on this stream (or stale entry to overwrite) —
        // resolve source and check cache
        auto* sourcePtr = BSResource::FieldAt<void* const>(a_this, BSResource::Field::Source);
        if (sourcePtr) {
            const auto* archive = ResolveSource(sourcePtr);

            if (archive) {
                auto& dcache = BSA::DecompCache::GetSingleton();
                if (dcache.IsReady()) {
                    auto startOff = BSResource::FieldAt<const std::uint32_t>(
                        a_this, BSResource::Field::StartOffset);
                    auto cached = dcache.Lookup(archive, startOff);
                    if (cached) {
                        s_inlineFirstReadHit.fetch_add(1, std::memory_order_relaxed);
                        const std::uint32_t n = (a_toRead < cached.size)
                            ? static_cast<std::uint32_t>(a_toRead) : cached.size;
                        _mm_prefetch(reinterpret_cast<const char*>(cached.data), _MM_HINT_T0);
                        if (n > 64)
                            _mm_prefetch(reinterpret_cast<const char*>(cached.data + 64), _MM_HINT_T0);
                        std::memcpy(a_buffer, cached.data, n);
                        a_read = n;
                        s_cacheServed.fetch_add(1, std::memory_order_relaxed);
                        s_cacheBytes.fetch_add(n, std::memory_order_relaxed);

                        // Park state for continuation reads. Heap-allocate
                        // and replace the map slot — any prior pointer at
                        // this address is intentionally leaked so threads
                        // still holding it in their thread-local slot see
                        // a valid (stale) struct and reject it via the
                        // identity check.
                        if (n < cached.size) {
                            auto* newState = new InlineCacheState{
                                cached.data, cached.size, n,
                                sourcePtr, startOff,
                                std::move(cached.owner)
                            };
                            {
                                auto& sh = s_inlineShards[shardIdx];
                                std::lock_guard lk(sh.mtx);
                                sh.map[a_this] = newState;  // prior entry leaked
                            }
                            t_lastInlineStream = a_this;
                            t_lastInlineState  = newState;
                        }
                        return RE::BSResource::ErrorCode::kNone;
                    }

                    s_inlineFirstReadMiss.fetch_add(1, std::memory_order_relaxed);
                    dcache.RecordMiss();
                }
            }
        }
        // Cache miss — fall through to original decompressor below
    }

    // Resolve source → archive mapping once (for factory delivery or recording).
    auto* sourcePtr = BSResource::FieldAt<void* const>(a_this, BSResource::Field::Source);
    const BSA::MappedArchive* resolvedArchive = sourcePtr ? ResolveSource(sourcePtr) : nullptr;

    // Call original decompressor
    LARGE_INTEGER t0{}, t1{};
    if (measure) QueryPerformanceCounter(&t0);
    auto err = s_originalCompDoRead(a_this, a_buffer, a_toRead, a_read);
    if (measure && err == RE::BSResource::ErrorCode::kNone && a_read > 0) {
        QueryPerformanceCounter(&t1);
        RecordCompressedPayload(a_read, t1.QuadPart - t0.QuadPart);
    }

    // Record decompressed data for cache building
    if (Settings::bEnableDecompCache && !Settings::bBaselineMode
        && err == RE::BSResource::ErrorCode::kNone && a_read > 0 && resolvedArchive)
    {
        auto& dcache = BSA::DecompCache::GetSingleton();
        if (dcache.IsBuilding()) {
            const auto startOff = BSResource::FieldAt<const std::uint32_t>(
                a_this, BSResource::Field::StartOffset);

            // Skip recording if this entry is already cached (cheap, no shared_ptr bump)
            if (dcache.IsReady() && dcache.Contains(resolvedArchive, startOff))
                return err;

            const auto totalSize = BSResource::GetTotalSize(a_this);

            auto& sh = s_accumShards[shardIdx];
            std::unique_lock shardLock(sh.mtx);
            auto it = sh.map.find(a_this);
            if (it == sh.map.end())
                it = sh.map.emplace(a_this, StreamAccum{}).first;
            auto& acc = it->second;
            if (acc.totalSize == 0 || acc.startOffset != startOff) {
                acc.archive = resolvedArchive;
                acc.startOffset = startOff;
                acc.totalSize = totalSize;
                acc.bytesAccum = 0;
                acc.buf.clear();
                if (totalSize > 0 && totalSize < 16 * 1024 * 1024)
                    acc.buf.reserve(totalSize);
            }

            auto* data = static_cast<const std::uint8_t*>(a_buffer);
            acc.buf.insert(acc.buf.end(), data, data + a_read);
            acc.bytesAccum += static_cast<std::uint32_t>(a_read);

            if (acc.bytesAccum >= acc.totalSize) {
                // Move the buffer out under the lock, erase the entry, then
                // release the lock before calling RecordDecompressed (which
                // does its own memcpy under DecompCache's write lock).
                std::vector<std::uint8_t> completed = std::move(acc.buf);
                const auto completedOffset = acc.startOffset;
                const auto completedSize   = static_cast<std::uint32_t>(completed.size());
                sh.map.erase(it);
                shardLock.unlock();
                dcache.RecordDecompressed(resolvedArchive, completedOffset,
                    completed.data(), completedSize);
            }
        }
    }

    return err;
}

// ═══════════════════════════════════════════════════════════════════════════
// Resolve the call site in DoRead that calls ReadFromSource
// Returns the ADDRESS of the E8 call instruction (not the target function).
// We patch this call site via SKSE trampoline instead of Detours.
// ═══════════════════════════════════════════════════════════════════════════

static std::uintptr_t FindReadFromSourceCallSite()
{
    auto doReadAddr = reinterpret_cast<std::uintptr_t>(s_originalDoRead);
    if (!doReadAddr) return 0;

    auto* code = reinterpret_cast<std::uint8_t*>(doReadAddr);
    logger::info("BSAMmap: Scanning DoRead at {:X} (first bytes: {:02X} {:02X} {:02X} {:02X})",
        doReadAddr, code[0], code[1], code[2], code[3]);

    try {
        for (int offset = 0x20; offset < 0x140; ++offset) {
            if (code[offset] != 0xE8) continue;

            auto rel32 = *reinterpret_cast<std::int32_t*>(&code[offset + 1]);
            auto targetAddr = reinterpret_cast<std::uintptr_t>(&code[offset]) + 5 + rel32;
            auto* p = reinterpret_cast<std::uint8_t*>(targetAddr);

            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(p, &mbi, sizeof(mbi)) || !(mbi.Protect & 0xF0))
                continue;

            // Match ReadFromSource prologue: 40 5x (REX push) + sub rsp
            if (p[0] == 0x40 && (p[1] & 0xF0) == 0x50) {
                bool hasSub = false;
                for (int j = 2; j < 10; ++j) {
                    if (p[j] == 0x48 && p[j+1] == 0x83 && p[j+2] == 0xEC) {
                        hasSub = true;
                        break;
                    }
                }
                if (hasSub) {
                    auto callSiteAddr = doReadAddr + offset;
                    logger::info("BSAMmap: Found ReadFromSource call site at {:X} (DoRead+0x{:X}) → {:X}",
                        callSiteAddr, offset, targetAddr);
                    return callSiteAddr;
                }
            }
        }
    } catch (...) {
        logger::error("BSAMmap: Exception during call site scan");
    }

    logger::error("BSAMmap: Failed to find ReadFromSource call site");
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// BSA stream factory hook — replaces CompressedArchiveStream with MmapStream
// at creation time for cached entries. Zero decompression, single memcpy.
//
// Function at RVA 0xD03E10 (AE 1.6.1170), found via Ghidra xrefs to
// CompressedArchiveStream vtable. Called from 13 locations.
//
// Params (from Ghidra RE):
//   rcx: unused
//   rdx: BSA entry info record
//   r8:  output BSTSmartPointer<Stream> — stream stored here
//   r9:  output error code (0=success, 1=not compressed)
// ═══════════════════════════════════════════════════════════════════════════

using CreateBsaStream_t = void(__fastcall*)(void*, void*, void*, void*);
static CreateBsaStream_t s_origCreateBsaStream = nullptr;

static void __fastcall HookedCreateBsaStream(
    void* a_rcx, void* a_entryInfo, void* a_streamOut, void* a_errOut)
{
    // Call original — creates ArchiveStream or CompressedArchiveStream.
    // We can't skip this without RE'ing the entry info struct layout,
    // but with DecompCache's stable-mode fast path, the hit check below
    // is lock-free and shared_ptr-free once the cache is finalized.
    s_origCreateBsaStream(a_rcx, a_entryInfo, a_streamOut, a_errOut);

    // ── Early-out gates ordered cheapest-first, no QPC yet. ────────────
    if (Settings::bBaselineMode || !Settings::bEnableDecompCache)
        return;
    if (!a_errOut || !a_streamOut)
        return;
    if (*reinterpret_cast<std::uint32_t*>(a_errOut) != 0)
        return;

    auto& dcache = BSA::DecompCache::GetSingleton();
    if (!dcache.IsReady())
        return;

    auto* stream = *reinterpret_cast<RE::BSResource::Stream**>(a_streamOut);
    if (!stream) return;

    auto streamVtbl = *reinterpret_cast<std::uintptr_t*>(stream);
    if (streamVtbl != s_compressedArchiveStreamVtbl) {
        s_cacheSkipped.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    auto* sourcePtr = BSResource::FieldAt<void* const>(stream, BSResource::Field::Source);
    if (!sourcePtr) return;

    const auto* archive = ResolveSource(sourcePtr);
    if (!archive) return;

    const auto startOff = BSResource::FieldAt<const std::uint32_t>(
        stream, BSResource::Field::StartOffset);

    // Cache lookup — hot path. Lock-free + shared_ptr-free when stable.
    // When building, Lookup pins the MappedView via shared_ptr so a
    // concurrent rewrite can't unmap `cached.data` before MmapStream
    // takes ownership below.
    auto cached = dcache.Lookup(archive, startOff);
    if (!cached)
        return;

    // ── Confirmed hit. From here on the work is unavoidable. ─────────
    LARGE_INTEGER tFactory0; QueryPerformanceCounter(&tFactory0);

    // Get name from the original compressed stream via DoGetName virtual.
    // The name field on the stream isn't a simple BSFixedString read.
    RE::BSFixedString nameStr;
    {
        auto** vtblArr = reinterpret_cast<void**>(streamVtbl);
        using DoGetName_t = bool(*)(const void*, RE::BSFixedString*);
        auto getName = reinterpret_cast<DoGetName_t>(vtblArr[0x0A]);
        getName(stream, &nameStr);
    }

    // Create MmapStream with ArchiveStream-compatible field layout. When
    // cached.owner is non-empty (building mode), it pins the underlying
    // view for the stream's lifetime. When stable, the view is permanent
    // and owner is empty — no shared_ptr overhead.
    auto* mmapStream = new BSA::MmapStream(
        cached.data, cached.size, nameStr, archive,
        sourcePtr, startOff, /*cursor*/ 0, std::move(cached.owner));

    // Store MmapStream in smart pointer — FUN_140d05aa0 handles ref counting
    // at offset 0x10 (streamFlags_). MmapStream initializes it to 0x1000 (one ref).
    // The old CompressedArchiveStream gets DecRef'd and destroyed by the smart pointer.
    auto* smartPtr = reinterpret_cast<RE::BSTSmartPointer<RE::BSResource::Stream>*>(a_streamOut);
    smartPtr->reset(mmapStream);
    LARGE_INTEGER tFactory1; QueryPerformanceCounter(&tFactory1);
    logger::info("BSAMmap: Factory cache hit at {:X} -> {} ({:.1f} KB, {:.3f} ms setup)",
        startOff,
        nameStr.c_str() ? nameStr.c_str() : "<unnamed>",
        mmapStream->GetEntrySize() / 1024.0,
        (tFactory1.QuadPart - tFactory0.QuadPart) * 1000.0 / s_qpcFreq.QuadPart);
}

// ═══════════════════════════════════════════════════════════════════════════
// Installation
// ═══════════════════════════════════════════════════════════════════════════

void Install()
{
    QueryPerformanceFrequency(&s_qpcFreq);
    InitRdataRange();

    logger::info("BSAMmap: Field offsets — Source=0x{:X}, StartOffset=0x{:X}, CurrentOffset=0x{:X}, Name=0x{:X}",
        BSResource::Field::Source, BSResource::Field::StartOffset,
        BSResource::Field::CurrentOffset, BSResource::Field::Name);

    // Vtable addresses
    {
        REL::Relocation<std::uintptr_t> rv{ REL::VariantID(285761, 236985, 0x17ec318) };
        s_archiveStreamVtbl = rv.address();
    }
    {
        REL::Relocation<std::uintptr_t> rv{ REL::VariantID(285762, 236987, 0x17ec388) };
        s_compressedArchiveStreamVtbl = rv.address();
    }

    {
        // ArchiveStream::DoRead vtable hook — always installed.
        // With mmap enabled: serves uncompressed reads directly from mapped memory.
        // With mmap disabled or compatibility mode: lightweight passthrough that counts
        // bytes for throughput measurement.
        {
            constexpr std::size_t kDoReadIdx = 0x06;
            auto* entries = reinterpret_cast<std::uintptr_t*>(s_archiveStreamVtbl);
            s_originalDoRead = reinterpret_cast<DoRead_t>(entries[kDoReadIdx]);
            REL::safe_write(
                s_archiveStreamVtbl + kDoReadIdx * sizeof(std::uintptr_t),
                reinterpret_cast<std::uintptr_t>(&HookedDoRead));
            logger::info("BSAMmap: ArchiveStream::DoRead hook installed{}",
                (Settings::bCompatibilityMode || !Settings::bEnableMmap) ? " (counting only)" : "");
        }

        // CompressedArchiveStream::DoRead vtable hook — always installed for
        // cache delivery, decompression recording, and byte counting.
        {
            constexpr std::size_t kDoCloseIdx = 0x02;
            constexpr std::size_t kDoReadIdx = 0x06;
            auto* entries = reinterpret_cast<std::uintptr_t*>(s_compressedArchiveStreamVtbl);
            s_originalCompDoClose = reinterpret_cast<CompDoClose_t>(entries[kDoCloseIdx]);
            s_originalCompDoRead = reinterpret_cast<CompDoRead_t>(entries[kDoReadIdx]);
            REL::safe_write(
                s_compressedArchiveStreamVtbl + kDoCloseIdx * sizeof(std::uintptr_t),
                reinterpret_cast<std::uintptr_t>(&HookedCompDoClose));
            REL::safe_write(
                s_compressedArchiveStreamVtbl + kDoReadIdx * sizeof(std::uintptr_t),
                reinterpret_cast<std::uintptr_t>(&HookedCompDoRead));
            logger::info("BSAMmap: CompressedArchiveStream hooks installed (DoClose, DoRead)");
        }
    }

    if (Settings::bBaselineMode)
        logger::info("BSAMmap: *** BASELINE MODE — hooks passthrough (byte counting only) ***");

    // ReadFromSource call-site hook — uses our own trampoline to avoid
    // exhausting the shared SKSE trampoline pool (fixes compatibility with
    // DynDOLOD, Don't Send Me There Again, and other trampoline-heavy mods).
    // Skipped in compatibility mode — all I/O uses stock ReadFile.
    if (!Settings::bBaselineMode && Settings::bEnableMmap && !Settings::bCompatibilityMode) {
        auto callSite = FindReadFromSourceCallSite();
        if (callSite) {
            // Try to allocate trampoline near the call site using VirtualAlloc directly
            // SKSE::Trampoline::create() calls report_and_fail on failure (fatal),
            // so we must pre-check or use the shared trampoline.
            bool hooked = false;

            // Try shared SKSE trampoline first (safest — already allocated by SKSE)
            auto& trampoline = SKSE::GetTrampoline();
            if (trampoline.capacity() - trampoline.allocated_size() >= 14) {
                s_origReadFromSource = reinterpret_cast<ReadFromSource_t>(
                    trampoline.write_call<5>(callSite,
                        reinterpret_cast<std::uintptr_t>(&HookedReadFromSource)));
                logger::info("BSAMmap: ReadFromSource hook installed (shared trampoline)");
                hooked = true;
            }

            if (!hooked) {
                // Shared trampoline full — try allocating near game code (within ±2GB)
                auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(nullptr));
                for (std::uintptr_t off = 0x10000; off < 0x7FFF0000ULL; off += 0x10000) {
                    auto* mem = VirtualAlloc(reinterpret_cast<void*>(base + off),
                        64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (mem) {
                        static SKSE::Trampoline localTrampoline;
                        localTrampoline.set_trampoline(mem, 64);
                        s_origReadFromSource = reinterpret_cast<ReadFromSource_t>(
                            localTrampoline.write_call<5>(callSite,
                                reinterpret_cast<std::uintptr_t>(&HookedReadFromSource)));
                        logger::info("BSAMmap: ReadFromSource hook installed (private alloc at {:X})",
                            reinterpret_cast<std::uintptr_t>(mem));
                        hooked = true;
                        break;
                    }
                }
            }

            if (!hooked) {
                logger::warn("BSAMmap: ReadFromSource hook failed — no trampoline available");
            }
        }
    } else if (Settings::bCompatibilityMode) {
        logger::info("BSAMmap: ReadFromSource hook skipped (compatibility mode)");
    } else if (!Settings::bEnableMmap) {
        logger::info("BSAMmap: ReadFromSource hook skipped (mmap disabled)");
    } else {
        logger::info("BSAMmap: ReadFromSource hook skipped (baseline mode)");
    }

    const char* mode = Settings::bBaselineMode ? "BASELINE (passthrough)"
                     : Settings::bCompatibilityMode ? "COMPATIBILITY (stock engine I/O)"
                     : "MMAP (active)";
    logger::info("BSAMmap: Hooks installed — mode: {}", mode);

    // BSA stream factory hook — Detours on the internal function that creates
    // CompressedArchiveStream. Replaces with MmapStream for cached entries.
    // Only used in factory mode (bCompatibilityMode == false); compatibility mode
    // serves cached data directly inside HookedCompDoRead.
    if (!Settings::bBaselineMode && Settings::bEnableDecompCache && !Settings::bCompatibilityMode) {
        auto gameBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(nullptr));

        // Known RVAs: SE 1.5.97: 0xC3E630, AE 1.6.1170: 0xD03E10, VR 1.4.15: 0xC836E0
        auto funcAddr = gameBase + REL::Relocate(0xC3E630, 0xD03E10, 0xC836E0);

        // Verify the function has the expected compression check pattern:
        // test/cmp [reg+0xC] with 0x80000000 or sign check within first 64 bytes
        auto* code = reinterpret_cast<const std::uint8_t*>(funcAddr);
        bool verified = false;
        for (int i = 0; i < 64 && !verified; ++i) {
            // Pattern: F7 xx 0C 00 00 00 80 (test [reg+0xC], 0x80000000)
            if (i + 7 <= 64 && code[i] == 0xF7 && code[i+2] == 0x0C &&
                code[i+3] == 0x00 && code[i+4] == 0x00 && code[i+5] == 0x00 && code[i+6] == 0x80)
                verified = true;
            // Pattern: 83 7x 0C 00 0F 8D (cmp [reg+0xC], 0; jge)
            if (i + 6 <= 64 && code[i] == 0x83 && (code[i+1] & 0xF8) == 0x78 &&
                code[i+2] == 0x0C && code[i+3] == 0x00 && code[i+4] == 0x0F && code[i+5] == 0x8D)
                verified = true;
            // Pattern: 81 xx 0C 00 00 00 80 (test dword [reg+0xC], 0x80000000)
            if (i + 7 <= 64 && (code[i] == 0x81 || code[i] == 0xF7) &&
                code[i+2] == 0x0C && code[i+6] == 0x80)
                verified = true;
        }

        if (!verified) {
            // Hardcoded RVA doesn't match this game version — try runtime scan
            logger::info("BSAMmap: Factory function not at expected RVA, scanning...");
            funcAddr = 0;

            // Scan for LEA to CompressedArchiveStream vtable, find constructor, find caller
            auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(gameBase);
            auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(gameBase + dos->e_lfanew);
            auto* sec = IMAGE_FIRST_SECTION(nt);
            const std::uint8_t* textBase = nullptr;
            std::size_t textSize = 0;
            std::uintptr_t textVA = 0;
            for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                if (std::memcmp(sec[i].Name, ".text", 5) == 0 && sec[i].VirtualAddress < 0x100000) {
                    textBase = reinterpret_cast<const std::uint8_t*>(gameBase + sec[i].VirtualAddress);
                    textSize = sec[i].Misc.VirtualSize;
                    textVA = sec[i].VirtualAddress;
                    break;
                }
            }

            if (textBase) {
                // Find LEA RAX, [CompressedArchiveStream vtable] xrefs
                for (std::size_t i = 0; i + 7 < textSize && !funcAddr; ++i) {
                    if (textBase[i] == 0x48 && textBase[i+1] == 0x8D && (textBase[i+2] & 0xC7) == 0x05) {
                        auto disp = *reinterpret_cast<const std::int32_t*>(textBase + i + 3);
                        auto target = gameBase + textVA + i + 7 + disp;
                        if (target != s_compressedArchiveStreamVtbl) continue;

                        // Found vtable xref — find this function's start
                        auto ctorOff = i;
                        for (auto b = i; b > 0 && b > i - 0x300; --b) {
                            if (textBase[b-1] == 0xCC && textBase[b] != 0xCC) { ctorOff = b; break; }
                        }
                        auto ctorAddr = gameBase + textVA + ctorOff;

                        // Find callers of this constructor
                        for (std::size_t j = 0; j + 5 < textSize; ++j) {
                            if (textBase[j] != 0xE8) continue;
                            auto rel = *reinterpret_cast<const std::int32_t*>(textBase + j + 1);
                            if (gameBase + textVA + j + 5 + rel != ctorAddr) continue;

                            // Found caller — find its function start
                            auto parentOff = j;
                            for (auto b = j; b > 0 && b > j - 0x400; --b) {
                                if (textBase[b-1] == 0xCC && textBase[b] != 0xCC) { parentOff = b; break; }
                            }
                            auto parentAddr = gameBase + textVA + parentOff;

                            // Verify compression check in parent
                            auto* pc = reinterpret_cast<const std::uint8_t*>(parentAddr);
                            bool hasCheck = false;
                            for (int k = 0; k < 64; ++k) {
                                if (k + 7 <= 64 && pc[k] == 0xF7 && pc[k+2] == 0x0C && pc[k+6] == 0x80)
                                    hasCheck = true;
                                if (k + 6 <= 64 && pc[k] == 0x83 && (pc[k+1] & 0xF8) == 0x78 &&
                                    pc[k+2] == 0x0C && pc[k+3] == 0x00)
                                    hasCheck = true;
                                if (k + 7 <= 64 && pc[k] == 0x81 && pc[k+2] == 0x0C && pc[k+6] == 0x80)
                                    hasCheck = true;
                            }
                            if (hasCheck) {
                                funcAddr = parentAddr;
                                logger::info("BSAMmap: Factory function found via scan at {:X}", funcAddr);
                                break;
                            }
                        }
                    }
                }
            }

            if (!funcAddr) {
                logger::warn("BSAMmap: Could not find factory function — factory hook disabled");
            }
        }

        if (funcAddr) {
            s_origCreateBsaStream = reinterpret_cast<CreateBsaStream_t>(funcAddr);

            LONG err = DetourTransactionBegin();
            if (err == NO_ERROR) {
                DetourUpdateThread(GetCurrentThread());
                DetourAttach(reinterpret_cast<void**>(&s_origCreateBsaStream),
                             reinterpret_cast<void*>(&HookedCreateBsaStream));
                err = DetourTransactionCommit();
                if (err == NO_ERROR) {
                    logger::info("BSAMmap: Stream factory hook installed at {:X}", funcAddr);
                } else {
                    s_origCreateBsaStream = reinterpret_cast<CreateBsaStream_t>(funcAddr);
                    logger::error("BSAMmap: Stream factory Detours failed: {}", err);
                }
            }
        }
    } else if (Settings::bEnableDecompCache && Settings::bCompatibilityMode) {
        logger::info("BSAMmap: Stream factory hook skipped (using inline cache delivery)");
    }
}

}  // namespace Hooks
