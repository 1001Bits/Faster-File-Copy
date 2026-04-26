#include "PCH.h"
#include "Hooks.h"
#include "BA2MemoryMap.h"
#include "DecompCache.h"
#include "FastCopy.h"
#include "MmapStream.h"
#include "Settings.h"

#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>
#include <zlib.h>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <Psapi.h>
#include <detours/detours.h>
#pragma comment(lib, "psapi.lib")

static void LogInfo(const char* msg) { logger::info(msg); }
static void LogWarn(const char* msg) { logger::warn(msg); }

namespace Hooks
{

// ═════════════════════════════════════════════════════════════════════════════
// ReaderStream field offsets — runtime-initialized per game version
// ═════════════════════════════════════════════════════════════════════════════

namespace Field
{
    inline std::ptrdiff_t Source                = 0x10;
    inline std::ptrdiff_t StartOffset           = 0x20;
    inline std::ptrdiff_t Name                  = 0x28;
    inline std::ptrdiff_t CurrentRelativeOffset = 0x30;
    inline std::ptrdiff_t CompressedSize        = 0x34;
    inline std::ptrdiff_t UncompressedSize      = 0x38;
    inline std::ptrdiff_t Flags                 = 0x3C;

    inline void Init()
    {
        // AE 1.11.x shifts every field by +0x08 vs OG/NG/VR. CommonLibF4 only
        // distinguishes F4/NG/VR (both AE and NG 1.10.984 are "NG"), so we
        // branch on the minor version (patch byte) to pick the right layout.
        const auto ver = REL::Module::get().version();
        const bool isAE = (ver[1] == 11);
        const std::ptrdiff_t shift = isAE ? 0x08 : 0x00;

        Source                = 0x10 + shift;
        StartOffset           = 0x20 + shift;
        Name                  = 0x28 + shift;
        CurrentRelativeOffset = 0x30 + shift;
        CompressedSize        = 0x34 + shift;
        UncompressedSize      = 0x38 + shift;
        Flags                 = 0x3C + shift;

        char buf[256];
        std::snprintf(buf, sizeof(buf),
            "FFC4: Field offsets (ver %u.%u.%u.%u, AE=%d) — Source=0x%X, Start=0x%X, CurOff=0x%X, CompSz=0x%X, UncompSz=0x%X",
            ver[0], ver[1], ver[2], ver[3], isAE ? 1 : 0,
            static_cast<int>(Source), static_cast<int>(StartOffset),
            static_cast<int>(CurrentRelativeOffset),
            static_cast<int>(CompressedSize), static_cast<int>(UncompressedSize));
        LogInfo(buf);
    }
}

template <typename T>
static T ReadField(const void* obj, std::ptrdiff_t off)
{
    return *reinterpret_cast<const T*>(static_cast<const std::uint8_t*>(obj) + off);
}

template <typename T>
static void WriteField(void* obj, std::ptrdiff_t off, T val)
{
    *reinterpret_cast<T*>(static_cast<std::uint8_t*>(obj) + off) = val;
}

// ═════════════════════════════════════════════════════════════════════════════
// Lock-free source cache (512 slots, open-addressing)
// ═════════════════════════════════════════════════════════════════════════════

constexpr int kHashSlots = 512;
constexpr int kHashMask  = kHashSlots - 1;
constexpr int kMaxProbe  = 16;

struct SourceHashEntry {
    std::atomic<std::uintptr_t>            key{ 0 };
    std::atomic<const BA2::MappedArchive*> archive{ nullptr };
};

static SourceHashEntry s_sourceHash[kHashSlots];
static std::atomic<bool> s_cacheFrozen{ false };

static const BA2::MappedArchive* SourceLookup(const void* source)
{
    auto k = reinterpret_cast<std::uintptr_t>(source);
    auto slot = static_cast<int>((k >> 4) & kHashMask);
    for (int i = 0; i < kMaxProbe; ++i) {
        auto idx = (slot + i) & kHashMask;
        auto stored = s_sourceHash[idx].key.load(std::memory_order_acquire);
        if (stored == k) return s_sourceHash[idx].archive.load(std::memory_order_relaxed);
        if (stored == 0) return nullptr;
    }
    return nullptr;
}

static void SourceInsert(const void* source, const BA2::MappedArchive* archive)
{
    if (s_cacheFrozen.load(std::memory_order_relaxed)) return;
    auto k = reinterpret_cast<std::uintptr_t>(source);
    auto slot = static_cast<int>((k >> 4) & kHashMask);
    for (int i = 0; i < kMaxProbe; ++i) {
        auto idx = (slot + i) & kHashMask;
        std::uintptr_t expected = 0;
        // Prepare the archive pointer in a local variable first.
        // We'll attempt to CAS the key from 0 -> k. If we win, we then
        // store the archive pointer. This ensures no other thread can
        // see a non-zero key with a stale archive pointer.
        if (s_sourceHash[idx].key.compare_exchange_strong(
                expected, k, std::memory_order_acq_rel, std::memory_order_relaxed)) {
            // We own this slot — now store the archive.
            s_sourceHash[idx].archive.store(archive, std::memory_order_release);
            return;
        }
        if (expected == k) return;  // Key already present
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Stream → archive fast cache — populated at factory creation, consulted on
// DoRead hot path to skip SourceLookup().
//
// Single-slot per hash (no probing on lookup) for minimum latency. Collisions
// evict the prior entry; DoRead falls through to the old path on a miss.
//
// Entries carry a `source` validator (the Source pointer we read at insert
// time) to defend against stream-pointer reuse: if an old ReaderStream is
// freed and a new one is allocated at the same address without our factory
// hooks firing (e.g. inside a nested ctor we skipped), the cached entry's
// source won't match the new stream's Source field, and lookup returns
// nullptr so DoRead falls through to ResolveSource and backfills correctly.
// ═════════════════════════════════════════════════════════════════════════════

constexpr int kStreamHashSlots = 4096;
constexpr int kStreamHashMask  = kStreamHashSlots - 1;

struct StreamHashEntry {
    std::atomic<std::uintptr_t>            key{ 0 };
    std::atomic<const void*>               source{ nullptr };
    std::atomic<const BA2::MappedArchive*> archive{ nullptr };
};
static StreamHashEntry s_streamHash[kStreamHashSlots];

// Returns cached archive iff both the stream address AND its current Source
// pointer match the insertion-time values. `source_check` is the Source field
// the caller just read from the stream.
static inline const BA2::MappedArchive* StreamArchiveLookup(
    const void* stream, const void* source_check)
{
    auto k = reinterpret_cast<std::uintptr_t>(stream);
    auto idx = static_cast<int>((k >> 4) & kStreamHashMask);
    auto stored = s_streamHash[idx].key.load(std::memory_order_acquire);
    if (stored != k) return nullptr;
    auto storedSrc = s_streamHash[idx].source.load(std::memory_order_relaxed);
    if (storedSrc != source_check) return nullptr;
    return s_streamHash[idx].archive.load(std::memory_order_relaxed);
}

static inline void StreamArchiveInsert(
    const void* stream, const void* source, const BA2::MappedArchive* archive)
{
    auto k = reinterpret_cast<std::uintptr_t>(stream);
    auto idx = static_cast<int>((k >> 4) & kStreamHashMask);
    // Order matters: archive + source first, then release-store key.
    // A concurrent lookup that sees key==k must already see archive+source.
    s_streamHash[idx].archive.store(archive, std::memory_order_relaxed);
    s_streamHash[idx].source.store(source, std::memory_order_relaxed);
    s_streamHash[idx].key.store(k, std::memory_order_release);
}

// ═════════════════════════════════════════════════════════════════════════════
// QPC timing (forward declarations)
// ═════════════════════════════════════════════════════════════════════════════

static std::atomic<std::int64_t>  s_ticksMmapRead{ 0 };
static std::atomic<std::int64_t>  s_ticksFallbackRead{ 0 };
static std::atomic<std::int64_t>  s_ticksDecomp{ 0 };
static std::atomic<std::int64_t>  s_ticksResolve{ 0 };

// Shutdown flag for background threads (stats thread, flush thread)
static std::atomic<bool> s_shutdownRequested{ false };

// ═════════════════════════════════════════════════════════════════════════════
// .rdata section range — cached at startup for vtable validation
// ═════════════════════════════════════════════════════════════════════════════

static std::uintptr_t s_rdataStart = 0;
static std::uintptr_t s_rdataEnd   = 0;

static void InitRdataRange()
{
    auto gameBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(nullptr));
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(gameBase);
    auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS*>(gameBase + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(sec[i].Name, ".rdata", 6) == 0) {
            s_rdataStart = gameBase + sec[i].VirtualAddress;
            s_rdataEnd   = s_rdataStart + sec[i].Misc.VirtualSize;
            break;
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Source resolution — DoGetName on the source stream
// ═════════════════════════════════════════════════════════════════════════════

static const BA2::MappedArchive* ResolveSource(void* sourceStreamPtr)
{
    auto* cached = SourceLookup(sourceStreamPtr);
    if (cached) return cached;
    if (s_cacheFrozen.load(std::memory_order_relaxed)) return nullptr;

    const BA2::MappedArchive* result = nullptr;
    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);

    try {
        // Null / sentinel pre-check — catches nullptr, INVALID_HANDLE_VALUE, etc.
        if (!sourceStreamPtr || reinterpret_cast<std::uintptr_t>(sourceStreamPtr) < 0x10000)
        { goto done; }

        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(sourceStreamPtr, &mbi, sizeof(mbi)) ||
                !(mbi.State & MEM_COMMIT) || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
            { goto done; }

            // Validate vtable pointer — must be in the game's .rdata section
            // (where all vtables live). Calling DoGetName on an object with
            // an unknown vtable can execute arbitrary code and corrupt
            // heap/stack, causing delayed crashes in other mods.
            auto innerVtbl = *reinterpret_cast<std::uintptr_t*>(sourceStreamPtr);
            if (s_rdataStart && (innerVtbl < s_rdataStart || innerVtbl >= s_rdataEnd))
            { goto done; }

            auto** vtbl = reinterpret_cast<void**>(innerVtbl);

            RE::BSFixedString name;
            using DoGetName_t = bool(*)(void*, RE::BSFixedString*);
            auto doGetName = reinterpret_cast<DoGetName_t>(vtbl[0x0F]);

            if (doGetName(sourceStreamPtr, &name)) {
                const char* str = name.c_str();
                if (str && str[0]) {
                    std::filesystem::path p(str);
                    auto fname = p.filename().string();
                    result = BA2::MemoryMapManager::GetSingleton().FindByName(fname);
                    if (result) {
                        auto msg = "FFC4: Source resolved -> " + fname;
                        LogInfo(msg.c_str());
                    }
                }
            }
        }
    } catch (...) {}

done:
    SourceInsert(sourceStreamPtr, result);
    QueryPerformanceCounter(&t1);
    s_ticksResolve.fetch_add(t1.QuadPart - t0.QuadPart, std::memory_order_relaxed);
    return result;
}

// ═════════════════════════════════════════════════════════════════════════════
// QPC timing & statistics
// ═════════════════════════════════════════════════════════════════════════════

// Hot-path stat bump. Diagnostic-only counters go through this so release
// builds skip the cross-cache-line atomic traffic when the user has stats
// off. The branch predicts well because Settings::bEnableStats is read-only
// after startup. Logic-bearing atomics (bridge sequences, ring-buffer heads,
// shutdown flags) must NOT use this — they are always required.
#define STAT_ADD(ctr, val) do {                                            \
    if (Settings::bEnableStats)                                            \
        (ctr).fetch_add((val), std::memory_order_relaxed);                 \
} while (0)
#define STAT_INC(ctr) STAT_ADD(ctr, 1)

static std::int64_t s_qpcFreq    = 1;
static std::int64_t s_installTick = 0;

static std::atomic<std::uint64_t> s_mmapReads{ 0 };
static std::atomic<std::uint64_t> s_mmapBytes{ 0 };
static std::atomic<std::uint64_t> s_fallbackReads{ 0 };
static std::atomic<std::uint64_t> s_fallbackBytes{ 0 };
static std::atomic<std::uint64_t> s_streamReplacements{ 0 };
static std::atomic<std::uint64_t> s_cacheServed{ 0 };
static std::atomic<std::uint64_t> s_cacheServedBytes{ 0 };

// Inflate-path timing (apples-to-apples cache-on vs cache-off measurement).
// All counters are bumped from HookedInflate. _ServeNs is wall time spent in
// the cache-serve memcpy branches; _ZlibNs is wall time in s_origInflate.
// _TotalNs is the entire HookedInflate wall time; (Total - Zlib - Serve) is
// the FFC4 per-call overhead (bridge lookup, fp-hash, map probe, bookkeeping).
static std::atomic<std::uint64_t> s_inflateCalls{ 0 };
static std::atomic<std::uint64_t> s_inflateZlibNs{ 0 };
static std::atomic<std::uint64_t> s_inflateZlibBytesIn{ 0 };
static std::atomic<std::uint64_t> s_inflateZlibBytesOut{ 0 };
static std::atomic<std::uint64_t> s_inflateServeNs{ 0 };
static std::atomic<std::uint64_t> s_inflateTotalNs{ 0 };

// Wall-clock window across HookedInflate calls — pairs with _ZlibNs (CPU sum).
// Ratio cpu/wall reveals whether inflate is the wall bottleneck:
//   ~1.0  → CPU-bound, single-threaded inflate dominates
//   >>1.0 → multi-threaded, inflate parallelism saturates
//   <<1.0 → big gaps between calls — inflate is NOT the bottleneck (I/O wait)
// Reset on each stats snapshot so the ratio reflects the last interval only.
static std::atomic<std::int64_t> s_inflateFirstQpc{ 0 };
static std::atomic<std::int64_t> s_inflateLastQpc{ 0 };

// Diagnostic: BSTextureStreamer::Manager::zscrapAllocate call count + bytes.
// Asks "does our texture direct-serve actually bypass the engine's ScrapHeap
// allocation?" — A/B with bTextureDirectServe on vs off should show a delta.
// If no delta, our serve runs AFTER the scrap alloc and we still pay the
// Buffout4 bScrapHeap=true tax even on cache hits.
static std::atomic<std::uint64_t> s_zscrapCalls{ 0 };
static std::atomic<std::uint64_t> s_zscrapBytes{ 0 };
using zscrapAlloc_fn = void* (__fastcall*)(void* a_this, int a_size, int a_count);
static zscrapAlloc_fn s_origZscrapAlloc = nullptr;

// LooseFileStream slot-12 async submit (FUN_1416AEFE0 on AE) counters.
// Hook short-circuits the engine's async BA2 read: reads compressed bytes
// from the archive mmap directly into the caller's buffer and fakes async
// completion by making *wait_ptr == *tag_ptr. See the architecture reference
// memory for the full async-completion protocol and why this is safe.
static std::atomic<std::uint64_t> s_looseSubmitCalls{ 0 };   // hook entries
static std::atomic<std::uint64_t> s_looseSubmitServed{ 0 };  // short-circuited
static std::atomic<std::uint64_t> s_looseSubmitBytes{ 0 };   // bytes memcpy'd from mmap
using LooseAsyncSubmit_fn = int (__fastcall*)(
    void* self, void* buffer, std::uint64_t size, std::uint64_t offset,
    std::uint32_t arg5, int* tag_ptr, int* wait_ptr, void* event_flag);
static LooseAsyncSubmit_fn s_origLooseAsyncSubmit = nullptr;

// AsyncReaderStream::DoStartRead (FUN_1416A2350 on AE) — vtable slot 6 of the
// async stream class. Save-load uses async streams which call this instead
// of routing through the FUN_14169D530 → source slot-12 path. The orig is a
// tail-call wrapper: this[0x20] = source, this[0x28] = startOffset; r9 is
// adjusted to absolute offset and control jumps to source->vtbl[6]. We
// intercept here at the stream level (known field offsets, simple signature)
// and serve directly from the archive mmap. AsyncReaderStream::DoWait
// (vtbl 11) reads this[0x30] which our short-circuit never sets, so the
// follow-up wait returns immediately.
static std::atomic<std::uint64_t> s_asyncStartCalls{ 0 };
static std::atomic<std::uint64_t> s_asyncStartServed{ 0 };
static std::atomic<std::uint64_t> s_asyncStartBytes{ 0 };
using AsyncStartRead_fn = std::uint64_t (__fastcall*)(
    void* self, void* buffer, std::uint64_t size, std::uint64_t offset);
static AsyncStartRead_fn s_origAsyncStartRead = nullptr;

// Diagnostic ring buffer for first-call dst pointers — populated when
// strm->total_in == 0 (start of a new inflate stream). Used to discover
// where the game allocates UNPACKED dst buffers per stream, which is the
// missing piece for AE HL texture serve (stream+0xe0 is packed-size scratch).
struct InflateDstSample {
    std::uint32_t tid;
    void*         next_out;
    std::uint32_t avail_out;
};
static constexpr std::size_t kInflateDstSamples = 32;
static InflateDstSample s_inflateDstSamples[kInflateDstSamples] {};
static std::atomic<std::uint32_t> s_inflateDstHead{ 0 };
static std::atomic<bool>          s_inflateDstEnabled{ true };  // off after first dump

// Factory hook diagnostic counters — bumped per early-return reason so we
// can see where streams get filtered out on runtimes where cache serve
// fails (e.g. AE 1.11.191 when inflate hook can't install).
static std::atomic<std::uint64_t> s_facCalls{ 0 };      // total HookedFactory entries after s_origFactory
static std::atomic<std::uint64_t> s_facRejStream{ 0 };  // stream null or !IsArchiveReaderStream
static std::atomic<std::uint64_t> s_facRejSource{ 0 };  // sourcePtr null / archive not resolved / !IsOpen
static std::atomic<std::uint64_t> s_facServedMmap{ 0 }; // uncompressed → mmap replacement succeeded
static std::atomic<std::uint64_t> s_facNotReady{ 0 };   // compressed + cache enabled but DecompCache not ready
static std::atomic<std::uint64_t> s_facCacheMiss{ 0 };  // compressed + Lookup returned empty
static std::atomic<std::uint64_t> s_facServedCache{ 0 };// compressed + cache serve succeeded
static std::atomic<std::uint64_t> s_facReplaceCompressed{ 0 }; // compressed → MmapStream substitute (factory replace)

// Chunk factory hook (FUN_14169e3b0 on AE) — monitor-only path.
// cfCalls  : every entry into the hook (fires even on nested calls)
// cfInsert : successfully registered (stream, source, archive) into s_streamHash
// cfRejOk  : orig returned false / null outSharedPtr / null stream
// cfRejStream : IsArchiveReaderStream rejected the created stream
// cfRejSrc : stream had null Source or archive lookup failed
static std::atomic<std::uint64_t> s_cfCalls{ 0 };
static std::atomic<std::uint64_t> s_cfInsert{ 0 };
static std::atomic<std::uint64_t> s_cfRejOk{ 0 };
static std::atomic<std::uint64_t> s_cfRejStream{ 0 };
static std::atomic<std::uint64_t> s_cfRejSrc{ 0 };

// Vtable-swap replacement (task #75, bChunkFactoryReplace=true).
static std::atomic<std::uint64_t> s_overrideInstalled{ 0 };
static std::atomic<std::uint64_t> s_overrideDoReadCalls{ 0 };
static std::atomic<std::uint64_t> s_overrideDoReadBytes{ 0 };
static std::atomic<std::uint64_t> s_overrideDtors{ 0 };
static std::atomic<std::uint64_t> s_overrideUnregisterMiss{ 0 };
static std::atomic<std::uint64_t> s_overrideRejVtbl{ 0 };  // origVtbl outside .rdata — skipped swap

// Texture streamer counters (paired hooks defined below; definitions live
// here so OnPostLoadGame / StatsThreadFn can read them at any compile point).
static std::atomic<std::uint64_t> s_texRegistered{ 0 };
static std::atomic<std::uint64_t> s_texUnresolved{ 0 };
static std::atomic<std::uint64_t> s_texFetches{ 0 };
static std::atomic<std::uint64_t> s_texBridgeSet{ 0 };
static std::atomic<std::uint64_t> s_texBridgeConsumed{ 0 };
static std::atomic<std::uint64_t> s_texBridgeConsumedBytes{ 0 };
static std::atomic<std::uint64_t> s_texCacheMiss{ 0 };
static std::atomic<std::uint64_t> s_texDirectServed{ 0 };
static std::atomic<std::uint64_t> s_texDirectServedBytes{ 0 };
static std::atomic<std::uint64_t> s_texDirectWaitBypassed{ 0 };
static std::atomic<std::uint64_t> s_texCaptureRecorded{ 0 };
static std::atomic<std::uint64_t> s_texCaptureRecordedBytes{ 0 };
static std::atomic<std::uint64_t> s_texCaptureSkipped{ 0 };  // already cached, re-inflate skipped
static std::atomic<std::uint64_t> s_texFingerprintHits{ 0 };
static std::atomic<std::uint64_t> s_texSizeMismatch{ 0 };
static std::atomic<int>           s_texMismatchLogged{ 0 };
static std::atomic<std::uint64_t> s_texFpServed{ 0 };
static std::atomic<std::uint64_t> s_texFpServedBytes{ 0 };

// Cache-miss diagnostic counters — answer where the 68% zlib gameplay traffic
// is leaking past the cache. Zero cost beyond one relaxed fetch_add per site.
static std::atomic<std::uint64_t> s_texServeGatePass{ 0 };    // pre-inflate: retRVA matched tex gate
static std::atomic<std::uint64_t> s_texServeFpMiss{ 0 };      // pre-inflate: fp not in s_compFingerprint
static std::atomic<std::uint64_t> s_texServeSizeReject{ 0 };  // pre-inflate: |inDiff| > 2
static std::atomic<std::uint64_t> s_texServeDcacheMiss{ 0 };  // pre-inflate: fp matched but dcache empty
static std::atomic<std::uint64_t> s_texCaptureFpMiss{ 0 };    // post-inflate: tex-gate pass, fp not in index

// fpMiss diagnostic — per-gameplay-session sampler. Dumps the first N
// fp-miss inputs so we can categorize why the signature isn't in the
// index (archive not mapped / mid-stream inflate re-entry / streamer
// mutates buffer). Reset in SnapshotGameplayStart.
static std::atomic<std::uint32_t> s_fpMissDumpSeq{ 0 };
static constexpr std::uint32_t    kFpMissDumpLimit = 32;

// AsyncReaderStream diagnostics — answer whether our slot[6] intercept actually
// feeds the bridge pipeline during gameplay, or if the ~1 GB GNRL zlib gap is
// flowing through some other code path. Gameplay cache% barely moved after
// installing the async hook — these counters pinpoint why.
static std::atomic<std::uint64_t> s_asyncDoReadCalls{ 0 };    // total entries to HookedDoRead via async vtable
static std::atomic<std::uint64_t> s_asyncDoReadBytes{ 0 };    // bytes delivered by async DoRead (all types)
static std::atomic<std::uint64_t> s_asyncCompressedCalls{ 0 };// async calls where compressedSize != 0
static std::atomic<std::uint64_t> s_asyncBridgeHit{ 0 };      // async + compressed + Lookup returned data
static std::atomic<std::uint64_t> s_asyncBridgeMiss{ 0 };     // async + compressed + Lookup empty

// Cache-miss sampler (task #115) — capture the first N compressed-entry cache
// misses observed in HookedDoRead during save load, so we can identify which
// archives / sizes / call sites comprise the remaining 25% zlib bucket.
// Dumped at save-load completion alongside other SAVE LOAD lines.
struct CompMissSample {
    const BA2::MappedArchive* archive;     // resolved archive (we have name via path)
    std::uint32_t             startOff;
    std::uint32_t             compSize;
    std::uint32_t             uncompSize;
    std::uintptr_t            callerRVA;   // engine call site (HookedDoRead caller)
};
static constexpr std::size_t kCompMissSamples = 256;
static CompMissSample             s_compMissSamples[kCompMissSamples]{};
static std::atomic<std::uint32_t> s_compMissHead{ 0 };  // next slot to write
static std::atomic<std::uint64_t> s_compMissTotal{ 0 }; // total misses (uncapped)

// Unbridged-inflate caller sampler. When HookedInflate runs without a bridge
// set (i.e. the caller didn't come through our HookedDoRead → BridgeSet path),
// we attribute the zlib work back to each return-address bucket. Accounting is
// full (not sampled) because the unbridged rate is ~10K/s and a single lock
// scan over 32 entries is cheap. Per-caller ns + bytes tells us which zlib
// routes are actually worth caching (Csg, 4KB reader, etc). Up to 32 distinct
// RVAs retained. For the 4KB reader bucket (FUN_141da2ea0) we additionally
// sample the source-object vtable to identify the upstream class via Ghidra.
struct InflateCallerSample {
    std::uint32_t  rva        = 0;   // module-relative return address (0 = empty slot)
    std::uint32_t  count      = 0;   // total unbridged inflate calls matching this rva
    std::uint64_t  nsTotal    = 0;   // cumulative origInflate CPU time for this caller (ns)
    std::uint64_t  bytesTotal = 0;   // cumulative origInflate output bytes for this caller
    std::uintptr_t srcVtable  = 0;   // source-object vtable (only set for 4KB reader RVA)
};
static constexpr std::size_t kInflateCallerSamples = 32;
static InflateCallerSample s_inflateCallerSamples[kInflateCallerSamples]{};
static std::mutex          s_inflateCallerMtx;
static std::atomic<bool>   s_gameplayActive{ false };
static std::atomic<bool>   s_saveLoadActive{ false };  // also enables caller attribution
// Gameplay-phase gate: false during startup and the first save-load, flips
// true on the first kPostLoadGame and stays true. Gates BOTH cache-serve
// paths (compressed-direct-serve, bridge-set, texture fp-serve) AND cache-
// capture paths (GNRL accumulator in HookedDoRead, texture capture in
// HookedInflate post-inflate). Rationale: per user report, the startup
// phase win is mmap-only — cache adds no benefit there, and capture adds
// per-call overhead with no offsetting win. Save-load is short-circuited
// separately. Cache infra (capture + serve) only fires during gameplay.
static std::atomic<bool>   s_gameplayPhase{ false };

// Texture manager pointer — captured from HookedAE_ReadMipsToTexture so that
// HookedStreamInflate can resolve archive from stream.sourceIdx via the
// manager's sourceTable, instead of calling ResolveSource on the wrong object.
static std::atomic<void*> s_texMgr{ nullptr };

static const BA2::MappedArchive* ResolveTexStreamSource(void* a_stream)
{
    auto* mgr = static_cast<std::uint8_t*>(s_texMgr.load(std::memory_order_acquire));
    if (!mgr) return nullptr;
    auto* s = static_cast<std::uint8_t*>(a_stream);
    auto sourceIdx = *reinterpret_cast<std::uint8_t*>(s + 0x0c);
    auto sourceCount = *reinterpret_cast<std::uint32_t*>(mgr + 0x98de8);
    if (sourceIdx >= sourceCount) return nullptr;
    auto** sourceTable = *reinterpret_cast<void***>(mgr + 0x98de0);
    if (!sourceTable) return nullptr;
    auto* source = sourceTable[sourceIdx];
    if (!source) return nullptr;
    return SourceLookup(source);
}

// High-level ReadMipsToTexture dispatcher serve (crash-safety path for Buffout
// MM patches — see HookedReadMipsToTexture for rationale).
static std::atomic<std::uint64_t> s_hlCalls{ 0 };
static std::atomic<std::uint64_t> s_hlServed{ 0 };
static std::atomic<std::uint64_t> s_hlServedBytes{ 0 };
static std::atomic<std::uint64_t> s_hlMissChunk{ 0 };
static std::atomic<std::uint64_t> s_hlFallthrough{ 0 };
// Diagnostic counters for fallthrough reasons
static std::atomic<std::uint64_t> s_hlFtDisabled{ 0 };
static std::atomic<std::uint64_t> s_hlFtReader{ 0 };
static std::atomic<std::uint64_t> s_hlFtShadow{ 0 };
static std::atomic<std::uint64_t> s_hlFtPreload{ 0 };
static std::atomic<std::uint64_t> s_hlFtNoSource{ 0 };
static std::atomic<std::uint64_t> s_hlFtNoArchive{ 0 };
static std::atomic<std::uint64_t> s_hlFtNotReady{ 0 };
static std::atomic<std::uint64_t> s_hlFtRange{ 0 };
static std::atomic<std::uint64_t> s_hlFtNullPtrs{ 0 };
// Per-mipchain timing — measures in-game texture load cost directly.
// s_hlServedNs: cumulative time for served calls (entry to return).
// s_hlFtNs:     cumulative time spent inside s_origAE_ReadMipsToTexture for
//               fallthrough calls — this is the stock baseline we compare against.
// s_hlChunksServed: total chunks memcpy'd across all served calls.
static std::atomic<std::uint64_t> s_hlServedNs{ 0 };
static std::atomic<std::uint64_t> s_hlFtNs{ 0 };
static std::atomic<std::uint64_t> s_hlChunksServed{ 0 };
// Partial-mipchain serve counters. When the leading K chunks of [skip, lastMip]
// all hit but the rest miss, we memcpy those K mips and rewrite stream+0x4c to
// skip+K, so the fallthrough only re-processes the miss tail.
static std::atomic<std::uint64_t> s_hlPartialServed{ 0 };
static std::atomic<std::uint64_t> s_hlPartialChunks{ 0 };
static std::atomic<std::uint64_t> s_hlPartialBytes{ 0 };

// AE Manager::vtbl[0xe0]/[0xf0] completion-dispatcher MONITOR counters.
// Phase 1 (log-only) — validates call signature + completion-struct offsets
// before a future serve path allocates/uploads through these dispatchers.
static std::atomic<std::uint64_t> s_monE0Calls{ 0 };
static std::atomic<std::uint64_t> s_monF0Calls{ 0 };
static std::atomic<int>           s_monE0Logged{ 0 };
static std::atomic<int>           s_monF0Logged{ 0 };

static void InitTiming()
{
    LARGE_INTEGER freq, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&now);
    s_qpcFreq    = freq.QuadPart;
    s_installTick = now.QuadPart;
}

static double TicksToSec(std::int64_t ticks)
{
    return static_cast<double>(ticks) / static_cast<double>(s_qpcFreq);
}

std::uint64_t GetMappedReadCount()   { return s_mmapReads.load(std::memory_order_relaxed); }
std::uint64_t GetMappedBytesServed() { return s_mmapBytes.load(std::memory_order_relaxed); }
std::uint64_t GetFallbackReadCount() { return s_fallbackReads.load(std::memory_order_relaxed); }
std::uint64_t GetFallbackBytesServed(){ return s_fallbackBytes.load(std::memory_order_relaxed); }
std::uint64_t GetStreamReplacements(){ return s_streamReplacements.load(std::memory_order_relaxed); }
std::uint64_t GetCacheServedCount()  { return s_cacheServed.load(std::memory_order_relaxed); }
std::uint64_t GetCacheBytesServed()  { return s_cacheServedBytes.load(std::memory_order_relaxed); }
double GetMmapReadSeconds()          { return TicksToSec(s_ticksMmapRead.load(std::memory_order_relaxed)); }
double GetFallbackReadSeconds()      { return TicksToSec(s_ticksFallbackRead.load(std::memory_order_relaxed)); }
double GetDecompSeconds()            { return TicksToSec(s_ticksDecomp.load(std::memory_order_relaxed)); }
double GetResolveSeconds()           { return TicksToSec(s_ticksResolve.load(std::memory_order_relaxed)); }

double GetElapsedSeconds()
{
    LARGE_INTEGER now; QueryPerformanceCounter(&now);
    return TicksToSec(now.QuadPart - s_installTick);
}

Snapshot TakeSnapshot()
{
    return {
        s_mmapReads.load(std::memory_order_relaxed),
        s_mmapBytes.load(std::memory_order_relaxed),
        s_fallbackReads.load(std::memory_order_relaxed),
        s_fallbackBytes.load(std::memory_order_relaxed),
        s_cacheServed.load(std::memory_order_relaxed),
        s_cacheServedBytes.load(std::memory_order_relaxed),
        s_ticksMmapRead.load(std::memory_order_relaxed),
        s_ticksFallbackRead.load(std::memory_order_relaxed),
        s_ticksDecomp.load(std::memory_order_relaxed),
    };
}

// ── Save-load timing ────────────────────────────────────────────────────────

static std::int64_t s_preLoadTick = 0;
static Snapshot     s_preLoadSnap{};
static std::uint64_t s_preLoadInflateCalls     = 0;
static std::uint64_t s_preLoadInflateZlibNs    = 0;
static std::uint64_t s_preLoadInflateZlibIn    = 0;
static std::uint64_t s_preLoadInflateZlibOut   = 0;
static std::uint64_t s_preLoadInflateServeNs   = 0;

// Per-caller snapshot keyed by rva so the post-load logger can compute
// (calls/ns/bytes) deltas attributable to this save load only.
static InflateCallerSample s_preLoadCallerSnap[kInflateCallerSamples]{};

void OnPreLoadGame()
{
    LARGE_INTEGER now; QueryPerformanceCounter(&now);
    s_preLoadTick = now.QuadPart;
    s_preLoadSnap = TakeSnapshot();
    s_preLoadInflateCalls   = s_inflateCalls.load(std::memory_order_relaxed);
    s_preLoadInflateZlibNs  = s_inflateZlibNs.load(std::memory_order_relaxed);
    s_preLoadInflateZlibIn  = s_inflateZlibBytesIn.load(std::memory_order_relaxed);
    s_preLoadInflateZlibOut = s_inflateZlibBytesOut.load(std::memory_order_relaxed);
    s_preLoadInflateServeNs = s_inflateServeNs.load(std::memory_order_relaxed);

    // Reset cache-miss sampler so SAVE LOAD dump shows only this load's misses.
    s_compMissHead.store(0, std::memory_order_relaxed);
    s_compMissTotal.store(0, std::memory_order_relaxed);

    // Snapshot per-rva caller table for save-load attribution.
    {
        std::lock_guard lk(s_inflateCallerMtx);
        std::copy(std::begin(s_inflateCallerSamples),
                  std::end(s_inflateCallerSamples),
                  s_preLoadCallerSnap);
    }

    // Enable per-call caller attribution for the save-load window. Cleared in
    // OnPostLoadGame; gameplay path uses s_gameplayActive separately.
    s_saveLoadActive.store(true, std::memory_order_release);
}

double OnPostLoadGame()
{
    if (s_preLoadTick == 0) return 0.0;
    LARGE_INTEGER now; QueryPerformanceCounter(&now);
    double loadSec = TicksToSec(now.QuadPart - s_preLoadTick);
    auto post = TakeSnapshot();

    auto dMmapB  = post.mmapBytes - s_preLoadSnap.mmapBytes;
    auto dFBB    = post.fallbackBytes - s_preLoadSnap.fallbackBytes;
    auto dCacheB = post.cacheBytes - s_preLoadSnap.cacheBytes;
    auto dZlibOut = s_inflateZlibBytesOut.load(std::memory_order_relaxed) - s_preLoadInflateZlibOut;
    double dDecomp = TicksToSec(post.ticksDecomp - s_preLoadSnap.ticksDecomp);

    // MB/s = total decompressed payload delivered to engine per second.
    // Comparable across baseline (zlib_out only) and FFC4 (mmap + cache + zlib_out).
    double deliveredBytes = static_cast<double>(dMmapB + dCacheB + dZlibOut);
    double deliveredMB    = deliveredBytes / (1024.0 * 1024.0);
    double throughput     = (loadSec > 0.001) ? deliveredMB / loadSec : 0.0;

    double pctMmap  = (deliveredBytes > 0) ? dMmapB    / deliveredBytes * 100 : 0;
    double pctCache = (deliveredBytes > 0) ? dCacheB   / deliveredBytes * 100 : 0;
    double pctZlib  = (deliveredBytes > 0) ? dZlibOut  / deliveredBytes * 100 : 0;

    char buf[512];
    std::snprintf(buf, sizeof(buf),
        "SAVE LOAD: %.3fs | %.1f MB/s (%.1f MB delivered) | "
        "mmap %.1f%% (%.1f MB) | cache %.1f%% (%.1f MB) | "
        "zlib %.1f%% (%.1f MB, %.3fs decomp) | fb %.1f MB",
        loadSec, throughput, deliveredMB,
        pctMmap,  dMmapB   / (1024.0 * 1024.0),
        pctCache, dCacheB  / (1024.0 * 1024.0),
        pctZlib,  dZlibOut / (1024.0 * 1024.0), dDecomp,
        dFBB / (1024.0 * 1024.0));
    LogInfo(buf);

    // Inflate-path delta for this save load.
    auto dIC  = s_inflateCalls.load(std::memory_order_relaxed)      - s_preLoadInflateCalls;
    auto dIZ  = s_inflateZlibNs.load(std::memory_order_relaxed)     - s_preLoadInflateZlibNs;
    auto dIIn = s_inflateZlibBytesIn.load(std::memory_order_relaxed) - s_preLoadInflateZlibIn;
    auto dIO  = s_inflateZlibBytesOut.load(std::memory_order_relaxed)- s_preLoadInflateZlibOut;
    auto dIS  = s_inflateServeNs.load(std::memory_order_relaxed)    - s_preLoadInflateServeNs;
    double zlibMBps = (dIZ > 0) ? (dIO / (1024.0 * 1024.0)) / (dIZ / 1e9) : 0.0;
    char ibuf[512];
    std::snprintf(ibuf, sizeof(ibuf),
        "SAVE LOAD inflate: calls=%llu zlib %.1fms (in %.1f MB, out %.1f MB, %.1f MB/s) | serve %.1fms",
        (unsigned long long)dIC,
        dIZ / 1e6, dIIn / (1024.0 * 1024.0), dIO / (1024.0 * 1024.0), zlibMBps,
        dIS / 1e6);
    LogInfo(ibuf);

    // Cache-miss sampler dump (task #115). Per-archive aggregate first, then
    // up to 32 raw samples for spot-checking.
    {
        const auto totalMisses  = s_compMissTotal.load(std::memory_order_relaxed);
        const auto sampledCount = (std::min)(
            s_compMissHead.load(std::memory_order_relaxed),
            static_cast<std::uint32_t>(kCompMissSamples));
        if (sampledCount > 0) {
            // Aggregate by archive name + size bucket.
            struct AggKey { const BA2::MappedArchive* arc; std::uint64_t bucket; };
            struct AggVal { std::uint32_t count; std::uint64_t bytes; };
            std::vector<std::pair<const BA2::MappedArchive*, AggVal>> perArchive;
            perArchive.reserve(16);
            for (std::uint32_t i = 0; i < sampledCount; ++i) {
                const auto& s = s_compMissSamples[i];
                if (!s.archive) continue;
                bool found = false;
                for (auto& [arc, val] : perArchive) {
                    if (arc == s.archive) {
                        ++val.count;
                        val.bytes += s.uncompSize;
                        found = true;
                        break;
                    }
                }
                if (!found)
                    perArchive.push_back({ s.archive, AggVal{1, s.uncompSize} });
            }
            std::sort(perArchive.begin(), perArchive.end(),
                [](const auto& a, const auto& b) { return a.second.bytes > b.second.bytes; });

            char hdr[160];
            std::snprintf(hdr, sizeof(hdr),
                "SAVE LOAD comp-miss: total=%llu sampled=%u (top archives by uncomp bytes)",
                (unsigned long long)totalMisses, sampledCount);
            LogInfo(hdr);
            int shown = 0;
            for (const auto& [arc, val] : perArchive) {
                if (shown++ >= 8) break;
                char m[320];
                const auto& path = arc->GetPath();
                std::snprintf(m, sizeof(m),
                    "  miss[%d]: %s — %u entries, %.2f MB uncomp",
                    shown - 1,
                    path.filename().string().c_str(),
                    val.count,
                    val.bytes / (1024.0 * 1024.0));
                LogInfo(m);
            }
            // Spot-check raw samples (size + caller RVA).
            const std::uint32_t rawN = (sampledCount < 16) ? sampledCount : 16;
            for (std::uint32_t i = 0; i < rawN; ++i) {
                const auto& s = s_compMissSamples[i];
                char r[256];
                std::snprintf(r, sizeof(r),
                    "  raw[%u]: archive=%s startOff=%u comp=%u uncomp=%u callerRVA=0x%llX",
                    i,
                    s.archive ? s.archive->GetPath().filename().string().c_str() : "(null)",
                    s.startOff, s.compSize, s.uncompSize,
                    (unsigned long long)s.callerRVA);
                LogInfo(r);
            }
        }
    }

    // Inflate-caller diff for this save load (task #115). Snapshot caller table
    // now and subtract pre-load values per rva, so the breakdown attributes the
    // 25% zlib bucket to specific call sites (BA2 compressed reader vs save
    // file decompression vs other engine routes).
    {
        InflateCallerSample postSnap[kInflateCallerSamples];
        {
            std::lock_guard lk(s_inflateCallerMtx);
            std::copy(std::begin(s_inflateCallerSamples),
                      std::end(s_inflateCallerSamples), postSnap);
        }
        struct Diff { std::uint32_t rva, calls; std::uint64_t ns, bytes;
                      std::uintptr_t srcVtable; };
        std::vector<Diff> diffs;
        diffs.reserve(kInflateCallerSamples);
        for (const auto& post : postSnap) {
            if (post.rva == 0 || post.count == 0) continue;
            // Find matching pre-load entry by rva.
            std::uint32_t  preCalls = 0;
            std::uint64_t  preNs    = 0;
            std::uint64_t  preBytes = 0;
            for (const auto& pre : s_preLoadCallerSnap) {
                if (pre.rva == post.rva) {
                    preCalls = pre.count;
                    preNs    = pre.nsTotal;
                    preBytes = pre.bytesTotal;
                    break;
                }
            }
            if (post.count <= preCalls) continue;  // no new calls this load
            diffs.push_back({
                post.rva,
                post.count - preCalls,
                post.nsTotal    - preNs,
                post.bytesTotal - preBytes,
                post.srcVtable
            });
        }
        std::sort(diffs.begin(), diffs.end(),
                  [](const Diff& a, const Diff& b) { return a.bytes > b.bytes; });
        std::uint64_t totalDiffBytes = 0;
        for (const auto& d : diffs) totalDiffBytes += d.bytes;
        if (!diffs.empty()) {
            char hdr[160];
            std::snprintf(hdr, sizeof(hdr),
                "SAVE LOAD inflate-callers (top by bytes; total %.1f MB across %zu rvas):",
                totalDiffBytes / (1024.0 * 1024.0), diffs.size());
            LogInfo(hdr);
            int shown = 0;
            for (const auto& d : diffs) {
                if (shown++ >= 8) break;
                char m[256];
                if (d.srcVtable != 0) {
                    std::snprintf(m, sizeof(m),
                        "  caller[%d]: rva=0x%08X calls=%u %.1f MB %.1f ms srcVtbl=0x%016llX",
                        shown - 1, d.rva, d.calls,
                        d.bytes / (1024.0 * 1024.0), d.ns / 1.0e6,
                        (unsigned long long)d.srcVtable);
                } else {
                    std::snprintf(m, sizeof(m),
                        "  caller[%d]: rva=0x%08X calls=%u %.1f MB %.1f ms",
                        shown - 1, d.rva, d.calls,
                        d.bytes / (1024.0 * 1024.0), d.ns / 1.0e6);
                }
                LogInfo(m);
            }
        }
    }

    char fbuf[512];
    std::snprintf(fbuf, sizeof(fbuf),
        "FFC4 factory: calls=%llu rejStream=%llu rejSource=%llu "
        "servedMmap=%llu notReady=%llu cacheMiss=%llu servedCache=%llu",
        (unsigned long long)s_facCalls.load(std::memory_order_relaxed),
        (unsigned long long)s_facRejStream.load(std::memory_order_relaxed),
        (unsigned long long)s_facRejSource.load(std::memory_order_relaxed),
        (unsigned long long)s_facServedMmap.load(std::memory_order_relaxed),
        (unsigned long long)s_facNotReady.load(std::memory_order_relaxed),
        (unsigned long long)s_facCacheMiss.load(std::memory_order_relaxed),
        (unsigned long long)s_facServedCache.load(std::memory_order_relaxed));
    LogInfo(fbuf);

    char cfbuf[448];
    std::snprintf(cfbuf, sizeof(cfbuf),
        "FFC4 chunkfac: calls=%llu insert=%llu rejOk=%llu rejStream=%llu rejSrc=%llu "
        "swap=%llu swapReads=%llu (%.1f MB) swapDtors=%llu swapMiss=%llu rejVtbl=%llu",
        (unsigned long long)s_cfCalls.load(std::memory_order_relaxed),
        (unsigned long long)s_cfInsert.load(std::memory_order_relaxed),
        (unsigned long long)s_cfRejOk.load(std::memory_order_relaxed),
        (unsigned long long)s_cfRejStream.load(std::memory_order_relaxed),
        (unsigned long long)s_cfRejSrc.load(std::memory_order_relaxed),
        (unsigned long long)s_overrideInstalled.load(std::memory_order_relaxed),
        (unsigned long long)s_overrideDoReadCalls.load(std::memory_order_relaxed),
        s_overrideDoReadBytes.load(std::memory_order_relaxed) / (1024.0 * 1024.0),
        (unsigned long long)s_overrideDtors.load(std::memory_order_relaxed),
        (unsigned long long)s_overrideUnregisterMiss.load(std::memory_order_relaxed),
        (unsigned long long)s_overrideRejVtbl.load(std::memory_order_relaxed));
    LogInfo(cfbuf);

    char tbuf[640];
    std::snprintf(tbuf, sizeof(tbuf),
        "FFC4 tex: registered=%llu unresolved=%llu fetches=%llu "
        "bridgeSet=%llu consumed=%llu (%.1f MB) cacheMiss=%llu "
        "directServed=%llu (%.1f MB) waitBypassed=%llu "
        "captured=%llu (%.1f MB) capSkip=%llu fpHits=%llu fpServed=%llu (%.1f MB) sizeMismatch=%llu "
        "| serveGate=%llu serveFpMiss=%llu serveSzRej=%llu serveDcMiss=%llu capFpMiss=%llu",
        (unsigned long long)s_texRegistered.load(std::memory_order_relaxed),
        (unsigned long long)s_texUnresolved.load(std::memory_order_relaxed),
        (unsigned long long)s_texFetches.load(std::memory_order_relaxed),
        (unsigned long long)s_texBridgeSet.load(std::memory_order_relaxed),
        (unsigned long long)s_texBridgeConsumed.load(std::memory_order_relaxed),
        s_texBridgeConsumedBytes.load(std::memory_order_relaxed) / (1024.0 * 1024.0),
        (unsigned long long)s_texCacheMiss.load(std::memory_order_relaxed),
        (unsigned long long)s_texDirectServed.load(std::memory_order_relaxed),
        s_texDirectServedBytes.load(std::memory_order_relaxed) / (1024.0 * 1024.0),
        (unsigned long long)s_texDirectWaitBypassed.load(std::memory_order_relaxed),
        (unsigned long long)s_texCaptureRecorded.load(std::memory_order_relaxed),
        s_texCaptureRecordedBytes.load(std::memory_order_relaxed) / (1024.0 * 1024.0),
        (unsigned long long)s_texCaptureSkipped.load(std::memory_order_relaxed),
        (unsigned long long)s_texFingerprintHits.load(std::memory_order_relaxed),
        (unsigned long long)s_texFpServed.load(std::memory_order_relaxed),
        s_texFpServedBytes.load(std::memory_order_relaxed) / (1024.0 * 1024.0),
        (unsigned long long)s_texSizeMismatch.load(std::memory_order_relaxed),
        (unsigned long long)s_texServeGatePass.load(std::memory_order_relaxed),
        (unsigned long long)s_texServeFpMiss.load(std::memory_order_relaxed),
        (unsigned long long)s_texServeSizeReject.load(std::memory_order_relaxed),
        (unsigned long long)s_texServeDcacheMiss.load(std::memory_order_relaxed),
        (unsigned long long)s_texCaptureFpMiss.load(std::memory_order_relaxed));
    LogInfo(tbuf);

    char hbuf[640];
    std::snprintf(hbuf, sizeof(hbuf),
        "FFC4 HL: calls=%llu served=%llu (%.1f MB) partial=%llu (%llu chunks, %.1f MB)"
        " chunkMiss=%llu fallthrough=%llu"
        " [dis=%llu rdr=%llu shd=%llu pre=%llu src=%llu arc=%llu rdy=%llu rng=%llu nul=%llu]",
        (unsigned long long)s_hlCalls.load(std::memory_order_relaxed),
        (unsigned long long)s_hlServed.load(std::memory_order_relaxed),
        s_hlServedBytes.load(std::memory_order_relaxed) / (1024.0 * 1024.0),
        (unsigned long long)s_hlPartialServed.load(std::memory_order_relaxed),
        (unsigned long long)s_hlPartialChunks.load(std::memory_order_relaxed),
        s_hlPartialBytes.load(std::memory_order_relaxed) / (1024.0 * 1024.0),
        (unsigned long long)s_hlMissChunk.load(std::memory_order_relaxed),
        (unsigned long long)s_hlFallthrough.load(std::memory_order_relaxed),
        (unsigned long long)s_hlFtDisabled.load(std::memory_order_relaxed),
        (unsigned long long)s_hlFtReader.load(std::memory_order_relaxed),
        (unsigned long long)s_hlFtShadow.load(std::memory_order_relaxed),
        (unsigned long long)s_hlFtPreload.load(std::memory_order_relaxed),
        (unsigned long long)s_hlFtNoSource.load(std::memory_order_relaxed),
        (unsigned long long)s_hlFtNoArchive.load(std::memory_order_relaxed),
        (unsigned long long)s_hlFtNotReady.load(std::memory_order_relaxed),
        (unsigned long long)s_hlFtRange.load(std::memory_order_relaxed),
        (unsigned long long)s_hlFtNullPtrs.load(std::memory_order_relaxed));
    LogInfo(hbuf);

    const auto monE0 = s_monE0Calls.load(std::memory_order_relaxed);
    const auto monF0 = s_monF0Calls.load(std::memory_order_relaxed);
    if (monE0 || monF0) {
        char mbuf[160];
        std::snprintf(mbuf, sizeof(mbuf),
            "FFC4 texmon: E0=%llu F0=%llu (AE completion dispatchers)",
            (unsigned long long)monE0, (unsigned long long)monF0);
        LogInfo(mbuf);
    }

    s_preLoadTick = 0;
    s_saveLoadActive.store(false, std::memory_order_release);

    // First real save-load completed → enter "gameplay phase". Cache
    // capture + serve activate now. Before this, only mmap was active —
    // cache subsystem was dormant during startup so initAllForms ran
    // through pure mmap path without per-call cache overhead.
    if (!s_gameplayPhase.load(std::memory_order_acquire))
    {
        s_gameplayPhase.store(true, std::memory_order_release);
        LogInfo("FFC4: gameplay phase entered — cache capture + serve activated");
    }
    return loadSec;
}

// ── Gameplay measurement ────────────────────────────────────────────────────

static Snapshot s_gameplaySnap{};
static std::int64_t s_gameplayStartTick = 0;
static std::uint64_t s_gameplayZlibOutStart = 0;
// Texture fp-serve counter snapshot — taken at gameplay start so
// LogGameplaySummary can emit a gameplay-scoped delta (the stats thread backs
// off to minute+ intervals after save-load so the raw "FFC4 tex:" line doesn't
// re-emit during a 2-minute gameplay window).
static std::uint64_t s_gpTexGatePassStart    = 0;
static std::uint64_t s_gpTexFpServedStart    = 0;
static std::uint64_t s_gpTexFpBytesStart     = 0;
static std::uint64_t s_gpTexFpMissStart      = 0;
static std::uint64_t s_gpTexSizeRejectStart  = 0;
static std::uint64_t s_gpTexDcacheMissStart  = 0;

void SnapshotGameplayStart()
{
    LARGE_INTEGER now; QueryPerformanceCounter(&now);
    s_gameplayStartTick = now.QuadPart;
    s_gameplaySnap = TakeSnapshot();
    s_gameplayZlibOutStart = s_inflateZlibBytesOut.load(std::memory_order_relaxed);
    s_gpTexGatePassStart   = s_texServeGatePass.load(std::memory_order_relaxed);
    s_gpTexFpServedStart   = s_texFpServed.load(std::memory_order_relaxed);
    s_gpTexFpBytesStart    = s_texFpServedBytes.load(std::memory_order_relaxed);
    s_gpTexFpMissStart     = s_texServeFpMiss.load(std::memory_order_relaxed);
    s_gpTexSizeRejectStart = s_texServeSizeReject.load(std::memory_order_relaxed);
    s_gpTexDcacheMissStart = s_texServeDcacheMiss.load(std::memory_order_relaxed);
    s_fpMissDumpSeq.store(0, std::memory_order_relaxed);
    {
        std::lock_guard lk(s_inflateCallerMtx);
        for (auto& s : s_inflateCallerSamples) {
            s.rva = 0; s.count = 0;
            s.nsTotal = 0; s.bytesTotal = 0; s.srcVtable = 0;
        }
    }
    s_gameplayActive.store(true, std::memory_order_release);
    LogInfo("FFC4: Gameplay measurement started");
}

void LogGameplaySummary()
{
    if (s_gameplayStartTick == 0) return;
    LARGE_INTEGER now; QueryPerformanceCounter(&now);
    double elapsed = TicksToSec(now.QuadPart - s_gameplayStartTick);
    if (elapsed < 1.0) return;

    auto post = TakeSnapshot();
    auto dMmapB   = post.mmapBytes - s_gameplaySnap.mmapBytes;
    auto dFBB     = post.fallbackBytes - s_gameplaySnap.fallbackBytes;
    auto dCacheB  = post.cacheBytes - s_gameplaySnap.cacheBytes;
    auto dZlibOut = s_inflateZlibBytesOut.load(std::memory_order_relaxed) - s_gameplayZlibOutStart;

    double deliveredBytes = static_cast<double>(dMmapB + dCacheB + dZlibOut);
    double deliveredMB    = deliveredBytes / (1024.0 * 1024.0);
    double throughput     = deliveredMB / elapsed;
    double pctMmap  = (deliveredBytes > 0) ? dMmapB    / deliveredBytes * 100 : 0;
    double pctCache = (deliveredBytes > 0) ? dCacheB   / deliveredBytes * 100 : 0;
    double pctZlib  = (deliveredBytes > 0) ? dZlibOut  / deliveredBytes * 100 : 0;

    char buf[512];
    std::snprintf(buf, sizeof(buf),
        "GAMEPLAY: %.1fs | %.1f MB delivered (%.2f MB/s) | "
        "mmap %.1f%% | cache %.1f%% | zlib %.1f%% | fb %.1f MB",
        elapsed, deliveredMB, throughput,
        pctMmap, pctCache, pctZlib,
        dFBB / (1024.0 * 1024.0));
    LogInfo(buf);

    // Texture fp-serve gameplay delta. Decomposes BSTextureStreamer inflate
    // bucket (rva 0x017CB1B2) into its serve outcomes: gated calls that hit
    // the fp-serve path, chunks served from decomp cache, and the three miss
    // categories (fp not in index / size reject / dcache empty).
    auto dTexGate   = s_texServeGatePass.load(std::memory_order_relaxed)    - s_gpTexGatePassStart;
    auto dTexServed = s_texFpServed.load(std::memory_order_relaxed)         - s_gpTexFpServedStart;
    auto dTexBytes  = s_texFpServedBytes.load(std::memory_order_relaxed)    - s_gpTexFpBytesStart;
    auto dTexFpM    = s_texServeFpMiss.load(std::memory_order_relaxed)      - s_gpTexFpMissStart;
    auto dTexSzR    = s_texServeSizeReject.load(std::memory_order_relaxed)  - s_gpTexSizeRejectStart;
    auto dTexDcM    = s_texServeDcacheMiss.load(std::memory_order_relaxed)  - s_gpTexDcacheMissStart;
    char tbuf[384];
    std::snprintf(tbuf, sizeof(tbuf),
        "GAMEPLAY tex: gate=%llu served=%llu (%.1f MB) fpMiss=%llu szRej=%llu dcMiss=%llu",
        (unsigned long long)dTexGate,
        (unsigned long long)dTexServed, dTexBytes / (1024.0 * 1024.0),
        (unsigned long long)dTexFpM,
        (unsigned long long)dTexSzR,
        (unsigned long long)dTexDcM);
    LogInfo(tbuf);

    // AsyncReaderStream funnel — lets us distinguish between (a) hook not
    // firing, (b) hook fires but nothing is compressed, (c) compressed but
    // cache has no entry, (d) bridge set but inflate doesn't consume.
    auto asyncCalls = s_asyncDoReadCalls.load(std::memory_order_relaxed);
    auto asyncBytes = s_asyncDoReadBytes.load(std::memory_order_relaxed);
    auto asyncComp  = s_asyncCompressedCalls.load(std::memory_order_relaxed);
    auto asyncHit   = s_asyncBridgeHit.load(std::memory_order_relaxed);
    auto asyncMiss  = s_asyncBridgeMiss.load(std::memory_order_relaxed);
    char abuf[384];
    std::snprintf(abuf, sizeof(abuf),
        "GAMEPLAY async: calls=%llu bytes=%.1f MB compressed=%llu bridgeHit=%llu bridgeMiss=%llu",
        (unsigned long long)asyncCalls,
        asyncBytes / (1024.0 * 1024.0),
        (unsigned long long)asyncComp,
        (unsigned long long)asyncHit,
        (unsigned long long)asyncMiss);
    LogInfo(abuf);

    // Dump top unbridged-inflate callers — sorted desc by ns (CPU cost is the
    // metric that drives caching-vs-ignore decisions). Full per-call accounting
    // now (no sampling), so calls/MB/ms are exact.
    InflateCallerSample snap[kInflateCallerSamples];
    {
        std::lock_guard lk(s_inflateCallerMtx);
        std::copy(std::begin(s_inflateCallerSamples),
                  std::end(s_inflateCallerSamples), snap);
    }
    std::sort(std::begin(snap), std::end(snap),
              [](const InflateCallerSample& a, const InflateCallerSample& b) {
                  return a.nsTotal > b.nsTotal;
              });
    char cbuf[192];
    int emitted = 0;
    for (const auto& s : snap) {
        if (s.count == 0) break;
        double ms = s.nsTotal / 1.0e6;
        double mb = s.bytesTotal / (1024.0 * 1024.0);
        if (s.srcVtable != 0) {
            std::snprintf(cbuf, sizeof(cbuf),
                "GAMEPLAY inflate caller[%d]: rva=0x%08X calls=%u %.1f MB %.1f ms srcVtbl=0x%016llX",
                emitted, s.rva, s.count, mb, ms,
                (unsigned long long)s.srcVtable);
        } else {
            std::snprintf(cbuf, sizeof(cbuf),
                "GAMEPLAY inflate caller[%d]: rva=0x%08X calls=%u %.1f MB %.1f ms",
                emitted, s.rva, s.count, mb, ms);
        }
        LogInfo(cbuf);
        if (++emitted >= 8) break;  // top 8 is plenty
    }
}

// ── FreezeSourceCache with phase breakdown ───────────────────────────────────

void FreezeSourceCache()
{
    s_cacheFrozen.store(true, std::memory_order_release);

    // Defer detailed logging to the stats thread to avoid calling into spdlog
    // while the game's string/memory systems are still initializing.
    // BSstristr crashes if called too early (game's string pool not ready).
    OutputDebugStringA("FFC4: FreezeSourceCache called — cache frozen\n");
}

// ═════════════════════════════════════════════════════════════════════════════
// Residency sampler — QueryWorkingSetEx over a stride-sampled subset of pages
// ─────────────────────────────────────────────────────────────────────────────
// Returns (sampledPages, residentPages). For mmap'd ranges, a page is
// "resident" when its physical frame is currently in the process's working
// set — i.e. a touch won't hard-fault. Sampling keeps the query buffer small
// (<=kMaxSamplesPerRange pages * sizeof(WSEX entry)) regardless of range size.

static constexpr std::uint32_t kPageSize = 4096;
static constexpr std::uint32_t kMaxSamplesPerRange = 4096;  // 128 KB query buffer

struct ResidencySample {
    std::uint32_t sampled   = 0;
    std::uint32_t resident  = 0;
};

static ResidencySample SampleResidency(const std::uint8_t* base, std::uint64_t size)
{
    ResidencySample out{};
    if (!base || size < kPageSize) return out;

    const std::uint64_t totalPages = (size + kPageSize - 1) / kPageSize;
    const std::uint32_t samples    = static_cast<std::uint32_t>(
        totalPages <= kMaxSamplesPerRange ? totalPages : kMaxSamplesPerRange);
    const std::uint64_t stride     = totalPages / samples;  // >=1

    std::vector<PSAPI_WORKING_SET_EX_INFORMATION> buf(samples);
    for (std::uint32_t i = 0; i < samples; ++i) {
        buf[i].VirtualAddress = const_cast<std::uint8_t*>(base + (i * stride) * kPageSize);
    }

    if (!QueryWorkingSetEx(GetCurrentProcess(), buf.data(),
                           static_cast<DWORD>(samples * sizeof(buf[0])))) {
        return out;
    }

    out.sampled = samples;
    for (std::uint32_t i = 0; i < samples; ++i) {
        if (buf[i].VirtualAttributes.Valid) ++out.resident;
    }
    return out;
}

// ═════════════════════════════════════════════════════════════════════════════
// Stats thread
// ═════════════════════════════════════════════════════════════════════════════

static void StatsThreadFn()
{
    auto interval = std::chrono::milliseconds(
        Settings::iStatsIntervalMs > 0 ? Settings::iStatsIntervalMs : 5000);

    std::uint64_t prevMmap = 0, prevFallback = 0, prevCache = 0;
    std::uint64_t prevMmapB = 0, prevFallbackB = 0, prevCacheB = 0, prevZlibOutB = 0;
    DWORD         prevPageFaults = 0;

    int intervals[] = { 1, 1, 1, 1, 1, 1, 3, 3, 12 };
    int phase = 0;

    while (!s_shutdownRequested.load(std::memory_order_relaxed)) {
        int mult = (phase < 9) ? intervals[phase] : 12;
        ++phase;
        // Sleep in 1-second increments for shutdown responsiveness
        for (int s = 0; s < mult; ++s) {
            if (s_shutdownRequested.load(std::memory_order_relaxed))
                return;
            std::this_thread::sleep_for(interval);
        }

        auto curMmap     = s_mmapReads.load(std::memory_order_relaxed);
        auto curFallback = s_fallbackReads.load(std::memory_order_relaxed);
        auto curCache    = s_cacheServed.load(std::memory_order_relaxed);
        auto curMmapB    = s_mmapBytes.load(std::memory_order_relaxed);
        auto curFallbackB= s_fallbackBytes.load(std::memory_order_relaxed);
        auto curCacheB   = s_cacheServedBytes.load(std::memory_order_relaxed);

        auto dMmap    = curMmap - prevMmap;
        auto dFallback = curFallback - prevFallback;
        auto dCache   = curCache - prevCache;

        if (dMmap == 0 && dFallback == 0 && dCache == 0 && phase > 9) continue;

        const char* tag = Settings::bBaselineMode ? "BASELINE" : "MMAP";
        auto curZlibOutB = s_inflateZlibBytesOut.load(std::memory_order_relaxed);
        double dDeliveredMB = ((curMmapB - prevMmapB) + (curCacheB - prevCacheB) + (curZlibOutB - prevZlibOutB)) / (1024.0 * 1024.0);
        double elapsedSec = static_cast<double>(mult * Settings::iStatsIntervalMs) / 1000.0;
        double throughput = (elapsedSec > 0.001) ? dDeliveredMB / elapsedSec : 0.0;

        char buf[512];
        std::snprintf(buf, sizeof(buf),
            "[%s] +%llu mmap (%.1f MB), +%llu cache (%.1f MB), +%.1f MB zlib, +%llu fb (%.1f MB) | %.1f MB/s",
            tag,
            dMmap, (curMmapB - prevMmapB) / (1024.0 * 1024.0),
            dCache, (curCacheB - prevCacheB) / (1024.0 * 1024.0),
            (curZlibOutB - prevZlibOutB) / (1024.0 * 1024.0),
            dFallback, (curFallbackB - prevFallbackB) / (1024.0 * 1024.0),
            throughput);
        LogInfo(buf);

        // Cumulative inflate timing — lets us compare cache-on vs cache-off runs.
        auto ic    = s_inflateCalls.load(std::memory_order_relaxed);
        auto izNs  = s_inflateZlibNs.load(std::memory_order_relaxed);
        auto izIn  = s_inflateZlibBytesIn.load(std::memory_order_relaxed);
        auto izOut = s_inflateZlibBytesOut.load(std::memory_order_relaxed);
        auto isNs  = s_inflateServeNs.load(std::memory_order_relaxed);
        double zlibMBps = (izNs > 0)
            ? (izOut / (1024.0 * 1024.0)) / (izNs / 1e9) : 0.0;
        char ibuf[512];
        std::snprintf(ibuf, sizeof(ibuf),
            "FFC4 INFLATE: calls=%llu zlib %.1fms (in %.1f MB, out %.1f MB, %.1f MB/s) | serve %.1fms",
            (unsigned long long)ic,
            izNs / 1e6, izIn / (1024.0 * 1024.0), izOut / (1024.0 * 1024.0), zlibMBps,
            isNs / 1e6);
        LogInfo(ibuf);

        // Per-call breakdown: total HookedInflate time minus zlib minus serve
        // = FFC4 overhead. Express as ns per call so cache-on/cache-off configs
        // can be compared directly even at different call counts.
        auto itNs = s_inflateTotalNs.load(std::memory_order_relaxed);
        if (ic > 0) {
            std::uint64_t overheadNs = (itNs > izNs + isNs) ? (itNs - izNs - isNs) : 0;
            char obuf[256];
            std::snprintf(obuf, sizeof(obuf),
                "FFC4 OVERHEAD: total %.1fms | per-call: total %.2fus zlib %.2fus serve %.2fus overhead %.2fus",
                itNs / 1e6,
                itNs / (double)ic / 1e3,
                izNs / (double)ic / 1e3,
                isNs / (double)ic / 1e3,
                overheadNs / (double)ic / 1e3);
            LogInfo(obuf);
        }

        // Slot-12 async submit stats (AE only, only when FUN_1416AEFE0 hook installed).
        if (s_origLooseAsyncSubmit) {
            auto lc = s_looseSubmitCalls.load(std::memory_order_relaxed);
            auto ls = s_looseSubmitServed.load(std::memory_order_relaxed);
            auto lb = s_looseSubmitBytes.load(std::memory_order_relaxed);
            if (lc > 0) {
                char cbuf[256];
                std::snprintf(cbuf, sizeof(cbuf),
                    "FFC4 SUBMIT12: calls=%llu served=%llu (%.1f%%) bytes=%.1f MB",
                    (unsigned long long)lc,
                    (unsigned long long)ls,
                    lc > 0 ? 100.0 * ls / lc : 0.0,
                    lb / (1024.0 * 1024.0));
                LogInfo(cbuf);
            }
        }

        // AsyncReaderStream slot-6 DoStartRead stats (AE only, FUN_1416A2350).
        if (s_origAsyncStartRead) {
            auto ac = s_asyncStartCalls.load(std::memory_order_relaxed);
            auto as = s_asyncStartServed.load(std::memory_order_relaxed);
            auto ab = s_asyncStartBytes.load(std::memory_order_relaxed);
            if (ac > 0) {
                char cbuf[256];
                std::snprintf(cbuf, sizeof(cbuf),
                    "FFC4 ASYNC6: calls=%llu served=%llu (%.1f%%) bytes=%.1f MB",
                    (unsigned long long)ac,
                    (unsigned long long)as,
                    ac > 0 ? 100.0 * as / ac : 0.0,
                    ab / (1024.0 * 1024.0));
                LogInfo(cbuf);
            }
        }

        // ZSCRAP probe (AE only, only when probe installed).
        if (s_origZscrapAlloc) {
            auto zc = s_zscrapCalls.load(std::memory_order_relaxed);
            auto zb = s_zscrapBytes.load(std::memory_order_relaxed);
            char zbuf[160];
            std::snprintf(zbuf, sizeof(zbuf),
                "FFC4 ZSCRAP: calls=%llu, alloc=%.1f MB",
                (unsigned long long)zc, zb / (1024.0 * 1024.0));
            LogInfo(zbuf);
        }

        // MmapStream::DoRead size histogram + per-bucket avg ns.
        // Only logged when ANY bucket has calls — saves noise in cache-only runs.
        std::uint64_t totalMmapCalls = 0;
        for (int b = 0; b < BA2::kMmapHistBuckets; ++b)
            totalMmapCalls += BA2::g_mmapDoReadCalls[b].load(std::memory_order_relaxed);
        if (totalMmapCalls > 0) {
            static constexpr const char* bucketName[BA2::kMmapHistBuckets] = {
                "0B", "1-16", "17-64", "65-256", "257-1k",
                "1k-4k", "4k-16k", "16k-64k", "64k-256k", "256k-1M", ">1M"
            };
            char hbuf[512];
            int off = std::snprintf(hbuf, sizeof(hbuf),
                "FFC4 MMAP_DOREAD total=%llu | ", (unsigned long long)totalMmapCalls);
            for (int b = 0; b < BA2::kMmapHistBuckets && off < (int)sizeof(hbuf) - 1; ++b) {
                auto c = BA2::g_mmapDoReadCalls[b].load(std::memory_order_relaxed);
                auto ns = BA2::g_mmapDoReadNs[b].load(std::memory_order_relaxed);
                if (c == 0) continue;
                off += std::snprintf(hbuf + off, sizeof(hbuf) - off,
                    "%s=%llu@%.2fus ",
                    bucketName[b], (unsigned long long)c, ns / (double)c / 1e3);
            }
            LogInfo(hbuf);
        }

        // Wall-clock window vs CPU sum (#2). Reset window edges so the next
        // line reflects only the upcoming interval.
        auto firstQ = s_inflateFirstQpc.exchange(0, std::memory_order_relaxed);
        auto lastQ  = s_inflateLastQpc.exchange(0, std::memory_order_relaxed);
        if (firstQ > 0 && lastQ > firstQ) {
            double wallMs = static_cast<double>(lastQ - firstQ) * 1000.0
                          / static_cast<double>(s_qpcFreq);
            // Skip windows shorter than 10ms — these happen when the stats
            // interval lands on the tail of a completed inflate burst, so
            // first/last cover only a sliver of the real activity window
            // and the ratio is a meaningless outlier (e.g. 458× with 0.1ms).
            if (wallMs >= 10.0) {
                double cpuMs  = (izNs + isNs) / 1e6;
                double ratio  = cpuMs / wallMs;
                char wbuf[256];
                std::snprintf(wbuf, sizeof(wbuf),
                    "FFC4 INFLATE WALL: window=%.1fms cpu=%.1fms ratio=%.2f "
                    "(<1=I/O bound, ~1=single-thread CPU, >1=parallel)",
                    wallMs, cpuMs, ratio);
                LogInfo(wbuf);
            }
        }

        // Dst-pointer sample dump (#1) — emit once when we have a full ring,
        // then disable. The pointers reveal where unpacked data lands per
        // thread, which is the missing piece for AE HL serve.
        if (s_inflateDstEnabled.load(std::memory_order_relaxed)) {
            auto head = s_inflateDstHead.load(std::memory_order_relaxed);
            if (head >= kInflateDstSamples) {
                LogInfo("FFC4 INFLATE DST samples (tid → next_out, avail_out):");
                for (std::size_t i = 0; i < kInflateDstSamples; ++i) {
                    auto& s = s_inflateDstSamples[i];
                    char dbuf[160];
                    std::snprintf(dbuf, sizeof(dbuf),
                        "  [%2zu] tid=%5u  next_out=%p  avail_out=%u",
                        i, s.tid, s.next_out, s.avail_out);
                    LogInfo(dbuf);
                }
                s_inflateDstEnabled.store(false, std::memory_order_relaxed);
            }
        }

        // Per-mipchain timing — direct comparator for in-game texture load speed.
        // served = our cache-hit path (entry-to-return), fallthrough = stock path.
        auto hlS   = s_hlServed.load(std::memory_order_relaxed);
        auto hlSns = s_hlServedNs.load(std::memory_order_relaxed);
        auto hlSch = s_hlChunksServed.load(std::memory_order_relaxed);
        auto hlF   = s_hlFallthrough.load(std::memory_order_relaxed);
        auto hlFns = s_hlFtNs.load(std::memory_order_relaxed);
        double servedAvgMs = (hlS > 0) ? (hlSns / 1e6) / hlS : 0.0;
        double ftAvgMs     = (hlF > 0) ? (hlFns / 1e6) / hlF : 0.0;
        char hbuf2[512];
        std::snprintf(hbuf2, sizeof(hbuf2),
            "FFC4 HL TIMING: served=%llu avg %.3fms (%llu chunks) | fallthrough=%llu avg %.3fms",
            (unsigned long long)hlS, servedAvgMs, (unsigned long long)hlSch,
            (unsigned long long)hlF, ftAvgMs);
        LogInfo(hbuf2);

        // Process-wide memory + mmap residency — answers "is the cache warm?"
        // and "are we still hard-faulting pages during gameplay?". Page-fault
        // count from GetProcessMemoryInfo includes both soft and hard faults
        // (Windows doesn't split them at process level); big deltas during
        // gameplay usually mean disk-backed reads that dodged our serve paths.
        PROCESS_MEMORY_COUNTERS pmc{};
        pmc.cb = sizeof(pmc);
        if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
            DWORD dFaults = pmc.PageFaultCount - prevPageFaults;
            prevPageFaults = pmc.PageFaultCount;

            std::uint64_t ba2Sampled = 0, ba2Resident = 0, ba2Bytes = 0;
            const auto& archives = BA2::MemoryMapManager::GetSingleton().GetArchives();
            for (const auto& arc : archives) {
                if (!arc.IsOpen()) continue;
                auto s = SampleResidency(arc.GetBase(), arc.GetFileSize());
                ba2Sampled  += s.sampled;
                ba2Resident += s.resident;
                ba2Bytes    += arc.GetFileSize();
            }
            double ba2TotalMB    = ba2Bytes / (1024.0 * 1024.0);
            double ba2ResidentMB = ba2Sampled > 0
                ? ba2TotalMB * (static_cast<double>(ba2Resident) / ba2Sampled)
                : 0.0;
            double ba2Pct = ba2Sampled > 0
                ? 100.0 * ba2Resident / ba2Sampled : 0.0;

            std::uint64_t cacheSampled = 0, cacheResident = 0, cacheBytes = 0;
            auto views = BA2::DecompCache::GetSingleton().GetMappedViews();
            for (const auto& [vbase, vsize] : views) {
                auto s = SampleResidency(vbase, vsize);
                cacheSampled  += s.sampled;
                cacheResident += s.resident;
                cacheBytes    += vsize;
            }
            double cacheTotalMB    = cacheBytes / (1024.0 * 1024.0);
            double cacheResidentMB = cacheSampled > 0
                ? cacheTotalMB * (static_cast<double>(cacheResident) / cacheSampled)
                : 0.0;
            double cachePct = cacheSampled > 0
                ? 100.0 * cacheResident / cacheSampled : 0.0;

            double wsMB = pmc.WorkingSetSize / (1024.0 * 1024.0);
            double peakMB = pmc.PeakWorkingSetSize / (1024.0 * 1024.0);

            char mbuf[384];
            std::snprintf(mbuf, sizeof(mbuf),
                "FFC4 MEM: ws=%.0f MB (peak %.0f) +%lu faults | BA2 %.0f/%.0f MB (%.0f%%) | cache %.0f/%.0f MB (%.0f%%)",
                wsMB, peakMB, static_cast<unsigned long>(dFaults),
                ba2ResidentMB, ba2TotalMB, ba2Pct,
                cacheResidentMB, cacheTotalMB, cachePct);
            LogInfo(mbuf);
        }

        // Emit cumulative GAMEPLAY summary after each stats interval once the
        // post-save-load window has been opened. Makes the metric available
        // even when the game is force-terminated (atexit doesn't fire).
        LogGameplaySummary();

        prevMmap = curMmap; prevFallback = curFallback; prevCache = curCache;
        prevMmapB = curMmapB; prevFallbackB = curFallbackB; prevCacheB = curCacheB; prevZlibOutB = curZlibOutB;
    }
}

void StartStatsThread()
{
    if (!Settings::bEnableStats) return;
    std::thread(StatsThreadFn).detach();
    LogInfo("FFC4: Stats thread started");
}

// ═════════════════════════════════════════════════════════════════════════════
// ReaderStream vtable identity
//
// s_readerStreamVtbl is the address of the one vtable we write into at install
// time (REL::ID(218182) vtable[6] = HookedDoRead). But many reader-stream
// classes exist (GNRL/DX10, compressed/uncompressed, wrappers) with their own
// vtables. A strict pointer-equality check on the stream's vtable misses all
// of them.
//
// The correct test for "is this a stream whose reads we are intercepting" is:
// does its vtable[6] point at our HookedDoRead? If yes, we can safely replace
// the stream with an MmapStream (which has its own vtable) and downstream
// reads skip the hook entirely — pure memcpy.
// ═════════════════════════════════════════════════════════════════════════════

using DoRead_t = RE::BSResource::ErrorCode(*)(void*, void*, std::uint64_t, std::uint64_t&);
static std::uintptr_t s_readerStreamVtbl       = 0;
static std::uintptr_t s_asyncReaderStreamVtbl  = 0;
static DoRead_t       s_originalDoRead         = nullptr;
static DoRead_t       s_originalAsyncDoRead    = nullptr;

static RE::BSResource::ErrorCode HookedDoRead(
    void*           a_this,
    void*           a_buffer,
    std::uint64_t   a_toRead,
    std::uint64_t&  a_read);

// Strict pointer-equality check against the synchronous ReaderStream vtable.
// Factory-swap paths (HookedFactory / chunk-factory) rely on this being narrow:
// swapping the vtable on an AsyncReaderStream would break async read semantics,
// so even though AsyncReaderStream shares slot[6] we exclude it here. The
// AsyncReaderStream intercept is direct (vtable dispatch into HookedDoRead);
// it does not go through any factory-swap decision.
static bool IsArchiveReaderStream(const void* a_stream)
{
    if (!a_stream) return false;
    auto vtbl = *reinterpret_cast<const std::uintptr_t*>(a_stream);
    return vtbl == s_readerStreamVtbl;
}

// Pick the correct original DoRead for HookedDoRead's fall-through call. Both
// vtables land in the same HookedDoRead (slot[6]), but each has its own
// upstream implementation — calling the wrong one would corrupt stream state.
static inline DoRead_t PickOriginalDoRead(const void* a_stream)
{
    auto vtbl = *reinterpret_cast<const std::uintptr_t*>(a_stream);
    if (s_asyncReaderStreamVtbl != 0 && vtbl == s_asyncReaderStreamVtbl)
        return s_originalAsyncDoRead;
    return s_originalDoRead;
}

// ── Thread-ID bridge: DoRead sets these, inflate hook reads them ────────
// Can't use TLS because inflate may run on a different thread than DoRead.
// Use a larger atomic array keyed by thread ID to minimize collisions.
// Include a sequence number to detect stale entries from collisions.
struct InflateBridge {
    std::atomic<std::uint32_t>       threadId{ 0 };
    std::atomic<std::uint32_t>       sequence{ 0 };  // incremented on each set
    std::atomic<const std::uint8_t*> data{ nullptr };
    std::atomic<std::uint32_t>       size{ 0 };
    std::atomic<bool>                fromTex{ false };  // set by texture path
    // Non-atomic owner — only accessed by the thread that owns this slot.
    // Typed as shared_ptr<void> so the same field holds either a MappedView
    // (mmap-backed cache hits) or a shared pending buffer (not-yet-flushed).
    std::shared_ptr<void>            owner;
};
constexpr int kBridgeSlots = 256;  // Increased from 64 to reduce collisions
constexpr int kBridgeMask  = kBridgeSlots - 1;
static InflateBridge s_inflateBridge[kBridgeSlots];

struct BridgeEntry {
    const std::uint8_t*    data;
    std::uint32_t          size;
    bool                   fromTex;
    std::shared_ptr<void>  owner;  // keep backing storage (view or pending buf) alive
};
static void BridgeSet(const BA2::LookupResult& lr, bool fromTex = false) {
    auto tid = GetCurrentThreadId();
    auto slot = tid & kBridgeMask;
    auto* bridge = &s_inflateBridge[slot];
    // Increment sequence to invalidate any pending readers
    auto seq = bridge->sequence.fetch_add(1, std::memory_order_release) + 1;
    bridge->data.store(lr.data, std::memory_order_relaxed);
    bridge->size.store(lr.size, std::memory_order_relaxed);
    bridge->fromTex.store(fromTex, std::memory_order_relaxed);
    bridge->owner = lr.owner;  // keeps cache view alive during inflate
    bridge->threadId.store(tid, std::memory_order_release);
    // Return sequence for BridgeClear to match
    bridge->sequence.store(seq, std::memory_order_release);
}
static bool BridgeGet(std::uint32_t expectedSeq, BridgeEntry& out) {
    auto tid = GetCurrentThreadId();
    auto slot = tid & kBridgeMask;
    auto* bridge = &s_inflateBridge[slot];
    if (bridge->threadId.load(std::memory_order_acquire) == tid &&
        bridge->sequence.load(std::memory_order_acquire) == expectedSeq) {
        out.data    = bridge->data.load(std::memory_order_relaxed);
        out.size    = bridge->size.load(std::memory_order_relaxed);
        out.fromTex = bridge->fromTex.load(std::memory_order_relaxed);
        out.owner   = bridge->owner;  // extend view lifetime past bridge slot reuse
        return out.data != nullptr && out.size > 0;
    }
    return false;
}
static void BridgeClear(std::uint32_t expectedSeq) {
    auto tid = GetCurrentThreadId();
    auto slot = tid & kBridgeMask;
    auto* bridge = &s_inflateBridge[slot];
    // Only clear if sequence hasn't changed (prevents clearing another thread's data)
    if (bridge->sequence.load(std::memory_order_acquire) == expectedSeq) {
        bridge->data.store(nullptr, std::memory_order_relaxed);
        bridge->size.store(0, std::memory_order_relaxed);
        bridge->owner.reset();
        bridge->threadId.store(0, std::memory_order_release);
    }
}

// ── inflate hook — serves cached data at the zlib level ─────────────────
// Compatible with FastDecompress: our Detours hook chains AFTER theirs.
// When DoRead sets the bridge, our inflate hook copies cached data
// to strm->next_out and returns Z_STREAM_END — no decompression at all.
//
// z_stream layout (zlib 1.2.7 on Windows x64):
//   Offset  Size  Field
//   0x00    8     next_in   (const unsigned char*)
//   0x08    4     avail_in  (unsigned int)
//   0x0C    4     total_in  (unsigned long)
//   0x10    8     next_out  (unsigned char*)
//   0x18    4     avail_out (unsigned int)
//   0x1C    4     total_out (unsigned long)
// These offsets are from the Windows SDK zlib 1.2.7 shipped with Fallout 4.
// If the game updates to a different zlib version, these MUST be re-verified.
// Verified against: zlib 1.2.7 (Windows 10/11 system zlib, same as FO4 NG)
struct z_stream_compat {
    std::uint8_t*  next_in;      // 0x00
    std::uint32_t  avail_in;     // 0x08
    std::uint32_t  total_in;     // 0x0C
    std::uint8_t*  next_out;     // 0x10
    std::uint32_t  avail_out;    // 0x18
    std::uint32_t  total_out;    // 0x1C
};

// ── Passive texture capture via compressed-data fingerprint index ────────
// At Z_STREAM_END in HookedInflate, we identify which archive chunk was just
// decompressed by hashing the first kFpHashLen (64) bytes of compressed input
// against a pre-built index of all DX10 archive chunks. On match, we decompress
// the chunk ourselves from the mmap'd archive data (one-time cost per chunk)
// instead of reading from the inflate output buffer, which may be a small
// scratch buffer that was recycled during incremental inflate calls.
//
// The index is built lazily on first texture-worker Z_STREAM_END via
// std::call_once. Two fingerprints are stored per chunk: one at the raw offset
// and one at offset+1, because BA2 compressed data may have a zlib prefix byte
// (0x78) that the engine strips before calling inflate.

struct CompFingerprintEntry {
    const BA2::MappedArchive* archive;
    std::uint32_t             fileOffset;
    std::uint32_t             packedSize;
    std::uint32_t             uncompSize;
};

// FNV-1a 64 over up to kFpHashLen compressed bytes. zlib output starts with a
// near-fixed 2-byte header, so an 8-byte prefix carries ~6 bytes of entropy —
// severe collisions at 70k entries. 64 bytes of deflate-stream data hits
// ~64 bits of entropy; birthday collision prob at 70k entries is ~5e-10.
static constexpr std::size_t kFpHashLen = 64;

static std::uint64_t FpHash(const void* data, std::size_t len)
{
    const auto*   p = static_cast<const std::uint8_t*>(data);
    std::uint64_t h = 0xcbf29ce484222325ULL;
    for (std::size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

static std::unordered_map<std::uint64_t, CompFingerprintEntry> s_compFingerprint;
// Non-blocking ready flag. Inflate hot path MUST NOT call the builder via
// call_once — during save load, 20+ IO worker threads pile into inflate in
// parallel, and the first one to hit a lazy builder stalls all the others
// on the once_flag while it enumerates ~139k DX10 entries over cold-mapped
// BA2s. That stall was the root cause of the tex-capture-on save-load hang
// (Addictol-swallowed → "infinite load"). Instead we build eagerly from a
// background thread at OnModuleLoad; the hot path just checks ready and
// falls through (no serve, no capture) until the flag flips.
static std::atomic<bool> s_compFingerprintReady{ false };
static std::atomic<bool> s_compFingerprintBuilding{ false };

static void BuildCompFingerprintIndex()
{
    const auto& archives = BA2::MemoryMapManager::GetSingleton().GetArchives();
    std::size_t indexed = 0;
    std::size_t collisions = 0;

    // Index every compressed entry in every archive — DX10 AND GNRL. The
    // serve gate (retRVA == BSTextureStreamer::Inflate+0x12) is narrow enough
    // that indexing GNRL chunks doesn't cause cross-caller false serves; it
    // just means GNRL texture chunks in mod atlases / archives generated with
    // Archive2 --format=GNRL become serveable. Cut fpMiss from 7.9% → ~0%.
    for (const auto& archive : archives) {
        if (!archive.IsOpen()) continue;

        std::vector<BA2::BA2Entry> entries;
        archive.EnumerateEntries(entries);

        for (const auto& entry : entries) {
            if (!entry.isCompressed || entry.packedSize < kFpHashLen) continue;

            auto fp0 = archive.At(entry.startOffset, kFpHashLen);
            if (fp0) {
                auto key0 = FpHash(fp0, kFpHashLen);
                auto [it, ok] = s_compFingerprint.try_emplace(key0,
                    CompFingerprintEntry{ &archive, entry.startOffset, entry.packedSize, entry.unpackedSize });
                if (!ok) ++collisions;
                else ++indexed;
            }

            if (entry.packedSize >= kFpHashLen + 1) {
                auto fp1 = archive.At(entry.startOffset + 1, kFpHashLen);
                if (fp1) {
                    auto key1 = FpHash(fp1, kFpHashLen);
                    auto [it, ok] = s_compFingerprint.try_emplace(key1,
                        CompFingerprintEntry{ &archive, entry.startOffset, entry.packedSize, entry.unpackedSize });
                    if (!ok) ++collisions;
                    else ++indexed;
                }
            }
        }
    }

    char buf[192];
    std::snprintf(buf, sizeof(buf),
        "FFC4: Fingerprint index built — %zu entries, %zu collisions",
        indexed, collisions);
    LogInfo(buf);
}

// ═════════════════════════════════════════════════════════════════════════════
// Fingerprint index sidecar — persists s_compFingerprint between runs so
// startup doesn't redo the ~19s BA2 page-fault-heavy rescan. Invalidation is
// per-archive (fileSize + lastWrite); any mismatch → full rebuild. Rebuilt
// sidecars are written .tmp then renamed so a mid-write crash can't leave a
// truncated-but-header-valid file.
// ═════════════════════════════════════════════════════════════════════════════

#pragma pack(push, 1)
struct FpxHeader {
    char          magic[8];         // "FFC4FPX1"
    std::uint32_t recordCount;
    std::uint32_t archiveCount;
};
struct FpxRecord {
    std::uint64_t hash;
    std::uint32_t startOffset;
    std::uint32_t packedSize;
    std::uint32_t unpackedSize;
    std::uint16_t archiveIdx;       // index into the archive-stamp table
    std::uint16_t _pad;
};
#pragma pack(pop)

static_assert(sizeof(FpxHeader) == 16, "FpxHeader layout");
static_assert(sizeof(FpxRecord) == 24, "FpxRecord layout");

static constexpr char kFpxMagic[8] = { 'F','F','C','4','F','P','X','1' };

static std::uint64_t FpxFileLastWrite(const std::filesystem::path& p)
{
    WIN32_FILE_ATTRIBUTE_DATA ad{};
    if (!GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &ad))
        return 0;
    ULARGE_INTEGER u{};
    u.LowPart  = ad.ftLastWriteTime.dwLowDateTime;
    u.HighPart = ad.ftLastWriteTime.dwHighDateTime;
    return u.QuadPart;
}

static std::filesystem::path FpxSidecarPath(const std::filesystem::path& dataPath)
{
    return dataPath / "F4SE" / "Plugins" / "FasterFileCopyFO4_cache" / "Fingerprints.fpx";
}

// Returns true and populates s_compFingerprint on a valid/matching sidecar.
// Returns false on any mismatch (missing, wrong magic, stale stamp, truncated
// records, archive not in current mapping). Caller falls back to a full
// rebuild when this returns false.
static bool LoadFingerprintSidecar(const std::filesystem::path& dataPath)
{
    auto reject = [](const char* reason) {
        char b[160];
        std::snprintf(b, sizeof(b), "FFC4: Fingerprint sidecar invalid — %s", reason);
        LogInfo(b);
        return false;
    };

    const auto path = FpxSidecarPath(dataPath);
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;  // no sidecar yet — normal first run, no log.

    FpxHeader hdr{};
    f.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
    if (!f || std::memcmp(hdr.magic, kFpxMagic, 8) != 0)
        return reject("bad magic/version");
    if (hdr.archiveCount == 0 || hdr.recordCount == 0)
        return reject("empty counts");

    const auto& archives = BA2::MemoryMapManager::GetSingleton().GetArchives();

    // Read every stamp, resolve each to a currently-open MappedArchive by
    // filename, verify size + mtime against the stamp. Any mismatch aborts.
    std::vector<const BA2::MappedArchive*> archiveIdx;
    archiveIdx.reserve(hdr.archiveCount);

    for (std::uint32_t i = 0; i < hdr.archiveCount; ++i) {
        std::uint16_t pathLen = 0;
        f.read(reinterpret_cast<char*>(&pathLen), sizeof(pathLen));
        if (!f || pathLen == 0 || pathLen > 512)
            return reject("bad path length in stamp");
        std::string relPath(pathLen, '\0');
        f.read(relPath.data(), pathLen);
        std::uint64_t fileSize = 0, lastWrite = 0;
        f.read(reinterpret_cast<char*>(&fileSize),  sizeof(fileSize));
        f.read(reinterpret_cast<char*>(&lastWrite), sizeof(lastWrite));
        if (!f) return reject("truncated stamp");

        const BA2::MappedArchive* match = nullptr;
        for (const auto& a : archives) {
            if (!a.IsOpen()) continue;
            if (a.GetPath().filename().string() == relPath) { match = &a; break; }
        }
        if (!match) {
            char b[256];
            std::snprintf(b, sizeof(b),
                "FFC4: Fingerprint sidecar invalid — archive '%s' not currently mapped",
                relPath.c_str());
            LogInfo(b);
            return false;
        }
        if (match->GetFileSize() != fileSize ||
            FpxFileLastWrite(match->GetPath()) != lastWrite)
        {
            char b[256];
            std::snprintf(b, sizeof(b),
                "FFC4: Fingerprint sidecar invalid — '%s' stamp changed",
                relPath.c_str());
            LogInfo(b);
            return false;
        }
        archiveIdx.push_back(match);
    }

    // Reject if the current mapping has any archive not represented in the
    // sidecar — a newly-installed BA2 would miss indexing until rebuild.
    std::size_t openCount = 0;
    for (const auto& a : archives) if (a.IsOpen()) ++openCount;
    if (openCount != hdr.archiveCount) {
        char b[160];
        std::snprintf(b, sizeof(b),
            "FFC4: Fingerprint sidecar invalid — archive count changed (open=%zu, stamped=%u)",
            openCount, hdr.archiveCount);
        LogInfo(b);
        return false;
    }

    std::vector<FpxRecord> records(hdr.recordCount);
    f.read(reinterpret_cast<char*>(records.data()),
           static_cast<std::streamsize>(sizeof(FpxRecord) * hdr.recordCount));
    if (!f) return reject("truncated records");

    s_compFingerprint.reserve(hdr.recordCount);
    for (const auto& r : records) {
        if (r.archiveIdx >= archiveIdx.size()) continue;
        s_compFingerprint.try_emplace(r.hash,
            CompFingerprintEntry{
                archiveIdx[r.archiveIdx],
                r.startOffset, r.packedSize, r.unpackedSize });
    }

    char buf[192];
    std::snprintf(buf, sizeof(buf),
        "FFC4: Fingerprint sidecar loaded — %u records, %u archives",
        hdr.recordCount, hdr.archiveCount);
    LogInfo(buf);
    return true;
}

static void WriteFingerprintSidecar(const std::filesystem::path& dataPath)
{
    if (s_compFingerprint.empty()) return;

    // Stamp every currently-open archive, not just those with indexed entries.
    // Uncompressed-only BA2s produce no fingerprint records but must still be
    // stamped so Load's `openCount == archiveCount` check passes next run.
    // Otherwise we'd reject our own freshly-written sidecar because a GNRL
    // archive with zero compressed entries was open at write time but not
    // referenced from any map entry.
    const auto& archives = BA2::MemoryMapManager::GetSingleton().GetArchives();
    std::unordered_map<const BA2::MappedArchive*, std::uint16_t> idxOf;
    std::vector<const BA2::MappedArchive*> archiveList;
    for (const auto& a : archives) {
        if (!a.IsOpen()) continue;
        idxOf.emplace(&a, static_cast<std::uint16_t>(archiveList.size()));
        archiveList.push_back(&a);
    }
    if (archiveList.empty() || archiveList.size() > 0xFFFFu) return;

    const auto finalPath = FpxSidecarPath(dataPath);
    std::error_code ec;
    std::filesystem::create_directories(finalPath.parent_path(), ec);
    const auto tmpPath = std::filesystem::path(finalPath.wstring() + L".tmp");

    std::ofstream f(tmpPath, std::ios::binary | std::ios::trunc);
    if (!f) return;

    FpxHeader hdr{};
    std::memcpy(hdr.magic, kFpxMagic, 8);
    hdr.recordCount  = static_cast<std::uint32_t>(s_compFingerprint.size());
    hdr.archiveCount = static_cast<std::uint32_t>(archiveList.size());
    f.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));

    for (const auto* a : archiveList) {
        const auto name = a->GetPath().filename().string();
        const auto len  = static_cast<std::uint16_t>(name.size());
        const std::uint64_t fileSize  = a->GetFileSize();
        const std::uint64_t lastWrite = FpxFileLastWrite(a->GetPath());
        f.write(reinterpret_cast<const char*>(&len), sizeof(len));
        f.write(name.data(), len);
        f.write(reinterpret_cast<const char*>(&fileSize),  sizeof(fileSize));
        f.write(reinterpret_cast<const char*>(&lastWrite), sizeof(lastWrite));
    }

    std::vector<FpxRecord> records;
    records.reserve(s_compFingerprint.size());
    for (const auto& kv : s_compFingerprint) {
        auto it = idxOf.find(kv.second.archive);
        if (it == idxOf.end()) continue;
        records.push_back(FpxRecord{
            kv.first, kv.second.fileOffset, kv.second.packedSize,
            kv.second.uncompSize, it->second, 0 });
    }
    f.write(reinterpret_cast<const char*>(records.data()),
            static_cast<std::streamsize>(sizeof(FpxRecord) * records.size()));

    f.flush();
    f.close();
    if (!f) { std::filesystem::remove(tmpPath, ec); return; }

    std::filesystem::remove(finalPath, ec);
    std::filesystem::rename(tmpPath, finalPath, ec);
    if (ec) { std::filesystem::remove(tmpPath, ec); return; }

    char buf[192];
    std::snprintf(buf, sizeof(buf),
        "FFC4: Fingerprint sidecar written — %zu records, %zu archives",
        s_compFingerprint.size(), archiveList.size());
    LogInfo(buf);
}

void BuildCompFingerprintIndexAsync(const std::filesystem::path& dataPath)
{
    if (s_compFingerprintReady.load(std::memory_order_acquire)) return;
    bool expected = false;
    if (!s_compFingerprintBuilding.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel))
        return;  // another caller already kicked off the build

    std::thread([dataPath]() {
        LARGE_INTEGER t0, t1, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&t0);

        // Fast path: try sidecar. Sub-second on a warm mmap, tens of ms cold.
        // If it loads cleanly we skip the full rescan entirely.
        const bool fromSidecar = LoadFingerprintSidecar(dataPath);

        if (!fromSidecar) {
            BuildCompFingerprintIndex();
            WriteFingerprintSidecar(dataPath);
        }

        QueryPerformanceCounter(&t1);
        double sec = static_cast<double>(t1.QuadPart - t0.QuadPart)
                   / static_cast<double>(freq.QuadPart);
        char buf[160];
        std::snprintf(buf, sizeof(buf),
            "FFC4: Fingerprint index ready in %.2fs (%s)",
            sec, fromSidecar ? "sidecar" : "rebuilt");
        LogInfo(buf);
        s_compFingerprintReady.store(true, std::memory_order_release);
    }).detach();
}

using inflate_fn = int(__cdecl*)(void*, int);
static inflate_fn s_origInflate = nullptr;

// BSTextureStreamer::Manager::zscrapAllocate hook body. State (typedef +
// s_origZscrapAlloc + counters) is declared near the top of this file so the
// stats logger can reference it.
static void* __fastcall HookedZscrapAlloc(void* a_this, int a_size, int a_count)
{
    s_zscrapCalls.fetch_add(1, std::memory_order_relaxed);
    s_zscrapBytes.fetch_add(
        static_cast<std::uint64_t>(static_cast<std::uint32_t>(a_size)) *
        static_cast<std::uint64_t>(static_cast<std::uint32_t>(a_count)),
        std::memory_order_relaxed);
    return s_origZscrapAlloc(a_this, a_size, a_count);
}

// ── LooseFileStream slot-12 async submit short-circuit ──────────────────────
// Hook target: FUN_1416AEFE0 on AE 1.11.191 — LooseFileStream's vtbl[0x60]
// entry (slot 12), the async BA2 read submit. See the Archive2 architecture
// memory for the full state machine; the short summary is:
//
//   FUN_14169D530 (compressed DoRead) calls source->vtbl[12] to submit an
//   async compressed-bytes read. The submit hands the request to an IO
//   worker via tag/wait_value pointers + an event flag. FUN_14169D530 then
//   calls source->vtbl[13] (DoWaitTags) which blocks until the worker bumps
//   *tag to match *wait. On return, ds->next_in points at fresh compressed
//   bytes and inflate runs.
//
// Short-circuit: when the archive is mmap-tracked, we read the compressed
// bytes directly from the mmap into the caller's buffer and fake
// "completion" by making *wait == *tag. DoWaitTags then returns immediately.
// Engine's internal ds state stays consistent; HookedInflate still runs
// and can fp-hash-serve from the decomp cache as before.
//
// Why NOT hook FUN_14169D530 itself: the full-function bypass broke the
// engine's async state machine — other subsystems wait on ds fields we'd
// never populate. Slot-12 scope is minimal (one compressed chunk read per
// call) and keeps ds flow authoritative.

static int __fastcall HookedLooseFileAsyncSubmit(
    void* self, void* buffer, std::uint64_t size, std::uint64_t offset,
    std::uint32_t arg5, int* tag_ptr, int* wait_ptr, void* event_flag)
{
    if (Settings::bEnableStats)
        s_looseSubmitCalls.fetch_add(1, std::memory_order_relaxed);

    const bool saveLoadShortCircuit = Settings::bShortCircuitDuringSaveLoad &&
        s_saveLoadActive.load(std::memory_order_acquire);

    if (!saveLoadShortCircuit &&
        Settings::bCompReadServe && buffer && size > 0 && self)
    {
        const auto* archive = SourceLookup(self);
        if (archive && archive->IsOpen()) {
            const auto* src = archive->At(offset, size);
            if (src) {
                // Fast sync read from mmap — bypass async infrastructure.
                std::memcpy(buffer, src, static_cast<std::size_t>(size));
                // Fake immediate completion: DoWaitTags compares *tag to
                // *wait and returns immediately when equal. No SetEvent
                // because we're claiming "no new work queued" (cache-hit
                // semantics per FUN_141681390).
                if (tag_ptr && wait_ptr)
                    *wait_ptr = *tag_ptr;
                if (Settings::bEnableStats) {
                    s_looseSubmitServed.fetch_add(1, std::memory_order_relaxed);
                    s_looseSubmitBytes.fetch_add(size, std::memory_order_relaxed);
                }
                return 0;  // success
            }
        }
    }
    return s_origLooseAsyncSubmit(self, buffer, size, offset, arg5,
                                  tag_ptr, wait_ptr, event_flag);
}

// AsyncReaderStream::DoStartRead at FUN_1416A2350. Stream-level intercept for
// the AsyncReaderStream class (separate from the sync ReaderStream that goes
// through FUN_14169D530 → source slot-12). Save-load uses async streams,
// hence the slot-12 hook never fires on the save-load hot path. This hook
// fills the gap.
//
// Args (4 reg, no stack — orig is a thin tail-call wrapper that doesn't read
// stack args either): self (AsyncReaderStream*), buffer, size, relativeOffset.
// On hit: memcpy from mmap and return 0; the matching DoWait reads this[0x30]
// which we never set, so it short-returns and engine sees the buffer filled.
static std::uint64_t __fastcall HookedAsyncStreamDoStartRead(
    void* self, void* buffer, std::uint64_t size, std::uint64_t offset)
{
    if (Settings::bEnableStats)
        s_asyncStartCalls.fetch_add(1, std::memory_order_relaxed);

    const bool saveLoadShortCircuit = Settings::bShortCircuitDuringSaveLoad &&
        s_saveLoadActive.load(std::memory_order_acquire);

    if (!saveLoadShortCircuit &&
        Settings::bCompReadServe && buffer && size > 0 && self)
    {
        // AsyncReaderStream layout (per disassembly of FUN_1416A2350):
        //   this[0x20] = source (LooseFileStream*)
        //   this[0x28] = startOffset (absolute BA2 offset of this entry)
        // Note: this[0x18] is NOT source on AsyncReaderStream — that's the
        // sync ReaderStream's layout. Different classes, different offsets.
        void* source = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(self) + 0x20);
        if (source) {
            const auto* archive = SourceLookup(source);
            if (archive && archive->IsOpen()) {
                const std::uint64_t startOff = *reinterpret_cast<std::uint64_t*>(
                    reinterpret_cast<std::uint8_t*>(self) + 0x28);
                const std::uint64_t absOffset = offset + startOff;
                const auto* src = archive->At(absOffset, size);
                if (src) {
                    std::memcpy(buffer, src, static_cast<std::size_t>(size));
                    if (Settings::bEnableStats) {
                        s_asyncStartServed.fetch_add(1, std::memory_order_relaxed);
                        s_asyncStartBytes.fetch_add(size, std::memory_order_relaxed);
                    }
                    return 0;  // success
                }
            }
        }
    }
    return s_origAsyncStartRead(self, buffer, size, offset);
}

static int __cdecl HookedInflate(void* strm_raw, int flush)
{
    // RAII total-time timer — scopes entire HookedInflate wall time so we can
    // back out the per-call FFC4 overhead = (Total - Zlib - Serve) / Calls.
    // Gated on stats so the QPC pair doesn't run when stats are off.
    struct TotalTimer {
        LARGE_INTEGER t0{};
        bool active;
        TotalTimer() : active(Settings::bEnableStats) {
            if (active) QueryPerformanceCounter(&t0);
        }
        ~TotalTimer() {
            if (!active) return;
            LARGE_INTEGER t1; QueryPerformanceCounter(&t1);
            s_inflateTotalNs.fetch_add(
                static_cast<std::uint64_t>(
                    (t1.QuadPart - t0.QuadPart) * 1000000000LL / s_qpcFreq),
                std::memory_order_relaxed);
        }
    } _totalTimer;

    // Fast-exit for non-BA2 zlib callers. HookedInflate is a *global* zlib
    // detour — it intercepts every z_inflate call in the process, including
    // any from third-party mods or engine subsystems unrelated to BA2. When
    // none of our features that need an inflate intercept are enabled, just
    // forward to the original and skip bridge/capture/diag overhead.
    // Branch is well-predicted (settings rarely change at runtime).
    // Baseline mode: forward every inflate but keep byte/time accounting so
    // SAVE LOAD's deliveredMB is directly comparable to the FFC4-on numbers
    // (mmap+cache both go to zero; all bytes land in the zlib_out column).
    // Save-load short-circuit reuses this path during kPreLoadGame → kPostLoadGame
    // so engine sees vanilla zlib timing — see HookedDoRead's matching gate.
    if (Settings::bBaselineMode ||
        (Settings::bShortCircuitDuringSaveLoad &&
         s_saveLoadActive.load(std::memory_order_acquire)))
    {
        auto* strm = reinterpret_cast<z_stream_compat*>(strm_raw);
        LARGE_INTEGER tz0{}, tz1{};
        std::uint32_t zlibInBefore  = 0;
        std::uint64_t zlibOutBefore = 0;
        if (Settings::bEnableStats) {
            s_inflateCalls.fetch_add(1, std::memory_order_relaxed);
            zlibInBefore  = strm->avail_in;
            zlibOutBefore = strm->total_out;
            QueryPerformanceCounter(&tz0);
        }
        const int rc = s_origInflate(strm_raw, flush);
        if (Settings::bEnableStats) {
            QueryPerformanceCounter(&tz1);
            s_inflateZlibNs.fetch_add(
                static_cast<std::uint64_t>((tz1.QuadPart - tz0.QuadPart) * 1000000000LL / s_qpcFreq),
                std::memory_order_relaxed);
            s_inflateZlibBytesIn.fetch_add(zlibInBefore - strm->avail_in, std::memory_order_relaxed);
            s_inflateZlibBytesOut.fetch_add(strm->total_out - zlibOutBefore, std::memory_order_relaxed);
        }
        return rc;
    }

    if (!Settings::bEnableDecompCache &&
        !Settings::bPassiveTextureCapture &&
        !Settings::bTextureDirectServe)
    {
        return s_origInflate(strm_raw, flush);
    }

    // Get the sequence before BridgeGet to ensure we match the right entry
    auto tid = GetCurrentThreadId();
    auto slot = tid & kBridgeMask;
    auto seq = s_inflateBridge[slot].sequence.load(std::memory_order_acquire);

    BridgeEntry cachedEntry{};
    bool hasCached = BridgeGet(seq, cachedEntry);

    // Per-caller attribution is done post-inflate (see below): we piggyback on
    // the origInflate ns + output-byte deltas already captured in the stats
    // block wrapping s_origInflate. _ReturnAddress() is stable across the
    // whole function, so sampling it after the call is fine.

    // Diagnostic counters + wall-clock window — all gated on stats, since
    // they are logging signal, not logic.
    if (Settings::bEnableStats) {
        static std::atomic<int> s_inflateTotal{ 0 };
        static std::atomic<int> s_inflateHit{ 0 };
        s_inflateTotal.fetch_add(1, std::memory_order_relaxed);
        if (hasCached) s_inflateHit.fetch_add(1, std::memory_order_relaxed);

        static std::atomic<int> s_infDiag{ 0 };
        if (s_cacheFrozen.load(std::memory_order_relaxed) &&
            s_infDiag.fetch_add(1, std::memory_order_relaxed) % 100000 == 0) {
            char buf[128];
            std::snprintf(buf, sizeof(buf),
                "FFC4 INFLATE stats: total=%d hit=%d",
                s_inflateTotal.load(), s_inflateHit.load());
            LogInfo(buf);
        }

        s_inflateCalls.fetch_add(1, std::memory_order_relaxed);

        LARGE_INTEGER nowQpc; QueryPerformanceCounter(&nowQpc);
        std::int64_t expected = 0;
        s_inflateFirstQpc.compare_exchange_strong(
            expected, nowQpc.QuadPart, std::memory_order_relaxed);
        s_inflateLastQpc.store(nowQpc.QuadPart, std::memory_order_relaxed);
    }

    auto* strm = reinterpret_cast<z_stream_compat*>(strm_raw);

    // Capture first kFpHashLen compressed bytes on the first inflate call for
    // this stream (total_in == 0). Used at Z_STREAM_END to identify the chunk
    // via fingerprint lookup, then self-decompress from the mmap.
    static thread_local std::uint64_t t_compKey = 0;
    static thread_local bool          t_hasKey  = false;

    // Slice-serve state: BSTextureStreamer calls z_inflate N times per DX10
    // chunk with avail_out=512KB — one chunk unpacks to ~3–7 MB, so we need
    // stateful delivery. Install on call 0 when fp matches, serve the next
    // slice on subsequent calls keyed on z_stream*, clear on Z_STREAM_END or
    // when the stream is reused for a new chunk (total_in resets to 0).
    struct SliceServe {
        std::shared_ptr<void> owner;
        const std::uint8_t*   data       = nullptr;
        std::uint32_t         size       = 0;
        std::uint32_t         cursor     = 0;
        std::uint32_t         packedSize = 0;
        void*                 zstream    = nullptr;
        void Clear() {
            owner.reset();
            data = nullptr; size = 0; cursor = 0; packedSize = 0;
            zstream = nullptr;
        }
    };
    static thread_local SliceServe t_slice;
    if (Settings::bPassiveTextureCapture &&
        strm->total_in == 0 && strm->avail_in >= kFpHashLen)
    {
        t_compKey = FpHash(strm->next_in, kFpHashLen);
        t_hasKey  = true;
    }

    // Diagnostic dst capture (#1) — first call of a stream tells us where the
    // game put the UNPACKED dst buffer. Sample only large outputs (>=64KB) to
    // bias toward textures over mesh/script chunks.
    if (s_inflateDstEnabled.load(std::memory_order_relaxed) &&
        strm->total_in == 0 && strm->avail_out >= 65536)
    {
        auto idx = s_inflateDstHead.fetch_add(1, std::memory_order_relaxed)
                   % kInflateDstSamples;
        s_inflateDstSamples[idx] = { tid, strm->next_out, strm->avail_out };
    }

    if (hasCached) {
        auto sz = cachedEntry.size;
        if (strm->avail_out >= sz) {
            LARGE_INTEGER ts0{}, ts1{};
            if (Settings::bEnableStats) QueryPerformanceCounter(&ts0);
            std::memcpy(strm->next_out, cachedEntry.data, sz);
            strm->next_out  += sz;
            strm->avail_out -= sz;
            strm->total_out  = sz;
            strm->total_in   = strm->avail_in;
            strm->avail_in   = 0;

            if (Settings::bEnableStats) {
                s_cacheServed.fetch_add(1, std::memory_order_relaxed);
                s_cacheServedBytes.fetch_add(sz, std::memory_order_relaxed);
                if (cachedEntry.fromTex) {
                    s_texBridgeConsumed.fetch_add(1, std::memory_order_relaxed);
                    s_texBridgeConsumedBytes.fetch_add(sz, std::memory_order_relaxed);
                }
            }

            auto& dcache = BA2::DecompCache::GetSingleton();
            dcache.RecordHit(sz);

            BridgeClear(seq);  // consumed
            if (Settings::bEnableStats) {
                QueryPerformanceCounter(&ts1);
                s_inflateServeNs.fetch_add(
                    static_cast<std::uint64_t>((ts1.QuadPart - ts0.QuadPart) * 1000000000LL / s_qpcFreq),
                    std::memory_order_relaxed);
            }
            return 1;  // Z_STREAM_END
        }
    }

    // ── Texture inflate-level serve via fingerprint ─────────────────────
    // AE's vtbl[0x60] is async (fire-and-forget to an IO worker thread),
    // so the bridge TLS can't relay data from HookedStreamInflate to here.
    // Instead we identify the chunk at inflate time: compressed-data
    // fingerprint → (archive, fileOffset) → decomp cache → memcpy.
    // The pool buffer that ReadMipsToTexture allocates is sized for
    // sum(packedSize), NOT sum(unpackedSize), so HL-level memcpy into
    // that buffer overflows and corrupts the custom allocator — that was
    // the root cause of the Fallout4.exe+17CECA6 crash.
    if (Settings::bEnableTextureCache &&
        Settings::bTextureDirectServe && strm->avail_out > 0 &&
        !s_saveLoadActive.load(std::memory_order_acquire) &&
        s_gameplayPhase.load(std::memory_order_acquire))
    {
        // Per-runtime return-address of the texture-streamer inflate caller.
        // This MUST be a tight gate — the 8-byte fp has ~6 bytes of entropy
        // (zlib header is nearly fixed), so fp-only matching collides across
        // unrelated callers and serves wrong bytes. A broad gate (e.g.
        // total_in == 0) lets mesh/sound/interface inflate through and
        // overruns their dst buffer with a DX10 chunk's unpack size.
        static const std::uintptr_t s_texServeRVA = [] {
            const auto& mod = REL::Module::get();
            const auto  ver = mod.version();
            if (mod.IsVR())      return std::uintptr_t(0x1D373D2);  // F4VR 1.2.72 BSTextureStreamer::zlibStreamDetail::Inflate+0x12
            if (ver[1] == 11)    return std::uintptr_t(0x17CB1B2);  // AE 1.11.x
            return std::uintptr_t(0);  // OG/NG: unknown, skip fp-serve
        }();

        // Second accepted caller: the inflate site inside FUN_14169D530, the
        // BA2 compressed reader. Save-load attribution (task #115) showed
        // 128 MB of unbridged inflate at 0x0169D766 on AE — these are
        // continuation reads on entries the bridge couldn't serve in one
        // shot. Letting slice-serve answer them too closes that bucket
        // without needing a separate hook. Per-runtime gate.
        static const std::uintptr_t s_ba2CompServeRVA = [] {
            const auto& mod = REL::Module::get();
            const auto  ver = mod.version();
            if (mod.IsVR())      return std::uintptr_t(0);  // F4VR: not yet identified
            if (ver[1] == 11)    return std::uintptr_t(0x0169D766);  // AE 1.11.x: FUN_14169D530+0x236
            return std::uintptr_t(0);
        }();

        bool gateOk = false;
        if (s_texServeRVA != 0 || s_ba2CompServeRVA != 0) {
            auto retRVA = reinterpret_cast<std::uintptr_t>(_ReturnAddress())
                         - REL::Module::get().base();
            gateOk = (retRVA == s_texServeRVA) ||
                     (s_ba2CompServeRVA != 0 && retRVA == s_ba2CompServeRVA);
        }

        if (gateOk) {
            // Stale-state invalidation: slice state is per-thread but z_stream
            // pointers can be reused across chunks. If the caller reset the
            // stream (total_in==0) or moved to a different z_stream, drop it.
            if (t_slice.zstream &&
                (t_slice.zstream != strm || strm->total_in == 0))
            {
                t_slice.Clear();
            }

            // Continuation: same z_stream, mid-stream slice. Serve next
            // piece from cache, advance input proportionally, clear and
            // return Z_STREAM_END on the last slice.
            if (t_slice.zstream == strm && t_slice.cursor < t_slice.size) {
                LARGE_INTEGER ts0{}, ts1{};
                if (Settings::bEnableStats) QueryPerformanceCounter(&ts0);

                auto remain = t_slice.size - t_slice.cursor;
                auto copy   = (remain < strm->avail_out)
                              ? remain : strm->avail_out;
                BA2::FastCopyLarge(strm->next_out,
                                   t_slice.data + t_slice.cursor, copy);
                strm->next_out   += copy;
                strm->avail_out  -= copy;
                strm->total_out  += copy;
                t_slice.cursor   += copy;

                const bool last = (t_slice.cursor == t_slice.size);
                std::uint32_t inConsume;
                if (last) {
                    std::uint64_t consumed =
                        (t_slice.packedSize > strm->total_in)
                        ? t_slice.packedSize - strm->total_in : 0;
                    inConsume = (consumed > strm->avail_in)
                                ? strm->avail_in
                                : static_cast<std::uint32_t>(consumed);
                } else {
                    std::uint64_t want =
                        (static_cast<std::uint64_t>(copy) *
                         t_slice.packedSize) / t_slice.size;
                    inConsume = (want > strm->avail_in)
                                ? strm->avail_in
                                : static_cast<std::uint32_t>(want);
                }
                strm->next_in  += inConsume;
                strm->avail_in -= inConsume;
                strm->total_in += inConsume;

                if (last) {
                    t_hasKey = false;
                    t_slice.Clear();
                }

                BA2::DecompCache::GetSingleton().RecordHit(copy);
                if (Settings::bEnableStats) {
                    s_texFpServed.fetch_add(1, std::memory_order_relaxed);
                    s_texFpServedBytes.fetch_add(copy, std::memory_order_relaxed);
                    s_cacheServed.fetch_add(1, std::memory_order_relaxed);
                    s_cacheServedBytes.fetch_add(copy, std::memory_order_relaxed);
                    QueryPerformanceCounter(&ts1);
                    s_inflateServeNs.fetch_add(
                        static_cast<std::uint64_t>(
                            (ts1.QuadPart - ts0.QuadPart) * 1000000000LL / s_qpcFreq),
                        std::memory_order_relaxed);
                }
                return last ? 1 : 0;  // Z_STREAM_END : Z_OK
            }
        }

        if (gateOk && strm->avail_in >= kFpHashLen &&
            s_compFingerprintReady.load(std::memory_order_acquire)) {
            if (Settings::bEnableStats) {
                s_texServeGatePass.fetch_add(1, std::memory_order_relaxed);
            }
            auto fp = FpHash(strm->next_in, kFpHashLen);
            auto it = s_compFingerprint.find(fp);
            if (it == s_compFingerprint.end()) {
                if (Settings::bEnableStats) {
                    s_texServeFpMiss.fetch_add(1, std::memory_order_relaxed);
                }
                // Sampler: dump first N fpMiss inputs per gameplay.
                // With slice-serve installed, total_in==0 is the only
                // path that can fp-match — misses here are genuine
                // (archive not mapped, or streamer mutated the input).
                if (s_gameplayActive.load(std::memory_order_relaxed)) {
                    auto dumpIdx = s_fpMissDumpSeq.fetch_add(
                        1, std::memory_order_relaxed);
                    if (dumpIdx < kFpMissDumpLimit) {
                        const auto* p = strm->next_in;
                        char hex[16 * 3 + 1];
                        for (int i = 0; i < 16; ++i) {
                            std::snprintf(hex + i * 3, 4, "%02X ", p[i]);
                        }
                        hex[16 * 3 - 1] = '\0';
                        std::uint32_t sizeMatches = 0;
                        for (const auto& kv : s_compFingerprint) {
                            if (kv.second.packedSize == strm->avail_in) {
                                ++sizeMatches;
                                if (sizeMatches > 16) break;
                            }
                        }
                        char line[256];
                        std::snprintf(line, sizeof(line),
                            "FFC4 fpMiss[%u]: avail_in=%u avail_out=%u "
                            "total_in=%llu total_out=%llu fp=%016llX "
                            "sizeMatches=%u hex=%s",
                            dumpIdx, strm->avail_in, strm->avail_out,
                            (unsigned long long)strm->total_in,
                            (unsigned long long)strm->total_out,
                            (unsigned long long)fp, sizeMatches, hex);
                        LogInfo(line);
                    }
                }
            } else {
                const auto& fpe = it->second;
                auto inDiff = static_cast<std::int64_t>(strm->avail_in)
                            - static_cast<std::int64_t>(fpe.packedSize);
                if (inDiff < -2 || inDiff > 2) {
                    if (Settings::bEnableStats) {
                        s_texServeSizeReject.fetch_add(1, std::memory_order_relaxed);
                    }
                } else {
                    auto& dcache = BA2::DecompCache::GetSingleton();
                    if (dcache.IsReady()) {
                        auto lr = dcache.Lookup(fpe.archive, fpe.fileOffset);
                        if (!lr || lr.size != fpe.uncompSize) {
                            if (Settings::bEnableStats) {
                                s_texServeDcacheMiss.fetch_add(1, std::memory_order_relaxed);
                            }
                        } else if (strm->avail_out >= lr.size) {
                            // Single-shot: caller's buffer fits the whole
                            // decompressed chunk.
                            LARGE_INTEGER ts0{}, ts1{};
                            if (Settings::bEnableStats) QueryPerformanceCounter(&ts0);
                            BA2::FastCopyLarge(strm->next_out, lr.data, lr.size);
                            strm->next_out  += lr.size;
                            strm->avail_out -= lr.size;
                            strm->total_out  = lr.size;
                            strm->total_in   = strm->avail_in;
                            strm->avail_in   = 0;

                            // Prevent the post-inflate capture path from
                            // re-decompressing the same chunk we just served.
                            t_hasKey = false;

                            dcache.RecordHit(lr.size);
                            if (Settings::bEnableStats) {
                                s_texFpServed.fetch_add(1, std::memory_order_relaxed);
                                s_texFpServedBytes.fetch_add(lr.size, std::memory_order_relaxed);
                                s_cacheServed.fetch_add(1, std::memory_order_relaxed);
                                s_cacheServedBytes.fetch_add(lr.size, std::memory_order_relaxed);
                                QueryPerformanceCounter(&ts1);
                                s_inflateServeNs.fetch_add(
                                    static_cast<std::uint64_t>((ts1.QuadPart - ts0.QuadPart) * 1000000000LL / s_qpcFreq),
                                    std::memory_order_relaxed);
                            }
                            return 1;  // Z_STREAM_END
                        } else {
                            // Slice path: blob is bigger than avail_out
                            // (typical: 3–7 MB decomp into a 512 KB
                            // output buffer). Install per-thread state
                            // and serve the first slice. Subsequent
                            // calls re-enter through the continuation
                            // branch above.
                            LARGE_INTEGER ts0{}, ts1{};
                            if (Settings::bEnableStats) QueryPerformanceCounter(&ts0);

                            t_slice.owner      = lr.owner;
                            t_slice.data       = lr.data;
                            t_slice.size       = lr.size;
                            t_slice.cursor     = 0;
                            t_slice.packedSize = fpe.packedSize;
                            t_slice.zstream    = strm;

                            auto copy = strm->avail_out;
                            BA2::FastCopyLarge(strm->next_out, t_slice.data, copy);
                            strm->next_out  += copy;
                            strm->avail_out -= copy;
                            strm->total_out += copy;
                            t_slice.cursor   = copy;

                            std::uint64_t want =
                                (static_cast<std::uint64_t>(copy) *
                                 t_slice.packedSize) / t_slice.size;
                            std::uint32_t inConsume =
                                (want > strm->avail_in)
                                ? strm->avail_in
                                : static_cast<std::uint32_t>(want);
                            strm->next_in  += inConsume;
                            strm->avail_in -= inConsume;
                            strm->total_in += inConsume;

                            t_hasKey = false;
                            dcache.RecordHit(copy);
                            if (Settings::bEnableStats) {
                                s_texFpServed.fetch_add(1, std::memory_order_relaxed);
                                s_texFpServedBytes.fetch_add(copy, std::memory_order_relaxed);
                                s_cacheServed.fetch_add(1, std::memory_order_relaxed);
                                s_cacheServedBytes.fetch_add(copy, std::memory_order_relaxed);
                                QueryPerformanceCounter(&ts1);
                                s_inflateServeNs.fetch_add(
                                    static_cast<std::uint64_t>(
                                        (ts1.QuadPart - ts0.QuadPart) * 1000000000LL / s_qpcFreq),
                                    std::memory_order_relaxed);
                            }
                            return 0;  // Z_OK — more slices to come
                        }
                    }
                }
            }
        }
    }

    // When stats are off, skip the QPC pair + byte-diff bookkeeping around
    // the original inflate. That saves two RDTSC-domain reads + three atomic
    // adds per inflate call — one of the highest-frequency sites in the mod.
    LARGE_INTEGER tz0{}, tz1{};
    std::uint32_t zlibInBefore = 0;
    std::uint64_t zlibOutBefore = 0;
    if (Settings::bEnableStats) {
        zlibInBefore  = strm->avail_in;
        zlibOutBefore = strm->total_out;
        QueryPerformanceCounter(&tz0);
    }
    const int rc = s_origInflate(strm_raw, flush);
    if (Settings::bEnableStats) {
        QueryPerformanceCounter(&tz1);
        s_inflateZlibNs.fetch_add(
            static_cast<std::uint64_t>((tz1.QuadPart - tz0.QuadPart) * 1000000000LL / s_qpcFreq),
            std::memory_order_relaxed);
        s_inflateZlibBytesIn.fetch_add(zlibInBefore - strm->avail_in, std::memory_order_relaxed);
        s_inflateZlibBytesOut.fetch_add(strm->total_out - zlibOutBefore, std::memory_order_relaxed);

        // Unbridged-caller attribution (gameplay-only). Counts every call,
        // sums ns + bytes per return-address bucket. For the 4KB reader
        // (FUN_141da2ea0, RVA 0x01DA2FA5) we additionally sample the source
        // object vtable so the upstream class can be identified in Ghidra.
        if (!hasCached &&
            (s_gameplayActive.load(std::memory_order_relaxed) ||
             s_saveLoadActive.load(std::memory_order_relaxed))) {
            auto ra   = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
            auto rva  = static_cast<std::uint32_t>(ra - REL::Module::get().base());
            auto dNs  = static_cast<std::uint64_t>(
                (tz1.QuadPart - tz0.QuadPart) * 1000000000LL / s_qpcFreq);
            auto dBy  = strm->total_out - zlibOutBefore;

            std::lock_guard lk(s_inflateCallerMtx);
            InflateCallerSample* bucket = nullptr;
            for (auto& s : s_inflateCallerSamples) {
                if (s.rva == rva) { bucket = &s; break; }
            }
            if (!bucket) {
                for (auto& s : s_inflateCallerSamples) {
                    if (s.rva == 0) { s.rva = rva; bucket = &s; break; }
                }
            }
            if (bucket) {
                ++bucket->count;
                bucket->nsTotal    += dNs;
                bucket->bytesTotal += dBy;
                // FUN_141da2ea0 outer object = z_stream - 0x08; outer+0 = source ptr.
                if (rva == 0x01DA2FA5 && bucket->srcVtable == 0) {
                    auto* outer = reinterpret_cast<std::uint8_t*>(strm) - 0x08;
                    auto src    = *reinterpret_cast<void**>(outer);
                    if (src) bucket->srcVtable = *reinterpret_cast<std::uintptr_t*>(src);
                }
            }
        }
    }

    // Passive texture capture via compressed-data fingerprint.
    // On fingerprint match, self-decompress from the mmap'd archive data
    // instead of reading from the inflate output buffer (which may be a
    // small scratch buffer recycled during incremental inflate).
    if (rc == 1 /* Z_STREAM_END */ && t_hasKey &&
        Settings::bEnableTextureCache && Settings::bPassiveTextureCapture &&
        strm->total_out > 0 &&
        s_gameplayPhase.load(std::memory_order_acquire))
    {
        t_hasKey = false;

        // Return-address gate: skip non-texture inflate calls cheaply.
        static const std::uintptr_t s_texRetRVA = [] {
            const auto& mod = REL::Module::get();
            const auto  ver = mod.version();
            if (mod.IsVR())   return std::uintptr_t(0x1D373D2);  // F4VR 1.2.72
            if (ver[1] == 11) return std::uintptr_t(0x17CB1B2);  // AE 1.11.x
            return std::uintptr_t(0);  // OG/NG: retRVA unknown, fall through
        }();

        bool isTexInflate = true;
        if (s_texRetRVA != 0) {
            auto retRVA = reinterpret_cast<std::uintptr_t>(_ReturnAddress())
                         - REL::Module::get().base();
            isTexInflate = (retRVA == s_texRetRVA);
        }

        if (isTexInflate && s_compFingerprintReady.load(std::memory_order_acquire))
        {
            auto it = s_compFingerprint.find(t_compKey);
            if (it == s_compFingerprint.end()) {
                if (Settings::bEnableStats) {
                    s_texCaptureFpMiss.fetch_add(1, std::memory_order_relaxed);
                }
            } else {
                s_texFingerprintHits.fetch_add(1, std::memory_order_relaxed);
                const auto& fp = it->second;
                if (strm->total_out == fp.uncompSize) {
                    // Dedup: skip the re-inflate + record entirely if the
                    // (archive, fileOffset) is already in the cache. Without
                    // this, every save-load re-does ~100+ MB of redundant
                    // inflate work on the IO worker threads, hurting wall
                    // time even though the cache is warm. This was the main
                    // cost in the cache+capture test run.
                    auto& dcache = BA2::DecompCache::GetSingleton();
                    if (dcache.IsReady()) {
                        auto existing = dcache.Lookup(fp.archive, fp.fileOffset);
                        if (existing && existing.size == fp.uncompSize) {
                            s_texCaptureSkipped.fetch_add(1, std::memory_order_relaxed);
                            goto capture_done;
                        }
                    }
                    const auto* compData = fp.archive->At(fp.fileOffset, fp.packedSize);
                    if (compData) {
                        std::vector<std::uint8_t> buf(fp.uncompSize);
                        bool ok = false;
                        {
                            z_stream zs{};
                            if (inflateInit(&zs) == Z_OK) {
                                zs.next_in  = const_cast<Bytef*>(compData);
                                zs.avail_in = fp.packedSize;
                                zs.next_out = buf.data();
                                zs.avail_out = fp.uncompSize;
                                ok = (inflate(&zs, Z_FINISH) == Z_STREAM_END
                                      && zs.total_out == fp.uncompSize);
                                inflateEnd(&zs);
                            }
                        }
                        if (!ok) {
                            z_stream zs{};
                            if (inflateInit2(&zs, -MAX_WBITS) == Z_OK) {
                                zs.next_in  = const_cast<Bytef*>(compData + 1);
                                zs.avail_in = fp.packedSize - 1;
                                zs.next_out = buf.data();
                                zs.avail_out = fp.uncompSize;
                                ok = (inflate(&zs, Z_FINISH) == Z_STREAM_END
                                      && zs.total_out == fp.uncompSize);
                                inflateEnd(&zs);
                            }
                        }
                        if (ok) {
                            dcache.RecordDecompressed(fp.archive, fp.fileOffset,
                                buf.data(), fp.uncompSize);
                            s_texCaptureRecorded.fetch_add(1, std::memory_order_relaxed);
                            s_texCaptureRecordedBytes.fetch_add(fp.uncompSize,
                                std::memory_order_relaxed);
                        }
                    }
                }
            }
        }
    }

capture_done:
    return rc;
}

static RE::BSResource::ErrorCode HookedDoRead(
    void*           a_this,
    void*           a_buffer,
    std::uint64_t   a_toRead,
    std::uint64_t&  a_read)
{
    // Detect async stream up front so every diagnostic path can see it. Cheap:
    // one indirect load. Used by the baseline-mode counter below and by the
    // main-path bridge diagnostics.
    const bool isAsyncStream =
        s_asyncReaderStreamVtbl != 0 &&
        *reinterpret_cast<std::uintptr_t*>(a_this) == s_asyncReaderStreamVtbl;

    // ── Baseline mode / save-load short-circuit ────────────────────────
    // Pure pass-through. ResolveSource calls DoGetName via vtbl[0x0F] on
    // the source stream, which can deadlock against locks held by the
    // caller's DoRead path (AE main-menu hang). Baseline must do no work
    // beyond timing the original read. Save-load short-circuit (gated on
    // bShortCircuitDuringSaveLoad) reuses this path during kPreLoadGame →
    // kPostLoadGame so the engine sees vanilla I/O timing during save
    // load — benchmarked +1.7s save-load otherwise from hook prep work.
    if (Settings::bBaselineMode ||
        (!Settings::bEnableMmap && !Settings::bEnableDecompCache) ||
        (Settings::bShortCircuitDuringSaveLoad &&
         s_saveLoadActive.load(std::memory_order_acquire)))
    {
        auto orig = PickOriginalDoRead(a_this);
        LARGE_INTEGER t0{}, t1{};
        if (Settings::bEnableStats) QueryPerformanceCounter(&t0);
        auto err = orig(a_this, a_buffer, a_toRead, a_read);
        if (Settings::bEnableStats) {
            QueryPerformanceCounter(&t1);
            s_ticksFallbackRead.fetch_add(t1.QuadPart - t0.QuadPart, std::memory_order_relaxed);
            s_fallbackReads.fetch_add(1, std::memory_order_relaxed);
            s_fallbackBytes.fetch_add(a_read, std::memory_order_relaxed);
            if (isAsyncStream) {
                s_asyncDoReadCalls.fetch_add(1, std::memory_order_relaxed);
                s_asyncDoReadBytes.fetch_add(a_read, std::memory_order_relaxed);
            }
        }
        return err;
    }

    if (Settings::bEnableStats && isAsyncStream) {
        s_asyncDoReadCalls.fetch_add(1, std::memory_order_relaxed);
        // bytes counted at tail where a_read is known
    }

    const auto compressedSize = ReadField<std::uint32_t>(a_this, Field::CompressedSize);
    if (Settings::bEnableStats && isAsyncStream && compressedSize != 0)
        s_asyncCompressedCalls.fetch_add(1, std::memory_order_relaxed);

    // Always read Source so we can validate the fast-cache entry against
    // stream-pointer reuse. ReadField is a single load; cheaper than the
    // cost of serving wrong bytes.
    void* sourcePtr = ReadField<void*>(a_this, Field::Source);

    // Diagnostic: per-(source vtbl × stream kind) call counters with first-hit
    // logging. Replaces the simpler prior probe — now tracks call frequency so
    // we can distinguish "vtable we saw once on a config read" from "vtable we
    // read from 10000× on save-load." Separately bucketed by async flag so we
    // see whether async traffic lands on a different source class.
    if (sourcePtr && Settings::bEnableStats) {
        struct SrcBucket {
            std::atomic<std::uintptr_t> srcVtbl{ 0 };
            std::atomic<std::uintptr_t> streamVtbl{ 0 };
            std::atomic<std::uint64_t>  calls{ 0 };
            std::atomic<int>            isAsync{ -1 };  // -1 unset, 0 sync, 1 async
        };
        static constexpr int kSrcBuckets = 16;
        static SrcBucket s_srcBuckets[kSrcBuckets];

        const auto srcVtbl = *reinterpret_cast<std::uintptr_t*>(sourcePtr);
        const auto streamVtbl = *reinterpret_cast<std::uintptr_t*>(a_this);
        const int asyncFlag = isAsyncStream ? 1 : 0;

        int foundIdx = -1;
        for (int i = 0; i < kSrcBuckets; ++i) {
            auto v = s_srcBuckets[i].srcVtbl.load(std::memory_order_relaxed);
            if (v == srcVtbl &&
                s_srcBuckets[i].streamVtbl.load(std::memory_order_relaxed) == streamVtbl &&
                s_srcBuckets[i].isAsync.load(std::memory_order_relaxed) == asyncFlag) {
                foundIdx = i;
                break;
            }
            if (v == 0 && foundIdx < 0) {
                std::uintptr_t expected = 0;
                if (s_srcBuckets[i].srcVtbl.compare_exchange_strong(expected, srcVtbl)) {
                    s_srcBuckets[i].streamVtbl.store(streamVtbl, std::memory_order_relaxed);
                    s_srcBuckets[i].isAsync.store(asyncFlag, std::memory_order_relaxed);
                    // First-hit log.
                    auto slot7 = *reinterpret_cast<std::uintptr_t*>(srcVtbl + 0x38);
                    auto slot6 = *reinterpret_cast<std::uintptr_t*>(srcVtbl + 0x30);
                    auto slot8 = *reinterpret_cast<std::uintptr_t*>(srcVtbl + 0x40);
                    char buf[256];
                    std::snprintf(buf, sizeof(buf),
                        "FFC4 SRCPROBE #%d: src=%llX srcVtbl=%llX streamVtbl=%llX "
                        "async=%d slot6=%llX slot7=%llX slot8=%llX",
                        i,
                        (unsigned long long)sourcePtr,
                        (unsigned long long)srcVtbl,
                        (unsigned long long)streamVtbl,
                        asyncFlag,
                        (unsigned long long)slot6,
                        (unsigned long long)slot7,
                        (unsigned long long)slot8);
                    LogInfo(buf);
                    foundIdx = i;
                }
            }
        }
        if (foundIdx >= 0)
            s_srcBuckets[foundIdx].calls.fetch_add(1, std::memory_order_relaxed);
    }

    // Fast path: stream→archive was cached at factory time AND the source
    // pointer still matches. Skips the SourceLookup hashtable probe.
    const BA2::MappedArchive* archive = StreamArchiveLookup(a_this, sourcePtr);
    if (!archive) {
        if (sourcePtr)
            archive = ResolveSource(sourcePtr);
        // Backfill the cache so the next read on this stream hits the fast path.
        if (archive)
            StreamArchiveInsert(a_this, sourcePtr, archive);
    }

    // ── Uncompressed → serve from archive mmap (if enabled) ─────────────
    // Gate to synchronous ReaderStream only. AsyncReaderStream's DoRead is
    // hooked too (for cache serving via the inflate bridge), but bypassing
    // its orig with a pure memcpy could leave async completion state stale.
    // AsyncReaderStream always falls through to PickOriginalDoRead below.
    // isAsyncStream was computed at function entry.
    // iCacheDelivery mode 2 (minimal): skip inline mmap serve, fall through
    // to stock ReaderStream::DoRead for maximum compat.
    if (Settings::bEnableMmap && !isAsyncStream &&
        Settings::iCacheDelivery <= 1 &&
        compressedSize == 0 && archive && archive->IsOpen()) {
        LARGE_INTEGER t0{}, t1{};
        if (Settings::bEnableStats) QueryPerformanceCounter(&t0);
        const auto startOff = ReadField<std::uint64_t>(a_this, Field::StartOffset);
        const auto curOff   = ReadField<std::uint32_t>(a_this, Field::CurrentRelativeOffset);
        const auto uncompSz = ReadField<std::uint32_t>(a_this, Field::UncompressedSize);

        const std::uint64_t remaining = (curOff < uncompSz) ? (uncompSz - curOff) : 0;
        const std::uint64_t n = (a_toRead < remaining) ? a_toRead : remaining;

        if (n > 0) {
            const auto* src = archive->At(startOff + curOff, n);
            if (src) {
                BA2::FastCopyLarge(a_buffer, src, static_cast<std::size_t>(n));
                WriteField<std::uint32_t>(a_this, Field::CurrentRelativeOffset,
                    curOff + static_cast<std::uint32_t>(n));
                a_read = n;
                if (Settings::bEnableStats) {
                    QueryPerformanceCounter(&t1);
                    s_ticksMmapRead.fetch_add(t1.QuadPart - t0.QuadPart, std::memory_order_relaxed);
                    s_mmapReads.fetch_add(1, std::memory_order_relaxed);
                    s_mmapBytes.fetch_add(n, std::memory_order_relaxed);
                }
                return RE::BSResource::ErrorCode::kNone;
            }
        }
        if (remaining == 0) { a_read = 0; return RE::BSResource::ErrorCode::kNone; }
    }

    const auto streamCursor = ReadField<std::uint32_t>(a_this, Field::CurrentRelativeOffset);

    // ── Compressed direct-serve: short-circuit ReaderStream::DoRead entirely
    //    (skips source->vtbl[7] decomp setup + zlib machinery). Requires a
    //    fresh stream + whole-entry request + hot cache. Per Ghidra RE of
    //    ReaderStream::DoRead: the only post-read state it sets is cursor +=
    //    a_read, so we emulate that and return — stays correctness-equivalent
    //    from the caller's view, skips ~50-150 µs of source-side work.
    if (compressedSize != 0 && archive &&
        Settings::bEnableGNRLCache && Settings::bCompressedDirectServe &&
        (!isAsyncStream || Settings::bCompressedDirectServeAsync) &&
        streamCursor == 0 &&
        !s_saveLoadActive.load(std::memory_order_acquire) &&
        s_gameplayPhase.load(std::memory_order_acquire))
    {
        auto& dcache = BA2::DecompCache::GetSingleton();
        if (dcache.IsReady()) {
            const auto startOff = static_cast<std::uint32_t>(
                ReadField<std::uint64_t>(a_this, Field::StartOffset));
            const auto uncompSz = ReadField<std::uint32_t>(a_this, Field::UncompressedSize);
            auto lr = dcache.Lookup(archive, startOff);
            if (lr && lr.size == uncompSz && a_toRead >= lr.size) {
                LARGE_INTEGER t0{}, t1{};
                if (Settings::bEnableStats) QueryPerformanceCounter(&t0);
                BA2::FastCopyLarge(a_buffer, lr.data, lr.size);
                WriteField<std::uint32_t>(a_this, Field::CurrentRelativeOffset, lr.size);
                a_read = lr.size;
                if (Settings::bEnableStats) {
                    QueryPerformanceCounter(&t1);
                    s_ticksDecomp.fetch_add(t1.QuadPart - t0.QuadPart, std::memory_order_relaxed);
                    s_cacheServed.fetch_add(1, std::memory_order_relaxed);
                    s_cacheServedBytes.fetch_add(lr.size, std::memory_order_relaxed);
                }
                return RE::BSResource::ErrorCode::kNone;
            }
        }
    }

    // ── Compressed → set bridge for inflate hook, call original DoRead ──
    // The inflate hook (installed separately) checks the bridge and serves from
    // decomp cache at the zlib level — compatible with FastDecompress.
    // Stream-state guard (Skyrim kInitialized analog): only bridge-set on a
    // fresh stream (cursor == 0). If the engine has already served some bytes
    // from the stock path, our bridge would redirect zlib mid-stream and the
    // cached-decompressed bytes would desync with what the engine has already
    // consumed. Safer to let zlib run stock when the stream isn't fresh.
    std::uint32_t bridgeSeq = 0;
    if (compressedSize != 0 && archive && Settings::bEnableGNRLCache &&
        streamCursor == 0 &&
        !s_saveLoadActive.load(std::memory_order_acquire) &&
        s_gameplayPhase.load(std::memory_order_acquire)) {
        auto& dcache = BA2::DecompCache::GetSingleton();
        const auto startOff = static_cast<std::uint32_t>(
            ReadField<std::uint64_t>(a_this, Field::StartOffset));

        // Set bridge so our inflate hook knows which entry is active
        auto lr = dcache.IsReady() ? dcache.Lookup(archive, startOff) : BA2::LookupResult{};
        if (lr) {
            BridgeSet(lr);
            // Capture sequence for later clear
            auto tid = GetCurrentThreadId();
            auto slot = tid & kBridgeMask;
            bridgeSeq = s_inflateBridge[slot].sequence.load(std::memory_order_relaxed);
            if (Settings::bEnableStats && isAsyncStream)
                s_asyncBridgeHit.fetch_add(1, std::memory_order_relaxed);
        } else if (Settings::bEnableStats) {
            if (isAsyncStream)
                s_asyncBridgeMiss.fetch_add(1, std::memory_order_relaxed);

            // Cache-miss sampler (task #115). Bump uncapped total; record
            // up to kCompMissSamples first-look misses for save-load dump.
            s_compMissTotal.fetch_add(1, std::memory_order_relaxed);
            auto idx = s_compMissHead.fetch_add(1, std::memory_order_relaxed);
            if (idx < kCompMissSamples) {
                const auto uncompSz = ReadField<std::uint32_t>(
                    a_this, Field::UncompressedSize);
                auto retRVA = reinterpret_cast<std::uintptr_t>(_ReturnAddress())
                              - REL::Module::get().base();
                s_compMissSamples[idx] = {
                    archive,
                    startOff,
                    static_cast<std::uint32_t>(compressedSize),
                    uncompSz,
                    retRVA
                };
            }
        }
    }

    // ── Call original DoRead ────────────────────────────────────────────
    // Pick the correct upstream based on stream vtable: ReaderStream and
    // AsyncReaderStream both land here but have distinct slot[6] funcs.
    auto orig = PickOriginalDoRead(a_this);
    LARGE_INTEGER t0{}, t1{};
    if (Settings::bEnableStats) QueryPerformanceCounter(&t0);
    auto err = orig(a_this, a_buffer, a_toRead, a_read);
    if (Settings::bEnableStats) QueryPerformanceCounter(&t1);

    if (bridgeSeq != 0)
        BridgeClear(bridgeSeq);

    const auto dt = Settings::bEnableStats ? (t1.QuadPart - t0.QuadPart) : 0;

    if (compressedSize != 0) {
        if (Settings::bEnableStats)
            s_ticksDecomp.fetch_add(dt, std::memory_order_relaxed);

        // GNRL capture — accumulate decompressed bytes into cache. Gated on
        // s_gameplayPhase so capture only runs after first save-load (never
        // during startup / initAllForms — that phase wins on mmap, cache
        // capture would just add per-call overhead with no benefit).
        if (archive && Settings::bEnableGNRLCache &&
            err == RE::BSResource::ErrorCode::kNone && a_read > 0 &&
            s_gameplayPhase.load(std::memory_order_acquire))
        {
            auto& dcache = BA2::DecompCache::GetSingleton();
            if (dcache.IsBuilding()) {
                const auto startOff = static_cast<std::uint32_t>(
                    ReadField<std::uint64_t>(a_this, Field::StartOffset));
                const auto uncompSz = ReadField<std::uint32_t>(a_this, Field::UncompressedSize);

                struct AccumState {
                    std::uint32_t startOff = 0;
                    std::uint32_t totalSize = 0;
                    std::vector<std::uint8_t> buf;
                    std::uint32_t lastAccess = 0;  // monotonic counter for LRU
                };
                static std::unordered_map<const void*, AccumState> s_accums;
                static std::mutex s_accumMtx;
                static std::uint32_t s_accessGen = 0;

                // Evict stale entries if map grows too large (indicates stream destruction without cleanup)
                constexpr std::size_t kMaxAccumEntries = 256;
                if (s_accums.size() > kMaxAccumEntries) {
                    // Remove oldest entries
                    std::vector<std::pair<const void*, std::uint32_t>> entries;
                    entries.reserve(s_accums.size());
                    for (const auto& [k, v] : s_accums)
                        entries.emplace_back(k, v.lastAccess);
                    std::sort(entries.begin(), entries.end(),
                        [](auto& a, auto& b) { return a.second < b.second; });

                    std::size_t toRemove = s_accums.size() - kMaxAccumEntries / 2;
                    for (std::size_t i = 0; i < toRemove && i < entries.size(); ++i)
                        s_accums.erase(entries[i].first);
                }

                std::lock_guard lk(s_accumMtx);
                ++s_accessGen;
                auto& acc = s_accums[a_this];
                acc.lastAccess = s_accessGen;

                if (acc.startOff != startOff || acc.totalSize != uncompSz) {
                    acc.startOff = startOff;
                    acc.totalSize = uncompSz;
                    acc.buf.clear();
                    if (uncompSz > 0 && uncompSz < 16 * 1024 * 1024)
                        acc.buf.reserve(uncompSz);
                }

                auto* data = static_cast<const std::uint8_t*>(a_buffer);
                acc.buf.insert(acc.buf.end(), data, data + a_read);

                if (acc.buf.size() >= uncompSz) {
                    dcache.RecordDecompressed(archive, startOff,
                        acc.buf.data(), static_cast<std::uint32_t>(acc.buf.size()));
                    s_accums.erase(a_this);
                }
            }
        }
    } else {
        s_ticksFallbackRead.fetch_add(dt, std::memory_order_relaxed);
    }

    s_fallbackReads.fetch_add(1, std::memory_order_relaxed);
    s_fallbackBytes.fetch_add(a_read, std::memory_order_relaxed);
    if (Settings::bEnableStats && isAsyncStream)
        s_asyncDoReadBytes.fetch_add(a_read, std::memory_order_relaxed);
    return err;
}

// ═════════════════════════════════════════════════════════════════════════════
// Hook 3: LocationTree::DoCreateStream — Detours factory hook
//
// Signature (from fo4_database.csv ID 476824):
//   ErrorCode __fastcall DoCreateStream(this, char* path,
//       BSTSmartPointer<Stream>& result, Location*& location,
//       bool writable, LocationTraverser* traverser)
using FactoryFunc_t = RE::BSResource::ErrorCode(__fastcall*)(
    void*, const char*, void*, void*, bool, void*);
static FactoryFunc_t s_origFactory = nullptr;

// Forward decl — implementation below alongside the chunk-factory overrides.
static bool InstallStreamOverride(
    void*                     stream,
    const BA2::MappedArchive* archive,
    const std::uint8_t*       data,
    std::uint32_t             size);

static RE::BSResource::ErrorCode __fastcall HookedFactory(
    void* a_this, const char* a_path, void* a_streamOut,
    void* a_locationOut, bool a_writable, void* a_traverser)
{
    // Count every entry, even before the orig call — so calls=0 proves
    // the hook isn't being reached at all (wrong target or not called).
    s_facCalls.fetch_add(1, std::memory_order_relaxed);

    auto ret = s_origFactory(a_this, a_path, a_streamOut, a_locationOut, a_writable, a_traverser);

    if (ret != RE::BSResource::ErrorCode::kNone || a_writable || Settings::bBaselineMode ||
        !Settings::bEnableMmap ||
        (Settings::bShortCircuitDuringSaveLoad &&
         s_saveLoadActive.load(std::memory_order_acquire)))
        return ret;

    auto* stream = *reinterpret_cast<RE::BSResource::Stream**>(a_streamOut);
    if (!stream || !IsArchiveReaderStream(stream)) {
        s_facRejStream.fetch_add(1, std::memory_order_relaxed);
        return ret;
    }

    auto* sourcePtr = ReadField<void*>(stream, Field::Source);
    if (!sourcePtr) {
        s_facRejSource.fetch_add(1, std::memory_order_relaxed);
        return ret;
    }

    const auto* archive = SourceLookup(sourcePtr);
    if (!archive) archive = ResolveSource(sourcePtr);
    if (!archive || !archive->IsOpen()) {
        s_facRejSource.fetch_add(1, std::memory_order_relaxed);
        return ret;
    }

    // Pre-populate stream→archive cache so the subsequent HookedDoRead calls
    // on this stream skip SourceLookup entirely.
    StreamArchiveInsert(stream, sourcePtr, archive);

    const auto compSize  = ReadField<std::uint32_t>(stream, Field::CompressedSize);
    const auto startOff  = ReadField<std::uint64_t>(stream, Field::StartOffset);
    const auto uncompSz  = ReadField<std::uint32_t>(stream, Field::UncompressedSize);

    // ── Uncompressed → in-place vtable swap over archive mmap ───────────
    // InstallStreamOverride keeps the game-allocated ReaderStream (its full
    // field layout + refcount + allocator ownership intact) and only swaps
    // vtable slots 0/6/7. No `new`-allocated substitute, no Buffout TBB /
    // BSTextureStreamerLocalHeap interaction — same pattern as task #75.
    //
    // Uncompressed only — see HookedBA2ChunkFactory for rationale: ReaderStream
    // sits below the inflate layer, so serving decompressed bytes for a
    // compressed entry breaks the contract — callers still feed those bytes
    // into zlib, which spins on garbage (manifests as multi-minute serve hang).
    // The compressed cache path is handled by HookedInflate fp-serve.
    if (Settings::bEnableMmap && Settings::iCacheDelivery == 0 && compSize == 0) {
        const auto* data = archive->At(startOff, uncompSz);
        if (data && InstallStreamOverride(stream, archive, data, uncompSz)) {
            s_streamReplacements.fetch_add(1, std::memory_order_relaxed);
            s_facServedMmap.fetch_add(1, std::memory_order_relaxed);
            s_mmapBytes.fetch_add(uncompSz, std::memory_order_relaxed);
        }
    }

    // ── Compressed + cache hit → substitute with cache-backed MmapStream ──
    // BSAMemoryMap-equivalent path (HookedCreateBsaStream). Engine never
    // enters its CompressedReaderStream pipeline; every DoRead is a memcpy
    // from the .decomp file mmap. Opt-in via bFactoryReplaceCompressed —
    // chunk-factory analog crashed when callers introspected ReaderStream
    // fields; HookedFactory's callers (BSResource location traversal) should
    // only use the abstract Stream API, but this is unproven on F4.
    if (Settings::bFactoryReplaceCompressed && Settings::bEnableDecompCache &&
        Settings::iCacheDelivery == 0 && compSize != 0)
    {
        auto& dcache = BA2::DecompCache::GetSingleton();
        if (dcache.IsReady()) {
            auto vbr = dcache.LookupViewBacked(archive,
                static_cast<std::uint32_t>(startOff));
            if (vbr && vbr.size == uncompSz) {
                // Capture name via DoGetName (vtable[0x0F]) before we drop
                // the engine's stream — name strings on ReaderStream live
                // in source-side state.
                RE::BSFixedString nameStr;
                using DoGetName_t = bool(*)(const void*, RE::BSFixedString*);
                auto* vtbl = *reinterpret_cast<std::uintptr_t**>(stream);
                auto getName = reinterpret_cast<DoGetName_t>(vtbl[0x0F]);
                getName(stream, &nameStr);

                auto* substitute = new BA2::MmapStream(
                    vbr.data, vbr.size, nameStr, archive,
                    std::move(vbr.view));

                // Engine wrote a smartptr to a_streamOut. reset() DecRefs
                // the engine's CompressedReaderStream (likely deleting it)
                // and adopts our substitute (already AddRef'd at refcount=1
                // by Stream's ctor).
                auto* sp = reinterpret_cast<RE::BSTSmartPointer<RE::BSResource::Stream>*>(a_streamOut);
                sp->reset(substitute);

                s_facReplaceCompressed.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    return ret;
}

// ═════════════════════════════════════════════════════════════════════════════
// Hook 3-NEW: BSResource::Archive2::ReaderStream::ReaderStream — primary ctor
//
// PDB-confirmed signature (8 explicit params + implicit `this`):
//   ReaderStream::ReaderStream(
//       this,                           // RCX
//       BSTSmartPointer<Stream>&,       // RDX  — populated to point at `this`
//       u64    offset,                  // R8
//       u32    compSize,                // R9
//       u32    uncompSize,              // [rsp+0x28]
//       BSFixedString& name,            // [rsp+0x30]
//       bool   flag1,                   // [rsp+0x38]
//       bool   flag2,                   // [rsp+0x40]
//       u8     flag3);                  // [rsp+0x48]
//
// Per-runtime ctor RVAs (from Microsoft/F4SE PDB exports):
//   OG  1.10.163 → 0x01B703C0
//   VR  1.2.72   → 0x01BEF7D0
//   NG  1.10.984 → resolved by vtable xref scan (REL::ID 218182)
//   AE  1.11.191 → resolved by vtable xref scan (REL::ID 218182)
//
// Hooking the ctor is preferred over LocationTree::DoCreateStream because
// every BA2-backed stream allocation funnels through this single ctor —
// the LocationTree path catches only the file-system lookup variant, missing
// archive-direct callers from BGSInventory, Quest, Havok, Nif, etc.
// ═════════════════════════════════════════════════════════════════════════════
using ReaderStreamCtor_t = void(__fastcall*)(
    void*           /*this*/,
    void*           /*smartPtrOut*/,
    std::uint64_t   /*offset*/,
    std::uint32_t   /*compSize*/,
    std::uint32_t   /*uncompSize*/,
    void*           /*name*/,
    bool            /*flag1*/,
    bool            /*flag2*/,
    std::uint8_t    /*flag3*/);
static ReaderStreamCtor_t s_origReaderStreamCtor = nullptr;

// Thread-local recursion guard. The ctor is called from many more sites than
// LocationTree::DoCreateStream (including paths inside the game's own resource
// loaders), so some callers may hold locks that our post-processing cannot
// safely re-enter. On any nested entry we forward to the original and return
// without touching the smart pointer.
static thread_local int s_ctorDepth = 0;

static void __fastcall HookedReaderStreamCtor(
    void*           a_this,
    void*           a_smartPtrOut,
    std::uint64_t   a_offset,
    std::uint32_t   a_compSize,
    std::uint32_t   a_uncompSize,
    void*           a_name,
    bool            a_flag1,
    bool            a_flag2,
    std::uint8_t    a_flag3)
{
    ++s_ctorDepth;
    struct DepthGuard { ~DepthGuard() { --s_ctorDepth; } } _depthGuard;

    s_facCalls.fetch_add(1, std::memory_order_relaxed);

    // Forward unchanged — original ctor fully initializes the ReaderStream
    // and binds the smart pointer to it (refcount = 1).
    s_origReaderStreamCtor(a_this, a_smartPtrOut, a_offset, a_compSize,
                           a_uncompSize, a_name, a_flag1, a_flag2, a_flag3);

    if (Settings::bBaselineMode || !Settings::bEnableMmap) return;

    // Skip post-processing on nested entries — caller may hold a lock that
    // ResolveSource (DoGetName virtual call) or the heap allocator would
    // re-enter. Outer call will still get a chance via subsequent ctors.
    if (s_ctorDepth > 1) return;

    if (!IsArchiveReaderStream(a_this)) {
        s_facRejStream.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    auto* sourcePtr = ReadField<void*>(a_this, Field::Source);
    if (!sourcePtr) {
        s_facRejSource.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // Cache-only lookup — never call ResolveSource from the ctor path. The
    // DoGetName virtual call inside ResolveSource may acquire a BSResource
    // mutex that the ctor's caller already holds, deadlocking the IO thread.
    // HookedDoRead populates the cache on first read of each source, so the
    // second stream from any archive will hit the cache and get replaced.
    const auto* archive = SourceLookup(sourcePtr);
    if (!archive || !archive->IsOpen()) {
        s_facRejSource.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // Pre-populate stream→archive cache so HookedDoRead skips source lookup.
    StreamArchiveInsert(a_this, sourcePtr, archive);

    // Read the freshly-constructed fields directly from the stream (don't trust
    // the param interpretation — the field layout is already version-resolved).
    const auto compSize = ReadField<std::uint32_t>(a_this, Field::CompressedSize);
    const auto startOff = ReadField<std::uint64_t>(a_this, Field::StartOffset);
    const auto uncompSz = ReadField<std::uint32_t>(a_this, Field::UncompressedSize);

    // In-place vtable swap — uncompressed only. See HookedFactory rationale:
    // serving decompressed bytes for compressed entries hangs the inflate path.
    if (Settings::bEnableMmap && Settings::iCacheDelivery == 0 && compSize == 0) {
        const auto* data = archive->At(startOff, uncompSz);
        if (data && InstallStreamOverride(a_this, archive, data, uncompSz)) {
            s_streamReplacements.fetch_add(1, std::memory_order_relaxed);
            s_facServedMmap.fetch_add(1, std::memory_order_relaxed);
            s_mmapBytes.fetch_add(uncompSz, std::memory_order_relaxed);
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Chunk-factory stream vtable override
//
// Task #75 replacement strategy. The earlier `new MmapStream` approach
// crashed under bChunkFactoryReplace because a C++-allocated MmapStream does
// not match the canonical 0x48-byte ReaderStream layout the factory's
// callers assume — specifically +0x10/+0x40 field semantics, which the game
// allocator + post-ctor factory writes produce. Fix: keep the orig factory
// result (its layout is already correct, including +0x40) and swap ONLY the
// vtable pointer at stream[+0x00] to a cloned vtable whose DoRead / DoReadAt
// / dtor serve from a side table. All other slots tail-call the original
// ReaderStream vtable — the 15 factory callers are hash-inserters that never
// touch DoSeek / tagged reads / DoWaitTags on these streams, per Ghidra RE.
//
// The intrusive refcount in StreamBase::flags (inside the 0x48 struct) is
// untouched — only the 8-byte vtable pointer at offset 0 is swapped, so
// AddRef / DecRef by the smart-ptr helper still target the correct field.
// ═════════════════════════════════════════════════════════════════════════════

static constexpr std::size_t kOverrideSlotCount = 24;  // bounded by Stream vtable (~20 slots)
alignas(std::uintptr_t) static std::uintptr_t s_overrideVtbl[kOverrideSlotCount];
static std::atomic<bool>                      s_overrideVtblReady{ false };
static std::uintptr_t                         s_overrideVtblOrig{ 0 };

struct ReaderStreamOverrideEntry {
    const BA2::MappedArchive*   archive;
    const std::uint8_t*         data;
    std::uint32_t               size;
    std::atomic<std::uint32_t>  cursor;
    std::uintptr_t              origVtbl;  // to restore in dtor before orig call
    // Back-pointer to the owning stream. Set in InstallStreamOverride, cleared
    // to nullptr in OverrideDtor. TLS fast path requires
    // `entry->stream.load() == self` so a stream address reused by the engine
    // after free doesn't match against a stale leaked entry.
    std::atomic<void*>          stream;
};

// Sharded per-stream lookup — N shards each with own mutex + map. Same
// leak-on-overwrite / leak-on-dtor semantics per shard as the single-shard
// predecessor (heap block leaks; map slot drops on dtor). Spreads lock
// contention across threads when many streams get torn down / created
// concurrently. TLS fast path in OverrideDoRead catches the common case
// without touching any shard — sharding only matters on TLS miss.
struct OverrideShard {
    std::mutex mu;
    std::unordered_map<void*, ReaderStreamOverrideEntry*> map;
};
static constexpr int kOverrideShardBits = 4;                         // 16 shards
static constexpr std::uintptr_t kOverrideShardMask = (1ull << kOverrideShardBits) - 1;
static OverrideShard s_overrideShards[1 << kOverrideShardBits];

static inline OverrideShard& ShardFor(void* stream) {
    // Drop low alignment bits — CRT 8/16-byte alignment zeros the bottom nibble
    // and would collapse all streams into one shard. Shift-right first.
    auto h = reinterpret_cast<std::uintptr_t>(stream) >> 4;
    return s_overrideShards[h & kOverrideShardMask];
}

// Thread-local one-slot cache. The engine's dominant DoRead pattern is
// same-stream-back-to-back (tight chunk loops), so skipping the shard mutex
// + hashmap lookup on a match collapses hot-path cost to a single pointer
// compare. Entries are never freed (leak-on-dtor), so a stale cached ptr
// stays dereferenceable until the worker thread touches a different stream.
thread_local void*                      t_lastStream = nullptr;
thread_local ReaderStreamOverrideEntry* t_lastEntry  = nullptr;

// Counters (s_overrideInstalled / DoReadCalls / DoReadBytes / Dtors /
// UnregisterMiss / RejVtbl) are declared earlier alongside s_cfCalls so they
// are visible to the stats log formatter.

static ReaderStreamOverrideEntry* OverrideLookupLocked(OverrideShard& sh, void* stream)
{
    auto it = sh.map.find(stream);
    return (it != sh.map.end()) ? it->second : nullptr;
}

// ── Override vtable slot implementations ─────────────────────────────────────

// Slot 0: scalar-deleting dtor. MSVC calling convention: void(T*, u32 flag).
// We restore the orig vtable on `self`, unregister, then tail-call orig dtor.
// Leak-on-dtor: the entry's heap allocation is intentionally NOT freed, so
// any thread-local cached pointer to it (see t_lastEntry above) stays
// dereferenceable indefinitely.
static void __fastcall OverrideDtor(void* self, std::uint32_t freeFlag)
{
    std::uintptr_t origVtbl = 0;
    ReaderStreamOverrideEntry* entry = nullptr;
    {
        auto& sh = ShardFor(self);
        std::lock_guard lk(sh.mu);
        auto it = sh.map.find(self);
        if (it != sh.map.end()) {
            entry    = it->second;
            origVtbl = entry->origVtbl;
            sh.map.erase(it);   // drop map slot; entry heap block leaked
        }
    }
    // Publish dead-entry marker so any OTHER thread's stale TLS fast path
    // rejects this leaked entry even if the stream address gets recycled.
    if (entry) entry->stream.store(nullptr, std::memory_order_release);
    // Clear our own thread-local cache if it was pointing at this stream.
    if (self == t_lastStream) {
        t_lastStream = nullptr;
        t_lastEntry  = nullptr;
    }
    if (!origVtbl) {
        s_overrideUnregisterMiss.fetch_add(1, std::memory_order_relaxed);
        origVtbl = s_overrideVtblOrig;
    }
    if (origVtbl) {
        *reinterpret_cast<std::uintptr_t*>(self) = origVtbl;
        auto origDtor = reinterpret_cast<void(__fastcall*)(void*, std::uint32_t)>(
            reinterpret_cast<std::uintptr_t*>(origVtbl)[0]);
        s_overrideDtors.fetch_add(1, std::memory_order_relaxed);
        origDtor(self, freeFlag);
    }
}

// Slot 6: DoRead — serves bytes from (data, size) using cursor.
static RE::BSResource::ErrorCode __fastcall OverrideDoRead(
    void* self, void* buffer, std::uint64_t toRead, std::uint64_t& read)
{
    const bool timing = Settings::bEnableStats;
    LARGE_INTEGER t0{};
    if (timing) QueryPerformanceCounter(&t0);

    // Thread-local fast path — same-stream-back-to-back skips the mutex and
    // the hashmap lookup. Entries are never freed, but the dtor clears
    // `entry->stream` to nullptr — so when a stream address gets recycled by
    // the engine, the stale entry's back-pointer check rejects it and we
    // fall through to the map lookup for the new (correct) entry.
    ReaderStreamOverrideEntry* entry = nullptr;
    if (self == t_lastStream && t_lastEntry &&
        t_lastEntry->stream.load(std::memory_order_acquire) == self) {
        entry = t_lastEntry;
    }
    if (!entry) {
        auto& sh = ShardFor(self);
        std::lock_guard lk(sh.mu);
        entry = OverrideLookupLocked(sh, self);
        if (entry) {
            t_lastStream = self;
            t_lastEntry  = entry;
        }
    }
    if (!entry) { read = 0; return RE::BSResource::ErrorCode::kFileError; }

    const auto cur = entry->cursor.load(std::memory_order_relaxed);
    if (cur >= entry->size) { read = 0; return RE::BSResource::ErrorCode::kNone; }

    const auto remaining = entry->size - cur;
    const auto n = (toRead < remaining) ? static_cast<std::uint32_t>(toRead) : remaining;
    if (n > 0) {
        BA2::FastCopyLarge(buffer, entry->data + cur, n);
        entry->cursor.fetch_add(n, std::memory_order_relaxed);
        s_overrideDoReadBytes.fetch_add(n, std::memory_order_relaxed);
    }
    s_overrideDoReadCalls.fetch_add(1, std::memory_order_relaxed);
    read = n;

    if (timing) {
        LARGE_INTEGER t1; QueryPerformanceCounter(&t1);
        const int b = BA2::MmapSizeBucket(n);
        BA2::g_mmapDoReadCalls[b].fetch_add(1, std::memory_order_relaxed);
        BA2::g_mmapDoReadNs[b].fetch_add(
            static_cast<std::uint64_t>(
                (t1.QuadPart - t0.QuadPart) * 1000000000LL / s_qpcFreq),
            std::memory_order_relaxed);
    }
    return RE::BSResource::ErrorCode::kNone;
}

// Slot 7: DoReadAt — serves bytes at absolute position (no cursor change).
static RE::BSResource::ErrorCode __fastcall OverrideDoReadAt(
    void* self, void* buffer, std::uint64_t toRead, std::uint64_t pos, std::uint64_t& read)
{
    ReaderStreamOverrideEntry* entry = nullptr;
    if (self == t_lastStream && t_lastEntry &&
        t_lastEntry->stream.load(std::memory_order_acquire) == self) {
        entry = t_lastEntry;
    }
    if (!entry) {
        auto& sh = ShardFor(self);
        std::lock_guard lk(sh.mu);
        entry = OverrideLookupLocked(sh, self);
        if (entry) {
            t_lastStream = self;
            t_lastEntry  = entry;
        }
    }
    if (!entry) { read = 0; return RE::BSResource::ErrorCode::kFileError; }

    if (pos >= entry->size) { read = 0; return RE::BSResource::ErrorCode::kNone; }
    const auto remaining = entry->size - static_cast<std::uint32_t>(pos);
    const auto n = (toRead < remaining) ? static_cast<std::uint32_t>(toRead) : remaining;
    if (n > 0) BA2::FastCopyLarge(buffer, entry->data + pos, n);
    s_overrideDoReadCalls.fetch_add(1, std::memory_order_relaxed);
    s_overrideDoReadBytes.fetch_add(n, std::memory_order_relaxed);
    read = n;
    return RE::BSResource::ErrorCode::kNone;
}

// Build the clone vtable from the ReaderStream vtable the orig stream carries.
// Runs once — s_overrideVtbl is shared across all swapped instances.
static bool InitOverrideVtbl(std::uintptr_t origVtbl)
{
    if (s_overrideVtblReady.load(std::memory_order_acquire)) return true;
    if (!origVtbl) return false;

    auto* src = reinterpret_cast<std::uintptr_t*>(origVtbl);
    for (std::size_t i = 0; i < kOverrideSlotCount; ++i)
        s_overrideVtbl[i] = src[i];

    s_overrideVtbl[0] = reinterpret_cast<std::uintptr_t>(&OverrideDtor);
    s_overrideVtbl[6] = reinterpret_cast<std::uintptr_t>(&OverrideDoRead);
    s_overrideVtbl[7] = reinterpret_cast<std::uintptr_t>(&OverrideDoReadAt);

    s_overrideVtblOrig = origVtbl;
    s_overrideVtblReady.store(true, std::memory_order_release);
    return true;
}

// Register a stream in the side table and swap its vtable pointer. Returns
// true on success. The caller guarantees `stream` was just returned by the
// orig factory (so all ReaderStream fields are valid).
static bool InstallStreamOverride(
    void*                     stream,
    const BA2::MappedArchive* archive,
    const std::uint8_t*       data,
    std::uint32_t             size)
{
    if (!stream || !data) return false;

    const auto origVtbl = *reinterpret_cast<std::uintptr_t*>(stream);

    // Refuse to swap when the stream's current vtable isn't inside the game's
    // own .rdata. Another plugin may have replaced the vtable pointer with one
    // pointing to its own code / data — cloning that would inherit its slots
    // and later dispatch through its (possibly stale) function pointers.
    // Skyrim BSAMemoryMap 1.5.0 hit this with ODF.
    if (s_rdataStart && (origVtbl < s_rdataStart || origVtbl >= s_rdataEnd)) {
        s_overrideRejVtbl.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    if (!InitOverrideVtbl(origVtbl)) return false;

    // Raw `new` — intentional leak-on-dtor / leak-on-overwrite policy so
    // thread-local fast-path pointers (t_lastEntry) remain dereferenceable.
    auto* entry = new ReaderStreamOverrideEntry();
    entry->archive  = archive;
    entry->data     = data;
    entry->size     = size;
    entry->cursor.store(0, std::memory_order_relaxed);
    entry->origVtbl = origVtbl;
    entry->stream.store(stream, std::memory_order_release);

    {
        auto& sh = ShardFor(stream);
        std::lock_guard lk(sh.mu);
        // Overwrite any stale entry at this address — previous block leaks.
        // (Should be rare: dtor path erases its own slot before freeing.)
        sh.map[stream] = entry;
    }

    // Single aligned 8-byte store — atomic on x64.
    *reinterpret_cast<std::uintptr_t*>(stream) =
        reinterpret_cast<std::uintptr_t>(&s_overrideVtbl[0]);

    s_overrideInstalled.fetch_add(1, std::memory_order_relaxed);
    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
// Hook 3-CHUNK: BSResource::Archive2 BA2-chunk factory (inlined primary ctor)
//
// Ghidra-identified target on AE 1.11.191: FUN_14169e3b0 (static 0x14169e3b0).
// MSVC inlined the out-of-line ReaderStream ctor into ~14 callsites, so the
// Hook 3-NEW target has zero code callers and never fires. This is the next
// shared funnel up — the single BA2-chunk factory that ~15 resource-cache
// inserters call (textures, inventory, mesh, material, script, animation,
// terrain, sound, …).
//
// Prototype (from Ghidra decomp):
//   bool Factory(ReaderStreamDescriptor* desc /*RCX*/,
//                SmartPtr<ReaderStream>* outSp /*RDX*/);
// On success, *outSp holds a smart-pointer whose offset 0 = ReaderStream*.
//
// Monitor-only by default — see Settings::bUseChunkFactoryHook. We populate
// s_streamHash (stream, source, archive) and return. When bChunkFactoryReplace
// is enabled, cacheable streams also get a vtable swap (see block above) that
// routes DoRead through mmap / decomp cache without allocating a new object.
// ═════════════════════════════════════════════════════════════════════════════
using BA2ChunkFactory_t = bool(__fastcall*)(void* /*desc*/, void* /*outSp*/);
static BA2ChunkFactory_t s_origBA2ChunkFactory = nullptr;
static thread_local int  s_cfDepth             = 0;

static bool __fastcall HookedBA2ChunkFactory(void* a_desc, void* a_outSp)
{
    ++s_cfDepth;
    struct DepthGuard { ~DepthGuard() { --s_cfDepth; } } _depthGuard;

    s_cfCalls.fetch_add(1, std::memory_order_relaxed);

    const bool ok = s_origBA2ChunkFactory(a_desc, a_outSp);

    if (Settings::bBaselineMode) return ok;
    if (s_cfDepth > 1)           return ok;   // re-entry: caller may hold locks

    if (!ok || !a_outSp) { s_cfRejOk.fetch_add(1, std::memory_order_relaxed); return ok; }

    // Extract raw stream pointer from smart-pointer slot 0.
    auto* stream = *reinterpret_cast<void**>(a_outSp);
    if (!stream) { s_cfRejOk.fetch_add(1, std::memory_order_relaxed); return ok; }

    if (!IsArchiveReaderStream(stream)) {
        s_cfRejStream.fetch_add(1, std::memory_order_relaxed);
        return ok;
    }

    auto* sourcePtr = ReadField<void*>(stream, Field::Source);
    if (!sourcePtr) {
        s_cfRejSrc.fetch_add(1, std::memory_order_relaxed);
        return ok;
    }

    // Cache-only lookup — don't call ResolveSource here. The factory runs
    // under BSResource locks, and DoGetName inside ResolveSource could
    // re-enter them. HookedDoRead populates the source cache on first read,
    // so later streams for the same archive will hit.
    const auto* archive = SourceLookup(sourcePtr);
    if (!archive || !archive->IsOpen()) {
        s_cfRejSrc.fetch_add(1, std::memory_order_relaxed);
        return ok;
    }

    StreamArchiveInsert(stream, sourcePtr, archive);
    s_cfInsert.fetch_add(1, std::memory_order_relaxed);

    // Optional in-place stream override — task #75. The orig factory already
    // ran, so the ReaderStream's fields (including post-ctor writes like +0x40)
    // are intact. We only swap the vtable pointer at stream[+0x00] to route
    // DoRead through the mmap side table. No new allocation, no layout
    // mismatch, no refcount-slot confusion. Gated by bChunkFactoryReplace.
    if (!Settings::bChunkFactoryReplace) return ok;

    const auto compSize = ReadField<std::uint32_t>(stream, Field::CompressedSize);
    const auto startOff = ReadField<std::uint64_t>(stream, Field::StartOffset);
    const auto uncompSz = ReadField<std::uint32_t>(stream, Field::UncompressedSize);

    // Uncompressed only. ReaderStream sits below the inflate layer, so serving
    // decompressed bytes for a compressed entry would break the contract —
    // callers still expect to drive zlib themselves. The existing inflate-level
    // hook handles the compressed path without layering concerns.
    if (compSize != 0) return ok;

    const auto* data = archive->At(startOff, uncompSz);
    if (data && InstallStreamOverride(stream, archive, data, uncompSz)) {
        s_streamReplacements.fetch_add(1, std::memory_order_relaxed);
        s_facServedMmap.fetch_add(1, std::memory_order_relaxed);
        s_mmapBytes.fetch_add(uncompSz, std::memory_order_relaxed);
    }
    return ok;
}

// Locate FUN_14169e3b0-equivalent by scanning .text for the distinctive
// prologue:
//   48 89 54 24 10        mov [rsp+10h], rdx      ; save outSp to home slot
//   53 55 56 57           push rbx, rbp, rsi, rdi
//   41 56 41 57           push r14, r15
//   48 83 EC 48           sub rsp, 48h
// Requires the preceding byte be 0xCC (function boundary) to avoid mid-code
// false positives. Returns 0 on zero matches or when multiple matches exist
// (ambiguity — caller should fall back to the ctor scan).
static std::uintptr_t ScanForBA2ChunkFactory()
{
    static constexpr std::uint8_t kProlog[] = {
        0x48, 0x89, 0x54, 0x24, 0x10,
        0x53, 0x55, 0x56, 0x57,
        0x41, 0x56, 0x41, 0x57,
        0x48, 0x83, 0xEC, 0x48
    };
    constexpr std::size_t kLen = sizeof(kProlog);

    auto textSeg  = REL::Module::get().segment(REL::Segment::text);
    auto* textBase = reinterpret_cast<const std::uint8_t*>(textSeg.address());
    const auto textSize = textSeg.size();
    const auto textVA   = textSeg.address();

    std::vector<std::uintptr_t> hits;
    for (std::size_t i = 1; i + kLen < textSize; ++i) {
        if (textBase[i - 1] != 0xCC) continue;
        if (std::memcmp(textBase + i, kProlog, kLen) != 0) continue;
        hits.push_back(textVA + i);
        if (hits.size() > 4) break;  // more than unique → bail early
    }

    if (hits.size() == 1) return hits[0];

    if (!hits.empty()) {
        char msg[160];
        std::snprintf(msg, sizeof(msg),
            "FFC4: BA2 chunk factory scan ambiguous — %zu candidates", hits.size());
        LogWarn(msg);
    }
    return 0;
}

// ═════════════════════════════════════════════════════════════════════════════
// Texture streamer hooks — extends the decomp cache to DX10 texture BA2s
//
// Fallout 4 has two completely separate BA2 access paths:
//   - BSResource::Archive2 (GNRL: meshes/scripts/sounds/UI) — handled by the
//     DoRead + factory hooks above via per-entry ReaderStream objects.
//   - BSTextureStreamer (DX10 textures) — bypasses ReaderStream entirely. Each
//     .ba2 is registered as a single shared BSResource::Stream via
//     BSTextureIndex::Index::AddDataFile, and the streamer thread pipes chunks
//     from that stream through zlibStreamDetail::Inflate → global inflate().
//
// Bridge path → stream → archive via two hooks:
//   1. AddDataFile fires during Archive2::Register's synchronous event
//      dispatch. Its `sp` arg is the stack-allocated BTDX RegisteredEvent,
//      whose layout (decoded from Register's decomp) is:
//          +0x00  BSResource::Stream*  source stream
//          +0x20  BSResource::ID       (16 bytes)
//          +0x30  char*                path (caller-owned, still live)
//          +0x38  u32                  format fourcc ("DX10" = 0x30315844)
//      So we read path from event+0x30 and stream from event+0x00 in one
//      hook — no Archive2::Register hook, no TLS.
//   2. StartNextFetch fires per-chunk on the streamer thread; look up source
//      (ReadState+0x10) in the registry, compute chunk offset from
//      stream->chunks[effIdx].fileOffset, and BridgeSet the decomp-cache
//      lookup. Existing HookedInflate serves automatically on the same
//      thread.
//
// Per-mip granularity is free: each DX10 chunk has its own fileOffset, so the
// (archive, fileOffset) cache key naturally separates individual mip levels.
// ═════════════════════════════════════════════════════════════════════════════

// Registry: BSResource::Stream* (per-.ba2 shared stream) → MappedArchive.
static std::unordered_map<const void*, const BA2::MappedArchive*> s_texRegistry;
static std::mutex s_texRegistryMtx;

// (Counters s_texRegistered, s_texUnresolved, s_texFetches, s_texBridgeSet,
// s_texCacheMiss are defined at the top of the file alongside s_facCalls etc.
// so they're visible to OnPostLoadGame without a forward declaration.)

static const BA2::MappedArchive* TextureRegistryLookup(const void* streamPtr)
{
    std::lock_guard lk(s_texRegistryMtx);
    auto it = s_texRegistry.find(streamPtr);
    return (it != s_texRegistry.end()) ? it->second : nullptr;
}

// Collect unique archives from the texture registry (for PreloadState scan).
static std::vector<const BA2::MappedArchive*> TextureRegistryArchives()
{
    std::lock_guard lk(s_texRegistryMtx);
    std::vector<const BA2::MappedArchive*> out;
    out.reserve(s_texRegistry.size());
    for (const auto& [_, arc] : s_texRegistry) {
        if (arc && arc->IsOpen() &&
            std::find(out.begin(), out.end(), arc) == out.end())
            out.push_back(arc);
    }
    return out;
}

// ── Hook T1: BSTextureIndex::Index::AddDataFile — registers stream ptr ──────
// Signature: void AddDataFile(this, BSTSmartPointer<Stream>& sp, ID& id, u32 idx)
//
// The decomp of BSTextureStreamer::Manager::ProcessEvent shows:
//   AddDataFile(mgr, event, event+0x20, idx)
// So `sp` is the raw BTDX RegisteredEvent struct — its +0x00 slot is the
// source BSResource::Stream* (what ProcessEvent treats as the smart-ptr),
// and +0x30 is the original `char* path` passed to Archive2::Register.
// Both are valid here because event dispatch is synchronous (Register
// constructs the event on its own stack and waits for SendEvent to return).
using TextureAddDataFile_t = void (__fastcall*)(void*, void*, void*, std::uint32_t);
static TextureAddDataFile_t s_origTextureAddDataFile = nullptr;

static void __fastcall HookedTextureAddDataFile(
    void* a_this, void* a_event, void* a_id, std::uint32_t a_idx)
{
    s_origTextureAddDataFile(a_this, a_event, a_id, a_idx);

    if (!a_event) return;

    auto* eventBytes = static_cast<std::uint8_t*>(a_event);
    auto* streamPtr  = *reinterpret_cast<void**>(eventBytes);        // +0x00
    const char* path = *reinterpret_cast<const char**>(eventBytes + 0x30);
    if (!streamPtr || !path || reinterpret_cast<std::uintptr_t>(path) < 0x10000)
        return;

    std::filesystem::path p;
    try { p = std::filesystem::path(path); } catch (...) { return; }
    auto fname = p.filename().string();
    if (fname.empty()) return;

    const auto* archive = BA2::MemoryMapManager::GetSingleton().FindByName(fname);
    if (!archive || !archive->IsOpen()) {
        s_texUnresolved.fetch_add(1, std::memory_order_relaxed);
        char msg[256];
        std::snprintf(msg, sizeof(msg),
            "FFC4 tex: AddDataFile saw %s but no MappedArchive", fname.c_str());
        LogInfo(msg);
        return;
    }

    {
        std::lock_guard lk(s_texRegistryMtx);
        s_texRegistry[streamPtr] = archive;
    }
    s_texRegistered.fetch_add(1, std::memory_order_relaxed);

    char msg[256];
    std::snprintf(msg, sizeof(msg),
        "FFC4 tex: registered stream %p -> %s", streamPtr, fname.c_str());
    LogInfo(msg);
}

// ── Hook T2: BSTextureStreamer::ReadState::StartNextFetch — bridge for cache ─
// Verified signature (F4VR PDB + Ghidra decomp at 0x141D2FEC0):
//   void StartNextFetch(ReadState* this, BSTextureStreamer::Stream* stream)
//
// ReadState fields:
//   +0x10  BSResource::Stream*  source      (registered per-.ba2)
//   +0x20  u64                  curFileOff  (running position, advances per read)
//   +0x3c  u32                  bytesRem    (bytes remaining in current chunk)
//   +0x58  u32                  chunksRem   (chunks remaining inc. current)
//   +0x5c  u32                  curIdx      (current chunk index)
//
// Stream fields (param_2 of StartNextFetch):
//   [0]    StreamDetailI*  (decompressor)
//   [1]    DX10Chunk*      base of chunks array (stride 0x18)
//            +0x00 u64 fileOffset
//            +0x08 u32 compSize
//            +0x0c u32 uncompSize
//
// Advance semantics (from decomp):
//   if (bytesRem == 0) {
//       --chunksRem;
//       if (chunksRem != 0) {  // still has chunks to fetch
//           ++curIdx;
//           bytesRem   = chunks[curIdx].compSize;
//           curFileOff = chunks[curIdx].fileOffset;
//       }
//   }
//   // read transferSz bytes from source at curFileOff, then:
//   bytesRem   -= transferSz;
//   curFileOff += transferSz;
//
// Because curFileOff advances WITHIN a chunk, we cannot use ReadState+0x20 as
// the cache key. Instead we compute chunks[effectiveIdx].fileOffset, where
// effectiveIdx is the chunk that will be read by THIS call — curIdx if mid-
// chunk (bytesRem > 0), or curIdx + 1 if we're about to advance (bytesRem == 0
// AND chunksRem > 1 after decrement; the decomp checks `--chunksRem != 0`).
using StartNextFetch_t = void (__fastcall*)(void*, void*);
static StartNextFetch_t s_origStartNextFetch = nullptr;

static void __fastcall HookedStartNextFetch(void* a_readState, void* a_stream)
{
    std::uint32_t bridgeSeq = 0;

    const bool saveLoadShortCircuit = Settings::bShortCircuitDuringSaveLoad &&
        s_saveLoadActive.load(std::memory_order_acquire);

    // With bHighLevelTexServe on, the dispatcher hook owns texture serve and
    // this per-chunk BridgeSet must stay dormant: fall-through reads need
    // stock timing (no Z_STREAM_END short-circuit) to avoid the Buffout4
    // LocalHeap / SmallBlockAllocator uninit-read races on VR.
    if (a_readState && a_stream && Settings::bEnableDecompCache &&
        !Settings::bHighLevelTexServe && !saveLoadShortCircuit) {
        auto* state = static_cast<std::uint8_t*>(a_readState);
        auto* source = *reinterpret_cast<void**>(state + 0x10);
        if (source) {
            const auto* archive = TextureRegistryLookup(source);
            if (archive && archive->IsOpen()) {
                const auto bytesRem  = *reinterpret_cast<std::uint32_t*>(state + 0x3c);
                const auto chunksRem = *reinterpret_cast<std::uint32_t*>(state + 0x58);
                const auto curIdx    = *reinterpret_cast<std::uint32_t*>(state + 0x5c);

                // Work out which chunk this call will read. Mid-chunk: curIdx.
                // Advance case: curIdx + 1 (but only if a next chunk exists —
                // the decomp decrements chunksRem first and only advances if
                // the post-decrement value is still non-zero).
                std::uint32_t effIdx = curIdx;
                bool havePending = true;
                if (bytesRem == 0) {
                    if (chunksRem > 1) {
                        effIdx = curIdx + 1;
                    } else {
                        havePending = false;
                    }
                }

                if (havePending) {
                    // stream[1] is the chunks array base (DX10Chunk*, stride 0x18).
                    auto** streamArr = reinterpret_cast<void**>(a_stream);
                    auto* chunksBase = reinterpret_cast<std::uint8_t*>(streamArr[1]);
                    if (chunksBase) {
                        auto chunkFileOff = *reinterpret_cast<std::uint64_t*>(
                            chunksBase + static_cast<std::size_t>(effIdx) * 0x18);

                        auto& dcache = BA2::DecompCache::GetSingleton();
                        if (dcache.IsReady()) {
                            auto lr = dcache.Lookup(archive,
                                static_cast<std::uint32_t>(chunkFileOff));
                            s_texFetches.fetch_add(1, std::memory_order_relaxed);
                            if (lr) {
                                BridgeSet(lr, /*fromTex=*/true);
                                auto tid = GetCurrentThreadId();
                                bridgeSeq = s_inflateBridge[tid & kBridgeMask]
                                                .sequence.load(std::memory_order_relaxed);
                                s_texBridgeSet.fetch_add(1, std::memory_order_relaxed);
                            } else {
                                s_texCacheMiss.fetch_add(1, std::memory_order_relaxed);
                            }
                        }
                    }
                }
            }
        }
    }

    s_origStartNextFetch(a_readState, a_stream);

    if (bridgeSeq != 0) BridgeClear(bridgeSeq);
}

// ── AE variant: runtime-discovered stream->vtbl[0x60] inflate hook ─────────
//
// AE (Fallout4.exe 1.11.x) has no standalone BSTextureIndex::Index::AddDataFile
// and its per-chunk dispatcher (FUN_1417cdb80 @ 0x1417cdb80) loops over
// multiple chunks in one call, so the F4VR StartNextFetch-entry strategy
// doesn't map. Instead we:
//
//   1. Hook BSTextureStreamer::Manager::ProcessEvent (DX10 sink, 0x1417cc2b0).
//      On return, the event's source stream is stored in Manager+0x98d88.
//      We read *a_event (source BSResource::Stream*) and use it to runtime-
//      discover the stream class's vtbl[0x60] = per-chunk inflate entry
//      point, then Detour-hook it exactly once (CAS guard).
//   2. HookedStreamInflate receives (stream, dst, uncompSize, fileOffset, …)
//      per chunk. It looks up the archive via ResolveSource (which asks the
//      stream its own name via DoGetName @ vtbl[0x0F] — same path as GNRL),
//      probes the decomp cache at fileOffset, and on hit BridgeSets the
//      global HookedInflate bridge. The original vtbl[0x60] then drives
//      zlib inflate, which HookedInflate serves from the cache.
//
// Every texture BA2 source stream shares one class vtable, so the single
// vtbl[0x60] Detour covers all instances.
using StreamInflate_t = std::uint32_t (__fastcall*)(
    void*, void*, std::uint32_t, std::uint64_t,
    std::uint32_t, std::uint32_t*, std::uint32_t*, void*);
static StreamInflate_t s_origStreamInflate = nullptr;
static std::atomic<bool> s_streamInflateInstalled{ false };
static std::mutex s_streamInflateInstallMtx;

using TexProcessEvent_t = std::uint64_t (__fastcall*)(void*, void**);
static TexProcessEvent_t s_origTexProcessEvent = nullptr;

// Direct-serve on cache hit without touching vtbl[0x68]. How this works:
//
// BSTextureStreamer::ReadState::StartNextFetch zeros the outPosLo/outPosHi
// slot pair, then calls reader->vtbl[0x60] (us). The wrapper at 0x1416aefe0
// delegates to a ring-buffer submit (FUN_1416840e0) that increments
// *a_outPosHi by 1 per chunk submitted and queues work on a background IO
// thread. ReadMipsToTexture later calls reader->vtbl[0x68](&outPosLo, *outPosHi, ...)
// which ends up in FUN_141686400 (wait worker). The wait worker's very
// first branch is "if *outPosLoPtr >= outPosHiVal, return immediately" —
// no critical section, no event, no blocking call, nothing.
//
// So the direct-serve recipe is: memcpy cached bytes into a_dst, DO NOT
// call the original vtbl[0x60] (so outPosHi never gets bumped), and return.
// Both outPosLo and outPosHi stay at 0 (the post-StartNextFetch state),
// satisfying *outPosLo(0) >= outPosHi(0). The subsequent unmodified
// vtbl[0x68] call on that slot falls through its early-return branch.
//
// Size guard: only direct-serve if cached entry size exactly matches
// a_uncompSize. Mismatch would corrupt textures, so we fall through to
// the original scheduler and cache remains silently unused for that call.
static std::uint32_t __fastcall HookedStreamInflate(
    void* a_stream, void* a_dst, std::uint32_t a_packedSize, std::uint64_t a_fileOffset,
    std::uint32_t a_flags, std::uint32_t* a_outPosLo, std::uint32_t* a_outPosHi, void* a_mgrState)
{
    // vtbl[0x60] is a fire-and-forget scheduler on AE — a BridgeSet here
    // would race across threads (the inflate that consumes the bridge runs
    // on a different IO worker than the slot owner). AE serves happen in
    // HookedInflate via fingerprint matching; this hook was previously
    // doing 3000+ resolve+lookup calls per save load with no useful output.
    // Leave as a pure passthrough — the vtbl-swizzle still routes calls but
    // adds no work.
    return s_origStreamInflate(
        a_stream, a_dst, a_packedSize, a_fileOffset,
        a_flags, a_outPosLo, a_outPosHi, a_mgrState);
}

// Install the texture stream hook via **vtable swizzle**, not Detours function
// patching. Previous (Apr 15) attempts that hooked vtbl[0x68] by ANY mechanism
// (DetourAttach *or* vtable swizzle) corrupted BSResourceNiBinaryStream mesh
// loading — identical Clouds.nif crashes on back-to-back runs proved the mesh
// stream class shares the same slot implementation. vtbl[0x60] is the only
// safe intercept point here, and even that is observational-only: the
// scheduler is fire-and-forget so a_dst is empty on return, and without a
// trustworthy completion signal we can't capture real decompressed bytes.
static void TryInstallStreamInflateHook(void* a_stream)
{
    if (s_streamInflateInstalled.load(std::memory_order_acquire)) return;
    if (!a_stream || reinterpret_cast<std::uintptr_t>(a_stream) < 0x10000) return;

    std::lock_guard lk(s_streamInflateInstallMtx);
    if (s_streamInflateInstalled.load(std::memory_order_relaxed)) return;

    auto vtblAddr = *reinterpret_cast<std::uintptr_t*>(a_stream);
    if (s_rdataStart && (vtblAddr < s_rdataStart || vtblAddr >= s_rdataEnd)) {
        LogWarn("FFC4 tex: stream vtable out of rdata — skipping vtbl[0x60] install");
        return;
    }
    auto** vtbl = reinterpret_cast<void**>(vtblAddr);

    auto* fn = reinterpret_cast<StreamInflate_t>(vtbl[12]);   // 0x60 / 8
    if (!fn) return;

    s_origStreamInflate = fn;

    // Swizzle vtbl[12] → HookedStreamInflate. DO NOT touch vtbl[13] — that
    // slot is shared with BSResourceNiBinaryStream and any modification
    // crashes mesh loading.
    REL::safe_write(
        vtblAddr + 12 * sizeof(std::uintptr_t),
        reinterpret_cast<std::uintptr_t>(&HookedStreamInflate));

    s_streamInflateInstalled.store(true, std::memory_order_release);

    char msg[256];
    std::snprintf(msg, sizeof(msg),
        "FFC4 tex: vtbl-swizzle vtbl[0x60]=%p (class vtbl %p, observational-only)",
        reinterpret_cast<void*>(fn), reinterpret_cast<void*>(vtblAddr));
    LogInfo(msg);
}

static std::uint64_t __fastcall HookedTexProcessEvent(void* a_this, void** a_event)
{
    auto result = s_origTexProcessEvent(a_this, a_event);

    if (!a_event) return result;

    // Skip per-event work during save-load — ResolveSource is the heavy item
    // (vtbl[0x0F] DoGetName + archive map walk on first hit). One-time stream
    // inflate hook install lazily catches up on the next event after save-load.
    if (Settings::bShortCircuitDuringSaveLoad &&
        s_saveLoadActive.load(std::memory_order_acquire))
        return result;

    // Replicate decomp's fourcc gate (`param_2[7] != 0x30315844`) so we only
    // read *a_event on DX10 RegisteredEvents where offset 0 is the source
    // BSResource::Stream*. Other event types would have a different layout.
    auto* eventBytes = reinterpret_cast<std::uint8_t*>(a_event);
    auto fourcc = *reinterpret_cast<std::uint32_t*>(eventBytes + 0x38);
    if (fourcc != 0x30315844u) return result;   // "DX10"

    void* stream = *a_event;                    // +0x00 source stream
    if (stream) {
        if (!s_streamInflateInstalled.load(std::memory_order_acquire))
            TryInstallStreamInflateHook(stream);
        ResolveSource(stream);
    }

    return result;
}

// ═════════════════════════════════════════════════════════════════════════════
// Hook T3: BSTextureStreamer::ReadMipsToTexture (dispatcher)
//
// The dispatcher selects between PreloadState::ReadMipsToTexture and
// ReadState::ReadMipsToTexture based on which state is set on the Stream:
//
//   void BSTextureStreamer::ReadMipsToTexture(Stream* stream, char* dst_buf) {
//       if (stream->preload_state) PreloadState::ReadMipsToTexture(...);
//       else if (stream->read_state) ReadState::ReadMipsToTexture(...);
//   }
//
// Hooking here lets us serve an entire mipchain from the decomp cache with
// a sequence of memcpys, completely bypassing the per-chunk vtbl[0x60] /
// vtbl[0x68] pipeline. This matters for VR crash safety: the pipelined
// loop allocates from BSTextureStreamerLocalHeap and SmallBlockAllocator,
// and Buffout4's replacements of those allocators expose engine uninit-read
// bugs when the HookedInflate Z_STREAM_END short-circuit shifts per-chunk
// timing. If we never enter the pipeline (full cache hit), the race window
// doesn't exist. If we fall through (any miss), stock-timing runs because
// HookedStartNextFetch's BridgeSet is gated on !bHighLevelTexServe.
//
// Stream layout (F4VR Ghidra, param_2 of ReadState::ReadMipsToTexture):
//   +0x00  Reader* (StreamDetailI*)
//   +0x08  DX10Chunk* (chunks array, stride 0x18)
//            +0x00  u64 fileOffset
//            +0x08  u32 compSize
//            +0x0c  u32 uncompSize
//   +0x10  u32* mip_sizes (per-mip decompressed byte counts)
//   +0x18  PreloadState*
//   +0x20  ReadState*  (ReadState+0x10 = BSResource::Stream* source)
//   +0x44  u32 current chunk idx (scratch, written by ReadMipsToTexture)
//   +0x4c  u32 skip count (mips to leave untouched at start of dst_buf)
//   +0x50  u32 last mip index inclusive
//
// Shadow-buffer-mode flag at (*stream + 8): when non-zero, ReadState goes
// down the DecompressThroughShadowBuffer path (BC on-the-fly decode). Our
// cache stores already-decompressed bytes, so we fall through in that case
// to let the engine do its BC work.
// ═════════════════════════════════════════════════════════════════════════════
using ReadMipsToTexture_t = void (__fastcall*)(void*, char*);
static ReadMipsToTexture_t s_origReadMipsToTexture = nullptr;

static void __fastcall HookedReadMipsToTexture(void* a_stream, char* a_dst)
{
    s_hlCalls.fetch_add(1, std::memory_order_relaxed);

    const bool serveEnabled =
        a_stream && a_dst &&
        Settings::bEnableDecompCache &&
        Settings::bEnableTextureCache &&
        Settings::bHighLevelTexServe;

    if (!serveEnabled) {
        s_hlFtDisabled.fetch_add(1, std::memory_order_relaxed);
        s_hlFallthrough.fetch_add(1, std::memory_order_relaxed);
        s_origReadMipsToTexture(a_stream, a_dst);
        return;
    }

    auto* streamBytes = static_cast<std::uint8_t*>(a_stream);

    // Shadow-buffer gate — cache stores decompressed bytes, BC path owns
    // its own decode so we can't serve directly there.
    auto* reader = *reinterpret_cast<void**>(streamBytes + 0x00);
    if (!reader || reinterpret_cast<std::uintptr_t>(reader) < 0x10000) {
        s_hlFtReader.fetch_add(1, std::memory_order_relaxed);
        s_hlFallthrough.fetch_add(1, std::memory_order_relaxed);
        s_origReadMipsToTexture(a_stream, a_dst);
        return;
    }
    // Shadow-buffer-mode gate: reader+0x08 is the shadow flag on AE, but on
    // VR (and OG, same pre-AE MSVC era) this byte is always 1 (likely a
    // different field — refcount or flags). Skip the check on VR/OG; the
    // chunk-size validation in the lookup pass will catch any shadow-buffer
    // format mismatches safely.
    const bool isPreAE = REL::Module::IsVR() ||
        REL::Module::get().version() < REL::Version{ 1, 10, 980, 0 };
    if (!isPreAE) {
        if (*(reinterpret_cast<std::uint8_t*>(reader) + 0x08) != 0) {
            s_hlFtShadow.fetch_add(1, std::memory_order_relaxed);
            s_hlFallthrough.fetch_add(1, std::memory_order_relaxed);
            s_origReadMipsToTexture(a_stream, a_dst);
            return;
        }
    }

    // Source archive resolution: two paths.
    // - ReadState path: ReadState+0x10 = BSResource::Stream* → texture registry.
    // - PreloadState path: no source pointer available. The archive is identified
    //   by trial-scanning all registered archives in the chunk-lookup pass below.
    const BA2::MappedArchive* archive = nullptr;
    auto* readState = *reinterpret_cast<void**>(streamBytes + 0x20);
    if (readState) {
        auto* source = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(readState) + 0x10);
        if (source)
            archive = TextureRegistryLookup(source);
    }
    // archive may be null here (PreloadState path) — resolved in chunk pass.
    if (!archive) {
        // PreloadState: no source pointer. Use the first chunk's fileOffset
        // to identify the archive by trial-scanning all registered archives.
        auto* chunksBase0 = *reinterpret_cast<std::uint8_t**>(streamBytes + 0x08);
        const auto skip0  = *reinterpret_cast<std::uint32_t*>(streamBytes + 0x4c);
        if (chunksBase0) {
            auto* chunk0 = chunksBase0 + static_cast<std::size_t>(skip0) * 0x18;
            const auto probeOff  = *reinterpret_cast<std::uint64_t*>(chunk0 + 0x00);
            const auto probeSz   = *reinterpret_cast<std::uint32_t*>(chunk0 + 0x0c);
            auto& dc = BA2::DecompCache::GetSingleton();
            if (dc.IsReady()) {
                for (const auto* arc : TextureRegistryArchives()) {
                    auto lr = dc.Lookup(arc, static_cast<std::uint32_t>(probeOff));
                    if (lr && lr.size == probeSz) {
                        archive = arc;
                        break;
                    }
                }
            }
        }
        if (!archive) {
            s_hlFtPreload.fetch_add(1, std::memory_order_relaxed);
            s_hlFallthrough.fetch_add(1, std::memory_order_relaxed);
            s_origReadMipsToTexture(a_stream, a_dst);
            return;
        }
    }

    auto& dcache = BA2::DecompCache::GetSingleton();
    if (!dcache.IsReady()) {
        s_hlFtNotReady.fetch_add(1, std::memory_order_relaxed);
        s_hlFallthrough.fetch_add(1, std::memory_order_relaxed);
        s_origReadMipsToTexture(a_stream, a_dst);
        return;
    }

    // Chunk range [skip, lastMip] inclusive.
    const auto skip    = *reinterpret_cast<std::uint32_t*>(streamBytes + 0x4c);
    const auto lastMip = *reinterpret_cast<std::uint32_t*>(streamBytes + 0x50);
    if (lastMip < skip) {
        s_hlFtRange.fetch_add(1, std::memory_order_relaxed);
        s_hlFallthrough.fetch_add(1, std::memory_order_relaxed);
        s_origReadMipsToTexture(a_stream, a_dst);
        return;
    }
    const std::uint32_t count = lastMip - skip + 1u;

    // Max mip count per request — DX10 mipchains cap at 14 for 8192² (plus a
    // safety margin); anything wilder gets the original path.
    constexpr std::uint32_t kMaxMips = 16;
    if (count > kMaxMips) {
        s_hlFtRange.fetch_add(1, std::memory_order_relaxed);
        s_hlFallthrough.fetch_add(1, std::memory_order_relaxed);
        s_origReadMipsToTexture(a_stream, a_dst);
        return;
    }

    auto* chunksBase = *reinterpret_cast<std::uint8_t**>(streamBytes + 0x08);
    auto* mipSizes   = *reinterpret_cast<std::uint32_t**>(streamBytes + 0x10);
    if (!chunksBase || !mipSizes) {
        s_hlFtNullPtrs.fetch_add(1, std::memory_order_relaxed);
        s_hlFallthrough.fetch_add(1, std::memory_order_relaxed);
        s_origReadMipsToTexture(a_stream, a_dst);
        return;
    }

    // First pass: look up every chunk and count the leading prefix that all hit
    // with matching uncompSize. If the entire range hits, we serve it all. If
    // only a prefix hits, we memcpy that prefix and rewrite skip so the original
    // dispatcher processes just the miss tail (partial-mipchain serve). If the
    // very first chunk misses, fall through unchanged (nothing to save).
    BA2::LookupResult lrs[kMaxMips];
    std::uint32_t prefixHits = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto chunkIdx = skip + i;
        auto* chunk = chunksBase + static_cast<std::size_t>(chunkIdx) * 0x18;
        const auto fileOff  = *reinterpret_cast<std::uint64_t*>(chunk + 0x00);
        const auto uncompSz = *reinterpret_cast<std::uint32_t*>(chunk + 0x0c);

        lrs[i] = dcache.Lookup(archive, static_cast<std::uint32_t>(fileOff));
        if (!lrs[i] || lrs[i].size != uncompSz)
            break;
        ++prefixHits;
    }

    if (prefixHits == 0) {
        // Head miss — no point doing partial; original would start from the
        // same chunk anyway. Full fallthrough.
        s_hlMissChunk.fetch_add(1, std::memory_order_relaxed);
        s_hlFallthrough.fetch_add(1, std::memory_order_relaxed);
        s_origReadMipsToTexture(a_stream, a_dst);
        return;
    }

    if (prefixHits < count) {
        // Partial: memcpy the cached prefix into dst at its natural offset,
        // then advance skip past those chunks and let the original process the
        // miss tail. dst_buf layout is mip-index-addressed, so the original's
        // own skip-based offset math still lands the remaining chunks in the
        // correct slots — no need to pre-fill anything else.
        std::uint64_t dstOffset = 0;
        for (std::uint32_t i = 0; i < skip; ++i)
            dstOffset += mipSizes[i];

        char* dst = a_dst + dstOffset;
        std::uint64_t partBytes = 0;
        for (std::uint32_t i = 0; i < prefixHits; ++i) {
            BA2::FastCopyLarge(dst, lrs[i].data, lrs[i].size);
            dst       += lrs[i].size;
            partBytes += lrs[i].size;
            dcache.RecordHit(lrs[i].size);
        }

        *reinterpret_cast<std::uint32_t*>(streamBytes + 0x4c) = skip + prefixHits;

        s_hlPartialServed.fetch_add(1, std::memory_order_relaxed);
        s_hlPartialChunks.fetch_add(prefixHits, std::memory_order_relaxed);
        s_hlPartialBytes.fetch_add(partBytes, std::memory_order_relaxed);
        s_cacheServedBytes.fetch_add(partBytes, std::memory_order_relaxed);

        s_origReadMipsToTexture(a_stream, a_dst);
        return;
    }
    // prefixHits == count: full hit — fall through to the existing serve path.

    // Second pass: compute the start offset inside dst_buf by summing the
    // skipped mip sizes (matches ReadState's skip loop), then memcpy each
    // cached mip contiguously.
    std::uint64_t dstOffset = 0;
    for (std::uint32_t i = 0; i < skip; ++i)
        dstOffset += mipSizes[i];

    char* dst = a_dst + dstOffset;
    std::uint64_t totalBytes = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        std::memcpy(dst, lrs[i].data, lrs[i].size);
        dst        += lrs[i].size;
        totalBytes += lrs[i].size;
        dcache.RecordHit(lrs[i].size);
    }

    // Leave stream+0x44 at the last read chunk index so any code that
    // inspects it post-call sees a consistent "all done" state.
    *reinterpret_cast<std::uint32_t*>(streamBytes + 0x44) = lastMip;

    s_hlServed.fetch_add(1, std::memory_order_relaxed);
    s_hlServedBytes.fetch_add(totalBytes, std::memory_order_relaxed);
    s_cacheServed.fetch_add(1, std::memory_order_relaxed);
    s_cacheServedBytes.fetch_add(totalBytes, std::memory_order_relaxed);
}

// ═════════════════════════════════════════════════════════════════════════════
// Hook T3-AE: FUN_1417cdb80 — AE per-chunk fetch loop (inner dispatcher)
//
// AE has no standalone outer dispatcher like F4VR's 0x141d2efd0 — the only
// caller of this function is BSTextureStreamer::Manager::ThreadProc (FUN_
// 1417cdd90), which drives texture requests through it directly. So this IS
// the hook point for high-level serve on AE. The call signature is different
// from F4VR: (Manager*, Stream*) with dst_buf embedded at stream+0xe0 instead
// of passed as an outer arg.
//
// Stream struct layout (AE, derived from FUN_1417cdb80 disassembly):
//   +0x0c  u8   source_idx (index into Manager->sourceTable)
//   +0x0e  u16  chunk_table_offset (chunks inline at stream + this offset,
//              stride 0x18 — NOT a separate pointer like F4VR +0x08)
//   +0xe0  u64  dst_buf pointer (loaded into a scratch reg, stock does NOT
//              write back after advancing; we follow suit)
//   +0xf8  u32  scratch (stock pre-zeros, vtbl[0x60] writes — we zero it)
//   +0xfc  u32  scratch (same)
//   +0x100 u16  current chunk idx (start of range)
//   +0x102 u16  last chunk idx (inclusive)
//   +0x10a u8   flag (stock clears at successful exit)
//
// DX10 chunk on AE (stride 0x18):
//   +0x00  u64  fileOffset
//   +0x08  u32  decompressed size — used as vtbl[0x60] arg3 AND as the
//              `dst += ...` advance amount per chunk (verified in raw
//              disassembly: both reads at 0x1417cdc9a and 0x1417cdcd6 hit
//              the same byte offset)
//
// Source/archive: Manager[+0x98de0] = sourceTable (void**), Manager[+0x98df0]
// = u32 count. sourceTable[stream+0xc] is the BSResource::Stream* we hand
// to ResolveSource() (same DoGetName path HookedStreamInflate uses) to look
// up the MappedArchive. Source flags live at source+0x10 (bit 0 = invalid,
// stock skips vtbl[0x60] with error code 8).
//
// Side-effect parity with stock on cache-hit path:
//   - pre-zero stream+0xf8/0xfc
//   - do NOT touch source+0x10 refcount (stock does balanced inc/dec via
//     CMPXCHG by 0x1000, net zero — we skip both)
//   - do NOT take Manager+0x98db0 lock (stock uses it to serialize vtbl[0x60]
//     calls; we do pure memcpy into a per-request buffer, no concurrency)
//   - clear stream+0x10a on exit
//   - do NOT write stream+0x100 (stock doesn't — the loop iterates a local
//     register, never stores back; caller owns the range state)
// ═════════════════════════════════════════════════════════════════════════════
using AE_ReadMipsToTexture_t = void (__fastcall*)(void*, void*);
static AE_ReadMipsToTexture_t s_origAE_ReadMipsToTexture = nullptr;

static void __fastcall HookedAE_ReadMipsToTexture(void* a_mgr, void* a_stream)
{
    LARGE_INTEGER tEntry; QueryPerformanceCounter(&tEntry);
    s_hlCalls.fetch_add(1, std::memory_order_relaxed);
    if (a_mgr) s_texMgr.store(a_mgr, std::memory_order_release);

    // Time the stock call and record both the fallthrough count and its cost.
    // This gives a per-mipchain baseline we can compare the served path against.
    auto fallthrough = [&]() {
        LARGE_INTEGER tFt0; QueryPerformanceCounter(&tFt0);
        s_origAE_ReadMipsToTexture(a_mgr, a_stream);
        LARGE_INTEGER tFt1; QueryPerformanceCounter(&tFt1);
        s_hlFallthrough.fetch_add(1, std::memory_order_relaxed);
        s_hlFtNs.fetch_add(
            static_cast<std::uint64_t>((tFt1.QuadPart - tFt0.QuadPart) * 1000000000LL / s_qpcFreq),
            std::memory_order_relaxed);
    };
    auto recordServed = [&](std::uint32_t chunks) {
        LARGE_INTEGER tEnd; QueryPerformanceCounter(&tEnd);
        s_hlServed.fetch_add(1, std::memory_order_relaxed);
        s_hlServedNs.fetch_add(
            static_cast<std::uint64_t>((tEnd.QuadPart - tEntry.QuadPart) * 1000000000LL / s_qpcFreq),
            std::memory_order_relaxed);
        s_hlChunksServed.fetch_add(chunks, std::memory_order_relaxed);
    };

    const bool serveEnabled =
        a_mgr && a_stream &&
        Settings::bEnableDecompCache &&
        Settings::bEnableTextureCache &&
        Settings::bHighLevelTexServe;

    if (!serveEnabled) {
        fallthrough();
        return;
    }

    auto* s   = static_cast<std::uint8_t*>(a_stream);
    auto* mgr = static_cast<std::uint8_t*>(a_mgr);

    // Source lookup via Manager[+0x98de0] sourceTable[byte[stream+0xc]]
    const auto sourceIdx  = *reinterpret_cast<std::uint8_t*>(s + 0x0c);
    const auto tableCount = *reinterpret_cast<std::uint32_t*>(mgr + 0x98df0);
    if (sourceIdx >= tableCount) { fallthrough(); return; }
    auto** sourceTable = *reinterpret_cast<void***>(mgr + 0x98de0);
    if (!sourceTable) { fallthrough(); return; }
    auto* source = sourceTable[sourceIdx];
    if (!source) { fallthrough(); return; }
    // Bit 0 of source+0x10 = "invalid" flag; stock skips fetch.
    const auto sourceFlags = *reinterpret_cast<std::uint8_t*>(
        static_cast<std::uint8_t*>(source) + 0x10);
    if (sourceFlags & 0x1) { fallthrough(); return; }

    // CACHE-ONLY source lookup — do NOT call ResolveSource here. ResolveSource
    // invokes DoGetName via source->vtbl[0x0F], which can acquire a BSResource
    // mutex that the streamer thread (our current caller, via ThreadProc)
    // already holds. That deadlocks ThreadProc and wedges all texture I/O
    // (reproduced on AE 1.11.191: infinite main-menu load, [MMAP] stats go
    // to zero after the initial mesh batch). The per-chunk HookedStreamInflate
    // path populates the source hash via its own ResolveSource call from a
    // safer context, so by the time we see a second request for the same
    // source, SourceLookup will hit and HL can serve.
    const auto* archive = SourceLookup(source);
    if (!archive || !archive->IsOpen()) { fallthrough(); return; }

    auto& dcache = BA2::DecompCache::GetSingleton();
    if (!dcache.IsReady()) { fallthrough(); return; }

    // Range [first, last] inclusive, u16 on AE.
    const auto first = *reinterpret_cast<std::uint16_t*>(s + 0x100);
    const auto last  = *reinterpret_cast<std::uint16_t*>(s + 0x102);
    if (first > last) {
        // Empty range — stock's `CMP ESI, EAX; JA <exit>` branch skips the
        // loop entirely, then clears the flag and returns. Match state.
        *reinterpret_cast<std::uint8_t*>(s + 0x10a) = 0;
        recordServed(0);
        return;
    }
    const std::uint32_t count = static_cast<std::uint32_t>(last - first + 1);

    constexpr std::uint32_t kMaxMips = 16;
    if (count > kMaxMips) { fallthrough(); return; }

    const auto chunkOff = *reinterpret_cast<std::uint16_t*>(s + 0x0e);
    if (chunkOff == 0) { fallthrough(); return; }
    auto* chunksBase = s + chunkOff;

    // Validate every chunk is in the decomp cache. chunk+0x08 is packedSize
    // (not uncompSize) — match by offset only. Any miss → fall through to stock.
    BA2::LookupResult lrs[kMaxMips];
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto chunkIdx = static_cast<std::uint32_t>(first) + i;
        auto* chunk = chunksBase + static_cast<std::size_t>(chunkIdx) * 0x18;
        const auto fileOff  = *reinterpret_cast<std::uint64_t*>(chunk + 0x00);
        lrs[i] = dcache.Lookup(archive, static_cast<std::uint32_t>(fileOff));
        if (!lrs[i]) {
            s_hlMissChunk.fetch_add(1, std::memory_order_relaxed);
            fallthrough();
            return;
        }
    }

    // Second pass: memcpy into dst_buf (stored at stream+0xe0). Stock advances
    // a local register copy without writing back; we follow the same contract.
    auto* dst = *reinterpret_cast<std::uint8_t**>(s + 0xe0);
    if (!dst) { fallthrough(); return; }
    std::uint64_t totalBytes = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        std::memcpy(dst, lrs[i].data, lrs[i].size);
        dst        += lrs[i].size;
        totalBytes += lrs[i].size;
        dcache.RecordHit(lrs[i].size);
    }

    // Match stock's exit-state side effects. ThreadProc (FUN_1417cdd90 @
    // +0x960 / AE 0x1417ce6f0) reads these and takes an allocator free-list
    // walk when `f8 >= fc`. That walk assumes vtbl[0x60] populated block
    // header metadata at dst_buf-0x10 — we skipped that, so its next/prev
    // pointers are garbage and it crashes at 0x1417ceca6 (`mov [r8+0x28],
    // rax` with r8=0x10001000 = texel data). Leaving `f8 < fc` steers
    // ThreadProc into the 0x1417cee3b branch which, with 0x10a cleared,
    // jumps straight to the clean exit at 0x1417cef46.
    *reinterpret_cast<std::uint32_t*>(s + 0xf8)  = 0;
    *reinterpret_cast<std::uint32_t*>(s + 0xfc)  = totalBytes > 0
        ? static_cast<std::uint32_t>(totalBytes & 0xFFFFFFFFu)
        : 1u;
    *reinterpret_cast<std::uint8_t*> (s + 0x10a) = 0;

    s_hlServedBytes.fetch_add(totalBytes, std::memory_order_relaxed);
    s_cacheServed.fetch_add(1, std::memory_order_relaxed);
    s_cacheServedBytes.fetch_add(totalBytes, std::memory_order_relaxed);
    recordServed(count);
}

// ═════════════════════════════════════════════════════════════════════════════
// AE Manager::vtbl[0xe0]/[0xf0] completion-dispatcher MONITOR hooks
// ─────────────────────────────────────────────────────────────────────────────
// Phase-1 log-only hooks on the AE completion dispatchers that own the REAL
// unpacked buffer alloc + inflate + D3D upload. Memory note
// project_ae_hl_serve_viable.md has the full pipeline; these hooks capture
// call frequency + completion-struct offsets so Phase 2 can serve from cache
// without a D3D miscall. Signature is assumed (mgr, a2, a3, a4); the log
// reveals which arg actually carries the completion struct.
// ═════════════════════════════════════════════════════════════════════════════
using AE_MgrComplete_t = std::uint64_t (__fastcall*)(void*, void*, void*, std::uint32_t);
static AE_MgrComplete_t s_origAE_MgrCompleteE0 = nullptr;
static AE_MgrComplete_t s_origAE_MgrCompleteF0 = nullptr;

static std::uint64_t MonSafeReadU64(const void* p)
{
    std::uint64_t v = 0;
    __try { v = *reinterpret_cast<const std::uint64_t*>(p); }
    __except (EXCEPTION_EXECUTE_HANDLER) { v = 0xDEADC0DEDEADC0DEULL; }
    return v;
}
static std::uint32_t MonSafeReadU32(const void* p)
{
    std::uint32_t v = 0;
    __try { v = *reinterpret_cast<const std::uint32_t*>(p); }
    __except (EXCEPTION_EXECUTE_HANDLER) { v = 0xDEADC0DEu; }
    return v;
}

static std::uint16_t MonSafeReadU16(const void* p)
{
    std::uint16_t v = 0;
    __try { v = *reinterpret_cast<const std::uint16_t*>(p); }
    __except (EXCEPTION_EXECUTE_HANDLER) { v = 0xDEAD; }
    return v;
}
static std::uint8_t MonSafeReadU8(const void* p)
{
    std::uint8_t v = 0;
    __try { v = *reinterpret_cast<const std::uint8_t*>(p); }
    __except (EXCEPTION_EXECUTE_HANDLER) { v = 0xDE; }
    return v;
}

static void LogMonDispatch(const char* tag, void* mgr, void* a2, void* a3, std::uint32_t a4)
{
    char buf[1536];
    int  n = 0;
    n += std::snprintf(buf + n, sizeof(buf) - n,
        "FFC4 texmon [%s]: mgr=%p a2=%p a3=%p a4=%x",
        tag, mgr, a2, a3, a4);
    // Treat a2 as a candidate Stream struct (layout per project_ae_readmipstotexture.md).
    // If a2 IS the stream: +0x0c srcIdx, +0x0e chunkOff, +0xe0 dst_buf, +0xec priority,
    // +0x100 firstMip, +0x102 lastMip, +0x10a flag.
    if (a2) {
        auto* p = static_cast<const std::uint8_t*>(a2);
        n += std::snprintf(buf + n, sizeof(buf) - n,
            " | a2[0]=%llx [08]=%llx [0c]=%02x [0e]=%04x [10]=%llx [18]=%llx"
            " [20]=%llx [28]=%llx [30]=%llx [38]=%llx [40]=%x [44]=%x [48]=%x [4c]=%x [50]=%x"
            " [58]=%llx [80]=%llx [e0]=%llx [ec]=%x [f8]=%x [fc]=%x [100]=%04x [102]=%04x [10a]=%02x",
            (unsigned long long)MonSafeReadU64(p + 0x00),
            (unsigned long long)MonSafeReadU64(p + 0x08),
            MonSafeReadU8(p + 0x0c),
            MonSafeReadU16(p + 0x0e),
            (unsigned long long)MonSafeReadU64(p + 0x10),
            (unsigned long long)MonSafeReadU64(p + 0x18),
            (unsigned long long)MonSafeReadU64(p + 0x20),
            (unsigned long long)MonSafeReadU64(p + 0x28),
            (unsigned long long)MonSafeReadU64(p + 0x30),
            (unsigned long long)MonSafeReadU64(p + 0x38),
            MonSafeReadU32(p + 0x40),
            MonSafeReadU32(p + 0x44),
            MonSafeReadU32(p + 0x48),
            MonSafeReadU32(p + 0x4c),
            MonSafeReadU32(p + 0x50),
            (unsigned long long)MonSafeReadU64(p + 0x58),
            (unsigned long long)MonSafeReadU64(p + 0x80),
            (unsigned long long)MonSafeReadU64(p + 0xe0),
            MonSafeReadU32(p + 0xec),
            MonSafeReadU32(p + 0xf8),
            MonSafeReadU32(p + 0xfc),
            MonSafeReadU16(p + 0x100),
            MonSafeReadU16(p + 0x102),
            MonSafeReadU8(p + 0x10a));
    }
    if (a3) {
        auto* p = static_cast<const std::uint8_t*>(a3);
        n += std::snprintf(buf + n, sizeof(buf) - n,
            " | a3[0]=%llx [08]=%llx [10]=%llx [18]=%llx [20]=%llx [28]=%llx [30]=%llx"
            " [38]=%llx [40]=%x [48]=%x [4c]=%x [50]=%x [58]=%llx",
            (unsigned long long)MonSafeReadU64(p + 0x00),
            (unsigned long long)MonSafeReadU64(p + 0x08),
            (unsigned long long)MonSafeReadU64(p + 0x10),
            (unsigned long long)MonSafeReadU64(p + 0x18),
            (unsigned long long)MonSafeReadU64(p + 0x20),
            (unsigned long long)MonSafeReadU64(p + 0x28),
            (unsigned long long)MonSafeReadU64(p + 0x30),
            (unsigned long long)MonSafeReadU64(p + 0x38),
            MonSafeReadU32(p + 0x40),
            MonSafeReadU32(p + 0x48),
            MonSafeReadU32(p + 0x4c),
            MonSafeReadU32(p + 0x50),
            (unsigned long long)MonSafeReadU64(p + 0x58));
    }
    LogInfo(buf);
}

static std::uint64_t __fastcall HookedAE_MgrCompleteE0(void* mgr, void* a2, void* a3, std::uint32_t a4)
{
    s_monE0Calls.fetch_add(1, std::memory_order_relaxed);
    if (s_monE0Logged.fetch_add(1, std::memory_order_relaxed) < 15) {
        LogMonDispatch("E0", mgr, a2, a3, a4);
    }
    return s_origAE_MgrCompleteE0(mgr, a2, a3, a4);
}
static std::uint64_t __fastcall HookedAE_MgrCompleteF0(void* mgr, void* a2, void* a3, std::uint32_t a4)
{
    s_monF0Calls.fetch_add(1, std::memory_order_relaxed);
    if (s_monF0Logged.fetch_add(1, std::memory_order_relaxed) < 15) {
        LogMonDispatch("F0", mgr, a2, a3, a4);
    }
    return s_origAE_MgrCompleteF0(mgr, a2, a3, a4);
}

// ── Install the texture-chain hooks via Detours (per-runtime) ─────────────
// F4VR and OG use AddDataFile + StartNextFetch (two detours on named
// functions — OG's StartNextFetch is byte-identical to F4VR's).
// AE uses ProcessEvent + a runtime-discovered vtbl[0x60] detour. NG is not
// yet wired up — we skip silently on that runtime.
static void InstallTextureStreamerHooks()
{
    auto base = REL::Module::get().base();

    // Diagnostic detour on BSTextureStreamer::Manager::zscrapAllocate (AE only).
    // Counts ScrapHeap allocations from the texture decomp path. A/B with
    // bTextureDirectServe on vs off reveals whether our cache hits actually
    // bypass the engine's scrap-alloc step (= the Buffout4 bScrapHeap interaction
    // point). Always installed when stats are on and we're on AE 1.11.
    if (Settings::bEnableStats && !REL::Module::IsVR() &&
        REL::Module::get().version()[1] == 11)
    {
        auto zscrapAddr = base + 0x0169EE90;
        s_origZscrapAlloc = reinterpret_cast<zscrapAlloc_fn>(zscrapAddr);
        LONG err = DetourTransactionBegin();
        if (err == NO_ERROR) {
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(reinterpret_cast<void**>(&s_origZscrapAlloc),
                         reinterpret_cast<void*>(&HookedZscrapAlloc));
            err = DetourTransactionCommit();
        }
        if (err != NO_ERROR) {
            LogWarn("FFC4 tex: zscrap probe install failed");
            s_origZscrapAlloc = nullptr;
        } else {
            char m[160];
            std::snprintf(m, sizeof(m),
                "FFC4 tex: zscrap probe installed @ %llX",
                (unsigned long long)zscrapAddr);
            LogInfo(m);
        }

        // LooseFileStream slot-12 async submit hook (AE only) — FUN_1416AEFE0,
        // LooseFileStream's vtbl[0x60] entry. Reads compressed bytes directly
        // from the archive mmap and fakes async completion, so FUN_14169D530's
        // DoWaitTags returns immediately and inflate runs without ever
        // touching the game's I/O worker queue. See HookedLooseFileAsyncSubmit
        // for the full rationale.
        auto submitAddr = base + 0x016AEFE0;
        s_origLooseAsyncSubmit = reinterpret_cast<LooseAsyncSubmit_fn>(submitAddr);
        LONG err2 = DetourTransactionBegin();
        if (err2 == NO_ERROR) {
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(reinterpret_cast<void**>(&s_origLooseAsyncSubmit),
                         reinterpret_cast<void*>(&HookedLooseFileAsyncSubmit));
            err2 = DetourTransactionCommit();
        }
        if (err2 != NO_ERROR) {
            LogWarn("FFC4 tex: LooseFile slot-12 submit install failed");
            s_origLooseAsyncSubmit = nullptr;
        } else {
            char m[192];
            std::snprintf(m, sizeof(m),
                "FFC4 tex: LooseFile slot-12 submit hook installed @ %llX",
                (unsigned long long)submitAddr);
            LogInfo(m);
        }

        // AsyncReaderStream::DoStartRead hook (AE only) — FUN_1416A2350, slot 6
        // of the async stream class. Save-load reads route through this path,
        // not through the slot-12 hook above. Mmap-direct serve at the stream
        // level using AsyncReaderStream's own this[0x20]=source / this[0x28]=
        // startOffset layout. See HookedAsyncStreamDoStartRead body comment
        // for why the matching DoWait short-returns safely.
        auto asyncStartAddr = base + 0x016A2350;
        s_origAsyncStartRead = reinterpret_cast<AsyncStartRead_fn>(asyncStartAddr);
        LONG err4 = DetourTransactionBegin();
        if (err4 == NO_ERROR) {
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(reinterpret_cast<void**>(&s_origAsyncStartRead),
                         reinterpret_cast<void*>(&HookedAsyncStreamDoStartRead));
            err4 = DetourTransactionCommit();
        }
        if (err4 != NO_ERROR) {
            LogWarn("FFC4 tex: AsyncReaderStream slot-6 install failed");
            s_origAsyncStartRead = nullptr;
        } else {
            char m[192];
            std::snprintf(m, sizeof(m),
                "FFC4 tex: AsyncReaderStream slot-6 hook installed @ %llX",
                (unsigned long long)asyncStartAddr);
            LogInfo(m);
        }
    }

    // AE HL-dispatcher hook can install independently of cache: when cache is
    // off but stats are on, every call falls through to s_origAE_ReadMipsToTexture
    // and we get per-mipchain stock timing — the baseline for cache-on vs cache-off
    // A/B. Must precede the cache-disabled early-return below.
    // BISECT 2026-04-21: gated on bHighLevelTexServe too — the unconditional
    // timing-only install was the only block added today that fires on AE 1.11
    // with all features off, and the user reports a non-crashing infinite load
    // during save-load under exactly that config. If disabling it resolves the
    // hang, the trampoline on FUN_1417cdb80 is the culprit.
    const bool installAeHlTiming =
        Settings::bEnableStats && !Settings::bEnableDecompCache &&
        Settings::bHighLevelTexServe &&
        !REL::Module::IsVR() &&
        REL::Module::get().version()[1] == 11;
    if (installAeHlTiming) {
        auto aeDispatcherAddr = base + 0x017CDB80;
        s_origAE_ReadMipsToTexture =
            reinterpret_cast<AE_ReadMipsToTexture_t>(aeDispatcherAddr);
        LONG err2 = DetourTransactionBegin();
        if (err2 == NO_ERROR) {
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(reinterpret_cast<void**>(&s_origAE_ReadMipsToTexture),
                         reinterpret_cast<void*>(&HookedAE_ReadMipsToTexture));
            err2 = DetourTransactionCommit();
        }
        if (err2 != NO_ERROR) {
            LogWarn("FFC4 tex: AE HL timing-only hook failed");
            s_origAE_ReadMipsToTexture = nullptr;
        } else {
            char m[192];
            std::snprintf(m, sizeof(m),
                "FFC4 tex: AE HL timing-only hook installed @ %llX (cache off)",
                (unsigned long long)aeDispatcherAddr);
            LogInfo(m);
        }
    }

    if (!Settings::bEnableDecompCache) {
        LogInfo("FFC4 tex: decomp cache disabled — skipping texture hooks");
        return;
    }
    if (!Settings::bEnableTextureCache) {
        LogInfo("FFC4 tex: bEnableTextureCache=false — skipping texture hooks");
        return;
    }

    // Shared path for F4VR and OG: both have StartNextFetch as a clean leaf
    // function with identical field offsets and identical AddDataFile call
    // signature from ProcessEvent. We resolve (addDataFile, startFetch) per
    // runtime and share the same hook functions.
    struct TexAddrs { std::uintptr_t addDataFile; std::uintptr_t startFetch; const char* tag; };
    std::optional<TexAddrs> texAddrs;

    if (REL::Module::IsVR()) {
        // F4VR 1.2.72 (symbolized in Ghidra).
        texAddrs = TexAddrs{
            base + 0x01D33EF0,   // BSTextureIndex::Index::AddDataFile
            base + 0x01D2FEC0,   // BSTextureStreamer::ReadState::StartNextFetch
            "F4VR"
        };
    } else if (REL::Module::get().version() < REL::Version{ 1, 10, 980, 0 }) {
        // F4 OG 1.10.163 (stripped — addresses from Ghidra pattern search).
        // AddDataFile: FUN_141cb4060, called from ProcessEvent's tail with
        //   FUN_141cb4060(index, event, &event.id, idx) — same layout as F4VR's
        //   BSTextureIndex::Index::AddDataFile call.
        // StartNextFetch: FUN_141cb0030, byte-identical to F4VR's
        //   BSTextureStreamer::ReadState::StartNextFetch (identical decomp,
        //   same field offsets 0x10/0x20/0x28/0x30/0x38/0x48/0x50/0x5c,
        //   same reader->vtbl[0x60] call arg order). Located via `41 FF 53 60`
        //   byte-pattern search in the OG .text segment.
        texAddrs = TexAddrs{
            base + 0x01CB4060,
            base + 0x01CB0030,
            "OG"
        };
    }

    if (texAddrs) {
        s_origTextureAddDataFile = reinterpret_cast<TextureAddDataFile_t>(texAddrs->addDataFile);
        s_origStartNextFetch     = reinterpret_cast<StartNextFetch_t>(texAddrs->startFetch);

        LONG err = DetourTransactionBegin();
        if (err != NO_ERROR) {
            char w[128];
            std::snprintf(w, sizeof(w),
                "FFC4 tex: DetourTransactionBegin (%s) failed", texAddrs->tag);
            LogWarn(w);
            s_origTextureAddDataFile = nullptr;
            s_origStartNextFetch = nullptr;
            return;
        }
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(reinterpret_cast<void**>(&s_origTextureAddDataFile),
                     reinterpret_cast<void*>(&HookedTextureAddDataFile));
        DetourAttach(reinterpret_cast<void**>(&s_origStartNextFetch),
                     reinterpret_cast<void*>(&HookedStartNextFetch));
        err = DetourTransactionCommit();
        if (err != NO_ERROR) {
            char w[128];
            std::snprintf(w, sizeof(w),
                "FFC4 tex: DetourTransactionCommit (%s) failed", texAddrs->tag);
            LogWarn(w);
            s_origTextureAddDataFile = nullptr;
            s_origStartNextFetch = nullptr;
            return;
        }

        char msg[256];
        std::snprintf(msg, sizeof(msg),
            "FFC4 tex: hooks installed (%s) — AddDataFile=%llX StartNextFetch=%llX",
            texAddrs->tag,
            (unsigned long long)texAddrs->addDataFile,
            (unsigned long long)texAddrs->startFetch);
        LogInfo(msg);

        // High-level dispatcher hook (crash-safety path — avoids per-chunk
        // pipeline interleaving with Buffout4's LocalHeap/SmallBlockAllocator
        // replacements). F4VR + F4 OG both have a proper outer dispatcher with
        // `void (Stream&, void* dst_buf)` signature (PDB-confirmed on both).
        // AE has NO outer dispatcher — the work is inlined into Manager::ThreadProc,
        // and stream+0xe0 is packed-size scratch so HL memcpy would overflow;
        // AE keeps HL serve off by default. NG TBD (task #40).
        std::uintptr_t hlAddr = 0;
        const char*    hlTag  = nullptr;
        if (REL::Module::IsVR()) {
            hlAddr = base + 0x01D2EFD0;  // F4VR 1.2.72 (symbolized)
            hlTag  = "F4VR";
        } else if (REL::Module::get().version() < REL::Version{ 1, 10, 980, 0 }) {
            hlAddr = base + 0x01CAF140;  // F4 OG 1.10.163 BSTextureStreamer::ReadMipsToTexture
            hlTag  = "OG";
        }

        if (Settings::bHighLevelTexServe && hlAddr) {
            s_origReadMipsToTexture = reinterpret_cast<ReadMipsToTexture_t>(hlAddr);

            LONG err2 = DetourTransactionBegin();
            if (err2 == NO_ERROR) {
                DetourUpdateThread(GetCurrentThread());
                DetourAttach(reinterpret_cast<void**>(&s_origReadMipsToTexture),
                             reinterpret_cast<void*>(&HookedReadMipsToTexture));
                err2 = DetourTransactionCommit();
            }
            if (err2 != NO_ERROR) {
                LogWarn("FFC4 tex: ReadMipsToTexture detour failed — fallback via StartNextFetch");
                s_origReadMipsToTexture = nullptr;
            } else {
                char m2[192];
                std::snprintf(m2, sizeof(m2),
                    "FFC4 tex: HL dispatcher hook installed (%s) @ %llX",
                    hlTag, (unsigned long long)hlAddr);
                LogInfo(m2);
            }
        }

        return;
    }

    if (REL::Module::get().version()[1] == 11) {
        // AE 1.11.x — one detour at ProcessEvent (DX10 sink). The hook runs
        // the original, then reads the source stream from *a_event and
        // runtime-discovers vtbl[0x60] to install a second Detour on the
        // stream class's per-chunk inflate entry point (lazy, CAS-guarded).
        auto processEventAddr = base + 0x017CC2B0;   // 0x1417cc2b0 − 0x140000000

        s_origTexProcessEvent = reinterpret_cast<TexProcessEvent_t>(processEventAddr);

        LONG err = DetourTransactionBegin();
        if (err != NO_ERROR) {
            LogWarn("FFC4 tex: DetourTransactionBegin (AE) failed");
            s_origTexProcessEvent = nullptr;
            return;
        }
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(reinterpret_cast<void**>(&s_origTexProcessEvent),
                     reinterpret_cast<void*>(&HookedTexProcessEvent));
        err = DetourTransactionCommit();
        if (err != NO_ERROR) {
            LogWarn("FFC4 tex: DetourTransactionCommit (AE) failed");
            s_origTexProcessEvent = nullptr;
            return;
        }

        char msg[256];
        std::snprintf(msg, sizeof(msg),
            "FFC4 tex: hooks installed (AE) — ProcessEvent=%llX (stream vtbl[0x60] resolves lazily)",
            (unsigned long long)processEventAddr);
        LogInfo(msg);

        // High-level dispatcher hook for AE: FUN_1417cdb80 is the per-chunk
        // fetch loop, the only caller being ThreadProc. On full-mipchain cache
        // hit we memcpy the whole range and return, skipping the per-chunk
        // vtbl[0x60] pipeline entirely. On any miss we fall through and the
        // existing HookedStreamInflate per-chunk path picks up partial hits.
        //
        // Also installed when bEnableStats is on (even without serve) so we can
        // measure per-mipchain fallthrough time — that's the stock baseline
        // we compare the served path against.
        if (Settings::bHighLevelTexServe || Settings::bEnableStats) {
            auto aeDispatcherAddr = base + 0x017CDB80;   // 0x1417cdb80 − 0x140000000
            s_origAE_ReadMipsToTexture =
                reinterpret_cast<AE_ReadMipsToTexture_t>(aeDispatcherAddr);

            LONG err2 = DetourTransactionBegin();
            if (err2 == NO_ERROR) {
                DetourUpdateThread(GetCurrentThread());
                DetourAttach(reinterpret_cast<void**>(&s_origAE_ReadMipsToTexture),
                             reinterpret_cast<void*>(&HookedAE_ReadMipsToTexture));
                err2 = DetourTransactionCommit();
            }
            if (err2 != NO_ERROR) {
                LogWarn("FFC4 tex: AE HL dispatcher detour failed — falling back to per-chunk path only");
                s_origAE_ReadMipsToTexture = nullptr;
            } else {
                char m2[192];
                std::snprintf(m2, sizeof(m2),
                    "FFC4 tex: HL dispatcher hook installed (AE) @ %llX",
                    (unsigned long long)aeDispatcherAddr);
                LogInfo(m2);
            }
        }

        return;
    }

    LogWarn("FFC4 tex: texture hooks not wired for this runtime (NG) — skipped");
}

// AE Manager::vtbl[0xe0]/[0xf0] completion-dispatcher hook install. Independent
// of bEnableTextureCache — runs whenever stats are on AND we're on AE. Phase 1
// is log-only (HookedAE_MgrComplete* dumps struct), Phase 2 will add capture
// + serve here at the unpacked-buffer entry point.
static void InstallAEManagerDispatchHooks()
{
    if (REL::Module::IsVR()) return;
    if (REL::Module::get().version()[1] != 11) return;
    if (!Settings::bEnableStats) return;

    auto base = REL::Module::get().base();
    auto e0Addr = base + 0x0226EA40;   // 0x14226EA40 Manager::vtbl[0xe0]
    auto f0Addr = base + 0x0226EAF0;   // 0x14226EAF0 Manager::vtbl[0xf0]
    s_origAE_MgrCompleteE0 = reinterpret_cast<AE_MgrComplete_t>(e0Addr);
    s_origAE_MgrCompleteF0 = reinterpret_cast<AE_MgrComplete_t>(f0Addr);

    LONG err = DetourTransactionBegin();
    if (err == NO_ERROR) {
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(reinterpret_cast<void**>(&s_origAE_MgrCompleteE0),
                     reinterpret_cast<void*>(&HookedAE_MgrCompleteE0));
        DetourAttach(reinterpret_cast<void**>(&s_origAE_MgrCompleteF0),
                     reinterpret_cast<void*>(&HookedAE_MgrCompleteF0));
        err = DetourTransactionCommit();
    }
    if (err != NO_ERROR) {
        LogWarn("FFC4 tex: AE completion-dispatcher monitor detours failed");
        s_origAE_MgrCompleteE0 = nullptr;
        s_origAE_MgrCompleteF0 = nullptr;
    } else {
        char m[192];
        std::snprintf(m, sizeof(m),
            "FFC4 tex: AE completion-monitor hooks installed — E0=%llX F0=%llX",
            (unsigned long long)e0Addr, (unsigned long long)f0Addr);
        LogInfo(m);
    }
}

// Find the primary ReaderStream ctor by scanning .text for the prologue
// pattern that loads its own vtable into [rcx]:
//   48 8D 05 ?? ?? ?? ??    lea rax, [rip+disp32]    ; vtable address
//   48 89 01                mov [rcx], rax           ; install in *this
//
// On a multi-match, prefer the candidate whose body references one of the
// stack-arg slots [rsp+0x28..0x48] — the copy ctor (2 params) does not.
static std::uintptr_t ScanForReaderStreamCtor(std::uintptr_t a_vtblAddr)
{
    auto textSeg  = REL::Module::get().segment(REL::Segment::text);
    auto* textBase = reinterpret_cast<const std::uint8_t*>(textSeg.address());
    auto textSize = textSeg.size();
    auto textVA   = textSeg.address();

    struct Hit { std::uintptr_t funcStart; std::size_t funcSize; bool primary; };
    std::vector<Hit> hits;

    for (std::size_t i = 0; i + 10 < textSize; ++i) {
        if (textBase[i]   != 0x48 || textBase[i+1] != 0x8D || textBase[i+2] != 0x05) continue;
        if (textBase[i+7] != 0x48 || textBase[i+8] != 0x89 || textBase[i+9] != 0x01) continue;

        std::int32_t disp = *reinterpret_cast<const std::int32_t*>(textBase + i + 3);
        std::uintptr_t target = textVA + i + 7 + disp;
        if (target != a_vtblAddr) continue;

        // Walk back over instructions until 0xCC padding (function boundary).
        std::size_t startIdx = i;
        for (std::size_t back = 1; back < 256 && back <= i; ++back) {
            if (textBase[i - back] == 0xCC) {
                startIdx = i - back + 1;
                break;
            }
        }

        // Walk forward until next 0xCC padding to bound the function.
        std::size_t endIdx = startIdx;
        for (std::size_t j = startIdx; j < textSize && (j - startIdx) < 0x2000; ++j) {
            if (textBase[j] == 0xCC) { endIdx = j; break; }
            endIdx = j + 1;
        }

        // Detect stack-arg access: SIB byte 0x24 (= [rsp]) followed by an offset
        // in [0x28..0x48]. Present in the 9-arg primary ctor, absent in the
        // 2-arg copy ctor.
        bool primary = false;
        for (std::size_t j = startIdx; j + 1 < endIdx; ++j) {
            if (textBase[j] == 0x24) {
                std::uint8_t off = textBase[j + 1];
                if (off >= 0x28 && off <= 0x48) { primary = true; break; }
            }
        }

        hits.push_back({ textVA + startIdx, endIdx - startIdx, primary });
    }

    if (hits.empty()) return 0;

    // Prefer the primary-marked hit; fall back to the largest body.
    std::uintptr_t best = 0;
    std::size_t   bestSize = 0;
    for (auto& h : hits) {
        if (h.primary) return h.funcStart;
        if (h.funcSize > bestSize) { bestSize = h.funcSize; best = h.funcStart; }
    }
    return best;
}

// Runtime RTTI walker: locates the BSResource::Archive2::ReaderStream vtable
// by scanning .rdata for the MSVC mangled type-descriptor name, then following
// the RTTI_Complete_Object_Locator back to the vtable.
//
// Why: REL::ID(218182) is unreliable on 1.10.980/1.10.984 — the address library
// for those runtimes maps 218182 to an unrelated (near-empty) vtable. Hooking
// it does nothing. On 1.10.163 (OG), 1.11.191 (latest NG), and VR the ID is
// fine, but the scanner is version-independent so we use it as a fallback
// everywhere it's needed.
// Iterate the module's PE section table and invoke fn(base, size) for every
// readable, non-executable section. Returns false if the module is malformed.
template <typename Fn>
static bool ForEachReadOnlySection(Fn&& fn)
{
    const auto  modBase = REL::Module::get().base();
    const auto* dosHdr  = reinterpret_cast<const IMAGE_DOS_HEADER*>(modBase);
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* ntHdr   = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        modBase + dosHdr->e_lfanew);
    if (ntHdr->Signature != IMAGE_NT_SIGNATURE) return false;
    const auto  numSec  = ntHdr->FileHeader.NumberOfSections;
    const auto* section = IMAGE_FIRST_SECTION(ntHdr);
    for (std::uint16_t i = 0; i < numSec; ++i, ++section) {
        const auto flags = section->Characteristics;
        if (!(flags & IMAGE_SCN_MEM_READ)) continue;
        if (flags & IMAGE_SCN_MEM_EXECUTE) continue;  // skip .text
        const auto base = modBase + section->VirtualAddress;
        const auto size = static_cast<std::size_t>(section->Misc.VirtualSize);
        if (size == 0) continue;
        fn(base, size);
    }
    return true;
}

static std::uintptr_t FindVtableByRTTIName(const char* kName, std::size_t kNameLen, const char* logTag)
{
    const auto imgBase = REL::Module::get().base();

    // 1) Find the type-descriptor name across all read-only sections.
    std::uintptr_t tdAddr = 0;
    ForEachReadOnlySection([&](std::uintptr_t base, std::size_t size) {
        if (tdAddr) return;
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(base);
        for (std::size_t i = 16; i + kNameLen + 1 < size; ++i) {
            if (bytes[i] != '.' || bytes[i + 1] != '?') continue;
            if (std::memcmp(bytes + i, kName, kNameLen) != 0) continue;
            if (bytes[i + kNameLen] != 0) continue;
            // type_descriptor layout: void* vftable; void* spare; char name[];
            tdAddr = base + i - 16;
            return;
        }
    });
    if (!tdAddr) {
        char wmsg[192];
        std::snprintf(wmsg, sizeof(wmsg),
            "FFC4 RTTI (%s): type-descriptor name not found in any RO section", logTag);
        LogWarn(wmsg);
        return 0;
    }
    {
        char msg[192];
        std::snprintf(msg, sizeof(msg), "FFC4 RTTI (%s): td @ %llX (rva %X)",
            logTag,
            (unsigned long long)tdAddr,
            (unsigned)(tdAddr - imgBase));
        LogInfo(msg);
    }

    const std::uint32_t tdRva = static_cast<std::uint32_t>(tdAddr - imgBase);

    // 2) Find an RTTI_Complete_Object_Locator referencing this TD.
    // COL layout (u32 each): signature, offset, cdOffset, typeDescriptor(RVA),
    // classDescriptor(RVA), [selfPointer(RVA) if sig==1].
    // Primary object's COL has offset == 0.
    std::uintptr_t colAddr = 0;
    ForEachReadOnlySection([&](std::uintptr_t base, std::size_t size) {
        if (colAddr) return;
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(base);
        for (std::size_t j = 0x0C; j + 4 <= size; ++j) {
            std::uint32_t slot;
            std::memcpy(&slot, bytes + j, 4);
            if (slot != tdRva) continue;
            const std::uintptr_t colCand = base + j - 0x0C;
            std::uint32_t sig, off;
            std::memcpy(&sig, reinterpret_cast<const void*>(colCand), 4);
            if (sig != 0 && sig != 1) continue;
            std::memcpy(&off, reinterpret_cast<const void*>(colCand + 4), 4);
            if (off != 0) continue;
            colAddr = colCand;
            return;
        }
    });
    if (!colAddr) {
        char wmsg[192];
        std::snprintf(wmsg, sizeof(wmsg),
            "FFC4 RTTI (%s): no COL references the type-descriptor", logTag);
        LogWarn(wmsg);
        return 0;
    }
    {
        char msg[192];
        std::snprintf(msg, sizeof(msg), "FFC4 RTTI (%s): COL @ %llX (rva %X)",
            logTag,
            (unsigned long long)colAddr,
            (unsigned)(colAddr - imgBase));
        LogInfo(msg);
    }

    // 3) Find the vtable's meta-pointer: a qword == COL VA in any RO section.
    // The vtable[0] slot lives immediately after that meta-pointer.
    const std::uint64_t colVA = static_cast<std::uint64_t>(colAddr);
    std::uintptr_t vtbl = 0;
    ForEachReadOnlySection([&](std::uintptr_t base, std::size_t size) {
        if (vtbl) return;
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(base);
        for (std::size_t k = 0; k + 16 <= size; k += 8) {
            std::uint64_t q;
            std::memcpy(&q, bytes + k, 8);
            if (q == colVA) {
                vtbl = base + k + 8;
                return;
            }
        }
    });
    if (!vtbl) {
        char wmsg[192];
        std::snprintf(wmsg, sizeof(wmsg),
            "FFC4 RTTI (%s): vtable meta-pointer for COL not found", logTag);
        LogWarn(wmsg);
    }
    return vtbl;
}

static std::uintptr_t FindReaderStreamVtableByRTTI()
{
    constexpr const char kName[] = ".?AVReaderStream@Archive2@BSResource@@";
    return FindVtableByRTTIName(kName, sizeof(kName) - 1, "ReaderStream");
}

static std::uintptr_t FindAsyncReaderStreamVtableByRTTI()
{
    constexpr const char kName[] = ".?AVAsyncReaderStream@Archive2@BSResource@@";
    return FindVtableByRTTIName(kName, sizeof(kName) - 1, "AsyncReaderStream");
}

// A "bad" vtable slot is the empty inline stub (`xor eax, eax; ret` or `ret 0`)
// that fills in slots on unrelated classes. A real DoRead always has a prologue.
static bool VtableSlotLooksReal(std::uintptr_t a_slotFn)
{
    if (!a_slotFn) return false;
    auto textSeg = REL::Module::get().segment(REL::Segment::text);
    if (a_slotFn < textSeg.address() ||
        a_slotFn >= textSeg.address() + textSeg.size()) return false;
    const auto* p = reinterpret_cast<const std::uint8_t*>(a_slotFn);
    // xor eax,eax ; ret
    if (p[0] == 0x33 && p[1] == 0xC0 && p[2] == 0xC3) return false;
    // ret imm16
    if (p[0] == 0xC2) return false;
    // ret
    if (p[0] == 0xC3) return false;
    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
// Installation
// ═════════════════════════════════════════════════════════════════════════════

void Install()
{
    InitTiming();
    InitRdataRange();
    Field::Init();

    if (REL::Module::IsVR()) {
        LogWarn("FFC4: VR mode — hooks will be installed using VR-specific addresses");
        LogWarn("FFC4: VR support is experimental — report issues with full logs");
        // Continue installation with VR offsets (set via REL::Relocate in Field::Init)
    }

    // Resolve the ReaderStream vtable. REL::ID(218182) is known-correct on OG,
    // NG 1.10.984, and AE 1.11.191, so we use it first. The RTTI scan stays as
    // a fallback in case a future runtime breaks addrlib — but it isn't always
    // unambiguous (on AE it can pick up a different COL for the same type name
    // and return the wrong vtable), so it only runs if addrlib fails.
    {
        std::uintptr_t vtbl = REL::Relocation<std::uintptr_t>{ REL::ID(218182) }.address();
        bool ok = false;
        if (vtbl) {
            auto fn = reinterpret_cast<const std::uintptr_t*>(vtbl)[0x06];
            if (VtableSlotLooksReal(fn)) {
                char msg[160];
                std::snprintf(msg, sizeof(msg),
                    "FFC4: ReaderStream vtable resolved via REL::ID(218182) at %llX",
                    (unsigned long long)vtbl);
                LogInfo(msg);
                ok = true;
            } else {
                char msg[192];
                std::snprintf(msg, sizeof(msg),
                    "FFC4: REL::ID(218182) = %llX has stub-like slot[6] — "
                    "trying RTTI scan fallback",
                    (unsigned long long)vtbl);
                LogWarn(msg);
            }
        }
        if (!ok) {
            vtbl = FindReaderStreamVtableByRTTI();
            if (vtbl) {
                char msg[160];
                std::snprintf(msg, sizeof(msg),
                    "FFC4: ReaderStream vtable resolved via RTTI scan at %llX",
                    (unsigned long long)vtbl);
                LogInfo(msg);
            } else {
                LogWarn("FFC4: RTTI scan fallback failed — DoRead hook disabled");
            }
        }

        s_readerStreamVtbl = vtbl;
    }

    if (s_readerStreamVtbl == 0) {
        LogWarn("FFC4: no valid ReaderStream vtable — skipping DoRead hook, "
                "inflate-cache path will still work");
    }

    // Log vtable[0..11] function-prologue bytes for diagnostic purposes.
    // Needed to identify DoRead's real slot on runtimes where the field layout
    // isn't known yet (e.g. NG 1.10.984).
    if (s_readerStreamVtbl != 0) {
        auto* entries = reinterpret_cast<std::uintptr_t*>(s_readerStreamVtbl);
        for (int i = 0; i < 12; ++i) {
            auto fn = entries[i];
            const auto* p = reinterpret_cast<const std::uint8_t*>(fn);
            char msg[192];
            std::snprintf(msg, sizeof(msg),
                "FFC4 probe: vtbl[%2d] = %llX  bytes %02X %02X %02X %02X %02X %02X %02X %02X",
                i, (unsigned long long)fn,
                p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
            LogInfo(msg);
        }
    }

    // Hook 1: ReaderStream::DoRead (vtable index 6)
    if (s_readerStreamVtbl != 0) {
        constexpr std::size_t kIdx = 0x06;
        auto* entries = reinterpret_cast<std::uintptr_t*>(s_readerStreamVtbl);
        s_originalDoRead = reinterpret_cast<DoRead_t>(entries[kIdx]);
        REL::safe_write(
            s_readerStreamVtbl + kIdx * sizeof(std::uintptr_t),
            reinterpret_cast<std::uintptr_t>(&HookedDoRead));
        char msg[160];
        std::snprintf(msg, sizeof(msg),
            "FFC4: DoRead hook installed at vtable %llX slot[6]",
            (unsigned long long)s_readerStreamVtbl);
        LogInfo(msg);
    }

    // Hook 1b: AsyncReaderStream::DoRead (vtable index 6).
    // AsyncReaderStream is the class ReaderStream::DoCreateAsync constructs
    // for async cell/navmesh streaming during gameplay. Same field layout as
    // ReaderStream, different vtable. Without this hook, ~1 GB of gameplay
    // zlib bypasses the decomp cache entirely (bridge never set).
    if (Settings::bHookAsyncReaderStream) {
        std::uintptr_t asyncVtbl = FindAsyncReaderStreamVtableByRTTI();
        if (asyncVtbl != 0) {
            auto fn = reinterpret_cast<const std::uintptr_t*>(asyncVtbl)[0x06];
            if (VtableSlotLooksReal(fn)) {
                s_asyncReaderStreamVtbl = asyncVtbl;
                auto* entries = reinterpret_cast<std::uintptr_t*>(asyncVtbl);
                s_originalAsyncDoRead = reinterpret_cast<DoRead_t>(entries[0x06]);
                REL::safe_write(
                    asyncVtbl + 0x06 * sizeof(std::uintptr_t),
                    reinterpret_cast<std::uintptr_t>(&HookedDoRead));
                char msg[192];
                std::snprintf(msg, sizeof(msg),
                    "FFC4: AsyncReaderStream DoRead hook installed at vtable %llX slot[6] "
                    "(orig %llX)",
                    (unsigned long long)asyncVtbl,
                    (unsigned long long)reinterpret_cast<std::uintptr_t>(s_originalAsyncDoRead));
                LogInfo(msg);
            } else {
                char msg[192];
                std::snprintf(msg, sizeof(msg),
                    "FFC4: AsyncReaderStream vtable %llX slot[6] is stub-like — hook skipped",
                    (unsigned long long)asyncVtbl);
                LogWarn(msg);
            }
        } else {
            LogWarn("FFC4: AsyncReaderStream vtable not found via RTTI — hook skipped");
        }
    }

    // Hook 2: inflate hook is now installed separately from InstallInflateHook(),
    // called at F4SE kPostLoad. Deferring guarantees we are the *outer* Detours
    // hook if FastDecompress.dll is also present — Detours chains LIFO, so our
    // hook runs first and short-circuits to cached data, or delegates to
    // s_origInflate which points at FastDecompress's trampoline.

    // Hook 3: LocationTree::DoCreateStream — Detours factory hook
    // Intercepts ALL archive stream creation and replaces ReaderStreams with
    // MmapStream for uncompressed entries or cached compressed entries.
    // Address Library IDs:
    //   F4 1.10.163  → 476824  (bin + VR CSV)
    //   NG 1.10.984  → 2269550 (bin renumbered starting with 1.10.980)
    //   AE 1.11.191  → 2269550 (verified via Ghidra: LocationTree vtable
    //                           slot[3] = 0x1416aac40, corresponding to
    //                           ID 2269550 in version-1-11-191-0.bin)
    // Note: RelocationID's 2-arg form uses the F4 id for VR, which is
    // correct because VR's fo4_database.csv uses the 1.10.163 numbering.
    if (REL::Module::IsVR()) {
        // VR has no viable factory hook target:
        //   NEW (ReaderStream ctor @ base+0x01BEF7D0) is inlined at every
        //     callsite; the out-of-line copy has 1 DATA xref (pdata) and 0
        //     calls → hook fires never.
        //   OLD (LocationTree::DoCreateStream) fires, but only produces
        //     compressed ReaderStreams. Uncompressed BA2 entries use a
        //     different class and fail IsArchiveReaderStream. Swapping
        //     compressed streams is unsafe (ReaderStream sits below the
        //     inflate layer — serving decompressed bytes from DoRead hangs
        //     the zlib caller).
        // The cache win on VR comes from HookedInflate fp-serve (texture
        // cache) + the zlib bridge (mesh/anim), not the factory.
        LogInfo("FFC4: Factory hook skipped on VR — no viable target");
    } else {
        // Check shared F4SE trampoline capacity — warn if nearly exhausted
        auto& trampoline = F4SE::GetTrampoline();
        auto remaining = trampoline.capacity() - trampoline.allocated_size();
        if (remaining < 64) {
            char buf[128];
            std::snprintf(buf, sizeof(buf),
                "FFC4: Shared trampoline nearly exhausted (%zu/%zu bytes free)",
                remaining, trampoline.capacity());
            LogWarn(buf);
        }

        // A/B toggle: hook the BSResource::Archive2::ReaderStream primary ctor
        // (catches every BA2-backed stream allocation) vs the original
        // LocationTree::DoCreateStream path. OG and VR addresses come from PDB
        // exports; NG and AE are resolved by scanning .text for the ctor
        // prologue that writes the ReaderStream vtable into [rcx].
        // Resolve the chunk factory (FUN_14169e3b0-equivalent) first — it's
        // the next funnel up from the inlined ctor and the only one that
        // actually fires on AE/NG. Opt-in via bUseChunkFactoryHook; falls
        // back to the ctor scan on ambiguous/no match or F4/VR.
        std::uintptr_t chunkFacAddr = 0;
        if (Settings::bUseChunkFactoryHook && !REL::Module::IsF4() && !REL::Module::IsVR()) {
            chunkFacAddr = ScanForBA2ChunkFactory();
            if (chunkFacAddr) {
                char msg[160];
                std::snprintf(msg, sizeof(msg),
                    "FFC4: BA2 chunk factory located at %llX",
                    (unsigned long long)chunkFacAddr);
                LogInfo(msg);
            } else {
                LogWarn("FFC4: BA2 chunk factory scan failed — falling back to ReaderStream ctor");
            }
        }

        std::uintptr_t ctorAddr = 0;
        if (Settings::bUseNewFactoryHook && !chunkFacAddr) {
            auto base = REL::Module::get().base();
            if (REL::Module::IsF4()) {
                ctorAddr = base + 0x01B703C0;       // OG 1.10.163 PDB
            } else if (REL::Module::IsVR()) {
                ctorAddr = base + 0x01BEF7D0;       // VR 1.2.72 PDB
            } else {
                // NG 1.10.984 / AE 1.11.191 — no PDB, find via vtable xref.
                ctorAddr = ScanForReaderStreamCtor(s_readerStreamVtbl);
                if (ctorAddr) {
                    char msg[160];
                    std::snprintf(msg, sizeof(msg),
                        "FFC4: ReaderStream ctor located via vtable xref scan at %llX",
                        (unsigned long long)ctorAddr);
                    LogInfo(msg);
                } else {
                    LogWarn("FFC4: ReaderStream ctor xref scan found no candidate — falling back to LocationTree hook");
                }
            }
        }
        const bool useChunkFactory = (chunkFacAddr != 0);
        const bool useNewFactory   = !useChunkFactory && (ctorAddr != 0);
        std::uintptr_t factoryAddr = 0;
        void** origSlot = nullptr;
        void*  hookFn   = nullptr;

        if (useChunkFactory) {
            factoryAddr = chunkFacAddr;
            s_origBA2ChunkFactory = reinterpret_cast<BA2ChunkFactory_t>(factoryAddr);
            origSlot = reinterpret_cast<void**>(&s_origBA2ChunkFactory);
            hookFn   = reinterpret_cast<void*>(&HookedBA2ChunkFactory);
            char msg[160];
            std::snprintf(msg, sizeof(msg),
                "FFC4: Factory hook target = CHUNK (BA2 chunk factory) at %llX", factoryAddr);
            LogInfo(msg);
        } else if (useNewFactory) {
            factoryAddr = ctorAddr;
            s_origReaderStreamCtor = reinterpret_cast<ReaderStreamCtor_t>(factoryAddr);
            origSlot = reinterpret_cast<void**>(&s_origReaderStreamCtor);
            hookFn   = reinterpret_cast<void*>(&HookedReaderStreamCtor);
            char msg[160];
            std::snprintf(msg, sizeof(msg),
                "FFC4: Factory hook target = NEW (ReaderStream ctor) at %llX", factoryAddr);
            LogInfo(msg);
        } else {
            REL::Relocation<FactoryFunc_t> rf{ REL::RelocationID(476824, 2269550) };
            s_origFactory = rf.get();
            factoryAddr = rf.address();
            origSlot = reinterpret_cast<void**>(&s_origFactory);
            hookFn   = reinterpret_cast<void*>(&HookedFactory);
            char msg[160];
            std::snprintf(msg, sizeof(msg),
                "FFC4: Factory hook target = OLD (LocationTree::DoCreateStream) at %llX", factoryAddr);
            LogInfo(msg);
        }

        LONG err = DetourTransactionBegin();
        if (err == NO_ERROR) {
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(origSlot, hookFn);
            err = DetourTransactionCommit();
            if (err == NO_ERROR) {
                char buf[128];
                std::snprintf(buf, sizeof(buf),
                    "FFC4: Factory hook installed at %llX", factoryAddr);
                LogInfo(buf);
            } else {
                if (useChunkFactory)    s_origBA2ChunkFactory  = nullptr;
                else if (useNewFactory) s_origReaderStreamCtor = nullptr;
                else                    s_origFactory          = nullptr;
                LogWarn("FFC4: Factory Detours commit failed — trying private trampoline");

                // Fallback: allocate near game code (within ±2GB) for Detours relay
                auto gameBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(nullptr));
                bool hooked = false;
                for (std::uintptr_t off = 0x10000; off < 0x7FFF0000ULL; off += 0x10000) {
                    auto* mem = VirtualAlloc(reinterpret_cast<void*>(gameBase + off),
                        64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (mem) {
                        if (useChunkFactory)
                            s_origBA2ChunkFactory  = reinterpret_cast<BA2ChunkFactory_t>(factoryAddr);
                        else if (useNewFactory)
                            s_origReaderStreamCtor = reinterpret_cast<ReaderStreamCtor_t>(factoryAddr);
                        else
                            s_origFactory          = reinterpret_cast<FactoryFunc_t>(factoryAddr);
                        err = DetourTransactionBegin();
                        if (err == NO_ERROR) {
                            DetourUpdateThread(GetCurrentThread());
                            DetourAttach(origSlot, hookFn);
                            err = DetourTransactionCommit();
                            if (err == NO_ERROR) {
                                char msg[128];
                                std::snprintf(msg, sizeof(msg),
                                    "FFC4: Factory hook installed (private alloc at %llX)",
                                    reinterpret_cast<std::uintptr_t>(mem));
                                LogInfo(msg);
                                hooked = true;
                                break;
                            }
                        }
                        VirtualFree(mem, 0, MEM_RELEASE);
                    }
                }
                if (!hooked) {
                    if (useChunkFactory)    s_origBA2ChunkFactory  = nullptr;
                    else if (useNewFactory) s_origReaderStreamCtor = nullptr;
                    else                    s_origFactory          = nullptr;
                    LogWarn("FFC4: Factory hook failed — no trampoline available");
                }
            }
        } else {
            LogWarn("FFC4: Factory DetourTransactionBegin failed");
        }
    }

    // Hook T: BSTextureStreamer chain — serves texture BA2 reads from the
    // decomp cache via the existing inflate bridge. Currently VR-only.
    InstallTextureStreamerHooks();

    // AE-only: Manager vtbl[0xe0]/[0xf0] completion-dispatcher monitor.
    // Independent of bEnableTextureCache — installs when stats are on so we
    // can validate the Phase-2 capture+serve entry point without needing the
    // heavy ProcessEvent + vtbl[0x60] + HL-timing stack.
    InstallAEManagerDispatchHooks();

    auto modeMsg = std::string("FFC4: Startup hooks installed - mode: ")
        + (Settings::bBaselineMode ? "BASELINE" : "MMAP")
        + " (inflate hook deferred to kPostLoad)";
    LogInfo(modeMsg.c_str());
}

// Install the inflate hook. Called from F4SE kPostLoad, after all plugins
// (including FastDecompress) have finished loading. Detours chains LIFO —
// installing last means our hook runs *first*, so we can short-circuit to
// cached data when available, or call s_origInflate (which now points at
// FastDecompress's trampoline, or at the real inflate if FD is absent).
void InstallInflateHook()
{
    // Install when either the cache wants to serve, or stats wants to time
    // pure-zlib calls for an apples-to-apples cache-off baseline run.
    if (!Settings::bEnableDecompCache && !Settings::bEnableStats) {
        LogInfo("FFC4: Decomp cache disabled — skipping inflate hook");
        return;
    }
    if (s_origInflate) {
        LogWarn("FFC4: Inflate hook already installed");
        return;
    }

    bool hasFD = (GetModuleHandleA("FastDecompress.dll") != nullptr);

    std::uintptr_t inflateAddr = 0;
    auto base = REL::Module::get().base();

    if (REL::Module::IsVR()) {
        // FO4 VR 1.2.72 — hardcoded offset (FastDecompress VR fallback)
        inflateAddr = base + 0x01BD66A0;
    } else if (REL::Module::get().version() >= REL::Version{ 1, 10, 980, 0 }) {
        // FO4 NG 1.10.984 / AE 1.11.191 — Address Library ID 2168026
        // (verified: both runtimes map this ID to inflate at base+0x7860).
        // Avoids the signature scan entirely, which is unreliable when
        // FastDecompress.dll has already patched the prologue.
        REL::ID inflateID{ 2168026 };
        inflateAddr = inflateID.address();
        char msg[128];
        std::snprintf(msg, sizeof(msg),
            "FFC4: inflate resolved via Address Library ID 2168026 = %llX",
            static_cast<unsigned long long>(inflateAddr));
        LogInfo(msg);
    } else {
        // FO4 OG 1.10.163 — signature scan (no Address Library ID available
        // for inflate on OG's 1.10.163 id-numbering scheme).
        //
        // We can't simply scan for the inflate prologue
        //   89 54 24 10       mov [rsp+0x10], edx
        //   48 89 4C 24 08    mov [rsp+0x8], rcx
        //   55                push rbp
        //   41 54             push r12
        // because FastDecompress.dll loads alphabetically before us
        // (FastD… < FastF…) and its F4SEPlugin_Load has already patched
        // those bytes with an `E9 rel32` jmp by the time we run at kPostLoad.
        //
        // Instead, anchor on inflateEnd — FD does not hook it — then walk
        // back -0x1960 to find inflate. At that probe we accept either the
        // original prologue OR the Detoured form (E9 ?? ?? ?? ?? + the tail
        // of the original prologue that survives past the 5-byte jmp).
        static constexpr std::uint8_t kSigInflateOrig[] = {
            0x89, 0x54, 0x24, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x41, 0x54 };
        static constexpr std::uint8_t kSigInflateTail[] = {
            0x89, 0x4C, 0x24, 0x08, 0x55, 0x41, 0x54 };  // bytes 5..11 of original
        static constexpr std::ptrdiff_t kOffEnd = 0x1960;
        static constexpr std::uint8_t kSigEnd[] = {
            0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x85, 0xC9 };

        auto textSeg = REL::Module::get().segment(REL::Segment::text);
        auto* textBase = reinterpret_cast<const std::uint8_t*>(textSeg.address());
        auto textSize = textSeg.size();

        // ── collect candidates, require 16-byte function alignment ─────
        // Raw pattern counts include in-the-middle false positives; only
        // 16-byte-aligned hits are plausible function entries.
        std::vector<std::uintptr_t> alignedInflate;
        std::vector<std::uintptr_t> alignedInflateEnd;
        int nSigOrigRaw = 0, nSigEndRaw = 0;
        for (std::size_t i = 0; i + sizeof(kSigInflateOrig) < textSize; ++i) {
            if (std::memcmp(textBase + i, kSigInflateOrig, sizeof(kSigInflateOrig)) == 0) {
                ++nSigOrigRaw;
                auto va = textSeg.address() + i;
                if ((va & 0xF) == 0) alignedInflate.push_back(va);
            }
        }
        for (std::size_t i = 0; i + sizeof(kSigEnd) < textSize; ++i) {
            if (std::memcmp(textBase + i, kSigEnd, sizeof(kSigEnd)) == 0) {
                ++nSigEndRaw;
                auto va = textSeg.address() + i;
                if ((va & 0xF) == 0) alignedInflateEnd.push_back(va);
            }
        }
        {
            char diag[224];
            std::snprintf(diag, sizeof(diag),
                "FFC4 scan: kSigInflate raw=%d aligned=%zu, kSigEnd raw=%d aligned=%zu",
                nSigOrigRaw, alignedInflate.size(),
                nSigEndRaw,  alignedInflateEnd.size());
            LogInfo(diag);
            for (std::size_t k = 0; k < alignedInflate.size() && k < 8; ++k) {
                char d2[96];
                std::snprintf(d2, sizeof(d2), "FFC4   inflate cand[%zu]=%llX",
                    k, static_cast<unsigned long long>(alignedInflate[k]));
                LogInfo(d2);
            }
        }

        // ── primary: for each aligned inflate candidate, look for ANY
        //    aligned inflateEnd within a forward window [0x1000..0x3000].
        //    On 1.10.984 the observed delta was 0x1960; the window covers
        //    minor codegen drift across NG/AE builds.
        constexpr std::ptrdiff_t kMinDelta = 0x1000;
        constexpr std::ptrdiff_t kMaxDelta = 0x3000;
        for (auto cand : alignedInflate) {
            for (auto end : alignedInflateEnd) {
                auto delta = static_cast<std::ptrdiff_t>(end - cand);
                if (delta < kMinDelta || delta > kMaxDelta) continue;
                inflateAddr = cand;
                char msg[160];
                std::snprintf(msg, sizeof(msg),
                    "FFC4: inflate anchored via aligned prologue (delta=%llX)",
                    static_cast<unsigned long long>(delta));
                LogInfo(msg);
                break;
            }
            if (inflateAddr) break;
        }

        // ── fallback: FD already patched inflate's prologue. Anchor on
        //    an aligned inflateEnd, walk back in the same window, and
        //    accept either the original prologue or the Detoured form
        //    (E9 rel32 + 7-byte surviving tail of the original prologue).
        if (!inflateAddr) {
            for (auto end : alignedInflateEnd) {
                for (std::ptrdiff_t delta = kMinDelta; delta <= kMaxDelta; delta += 0x10) {
                    auto candVA = end - delta;
                    auto off = static_cast<std::ptrdiff_t>(candVA - textSeg.address());
                    if (off < 0 || off + 12 > static_cast<std::ptrdiff_t>(textSize)) continue;
                    const auto* bytes = textBase + off;
                    bool isOriginal =
                        std::memcmp(bytes, kSigInflateOrig, sizeof(kSigInflateOrig)) == 0;
                    bool isDetoured =
                        bytes[0] == 0xE9 &&
                        std::memcmp(bytes + 5, kSigInflateTail, sizeof(kSigInflateTail)) == 0;
                    if (isOriginal || isDetoured) {
                        inflateAddr = candVA;
                        char msg[160];
                        std::snprintf(msg, sizeof(msg),
                            "FFC4: inflate anchored via inflateEnd (%s form, delta=%llX)",
                            isDetoured ? "Detoured" : "original",
                            static_cast<unsigned long long>(delta));
                        LogInfo(msg);
                        break;
                    }
                }
                if (inflateAddr) break;
            }
        }
    }

    if (!inflateAddr) {
        LogWarn("FFC4: inflate not found — decomp cache BUILD enabled, SERVE disabled");
        return;
    }

    // Note: when FastDecompress is present, `inflateAddr` still points at the
    // original inflate function bytes in .text, but those bytes have already
    // been patched by FD's Detours attach (first bytes = jmp to FD's hook).
    // When we DetourAttach here, Detours reads the current prologue (which
    // includes FD's jmp), writes our own jmp, and generates a trampoline that
    // calls FD's hook. So s_origInflate ends up pointing at FD's hook, which
    // is exactly what we want — cache miss → FD decompresses → real inflate.
    s_origInflate = reinterpret_cast<inflate_fn>(inflateAddr);
    LONG err = DetourTransactionBegin();
    if (err != NO_ERROR) {
        s_origInflate = nullptr;
        LogWarn("FFC4: inflate DetourTransactionBegin failed");
        return;
    }
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<void**>(&s_origInflate),
                 reinterpret_cast<void*>(&HookedInflate));
    err = DetourTransactionCommit();
    if (err != NO_ERROR) {
        s_origInflate = nullptr;
        LogWarn("FFC4: inflate DetourTransactionCommit failed");
        return;
    }

    char buf[160];
    std::snprintf(buf, sizeof(buf),
        "FFC4: inflate hook installed at %llX%s",
        inflateAddr,
        hasFD ? " (chained after FastDecompress)" : "");
    LogInfo(buf);
}

void RequestShutdown()
{
    LogGameplaySummary();
    s_shutdownRequested.store(true, std::memory_order_release);
    LogInfo("FFC4: Shutdown requested — background threads will stop");
}

}  // namespace Hooks
