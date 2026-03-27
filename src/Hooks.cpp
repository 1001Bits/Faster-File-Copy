#include "PCH.h"
#include "Hooks.h"
#include "ArchiveStream.h"
#include "BSAMemoryMap.h"
#include "MmapStream.h"
#include "Settings.h"

#include <thread>
#include <chrono>

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

static const BSA::MappedArchive* SourceLookup(const void* source)
{
    auto k = reinterpret_cast<std::uintptr_t>(source);
    auto slot = static_cast<int>((k >> 4) & kHashMask);  // shift past alignment bits

    for (int i = 0; i < 16; ++i) {  // linear probe, max 16 steps
        auto stored = s_sourceHash[slot].key.load(std::memory_order_acquire);
        if (stored == k)
            return s_sourceHash[slot].archive.load(std::memory_order_relaxed);
        if (stored == 0)
            return nullptr;  // empty slot = not found
        slot = (slot + 1) & kHashMask;
    }
    return nullptr;
}

static void SourceInsert(const void* source, const BSA::MappedArchive* archive)
{
    auto k = reinterpret_cast<std::uintptr_t>(source);
    auto slot = static_cast<int>((k >> 4) & kHashMask);

    for (int i = 0; i < 16; ++i) {
        auto stored = s_sourceHash[slot].key.load(std::memory_order_relaxed);
        if (stored == k) return;  // already inserted
        if (stored == 0) {
            // Try to claim this slot
            std::uintptr_t expected = 0;
            s_sourceHash[slot].archive.store(archive, std::memory_order_relaxed);
            if (s_sourceHash[slot].key.compare_exchange_strong(expected, k,
                    std::memory_order_release, std::memory_order_relaxed)) {
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
static std::atomic<std::uint64_t> s_ticksResolve{ 0 };
static std::atomic<std::uint64_t> s_ticksDecomp{ 0 };

static const BSA::MappedArchive* ResolveSource(const void* source)
{
    auto* cached = SourceLookup(source);
    if (cached) return cached;

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
            auto** vtbl = *reinterpret_cast<void***>(innerStream);
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
static std::atomic<std::uint64_t> s_fallbackReads{ 0 };
static std::atomic<std::uint64_t> s_fallbackBytes{ 0 };

// Phase timing — declared here so they're visible to all functions below

static LARGE_INTEGER s_qpcFreq;
static std::int64_t s_installTime = 0;

static void InitTiming()
{
    QueryPerformanceFrequency(&s_qpcFreq);
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    s_installTime = now.QuadPart;
}

static double QpcToSec(std::int64_t ticks)
{
    return static_cast<double>(ticks) / s_qpcFreq.QuadPart;
}

void FreezeSourceCache()
{
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);

    double loadTimeSec = QpcToSec(now.QuadPart - s_installTime);
    const char* mode = Settings::bBaselineMode ? "BASELINE" : "MMAP";

    std::uint64_t reads = s_mmapReads.load(std::memory_order_relaxed);
    std::uint64_t bytes = s_mmapBytes.load(std::memory_order_relaxed);
    std::uint64_t fb = s_fallbackReads.load(std::memory_order_relaxed);
    std::uint64_t fbB = s_fallbackBytes.load(std::memory_order_relaxed);

    double tMmap    = QpcToSec(s_ticksMmapRead.load(std::memory_order_relaxed));
    double tFallback = QpcToSec(s_ticksFallbackRead.load(std::memory_order_relaxed));
    double tResolve = QpcToSec(s_ticksResolve.load(std::memory_order_relaxed));
    double tDecomp  = QpcToSec(s_ticksDecomp.load(std::memory_order_relaxed));
    double tIO      = tMmap + tFallback;
    double tOther   = loadTimeSec - tIO - tDecomp;

    logger::info("========================================");
    logger::info("[{}] LOAD TIME: {:.3f} seconds", mode, loadTimeSec);
    logger::info("[{}] PHASE BREAKDOWN:", mode);
    logger::info("[{}]   I/O (mmap+fallback):  {:.3f}s ({:.1f}%)", mode, tIO, tIO/loadTimeSec*100);
    logger::info("[{}]     mmap reads:         {:.3f}s  ({} reads, {:.1f} MB)", mode, tMmap, reads, bytes/(1024.*1024.));
    logger::info("[{}]     fallback reads:     {:.3f}s  ({} reads, {:.1f} MB)", mode, tFallback, fb, fbB/(1024.*1024.));
    logger::info("[{}]   Decompression:        {:.3f}s ({:.1f}%)", mode, tDecomp, tDecomp/loadTimeSec*100);
    logger::info("[{}]   Source resolution:    {:.3f}s", mode, tResolve);
    logger::info("[{}]   Other (parse/init):   {:.3f}s ({:.1f}%)", mode, tOther, tOther/loadTimeSec*100);
    logger::info("[{}]   Sources cached: {}", mode, s_sourceCacheCount.load(std::memory_order_relaxed));
    logger::info("========================================");
}

std::uint64_t GetMappedReadCount()    { return s_mmapReads.load(std::memory_order_relaxed); }
std::uint64_t GetMappedBytesServed()  { return s_mmapBytes.load(std::memory_order_relaxed); }
std::uint64_t GetFallbackReadCount()  { return s_fallbackReads.load(std::memory_order_relaxed); }
std::uint64_t GetStreamReplacements() { return 0; }
std::uint64_t GetTotalReadTicks()     { return 0; }
std::uint64_t GetTotalReadCount()     { return s_mmapReads.load() + s_fallbackReads.load(); }

// ═══════════════════════════════════════════════════════════════════════════
// Stats thread
// ═══════════════════════════════════════════════════════════════════════════

static void StatsThreadFn()
{
    constexpr int kSchedule[] = { 5, 5, 5, 5, 5, 5, 15, 15, 60 };
    constexpr int kScheduleLen = sizeof(kSchedule) / sizeof(kSchedule[0]);
    int schedIdx = 0;
    std::uint64_t prevMmap = 0, prevMmapB = 0, prevFB = 0, prevFBB = 0;
    const char* mode = Settings::bBaselineMode ? "BASELINE" : "MMAP";

    for (;;) {
        int waitSec = (schedIdx < kScheduleLen) ? kSchedule[schedIdx] : kSchedule[kScheduleLen - 1];
        std::this_thread::sleep_for(std::chrono::seconds(waitSec));
        ++schedIdx;

        auto mmap = s_mmapReads.load(std::memory_order_relaxed);
        auto mmapB = s_mmapBytes.load(std::memory_order_relaxed);
        auto fb = s_fallbackReads.load(std::memory_order_relaxed);
        auto fbB = s_fallbackBytes.load(std::memory_order_relaxed);

        auto dMmap = mmap - prevMmap; auto dMmapB = mmapB - prevMmapB;
        auto dFB = fb - prevFB; auto dFBB = fbB - prevFBB;
        prevMmap = mmap; prevMmapB = mmapB; prevFB = fb; prevFBB = fbB;

        if (dMmap == 0 && dFB == 0) continue;

        logger::info("[{}] delta: +{} mmap ({:.1f} MB), +{} fallback ({:.1f} MB) | "
                     "total: {} mmap ({:.1f} MB), {} fallback ({:.1f} MB)",
            mode, dMmap, dMmapB/(1024.*1024.), dFB, dFBB/(1024.*1024.),
            mmap, mmapB/(1024.*1024.), fb, fbB/(1024.*1024.));
    }
}

void StartStatsThread()
{
    if (!Settings::bEnableStats) return;
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
    LARGE_INTEGER t0; QueryPerformanceCounter(&t0);

    if (!Settings::bBaselineMode) {
        const auto* archive = SourceLookup(a_source);

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
                    LARGE_INTEGER t1; QueryPerformanceCounter(&t1);
                    s_ticksMmapRead.fetch_add(t1.QuadPart - t0.QuadPart, std::memory_order_relaxed);
                    s_mmapReads.fetch_add(1, std::memory_order_relaxed);
                    s_mmapBytes.fetch_add(n, std::memory_order_relaxed);
                    return 0;  // success
                }
            }

            if (a_bytesRead) *a_bytesRead = 0;
            return 0;
        }
    }

    // Unknown source or baseline — call original, PRESERVE return value
    int ret = s_origReadFromSource(a_source, a_buffer, a_readOffset, a_readSize, a_bytesRead);
    LARGE_INTEGER t1; QueryPerformanceCounter(&t1);
    s_ticksFallbackRead.fetch_add(t1.QuadPart - t0.QuadPart, std::memory_order_relaxed);
    s_fallbackReads.fetch_add(1, std::memory_order_relaxed);
    if (a_bytesRead)
        s_fallbackBytes.fetch_add(*a_bytesRead, std::memory_order_relaxed);
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
    if (Settings::bBaselineMode)
        return s_originalDoRead(a_this, a_buffer, a_toRead, a_read);

    // Serve uncompressed reads directly from mmap — bypasses the ENTIRE
    // source object chain (spinlock, buffered reader, ReadFromSource, ReadFile).
    auto* sourcePtr = BSResource::FieldAt<void* const>(a_this, BSResource::Field::Source);
    if (sourcePtr) {
        auto* archive = SourceLookup(sourcePtr);
        if (!archive) archive = ResolveSource(sourcePtr);

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
                    std::memcpy(a_buffer, src, static_cast<std::size_t>(n));
                    BSResource::FieldAt<std::uint32_t>(
                        const_cast<void*>(a_this), BSResource::Field::CurrentOffset) =
                        curOff + static_cast<std::uint32_t>(n);
                    a_read = n;
                    s_mmapReads.fetch_add(1, std::memory_order_relaxed);
                    s_mmapBytes.fetch_add(n, std::memory_order_relaxed);
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

static RE::BSResource::ErrorCode __fastcall HookedCompDoRead(
    const void*     a_this,
    void*           a_buffer,
    std::uint64_t   a_toRead,
    std::uint64_t&  a_read)
{
    auto* sourcePtr = BSResource::FieldAt<void* const>(a_this, BSResource::Field::Source);
    if (sourcePtr && !SourceLookup(sourcePtr))
        ResolveSource(sourcePtr);

    LARGE_INTEGER t0; QueryPerformanceCounter(&t0);
    auto err = s_originalCompDoRead(a_this, a_buffer, a_toRead, a_read);
    LARGE_INTEGER t1; QueryPerformanceCounter(&t1);
    s_ticksDecomp.fetch_add(t1.QuadPart - t0.QuadPart, std::memory_order_relaxed);
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
// Installation
// ═══════════════════════════════════════════════════════════════════════════

void Install()
{
    InitTiming();

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

    // ArchiveStream::DoRead vtable hook (populates source cache)
    {
        constexpr std::size_t kDoReadIdx = 0x06;
        auto* entries = reinterpret_cast<std::uintptr_t*>(s_archiveStreamVtbl);
        s_originalDoRead = reinterpret_cast<DoRead_t>(entries[kDoReadIdx]);
        REL::safe_write(
            s_archiveStreamVtbl + kDoReadIdx * sizeof(std::uintptr_t),
            reinterpret_cast<std::uintptr_t>(&HookedDoRead));
        logger::info("BSAMmap: ArchiveStream::DoRead hook installed (cache populator)");
    }

    // CompressedArchiveStream::DoRead vtable hook (populates source cache)
    {
        constexpr std::size_t kDoReadIdx = 0x06;
        auto* entries = reinterpret_cast<std::uintptr_t*>(s_compressedArchiveStreamVtbl);
        s_originalCompDoRead = reinterpret_cast<CompDoRead_t>(entries[kDoReadIdx]);
        REL::safe_write(
            s_compressedArchiveStreamVtbl + kDoReadIdx * sizeof(std::uintptr_t),
            reinterpret_cast<std::uintptr_t>(&HookedCompDoRead));
        logger::info("BSAMmap: CompressedArchiveStream::DoRead hook installed (cache populator)");
    }

    // SKSE trampoline hook on ReadFromSource call site.
    // Instead of Detours (which modifies the function prologue and can break
    // other mods), we patch the E8 call instruction in ArchiveStream::DoRead
    // that calls ReadFromSource.  This only touches 5 bytes at the call site
    // and is compatible with other SKSE plugins' trampoline hooks.
    {
        auto callSite = FindReadFromSourceCallSite();
        if (callSite) {
            auto& trampoline = SKSE::GetTrampoline();
            s_origReadFromSource = reinterpret_cast<ReadFromSource_t>(
                trampoline.write_call<5>(callSite,
                    reinterpret_cast<std::uintptr_t>(&HookedReadFromSource)));
            logger::info("BSAMmap: ReadFromSource call-site hook installed via SKSE trampoline — ALL BSA I/O via mmap");
        }
    }

    const char* mode = Settings::bBaselineMode ? "BASELINE (passthrough)" : "MMAP (active)";
    logger::info("BSAMmap: Hooks installed — mode: {}", mode);
}

}  // namespace Hooks
