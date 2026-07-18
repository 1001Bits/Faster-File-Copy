#include "PCH.h"
#include "Hooks.h"

#include "ArchiveStream.h"
#include "AtomicByteBudget.h"
#include "BSAMemoryMap.h"
#include "CompressedReadPolicy.h"
#include "DecompCache.h"
#include "PESectionSelect.h"
#include "Settings.h"
#include "StreamCursor.h"

#include <array>
#include <chrono>
#include <compare>
#include <limits>
#include <memory>
#include <optional>
#include <thread>

namespace Hooks
{

namespace
{

// Only these layouts have been reverse-engineered and validated.  Address
// Library resolves the vtables, but it cannot make undocumented object fields
// portable to an unknown executable.  Unknown runtimes therefore fail closed.
[[nodiscard]] bool IsVerifiedRuntime() noexcept
{
    const auto version = REL::Module::get().version();
    const auto isVersion = [&](std::uint16_t major, std::uint16_t minor,
                               std::uint16_t patch, std::uint16_t build = 0) {
        return version.major() == major && version.minor() == minor &&
               version.patch() == patch && version.build() == build;
    };

    if (REL::Module::IsVR()) {
        return isVersion(1, 4, 15);
    }

    // GOG AE 1.6.1179 verified against 1.6.1170 in Ghidra (2026-07-14): all 13
    // ArchiveStream and 13 CompressedArchiveStream vtable slots are
    // byte-identical functions (relocated to vtables 0x1419a9b88/0x1419a9bf8),
    // and every reverse-engineered field offset matches (source 0x18,
    // startOffset 0x20, currentOffset 0x24, streamFlags 0x10, name 0x28).
    return isVersion(1, 5, 97) || isVersion(1, 6, 1170) ||
           isVersion(1, 6, 1179);
}

static std::atomic<bool> s_hooksActive{ false };
static std::atomic<bool> s_installStarted{ false };

static std::uintptr_t s_rdataStart = 0;
static std::uintptr_t s_rdataEnd = 0;

[[nodiscard]] bool InitModuleRanges() noexcept
{
    const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    if (!base) {
        return false;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
        return false;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    const auto* section = IMAGE_FIRST_SECTION(nt);
    PESectionSelect::AddressRange rdata;
    for (std::uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        // PE section names are fixed-width identifiers, not prefixes. AE
        // 1.6.1170 contains two sections named ".text" (the latter is small,
        // writable data), which made the old last-prefix-match scan retain the
        // wrong code range. We only need the trusted vtable section here and
        // select the largest exact, readable .rdata range defensively.
        (void)PESectionSelect::Consider(
            rdata, base, section[i].Name, ".rdata",
            section[i].VirtualAddress, section[i].Misc.VirtualSize,
            section[i].Characteristics, IMAGE_SCN_MEM_READ);
    }

    s_rdataStart = rdata.begin;
    s_rdataEnd = rdata.end;
    return s_rdataStart < s_rdataEnd;
}

[[nodiscard]] bool IsReadableRange(const void* address, std::size_t size) noexcept
{
    if (!address || size == 0) {
        return false;
    }

    const auto start = reinterpret_cast<std::uintptr_t>(address);
    const auto end = start + size;
    if (start < 0x10000 || end < start) {
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(address, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT ||
        (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
        return false;
    }

    const auto regionStart = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
    const auto regionEnd = regionStart + mbi.RegionSize;
    return regionEnd >= regionStart && start >= regionStart && end <= regionEnd;
}

[[nodiscard]] bool IsExecutableAddress(const void* address) noexcept
{
    if (!address) {
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(address, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT ||
        (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
        return false;
    }

    switch (mbi.Protect & 0xFF) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

[[nodiscard]] bool TryReadSourceInner(
    const void* source, const void*& innerStream) noexcept
{
    innerStream = nullptr;
    if (!source) {
        return false;
    }
#if defined(_MSC_VER)
    // This is deliberately isolated from C++ objects requiring unwinding.
    // /EHsc does not translate access violations into catch(...), so the hot
    // source-cache lookup needs SEH to fail closed without a VirtualQuery on
    // every successful mapped read.
    __try {
        innerStream = *reinterpret_cast<void* const*>(
            static_cast<const std::byte*>(source) + 0x28);
        return innerStream != nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        innerStream = nullptr;
        return false;
    }
#else
    if (!IsReadableRange(source, 0x30)) {
        return false;
    }
    innerStream = *reinterpret_cast<void* const*>(
        static_cast<const std::byte*>(source) + 0x28);
    return innerStream != nullptr;
#endif
}

[[nodiscard]] bool TryCopyMapped(
    void* destination, const void* source, std::size_t size) noexcept
{
    if (!destination || !source || size == 0) return size == 0;
#if defined(_MSC_VER)
    __try {
        std::memcpy(destination, source, size);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
#else
    std::memcpy(destination, source, size);
    return true;
#endif
}

[[nodiscard]] bool IsInRange(std::uintptr_t address, std::size_t size,
                             std::uintptr_t begin, std::uintptr_t end) noexcept
{
    const auto rangeEnd = address + size;
    return address >= begin && rangeEnd >= address && rangeEnd <= end;
}

// -------------------------------------------------------------------------
// Source -> archive cache
// -------------------------------------------------------------------------

// Positive mappings are immutable for the game's lifetime.  A single writer
// mutex lets us publish archive before key; acquire-loading key then makes the
// value visible without the old key-before-value race. Negative results are
// memoized via NegativeSentinel(), keyed by (source, inner), with bounded
// revalidation: repeated reads of an unresolvable stream must not rerun several
// VirtualQuery calls and a virtual DoGetName on every chunk. Positive archive
// sources and their owned backing streams are process-lifetime engine objects;
// a recycled source with a different backing pointer still re-resolves.
static constexpr std::size_t kSourceHashSlots = 4096;
static constexpr std::size_t kSourceHashMask = kSourceHashSlots - 1;

struct SourceHashEntry
{
    std::atomic<std::uintptr_t> key{ 0 };
    // Even generation = coherent pair, odd = writer updating a recycled key.
    std::atomic<std::uint64_t> generation{ 0 };
    std::atomic<std::uintptr_t> innerStream{ 0 };
    std::atomic<const BSA::MappedArchive*> archive{ nullptr };
    std::atomic<std::uint64_t> validUntilMs{ 0 };
};

struct SourceCacheValue
{
    const void* innerStream{ nullptr };
    const BSA::MappedArchive* archive{ nullptr };
    std::uint64_t validUntilMs{ 0 };
};

static SourceHashEntry s_sourceHash[kSourceHashSlots];
static std::mutex s_sourceInsertMutex;
static std::shared_mutex s_sourceOverflowMutex;
static std::unordered_map<const void*, SourceCacheValue> s_sourceOverflow;

// Pointer-pair identities are stable in normal Skyrim archive-source objects,
// but bounded revalidation prevents an allocator recycling both addresses from
// inheriting an old archive for the rest of the process. Structural failures
// use a much shorter backoff so they cannot recreate the per-read probe storm.
static constexpr std::uint64_t kSourceNegativeValidationMs = 60ull * 1000ull;
static constexpr std::uint64_t kSourceRetryMs = 5ull * 1000ull;

// Sentinel archive value meaning "definitively resolved to no mapped BSA".
// A unique, non-null address that can never equal a real MappedArchive*.
[[nodiscard]] inline const BSA::MappedArchive* NegativeSentinel() noexcept
{
    static const int marker = 0;
    return reinterpret_cast<const BSA::MappedArchive*>(&marker);
}

[[nodiscard]] std::size_t SourceSlot(const void* source) noexcept
{
    auto key = reinterpret_cast<std::uintptr_t>(source);
    key ^= key >> 17;
    key *= static_cast<std::uintptr_t>(0x9E3779B185EBCA87ULL);
    return static_cast<std::size_t>((key >> 4) & kSourceHashMask);
}

[[nodiscard]] bool SourceLookup(const void* source,
                                const BSA::MappedArchive*& archive)
{
    archive = nullptr;
    if (!source) {
        return false;
    }

    // The stream holds a reference to source, so this field is live for the
    // duration of DoRead. Including the backing-stream identity prevents a
    // recycled source address from inheriting another archive's cache entry.
    const void* currentInner = nullptr;
    if (!TryReadSourceInner(source, currentInner)) return false;

    const auto key = reinterpret_cast<std::uintptr_t>(source);
    auto slot = SourceSlot(source);
    for (std::size_t probe = 0; probe < kSourceHashSlots; ++probe) {
        const auto stored = s_sourceHash[slot].key.load(std::memory_order_acquire);
        if (stored == key) {
            for (;;) {
                const auto before = s_sourceHash[slot].generation.load(
                    std::memory_order_acquire);
                if ((before & 1u) != 0) continue;
                const auto inner = s_sourceHash[slot].innerStream.load(
                    std::memory_order_relaxed);
                const auto candidate = s_sourceHash[slot].archive.load(
                    std::memory_order_relaxed);
                const auto validUntil = s_sourceHash[slot].validUntilMs.load(
                    std::memory_order_relaxed);
                const auto after = s_sourceHash[slot].generation.load(
                    std::memory_order_acquire);
                if (before != after) continue;
                if (inner != reinterpret_cast<std::uintptr_t>(currentInner))
                    return false;
                if (candidate == NegativeSentinel()) {
                    const auto now = GetTickCount64();
                    if (now >= validUntil) {
                        // Single-flight the refresh: one reader probes while
                        // all others keep using the short negative backoff.
                        auto expectedDeadline = validUntil;
                        const auto retryDeadline = now + kSourceRetryMs;
                        if (s_sourceHash[slot].validUntilMs.compare_exchange_strong(
                                expectedDeadline, retryDeadline,
                                std::memory_order_acq_rel,
                                std::memory_order_relaxed)) {
                            return false;
                        }
                    }
                    archive = nullptr;
                } else {
                    archive = candidate;
                }
                return true;  // definitive cached result (positive or negative)
            }
        }
        if (stored == 0) {
            break;
        }
        slot = (slot + 1) & kSourceHashMask;
    }

    std::shared_lock lock(s_sourceOverflowMutex);
    const auto it = s_sourceOverflow.find(source);
    if (it == s_sourceOverflow.end()) {
        return false;
    }
    if (it->second.innerStream != currentInner) return false;
    if (it->second.archive == NegativeSentinel()) {
        if (GetTickCount64() >= it->second.validUntilMs) return false;
        archive = nullptr;
    } else {
        archive = it->second.archive;
    }
    return true;  // definitive cached result (positive or negative)
}

void SourceInsert(const void* source, const void* innerStream,
                  const BSA::MappedArchive* archive, std::uint64_t validForMs)
{
    if (!source || !innerStream || !archive) {
        return;
    }

    const auto key = reinterpret_cast<std::uintptr_t>(source);
    const auto now = GetTickCount64();
    const auto validUntil = validForMs >
            (std::numeric_limits<std::uint64_t>::max)() - now
        ? (std::numeric_limits<std::uint64_t>::max)()
        : now + validForMs;
    std::lock_guard insertLock(s_sourceInsertMutex);

    auto slot = SourceSlot(source);
    for (std::size_t probe = 0; probe < kSourceHashSlots; ++probe) {
        const auto stored = s_sourceHash[slot].key.load(std::memory_order_acquire);
        if (stored == key) {
            const auto existingInner = s_sourceHash[slot].innerStream.load(
                std::memory_order_relaxed);
            const auto existingArchive = s_sourceHash[slot].archive.load(
                std::memory_order_relaxed);
            // A slower negative refresh must never overwrite a positive result
            // already published for the same source generation.
            if (existingInner == reinterpret_cast<std::uintptr_t>(innerStream) &&
                existingArchive != nullptr &&
                existingArchive != NegativeSentinel()) {
                return;
            }
            s_sourceHash[slot].generation.fetch_add(1, std::memory_order_acq_rel);
            s_sourceHash[slot].innerStream.store(
                reinterpret_cast<std::uintptr_t>(innerStream),
                std::memory_order_relaxed);
            s_sourceHash[slot].archive.store(archive, std::memory_order_relaxed);
            s_sourceHash[slot].validUntilMs.store(
                validUntil, std::memory_order_relaxed);
            s_sourceHash[slot].generation.fetch_add(1, std::memory_order_release);
            return;
        }
        if (stored == 0) {
            s_sourceHash[slot].archive.store(archive, std::memory_order_relaxed);
            s_sourceHash[slot].innerStream.store(
                reinterpret_cast<std::uintptr_t>(innerStream),
                std::memory_order_relaxed);
            s_sourceHash[slot].validUntilMs.store(
                validUntil, std::memory_order_relaxed);
            s_sourceHash[slot].key.store(key, std::memory_order_release);
            return;
        }
        slot = (slot + 1) & kSourceHashMask;
    }

    std::unique_lock overflowLock(s_sourceOverflowMutex);
    if (const auto existing = s_sourceOverflow.find(source);
        existing != s_sourceOverflow.end() &&
        existing->second.innerStream == innerStream &&
        existing->second.archive != nullptr &&
        existing->second.archive != NegativeSentinel()) {
        return;
    }
    s_sourceOverflow.insert_or_assign(
        source, SourceCacheValue{ innerStream, archive, validUntil });
}

// -------------------------------------------------------------------------
// Statistics
// -------------------------------------------------------------------------

struct AtomicReadPath
{
    std::atomic<std::uint64_t> calls{ 0 };
    std::atomic<std::uint64_t> requestedBytes{ 0 };
    std::atomic<std::uint64_t> returnedBytes{ 0 };
    std::atomic<std::uint64_t> failures{ 0 };
    std::atomic<std::uint64_t> qpcTicks{ 0 };
};

static AtomicReadPath s_directMmap{};
static AtomicReadPath s_directStock{};
static AtomicReadPath s_cachePath{};
static AtomicReadPath s_decompressorPath{};
static AtomicReadPath s_compressedSourceMmap{};
static AtomicReadPath s_compressedSourceStock{};
static std::atomic<std::uint64_t> s_cacheAttachments{ 0 };
static std::atomic<std::uint64_t> s_cacheSizeMismatches{ 0 };
static std::atomic<std::uint64_t> s_cacheNotReady{ 0 };
static std::atomic<std::uint64_t> s_cacheServeDisabled{ 0 };
static std::atomic<std::uint64_t> s_loadPhaseUncompressedCalls{ 0 };
static std::atomic<std::uint64_t> s_loadPhaseUncompressedRequestedBytes{ 0 };
static std::atomic<std::uint64_t> s_loadPhaseCompressedCalls{ 0 };
static std::atomic<std::uint64_t> s_loadPhaseCompressedRequestedBytes{ 0 };
static std::atomic<std::uint64_t> s_loadPhaseGrandfatheredCacheCalls{ 0 };
static std::atomic<bool> s_engineLoadActive{ false };
static std::atomic<std::uint64_t> s_sourcesResolved{ 0 };
static std::atomic<std::uint64_t> s_sourceSemanticMisses{ 0 };
static std::atomic<std::uint64_t> s_sourceStructuralBackoffs{ 0 };
static std::atomic<std::uint64_t> s_unknownCompressedCursors{ 0 };
static std::atomic<std::uint64_t> s_captureBudgetRejects{ 0 };
static std::atomic<std::uint64_t> s_captureSeekInvalidations{ 0 };
static std::atomic<std::uint64_t> s_capturesCompleted{ 0 };

static LARGE_INTEGER s_qpcFreq{};

[[nodiscard]] bool LoadPhaseAccelerationSuppressed() noexcept
{
    // The default true setting avoids even an atomic load on the production
    // hot path. The phase switch exists solely for the controlled A/B.
    return !Settings::bEnableDuringSaveLoad &&
        s_engineLoadActive.load(std::memory_order_acquire);
}

thread_local std::uint32_t s_nativeCompressedDepth = 0;

class NativeCompressedReadScope
{
public:
    explicit NativeCompressedReadScope(const bool a_enabled) noexcept :
        enabled_(a_enabled)
    {
        if (enabled_)
            ++s_nativeCompressedDepth;
    }
    ~NativeCompressedReadScope()
    {
        if (enabled_)
            --s_nativeCompressedDepth;
    }
    NativeCompressedReadScope(const NativeCompressedReadScope&) = delete;
    NativeCompressedReadScope& operator=(const NativeCompressedReadScope&) = delete;

private:
    bool enabled_{ false };
};

void RecordPath(AtomicReadPath& a_path, const std::uint64_t a_requested,
                const std::uint64_t a_returned, const bool a_failed,
                const std::uint64_t a_ticks) noexcept
{
    a_path.calls.fetch_add(1, std::memory_order_relaxed);
    a_path.requestedBytes.fetch_add(a_requested, std::memory_order_relaxed);
    a_path.returnedBytes.fetch_add(a_returned, std::memory_order_relaxed);
    if (a_failed)
        a_path.failures.fetch_add(1, std::memory_order_relaxed);
    a_path.qpcTicks.fetch_add(a_ticks, std::memory_order_relaxed);
}

[[nodiscard]] ReadPathStats SnapshotPath(const AtomicReadPath& a_path) noexcept
{
    return {
        a_path.calls.load(std::memory_order_relaxed),
        a_path.requestedBytes.load(std::memory_order_relaxed),
        a_path.returnedBytes.load(std::memory_order_relaxed),
        a_path.failures.load(std::memory_order_relaxed),
        a_path.qpcTicks.load(std::memory_order_relaxed)
    };
}

void RecordMappedPayload(const std::uint64_t a_requested,
                         const std::uint64_t a_returned,
                         const std::uint64_t a_ticks) noexcept
{
    RecordPath(s_nativeCompressedDepth > 0
            ? s_compressedSourceMmap : s_directMmap,
        a_requested, a_returned, false, a_ticks);
}

void RecordFallbackPayload(const std::uint64_t a_requested,
                           const std::uint64_t a_returned,
                           const bool a_failed,
                           const std::uint64_t a_ticks) noexcept
{
    RecordPath(s_nativeCompressedDepth > 0
            ? s_compressedSourceStock : s_directStock,
        a_requested, a_returned, a_failed, a_ticks);
}

void RecordCompressedPayload(const std::uint64_t a_requested,
                             const std::uint64_t a_returned,
                             const bool a_failed,
                             const std::uint64_t a_ticks) noexcept
{
    RecordPath(s_decompressorPath, a_requested, a_returned, a_failed, a_ticks);
}

[[nodiscard]] const char* EffectiveModeLabel() noexcept
{
    if (!s_hooksActive.load(std::memory_order_acquire)) {
        return "INACTIVE";
    }
    if (Settings::bBaselineMode) {
        return "BASELINE";
    }
    if (!Settings::bEnableMmap) {
        return Settings::bEnableDecompCache ? "CACHE+STOCK-IO" : "STOCK-IO";
    }
    return Settings::bEnableDecompCache ? "MMAP+CACHE" : "MMAP";
}

// -------------------------------------------------------------------------
// Safe source resolution
// -------------------------------------------------------------------------

[[nodiscard]] const BSA::MappedArchive* ResolveSource(const void* source) noexcept
{
    const BSA::MappedArchive* cached = nullptr;
    try {
        if (SourceLookup(source, cached)) {
            return cached;
        }
    } catch (...) {
        return nullptr;
    }

    const BSA::MappedArchive* result = nullptr;
    void* resolvedInnerStream = nullptr;
    bool haveInner = false;
    // Only a completed virtual name query is a semantic negative. Pointer,
    // vtable, and target validation failures may be transient or belong to a
    // third-party source type and receive a bounded retry instead.
    bool nameProbeCompleted = false;
    try {
        // Verified source layout: the backing stream pointer is at +0x28.
        if (IsReadableRange(source, 0x30)) {
            auto* innerStream = *reinterpret_cast<void* const*>(
                static_cast<const std::byte*>(source) + 0x28);
            resolvedInnerStream = innerStream;
            haveInner = true;

            if (IsReadableRange(innerStream, sizeof(std::uintptr_t))) {
                const auto innerVtable =
                    *reinterpret_cast<const std::uintptr_t*>(innerStream);
                constexpr std::size_t kRequiredVtableEntries = 0x0B;
                if (IsInRange(innerVtable,
                        kRequiredVtableEntries * sizeof(std::uintptr_t),
                        s_rdataStart, s_rdataEnd) &&
                    IsReadableRange(reinterpret_cast<const void*>(innerVtable),
                        kRequiredVtableEntries * sizeof(std::uintptr_t))) {
                    auto** vtable = reinterpret_cast<void**>(innerVtable);
                    auto* getNameAddress = vtable[0x0A];
                    // The vtable itself is owned by the game's trusted .rdata,
                    // but a legitimate plugin may detour the virtual target to
                    // another executable module. Executable-page validation is
                    // therefore the correct ownership-independent guard.
                    if (IsExecutableAddress(getNameAddress)) {
                        using DoGetName_t = bool (*)(void*, RE::BSFixedString*);
                        RE::BSFixedString name;
                        const bool hasName =
                            reinterpret_cast<DoGetName_t>(getNameAddress)(
                                innerStream, &name);
                        if (hasName) {
                            const char* value = name.c_str();
                            if (value && value[0] != '\0') {
                                const std::filesystem::path path(value);
                                result = BSA::MemoryMapManager::GetSingleton()
                                             .FindByName(path.filename().string());
                                // A valid, non-empty name with no matching
                                // loaded BSA is a semantic negative. False or
                                // empty names may be lazy initialization and
                                // retain the short structural retry.
                                nameProbeCompleted = true;
                            }
                        }
                    }
                }
            }
        }
    } catch (...) {
        result = nullptr;
        nameProbeCompleted = false;
    }

    try {
        if (result) {
            s_sourcesResolved.fetch_add(1, std::memory_order_relaxed);
            SourceInsert(source, resolvedInnerStream, result,
                (std::numeric_limits<std::uint64_t>::max)());
            if (Settings::bLogReads) {
                logger::debug("BSAMmap: resolved source {:X} -> {}",
                    reinterpret_cast<std::uintptr_t>(source),
                    result->GetPath().filename().string());
            }
        } else if (haveInner && resolvedInnerStream) {
            // A semantic miss and a structural failure both fall back to the
            // stock path. The former is revalidated periodically for pointer
            // reuse; the latter retries sooner without probing on every read.
            (nameProbeCompleted ? s_sourceSemanticMisses :
                s_sourceStructuralBackoffs).fetch_add(1, std::memory_order_relaxed);
            SourceInsert(source, resolvedInnerStream, NegativeSentinel(),
                nameProbeCompleted ? kSourceNegativeValidationMs : kSourceRetryMs);
        }
    } catch (...) {
        // Resolution remains usable if an optional cache insertion or
        // diagnostic allocation fails.
    }

    return result;
}

// -------------------------------------------------------------------------
// ArchiveStream (uncompressed) hook
// -------------------------------------------------------------------------

static std::uintptr_t s_archiveStreamVtable = 0;
using DoRead_t = RE::BSResource::ErrorCode (*)(
    const void*, void*, std::uint64_t, std::uint64_t&);
static DoRead_t s_originalDoRead = nullptr;

RE::BSResource::ErrorCode CallOriginalArchiveRead(
    const void* stream, void* buffer, std::uint64_t toRead,
    std::uint64_t& read)
{
    const bool measure = Settings::bMeasureStats;
    LARGE_INTEGER started{};
    if (measure)
        QueryPerformanceCounter(&started);
    const auto error = s_originalDoRead(stream, buffer, toRead, read);
    if (measure) {
        LARGE_INTEGER finished{};
        QueryPerformanceCounter(&finished);
        RecordFallbackPayload(toRead, read,
            error != RE::BSResource::ErrorCode::kNone,
            finished.QuadPart >= started.QuadPart
                ? static_cast<std::uint64_t>(
                    finished.QuadPart - started.QuadPart)
                : 0);
    }
    return error;
}

RE::BSResource::ErrorCode __fastcall HookedDoRead(
    const void* stream, void* buffer, std::uint64_t toRead,
    std::uint64_t& read)
{
    const bool loadSuppressed = LoadPhaseAccelerationSuppressed();
    if (loadSuppressed && Settings::bMeasureStats) {
        s_loadPhaseUncompressedCalls.fetch_add(1, std::memory_order_relaxed);
        s_loadPhaseUncompressedRequestedBytes.fetch_add(
            toRead, std::memory_order_relaxed);
    }
    if (!s_hooksActive.load(std::memory_order_acquire) ||
        Settings::bBaselineMode || !Settings::bEnableMmap ||
        loadSuppressed || (toRead > 0 && !buffer)) {
        return CallOriginalArchiveRead(stream, buffer, toRead, read);
    }

    auto* source = BSResource::FieldAt<void* const>(
        stream, BSResource::Field::Source);
    const auto* archive = source ? ResolveSource(source) : nullptr;
    if (!archive || !archive->IsMapped()) {
        return CallOriginalArchiveRead(stream, buffer, toRead, read);
    }

    const auto startOffset = BSResource::FieldAt<const std::uint32_t>(
        stream, BSResource::Field::StartOffset);
    const auto totalSize = BSResource::FieldAt<const std::uint32_t>(
        stream, BSResource::Field::TotalSize);

    // Validate the complete immutable entry before claiming cursor bytes.  Once
    // a range is claimed it cannot safely be rolled back around other readers.
    const auto* entry = totalSize > 0 ? archive->At(startOffset, totalSize) : nullptr;
    if (totalSize > 0 && !entry) {
        return CallOriginalArchiveRead(stream, buffer, toRead, read);
    }

    auto& cursor = BSResource::FieldAt<std::uint32_t>(
        const_cast<void*>(stream), BSResource::Field::CurrentOffset);
    const auto claim = StreamCursor::ClaimRange(
        cursor, startOffset, totalSize, toRead);
    if (!claim.IsValid()) {
        return CallOriginalArchiveRead(stream, buffer, toRead, read);
    }

    LARGE_INTEGER copyStarted{};
    if (Settings::bMeasureStats)
        QueryPerformanceCounter(&copyStarted);
    if (claim.size > 0) {
        std::memcpy(buffer, entry + claim.relativeOffset, claim.size);
    }
    read = claim.size;

    if (Settings::bMeasureStats) {
        LARGE_INTEGER copyFinished{};
        QueryPerformanceCounter(&copyFinished);
        RecordMappedPayload(toRead, claim.size,
            copyFinished.QuadPart >= copyStarted.QuadPart
                ? static_cast<std::uint64_t>(
                    copyFinished.QuadPart - copyStarted.QuadPart)
                : 0);
    }
    if (Settings::bLogReads && claim.size > 0) {
        try {
            logger::debug("BSAMmap: mmap read offset=0x{:X}, bytes={}",
                claim.absoluteOffset, claim.size);
        } catch (...) {
        }
    }

    return RE::BSResource::ErrorCode::kNone;
}

// -------------------------------------------------------------------------
// CompressedArchiveStream side state and hooks
// -------------------------------------------------------------------------

static std::uintptr_t s_compressedArchiveStreamVtable = 0;

using CompDtor_t = void* (*)(void*, std::uint32_t);
using CompDoOpen_t = RE::BSResource::ErrorCode (*)(void*);
using CompDoClose_t = void (*)(void*);
using CompDoClone_t = void (*)(
    const void*, RE::BSTSmartPointer<RE::BSResource::Stream>&);
using CompDoRead_t = RE::BSResource::ErrorCode (*)(
    const void*, void*, std::uint64_t, std::uint64_t&);
using CompDoSeek_t = RE::BSResource::ErrorCode (*)(
    const void*, std::uint64_t, RE::BSResource::SeekMode, std::uint64_t&);

static CompDtor_t s_originalCompDtor = nullptr;
static CompDoOpen_t s_originalCompDoOpen = nullptr;
static CompDoClose_t s_originalCompDoClose = nullptr;
static CompDoClone_t s_originalCompDoClone = nullptr;
static CompDoRead_t s_originalCompDoRead = nullptr;
static CompDoSeek_t s_originalCompDoSeek = nullptr;

struct StreamIdentity
{
    const void* source{ nullptr };
    const BSA::MappedArchive* archive{ nullptr };
    std::uint32_t startOffset{ 0 };
    std::uint32_t totalSize{ 0 };

    [[nodiscard]] bool operator==(const StreamIdentity&) const noexcept = default;
};

enum class CaptureStatus : std::uint8_t
{
    kEmpty,
    kActive,
    kCompleted,
    kInvalid
};

// A corrupt decompressed-size field must not grow a side accumulator toward
// the 32-bit stream limit.  Large valid resources continue through the stock
// decompressor; they simply are not learned by this cache build.
static constexpr std::uint32_t kMaxCaptureEntrySize =
    (std::min)(BSA::CacheFormat::kMaxPayloadSize, 64u * 1024u * 1024u);
static constexpr std::uint64_t kMaxConcurrentCaptureBytes = 256ull * 1024ull * 1024ull;
static AtomicByteBudget s_captureBudget{ kMaxConcurrentCaptureBytes };

[[nodiscard]] std::uint32_t ResolveDeclaredDecompressedSize(
    const BSA::MappedArchive* archive, std::uint32_t startOffset)
{
    if (!archive)
        return 0;
    return archive->GetDeclaredDecompressedSize(startOffset).value_or(0);
}

class CaptureBudgetChargeGuard
{
public:
    explicit CaptureBudgetChargeGuard(std::uint64_t& charge) noexcept : charge_(charge) {}
    ~CaptureBudgetChargeGuard()
    {
        if (charge_ > 0) {
            (void)s_captureBudget.Release(charge_);
        }
    }

    CaptureBudgetChargeGuard(const CaptureBudgetChargeGuard&) = delete;
    CaptureBudgetChargeGuard& operator=(const CaptureBudgetChargeGuard&) = delete;

private:
    std::uint64_t& charge_;
};

struct CompressedStreamState
{
    explicit CompressedStreamState(
        StreamIdentity value, std::uint32_t initialCursor = 0) :
        identity(value), logicalCursor(initialCursor)
    {}

    ~CompressedStreamState()
    {
        if (accountedCaptureBytes > 0) {
            (void)s_captureBudget.Release(accountedCaptureBytes);
        }
    }

    std::mutex ioMutex;
    std::atomic<bool> retired{ false };
    const StreamIdentity identity;
    // Relative decompressed cursor. CompressedArchiveStream keeps its logical
    // position in separate decompressor state (AE 1.6.1170 uses object+0x38),
    // not ArchiveStream::CurrentOffset (+0x24). Never mirror this into that
    // native source-position field.
    std::atomic<std::uint32_t> logicalCursor{ 0 };
    // A failed native cursor query must never be interpreted as byte zero for
    // cache delivery. Atomic because identity upgrades inspect it before they
    // acquire the per-state I/O mutex.
    std::atomic<bool> cursorKnown{ true };

    bool cacheLookupAttempted{ false };
    const std::uint8_t* cacheData{ nullptr };
    std::uint32_t cacheSize{ 0 };
    std::shared_ptr<BSA::MappedView> cacheOwner;

    CaptureStatus captureStatus{ CaptureStatus::kEmpty };
    std::uint32_t nextCaptureOffset{ 0 };
    std::vector<std::uint8_t> captureBuffer;
    // Full entry reservation charged before captureBuffer allocates. Charging
    // only appended bytes understated vector capacity and allowed many active
    // streams to reserve substantially more RAM than the advertised bound.
    // Access is serialized by ioMutex; destruction follows retirement.
    std::uint64_t accountedCaptureBytes{ 0 };
};

void ClearCaptureBuffer(CompressedStreamState& state) noexcept
{
    if (state.accountedCaptureBytes > 0) {
        (void)s_captureBudget.Release(state.accountedCaptureBytes);
        state.accountedCaptureBytes = 0;
    }
    // Release capacity as well as size. Retaining a large failed/abandoned
    // accumulator would defeat the global RAM bound even after its accounting
    // was returned.
    std::vector<std::uint8_t>().swap(state.captureBuffer);
}

static constexpr std::size_t kStreamShardCount = 32;
static constexpr std::size_t kStreamShardMask = kStreamShardCount - 1;

struct StreamStateShard
{
    std::mutex mutex;
    std::unordered_map<const void*, std::shared_ptr<CompressedStreamState>> states;
};

static StreamStateShard s_streamStateShards[kStreamShardCount];

thread_local const void* t_lastCompressedStream = nullptr;
thread_local std::weak_ptr<CompressedStreamState> t_lastCompressedState;

[[nodiscard]] std::size_t StreamShardIndex(const void* stream) noexcept
{
    auto value = reinterpret_cast<std::uintptr_t>(stream);
    value ^= value >> 19;
    return static_cast<std::size_t>((value >> 4) & kStreamShardMask);
}

[[nodiscard]] std::shared_ptr<CompressedStreamState> FindCompressedState(
    const void* stream)
{
    if (stream == t_lastCompressedStream) {
        if (auto state = t_lastCompressedState.lock();
            state && !state->retired.load(std::memory_order_acquire)) {
            return state;
        }
    }

    auto& shard = s_streamStateShards[StreamShardIndex(stream)];
    std::lock_guard lock(shard.mutex);
    const auto it = shard.states.find(stream);
    if (it == shard.states.end() ||
        it->second->retired.load(std::memory_order_acquire)) {
        return {};
    }

    t_lastCompressedStream = stream;
    t_lastCompressedState = it->second;
    return it->second;
}

[[nodiscard]] std::shared_ptr<CompressedStreamState> PublishCompressedStateIfAbsent(
    const void* stream, const std::shared_ptr<CompressedStreamState>& state)
{
    auto& shard = s_streamStateShards[StreamShardIndex(stream)];
    std::lock_guard lock(shard.mutex);
    const auto it = shard.states.find(stream);
    if (it != shard.states.end() &&
        !it->second->retired.load(std::memory_order_acquire)) {
        t_lastCompressedStream = stream;
        t_lastCompressedState = it->second;
        return it->second;
    }
    if (it != shard.states.end()) {
        it->second->retired.store(true, std::memory_order_release);
    }
    shard.states[stream] = state;
    t_lastCompressedStream = stream;
    t_lastCompressedState = state;
    return state;
}

[[nodiscard]] bool TryReplaceCompressedState(
    const void* stream, const std::shared_ptr<CompressedStreamState>& expected,
    const std::shared_ptr<CompressedStreamState>& replacement)
{
    auto& shard = s_streamStateShards[StreamShardIndex(stream)];
    std::lock_guard lock(shard.mutex);
    const auto it = shard.states.find(stream);
    if (it == shard.states.end() || it->second != expected ||
        expected->retired.load(std::memory_order_acquire)) {
        return false;
    }
    expected->retired.store(true, std::memory_order_release);
    it->second = replacement;
    t_lastCompressedStream = stream;
    t_lastCompressedState = replacement;
    return true;
}

void ReplaceCompressedState(
    const void* stream, const std::shared_ptr<CompressedStreamState>& state)
{
    auto& shard = s_streamStateShards[StreamShardIndex(stream)];
    std::lock_guard lock(shard.mutex);
    const auto it = shard.states.find(stream);
    if (it != shard.states.end()) {
        it->second->retired.store(true, std::memory_order_release);
    }
    shard.states[stream] = state;
    t_lastCompressedStream = stream;
    t_lastCompressedState = state;
}

void RetireCompressedState(const void* stream)
{
    if (!stream) {
        return;
    }

    std::shared_ptr<CompressedStreamState> state;
    auto& shard = s_streamStateShards[StreamShardIndex(stream)];
    {
        std::lock_guard lock(shard.mutex);
        const auto it = shard.states.find(stream);
        if (it != shard.states.end()) {
            state = std::move(it->second);
            shard.states.erase(it);
            state->retired.store(true, std::memory_order_release);
        }
    }

    if (stream == t_lastCompressedStream) {
        t_lastCompressedStream = nullptr;
        t_lastCompressedState.reset();
    }

    // Lifecycle completion waits for an in-flight read/copy before allowing
    // the engine to close or destroy the underlying stream object.
    if (state) {
        std::unique_lock waitForRead(state->ioMutex);
    }
}

[[nodiscard]] StreamIdentity InspectCompressedStream(const void* stream)
{
    auto* source = BSResource::FieldAt<void* const>(
        stream, BSResource::Field::Source);
    const auto* archive = source ? ResolveSource(source) : nullptr;
    const auto startOffset = BSResource::FieldAt<const std::uint32_t>(
        stream, BSResource::Field::StartOffset);
    if (const auto state = FindCompressedState(stream);
        state && state->identity.source == source &&
        state->identity.archive == archive &&
        state->identity.startOffset == startOffset &&
        state->identity.totalSize > 0) {
        return state->identity;
    }
    const auto totalSize = ResolveDeclaredDecompressedSize(archive, startOffset);
    return StreamIdentity{ source, archive, startOffset, totalSize };
}

[[nodiscard]] std::optional<std::uint32_t> QueryCompressedLogicalCursor(
    const void* stream, std::uint32_t totalSize) noexcept
{
    // The decompressed cursor is private CompressedArchiveStream state and is
    // not ArchiveStream::CurrentOffset.  Asking the original implementation
    // for a zero-distance current seek gives us a layout-independent initial
    // position for streams that existed before our side state was created.
    try {
        std::uint64_t position = 0;
        const auto error = s_originalCompDoSeek(
            stream, 0, RE::BSResource::SeekMode::kCur, position);
        if (error == RE::BSResource::ErrorCode::kNone &&
            (totalSize == 0 || position <= totalSize) &&
            position <= (std::numeric_limits<std::uint32_t>::max)()) {
            return static_cast<std::uint32_t>(position);
        }
    } catch (...) {
    }
    return std::nullopt;
}

[[nodiscard]] std::shared_ptr<CompressedStreamState> GetOrCreateCompressedState(
    const void* stream, const StreamIdentity& identity)
{
    if (auto state = FindCompressedState(stream)) {
        return state;
    }
    const auto cursor = QueryCompressedLogicalCursor(stream, identity.totalSize);
    if (!cursor) {
        s_unknownCompressedCursors.fetch_add(1, std::memory_order_relaxed);
        auto state = std::make_shared<CompressedStreamState>(identity, 0);
        state->cursorKnown.store(false, std::memory_order_relaxed);
        return PublishCompressedStateIfAbsent(stream, state);
    }
    return PublishCompressedStateIfAbsent(
        stream, std::make_shared<CompressedStreamState>(identity, *cursor));
}

void ResetCaptureAfterSeek(CompressedStreamState& state,
                           std::uint32_t logicalOffset)
{
    ClearCaptureBuffer(state);
    state.nextCaptureOffset = 0;
    state.captureStatus = logicalOffset == 0
        ? CaptureStatus::kEmpty
        : CaptureStatus::kInvalid;
}

[[nodiscard]] bool BeginCapture(
    CompressedStreamState& state, std::uint32_t totalSize)
{
    ClearCaptureBuffer(state);
    if (totalSize == 0) {
        state.captureStatus = CaptureStatus::kInvalid;
        return false;
    }
    if (!s_captureBudget.TryReserve(totalSize)) {
        s_captureBudgetRejects.fetch_add(1, std::memory_order_relaxed);
        state.captureStatus = CaptureStatus::kInvalid;
        return false;
    }

    state.accountedCaptureBytes = totalSize;
    try {
        // Allocate once while the complete capacity is charged to the global
        // budget. This removes repeated vector growth/copies and makes the RAM
        // bound reflect capacity, not merely bytes appended so far.
        state.captureBuffer.reserve(totalSize);
    } catch (...) {
        state.captureStatus = CaptureStatus::kInvalid;
        ClearCaptureBuffer(state);
        return false;
    }
    state.nextCaptureOffset = 0;
    state.captureStatus = CaptureStatus::kActive;
    return true;
}

[[nodiscard]] bool AppendCapture(
    CompressedStreamState& state, std::uint32_t totalSize,
    const void* buffer, std::uint64_t read, bool beginCapture,
    std::vector<std::uint8_t>& completed,
    std::uint64_t& completedCaptureCharge)
{
    if (!buffer || read == 0 || state.nextCaptureOffset > totalSize ||
        read > totalSize - state.nextCaptureOffset) {
        state.captureStatus = CaptureStatus::kInvalid;
        ClearCaptureBuffer(state);
        return false;
    }
    if (beginCapture && !BeginCapture(state, totalSize)) {
        return false;
    }
    if (state.captureStatus != CaptureStatus::kActive ||
        read > totalSize - state.nextCaptureOffset) {
        state.captureStatus = CaptureStatus::kInvalid;
        ClearCaptureBuffer(state);
        return false;
    }

    try {
        const auto* bytes = static_cast<const std::uint8_t*>(buffer);
        state.captureBuffer.insert(
            state.captureBuffer.end(), bytes, bytes + read);
        state.nextCaptureOffset += static_cast<std::uint32_t>(read);
        if (state.nextCaptureOffset == totalSize &&
            state.captureBuffer.size() == totalSize) {
            // Transfer the charge to the caller until RecordDecompressed has
            // either admitted the vector to its independently bounded pending
            // queue or rejected it. Otherwise completed vectors briefly belong
            // to neither budget and concurrency can exceed the RAM bound.
            completedCaptureCharge = state.accountedCaptureBytes;
            state.accountedCaptureBytes = 0;
            completed = std::move(state.captureBuffer);
            state.captureStatus = CaptureStatus::kCompleted;
            s_capturesCompleted.fetch_add(1, std::memory_order_relaxed);
        }
        return true;
    } catch (...) {
        state.captureStatus = CaptureStatus::kInvalid;
        ClearCaptureBuffer(state);
        return false;
    }
}

void TryAttachCachedEntry(CompressedStreamState& state)
{
    if (state.cacheLookupAttempted ||
        !state.cursorKnown.load(std::memory_order_acquire) ||
        !Settings::bEnableDecompCache ||
        !state.identity.archive || state.identity.totalSize == 0) {
        return;
    }

    // Do not make a new cache/native path choice in a suppressed load phase.
    // Existing cache-backed streams are handled by HookedCompDoRead and must
    // remain cache-backed because their native decompressor cursor is stale.
    if (LoadPhaseAccelerationSuppressed())
        return;

    if (!Settings::bServeDecompCache) {
        state.cacheLookupAttempted = true;
        if (Settings::bMeasureStats)
            s_cacheServeDisabled.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    auto& cache = BSA::DecompCache::GetSingleton();
    if (!cache.IsReady()) {
        if (Settings::bMeasureStats)
            s_cacheNotReady.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    state.cacheLookupAttempted = true;
    auto entry = cache.Lookup(state.identity.archive, state.identity.startOffset);
    if (!entry) {
        return;
    }

    // A cache entry is only interchangeable with this stream when its exact
    // payload length matches the BSA block's declared decompressed length.
    if (entry.size != state.identity.totalSize) {
        if (Settings::bMeasureStats)
            s_cacheSizeMismatches.fetch_add(1, std::memory_order_relaxed);
        logger::warn(
            "BSAMmap: invalidating cache entry at 0x{:X}: cached size {} != BSA-declared decompressed size {}",
            state.identity.startOffset, entry.size, state.identity.totalSize);
        cache.ReportCacheValidationFailure(entry.owner);
        return;
    }

    state.cacheData = entry.data;
    state.cacheSize = entry.size;
    state.cacheOwner = std::move(entry.owner);
    if (Settings::bMeasureStats)
        s_cacheAttachments.fetch_add(1, std::memory_order_relaxed);
    state.captureStatus = CaptureStatus::kInvalid;
    ClearCaptureBuffer(state);
}

[[nodiscard]] RE::BSResource::ErrorCode ServeCachedRead(
    CompressedStreamState& state, void* buffer,
    std::uint64_t toRead, std::uint64_t& read)
{
    read = 0;
    if (!state.cacheData || state.cacheSize == 0 || (toRead > 0 && !buffer)) {
        return RE::BSResource::ErrorCode::kInvalidParam;
    }
    if (state.cacheOwner &&
        state.cacheOwner->unusable.load(std::memory_order_acquire)) {
        return RE::BSResource::ErrorCode::kFileError;
    }

    const auto claim = StreamCursor::ClaimRange(
        state.logicalCursor, 0, state.cacheSize, toRead);
    if (!claim.IsValid()) {
        return RE::BSResource::ErrorCode::kInvalidParam;
    }

    LARGE_INTEGER copyStarted{};
    if (Settings::bMeasureStats)
        QueryPerformanceCounter(&copyStarted);
    if (claim.size > 0) {
        if (!TryCopyMapped(
                buffer, state.cacheData + claim.relativeOffset, claim.size)) {
            // ClaimRange advances before the copy. The per-stream I/O mutex is
            // held by the caller, so rolling back is race-free. Its native
            // decompressor cursor may already be stale after earlier cache
            // reads; return a file error instead of mixing the two paths.
            state.logicalCursor.store(
                claim.absoluteOffset, std::memory_order_release);
            BSA::DecompCache::GetSingleton().ReportMappingIoFailure(
                state.cacheOwner);
            read = 0;
            if (Settings::bMeasureStats) {
                LARGE_INTEGER copyFinished{};
                QueryPerformanceCounter(&copyFinished);
                RecordPath(s_cachePath, toRead, 0, true,
                    copyFinished.QuadPart >= copyStarted.QuadPart
                        ? static_cast<std::uint64_t>(
                            copyFinished.QuadPart - copyStarted.QuadPart)
                        : 0);
            }
            return RE::BSResource::ErrorCode::kFileError;
        }
    }
    read = claim.size;

    if (Settings::bMeasureStats) {
        LARGE_INTEGER copyFinished{};
        QueryPerformanceCounter(&copyFinished);
        RecordPath(s_cachePath, toRead, claim.size, false,
            copyFinished.QuadPart >= copyStarted.QuadPart
                ? static_cast<std::uint64_t>(
                    copyFinished.QuadPart - copyStarted.QuadPart)
                : 0);
    }
    if (Settings::bLogReads && claim.size > 0) {
        try {
            logger::debug("BSAMmap: decompression-cache read entry=0x{:X}, pos={}, bytes={}",
                state.identity.startOffset, claim.relativeOffset, claim.size);
        } catch (...) {
        }
    }

    return RE::BSResource::ErrorCode::kNone;
}

RE::BSResource::ErrorCode CallOriginalCompressedRead(
    const void* stream, void* buffer, std::uint64_t toRead,
    std::uint64_t& read)
{
    const bool measure = Settings::bMeasureStats;
    LARGE_INTEGER started{};
    if (measure)
        QueryPerformanceCounter(&started);
    RE::BSResource::ErrorCode error{};
    {
        NativeCompressedReadScope sourceScope(measure);
        error = s_originalCompDoRead(stream, buffer, toRead, read);
    }
    if (measure) {
        LARGE_INTEGER finished{};
        QueryPerformanceCounter(&finished);
        RecordCompressedPayload(toRead, read,
            error != RE::BSResource::ErrorCode::kNone,
            finished.QuadPart >= started.QuadPart
                ? static_cast<std::uint64_t>(
                    finished.QuadPart - started.QuadPart)
                : 0);
    }
    return error;
}

void* __fastcall HookedCompDtor(void* stream, std::uint32_t flags)
{
    try {
        RetireCompressedState(stream);
    } catch (...) {
        // Never allow bookkeeping failure to escape an engine destructor.
    }
    return s_originalCompDtor(stream, flags);
}

RE::BSResource::ErrorCode __fastcall HookedCompDoOpen(void* stream)
{
    try {
        RetireCompressedState(stream);
    } catch (...) {
    }
    const auto error = s_originalCompDoOpen(stream);
    if (error != RE::BSResource::ErrorCode::kNone ||
        !s_hooksActive.load(std::memory_order_acquire) ||
        Settings::bBaselineMode || !Settings::bEnableDecompCache) {
        return error;
    }

    // A successful open is the one lifecycle point where decompressed cursor
    // zero is known without querying private decompressor state. Cache identity
    // comes from the BSA block, never StreamBase's stored/compressed byte count.
    try {
        const auto identity = InspectCompressedStream(stream);
        (void)PublishCompressedStateIfAbsent(
            stream, std::make_shared<CompressedStreamState>(identity, 0));
    } catch (...) {
        try {
            RetireCompressedState(stream);
        } catch (...) {
        }
    }
    return error;
}

void __fastcall HookedCompDoClose(void* stream)
{
    try {
        RetireCompressedState(stream);
    } catch (...) {
    }
    s_originalCompDoClose(stream);
}

void __fastcall HookedCompDoClone(
    const void* stream, RE::BSTSmartPointer<RE::BSResource::Stream>& result)
{
    if (!s_hooksActive.load(std::memory_order_acquire)) {
        s_originalCompDoClone(stream, result);
        return;
    }

    std::shared_ptr<CompressedStreamState> state;
    if (!Settings::bBaselineMode && Settings::bEnableDecompCache) {
        try {
            const auto identity = InspectCompressedStream(stream);
            state = GetOrCreateCompressedState(stream, identity);
        } catch (...) {
        }
    }

    std::shared_ptr<CompressedStreamState> cloneState;
    if (state) {
        std::unique_lock lock(state->ioMutex);
        if (state->retired.load(std::memory_order_acquire)) {
            if (const auto replacement = FindCompressedState(stream);
                replacement && replacement != state) {
                lock.unlock();
                HookedCompDoClone(stream, result);
                return;
            }
            s_originalCompDoClone(stream, result);
            lock.unlock();
            if (auto* clone = result.get(); clone && clone != stream) {
                try {
                    RetireCompressedState(clone);
                } catch (...) {
                }
            }
            return;
        }
        s_originalCompDoClone(stream, result);

        auto* clone = result.get();
        if (state->cursorKnown.load(std::memory_order_acquire) &&
            clone && clone != stream &&
            *reinterpret_cast<const std::uintptr_t*>(clone) ==
                s_compressedArchiveStreamVtable) {
            const auto cloneCursor =
                state->logicalCursor.load(std::memory_order_acquire);
            bool nativeCursorSynchronized = true;
            if (state->cacheData) {
                // The parent's native decompressor did not advance while its
                // mapped payload was served. Synchronize the native clone as
                // a fail-safe before any side-state allocation can fail.
                std::uint64_t nativePosition = 0;
                const auto seekError = s_originalCompDoSeek(
                    clone, cloneCursor, RE::BSResource::SeekMode::kSet,
                    nativePosition);
                nativeCursorSynchronized =
                    seekError == RE::BSResource::ErrorCode::kNone &&
                    nativePosition == cloneCursor;
            }
            try {
                const auto cloneIdentity = InspectCompressedStream(clone);
                cloneState = std::make_shared<CompressedStreamState>(
                    cloneIdentity, cloneCursor);
                cloneState->captureStatus = cloneCursor == 0
                    ? CaptureStatus::kEmpty
                    : CaptureStatus::kInvalid;

                const bool sameIdentity =
                    cloneIdentity.archive == state->identity.archive &&
                    cloneIdentity.startOffset == state->identity.startOffset &&
                    cloneIdentity.totalSize == state->identity.totalSize;
                if (sameIdentity) {
                    cloneState->cacheLookupAttempted = state->cacheLookupAttempted;
                    cloneState->cacheData = state->cacheData;
                    cloneState->cacheSize = state->cacheSize;
                    cloneState->cacheOwner = state->cacheOwner;
                } else if (!nativeCursorSynchronized) {
                    // The clone cannot inherit a logical cursor that its native
                    // decompressor failed to reach unless the identical cache
                    // payload was attached above.
                    cloneState->cursorKnown.store(
                        false, std::memory_order_relaxed);
                    cloneState->captureStatus = CaptureStatus::kInvalid;
                }
            } catch (...) {
                cloneState.reset();
            }
            if (state->cacheData && !nativeCursorSynchronized &&
                (!cloneState || !cloneState->cacheData)) {
                // A cache-backed parent has a deliberately stale native
                // decompressor. If the clone cannot be synchronized and cannot
                // inherit the exact cache identity, exposing it would return
                // incorrect bytes on its first native read.
                cloneState.reset();
                result.reset();
                return;
            }
        }
    } else {
        s_originalCompDoClone(stream, result);
    }

    auto* clone = result.get();
    if (!clone || clone == stream) {
        return;
    }

    try {
        if (cloneState) {
            ReplaceCompressedState(clone, cloneState);
        } else {
            // A recycled output address must never inherit another stream's state.
            RetireCompressedState(clone);
        }
    } catch (...) {
        try {
            RetireCompressedState(clone);
        } catch (...) {
        }
    }
}

RE::BSResource::ErrorCode __fastcall HookedCompDoSeek(
    const void* stream, std::uint64_t offset, RE::BSResource::SeekMode mode,
    std::uint64_t& position)
{
    if (!s_hooksActive.load(std::memory_order_acquire) ||
        Settings::bBaselineMode || !Settings::bEnableDecompCache) {
        return s_originalCompDoSeek(stream, offset, mode, position);
    }

    std::shared_ptr<CompressedStreamState> state;
    try {
        const auto identity = InspectCompressedStream(stream);
        state = GetOrCreateCompressedState(stream, identity);
    } catch (...) {
        return s_originalCompDoSeek(stream, offset, mode, position);
    }

    std::unique_lock lock(state->ioMutex);
    if (state->retired.load(std::memory_order_acquire)) {
        if (const auto replacement = FindCompressedState(stream);
            replacement && replacement != state) {
            lock.unlock();
            return HookedCompDoSeek(stream, offset, mode, position);
        }
        // A close/destructor that retired this state is waiting on ioMutex.
        // Keep it held until the native seek finishes.
        return s_originalCompDoSeek(stream, offset, mode, position);
    }

    try {
        TryAttachCachedEntry(*state);
    } catch (...) {
        state->cacheLookupAttempted = true;
    }

    if (state->cacheData && state->cacheSize > 0) {
        StreamCursor::SeekOrigin origin{};
        switch (mode) {
        case RE::BSResource::SeekMode::kSet:
            origin = StreamCursor::SeekOrigin::kBegin;
            break;
        case RE::BSResource::SeekMode::kCur:
            origin = StreamCursor::SeekOrigin::kCurrent;
            break;
        case RE::BSResource::SeekMode::kEnd:
            origin = StreamCursor::SeekOrigin::kEnd;
            break;
        default:
            return RE::BSResource::ErrorCode::kInvalidParam;
        }

        const auto sought = StreamCursor::ClampSeek(
            state->logicalCursor.load(std::memory_order_acquire), 0,
            state->cacheSize, static_cast<std::int64_t>(offset), origin);
        if (!sought.valid) {
            return RE::BSResource::ErrorCode::kInvalidParam;
        }

        state->logicalCursor.store(sought.relativeOffset, std::memory_order_release);
        state->cursorKnown.store(true, std::memory_order_release);
        position = sought.relativeOffset;
        ResetCaptureAfterSeek(*state, sought.relativeOffset);
        return RE::BSResource::ErrorCode::kNone;
    }

    const auto previousPosition =
        state->logicalCursor.load(std::memory_order_acquire);
    const auto error = s_originalCompDoSeek(stream, offset, mode, position);
    if (error == RE::BSResource::ErrorCode::kNone &&
        position <= (std::numeric_limits<std::uint32_t>::max)() &&
        (state->identity.totalSize == 0 || position <= state->identity.totalSize)) {
        const auto logicalPosition = static_cast<std::uint32_t>(position);
        state->logicalCursor.store(logicalPosition, std::memory_order_release);
        state->cursorKnown.store(true, std::memory_order_release);
        // Some engine paths query position with Seek(kCur, 0) between chunks.
        // A no-op seek preserves sequential capture; only movement invalidates
        // or explicitly restarts it from byte zero.
        if (CompressedReadPolicy::SeekMoved(
                previousPosition, logicalPosition)) {
            if (state->captureStatus == CaptureStatus::kActive) {
                s_captureSeekInvalidations.fetch_add(1, std::memory_order_relaxed);
            }
            ResetCaptureAfterSeek(*state, logicalPosition);
        }
    } else {
        state->cursorKnown.store(false, std::memory_order_release);
        state->captureStatus = CaptureStatus::kInvalid;
        ClearCaptureBuffer(*state);
    }
    // Cache data and its owner intentionally remain attached through EOF and
    // seeks; the side cursor determines the next cache range to serve.
    return error;
}

RE::BSResource::ErrorCode __fastcall HookedCompDoRead(
    const void* stream, void* buffer, std::uint64_t toRead,
    std::uint64_t& read)
{
    if (!s_hooksActive.load(std::memory_order_acquire) ||
        Settings::bBaselineMode || !Settings::bEnableDecompCache) {
        return CallOriginalCompressedRead(stream, buffer, toRead, read);
    }

    const bool loadSuppressed = LoadPhaseAccelerationSuppressed();
    if (loadSuppressed && Settings::bMeasureStats) {
        s_loadPhaseCompressedCalls.fetch_add(1, std::memory_order_relaxed);
        s_loadPhaseCompressedRequestedBytes.fetch_add(
            toRead, std::memory_order_relaxed);
    }

    StreamIdentity identity{};
    try {
        identity = InspectCompressedStream(stream);
    } catch (...) {
        // No bookkeeping/lock failure may escape a game-engine virtual call.
        return CallOriginalCompressedRead(stream, buffer, toRead, read);
    }
    const auto* archive = identity.archive;
    const auto startOffset = identity.startOffset;
    const auto totalSize = identity.totalSize;
    std::shared_ptr<CompressedStreamState> state;
    try {
        state = GetOrCreateCompressedState(stream, identity);
    } catch (...) {
        return CallOriginalCompressedRead(stream, buffer, toRead, read);
    }
    if (!state) {
        // Without a lifecycle-established or successfully queried logical
        // cursor, stock decompression is the only correctness-safe path.
        return CallOriginalCompressedRead(stream, buffer, toRead, read);
    }

    std::vector<std::uint8_t> completed;
    std::uint64_t completedCaptureCharge = 0;
    CaptureBudgetChargeGuard completedChargeGuard(completedCaptureCharge);
    const BSA::MappedArchive* completedArchive = nullptr;
    std::uint32_t completedStartOffset = 0;

    std::unique_lock stateLock(state->ioMutex);
    if (state->retired.load(std::memory_order_acquire)) {
        if (const auto replacement = FindCompressedState(stream);
            replacement && replacement != state) {
            stateLock.unlock();
            return HookedCompDoRead(stream, buffer, toRead, read);
        }
        // Keep the lifecycle mutex held across the stock read. A concurrent
        // close/destructor has already removed this state and is waiting on
        // the same mutex before touching the native stream.
        return CallOriginalCompressedRead(stream, buffer, toRead, read);
    }
    if (state->identity != identity && !state->cacheData) {
        try {
            const bool sameGeneration =
                state->identity.source == identity.source &&
                state->identity.startOffset == identity.startOffset;
            auto cursor = sameGeneration &&
                    state->cursorKnown.load(std::memory_order_acquire)
                ? std::optional<std::uint32_t>{
                    state->logicalCursor.load(std::memory_order_acquire) }
                : QueryCompressedLogicalCursor(stream, identity.totalSize);
            auto replacement = std::make_shared<CompressedStreamState>(
                identity, cursor.value_or(0));
            replacement->cursorKnown.store(
                cursor.has_value(), std::memory_order_relaxed);
            if (!cursor || *cursor != 0) {
                replacement->captureStatus = CaptureStatus::kInvalid;
            }
            if (TryReplaceCompressedState(stream, state, replacement)) {
                stateLock.unlock();
                return HookedCompDoRead(stream, buffer, toRead, read);
            }
        } catch (...) {
        }
        if (const auto replacement = FindCompressedState(stream);
            replacement && replacement != state) {
            stateLock.unlock();
            return HookedCompDoRead(stream, buffer, toRead, read);
        }
        return CallOriginalCompressedRead(stream, buffer, toRead, read);
    }
    if (!state->cursorKnown.load(std::memory_order_acquire)) {
        // The original read remains usable, but neither cache byte zero nor a
        // guessed capture position is safe. A later successful seek/open (or a
        // new stream generation) can establish a known cursor.
        // Keep lifecycle exclusion even though this generation cannot be
        // cached. Unlocking here lets DoClose destroy the native stream while
        // its original read is still executing.
        const auto error = CallOriginalCompressedRead(
            stream, buffer, toRead, read);
        const auto recoveredCursor = QueryCompressedLogicalCursor(
            stream, state->identity.totalSize);
        if (recoveredCursor) {
            state->logicalCursor.store(
                *recoveredCursor, std::memory_order_release);
            state->cursorKnown.store(true, std::memory_order_release);
        }
        state->captureStatus = CaptureStatus::kInvalid;
        ClearCaptureBuffer(*state);
        return error;
    }

    try {
        TryAttachCachedEntry(*state);
    } catch (...) {
        // A lookup/allocation failure must leave the stock decompressor usable.
        state->cacheLookupAttempted = true;
    }

    if (state->cacheData) {
        // Once a stream is served from a cached payload its native
        // decompressor cursor intentionally stops advancing.  Never mix the
        // two data paths for that stream.
        if (loadSuppressed && Settings::bMeasureStats) {
            s_loadPhaseGrandfatheredCacheCalls.fetch_add(
                1, std::memory_order_relaxed);
        }
        return ServeCachedRead(*state, buffer, toRead, read);
    }

    auto& cache = BSA::DecompCache::GetSingleton();
    const bool fitsConfiguredCache =
        Settings::uDecompCacheMaxBytes > 0 &&
        static_cast<std::uint64_t>(totalSize) <=
            Settings::uDecompCacheMaxBytes;
    const bool captureEnabled = !loadSuppressed &&
        archive != nullptr && totalSize > 0 &&
        state->cursorKnown.load(std::memory_order_acquire) &&
        cache.IsBuilding() &&
        totalSize <= kMaxCaptureEntrySize &&
        fitsConfiguredCache &&
        state->cacheData == nullptr &&
        state->captureStatus != CaptureStatus::kCompleted &&
        state->captureStatus != CaptureStatus::kInvalid;

    const auto cursorBefore = state->logicalCursor.load(std::memory_order_acquire);
    bool appendThisRead = false;
    bool beginCapture = false;
    if (captureEnabled) {
        if (state->captureStatus == CaptureStatus::kEmpty) {
            appendThisRead = cursorBefore == 0;
            beginCapture = appendThisRead;
            if (!appendThisRead) {
                state->captureStatus = CaptureStatus::kInvalid;
            }
        } else if (state->captureStatus == CaptureStatus::kActive) {
            appendThisRead = cursorBefore == state->nextCaptureOffset;
            if (!appendThisRead) {
                // Never restart an existing generation merely because the
                // engine cursor moved back to start: that could be an opaque
                // compressed cursor and would persist a suffix as a full file.
                state->captureStatus = CaptureStatus::kInvalid;
                ClearCaptureBuffer(*state);
            }
        }
    }

    read = 0;

    const auto error = CallOriginalCompressedRead(
        stream, buffer, toRead, read);

    const auto progress = CompressedReadPolicy::ValidateNativeProgress(
        state->cursorKnown.load(std::memory_order_acquire), cursorBefore,
        totalSize, toRead, read,
        error == RE::BSResource::ErrorCode::kNone, buffer != nullptr);
    const bool validProgress = progress.valid;
    const auto cursorAfter = progress.cursorAfter;
    if (validProgress) {
        state->logicalCursor.store(cursorAfter, std::memory_order_release);
        state->cursorKnown.store(true, std::memory_order_release);
    } else {
        // Preserve correctness for a later clone/seek even if an engine or
        // third-party hook returned an unusual partial/error result.
        const auto queried = QueryCompressedLogicalCursor(
            stream, totalSize);
        if (queried) {
            state->logicalCursor.store(*queried, std::memory_order_release);
            state->cursorKnown.store(true, std::memory_order_release);
        } else {
            state->cursorKnown.store(false, std::memory_order_release);
            state->captureStatus = CaptureStatus::kInvalid;
            ClearCaptureBuffer(*state);
        }
    }

    if (appendThisRead) {
        const auto remaining = static_cast<std::uint64_t>(totalSize) -
                               state->nextCaptureOffset;
        const bool validResult = error == RE::BSResource::ErrorCode::kNone &&
            read > 0 && buffer && read <= toRead && read <= remaining;

        if (!validResult) {
            if (!(error == RE::BSResource::ErrorCode::kNone &&
                  read == 0 && toRead == 0)) {
                state->captureStatus = CaptureStatus::kInvalid;
                ClearCaptureBuffer(*state);
            }
        } else {
            (void)AppendCapture(*state, totalSize, buffer, read,
                beginCapture, completed, completedCaptureCharge);
            if (!completed.empty()) {
                completedArchive = archive;
                completedStartOffset = startOffset;
            }
        }
    }

    stateLock.unlock();
    if (!completed.empty()) {
        try {
            cache.RecordDecompressed(completedArchive, completedStartOffset,
                std::move(completed));
        } catch (...) {
            try {
                logger::error("BSAMmap: failed to record decompressed entry at 0x{:X}",
                    completedStartOffset);
            } catch (...) {
                OutputDebugStringA("FasterFileCopy: failed to record decompressed entry\n");
            }
        }
    }

    return error;
}

template <std::size_t N>
[[nodiscard]] bool ValidateVtableSlots(
    std::uintptr_t vtable, const std::array<std::size_t, N>& slots) noexcept
{
    constexpr std::size_t kVtableEntries = 13;
    if (!IsInRange(vtable, kVtableEntries * sizeof(std::uintptr_t),
            s_rdataStart, s_rdataEnd) ||
        !IsReadableRange(reinterpret_cast<const void*>(vtable),
            kVtableEntries * sizeof(std::uintptr_t))) {
        return false;
    }

    const auto* entries = reinterpret_cast<const std::uintptr_t*>(vtable);
    for (const auto slot : slots) {
        if (slot >= kVtableEntries ||
            !IsExecutableAddress(reinterpret_cast<const void*>(entries[slot]))) {
            return false;
        }
    }
    return true;
}

}  // namespace

// -------------------------------------------------------------------------
// Public statistics API
// -------------------------------------------------------------------------

IoStatsSnapshot GetIoStatsSnapshot()
{
    return {
        SnapshotPath(s_directMmap),
        SnapshotPath(s_directStock),
        SnapshotPath(s_cachePath),
        SnapshotPath(s_decompressorPath),
        SnapshotPath(s_compressedSourceMmap),
        SnapshotPath(s_compressedSourceStock),
        s_cacheAttachments.load(std::memory_order_relaxed),
        s_cacheSizeMismatches.load(std::memory_order_relaxed),
        s_cacheNotReady.load(std::memory_order_relaxed),
        s_cacheServeDisabled.load(std::memory_order_relaxed),
        s_loadPhaseUncompressedCalls.load(std::memory_order_relaxed),
        s_loadPhaseUncompressedRequestedBytes.load(std::memory_order_relaxed),
        s_loadPhaseCompressedCalls.load(std::memory_order_relaxed),
        s_loadPhaseCompressedRequestedBytes.load(std::memory_order_relaxed),
        s_loadPhaseGrandfatheredCacheCalls.load(std::memory_order_relaxed)
    };
}

void SetLoadActive(const bool a_active) noexcept
{
    s_engineLoadActive.store(a_active, std::memory_order_release);
}

std::uint64_t GetMappedBytesServed()
{
    return s_directMmap.returnedBytes.load(std::memory_order_relaxed);
}
std::uint64_t GetFallbackBytesServed()
{
    return s_directStock.returnedBytes.load(std::memory_order_relaxed);
}
std::uint64_t GetCacheBytesServed()
{
    return s_cachePath.returnedBytes.load(std::memory_order_relaxed);
}
std::uint64_t GetDecompBytesServed()
{
    return s_decompressorPath.returnedBytes.load(std::memory_order_relaxed);
}
// -------------------------------------------------------------------------
// Gameplay and periodic statistics
// -------------------------------------------------------------------------

struct GameplayBaseline
{
    std::int64_t qpc{ 0 };
    IoStatsSnapshot io{};
};

[[nodiscard]] ReadPathStats SubtractPath(
    const ReadPathStats& a_end, const ReadPathStats& a_begin) noexcept
{
    return {
        a_end.calls - a_begin.calls,
        a_end.requestedBytes - a_begin.requestedBytes,
        a_end.returnedBytes - a_begin.returnedBytes,
        a_end.failures - a_begin.failures,
        a_end.qpcTicks - a_begin.qpcTicks
    };
}

static std::mutex s_gameplayMutex;
static std::optional<GameplayBaseline> s_gameplayBaseline;

void SnapshotGameplayStart()
{
    if (!Settings::bMeasureStats) {
        return;
    }

    LARGE_INTEGER now{};
    QueryPerformanceCounter(&now);
    const GameplayBaseline baseline{ now.QuadPart, GetIoStatsSnapshot() };
    {
        std::lock_guard lock(s_gameplayMutex);
        s_gameplayBaseline = baseline;
    }
    logger::info("BSAMmap: === GAMEPLAY MEASUREMENT START ({}) ===",
        EffectiveModeLabel());
}

void LogGameplaySummary()
{
    std::optional<GameplayBaseline> baseline;
    {
        std::lock_guard lock(s_gameplayMutex);
        if (!s_gameplayBaseline) return;
        baseline = std::exchange(s_gameplayBaseline, std::nullopt);
    }

    LARGE_INTEGER now{};
    QueryPerformanceCounter(&now);
    const auto frequency = s_qpcFreq.QuadPart > 0 ? s_qpcFreq.QuadPart : 1;
    const double seconds = static_cast<double>(
        now.QuadPart - baseline->qpc) /
        static_cast<double>(frequency);

    const auto current = GetIoStatsSnapshot();
    const auto mmap = SubtractPath(current.directMmap, baseline->io.directMmap);
    const auto cache = SubtractPath(current.cache, baseline->io.cache);
    const auto decomp = SubtractPath(
        current.decompressor, baseline->io.decompressor);
    const auto native = SubtractPath(
        current.directStock, baseline->io.directStock);
    const auto sourceMmap = SubtractPath(
        current.compressedSourceMmap, baseline->io.compressedSourceMmap);
    const auto sourceStock = SubtractPath(
        current.compressedSourceStock, baseline->io.compressedSourceStock);
    const auto mmapBytes = mmap.returnedBytes;
    const auto cacheBytes = cache.returnedBytes;
    const auto decompBytes = decomp.returnedBytes;
    const auto nativeBytes = native.returnedBytes;
    const auto totalBytes = mmapBytes + cacheBytes + decompBytes + nativeBytes;

    const double totalMB = totalBytes / (1024.0 * 1024.0);
    const double throughput = seconds > 0.001 ? totalMB / seconds : 0.0;
    const auto percent = [totalBytes](std::uint64_t value) {
        return totalBytes > 0 ? value * 100.0 / totalBytes : 0.0;
    };
    const auto* mode = EffectiveModeLabel();

    logger::info("========================================");
    logger::info("[{}] GAMEPLAY THROUGHPUT: {:.1f}s measured", mode, seconds);
    logger::info("[{}]   direct mmap:     {:.1f} MB ({:.0f}%)", mode,
        mmapBytes / (1024.0 * 1024.0), percent(mmapBytes));
    logger::info("[{}]   decomp cache:    {:.1f} MB ({:.0f}%)", mode,
        cacheBytes / (1024.0 * 1024.0), percent(cacheBytes));
    logger::info("[{}]   decompressor:    {:.1f} MB ({:.0f}%)", mode,
        decompBytes / (1024.0 * 1024.0), percent(decompBytes));
    logger::info("[{}]   stock direct:    {:.1f} MB ({:.0f}%)", mode,
        nativeBytes / (1024.0 * 1024.0), percent(nativeBytes));
    logger::info("[{}]   total: {:.1f} MB | {:.1f} MB/s", mode, totalMB, throughput);
    logger::info("[{}]   compressed source I/O: mmap {:.1f} MB + stock {:.1f} MB", mode,
        sourceMmap.returnedBytes / (1024.0 * 1024.0),
        sourceStock.returnedBytes / (1024.0 * 1024.0));
    logger::info(
        "BSAMmap: BENCH GAMEPLAY run={} seconds={:.3f} logical_mib={:.3f} mmap_mib={:.3f} cache_mib={:.3f} decompressor_mib={:.3f} stock_mib={:.3f} source_mmap_mib={:.3f} source_stock_mib={:.3f} calls={}/{}/{}/{} path_operation_ms={:.3f}/{:.3f}/{:.3f}/{:.3f}",
        Settings::sBenchmarkRunTag.empty() ? "none" :
            Settings::sBenchmarkRunTag,
        seconds, totalMB,
        mmapBytes / (1024.0 * 1024.0),
        cacheBytes / (1024.0 * 1024.0),
        decompBytes / (1024.0 * 1024.0),
        nativeBytes / (1024.0 * 1024.0),
        sourceMmap.returnedBytes / (1024.0 * 1024.0),
        sourceStock.returnedBytes / (1024.0 * 1024.0),
        mmap.calls, cache.calls, decomp.calls, native.calls,
        mmap.qpcTicks * 1000.0 / frequency,
        cache.qpcTicks * 1000.0 / frequency,
        decomp.qpcTicks * 1000.0 / frequency,
        native.qpcTicks * 1000.0 / frequency);
    logger::info("========================================");
}

static std::mutex s_statsThreadMutex;
static std::unique_ptr<std::jthread> s_statsThread;

void StatsThreadFn(std::stop_token stopToken)
{
    const int intervalSeconds = (std::max)(1, Settings::iStatsIntervalSec);
    IoStatsSnapshot previousIo{};
    std::uint64_t previousResolved = 0;
    std::uint64_t previousSemanticMisses = 0;
    std::uint64_t previousStructuralBackoffs = 0;
    std::uint64_t previousUnknownCursors = 0;
    std::uint64_t previousBudgetRejects = 0;
    std::uint64_t previousSeekInvalidations = 0;
    std::uint64_t previousCapturesCompleted = 0;
    BSA::DecompCacheDiagnostics previousCacheDiagnostics{};
    auto previousTime = std::chrono::steady_clock::now();

    while (!stopToken.stop_requested()) {
        for (int elapsed = 0;
             elapsed < intervalSeconds && !stopToken.stop_requested();
             ++elapsed) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (stopToken.stop_requested()) {
            break;
        }

        const auto io = GetIoStatsSnapshot();
        const auto deltaMmapPath = SubtractPath(
            io.directMmap, previousIo.directMmap);
        const auto deltaCachePath = SubtractPath(io.cache, previousIo.cache);
        const auto deltaDecompPath = SubtractPath(
            io.decompressor, previousIo.decompressor);
        const auto deltaNativePath = SubtractPath(
            io.directStock, previousIo.directStock);
        const auto deltaSourceMmapPath = SubtractPath(
            io.compressedSourceMmap, previousIo.compressedSourceMmap);
        const auto deltaSourceStockPath = SubtractPath(
            io.compressedSourceStock, previousIo.compressedSourceStock);
        const auto deltaMmap = deltaMmapPath.returnedBytes;
        const auto deltaCache = deltaCachePath.returnedBytes;
        const auto deltaDecomp = deltaDecompPath.returnedBytes;
        const auto deltaNative = deltaNativePath.returnedBytes;
        previousIo = io;
        const auto now = std::chrono::steady_clock::now();
        const double elapsedSeconds = (std::max)(
            std::chrono::duration<double>(now - previousTime).count(), 0.001);
        previousTime = now;

        const auto deltaTotal = deltaMmap + deltaCache + deltaDecomp + deltaNative;
        const auto resolved = s_sourcesResolved.load(std::memory_order_relaxed);
        const auto semanticMisses =
            s_sourceSemanticMisses.load(std::memory_order_relaxed);
        const auto structuralBackoffs =
            s_sourceStructuralBackoffs.load(std::memory_order_relaxed);
        const auto unknownCursors =
            s_unknownCompressedCursors.load(std::memory_order_relaxed);
        const auto budgetRejects =
            s_captureBudgetRejects.load(std::memory_order_relaxed);
        const auto seekInvalidations =
            s_captureSeekInvalidations.load(std::memory_order_relaxed);
        const auto capturesCompleted =
            s_capturesCompleted.load(std::memory_order_relaxed);
        const auto cacheDiagnostics =
            BSA::DecompCache::GetSingleton().GetDiagnostics();

        const auto deltaResolved = resolved - previousResolved;
        const auto deltaSemanticMisses = semanticMisses - previousSemanticMisses;
        const auto deltaStructuralBackoffs =
            structuralBackoffs - previousStructuralBackoffs;
        const auto deltaUnknownCursors = unknownCursors - previousUnknownCursors;
        const auto deltaBudgetRejects = budgetRejects - previousBudgetRejects;
        const auto deltaSeekInvalidations =
            seekInvalidations - previousSeekInvalidations;
        const auto deltaCapturesCompleted =
            capturesCompleted - previousCapturesCompleted;
        const auto deltaQueued =
            cacheDiagnostics.queued - previousCacheDiagnostics.queued;
        const auto deltaDuplicates =
            cacheDiagnostics.duplicates - previousCacheDiagnostics.duplicates;
        const auto deltaPendingRejects = cacheDiagnostics.pendingCapRejects -
            previousCacheDiagnostics.pendingCapRejects;
        const auto deltaDiskRejects = cacheDiagnostics.diskCapRejects -
            previousCacheDiagnostics.diskCapRejects;
        const auto deltaLookupAttempts = cacheDiagnostics.lookupAttempts -
            previousCacheDiagnostics.lookupAttempts;
        const auto deltaLookupHits = cacheDiagnostics.lookupHits -
            previousCacheDiagnostics.lookupHits;
        const auto deltaLookupArchiveMisses =
            cacheDiagnostics.lookupArchiveMisses -
            previousCacheDiagnostics.lookupArchiveMisses;
        const auto deltaLookupInvalidMisses =
            cacheDiagnostics.lookupInvalidMisses -
            previousCacheDiagnostics.lookupInvalidMisses;
        const auto deltaLookupEntryMisses = cacheDiagnostics.lookupEntryMisses -
            previousCacheDiagnostics.lookupEntryMisses;
        const auto deltaLookupColdMisses = cacheDiagnostics.lookupColdMisses -
            previousCacheDiagnostics.lookupColdMisses;
        const auto deltaChecksumComputations =
            cacheDiagnostics.checksumComputations -
            previousCacheDiagnostics.checksumComputations;

        previousResolved = resolved;
        previousSemanticMisses = semanticMisses;
        previousStructuralBackoffs = structuralBackoffs;
        previousUnknownCursors = unknownCursors;
        previousBudgetRejects = budgetRejects;
        previousSeekInvalidations = seekInvalidations;
        previousCapturesCompleted = capturesCompleted;
        previousCacheDiagnostics = cacheDiagnostics;

        const auto diagnosticDelta = deltaResolved + deltaSemanticMisses +
            deltaStructuralBackoffs + deltaUnknownCursors + deltaBudgetRejects +
            deltaSeekInvalidations + deltaCapturesCompleted + deltaQueued +
            deltaDuplicates + deltaPendingRejects + deltaDiskRejects +
            deltaLookupAttempts + deltaChecksumComputations;
        if (deltaTotal == 0 && diagnosticDelta == 0) {
            continue;
        }

        if (deltaTotal > 0) {
            logger::info(
                "[{}] {:.1f}s logical payload: mmap {:.1f} MB, cache {:.1f} MB, decompressor {:.1f} MB, stock {:.1f} MB | {:.1f} MB/s | compressed source mmap {:.1f} MB + stock {:.1f} MB",
                EffectiveModeLabel(), elapsedSeconds,
                deltaMmap / (1024.0 * 1024.0),
                deltaCache / (1024.0 * 1024.0),
                deltaDecomp / (1024.0 * 1024.0),
                deltaNative / (1024.0 * 1024.0),
                deltaTotal / (1024.0 * 1024.0) / elapsedSeconds,
                deltaSourceMmapPath.returnedBytes / (1024.0 * 1024.0),
                deltaSourceStockPath.returnedBytes / (1024.0 * 1024.0));
        }
        if (diagnosticDelta > 0) {
            logger::info(
                "[{}] cache pipeline: source resolved +{}, semantic miss +{}, structural backoff +{} | cursor unknown +{} | capture completed +{}, budget reject +{}, seek invalidation +{} | queued +{}, duplicate +{}, pending-cap reject +{}, disk-cap reject +{}",
                EffectiveModeLabel(), deltaResolved, deltaSemanticMisses,
                deltaStructuralBackoffs, deltaUnknownCursors,
                deltaCapturesCompleted, deltaBudgetRejects,
                deltaSeekInvalidations, deltaQueued, deltaDuplicates,
                deltaPendingRejects, deltaDiskRejects);
            if (deltaLookupAttempts > 0 || deltaChecksumComputations > 0) {
                logger::info(
                    "[{}] cache lookup: attempts +{}, hits +{}, archive-miss +{}, invalid +{}, entry-miss +{}, cold +{} | checksum computations +{}",
                    EffectiveModeLabel(), deltaLookupAttempts,
                    deltaLookupHits, deltaLookupArchiveMisses,
                    deltaLookupInvalidMisses, deltaLookupEntryMisses,
                    deltaLookupColdMisses, deltaChecksumComputations);
            }
        }
    }

    LogGameplaySummary();
}

void SafeStatsThreadFn(std::stop_token stopToken) noexcept
{
    try {
        StatsThreadFn(stopToken);
    } catch (const std::exception& e) {
        try {
            logger::error("BSAMmap: statistics worker stopped: {}", e.what());
        } catch (...) {
            OutputDebugStringA("FasterFileCopy: statistics worker exception\n");
        }
    } catch (...) {
        OutputDebugStringA("FasterFileCopy: unknown statistics worker exception\n");
    }
}

void StartStatsThread()
{
    if (!Settings::bMeasureStats) {
        return;
    }

    std::lock_guard lock(s_statsThreadMutex);
    if (!s_statsThread) {
        s_statsThread = std::make_unique<std::jthread>(SafeStatsThreadFn);
    }
}

// -------------------------------------------------------------------------
// Installation
// -------------------------------------------------------------------------

void Install()
{
    bool expected = false;
    if (!s_installStarted.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        logger::warn("BSAMmap: hook installation requested more than once; ignored");
        return;
    }

    QueryPerformanceFrequency(&s_qpcFreq);

    if (!IsVerifiedRuntime()) {
        logger::critical(
            "BSAMmap: runtime {} has no verified ArchiveStream layout; all hooks disabled",
            REL::Module::get().version().string());
        return;
    }
    if (!InitModuleRanges()) {
        logger::critical("BSAMmap: executable section validation failed; all hooks disabled");
        return;
    }

    const bool aeLayout = !REL::Module::IsVR() &&
        REL::Module::get().version().minor() == 6;
    const bool fieldsValid = aeLayout
        ? BSResource::Field::Source == 0x18 &&
          BSResource::Field::StartOffset == 0x20 &&
          BSResource::Field::CurrentOffset == 0x24 &&
          BSResource::Field::Name == 0x28
        : BSResource::Field::Source == 0x10 &&
          BSResource::Field::StartOffset == 0x18 &&
          BSResource::Field::CurrentOffset == 0x1C &&
          BSResource::Field::Name == 0x20;
    if (!fieldsValid) {
        logger::critical("BSAMmap: ArchiveStream field offsets do not match the verified runtime; hooks disabled");
        return;
    }

    try {
        s_archiveStreamVtable = REL::Relocation<std::uintptr_t>{
            REL::VariantID(285761, 236985, 0x17ec318)
        }.address();
        s_compressedArchiveStreamVtable = REL::Relocation<std::uintptr_t>{
            REL::VariantID(285762, 236987, 0x17ec388)
        }.address();
    } catch (...) {
        logger::critical("BSAMmap: Address Library could not resolve archive vtables; hooks disabled");
        return;
    }

    if (!ValidateVtableSlots(s_archiveStreamVtable, std::array<std::size_t, 1>{ 6 }) ||
        !ValidateVtableSlots(s_compressedArchiveStreamVtable,
            std::array<std::size_t, 6>{ 0, 1, 2, 5, 6, 8 })) {
        logger::critical("BSAMmap: archive vtable ownership/targets failed validation; hooks disabled");
        return;
    }

    auto* archiveEntries = reinterpret_cast<std::uintptr_t*>(s_archiveStreamVtable);
    auto* compressedEntries = reinterpret_cast<std::uintptr_t*>(s_compressedArchiveStreamVtable);
    s_originalDoRead = reinterpret_cast<DoRead_t>(archiveEntries[6]);
    s_originalCompDtor = reinterpret_cast<CompDtor_t>(compressedEntries[0]);
    s_originalCompDoOpen = reinterpret_cast<CompDoOpen_t>(compressedEntries[1]);
    s_originalCompDoClose = reinterpret_cast<CompDoClose_t>(compressedEntries[2]);
    s_originalCompDoClone = reinterpret_cast<CompDoClone_t>(compressedEntries[5]);
    s_originalCompDoRead = reinterpret_cast<CompDoRead_t>(compressedEntries[6]);
    s_originalCompDoSeek = reinterpret_cast<CompDoSeek_t>(compressedEntries[8]);

    // All targets were resolved and validated before the first write.  There
    // are no hardcoded RVAs, heuristic scanners, Detours transactions, or
    // executable trampoline allocations in the stabilized path.
    REL::safe_write(
        s_archiveStreamVtable + 6 * sizeof(std::uintptr_t),
        reinterpret_cast<std::uintptr_t>(&HookedDoRead));
    REL::safe_write(
        s_compressedArchiveStreamVtable + 0 * sizeof(std::uintptr_t),
        reinterpret_cast<std::uintptr_t>(&HookedCompDtor));
    REL::safe_write(
        s_compressedArchiveStreamVtable + 1 * sizeof(std::uintptr_t),
        reinterpret_cast<std::uintptr_t>(&HookedCompDoOpen));
    REL::safe_write(
        s_compressedArchiveStreamVtable + 2 * sizeof(std::uintptr_t),
        reinterpret_cast<std::uintptr_t>(&HookedCompDoClose));
    REL::safe_write(
        s_compressedArchiveStreamVtable + 5 * sizeof(std::uintptr_t),
        reinterpret_cast<std::uintptr_t>(&HookedCompDoClone));
    REL::safe_write(
        s_compressedArchiveStreamVtable + 8 * sizeof(std::uintptr_t),
        reinterpret_cast<std::uintptr_t>(&HookedCompDoSeek));
    // Publish DoRead last. Until s_hooksActive is released, every already-
    // patched hook passes straight through, so a failed/partial installation
    // cannot mix a cached cursor with the native decompressor.
    REL::safe_write(
        s_compressedArchiveStreamVtable + 6 * sizeof(std::uintptr_t),
        reinterpret_cast<std::uintptr_t>(&HookedCompDoRead));

    s_hooksActive.store(true, std::memory_order_release);
    logger::info(
        "BSAMmap: verified vtable hooks installed (ArchiveStream::Read; CompressedArchiveStream lifecycle/read/seek); mode={}",
        EffectiveModeLabel());
    logger::info(
        "BSAMmap: unsafe factory replacement and ReadFromSource scanner are disabled by design");
}

}  // namespace Hooks
