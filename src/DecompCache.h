#pragma once
// Persistent decompression cache — stores decompressed BSA entry data on disk.
//
// First run:  CompressedArchiveStream::DoRead calls the engine's decompressor
//             as normal.  We capture the decompressed output and accumulate it
//             per-stream.  After Data loaded, the cache is flushed to disk.
//
// Subsequent: During init we mmap the cache files. After DataLoaded the owned
//             worker prefaults every committed page within the automatic
//             25%-of-physical-RAM ceiling. CompressedArchiveStream::DoRead then
//             serves pre-decompressed data directly from RAM-hot mappings.
//
// Cache format (one file per BSA):
//   [4]  magic "BSDC"
//   [4]  version
//   [8]  BSA file size (invalidation key)
//   [8]  BSA last-write-time (invalidation key)
//   [8]  BSA file identity + bounded content fingerprint
//   [4]  BSA entry count / index capacity
//   [4]  index capacity
//   [4]  committed cache-entry count
//   [capacity × 20] reserved index slots
//   [...]    append-only decompressed data blocks

#include "BSAMemoryMap.h"
#include "CacheFormat.h"
#include <condition_variable>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace BSA
{

using DecompCacheHeader = CacheFormat::Header;
using DecompCacheEntry  = CacheFormat::Entry;

// RAII owner of a memory-mapped cache view. Shared between the active
// ArchiveCache and any compressed-stream side state handed a pointer into it.
// When the last reference drops, the view is unmapped
// and the section handle is closed — so a cache rewrite cannot pull the
// rug out from under in-flight streams.
struct MappedView
{
    void*               mapHandle = nullptr;
    const std::uint8_t* base      = nullptr;
    std::uint64_t       size      = 0;
    // Structurally committed prefix. This can be smaller than the physical
    // mapping when startup found a crash tail that Windows could not trim.
    std::uint64_t       committedSize = 0;
    // Contiguous prefix explicitly faulted into RAM by the managed warmer.
    // Every newly installed mapping starts cold; interrupted passes retain
    // progress only while that exact mapping remains current.
    std::atomic<std::uint64_t> prefaultedThrough{ 0 };
    // Set when checksum validation or a mapped read reports that this complete
    // generation is no longer safe to serve. Existing stream owners can then
    // fail/recover without dereferencing the mapping again.
    std::atomic<bool> unusable{ false };
    // One byte per cache entry: 0=unknown, 1=verifying, 2=valid, 3=invalid.
    // Kept with the mapping so CachedEntry can perform lock-free lazy
    // full-payload verification without bloating/copy-disabling the map value.
    std::unique_ptr<std::atomic<std::uint8_t>[]> verification;
    std::uint32_t verificationCount = 0;

    MappedView() = default;
    MappedView(const MappedView&) = delete;
    MappedView& operator=(const MappedView&) = delete;
    ~MappedView();
};

// In-memory entry for fast lookup. data points into the ArchiveCache's
// current MappedView. Callers that retain the pointer past Lookup() must
// also retain the LookupResult::owner shared_ptr to keep the view alive.
struct CachedEntry
{
    const std::uint8_t* data;     // pointer into mmap'd cache file
    std::uint32_t       size;     // decompressed size
    std::uint32_t       checksum;
    std::atomic<std::uint8_t>* verification;
};

struct LookupResult
{
    const std::uint8_t*         data  = nullptr;
    std::uint32_t               size  = 0;
    std::shared_ptr<MappedView> owner;  // keeps `data` valid for the holder's lifetime

    explicit operator bool() const { return data != nullptr && size > 0; }
};

struct DecompCacheDiagnostics
{
    std::uint64_t queued{ 0 };
    std::uint64_t duplicates{ 0 };
    std::uint64_t pendingCapRejects{ 0 };
    std::uint64_t diskCapRejects{ 0 };
    std::uint64_t lookupAttempts{ 0 };
    std::uint64_t lookupHits{ 0 };
    std::uint64_t lookupArchiveMisses{ 0 };
    std::uint64_t lookupInvalidMisses{ 0 };
    std::uint64_t lookupEntryMisses{ 0 };
    std::uint64_t lookupColdMisses{ 0 };
    std::uint64_t lookupColdBytes{ 0 };
    std::uint64_t checksumComputations{ 0 };
    std::uint64_t checksumBytes{ 0 };
    std::uint64_t checksumQpcTicks{ 0 };
    std::uint64_t checksumFailures{ 0 };
    std::uint64_t checksumWaits{ 0 };
    std::uint64_t warmRequests{ 0 };
    std::uint64_t warmPassesStarted{ 0 };
    std::uint64_t warmPassesCompleted{ 0 };
    std::uint64_t warmInterruptedLoad{ 0 };
    std::uint64_t warmInterruptedFlush{ 0 };
    std::uint64_t warmInterruptedEpoch{ 0 };
    std::uint64_t warmInterruptedStop{ 0 };
    std::uint64_t warmIoFailures{ 0 };
    std::uint64_t warmBytesTouched{ 0 };
    std::uint64_t warmQpcTicks{ 0 };
};

// A point-in-time, parseable view of both useful cache payload and its backing
// mappings. `historicallyWarmedBytes` records page coverage by this process;
// only `residentBytes` (when residencyMeasured=true) describes pages currently
// in the process working set.
struct DecompCacheBenchmarkSnapshot
{
    DecompCacheDiagnostics diagnostics{};
    std::uint64_t physicalBytes{ 0 };
    std::uint64_t pendingBytes{ 0 };
    std::uint64_t selectedMappingBytes{ 0 };
    std::uint64_t historicallyWarmedBytes{ 0 };
    std::uint64_t payloadBytes{ 0 };
    std::uint64_t eligiblePayloadBytes{ 0 };
    std::uint64_t residentBytes{ 0 };
    std::uint64_t totalPages{ 0 };
    std::uint64_t residentPages{ 0 };
    std::uint64_t residencyQueryMicros{ 0 };
    std::uint64_t mappingCount{ 0 };
    std::uint64_t entryCount{ 0 };
    std::uint64_t eligibleEntryCount{ 0 };
    std::uint64_t verifiedEntryCount{ 0 };
    std::uint64_t verifiedPayloadBytes{ 0 };
    bool prefaultEnabled{ false };
    bool warmComplete{ false };
    bool residencyMeasured{ false };
};

class DecompCache
{
public:
    static DecompCache& GetSingleton();

    // Initialize: load existing caches or prepare for building
    void Initialize(const std::filesystem::path& dataPath,
                    const std::vector<MappedArchive>& archives);

    // Look up a cached decompressed entry by (archive, startOffset).
    // Returns the data pointer + a shared owner of the underlying view.
    // Hold `owner` for as long as `data` is read; otherwise the view may
    // be unmapped by a concurrent rewrite.
    LookupResult Lookup(const MappedArchive* archive,
                        std::uint32_t startOffset);
    void ReportMappingIoFailure(const std::shared_ptr<MappedView>& owner);
    void ReportCacheValidationFailure(const std::shared_ptr<MappedView>& owner);

    // Record decompressed data for an entry (called during cache build phase)
    void RecordDecompressed(const MappedArchive* archive,
                            std::uint32_t startOffset,
                            const void* data,
                            std::uint32_t size);

    // Zero-copy handoff for hook accumulators that already own the completed
    // payload. The vector is moved into the transactional pending queue.
    void RecordDecompressed(const MappedArchive* archive,
                            std::uint32_t startOffset,
                            std::vector<std::uint8_t>&& data);

    // Flush accumulated data to disk cache files
    void FlushToDisk();

    // Start the managed worker. Mode 0 closes capture after its startup commit;
    // both modes retain the owned worker for retry, invalidation, and load-gate
    // handoffs until singleton shutdown.
    void StartBackgroundFlush();

    // Mark an engine load as in progress. The worker stands down while active
    // and is woken immediately when the final load producer closes.
    void SetLoadActive(bool a_active);

    // Check if there are pending entries to flush
    bool HasPending() const;

    bool IsReady() const { return m_ready; }
    bool IsBuilding() const { return m_building; }
    bool IsRamWarm() const {
        return m_prefaultEnabled.load(std::memory_order_acquire) &&
            m_warmComplete.load(std::memory_order_acquire);
    }
    std::uint64_t GetRamWarmedBytes() const {
        return m_warmedBytes.load(std::memory_order_relaxed);
    }
    [[nodiscard]] DecompCacheDiagnostics GetDiagnostics() const noexcept;
    [[nodiscard]] DecompCacheBenchmarkSnapshot GetBenchmarkSnapshot(
        bool a_measureResidency = false) const;

private:
    DecompCache() = default;
    ~DecompCache();

    struct ArchiveCache
    {
        // For serving: shared owner of the mmap'd cache file. Cleared when
        // the cache is rewritten — outstanding streams hold their own copies
        // of the shared_ptr and keep the old view alive until they release.
        std::shared_ptr<MappedView> view;
        std::filesystem::path       activePath;
        std::uint64_t               bsaFingerprint{ 0 };
        mutable std::atomic<bool>   diskInvalidated{ false };
        // A structurally valid file may contain a crash-interrupted append
        // after its committed prefix. If startup cannot trim that tail, the
        // next write replaces the file instead of shrinking a live mapping.
        bool                        needsReplacement{ false };

        // Last time any entry in this archive was served (GetTickCount64 ms).
        // Updated by Lookup; read by EnforceSizeLimit to find
        // archives not hit in the last 60 s. 0 = never served this session.
        mutable std::atomic<std::uint64_t> lastAccessMs{ 0 };

        // Bytes occupied by this archive's currently selected cache file.
        // Directory reconciliation, rather than optimistic deltas, is the
        // authority for the total because failed replacements may leave more
        // than one physical generation on disk.
        std::uint64_t onDiskBytes{ 0 };

        // Index: startOffset → CachedEntry. Pointers in here belong to `view`;
        // they are valid as long as the same shared_ptr is held alongside.
        std::unordered_map<std::uint32_t, CachedEntry> index;

        // For building: accumulated decompressed data
        struct PendingEntry {
            std::uint32_t startOffset;
            // Payload bytes plus any one-time fixed file/index reservation
            // charged by the first entry for a previously absent cache file.
            std::uint64_t accountedBytes;
            std::vector<std::uint8_t> data;
        };
        std::vector<PendingEntry> pending;
        // Includes both entries in `pending` and entries temporarily moved to
        // an off-lock flush. This prevents duplicate capture while a rewrite
        // is in flight and makes transactional requeue cheap.
        std::unordered_set<std::uint32_t> bufferedOffsets;
        mutable std::mutex pendingMtx;

        void Close();
    };

    std::filesystem::path m_cachePath;
    std::unordered_map<const MappedArchive*, ArchiveCache> m_caches;
    mutable std::shared_mutex m_cacheMtx;
    // Cache-file basename -> warm rank from the previous session (1..N, higher
    // = more recently served). Written only during Initialize, before the
    // worker thread exists; read-only afterwards, so unsynchronized reads are
    // safe. Ranks are small integers, so any live GetTickCount64 lastAccessMs
    // always outranks them in the warm sort.
    std::unordered_map<std::wstring, std::uint64_t> m_warmPriorityRank;
    // Serializes whole flush operations so the off-lock write phase of one
    // flush can't overlap another. m_cacheMtx is taken only briefly inside
    // (snapshot in / install out) — never across disk I/O.
    std::mutex m_flushMtx;

    // The cache worker is owned and stopped by the singleton. A
    // condition variable makes shutdown immediate instead of waiting for the
    // 60-second flush interval.
    std::mutex              m_workerMtx;
    std::condition_variable m_workerCv;
    std::jthread            m_flushThread;
    std::atomic<bool>       m_backgroundStarted{ false };
    std::atomic<bool>       m_flushRequested{ false };
    std::atomic<bool>       m_warmRequested{ false };
    std::atomic<bool>       m_prefaultEnabled{ false };
    mutable std::atomic<bool> m_warmComplete{ false };
    // GetTickCount64 ms of the last over-cap flush wake. Zero means no wake has
    // been issued in this initialization, so the first rejection wakes the
    // worker immediately; later rejections are rate-limited to the cold window.
    std::atomic<std::uint64_t> m_lastOverCapNotifyMs{ 0 };

    std::atomic<bool> m_ready{ false };
    std::atomic<bool> m_building{ false };
    // Set by SetLoadActive — gates the background flush off the save-load path.
    std::atomic<bool> m_loadActive{ false };
    // GetTickCount64 at Initialize — eviction won't treat archives as "cold"
    // until at least one 60 s window has passed since startup, so we don't
    // evict startup archives that just haven't been re-touched yet.
    std::uint64_t     m_sessionStartMs{ 0 };
    std::atomic<std::uint64_t> m_pendingBytes{ 0 };
    // Successful writes remain charged in m_pendingBytes until a complete
    // directory reconciliation publishes their physical size. This prevents
    // an admission window where neither side accounts for committed bytes.
    std::atomic<std::uint64_t> m_committedReservations{ 0 };
    std::atomic<std::uint64_t> m_totalCacheBytes{ 0 };  // reconciled physical size
    // Largest rejected payload that needs disk headroom before a future
    // encounter can be admitted. Drives proactive cold-cache eviction even
    // when the current total is just below (rather than over) the hard cap.
    std::atomic<std::uint64_t> m_requiredHeadroom{ 0 };
    std::atomic<std::uint64_t> m_queuedEntries{ 0 };
    std::atomic<std::uint64_t> m_duplicateEntries{ 0 };
    std::atomic<std::uint64_t> m_pendingCapRejects{ 0 };
    std::atomic<std::uint64_t> m_diskCapRejects{ 0 };
    std::atomic<std::uint64_t> m_lookupAttempts{ 0 };
    std::atomic<std::uint64_t> m_lookupHits{ 0 };
    std::atomic<std::uint64_t> m_lookupArchiveMisses{ 0 };
    std::atomic<std::uint64_t> m_lookupInvalidMisses{ 0 };
    std::atomic<std::uint64_t> m_lookupEntryMisses{ 0 };
    std::atomic<std::uint64_t> m_lookupColdMisses{ 0 };
    std::atomic<std::uint64_t> m_lookupColdBytes{ 0 };
    std::atomic<std::uint64_t> m_checksumComputations{ 0 };
    std::atomic<std::uint64_t> m_checksumBytes{ 0 };
    std::atomic<std::uint64_t> m_checksumQpcTicks{ 0 };
    std::atomic<std::uint64_t> m_checksumFailures{ 0 };
    std::atomic<std::uint64_t> m_checksumWaits{ 0 };
    std::atomic<std::uint64_t> m_warmRequests{ 0 };
    std::atomic<std::uint64_t> m_warmPassesStarted{ 0 };
    std::atomic<std::uint64_t> m_warmPassesCompleted{ 0 };
    std::atomic<std::uint64_t> m_warmInterruptedLoad{ 0 };
    std::atomic<std::uint64_t> m_warmInterruptedFlush{ 0 };
    std::atomic<std::uint64_t> m_warmInterruptedEpoch{ 0 };
    std::atomic<std::uint64_t> m_warmInterruptedStop{ 0 };
    std::atomic<std::uint64_t> m_warmIoFailures{ 0 };
    std::atomic<std::uint64_t> m_warmBytesTouched{ 0 };
    std::atomic<std::uint64_t> m_warmQpcTicks{ 0 };
    std::atomic<std::uint64_t> m_lastWarmRequestQpc{ 0 };
    // Mapping replacements/evictions invalidate an in-progress warm snapshot.
    mutable std::atomic<std::uint64_t> m_cacheEpoch{ 0 };
    mutable std::atomic<std::uint64_t> m_warmedBytes{ 0 };

    // Serializes the disk-total/pending-reservation handoff used by admission,
    // and protects cache-format files not selected by any archive (stale,
    // orphaned, or superseded temp generations). Directory I/O never holds the
    // hot lookup lock.
    std::mutex m_accountingMtx;
    std::vector<std::filesystem::path> m_unownedFiles;

    bool LoadCacheFile(const MappedArchive* archive, ArchiveCache& cache);
    bool LoadCacheFile(const MappedArchive* archive, ArchiveCache& cache, const std::filesystem::path& path);
    std::filesystem::path CachePathFor(const MappedArchive* archive) const;
    void ReconcileDiskAccounting();
    void RemoveUnownedFiles();
    void EnforceSizeLimit(bool forceColdEviction = false);
    void RequestFlush();
    void RequestWarmup();
    // Cross-session warm-priority persistence: archives served most recently
    // last session are warmed first this session, so the first save load after
    // launch finds its entries already RAM-resident. Loaded once in
    // Initialize (before the worker starts), saved after each flush.
    void LoadWarmPriority() noexcept;
    void SaveWarmPriority() noexcept;
    void WarmMappedCaches(std::stop_token stopToken);
    bool HasInvalidGeneration() const;

    static bool IsCacheFilePath(const std::filesystem::path& path);
    static std::uint64_t GetFileLastWrite(const std::filesystem::path& path);
};

}  // namespace BSA
