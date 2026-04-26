#pragma once
// Persistent decompression cache — stores decompressed BA2 entry data on disk.
//
// First run:  ReaderStream::DoRead decompresses as normal.  We capture the
//             decompressed output and accumulate it per-stream.  After data
//             loaded, the cache is flushed to disk.
// Next runs:  We mmap the cache files.  DoRead serves pre-decompressed data
//             directly from the cache, skipping zlib entirely.
//
// Cache format (one .decomp file per BA2):
//   [4]     magic "B2DC"
//   [4]     version (2)
//   [8]     BA2 file size (invalidation key)
//   [8]     BA2 last-write-time (invalidation key)
//   [4]     entry count
//   [N×20]  index: { startOffset(4), decompSize(4), cacheOffset(8), checksum(4) }
//   [...]   decompressed data blocks

#include "BA2MemoryMap.h"
#include <algorithm>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

namespace BA2
{

#pragma pack(push, 1)
struct DecompCacheHeader
{
    char          magic[4];        // "B2DC"
    std::uint32_t version;         // 2
    std::uint64_t ba2FileSize;
    std::uint64_t ba2LastWrite;
    std::uint32_t entryCount;
};

struct DecompCacheEntry
{
    std::uint32_t startOffset;     // absolute BA2 position of compressed entry
    std::uint32_t decompSize;      // decompressed size
    std::uint64_t cacheOffset;     // offset into cache file where data starts
    std::uint32_t checksum;        // FNV-1a of first 64 bytes
};
#pragma pack(pop)

// RAII owner of a memory-mapped cache view. Shared between the active
// ArchiveCache and any in-flight reads that hold a pointer into it.
// When the last reference drops, the view is unmapped and the section
// handle is closed — so a cache rewrite cannot pull the rug out from
// under in-flight streams.
struct MappedView
{
    void*               mapHandle = nullptr;
    const std::uint8_t* base      = nullptr;
    std::uint64_t       size      = 0;
    // True if VirtualLock was applied to (base, size). Atomic because the
    // bg flush thread, the async Initialize lock thread, and the prefault
    // thread all read/write this concurrently. Writes only flip false→true;
    // dtor reads it once with no concurrency. UnmapViewOfFile releases any
    // working-set lock implicitly, but the explicit unlock keeps process
    // working-set accounting tidy.
    std::atomic<bool>   locked{ false };

    MappedView() = default;
    MappedView(const MappedView&) = delete;
    MappedView& operator=(const MappedView&) = delete;
    ~MappedView() {
        if (locked.load(std::memory_order_relaxed) && base)
            VirtualUnlock(const_cast<std::uint8_t*>(base), size);
        if (base) UnmapViewOfFile(base);
        if (mapHandle) CloseHandle(static_cast<HANDLE>(mapHandle));
    }
};

struct CachedEntry
{
    const std::uint8_t* data;
    std::uint32_t       size;
};

// Lookup result — holds a shared_ptr to keep the underlying storage alive for
// the caller's lifetime. For mmap-backed hits `owner` holds a MappedView; for
// not-yet-flushed pending hits it holds the pending std::vector buffer. Typed
// as shared_ptr<void> so both cases fit in one field.
struct LookupResult
{
    const std::uint8_t*    data  = nullptr;
    std::uint32_t          size  = 0;
    std::shared_ptr<void>  owner;

    explicit operator bool() const { return data != nullptr && size > 0; }
};

class DecompCache
{
public:
    static DecompCache& GetSingleton();

    void Initialize(const std::filesystem::path& dataPath,
                    const std::vector<MappedArchive>& archives);
    void Shutdown();

    // Proactively decompress ALL compressed entries from every mapped archive.
    // This ensures every compressed entry is cached, not just ones read during gameplay.
    // Returns {totalEntries, compressedEntries, cachedEntries, skippedBytes}.
    struct BuildResult {
        uint32_t totalEntries;
        uint32_t compressedEntries;
        uint32_t cachedEntries;
        uint64_t cachedBytes;
        uint32_t errors;
    };
    BuildResult BuildAllCache(const std::vector<MappedArchive>& archives);

    // Eagerly decompress every DX10 (texture) archive entry that isn't already
    // cached. Texture BA2s bypass the HookedDoRead passive-capture path, so
    // without this they'd never populate. Intended to run on the background
    // flush worker thread (single-threaded with FlushToDisk — no races).
    BuildResult BuildTextureCache(const std::vector<MappedArchive>& archives);

    LookupResult Lookup(const MappedArchive* archive,
                        std::uint32_t startOffset) const;

    // Stream-replacement variant of Lookup. Skips pending (not-yet-flushed)
    // entries — those live in std::vector buffers that flush will move out
    // from under us, which is safe for one-shot Lookup but unsafe to hand to
    // a long-lived stream substitute. Returns the shared_ptr<MappedView> as
    // a concrete type so HookedFactory can pin the cache mapping for the
    // life of the substituted MmapStream. In stable mode the view shared_ptr
    // is left empty (no refcount bump) since the mapping is permanent.
    struct ViewBackedResult {
        const std::uint8_t*         data = nullptr;
        std::uint32_t               size = 0;
        std::shared_ptr<MappedView> view;
        explicit operator bool() const { return data != nullptr && size > 0; }
    };
    ViewBackedResult LookupViewBacked(const MappedArchive* archive,
                                      std::uint32_t startOffset) const;

    void RecordDecompressed(const MappedArchive* archive,
                            std::uint32_t startOffset,
                            const void* data,
                            std::uint32_t size);

    void FlushToDisk();
    void StartBackgroundFlush();
    void PrefaultCachePages();  // Warm OS page cache by touching all loaded cache pages
    void CancelPrefault();      // Hard-stop prefault workers (called at save-load start)
    void RequestShutdown();  // Signal background flush thread to stop
    bool HasPending() const;

    // Pin every loaded cache view in the process working set via VirtualLock,
    // expanding the working-set quota first. Performs a safety check against
    // GlobalMemoryStatusEx — skipped if locking would leave less than
    // Settings::iLockCacheReserveMB MB free, or exceed 50% of total physical
    // RAM. Idempotent: views already locked are skipped. Called once after
    // Initialize and again after each WriteCacheFile rebuilds a view.
    void LockCacheInMemory();

    bool IsReady() const    { return m_ready; }
    bool IsBuilding() const { return m_building; }

    // True once no further writes can happen to m_caches or any
    // ArchiveCache::index/view — Lookup() then takes a lock-free path that
    // skips the per-cache shared_lock and the shared_ptr<MappedView> refcount
    // bump. One-way transition; never goes back to false. See FlushToDisk /
    // Initialize for the conditions that flip it.
    bool IsStable() const { return m_stable.load(std::memory_order_acquire); }

    void RecordHit(std::uint64_t bytes) {
        m_hits.fetch_add(1, std::memory_order_relaxed);
        m_hitBytes.fetch_add(bytes, std::memory_order_relaxed);
    }
    void RecordMiss() { m_misses.fetch_add(1, std::memory_order_relaxed); }

    std::uint64_t GetCacheHits() const   { return m_hits.load(std::memory_order_relaxed); }
    std::uint64_t GetCacheMisses() const { return m_misses.load(std::memory_order_relaxed); }
    std::uint64_t GetCacheHitBytes() const { return m_hitBytes.load(std::memory_order_relaxed); }
    std::uint64_t GetTotalCacheBytes() const { return m_totalCacheBytes.load(std::memory_order_relaxed); }

    // Snapshot of currently-mapped cache views (base pointer, byte size). Used
    // by the stats thread for residency sampling. Takes shared_lock per
    // ArchiveCache so a concurrent flush cannot unmap a view mid-read.
    std::vector<std::pair<const std::uint8_t*, std::uint64_t>> GetMappedViews() const;

private:
    DecompCache() = default;

    struct ArchiveCache
    {
        // Shared owner of the mmap'd cache file. Cleared when the cache is
        // rewritten — outstanding reads hold their own shared_ptr copies and
        // keep the old view alive until they finish.
        std::shared_ptr<MappedView> view;

        // Sorted-by-startOffset flat vector. Populated in LoadCacheFile and
        // rebuilt when the cache is flushed. Binary search via std::lower_bound
        // beats unordered_map for typical archive sizes (1k–50k entries) by
        // halving lookup latency and avoiding the per-bucket cache miss.
        // Pointers belong to `view` and stay valid as long as the same
        // shared_ptr is held alongside.
        std::vector<std::pair<std::uint32_t, CachedEntry>> index;

        // Guards `view` + `index` against concurrent flush (background thread
        // clears and rebuilds them in WriteCacheFile → LoadCacheFile). Readers
        // take shared lock; flush takes exclusive. Marked mutable so Lookup
        // (const) can acquire the shared lock.
        mutable std::shared_mutex rebuildMtx;

        // Lock-free fast-path count. Readers check this before acquiring
        // rebuildMtx — if it's zero, the archive has nothing cached and we
        // can return empty without touching the mutex. Writers update it
        // under the exclusive lock after rebuilding `index`.
        std::atomic<std::uint32_t> entryCount{ 0 };

        const CachedEntry* Find(std::uint32_t startOffset) const;
        bool               Contains(std::uint32_t startOffset) const;

        // Pending entry — data is held in a shared_ptr so Lookup can return a
        // pointer whose lifetime outlives the pending vector (flush swaps the
        // vector out from under in-flight readers).
        struct PendingEntry {
            std::uint32_t                              startOffset;
            std::shared_ptr<std::vector<std::uint8_t>> data;
        };
        std::vector<PendingEntry> pending;
        // mutable so const-qualified Lookup can take the lock.
        mutable std::mutex pendingMtx;

        // Lock-free size hint for pending. Lookup reads it to skip the mutex
        // on the fast path when nothing has been captured yet this session.
        std::atomic<std::uint32_t> pendingCount{ 0 };

        void Close();
    };

    std::filesystem::path m_cachePath;
    std::unordered_map<const MappedArchive*, ArchiveCache> m_caches;

    bool m_ready    = false;
    bool m_building = false;
    // Lock-free fast-path gate (see IsStable()). Atomic because Lookup readers
    // and the flush thread observe it concurrently.
    std::atomic<bool> m_stable{ false };
    std::atomic<bool> m_flushShutdownRequested{ false };
    // Serializes LockCacheInMemory() calls so the Initialize-async lock thread
    // and the bg-flush post-WriteCacheFile lock call don't race on view->locked
    // or on SetProcessWorkingSetSizeEx quota math.
    std::mutex m_lockMtx;
    std::atomic<bool> m_prefaultCancel{ false };
    std::unordered_set<std::string> m_startupFiles;

    std::atomic<std::uint64_t> m_hits{ 0 };
    std::atomic<std::uint64_t> m_misses{ 0 };
    std::atomic<std::uint64_t> m_hitBytes{ 0 };
    std::atomic<std::uint64_t> m_totalCacheBytes{ 0 };

    bool LoadCacheFile(const MappedArchive* archive, ArchiveCache& cache);
    bool WriteCacheFile(const MappedArchive* archive, ArchiveCache& cache,
                        const std::vector<ArchiveCache::PendingEntry>& pending);
    std::filesystem::path CachePathFor(const MappedArchive* archive) const;
    void EnforceSizeLimit();

    static std::uint64_t GetFileLastWrite(const std::filesystem::path& path);
    static std::uint32_t Checksum(const void* data, std::size_t size);
};

}  // namespace BA2
