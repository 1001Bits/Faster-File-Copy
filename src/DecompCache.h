#pragma once
// Persistent decompression cache — stores decompressed BSA entry data on disk.
//
// First run:  CompressedArchiveStream::DoRead calls the engine's decompressor
//             as normal.  We capture the decompressed output and accumulate it
//             per-stream.  After Data loaded, the cache is flushed to disk.
//
// Subsequent: During init we mmap the cache files.  CompressedArchiveStream::DoRead
//             serves pre-decompressed data directly from the cache, skipping
//             the entire decompression pipeline.
//
// Cache format (one file per BSA):
//   [4]  magic "BSDC"
//   [4]  version
//   [8]  BSA file size (invalidation key)
//   [8]  BSA last-write-time (invalidation key)
//   [4]  BSA entry count (invalidation key — catches game version differences)
//   [4]  entry count
//   [N × 20] index: { startOffset(4), decompSize(4), cacheOffset(8), checksum(4) }
//   [...]    decompressed data blocks

#include "BSAMemoryMap.h"
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>

namespace BSA
{

#pragma pack(push, 1)
struct DecompCacheHeader
{
    char          magic[4];       // "BSDC"
    std::uint32_t version;        // 4
    std::uint64_t bsaFileSize;
    std::uint64_t bsaLastWrite;
    std::uint32_t bsaEntryCount;  // BSA file count — invalidates on game version change
    std::uint32_t entryCount;     // number of cached entries in this file
};

struct DecompCacheEntry
{
    std::uint32_t startOffset;    // absolute BSA position of compressed entry
    std::uint32_t decompSize;     // decompressed size
    std::uint64_t cacheOffset;    // offset into cache file where decompressed data starts
    std::uint32_t checksum;       // simple checksum of first 64 bytes of decompressed data
};
#pragma pack(pop)

// RAII owner of a memory-mapped cache view. Shared between the active
// ArchiveCache and any MmapStream / InlineCacheState that has been handed
// a pointer into it. When the last reference drops, the view is unmapped
// and the section handle is closed — so a cache rewrite cannot pull the
// rug out from under in-flight streams.
struct MappedView
{
    void*               mapHandle = nullptr;
    const std::uint8_t* base      = nullptr;
    std::uint64_t       size      = 0;

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
};

struct LookupResult
{
    const std::uint8_t*         data  = nullptr;
    std::uint32_t               size  = 0;
    std::shared_ptr<MappedView> owner;  // keeps `data` valid for the holder's lifetime

    explicit operator bool() const { return data != nullptr && size > 0; }
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
                        std::uint32_t startOffset) const;

    // Cheap existence check — no shared_ptr bump, no LookupResult copy.
    bool Contains(const MappedArchive* archive,
                  std::uint32_t startOffset) const;

    // Record decompressed data for an entry (called during cache build phase)
    void RecordDecompressed(const MappedArchive* archive,
                            std::uint32_t startOffset,
                            const void* data,
                            std::uint32_t size);

    // Flush accumulated data to disk cache files
    void FlushToDisk();

    // Start background flush thread (mode 1: periodic flush during gameplay)
    void StartBackgroundFlush();

    // Touch every page of every loaded cache view to pin the whole cache
    // resident in the OS page cache. Idempotent; dispatches a detached,
    // throttled background worker that yields when the game is actively
    // streaming so we don't fight disk bandwidth on the critical path.
    void PrefaultAll();

    // Check if there are pending entries to flush
    bool HasPending() const;

    bool IsReady() const { return m_ready; }
    bool IsBuilding() const { return m_building; }

    // True once all builds/writes have completed and m_caches is immutable.
    // When stable, Lookup()/Contains() take no locks and return entries
    // without bumping any shared_ptr refcount. Never transitions back to false.
    bool IsStable() const { return m_stable.load(std::memory_order_acquire); }

    void RecordMiss() { m_misses.fetch_add(1, std::memory_order_relaxed); }
    std::uint64_t GetCacheMisses() const { return m_misses.load(std::memory_order_relaxed); }

private:
    DecompCache() = default;

    struct ArchiveCache
    {
        // For serving: shared owner of the mmap'd cache file. Cleared when
        // the cache is rewritten — outstanding streams hold their own copies
        // of the shared_ptr and keep the old view alive until they release.
        std::shared_ptr<MappedView> view;
        std::filesystem::path       activePath;

        // Index: startOffset → CachedEntry. Pointers in here belong to `view`;
        // they are valid as long as the same shared_ptr is held alongside.
        std::unordered_map<std::uint32_t, CachedEntry> index;

        // For building: accumulated decompressed data
        struct PendingEntry {
            std::uint32_t startOffset;
            std::vector<std::uint8_t> data;
        };
        std::vector<PendingEntry> pending;
        mutable std::mutex pendingMtx;

        void Close();
    };

    std::filesystem::path m_cachePath;
    std::unordered_map<const MappedArchive*, ArchiveCache> m_caches;
    mutable std::shared_mutex m_cacheMtx;

    std::atomic<bool> m_ready{ false };
    std::atomic<bool> m_building{ false };
    // Set once no more writes can happen (building done + all flushes complete).
    // Lookup/Contains consult this to take a lock-free fast path.
    std::atomic<bool> m_stable{ false };
    std::unordered_set<std::string> m_startupFiles;  // paths written during initial flush

    std::atomic<std::uint64_t> m_misses{ 0 };
    std::atomic<std::uint64_t> m_totalCacheBytes{ 0 };  // tracks on-disk cache size

    bool LoadCacheFile(const MappedArchive* archive, ArchiveCache& cache);
    bool LoadCacheFile(const MappedArchive* archive, ArchiveCache& cache, const std::filesystem::path& path);
    bool WriteCacheFile(const MappedArchive* archive, ArchiveCache& cache);
    std::filesystem::path CachePathFor(const MappedArchive* archive) const;
    std::filesystem::path ResolveCacheFilePath(const MappedArchive* archive) const;
    void EnforceSizeLimit();

    static bool IsCacheFilePath(const std::filesystem::path& path);
    static std::uint64_t GetFileLastWrite(const std::filesystem::path& path);
    static std::uint32_t Checksum(const void* data, std::size_t size);
};

}  // namespace BSA
