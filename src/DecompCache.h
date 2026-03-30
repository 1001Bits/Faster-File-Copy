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
//   [4]  entry count
//   [N × 20] index: { startOffset(4), decompSize(4), cacheOffset(8), checksum(4) }
//   [...]    decompressed data blocks

#include "BSAMemoryMap.h"
#include <unordered_map>
#include <unordered_set>

namespace BSA
{

#pragma pack(push, 1)
struct DecompCacheHeader
{
    char          magic[4];       // "BSDC"
    std::uint32_t version;        // 1
    std::uint64_t bsaFileSize;
    std::uint64_t bsaLastWrite;
    std::uint32_t entryCount;
};

struct DecompCacheEntry
{
    std::uint32_t startOffset;    // absolute BSA position of compressed entry
    std::uint32_t decompSize;     // decompressed size
    std::uint64_t cacheOffset;    // offset into cache file where decompressed data starts
    std::uint32_t checksum;       // simple checksum of first 64 bytes of decompressed data
};
#pragma pack(pop)

// In-memory entry for fast lookup
struct CachedEntry
{
    const std::uint8_t* data;     // pointer into mmap'd cache file
    std::uint32_t       size;     // decompressed size
};

class DecompCache
{
public:
    static DecompCache& GetSingleton();

    // Initialize: load existing caches or prepare for building
    void Initialize(const std::filesystem::path& dataPath,
                    const std::vector<MappedArchive>& archives);

    // Look up a cached decompressed entry by (archive, startOffset)
    const CachedEntry* Lookup(const MappedArchive* archive,
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

    // Check if there are pending entries to flush
    bool HasPending() const;

    bool IsReady() const { return m_ready; }
    bool IsBuilding() const { return m_building; }

    void RecordHit(std::uint64_t bytes) {
        m_hits.fetch_add(1, std::memory_order_relaxed);
        m_hitBytes.fetch_add(bytes, std::memory_order_relaxed);
    }
    void RecordMiss() { m_misses.fetch_add(1, std::memory_order_relaxed); }

    std::uint64_t GetCacheHits() const { return m_hits.load(std::memory_order_relaxed); }
    std::uint64_t GetCacheMisses() const { return m_misses.load(std::memory_order_relaxed); }
    std::uint64_t GetCacheBytes() const { return m_hitBytes.load(std::memory_order_relaxed); }

private:
    DecompCache() = default;

    struct ArchiveCache
    {
        // For serving: mmap'd cache file
        void*          mapHandle = nullptr;
        const uint8_t* base     = nullptr;
        std::uint64_t  fileSize = 0;

        // Index: startOffset → CachedEntry
        std::unordered_map<std::uint32_t, CachedEntry> index;

        // For building: accumulated decompressed data
        struct PendingEntry {
            std::uint32_t startOffset;
            std::vector<std::uint8_t> data;
        };
        std::vector<PendingEntry> pending;
        std::mutex pendingMtx;

        void Close();
    };

    std::filesystem::path m_cachePath;
    std::unordered_map<const MappedArchive*, ArchiveCache> m_caches;

    bool m_ready    = false;
    bool m_building = false;
    std::unordered_set<std::string> m_startupFiles;  // paths written during initial flush

    std::atomic<std::uint64_t> m_hits{ 0 };
    std::atomic<std::uint64_t> m_misses{ 0 };
    std::atomic<std::uint64_t> m_hitBytes{ 0 };
    std::atomic<std::uint64_t> m_totalCacheBytes{ 0 };  // tracks on-disk cache size

    bool LoadCacheFile(const MappedArchive* archive, ArchiveCache& cache);
    bool WriteCacheFile(const MappedArchive* archive, ArchiveCache& cache);
    std::filesystem::path CachePathFor(const MappedArchive* archive) const;
    void EnforceSizeLimit();

    static std::uint64_t GetFileLastWrite(const std::filesystem::path& path);
    static std::uint32_t Checksum(const void* data, std::size_t size);
};

}  // namespace BSA
