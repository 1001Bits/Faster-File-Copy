#include "PCH.h"
#include "DecompCache.h"
#include "Settings.h"

namespace BSA
{

DecompCache& DecompCache::GetSingleton()
{
    static DecompCache instance;
    return instance;
}

void DecompCache::ArchiveCache::Close()
{
    index.clear();
    if (base) { UnmapViewOfFile(base); base = nullptr; }
    if (mapHandle) { CloseHandle(static_cast<HANDLE>(mapHandle)); mapHandle = nullptr; }
    fileSize = 0;
}

std::filesystem::path DecompCache::CachePathFor(const MappedArchive* archive) const
{
    auto name = archive->GetPath().filename().string() + ".decomp";
    return m_cachePath / name;
}

std::uint64_t DecompCache::GetFileLastWrite(const std::filesystem::path& path)
{
    WIN32_FILE_ATTRIBUTE_DATA attr{};
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attr))
        return (static_cast<std::uint64_t>(attr.ftLastWriteTime.dwHighDateTime) << 32)
             | attr.ftLastWriteTime.dwLowDateTime;
    return 0;
}

std::uint32_t DecompCache::Checksum(const void* data, std::size_t size)
{
    auto* p = static_cast<const std::uint8_t*>(data);
    std::uint32_t h = 0x811C9DC5;  // FNV-1a
    auto n = (size < 64) ? size : 64;
    for (std::size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 0x01000193;
    }
    return h;
}

void DecompCache::Initialize(const std::filesystem::path& dataPath,
                              const std::vector<MappedArchive>& archives)
{
    m_cachePath = dataPath / "SKSE" / "Plugins" / "BSAMemoryMap_cache";
    std::filesystem::create_directories(m_cachePath);

    std::uint32_t loaded = 0;
    std::uint32_t stale = 0;

    for (const auto& archive : archives) {
        if (!archive.IsOpen() || !archive.IsDefaultCompressed())
            continue;

        auto& cache = m_caches[&archive];

        if (LoadCacheFile(&archive, cache)) {
            ++loaded;
        } else {
            ++stale;
        }
    }

    // Calculate total cache size on disk
    std::uint64_t totalOnDisk = 0;
    for (const auto& entry : std::filesystem::directory_iterator(m_cachePath)) {
        if (entry.is_regular_file() && entry.path().extension() == ".decomp")
            totalOnDisk += entry.file_size();
    }
    m_totalCacheBytes.store(totalOnDisk, std::memory_order_relaxed);

    if (loaded > 0) {
        m_ready = true;
        logger::info("BSAMmap: DecompCache loaded {} cache files ({} stale/missing, {:.1f} MB on disk)",
            loaded, stale, totalOnDisk / (1024.0 * 1024.0));
    }

    if (stale > 0) {
        m_building = true;
        logger::info("BSAMmap: DecompCache will build {} new cache files this run", stale);
    }
}

bool DecompCache::LoadCacheFile(const MappedArchive* archive, ArchiveCache& cache)
{
    auto path = CachePathFor(archive);

    HANDLE fh = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER li{};
    GetFileSizeEx(fh, &li);
    auto totalSize = static_cast<std::uint64_t>(li.QuadPart);

    if (totalSize < sizeof(DecompCacheHeader)) {
        CloseHandle(fh);
        return false;
    }

    HANDLE mh = CreateFileMappingW(fh, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mh) {
        CloseHandle(fh);
        return false;
    }

    auto* view = static_cast<const std::uint8_t*>(MapViewOfFile(mh, FILE_MAP_READ, 0, 0, 0));
    if (!view) {
        CloseHandle(mh);
        CloseHandle(fh);
        return false;
    }

    // Validate header
    auto* hdr = reinterpret_cast<const DecompCacheHeader*>(view);
    if (std::memcmp(hdr->magic, "BSDC", 4) != 0 || hdr->version != 1) {
        UnmapViewOfFile(view);
        CloseHandle(mh);
        CloseHandle(fh);
        return false;
    }

    // Check BSA hasn't changed
    if (hdr->bsaFileSize != archive->GetFileSize() ||
        hdr->bsaLastWrite != GetFileLastWrite(archive->GetPath()))
    {
        UnmapViewOfFile(view);
        CloseHandle(mh);
        CloseHandle(fh);
        logger::info("BSAMmap: DecompCache stale for {}",
            archive->GetPath().filename().string());
        return false;
    }

    // Build index
    auto* entries = reinterpret_cast<const DecompCacheEntry*>(
        view + sizeof(DecompCacheHeader));

    for (std::uint32_t i = 0; i < hdr->entryCount; ++i) {
        const auto& e = entries[i];
        if (e.cacheOffset + e.decompSize <= totalSize) {
            cache.index[e.startOffset] = CachedEntry{
                view + e.cacheOffset,
                e.decompSize
            };
        }
    }

    cache.base = view;
    cache.mapHandle = mh;
    cache.fileSize = totalSize;

    // Close the file handle (mapping keeps the file open)
    CloseHandle(fh);

    logger::info("BSAMmap: DecompCache loaded {} entries for {}",
        hdr->entryCount, archive->GetPath().filename().string());

    return true;
}

const CachedEntry* DecompCache::Lookup(const MappedArchive* archive,
                                        std::uint32_t startOffset) const
{
    auto it = m_caches.find(archive);
    if (it == m_caches.end())
        return nullptr;

    auto eit = it->second.index.find(startOffset);
    if (eit == it->second.index.end())
        return nullptr;

    return &eit->second;
}

void DecompCache::RecordDecompressed(const MappedArchive* archive,
                                      std::uint32_t startOffset,
                                      const void* data,
                                      std::uint32_t size)
{
    if (!m_building || !data || size == 0)
        return;

    // If building is stopped (size limit reached), don't record
    if (!m_building)
        return;

    auto it = m_caches.find(archive);
    if (it == m_caches.end())
        return;

    auto& cache = it->second;

    if (cache.index.count(startOffset))
        return;

    std::lock_guard lk(cache.pendingMtx);

    // Check if already pending
    for (const auto& p : cache.pending) {
        if (p.startOffset == startOffset)
            return;
    }

    ArchiveCache::PendingEntry entry;
    entry.startOffset = startOffset;
    entry.data.resize(size);
    std::memcpy(entry.data.data(), data, size);
    cache.pending.push_back(std::move(entry));
}

void DecompCache::FlushToDisk()
{
    if (!m_building)
        return;

    std::uint32_t written = 0;
    std::uint64_t totalBytes = 0;

    for (auto& [archive, cache] : m_caches) {
        if (cache.pending.empty())
            continue;

        // Check size limit BEFORE writing
        if (Settings::iDecompCacheMaxMB > 0) {
            std::uint64_t actualSize = 0;
            for (const auto& entry : std::filesystem::directory_iterator(m_cachePath)) {
                if (entry.is_regular_file() && entry.path().extension() == ".decomp")
                    actualSize += entry.file_size();
            }
            auto limit = static_cast<std::uint64_t>(Settings::iDecompCacheMaxMB) * 1024 * 1024;
            if (actualSize >= limit) {
                m_building = false;
                logger::info("BSAMmap: DecompCache size limit reached ({:.0f}/{} MB) — stopped caching",
                    actualSize / (1024.0 * 1024.0), Settings::iDecompCacheMaxMB);
                // Clear all remaining pending data
                for (auto& [a, c] : m_caches) {
                    std::lock_guard lk(c.pendingMtx);
                    c.pending.clear();
                    c.pending.shrink_to_fit();
                }
                break;
            }
        }

        if (WriteCacheFile(archive, cache)) {
            ++written;
            for (const auto& p : cache.pending)
                totalBytes += p.data.size();
            m_startupFiles.insert(CachePathFor(archive).string());
        }

        cache.pending.clear();
        cache.pending.shrink_to_fit();
    }

    if (written > 0) {
        logger::info("BSAMmap: DecompCache wrote {} cache files ({:.1f} MB)",
            written, totalBytes / (1024.0 * 1024.0));
    }

    EnforceSizeLimit();

    // In mode 0, stop building after initial flush.
    // In mode 1, keep building (background flush will handle ongoing entries).
    if (Settings::iDecompCacheMode == 0)
        m_building = false;
}

bool DecompCache::HasPending() const
{
    for (const auto& [archive, cache] : m_caches) {
        std::lock_guard lk(const_cast<std::mutex&>(cache.pendingMtx));
        if (!cache.pending.empty())
            return true;
    }
    return false;
}

void DecompCache::StartBackgroundFlush()
{
    if (Settings::iDecompCacheMode < 1)
        return;

    std::thread([this]() {
        logger::info("BSAMmap: DecompCache background flush thread started (60s interval)");
        for (;;) {
            std::this_thread::sleep_for(std::chrono::seconds(60));

            if (!m_building)
                continue;

            if (!HasPending())
                continue;

            // Reuse FlushToDisk which handles size limits and eviction
            FlushToDisk();
        }
    }).detach();
}

void DecompCache::EnforceSizeLimit()
{
    if (Settings::iDecompCacheMaxMB <= 0)
        return;

    auto maxBytes = static_cast<std::uint64_t>(Settings::iDecompCacheMaxMB) * 1024 * 1024;

    struct CacheFileInfo {
        std::filesystem::path path;
        std::uint64_t size;
        std::uint64_t lastWrite;
        bool inUse;     // currently mmap'd — don't evict
        bool startup;   // written during initial load — evict last
    };
    std::vector<CacheFileInfo> files;
    std::uint64_t totalSize = 0;

    // Build set of currently loaded cache paths
    std::unordered_set<std::string> loadedPaths;
    for (const auto& [archive, cache] : m_caches) {
        if (cache.base)  // actively mmap'd
            loadedPaths.insert(CachePathFor(archive).string());
    }

    for (const auto& entry : std::filesystem::directory_iterator(m_cachePath)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".decomp")
            continue;
        auto sz = entry.file_size();
        totalSize += sz;
        bool inUse = loadedPaths.count(entry.path().string()) > 0;
        bool startup = m_startupFiles.count(entry.path().string()) > 0;
        files.push_back({ entry.path(), sz, GetFileLastWrite(entry.path()), inUse, startup });
    }

    if (totalSize <= maxBytes)
        return;

    // Sort priority: in-use last, startup second-to-last, then oldest first
    std::sort(files.begin(), files.end(),
        [](const CacheFileInfo& a, const CacheFileInfo& b) {
            if (a.inUse != b.inUse) return !a.inUse;      // evictable first
            if (a.startup != b.startup) return !a.startup;  // non-startup before startup
            return a.lastWrite < b.lastWrite;               // oldest first
        });

    for (const auto& f : files) {
        if (totalSize <= maxBytes)
            break;
        if (f.inUse)
            break;  // don't evict loaded files
        logger::info("BSAMmap: DecompCache evicting {} ({:.1f} MB)",
            f.path.filename().string(), f.size / (1024.0 * 1024.0));
        std::filesystem::remove(f.path);
        totalSize -= f.size;
    }

    if (totalSize > maxBytes) {
        logger::info("BSAMmap: DecompCache still over limit ({:.0f}/{} MB) — in-use files can't be evicted",
            totalSize / (1024.0 * 1024.0), Settings::iDecompCacheMaxMB);
    }
}

bool DecompCache::WriteCacheFile(const MappedArchive* archive, ArchiveCache& cache)
{
    // Merge existing index entries with new pending entries
    // For simplicity, we rewrite the entire cache file

    auto path = CachePathFor(archive);

    // Collect all entries (existing + pending)
    struct WriteEntry {
        std::uint32_t startOffset;
        const std::uint8_t* data;
        std::uint32_t size;
    };
    std::vector<WriteEntry> allEntries;

    // Existing cached entries
    for (const auto& [offset, cached] : cache.index) {
        allEntries.push_back({ offset, cached.data, cached.size });
    }

    // New pending entries
    for (const auto& p : cache.pending) {
        allEntries.push_back({
            p.startOffset,
            p.data.data(),
            static_cast<std::uint32_t>(p.data.size())
        });
    }

    // Calculate file layout
    auto headerSize = sizeof(DecompCacheHeader);
    auto indexSize = allEntries.size() * sizeof(DecompCacheEntry);
    auto dataStart = headerSize + indexSize;

    // Build header
    DecompCacheHeader hdr{};
    std::memcpy(hdr.magic, "BSDC", 4);
    hdr.version = 1;
    hdr.bsaFileSize = archive->GetFileSize();
    hdr.bsaLastWrite = GetFileLastWrite(archive->GetPath());
    hdr.entryCount = static_cast<std::uint32_t>(allEntries.size());

    // Build index and data
    std::vector<DecompCacheEntry> indexEntries;
    std::vector<std::uint8_t> dataBlob;

    for (const auto& e : allEntries) {
        DecompCacheEntry ie{};
        ie.startOffset = e.startOffset;
        ie.decompSize = e.size;
        ie.cacheOffset = dataStart + dataBlob.size();
        ie.checksum = Checksum(e.data, e.size);
        indexEntries.push_back(ie);
        dataBlob.insert(dataBlob.end(), e.data, e.data + e.size);
    }

    // Close existing mapping before overwriting
    cache.Close();

    // Write file
    HANDLE fh = CreateFileW(path.c_str(), GENERIC_WRITE, 0,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE) {
        logger::warn("BSAMmap: DecompCache failed to create {}", path.string());
        return false;
    }

    DWORD written;
    WriteFile(fh, &hdr, sizeof(hdr), &written, nullptr);
    WriteFile(fh, indexEntries.data(),
        static_cast<DWORD>(indexEntries.size() * sizeof(DecompCacheEntry)),
        &written, nullptr);
    WriteFile(fh, dataBlob.data(),
        static_cast<DWORD>(dataBlob.size()), &written, nullptr);
    CloseHandle(fh);

    // Update total cache size tracker
    auto newSize = sizeof(hdr) + indexEntries.size() * sizeof(DecompCacheEntry) + dataBlob.size();
    m_totalCacheBytes.fetch_add(newSize, std::memory_order_relaxed);

    // Re-load the cache file we just wrote
    return LoadCacheFile(archive, cache);
}

}  // namespace BSA
