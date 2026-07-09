#include "PCH.h"
#include "DecompCache.h"
#include "Settings.h"

namespace BSA
{

// Bump this when cache format changes to auto-invalidate old caches.
// v6: checksum widened from head-64B to head-4KB + tail-64B + length mix —
//     the old window could not catch a truncated/torn data blob whose first
//     64 bytes were intact, which would then be served as a silently-corrupt
//     asset ("some mods just did not load").
static constexpr std::uint32_t kCacheVersion = 6;

static constexpr std::size_t   kChecksumHeadWindow        = 4096;
static constexpr std::size_t   kChecksumTailWindow        = 64;
static constexpr int           kBackgroundFlushIntervalSec = 60;
static constexpr std::uint64_t kBytesPerMB                = 1024ull * 1024ull;

MappedView::~MappedView()
{
    if (base) UnmapViewOfFile(base);
    if (mapHandle) CloseHandle(static_cast<HANDLE>(mapHandle));
}

DecompCache& DecompCache::GetSingleton()
{
    static DecompCache instance;
    return instance;
}

void DecompCache::ArchiveCache::Close()
{
    index.clear();
    view.reset();  // drops local strong ref; surviving streams keep view alive
    activePath.clear();
}

std::filesystem::path DecompCache::CachePathFor(const MappedArchive* archive) const
{
    auto name = archive->GetPath().filename().string() + ".decomp";
    return m_cachePath / name;
}

bool DecompCache::IsCacheFilePath(const std::filesystem::path& path)
{
    auto filename = path.filename().wstring();
    return path.extension() == L".decomp" || std::wstring_view(filename).find(L".decomp.tmp") != std::wstring_view::npos;
}

std::filesystem::path DecompCache::ResolveCacheFilePath(const MappedArchive* archive) const
{
    auto basePath = CachePathFor(archive);
    std::vector<std::filesystem::path> candidates;

    if (std::filesystem::exists(basePath))
        candidates.push_back(basePath);

    if (std::filesystem::exists(m_cachePath)) {
        auto tempPrefix = basePath.filename().wstring() + L".tmp";
        for (const auto& entry : std::filesystem::directory_iterator(m_cachePath)) {
            if (!entry.is_regular_file())
                continue;

            auto filename = entry.path().filename().wstring();
            if (std::wstring_view(filename).starts_with(tempPrefix))
                candidates.push_back(entry.path());
        }
    }

    if (candidates.empty())
        return basePath;

    return *std::max_element(candidates.begin(), candidates.end(),
        [](const auto& lhs, const auto& rhs) {
            return GetFileLastWrite(lhs) < GetFileLastWrite(rhs);
        });
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

    // Head window: catches wrong-content corruption.
    const auto head = (size < kChecksumHeadWindow) ? size : kChecksumHeadWindow;
    for (std::size_t i = 0; i < head; ++i) {
        h ^= p[i];
        h *= 0x01000193;
    }

    // Tail window: catches truncation / torn writes whose head is intact.
    if (size > head) {
        const auto tail = ((size - head) < kChecksumTailWindow) ? (size - head)
                                                                : kChecksumTailWindow;
        for (std::size_t i = size - tail; i < size; ++i) {
            h ^= p[i];
            h *= 0x01000193;
        }
    }

    // Mix in the length so a same-prefix, same-suffix resize can't collide.
    h ^= static_cast<std::uint32_t>(size);
    h *= 0x01000193;
    h ^= static_cast<std::uint32_t>(size >> 16);
    h *= 0x01000193;
    return h;
}

void DecompCache::Initialize(const std::filesystem::path& dataPath,
                              const std::vector<MappedArchive>& archives)
{
    std::unique_lock cacheLock(m_cacheMtx);
    m_cachePath = dataPath / "SKSE" / "Plugins" / "BSAMemoryMap_cache";
    std::filesystem::create_directories(m_cachePath);

    std::uint32_t loaded = 0;
    std::uint32_t stale = 0;

    for (const auto& archive : archives) {
        if (!archive.IsOpen())
            continue;

        auto& cache = m_caches[&archive];

        if (LoadCacheFile(&archive, cache)) {
            ++loaded;
        } else {
            ++stale;
        }
    }

    // Clean up stale temp files left from previous runs that lost the rename
    // race. For each archive, delete any "<bsa>.decomp.tmp.*" sibling that is
    // not the path we just loaded. The active temp (if any) is held open with
    // dwShareMode=0 by its writer, so a concurrent instance's file will fail
    // DeleteFileW with ERROR_SHARING_VIOLATION — harmless. The glob is
    // anchored to the BSA filename, so user files cannot match.
    std::uint32_t orphansRemoved = 0;
    for (const auto& [archive, cache] : m_caches) {
        const auto basePath  = CachePathFor(archive);
        const auto tempStem  = basePath.filename().wstring() + L".tmp.";
        const auto activeStr = cache.activePath.empty() ? std::wstring{} : cache.activePath.wstring();
        std::error_code ec;
        for (const auto& entry : std::filesystem::directory_iterator(m_cachePath, ec)) {
            if (ec) break;
            if (!entry.is_regular_file(ec)) continue;
            const auto name = entry.path().filename().wstring();
            if (!std::wstring_view(name).starts_with(tempStem)) continue;
            if (entry.path().wstring() == activeStr) continue;
            std::error_code rmErr;
            if (std::filesystem::remove(entry.path(), rmErr))
                ++orphansRemoved;
        }
    }
    if (orphansRemoved > 0)
        logger::info("BSAMmap: DecompCache removed {} orphaned temp file(s) from previous runs",
            orphansRemoved);

    // Calculate total cache size on disk
    std::uint64_t totalOnDisk = 0;
    for (const auto& entry : std::filesystem::directory_iterator(m_cachePath)) {
        if (entry.is_regular_file() && IsCacheFilePath(entry.path()))
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
    } else if (m_ready) {
        // Nothing to build — flip to stable mode immediately so Lookup() takes
        // the lock-free path from the very first call.
        m_stable.store(true, std::memory_order_release);
    }
}

bool DecompCache::LoadCacheFile(const MappedArchive* archive, ArchiveCache& cache)
{
    auto path = ResolveCacheFilePath(archive);
    if (!std::filesystem::exists(path))
        return false;

    return LoadCacheFile(archive, cache, path);
}

bool DecompCache::LoadCacheFile(const MappedArchive* archive, ArchiveCache& cache, const std::filesystem::path& path)
{

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
    if (std::memcmp(hdr->magic, "BSDC", 4) != 0 || hdr->version != kCacheVersion) {
        auto oldVersion = hdr->version;
        bool badMagic = std::memcmp(hdr->magic, "BSDC", 4) != 0;
        UnmapViewOfFile(view);
        CloseHandle(mh);
        CloseHandle(fh);
        if (!badMagic)
            logger::info("BSAMmap: DecompCache outdated version {} (expected {}), will rebuild: {}",
                oldVersion, kCacheVersion, archive->GetPath().filename().string());
        return false;
    }

    // Check BSA hasn't changed
    if (hdr->bsaFileSize != archive->GetFileSize() ||
        hdr->bsaLastWrite != GetFileLastWrite(archive->GetPath()) ||
        hdr->bsaEntryCount != archive->GetEntryCount())
    {
        UnmapViewOfFile(view);
        CloseHandle(mh);
        CloseHandle(fh);
        logger::info("BSAMmap: DecompCache stale for {} (size/time/entries mismatch)",
            archive->GetPath().filename().string());
        return false;
    }

    // Build index
    auto* entries = reinterpret_cast<const DecompCacheEntry*>(
        view + sizeof(DecompCacheHeader));

    bool corrupt = false;
    for (std::uint32_t i = 0; i < hdr->entryCount; ++i) {
        const auto& e = entries[i];
        if (e.cacheOffset + e.decompSize <= totalSize) {
            auto actual = Checksum(view + e.cacheOffset, e.decompSize);
            if (actual != e.checksum) {
                logger::warn("BSAMmap: Cache corruption detected in {}, will rebuild",
                    archive->GetPath().filename().string());
                corrupt = true;
                break;
            }
            cache.index[e.startOffset] = CachedEntry{
                view + e.cacheOffset,
                e.decompSize
            };
        }
    }

    if (corrupt) {
        cache.index.clear();
        UnmapViewOfFile(view);
        CloseHandle(mh);
        CloseHandle(fh);
        return false;
    }

    auto owner = std::make_shared<MappedView>();
    owner->base      = view;
    owner->mapHandle = mh;
    owner->size      = totalSize;
    cache.view       = std::move(owner);
    cache.activePath = path;

    // Close the file handle (mapping keeps the file open)
    CloseHandle(fh);

    logger::info("BSAMmap: DecompCache loaded {} entries for {}",
        hdr->entryCount, archive->GetPath().filename().string());

    return true;
}

LookupResult DecompCache::Lookup(const MappedArchive* archive,
                                  std::uint32_t startOffset) const
{
    // Fast path: once stable, m_caches is immutable and all views are
    // permanent — no lock, and no shared_ptr refcount bump. The returned
    // LookupResult has an empty owner; callers that need a long-lived
    // pointer don't need to pin the view because nothing can unmap it.
    if (m_stable.load(std::memory_order_acquire)) {
        auto it = m_caches.find(archive);
        if (it == m_caches.end())
            return {};
        const auto& index = it->second.index;
        auto eit = index.find(startOffset);
        if (eit == index.end())
            return {};
        LookupResult result;
        result.data = eit->second.data;
        result.size = eit->second.size;
        // owner intentionally left empty — view is permanent
        return result;
    }

    std::shared_lock cacheLock(m_cacheMtx);
    auto it = m_caches.find(archive);
    if (it == m_caches.end())
        return {};

    const auto& entry = it->second.index;
    auto eit = entry.find(startOffset);
    if (eit == entry.end())
        return {};

    LookupResult result;
    result.data  = eit->second.data;
    result.size  = eit->second.size;
    result.owner = it->second.view;  // share ownership of underlying view
    return result;
}

bool DecompCache::Contains(const MappedArchive* archive,
                           std::uint32_t startOffset) const
{
    // Fast path: no lock when stable (see Lookup for rationale).
    if (m_stable.load(std::memory_order_acquire)) {
        auto it = m_caches.find(archive);
        if (it == m_caches.end())
            return false;
        return it->second.index.find(startOffset) != it->second.index.end();
    }

    std::shared_lock cacheLock(m_cacheMtx);
    auto it = m_caches.find(archive);
    if (it == m_caches.end())
        return false;
    return it->second.index.find(startOffset) != it->second.index.end();
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

    std::unique_lock cacheLock(m_cacheMtx);

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
    std::unique_lock cacheLock(m_cacheMtx);

    if (!m_building)
        return;

    std::uint32_t written = 0;
    std::uint64_t totalBytes = 0;

    const std::uint64_t sizeLimit = (Settings::iDecompCacheMaxMB > 0)
        ? static_cast<std::uint64_t>(Settings::iDecompCacheMaxMB) * kBytesPerMB
        : 0;

    for (auto& [archive, cache] : m_caches) {
        {
            std::lock_guard pendingLock(cache.pendingMtx);
            if (cache.pending.empty())
                continue;
        }

        // Check size limit BEFORE writing — use cumulative counter, no dir scan.
        if (sizeLimit > 0) {
            const auto actualSize = m_totalCacheBytes.load(std::memory_order_relaxed);
            if (actualSize >= sizeLimit) {
                m_building = false;
                // No more writes will happen — flip to stable so future
                // Lookup() calls skip the lock.
                if (m_ready)
                    m_stable.store(true, std::memory_order_release);
                logger::info("BSAMmap: DecompCache size limit reached ({:.0f}/{} MB) — stopped caching",
                    actualSize / static_cast<double>(kBytesPerMB), Settings::iDecompCacheMaxMB);
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
            std::lock_guard pendingLock(cache.pendingMtx);
            for (const auto& p : cache.pending)
                totalBytes += p.data.size();
            if (!cache.activePath.empty())
                m_startupFiles.insert(cache.activePath.string());
        }

        {
            std::lock_guard pendingLock(cache.pendingMtx);
            cache.pending.clear();
            cache.pending.shrink_to_fit();
        }
    }

    if (written > 0) {
        logger::info("BSAMmap: DecompCache wrote {} cache files ({:.1f} MB)",
            written, totalBytes / (1024.0 * 1024.0));
    }

    EnforceSizeLimit();

    // In mode 0, stop building after initial flush.
    // In mode 1, keep building (background flush will handle ongoing entries).
    if (Settings::iDecompCacheMode == 0) {
        m_building = false;
        // No more writes — flip to stable so Lookup() takes the lock-free path.
        if (m_ready)
            m_stable.store(true, std::memory_order_release);
    }
}

bool DecompCache::HasPending() const
{
    std::shared_lock cacheLock(m_cacheMtx);
    for (const auto& [archive, cache] : m_caches) {
        std::lock_guard lk(cache.pendingMtx);
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
        logger::info("BSAMmap: DecompCache background flush thread started ({}s interval)",
            kBackgroundFlushIntervalSec);
        for (;;) {
            std::this_thread::sleep_for(std::chrono::seconds(kBackgroundFlushIntervalSec));

            if (!m_building)
                continue;

            if (!HasPending())
                continue;

            try {
                // Reuse FlushToDisk which handles size limits and eviction
                FlushToDisk();
            } catch (const std::exception& e) {
                logger::error("BSAMmap: DecompCache background flush failed: {}", e.what());
                m_building = false;
                if (m_ready)
                    m_stable.store(true, std::memory_order_release);
            } catch (...) {
                logger::error("BSAMmap: DecompCache background flush failed with unknown exception");
                m_building = false;
                if (m_ready)
                    m_stable.store(true, std::memory_order_release);
            }
        }
    }).detach();
}

void DecompCache::PrefaultAll()
{
    static std::atomic<bool> s_started{ false };
    if (s_started.exchange(true, std::memory_order_acq_rel))
        return;

    // Snapshot (view, size) under the shared lock, then release so the sweep
    // runs lock-free. The shared_ptr copies keep the views alive even if a
    // concurrent flush rebuilds the cache underneath us.
    std::vector<std::pair<std::shared_ptr<MappedView>, std::uint64_t>> snap;
    {
        std::shared_lock lock(m_cacheMtx);
        snap.reserve(m_caches.size());
        for (const auto& [archive, cache] : m_caches) {
            if (cache.view && cache.view->base && cache.view->size > 0)
                snap.emplace_back(cache.view, cache.view->size);
        }
    }
    if (snap.empty())
        return;

    std::thread([snap = std::move(snap)]() {
        LARGE_INTEGER t0, t1, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&t0);

        volatile std::uint8_t sink = 0;
        const std::size_t pageSize   = 4096;
        const std::size_t burstPages = 256;  // 1 MB bursts
        const auto idleYield = std::chrono::milliseconds(2);
        const auto busyYield = std::chrono::milliseconds(250);

        auto& dcache = DecompCache::GetSingleton();
        auto lastActivity = dcache.GetCacheMisses();

        std::uint64_t totalBytes = 0;
        for (const auto& [view, size] : snap) {
            const std::uint8_t* base = view->base;
            for (std::uint64_t off = 0; off < size;) {
                const std::uint64_t burstEnd =
                    std::min<std::uint64_t>(off + burstPages * pageSize, size);
                while (off < burstEnd) {
                    sink = base[off];
                    off += pageSize;
                }
                // Activity-aware throttle: >32 misses since last burst means
                // the game is loading — back off 250 ms; else yield 2 ms.
                const auto cur = dcache.GetCacheMisses();
                if (cur - lastActivity > 32)
                    std::this_thread::sleep_for(busyYield);
                else
                    std::this_thread::sleep_for(idleYield);
                lastActivity = cur;
            }
            totalBytes += size;
        }

        QueryPerformanceCounter(&t1);
        double sec = static_cast<double>(t1.QuadPart - t0.QuadPart)
                   / static_cast<double>(freq.QuadPart);
        double mb = totalBytes / (1024.0 * 1024.0);
        logger::info("BSAMmap: DecompCache prefault complete — {:.1f} MB in {:.2f}s ({:.0f} MB/s)",
            mb, sec, sec > 0.001 ? mb / sec : 0.0);
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
        if (cache.view)  // actively mmap'd
            loadedPaths.insert(cache.activePath.string());
    }

    for (const auto& entry : std::filesystem::directory_iterator(m_cachePath)) {
        if (!entry.is_regular_file() || !IsCacheFilePath(entry.path()))
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
    std::lock_guard pendingLock(cache.pendingMtx);

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
    hdr.version = kCacheVersion;
    hdr.bsaFileSize = archive->GetFileSize();
    hdr.bsaLastWrite = GetFileLastWrite(archive->GetPath());
    hdr.bsaEntryCount = archive->GetEntryCount();
    hdr.entryCount = static_cast<std::uint32_t>(allEntries.size());

    // Build index and data
    std::vector<DecompCacheEntry> indexEntries;
    std::vector<std::uint8_t> dataBlob;

    std::size_t totalDataBytes = 0;
    for (const auto& e : allEntries)
        totalDataBytes += e.size;

    indexEntries.reserve(allEntries.size());
    dataBlob.reserve(totalDataBytes);

    for (const auto& e : allEntries) {
        DecompCacheEntry ie{};
        ie.startOffset = e.startOffset;
        ie.decompSize = e.size;
        ie.cacheOffset = dataStart + dataBlob.size();
        ie.checksum = Checksum(e.data, e.size);
        indexEntries.push_back(ie);
        dataBlob.insert(dataBlob.end(), e.data, e.data + e.size);
    }

    // Drop the cache's strong reference to the previous mapping. Streams
    // and inline-state entries that still hold their own shared_ptr<MappedView>
    // keep the old view alive until they release it; once the last reader is
    // gone, the MappedView destructor unmaps and closes the section handle.
    cache.index.clear();
    cache.view.reset();
    cache.activePath.clear();

    // Write to a unique temp file then rename if possible — the old file may be
    // locked by retired mmaps, so the temp file itself must be loadable.
    static std::atomic<std::uint64_t> s_tempGeneration{ 0 };
    auto tempPath = path;
    tempPath += L".tmp.";
    tempPath += std::to_wstring(s_tempGeneration.fetch_add(1, std::memory_order_relaxed) + 1);
    HANDLE fh = CreateFileW(tempPath.c_str(), GENERIC_WRITE, 0,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE) {
        logger::warn("BSAMmap: DecompCache failed to create {}", tempPath.string());
        return false;
    }

    auto writeAll = [&](const void* buf, DWORD bytes) -> bool {
        DWORD wrote = 0;
        if (!WriteFile(fh, buf, bytes, &wrote, nullptr) || wrote != bytes) {
            logger::warn("BSAMmap: DecompCache WriteFile failed for {} (wrote {}/{}, err={})",
                tempPath.filename().string(), wrote, bytes, GetLastError());
            return false;
        }
        return true;
    };

    bool writeOk =
        writeAll(&hdr, static_cast<DWORD>(sizeof(hdr))) &&
        writeAll(indexEntries.data(),
            static_cast<DWORD>(indexEntries.size() * sizeof(DecompCacheEntry))) &&
        writeAll(dataBlob.data(), static_cast<DWORD>(dataBlob.size()));
    CloseHandle(fh);

    if (!writeOk) {
        std::error_code ec;
        std::filesystem::remove(tempPath, ec);
        return false;
    }

    std::filesystem::path activePath = path;

    // Replace old file with new one when possible. If the old file is still locked
    // by retired mmaps, keep serving from the new temp file and pick it up next launch.
    if (!MoveFileExW(tempPath.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        activePath = tempPath;
        logger::info("BSAMmap: Cache replace deferred for {}, serving from {} this run",
            path.filename().string(), tempPath.filename().string());
    }

    // Update total cache size tracker
    auto newSize = sizeof(hdr) + indexEntries.size() * sizeof(DecompCacheEntry) + dataBlob.size();
    m_totalCacheBytes.fetch_add(newSize, std::memory_order_relaxed);

    // Re-load the cache file we just wrote.
    return LoadCacheFile(archive, cache, activePath);
}

}  // namespace BSA
