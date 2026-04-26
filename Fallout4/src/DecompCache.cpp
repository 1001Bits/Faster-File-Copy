#include "PCH.h"
#include "DecompCache.h"
#include "Settings.h"
#include "BA2MemoryMap.h"

#include <algorithm>
#include <atomic>
#include <thread>
#include <zlib.h>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

namespace BA2
{

static constexpr std::uint32_t kCacheVersion = 4;

namespace {
// Holds a shared_ptr to the cache view so the mmap stays alive for the
// duration of the worker's walk. Without this, a concurrent flush /
// archive close that drops the cache view's shared_ptr would unmap the
// region while the worker is reading bytes from `base`, AVing on the next
// page touch — exactly the F4VR crash report from 2026-04-25 (FFC4+0x2CB73,
// `movzx ecx, byte ptr [rbx+rax*1]` inside the prefault loop).
struct PrefaultChunk {
    std::shared_ptr<MappedView> view;  // pins the mmap alive
    const std::uint8_t*         base;  // == view->base; cached for hot loop
    std::uint64_t               off;
    std::uint64_t               size;
};
}  // anonymous

DecompCache& DecompCache::GetSingleton()
{
    static DecompCache instance;
    return instance;
}

void DecompCache::ArchiveCache::Close()
{
    index.clear();
    view.reset();  // shared_ptr drop — unmaps when last holder releases
}

const CachedEntry* DecompCache::ArchiveCache::Find(std::uint32_t startOffset) const
{
    auto it = std::lower_bound(index.begin(), index.end(), startOffset,
        [](const auto& p, std::uint32_t k) { return p.first < k; });
    if (it != index.end() && it->first == startOffset)
        return &it->second;
    return nullptr;
}

bool DecompCache::ArchiveCache::Contains(std::uint32_t startOffset) const
{
    return Find(startOffset) != nullptr;
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
    m_cachePath = dataPath / "F4SE" / "Plugins" / "FasterFileCopyFO4_cache";
    std::error_code ec;
    std::filesystem::create_directories(m_cachePath, ec);

    std::uint32_t loaded = 0, stale = 0;

    for (const auto& archive : archives) {
        if (!archive.IsOpen())
            continue;

        // FIX: Use address of actual vector element, not the loop variable.
        // The loop variable 'archive' is a const ref that reuses the same
        // storage each iteration, so &archive would always be the same pointer.
        const MappedArchive* archPtr = std::addressof(archive);
        auto& cache = m_caches[archPtr];
        if (LoadCacheFile(archPtr, cache))
            ++loaded;
        else
            ++stale;
    }

    // Calculate total on-disk size
    std::uint64_t totalOnDisk = 0;
    for (const auto& entry : std::filesystem::directory_iterator(m_cachePath, ec)) {
        if (entry.is_regular_file() && entry.path().extension() == ".decomp")
            totalOnDisk += entry.file_size();
    }
    m_totalCacheBytes.store(totalOnDisk, std::memory_order_relaxed);

    if (loaded > 0) {
        m_ready = true;
        logger::info("DecompCache: Loaded {} cache files ({} stale/missing, {:.1f} MB on disk)",
            loaded, stale, totalOnDisk / (1024.0 * 1024.0));
        // Prefault is deferred until the main menu is ready (kInputLoaded) —
        // see main.cpp MessageHandler. Triggering it here would compete with
        // the engine's own data-load reads and steal disk bandwidth.
    }
    if (stale > 0) {
        m_building = true;
        logger::info("DecompCache: Will build {} new cache files this run", stale);
    }

    // Nothing to build and the caches we loaded are immutable for the rest of
    // the run — flip to stable so Lookup() takes the lock-free path. Mirrors
    // BSAMemoryMap's Initialize-time stable transition.
    if (m_ready && !m_building) {
        m_stable.store(true, std::memory_order_release);
        logger::info("DecompCache: Stable mode enabled (no rebuilds queued)");
    }

    // Defer VirtualLock to a background thread — page fault-in for the full
    // pinned set takes ~1s/GB on warm storage and was observed adding 3.7s to
    // F4SE plugin load on a 2 GB cache (delays game start). Cache lookups
    // don't depend on the lock being done; pages still serve correctly while
    // the lock catches up. Subsequent WriteCacheFile-driven re-locks happen
    // on the background flush thread and stay synchronous (small per-view).
    if (m_ready) {
        std::thread([this]() { LockCacheInMemory(); }).detach();
    }
}

void DecompCache::LockCacheInMemory()
{
    if (!Settings::bLockCacheInMemory)
        return;

    // Serialize against concurrent callers (initial async lock thread vs
    // bg-flush post-WriteCacheFile re-locks). Without this, two threads
    // would race on view->locked atomic stores and on quota math.
    std::lock_guard lg(m_lockMtx);

    // Snapshot the set of views to lock. shared_ptr copies pin each view
    // for the duration of the lock walk so a concurrent flush can't drop
    // it mid-VirtualLock. Per-cache shared_lock pairs with WriteCacheFile's
    // unique_lock when it swaps cache.view.
    struct LockTarget {
        const MappedArchive*        archive;
        std::shared_ptr<MappedView> view;
    };
    std::vector<LockTarget> targets;
    std::uint64_t pendingBytes = 0;
    for (auto& [archive, cache] : m_caches) {
        std::shared_lock rl(cache.rebuildMtx);
        if (cache.view && cache.view->base && cache.view->size > 0 &&
            !cache.view->locked.load(std::memory_order_acquire))
        {
            pendingBytes += cache.view->size;
            targets.push_back({ archive, cache.view });
        }
    }
    if (targets.empty())
        return;

    // Safety check against current free physical RAM. ullAvailPhys is "free
    // for new allocations" — it already accounts for everything else running.
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms)) {
        logger::warn("DecompCache: GlobalMemoryStatusEx failed ({}); skipping VirtualLock",
            GetLastError());
        return;
    }

    const auto reserveBytes = static_cast<std::uint64_t>(Settings::iLockCacheReserveMB)
                            * 1024ULL * 1024ULL;
    const auto totalPhys = ms.ullTotalPhys;
    const auto availPhys = ms.ullAvailPhys;

    // Two guards: (1) leave reserveBytes free after the lock, and (2) never
    // pin more than half of total physical RAM — protects against catastrophic
    // misconfiguration on small-RAM systems.
    if (pendingBytes + reserveBytes > availPhys) {
        logger::warn("DecompCache: VirtualLock skipped — locking {:.1f} MB would leave only {:.1f} MB free (need {:.1f} MB reserve, total RAM {:.1f} MB)",
            pendingBytes / (1024.0 * 1024.0),
            (availPhys > pendingBytes ? (availPhys - pendingBytes) : 0) / (1024.0 * 1024.0),
            reserveBytes / (1024.0 * 1024.0),
            totalPhys / (1024.0 * 1024.0));
        return;
    }
    if (pendingBytes > totalPhys / 2) {
        logger::warn("DecompCache: VirtualLock skipped — {:.1f} MB exceeds 50% of total RAM ({:.1f} MB)",
            pendingBytes / (1024.0 * 1024.0),
            totalPhys / (1024.0 * 1024.0));
        return;
    }

    // Expand working-set quota to fit. VirtualLock fails with
    // ERROR_WORKING_SET_QUOTA without this. Add 256 MB headroom on the max
    // so the game's own working set isn't crushed against the new floor.
    SIZE_T currMin = 0, currMax = 0;
    if (!GetProcessWorkingSetSize(GetCurrentProcess(), &currMin, &currMax)) {
        currMin = 0;
        currMax = 0;
    }
    const SIZE_T headroom = 256ULL * 1024 * 1024;
    SIZE_T newMin = currMin + static_cast<SIZE_T>(pendingBytes);
    SIZE_T newMax = (currMax > newMin + headroom) ? currMax : (newMin + headroom);
    if (!SetProcessWorkingSetSizeEx(GetCurrentProcess(), newMin, newMax,
                                    QUOTA_LIMITS_HARDWS_MIN_ENABLE)) {
        logger::warn("DecompCache: SetProcessWorkingSetSizeEx({} MB min, {} MB max) failed ({}); VirtualLock will likely fail",
            newMin / (1024 * 1024), newMax / (1024 * 1024), GetLastError());
    }

    int locked = 0, failed = 0;
    std::uint64_t lockedBytes = 0;
    for (auto& [archive, view] : targets) {
        // Recheck locked under our serialized critical section — a previous
        // call sharing the same window could have pinned this view first.
        if (view->locked.load(std::memory_order_acquire))
            continue;
        if (VirtualLock(const_cast<std::uint8_t*>(view->base),
                        static_cast<SIZE_T>(view->size))) {
            view->locked.store(true, std::memory_order_release);
            lockedBytes += view->size;
            ++locked;
        } else {
            ++failed;
            logger::warn("DecompCache: VirtualLock failed on {} ({:.1f} MB, error={})",
                archive->GetPath().filename().string(),
                view->size / (1024.0 * 1024.0), GetLastError());
        }
    }

    logger::info("DecompCache: VirtualLock pinned {} views ({:.1f} MB), {} failed (avail before={:.1f} MB)",
        locked, lockedBytes / (1024.0 * 1024.0), failed,
        availPhys / (1024.0 * 1024.0));
}

DecompCache::BuildResult DecompCache::BuildAllCache(const std::vector<MappedArchive>& archives)
{
    BuildResult result{};
    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);

    m_building = true;

    for (const auto& archive : archives) {
        if (!archive.IsOpen())
            continue;

        // Find the corresponding cache entry (by address match)
        const MappedArchive* archPtr = std::addressof(archive);
        auto& cache = m_caches[archPtr];
        if (cache.view) {
            // Already loaded from disk — skip, we'll only build missing entries
            continue;
        }

        std::vector<BA2Entry> entries;
        archive.EnumerateEntries(entries);
        result.totalEntries += static_cast<uint32_t>(entries.size());

        int compressedCount = 0;
        for (const auto& entry : entries) {
            if (!entry.isCompressed)
                continue;
            ++compressedCount;
            ++result.compressedEntries;

            // Skip if already cached
            if (cache.Contains(entry.startOffset))
                continue;

            // Read compressed data from mmap.
            if (entry.packedSize < 3) {
                ++result.errors;
                continue;
            }
            const uint8_t* compData = archive.At(entry.startOffset, entry.packedSize);
            if (!compData) {
                ++result.errors;
                continue;
            }

            std::vector<uint8_t> decompBuf(entry.unpackedSize);
            bool ok = false;

            // BA2 uses standard zlib compression (header 0x78 0x9C etc).
            // Try standard zlib inflate first.
            {
                z_stream strm{};
                int ret = inflateInit(&strm);
                if (ret == Z_OK) {
                    strm.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(compData));
                    strm.avail_in = entry.packedSize;
                    strm.next_out = decompBuf.data();
                    strm.avail_out = entry.unpackedSize;
                    ret = inflate(&strm, Z_FINISH);
                    inflateEnd(&strm);
                    if (ret == Z_STREAM_END && strm.total_out == entry.unpackedSize)
                        ok = true;
                }
            }

            // Fallback: try raw deflate (skip 1-byte compression type prefix 0x10)
            if (!ok && entry.packedSize >= 2) {
                const uint8_t* zData = compData + 1;
                uint32_t zSize = entry.packedSize - 1;
                z_stream strm{};
                int ret = inflateInit2(&strm, -MAX_WBITS);
                if (ret == Z_OK) {
                    strm.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(zData));
                    strm.avail_in = zSize;
                    strm.next_out = decompBuf.data();
                    strm.avail_out = entry.unpackedSize;
                    ret = inflate(&strm, Z_FINISH);
                    inflateEnd(&strm);
                    if (ret == Z_STREAM_END && strm.total_out == entry.unpackedSize)
                        ok = true;
                }
            }

            if (!ok) {
                ++result.errors;
                continue;
            }

            // Record in cache
            RecordDecompressed(archPtr, entry.startOffset,
                decompBuf.data(), static_cast<uint32_t>(decompBuf.size()));
            ++result.cachedEntries;
            result.cachedBytes += decompBuf.size();
        }

        if (compressedCount > 0) {
            char buf[256];
            std::snprintf(buf, sizeof(buf),
                "BA2Mmap: BuildAllCache %s — %d entries, %d compressed, %d cached",
                archive.GetPath().filename().string().c_str(),
                static_cast<int>(entries.size()), compressedCount, compressedCount);
            logger::info(buf);
        }
    }

    // Flush everything to disk
    FlushToDisk();

    QueryPerformanceCounter(&t1);
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    double elapsed = static_cast<double>(t1.QuadPart - t0.QuadPart) / static_cast<double>(freq.QuadPart);

    char buf[256];
    std::snprintf(buf, sizeof(buf),
        "BA2Mmap: BuildAllCache complete in %.1fs — %u total, %u compressed, %u cached (%.0f MB), %u errors",
        elapsed, result.totalEntries, result.compressedEntries,
        result.cachedEntries, result.cachedBytes / (1024.0 * 1024.0),
        result.errors);
    logger::info(buf);

    return result;
}

DecompCache::BuildResult DecompCache::BuildTextureCache(
    const std::vector<MappedArchive>& archives)
{
    BuildResult result{};
    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);

    // Builds feed RecordDecompressed; that path is gated on m_building.
    m_building = true;

    for (const auto& archive : archives) {
        if (!archive.IsOpen() || !archive.IsDX10())
            continue;

        const MappedArchive* archPtr = std::addressof(archive);
        auto& cache = m_caches[archPtr];

        // When bBuildTextureCache is set, discard any partial cache loaded
        // from disk so every chunk is re-decompressed from the archive.
        if (cache.view) {
            std::unique_lock lk(cache.rebuildMtx);
            cache.index.clear();
            cache.entryCount.store(0, std::memory_order_release);
            cache.view.reset();
        }

        std::vector<BA2Entry> entries;
        archive.EnumerateEntries(entries);
        result.totalEntries += static_cast<uint32_t>(entries.size());

        int compressedCount = 0;
        int cachedThisFile = 0;
        for (const auto& entry : entries) {
            if (!entry.isCompressed)
                continue;
            ++compressedCount;
            ++result.compressedEntries;

            if (cache.Contains(entry.startOffset))
                continue;

            if (entry.packedSize < 3) {
                ++result.errors;
                continue;
            }
            const uint8_t* compData = archive.At(entry.startOffset, entry.packedSize);
            if (!compData) {
                ++result.errors;
                continue;
            }

            std::vector<uint8_t> decompBuf(entry.unpackedSize);
            bool ok = false;
            {
                z_stream strm{};
                int ret = inflateInit(&strm);
                if (ret == Z_OK) {
                    strm.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(compData));
                    strm.avail_in = entry.packedSize;
                    strm.next_out = decompBuf.data();
                    strm.avail_out = entry.unpackedSize;
                    ret = inflate(&strm, Z_FINISH);
                    inflateEnd(&strm);
                    if (ret == Z_STREAM_END && strm.total_out == entry.unpackedSize)
                        ok = true;
                }
            }
            if (!ok && entry.packedSize >= 2) {
                const uint8_t* zData = compData + 1;
                uint32_t zSize = entry.packedSize - 1;
                z_stream strm{};
                int ret = inflateInit2(&strm, -MAX_WBITS);
                if (ret == Z_OK) {
                    strm.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(zData));
                    strm.avail_in = zSize;
                    strm.next_out = decompBuf.data();
                    strm.avail_out = entry.unpackedSize;
                    ret = inflate(&strm, Z_FINISH);
                    inflateEnd(&strm);
                    if (ret == Z_STREAM_END && strm.total_out == entry.unpackedSize)
                        ok = true;
                }
            }
            if (!ok) {
                ++result.errors;
                continue;
            }

            RecordDecompressed(archPtr, entry.startOffset,
                decompBuf.data(), static_cast<uint32_t>(decompBuf.size()));
            ++result.cachedEntries;
            ++cachedThisFile;
            result.cachedBytes += decompBuf.size();
        }

        if (compressedCount > 0) {
            char buf[256];
            std::snprintf(buf, sizeof(buf),
                "DecompCache: BuildTextureCache %s — %d chunks, %d compressed, %d cached",
                archive.GetPath().filename().string().c_str(),
                static_cast<int>(entries.size()), compressedCount, cachedThisFile);
            logger::info(buf);
        }

        // Flush this archive's pending entries NOW so we don't hold the whole
        // (multi-GB) decompressed texture cache in RAM while the next archive
        // inflates. Without this, accumulating all 9 Textures*.ba2 worth of
        // pending (~20-40 GB uncompressed) would OOM the process.
        // If the cap was tripped during flush, m_building is now false —
        // RecordDecompressed will silently drop subsequent entries and we
        // can stop early.
        FlushToDisk();
        if (!m_building)
            break;
    }

    QueryPerformanceCounter(&t1);
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    double elapsed = static_cast<double>(t1.QuadPart - t0.QuadPart)
                    / static_cast<double>(freq.QuadPart);

    char buf[256];
    std::snprintf(buf, sizeof(buf),
        "DecompCache: BuildTextureCache complete in %.1fs — %u chunks, %u compressed, %u cached (%.0f MB), %u errors",
        elapsed, result.totalEntries, result.compressedEntries,
        result.cachedEntries, result.cachedBytes / (1024.0 * 1024.0),
        result.errors);
    logger::info(buf);

    return result;
}

void DecompCache::Shutdown()
{
    for (auto& [k, ac] : m_caches)
        ac.Close();
    m_caches.clear();
}

std::vector<std::pair<const std::uint8_t*, std::uint64_t>>
DecompCache::GetMappedViews() const
{
    std::vector<std::pair<const std::uint8_t*, std::uint64_t>> out;
    out.reserve(m_caches.size());
    for (const auto& [k, ac] : m_caches) {
        std::shared_lock lk(ac.rebuildMtx);
        if (ac.view && ac.view->base && ac.view->size > 0)
            out.emplace_back(ac.view->base, ac.view->size);
    }
    return out;
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
    if (!mh) { CloseHandle(fh); return false; }

    auto* viewPtr = static_cast<const uint8_t*>(MapViewOfFile(mh, FILE_MAP_READ, 0, 0, 0));
    if (!viewPtr) { CloseHandle(mh); CloseHandle(fh); return false; }

    auto* hdr = reinterpret_cast<const DecompCacheHeader*>(viewPtr);
    if (std::memcmp(hdr->magic, "B2DC", 4) != 0 || hdr->version != kCacheVersion) {
        if (std::memcmp(hdr->magic, "B2DC", 4) == 0)
            logger::info("DecompCache: Outdated version {} (expected {}), will rebuild: {}",
                hdr->version, kCacheVersion, archive->GetPath().filename().string());
        UnmapViewOfFile(viewPtr); CloseHandle(mh); CloseHandle(fh);
        return false;
    }

    if (hdr->ba2FileSize != archive->GetFileSize() ||
        hdr->ba2LastWrite != GetFileLastWrite(archive->GetPath()))
    {
        logger::info("DecompCache: Stale for {}", archive->GetPath().filename().string());
        UnmapViewOfFile(viewPtr); CloseHandle(mh); CloseHandle(fh);
        return false;
    }

    // Build index with checksum verification
    auto* entries = reinterpret_cast<const DecompCacheEntry*>(viewPtr + sizeof(DecompCacheHeader));
    std::uint32_t corruptCount = 0;
    cache.index.reserve(hdr->entryCount);
    for (std::uint32_t i = 0; i < hdr->entryCount; ++i) {
        const auto& e = entries[i];
        if (e.cacheOffset + e.decompSize <= totalSize) {
            auto actual = Checksum(viewPtr + e.cacheOffset, e.decompSize);
            if (actual != e.checksum) {
                ++corruptCount;
                // If >10% of entries are corrupt, invalidate entire cache and rebuild
                if (corruptCount > hdr->entryCount / 10 + 1) {
                    logger::warn("DecompCache: Too many corrupt entries ({}/{}), will rebuild: {}",
                        corruptCount, hdr->entryCount, archive->GetPath().filename().string());
                    cache.index.clear();
                    UnmapViewOfFile(viewPtr); CloseHandle(mh); CloseHandle(fh);
                    return false;
                }
                continue;
            }
            cache.index.emplace_back(e.startOffset,
                CachedEntry{ viewPtr + e.cacheOffset, e.decompSize });
        }
    }
    // Sort by startOffset so Find/Contains can std::lower_bound. Entries may
    // already be sorted (WriteCacheFile writes them in map-iteration order
    // historically, but the new sorted-vector index guarantees order on
    // rewrite). std::sort on an already-sorted range is near-free.
    std::sort(cache.index.begin(), cache.index.end(),
        [](const auto& a, const auto& b) { return a.first < b.first; });
    if (corruptCount > 0)
        logger::warn("DecompCache: Skipped {} corrupt entries in {}",
            corruptCount, archive->GetPath().filename().string());

    auto owner = std::make_shared<MappedView>();
    owner->base      = viewPtr;
    owner->mapHandle = mh;
    owner->size      = totalSize;
    cache.view = std::move(owner);
    CloseHandle(fh);

    // Publish count after index is fully built — release pairs with
    // the acquire-load in Lookup's fast-path.
    cache.entryCount.store(static_cast<std::uint32_t>(cache.index.size()),
                           std::memory_order_release);

    logger::info("DecompCache: Loaded {} entries for {}",
        cache.index.size(), archive->GetPath().filename().string());
    return true;
}

LookupResult DecompCache::Lookup(const MappedArchive* archive,
                                  std::uint32_t startOffset) const
{
    // Fast path 1 — thread-local cache of the last ArchiveCache pointer.
    // Texture streaming is bursty with high archive locality (dozens of
    // chunks from the same BA2 in a row), so this hits on nearly every call
    // after the first and skips the unordered_map find.
    thread_local const MappedArchive*        tl_archive = nullptr;
    thread_local const ArchiveCache*         tl_cache   = nullptr;

    const ArchiveCache* cache;
    if (archive == tl_archive && tl_cache) {
        cache = tl_cache;
    } else {
        auto it = m_caches.find(archive);
        if (it == m_caches.end()) {
            tl_archive = nullptr;
            tl_cache   = nullptr;
            return {};
        }
        cache = &it->second;
        tl_archive = archive;
        tl_cache   = cache;
    }

    // Fast path 2 — stable mode. Once IsStable(), m_caches is immutable and
    // every ArchiveCache::view is permanent (no further WriteCacheFile will
    // unmap it). Lookup needs no shared_lock and no shared_ptr<MappedView>
    // refcount bump; the caller may use the raw `data` pointer for the
    // call's lifetime with `owner` left empty. Mirrors BSAMemoryMap's
    // stable-mode Lookup path.
    if (m_stable.load(std::memory_order_acquire)) {
        const CachedEntry* hit = cache->Find(startOffset);
        if (hit)
            return LookupResult{ hit->data, hit->size, {} };
        return {};
    }

    // Fast path 3 — lock-free empty-cache bail. An archive with nothing in
    // either the flushed index OR the pending queue needs no lock acquire,
    // no binary search, no shared_ptr copy. Common before passive capture
    // has populated the .decomp file and during the first run over a new BA2.
    const bool hasFlushed = cache->entryCount.load(std::memory_order_acquire) != 0;
    const bool hasPending = cache->pendingCount.load(std::memory_order_acquire) != 0;
    if (!hasFlushed && !hasPending)
        return {};

    // Take shared lock while reading index + view. Flush holds the
    // exclusive lock only during WriteCacheFile's clear/reload step.
    if (hasFlushed) {
        std::shared_lock lk(cache->rebuildMtx);
        const CachedEntry* hit = cache->Find(startOffset);
        if (hit) {
            // Copy the shared_ptr out under the lock; caller holds a ref that
            // keeps the mapping alive even if a concurrent flush resets view.
            return LookupResult{ hit->data, hit->size, cache->view };
        }
    }

    // Pending fallback — chunks captured this session but not yet flushed
    // live in `cache->pending`. Closes the "capture happened this run but the
    // 60s flush hasn't fired" window that otherwise shows up as dcMiss.
    if (hasPending) {
        std::lock_guard pLk(cache->pendingMtx);
        for (const auto& p : cache->pending) {
            if (p.startOffset == startOffset && p.data) {
                return LookupResult{
                    p.data->data(),
                    static_cast<std::uint32_t>(p.data->size()),
                    p.data  // shared_ptr<vector<u8>> → shared_ptr<void>
                };
            }
        }
    }
    return {};
}

DecompCache::ViewBackedResult DecompCache::LookupViewBacked(
    const MappedArchive* archive, std::uint32_t startOffset) const
{
    auto it = m_caches.find(archive);
    if (it == m_caches.end())
        return {};
    const auto& cache = it->second;

    // Stable: index immutable, view permanent. Return raw data with empty
    // view shared_ptr (caller doesn't need to pin).
    if (m_stable.load(std::memory_order_acquire)) {
        const CachedEntry* hit = cache.Find(startOffset);
        if (!hit) return {};
        return ViewBackedResult{ hit->data, hit->size, {} };
    }

    // Non-stable flushed path: copy shared_ptr<MappedView> under shared_lock
    // so the substitute stream can keep the mapping alive across flushes.
    if (cache.entryCount.load(std::memory_order_acquire) == 0)
        return {};
    std::shared_lock lk(cache.rebuildMtx);
    const CachedEntry* hit = cache.Find(startOffset);
    if (!hit) return {};
    return ViewBackedResult{ hit->data, hit->size, cache.view };
}

void DecompCache::RecordDecompressed(const MappedArchive* archive,
                                      std::uint32_t startOffset,
                                      const void* data,
                                      std::uint32_t size)
{
    if (!m_building || !data || size == 0)
        return;

    auto it = m_caches.find(archive);
    if (it == m_caches.end())
        return;

    auto& cache = it->second;
    {
        std::shared_lock rlk(cache.rebuildMtx);
        if (cache.Contains(startOffset))
            return;
    }

    std::lock_guard lk(cache.pendingMtx);
    for (const auto& p : cache.pending)
        if (p.startOffset == startOffset)
            return;

    auto buf = std::make_shared<std::vector<std::uint8_t>>(size);
    std::memcpy(buf->data(), data, size);
    cache.pending.push_back(ArchiveCache::PendingEntry{ startOffset, std::move(buf) });
    cache.pendingCount.fetch_add(1, std::memory_order_release);
}

void DecompCache::FlushToDisk()
{
    if (!m_building)
        return;

    std::uint32_t written = 0;
    std::uint64_t totalBytes = 0;

    // Running total, updated per-file after each successful write so the
    // cap check reflects the state the NEXT file will see, not the state
    // before the flush started.
    auto currentOnDisk = m_totalCacheBytes.load(std::memory_order_relaxed);
    const std::uint64_t limit = Settings::iDecompCacheMaxMB > 0
        ? static_cast<std::uint64_t>(Settings::iDecompCacheMaxMB) * 1024 * 1024
        : 0;

    for (auto& [archive, cache] : m_caches) {
        // Snapshot pending under the lock so we can release the lock before
        // the (potentially slow) WriteCacheFile call — this prevents a race
        // where HookedDoRead's RecordDecompressed pushes new entries while
        // WriteCacheFile iterates the vector, reallocating it mid-iteration.
        std::vector<ArchiveCache::PendingEntry> localPending;
        {
            std::lock_guard lk(cache.pendingMtx);
            if (cache.pending.empty())
                continue;
            localPending.swap(cache.pending);
            cache.pending.shrink_to_fit();
            cache.pendingCount.store(0, std::memory_order_release);
        }

        if (limit > 0) {
            // Project the size this file will have AFTER the rewrite:
            // header + (existing index entries + pending entries) + their data.
            std::uint64_t projected = sizeof(DecompCacheHeader);
            for (const auto& [off, cached] : cache.index)
                projected += sizeof(DecompCacheEntry) + cached.size;
            for (const auto& p : localPending)
                projected += sizeof(DecompCacheEntry) + (p.data ? p.data->size() : 0);

            // On-disk size of the file we're about to overwrite (0 if new).
            std::error_code ec;
            auto path = CachePathFor(archive);
            std::uint64_t existing = std::filesystem::exists(path, ec)
                ? std::filesystem::file_size(path, ec) : 0;
            if (ec) existing = 0;

            auto newTotal = currentOnDisk - std::min(currentOnDisk, existing) + projected;
            if (newTotal > limit) {
                m_building = false;
                logger::info("DecompCache: Cap would be exceeded ({:.1f} - {:.1f} + {:.1f} > {} MB) — stopped caching",
                    currentOnDisk / (1024.0 * 1024.0),
                    existing / (1024.0 * 1024.0),
                    projected / (1024.0 * 1024.0),
                    Settings::iDecompCacheMaxMB);
                // Drop our snapshot and clear any remaining pending on every
                // cache so the memory footprint doesn't keep growing.
                localPending.clear();
                localPending.shrink_to_fit();
                for (auto& [a, c] : m_caches) {
                    std::lock_guard lk(c.pendingMtx);
                    c.pending.clear();
                    c.pending.shrink_to_fit();
                    c.pendingCount.store(0, std::memory_order_release);
                }
                // No more writes will happen — flip to stable so Lookup
                // takes the lock-free path for the rest of the run.
                if (m_ready)
                    m_stable.store(true, std::memory_order_release);
                break;
            }
        }

        if (WriteCacheFile(archive, cache, localPending)) {
            ++written;
            for (const auto& p : localPending)
                totalBytes += p.data ? p.data->size() : 0;
            m_startupFiles.insert(CachePathFor(archive).string());
            // Refresh running total — WriteCacheFile updates m_totalCacheBytes
            // via sub(oldSize)+add(newSize), so reload after each write.
            currentOnDisk = m_totalCacheBytes.load(std::memory_order_relaxed);
        }
        // localPending goes out of scope here, freeing the decompressed buffers.
    }

    if (written > 0)
        logger::info("DecompCache: Wrote {} cache files ({:.1f} MB)", written, totalBytes / (1024.0 * 1024.0));

    EnforceSizeLimit();

    if (Settings::iDecompCacheMode == 0) {
        m_building = false;
        // Final flush in startup-only mode — no more writes can happen, so
        // Lookup can take the lock-free path. Mirrors BSAMemoryMap's mode 0
        // post-flush transition.
        if (m_ready)
            m_stable.store(true, std::memory_order_release);
    }
}

bool DecompCache::HasPending() const
{
    for (const auto& [archive, cache] : m_caches) {
        std::lock_guard lk(cache.pendingMtx);
        if (!cache.pending.empty())
            return true;
    }
    return false;
}

void DecompCache::CancelPrefault()
{
    m_prefaultCancel.store(true, std::memory_order_release);
}

void DecompCache::PrefaultCachePages()
{
    if (!m_ready || !Settings::bPrefaultCache)
        return;

    // Idempotent — kInputLoaded may fire multiple times on some runtimes
    // (e.g., after returning to main menu), and re-warming residents is cheap
    // but logging is noisy. Guard with a one-shot flag.
    static std::atomic<bool> s_started{ false };
    if (s_started.exchange(true, std::memory_order_acq_rel))
        return;

    std::thread([this]() {
        LARGE_INTEGER t0, t1, freq;
        QueryPerformanceCounter(&t0);
        QueryPerformanceFrequency(&freq);

        const std::size_t pageSize   = 4096;
        const std::size_t burstPages = 256;  // 1 MB per burst
        const auto baseYield = std::chrono::milliseconds(2);
        const auto busyYield = std::chrono::milliseconds(250);

        // Split each view into ~64 MB chunks so workers can cooperate on a
        // single large archive instead of serializing when there are few
        // views but each is multi-GB.
        constexpr std::uint64_t kChunkBytes = 64ull * 1024 * 1024;

        std::vector<PrefaultChunk> dx10Chunks, gnrlChunks;
        std::uint64_t dx10Bytes = 0, gnrlBytes = 0;
        std::uint64_t skippedLocked = 0;
        for (const auto& [archive, cache] : m_caches) {
            if (!archive) continue;
            // Snapshot the shared_ptr under the per-archive lock so a
            // concurrent rewrite can't swap cache.view out from under us
            // mid-snapshot. The shared_ptr copy keeps the view alive
            // across our subsequent reads.
            std::shared_ptr<MappedView> view;
            {
                std::shared_lock rl(cache.rebuildMtx);
                view = cache.view;
            }
            if (!view || !view->base || view->size == 0) continue;
            // Skip views already pinned by VirtualLock — locked pages are
            // guaranteed resident, so touching them is wasted CPU + memory
            // bandwidth, and the work would also overlap with save-load
            // reads if a save-load fires mid-prefault.
            if (view->locked.load(std::memory_order_acquire)) {
                skippedLocked += view->size;
                continue;
            }
            auto& dst = archive->IsDX10() ? dx10Chunks : gnrlChunks;
            auto& tally = archive->IsDX10() ? dx10Bytes : gnrlBytes;
            for (std::uint64_t off = 0; off < view->size; off += kChunkBytes) {
                std::uint64_t sz = std::min<std::uint64_t>(kChunkBytes, view->size - off);
                dst.push_back({ view, view->base, off, sz });
                tally += sz;
            }
        }
        if (skippedLocked > 0)
            logger::info("DecompCache: Prefault skipping {:.1f} MB already pinned by VirtualLock",
                skippedLocked / (1024.0 * 1024.0));

        const int workerCount = std::clamp(Settings::iPrefaultThreads, 1, 8);

        auto runPhase = [this, pageSize, burstPages, baseYield, busyYield, workerCount]
                        (std::vector<PrefaultChunk>& chunks)
        {
            std::atomic<std::size_t> next{ 0 };
            std::vector<std::thread> workers;
            workers.reserve(workerCount);
            const bool burst = Settings::bPrefaultBurst;
            auto worker = [this, pageSize, burstPages, baseYield, busyYield,
                           burst, &next, &chunks]()
            {
                volatile std::uint8_t sink = 0;
                auto lastActivity = GetCacheHits() + GetCacheMisses();
                for (;;) {
                    if (!burst && m_prefaultCancel.load(std::memory_order_acquire)) return;
                    std::size_t i = next.fetch_add(1, std::memory_order_relaxed);
                    if (i >= chunks.size()) return;
                    const auto& c = chunks[i];
                    std::uint64_t off = c.off;
                    const std::uint64_t end = c.off + c.size;
                    while (off < end) {
                        std::uint64_t burstEnd =
                            std::min<std::uint64_t>(off + burstPages * pageSize, end);
                        while (off < burstEnd) {
                            sink = c.base[off];
                            off += pageSize;
                        }
                        if (burst) continue;  // no throttle in burst mode
                        if (m_prefaultCancel.load(std::memory_order_acquire)) return;
                        const auto cur = GetCacheHits() + GetCacheMisses();
                        if (cur - lastActivity > 32)
                            std::this_thread::sleep_for(busyYield);
                        else
                            std::this_thread::sleep_for(baseYield);
                        lastActivity = cur;
                    }
                    (void)sink;
                }
            };
            for (int w = 0; w < workerCount; ++w)
                workers.emplace_back(worker);
            for (auto& t : workers) t.join();
        };

        runPhase(dx10Chunks);

        LARGE_INTEGER tDx10;
        QueryPerformanceCounter(&tDx10);
        double dx10Elapsed = static_cast<double>(tDx10.QuadPart - t0.QuadPart)
                            / static_cast<double>(freq.QuadPart);
        logger::info("DecompCache: Prefault pass 1 (DX10) — {:.1f} MB in {:.2f}s ({:.0f} MB/s, {} workers, burst={})",
            dx10Bytes / (1024.0 * 1024.0), dx10Elapsed,
            dx10Elapsed > 0 ? dx10Bytes / (1024.0 * 1024.0) / dx10Elapsed : 0.0,
            workerCount, Settings::bPrefaultBurst ? "true" : "false");

        if (!Settings::bPrefaultBurst && m_prefaultCancel.load(std::memory_order_acquire)) {
            logger::info("DecompCache: Prefault cancelled at save-load start — DX10 pass complete, GNRL skipped");
            return;
        }

        runPhase(gnrlChunks);

        QueryPerformanceCounter(&t1);
        double totalElapsed = static_cast<double>(t1.QuadPart - t0.QuadPart)
                             / static_cast<double>(freq.QuadPart);
        double gnrlElapsed = totalElapsed - dx10Elapsed;

        if (m_prefaultCancel.load(std::memory_order_acquire)) {
            logger::info("DecompCache: Prefault cancelled at save-load start — DX10 {:.1f} MB + GNRL {:.1f} MB (partial) in {:.2f}s",
                dx10Bytes / (1024.0 * 1024.0),
                gnrlBytes / (1024.0 * 1024.0),
                totalElapsed);
            return;
        }

        logger::info("DecompCache: Prefault complete — DX10 {:.1f} MB + GNRL {:.1f} MB in {:.2f}s (pass2 {:.2f}s @ {:.0f} MB/s)",
            dx10Bytes / (1024.0 * 1024.0),
            gnrlBytes / (1024.0 * 1024.0),
            totalElapsed,
            gnrlElapsed,
            gnrlElapsed > 0 ? gnrlBytes / (1024.0 * 1024.0) / gnrlElapsed : 0.0);
    }).detach();
}

void DecompCache::StartBackgroundFlush()
{
    if (Settings::iDecompCacheMode < 1)
        return;

    m_flushShutdownRequested.store(false, std::memory_order_release);

    std::thread([this]() {
        logger::info("DecompCache: Background flush thread started (60s interval)");

        // One-time DX10 texture cache build. Opt-in via bBuildTextureCache
        // (default off) — by default we rely on passive capture from
        // HookedInflate / HookedStreamInflate, which grows the cache only
        // with chunks the game actually reads during play. Runs on this
        // thread (not the main thread) to avoid blocking kGameDataReady,
        // and on THIS thread specifically — not a separate detached thread
        // — so it stays single-threaded with FlushToDisk.
        if (Settings::bEnableDecompCache && Settings::bEnableTextureCache &&
            Settings::bBuildTextureCache &&
            !m_flushShutdownRequested.load(std::memory_order_relaxed))
        {
            auto& mgr = MemoryMapManager::GetSingleton();
            BuildTextureCache(mgr.GetArchives());
            FlushToDisk();
        }

        while (!m_flushShutdownRequested.load(std::memory_order_relaxed)) {
            // Sleep in 1-second increments for shutdown responsiveness
            for (int s = 0; s < 60; ++s) {
                if (m_flushShutdownRequested.load(std::memory_order_relaxed))
                    return;
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            if (!m_building) continue;
            if (!HasPending()) continue;
            FlushToDisk();
        }
        logger::info("DecompCache: Background flush thread shutting down");
    }).detach();
}

void DecompCache::RequestShutdown()
{
    m_flushShutdownRequested.store(true, std::memory_order_release);
}

void DecompCache::EnforceSizeLimit()
{
    if (Settings::iDecompCacheMaxMB <= 0)
        return;

    auto maxBytes = static_cast<std::uint64_t>(Settings::iDecompCacheMaxMB) * 1024 * 1024;

    // Early exit if tracked size is well under limit
    auto trackedSize = m_totalCacheBytes.load(std::memory_order_relaxed);
    if (trackedSize <= maxBytes * 9 / 10)  // 10% buffer
        return;

    struct CacheFileInfo {
        std::filesystem::path path;
        std::uint64_t size;
        std::uint64_t lastWrite;
        bool inUse;
        bool startup;
    };
    std::vector<CacheFileInfo> files;
    std::uint64_t totalSize = 0;

    std::unordered_set<std::string> loadedPaths;
    for (const auto& [archive, cache] : m_caches)
        if (cache.view)
            loadedPaths.insert(CachePathFor(archive).string());

    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(m_cachePath, ec)) {
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

    // Evict: in-use last, startup second-to-last, then oldest first
    std::sort(files.begin(), files.end(),
        [](const CacheFileInfo& a, const CacheFileInfo& b) {
            if (a.inUse != b.inUse) return !a.inUse;
            if (a.startup != b.startup) return !a.startup;
            return a.lastWrite < b.lastWrite;
        });

    for (const auto& f : files) {
        if (totalSize <= maxBytes) break;
        if (f.inUse) break;
        logger::info("DecompCache: Evicting {} ({:.1f} MB)",
            f.path.filename().string(), f.size / (1024.0 * 1024.0));
        std::filesystem::remove(f.path, ec);
        totalSize -= f.size;
    }
}

bool DecompCache::WriteCacheFile(const MappedArchive* archive, ArchiveCache& cache,
                                  const std::vector<ArchiveCache::PendingEntry>& pending)
{
    auto path = CachePathFor(archive);

    // Merge existing + pending (pending is a caller-owned snapshot, safe to
    // iterate without taking cache.pendingMtx).
    struct WriteEntry {
        std::uint32_t startOffset;
        const std::uint8_t* data;
        std::uint32_t size;
    };
    std::vector<WriteEntry> allEntries;

    for (const auto& [offset, cached] : cache.index)
        allEntries.push_back({ offset, cached.data, cached.size });

    for (const auto& p : pending) {
        if (!p.data) continue;
        allEntries.push_back({
            p.startOffset, p.data->data(), static_cast<std::uint32_t>(p.data->size()) });
    }

    auto headerSize = sizeof(DecompCacheHeader);
    auto indexSize  = allEntries.size() * sizeof(DecompCacheEntry);
    auto dataStart  = headerSize + indexSize;

    DecompCacheHeader hdr{};
    std::memcpy(hdr.magic, "B2DC", 4);
    hdr.version      = kCacheVersion;
    hdr.ba2FileSize  = archive->GetFileSize();
    hdr.ba2LastWrite = GetFileLastWrite(archive->GetPath());
    hdr.entryCount   = static_cast<std::uint32_t>(allEntries.size());

    // Build index first (compute offsets without accumulating data blob).
    std::vector<DecompCacheEntry> indexEntries;
    std::uint64_t dataOffset = dataStart;

    for (const auto& e : allEntries) {
        DecompCacheEntry ie{};
        ie.startOffset = e.startOffset;
        ie.decompSize  = e.size;
        ie.cacheOffset = dataOffset;
        ie.checksum    = Checksum(e.data, e.size);
        indexEntries.push_back(ie);
        dataOffset += e.size;
    }

    // Capture the old file size BEFORE we unmap/remove it, so the tracked
    // total can be corrected (subtract old, add new) instead of only adding.
    std::error_code szEc;
    std::uint64_t oldSize = std::filesystem::exists(path, szEc)
        ? std::filesystem::file_size(path, szEc) : 0;
    if (szEc) oldSize = 0;

    // Write to a temp file then rename — prevents corruption on crash.
    // The old mmap view must stay alive until the write completes because
    // allEntries may contain pointers into the mmap'd cache file.
    auto tmpPath = path;
    tmpPath += L".tmp";

    HANDLE fh = CreateFileW(tmpPath.c_str(), GENERIC_WRITE, 0,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE)
        return false;

    DWORD w;
    WriteFile(fh, &hdr, sizeof(hdr), &w, nullptr);
    WriteFile(fh, indexEntries.data(),
        static_cast<DWORD>(indexEntries.size() * sizeof(DecompCacheEntry)), &w, nullptr);

    // Write data per-entry to avoid multi-GB memory allocation.
    for (const auto& e : allEntries) {
        const auto* ptr = e.data;
        std::uint32_t remaining = e.size;
        while (remaining > 0) {
            DWORD toWrite = remaining;
            DWORD written = 0;
            if (!WriteFile(fh, ptr, toWrite, &written, nullptr) || written == 0)
                break;
            ptr += written;
            remaining -= written;
        }
    }
    FlushFileBuffers(fh);
    CloseHandle(fh);

    // Mutation span: block concurrent Lookups while we tear down and rebuild
    // the mapped view + index. Everything before this point only READ cache
    // state; Lookup can run freely against it. LoadCacheFile repopulates both
    // under the same lock so readers never observe an empty index + stale view.
    std::unique_lock lk(cache.rebuildMtx);

    // Now safe to release the old mmap — data has been written to the tmp file.
    cache.index.clear();
    cache.entryCount.store(0, std::memory_order_release);
    cache.view.reset();

    // Atomic rename: delete old, rename tmp → final
    std::error_code ec;
    std::filesystem::remove(path, ec);
    std::filesystem::rename(tmpPath, path, ec);
    if (ec) {
        std::filesystem::remove(tmpPath, ec);
        return false;
    }

    auto newSize = sizeof(hdr) + indexEntries.size() * sizeof(DecompCacheEntry)
                 + (dataOffset - dataStart);
    m_totalCacheBytes.fetch_sub(oldSize, std::memory_order_relaxed);
    m_totalCacheBytes.fetch_add(newSize, std::memory_order_relaxed);

    // Load the new cache file (creates fresh shared_ptr<MappedView>).
    // Drop the rebuildMtx before pinning pages — VirtualLock on a large view
    // can be slow and we don't want to hold the per-archive lock during it.
    const bool ok = LoadCacheFile(archive, cache);
    lk.unlock();
    if (ok)
        LockCacheInMemory();
    return ok;
}

}  // namespace BA2
