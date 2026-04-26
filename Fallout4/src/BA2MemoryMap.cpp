#include "PCH.h"
#include "BA2MemoryMap.h"

#include <algorithm>
#include <cctype>
#include <cstring>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

namespace BA2
{
// ── MappedArchive ───────────────────────────────────────────────────────────

MappedArchive::~MappedArchive()
{
    Close();
}

MappedArchive::MappedArchive(MappedArchive&& o) noexcept
    : path_(std::move(o.path_))
    , fileHandle_(o.fileHandle_)
    , mapHandle_(o.mapHandle_)
    , base_(o.base_)
    , fileSize_(o.fileSize_)
    , header_(o.header_)
    , type_(o.type_)
    , fullyUncompressed_(o.fullyUncompressed_)
    , uncompressedCount_(o.uncompressedCount_)
{
    o.fileHandle_ = nullptr;
    o.mapHandle_  = nullptr;
    o.base_       = nullptr;
    o.fileSize_   = 0;
}

MappedArchive& MappedArchive::operator=(MappedArchive&& o) noexcept
{
    if (this != &o) {
        Close();
        path_              = std::move(o.path_);
        fileHandle_        = o.fileHandle_;
        mapHandle_         = o.mapHandle_;
        base_              = o.base_;
        fileSize_          = o.fileSize_;
        header_            = o.header_;
        type_              = o.type_;
        fullyUncompressed_ = o.fullyUncompressed_;
        uncompressedCount_ = o.uncompressedCount_;
        o.fileHandle_ = nullptr;
        o.mapHandle_  = nullptr;
        o.base_       = nullptr;
        o.fileSize_   = 0;
    }
    return *this;
}

bool MappedArchive::Open(const std::filesystem::path& archivePath)
{
    Close();
    path_ = archivePath;

    // FILE_FLAG_RANDOM_ACCESS: BA2 access is random (textures, meshes, scripts
    // jump around the file), so this is the correct caching hint regardless.
    // It also tells the cache manager to retain pages in standby longer —
    // SEQUENTIAL_SCAN aggressively evicts pages after first read, which fights
    // FFC4's whole "warm cache" premise. Same trick that Disk-Cache-Enable-F4VR
    // patches into the engine's own BA2 CreateFile call.
    HANDLE fh = CreateFileW(
        path_.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
        nullptr);

    if (fh == INVALID_HANDLE_VALUE) {
        logger::warn("BA2Mmap: Cannot open {}", path_.string());
        return false;
    }
    fileHandle_ = fh;

    LARGE_INTEGER li{};
    if (!GetFileSizeEx(fh, &li) || li.QuadPart < static_cast<LONGLONG>(sizeof(Header))) {
        logger::warn("BA2Mmap: File too small or size query failed: {}", path_.string());
        Close();
        return false;
    }
    fileSize_ = static_cast<uint64_t>(li.QuadPart);

    // Create a read-only file mapping.
    HANDLE mh = CreateFileMappingW(fh, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mh) {
        logger::warn("BA2Mmap: CreateFileMapping failed ({}): {}",
            GetLastError(), path_.string());
        Close();
        return false;
    }
    mapHandle_ = mh;

    // Map the entire file into our address space.
    auto* view = static_cast<const uint8_t*>(MapViewOfFile(mh, FILE_MAP_READ, 0, 0, 0));
    if (!view) {
        logger::warn("BA2Mmap: MapViewOfFile failed ({}): {}",
            GetLastError(), path_.string());
        Close();
        return false;
    }
    base_ = view;

    if (!ParseHeader()) {
        Close();
        return false;
    }

    return true;
}

void MappedArchive::Close()
{
    if (base_) {
        UnmapViewOfFile(base_);
        base_ = nullptr;
    }
    if (mapHandle_) {
        CloseHandle(static_cast<HANDLE>(mapHandle_));
        mapHandle_ = nullptr;
    }
    // INVALID_HANDLE_VALUE is (void*)(intptr_t)-1; nullptr means "never opened".
    if (fileHandle_ && fileHandle_ != reinterpret_cast<void*>(static_cast<intptr_t>(-1))) {
        CloseHandle(static_cast<HANDLE>(fileHandle_));
    }
    fileHandle_ = nullptr;
    fileSize_   = 0;
    uncompressedCount_ = 0;
    fullyUncompressed_ = false;
}

bool MappedArchive::ParseHeader()
{
    std::memcpy(&header_, base_, sizeof(Header));

    if (std::memcmp(header_.magic, "BTDX", 4) != 0) {
        logger::debug("BA2Mmap: Not a BA2 (bad magic): {}", path_.string());
        return false;
    }
    // BA2 versions: 1 = FO4 OG, 2/3 = Starfield, 7 = FO4 NG DX10, 8 = FO4 NG GNRL
    if (header_.version != 1 && header_.version != 7 && header_.version != 8) {
        logger::info("BA2Mmap: Unsupported BA2 version {}: {}", header_.version, path_.string());
        return false;
    }

    if (std::memcmp(header_.type, "GNRL", 4) == 0)
        type_ = Type::GNRL;
    else if (std::memcmp(header_.type, "DX10", 4) == 0)
        type_ = Type::DX10;
    else {
        logger::info("BA2Mmap: Unknown archive type in {}", path_.string());
        return false;
    }

    // Walk file records and count uncompressed entries.
    // For v7/v8 (NG), record layouts may differ — skip detailed parsing
    // but still map the file (the hook uses engine-provided offsets, not our parse).
    uncompressedCount_ = 0;

    if (header_.version >= 7) {
        // NG format — we map the file for the hook layer but don't parse records.
        // Mark as "all entries unknown" — the hook will determine per-read.
        fullyUncompressed_ = false;
        return true;
    }

    const uint8_t* cursor = base_ + sizeof(Header);

    if (type_ == Type::GNRL) {
        const uint64_t tableEnd = sizeof(Header)
            + static_cast<uint64_t>(header_.fileCount) * sizeof(GeneralFileRecord);
        if (fileSize_ < tableEnd) {
            logger::warn("BA2Mmap: Truncated GNRL table in {}", path_.string());
            return false;
        }
        for (uint32_t i = 0; i < header_.fileCount; ++i) {
            auto* rec = reinterpret_cast<const GeneralFileRecord*>(
                cursor + i * sizeof(GeneralFileRecord));
            if (rec->packedSize == 0)
                ++uncompressedCount_;
        }
    }
    else if (type_ == Type::DX10) {
        const uint8_t* end = base_ + fileSize_;
        for (uint32_t i = 0; i < header_.fileCount; ++i) {
            if (cursor + sizeof(DX10Header) > end) {
                logger::warn("BA2Mmap: Truncated DX10 header in {}", path_.string());
                return false;
            }
            auto* tex = reinterpret_cast<const DX10Header*>(cursor);
            cursor += sizeof(DX10Header);

            bool allUncompressed = true;
            for (uint8_t c = 0; c < tex->numChunks; ++c) {
                if (cursor + sizeof(DX10Chunk) > end) {
                    logger::warn("BA2Mmap: Truncated DX10 chunk in {}", path_.string());
                    return false;
                }
                auto* chunk = reinterpret_cast<const DX10Chunk*>(cursor);
                cursor += sizeof(DX10Chunk);
                if (chunk->packedSize != 0)
                    allUncompressed = false;
            }
            if (allUncompressed)
                ++uncompressedCount_;
        }
    }

    fullyUncompressed_ = (uncompressedCount_ == header_.fileCount);
    return true;
}

void MappedArchive::EnumerateEntries(std::vector<BA2Entry>& outEntries) const
{
    outEntries.clear();
    if (!base_) return;
    // v1 = FO4 OG (both GNRL + DX10).
    // v7 = FO4 NG/AE DX10 — verified by hex-dump of "Fallout4 - Textures1.ba2"
    //      on AE 1.11.191: record layout (DX10Header 0x18 + DX10Chunk 0x18 with
    //      BAADF00D sentinel at chunk+0x14) is byte-for-byte identical to v1.
    // v8 = FO4 NG GNRL — not supported here (different record layout).
    const bool v1 = (header_.version == 1);
    const bool v7dx10 = (header_.version == 7 && type_ == Type::DX10);
    if (!v1 && !v7dx10) return;

    const uint8_t* cursor = base_ + sizeof(Header);
    const uint8_t* end = base_ + fileSize_;

    if (type_ == Type::GNRL) {
        uint64_t tableEnd = sizeof(Header)
            + static_cast<uint64_t>(header_.fileCount) * sizeof(GeneralFileRecord);
        if (fileSize_ < tableEnd) return;

        for (uint32_t i = 0; i < header_.fileCount; ++i) {
            auto* rec = reinterpret_cast<const GeneralFileRecord*>(
                cursor + i * sizeof(GeneralFileRecord));
            BA2Entry entry{};
            entry.startOffset = static_cast<uint32_t>(rec->offset);
            entry.packedSize = rec->packedSize;
            entry.unpackedSize = rec->unpackedSize;
            entry.isCompressed = (rec->packedSize != 0);
            outEntries.push_back(entry);
        }
    }
    else if (type_ == Type::DX10) {
        for (uint32_t i = 0; i < header_.fileCount; ++i) {
            if (cursor + sizeof(DX10Header) > end) break;
            auto* tex = reinterpret_cast<const DX10Header*>(cursor);
            cursor += sizeof(DX10Header);

            for (uint8_t c = 0; c < tex->numChunks; ++c) {
                if (cursor + sizeof(DX10Chunk) > end) break;
                auto* chunk = reinterpret_cast<const DX10Chunk*>(cursor);
                cursor += sizeof(DX10Chunk);

                BA2Entry entry{};
                entry.startOffset = static_cast<uint32_t>(chunk->offset);
                entry.packedSize = chunk->packedSize;
                entry.unpackedSize = chunk->unpackedSize;
                entry.isCompressed = (chunk->packedSize != 0);
                outEntries.push_back(entry);
            }
        }
    }
}

// ── MemoryMapManager ────────────────────────────────────────────────────────

MemoryMapManager& MemoryMapManager::GetSingleton()
{
    static MemoryMapManager instance;
    return instance;
}

bool MemoryMapManager::Initialize(const std::filesystem::path& dataPath)
{
    logger::info("BA2Mmap: Scanning for BA2 archives in {}", dataPath.string());

    if (!std::filesystem::exists(dataPath)) {
        logger::error("BA2Mmap: Data path does not exist: {}", dataPath.string());
        return false;
    }

    uint32_t scanned = 0;
    uint32_t mapped  = 0;

    for (const auto& dirEntry : std::filesystem::directory_iterator(dataPath)) {
        if (!dirEntry.is_regular_file())
            continue;

        auto ext = dirEntry.path().extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(),
            [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });
        if (ext != ".ba2")
            continue;

        ++scanned;

        MappedArchive archive;
        if (!archive.Open(dirEntry.path()))
            continue;

        // Map ALL archives — even fully compressed ones benefit because the
        // OS page cache is shared: when the engine later calls ReadFile on the
        // same file, the data is already in physical memory from our mapping.

        auto filename = dirEntry.path().filename().string();
        std::string lowerName = filename;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
            [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });

        logger::info("BA2Mmap: Mapped {:>45s}  {:>5} entries  {:>5} uncompressed  {:>7.1f} MB{}",
            filename,
            archive.GetEntryCount(),
            archive.GetUncompressedCount(),
            archive.GetFileSize() / (1024.0 * 1024.0),
            archive.IsFullyUncompressed() ? "  [fully uncompressed]" : "");

        uint32_t idx = static_cast<uint32_t>(archives_.size());
        nameIndex_[lowerName] = idx;
        archives_.push_back(std::move(archive));
        ++mapped;
    }

    logger::info("BA2Mmap: Scan complete — {} archives scanned, {} memory-mapped ({:.1f} MB total)",
        scanned, mapped, GetTotalMappedBytes() / (1024.0 * 1024.0));

    return mapped > 0;
}

void MemoryMapManager::Shutdown()
{
    nameIndex_.clear();
    archives_.clear();
    logger::info("BA2Mmap: All memory maps released");
}

const MappedArchive* MemoryMapManager::FindByName(std::string_view filename) const
{
    std::string lower(filename);
    std::transform(lower.begin(), lower.end(), lower.begin(),
        [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });

    auto it = nameIndex_.find(lower);
    return (it != nameIndex_.end() && it->second < archives_.size())
        ? &archives_[it->second]
        : nullptr;
}

uint64_t MemoryMapManager::GetTotalMappedBytes() const
{
    uint64_t total = 0;
    for (const auto& a : archives_)
        total += a.GetFileSize();
    return total;
}

}  // namespace BA2
