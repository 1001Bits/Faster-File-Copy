#include "PCH.h"
#include "BSAMemoryMap.h"

namespace BSA
{

// ── MappedArchive ──────────────────────────────────────────────────────────

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
    , defaultCompressed_(o.defaultCompressed_)
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
        defaultCompressed_ = o.defaultCompressed_;
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

    HANDLE fh = CreateFileW(
        path_.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);

    if (fh == INVALID_HANDLE_VALUE) {
        logger::warn("BSAMmap: Cannot open {}", path_.string());
        return false;
    }
    fileHandle_ = fh;

    LARGE_INTEGER li{};
    if (!GetFileSizeEx(fh, &li) || li.QuadPart < static_cast<LONGLONG>(sizeof(Header))) {
        logger::warn("BSAMmap: File too small or size query failed: {}", path_.string());
        Close();
        return false;
    }
    fileSize_ = static_cast<uint64_t>(li.QuadPart);

    HANDLE mh = CreateFileMappingW(fh, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mh) {
        logger::warn("BSAMmap: CreateFileMapping failed ({}): {}",
            GetLastError(), path_.string());
        Close();
        return false;
    }
    mapHandle_ = mh;

    auto* view = static_cast<const uint8_t*>(MapViewOfFile(mh, FILE_MAP_READ, 0, 0, 0));
    if (!view) {
        logger::warn("BSAMmap: MapViewOfFile failed ({}): {}",
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
    if (fileHandle_ && fileHandle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(static_cast<HANDLE>(fileHandle_));
    }
    fileHandle_ = nullptr;
    fileSize_   = 0;
}

bool MappedArchive::ParseHeader()
{
    std::memcpy(&header_, base_, sizeof(Header));

    if (std::memcmp(header_.magic, "BSA\0", 4) != 0) {
        logger::debug("BSAMmap: Not a BSA (bad magic): {}", path_.string());
        return false;
    }

    if (header_.version != 104 && header_.version != 105) {
        logger::info("BSAMmap: Unsupported BSA version {}: {}", header_.version, path_.string());
        return false;
    }

    defaultCompressed_ = (header_.archiveFlags & ArchiveFlag::kDefaultCompressed) != 0;

    return true;
}

// ── MemoryMapManager ───────────────────────────────────────────────────────

MemoryMapManager& MemoryMapManager::GetSingleton()
{
    static MemoryMapManager instance;
    return instance;
}

bool MemoryMapManager::Initialize(const std::filesystem::path& dataPath)
{
    logger::info("BSAMmap: Scanning for BSA archives in {}", dataPath.string());

    if (!std::filesystem::exists(dataPath)) {
        logger::error("BSAMmap: Data path does not exist: {}", dataPath.string());
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
        if (ext != ".bsa")
            continue;

        ++scanned;

        MappedArchive archive;
        if (!archive.Open(dirEntry.path()))
            continue;

        auto filename = dirEntry.path().filename().string();
        std::string lowerName = filename;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
            [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });

        logger::info("BSAMmap: Mapped {:>45s}  {:>5} entries  {:>7.1f} MB  {}",
            filename,
            archive.GetEntryCount(),
            archive.GetFileSize() / (1024.0 * 1024.0),
            archive.IsDefaultCompressed() ? "[default compressed]" : "[uncompressed]");

        uint32_t idx = static_cast<uint32_t>(archives_.size());
        nameIndex_[lowerName] = idx;
        archives_.push_back(std::move(archive));
        ++mapped;
    }

    logger::info("BSAMmap: Scan complete — {} BSAs scanned, {} memory-mapped ({:.1f} MB total)",
        scanned, mapped, GetTotalMappedBytes() / (1024.0 * 1024.0));

    return mapped > 0;
}

void MemoryMapManager::Shutdown()
{
    nameIndex_.clear();
    archives_.clear();
    logger::info("BSAMmap: All memory maps released");
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

}  // namespace BSA
