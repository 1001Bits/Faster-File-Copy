#include "PCH.h"
#include "BSAMemoryMap.h"
#include "CompressedEntryLayout.h"
#include "Settings.h"

#include <array>
#include <limits>

namespace BSA
{
namespace
{
    [[nodiscard]] bool TryCopyMappedBytes(
        void* a_destination, const void* a_source, std::size_t a_size) noexcept
    {
#if defined(_MSC_VER)
        __try {
            std::memcpy(a_destination, a_source, a_size);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
#else
        std::memcpy(a_destination, a_source, a_size);
        return true;
#endif
    }

    std::string PathForLog(const std::filesystem::path& a_path) noexcept
    {
        try {
            const auto utf8 = a_path.u8string();
            return { reinterpret_cast<const char*>(utf8.data()), utf8.size() };
        } catch (...) {
            return "<unprintable path>";
        }
    }

    std::string LowerASCII(std::string a_value)
    {
        std::transform(a_value.begin(), a_value.end(), a_value.begin(),
            [](const unsigned char a_char) {
                return static_cast<char>(std::tolower(a_char));
            });
        return a_value;
    }
}

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
    , fingerprint_(o.fingerprint_)
    , header_(o.header_)
    , defaultCompressed_(o.defaultCompressed_)
    , valid_(o.valid_)
    , declaredSizes_(std::move(o.declaredSizes_))
{
    o.fileHandle_ = nullptr;
    o.mapHandle_  = nullptr;
    o.base_       = nullptr;
    o.fileSize_   = 0;
    o.fingerprint_ = 0;
    o.valid_      = false;
    o.declaredSizes_.clear();
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
        fingerprint_       = o.fingerprint_;
        header_            = o.header_;
        defaultCompressed_ = o.defaultCompressed_;
        valid_             = o.valid_;
        declaredSizes_     = std::move(o.declaredSizes_);
        o.fileHandle_ = nullptr;
        o.mapHandle_  = nullptr;
        o.base_       = nullptr;
        o.fileSize_   = 0;
        o.fingerprint_ = 0;
        o.valid_      = false;
        o.declaredSizes_.clear();
    }
    return *this;
}

bool MappedArchive::Open(const std::filesystem::path& archivePath, bool a_mapFull)
{
    Close();
    path_ = archivePath;

    HANDLE fh = CreateFileW(
        path_.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
        nullptr);

    if (fh == INVALID_HANDLE_VALUE) {
        logger::warn("BSAMmap: Cannot open {} (Win32 error {})",
            PathForLog(path_), GetLastError());
        return false;
    }
    fileHandle_ = fh;

    LARGE_INTEGER li{};
    if (!GetFileSizeEx(fh, &li) ||
        li.QuadPart < static_cast<LONGLONG>(sizeof(Header)) ||
        li.QuadPart > (std::numeric_limits<std::uint32_t>::max)()) {
        logger::warn("BSAMmap: Archive size is invalid for 32-bit BSA offsets: {}",
            PathForLog(path_));
        Close();
        return false;
    }
    fileSize_ = static_cast<uint64_t>(li.QuadPart);

    if (a_mapFull) {
        HANDLE mh = CreateFileMappingW(fh, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!mh) {
            logger::warn("BSAMmap: CreateFileMapping failed ({}): {}",
                GetLastError(), PathForLog(path_));
            Close();
            return false;
        }
        mapHandle_ = mh;

        // Whole-file view — needed by the mmap read path.
        auto* view = static_cast<const uint8_t*>(MapViewOfFile(mh, FILE_MAP_READ, 0, 0, 0));
        if (!view) {
            logger::warn("BSAMmap: MapViewOfFile failed ({}): {}",
                GetLastError(), PathForLog(path_));
            Close();
            return false;
        }
        base_ = view;
        if (!ParseHeader(base_) || !ComputeFingerprint()) {
            Close();
            return false;
        }
    } else {
        // Header-only mode does not need a section object or a virtual-address
        // reservation. Keep the read-only handle so compressed-entry metadata
        // can be read from the exact archive generation that was fingerprinted.
        Header header{};
        DWORD bytesRead = 0;
        if (!ReadFile(fh, &header, sizeof(header), &bytesRead, nullptr) ||
            bytesRead != sizeof(header)) {
            logger::warn("BSAMmap: Header read failed ({}): {}",
                GetLastError(), PathForLog(path_));
            Close();
            return false;
        }
        if (!ParseHeader(reinterpret_cast<const std::uint8_t*>(&header)) ||
            !ComputeFingerprint()) {
            Close();
            return false;
        }
    }

    valid_ = true;
    return true;
}

bool MappedArchive::ReadAt(
    std::uint64_t offset, void* destination, std::size_t size) const noexcept
{
    if (!valid_ || (size > 0 && !destination) ||
        size > fileSize_ || offset > fileSize_ - size) {
        return false;
    }
    if (size == 0) {
        return true;
    }
    if (base_) {
        return TryCopyMappedBytes(destination, base_ + offset, size);
    }
    if (!fileHandle_ || fileHandle_ == INVALID_HANDLE_VALUE ||
        size > (std::numeric_limits<DWORD>::max)()) {
        return false;
    }

    try {
        std::lock_guard lock(readMtx_);
        LARGE_INTEGER position{};
        position.QuadPart = static_cast<LONGLONG>(offset);
        if (!SetFilePointerEx(
                static_cast<HANDLE>(fileHandle_), position, nullptr, FILE_BEGIN)) {
            return false;
        }
        DWORD bytesRead = 0;
        return ReadFile(static_cast<HANDLE>(fileHandle_), destination,
                   static_cast<DWORD>(size), &bytesRead, nullptr) &&
               bytesRead == static_cast<DWORD>(size);
    } catch (...) {
        return false;
    }
}

std::optional<std::uint32_t> MappedArchive::GetDeclaredDecompressedSize(
    const std::uint32_t startOffset) const noexcept
{
    try {
        {
            std::shared_lock cacheLock(declaredSizeMtx_);
            if (const auto found = declaredSizes_.find(startOffset);
                found != declaredSizes_.end()) {
                return found->second != 0
                    ? std::optional<std::uint32_t>{ found->second }
                    : std::nullopt;
            }
        }

        std::uint8_t embeddedNameLength = 0;
        if (HasEmbeddedFileNames() &&
            !ReadAt(startOffset, &embeddedNameLength,
                sizeof(embeddedNameLength))) {
            std::unique_lock cacheLock(declaredSizeMtx_);
            declaredSizes_.try_emplace(startOffset, 0);
            return std::nullopt;
        }
        const auto sizeOffset = CompressedEntryLayout::SizeFieldOffset(
            startOffset, fileSize_, HasEmbeddedFileNames(), embeddedNameLength);

        std::uint32_t resolved = 0;
        if (sizeOffset) {
            std::array<std::uint8_t, sizeof(std::uint32_t)> sizeBytes{};
            if (ReadAt(*sizeOffset, sizeBytes.data(), sizeBytes.size())) {
                const auto candidate =
                    CompressedEntryLayout::DecodeLittleEndianSize(sizeBytes);
                if (CompressedEntryLayout::IsUsableDeclaredSize(candidate)) {
                    resolved = candidate;
                }
            }
        }

        std::unique_lock cacheLock(declaredSizeMtx_);
        const auto [found, inserted] =
            declaredSizes_.try_emplace(startOffset, resolved);
        (void)inserted;
        return found->second != 0
            ? std::optional<std::uint32_t>{ found->second }
            : std::nullopt;
    } catch (...) {
        // Metadata caching is an optimization. Allocation/locking failures must
        // leave the native decompressor as the only eligible path.
        return std::nullopt;
    }
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
    fingerprint_ = 0;
    header_     = {};
    defaultCompressed_ = false;
    valid_      = false;
    declaredSizes_.clear();
}

bool MappedArchive::ParseHeader(const uint8_t* a_hdr)
{
    std::memcpy(&header_, a_hdr, sizeof(Header));

    if (std::memcmp(header_.magic, "BSA\0", 4) != 0) {
        logger::debug("BSAMmap: Not a BSA (bad magic): {}", PathForLog(path_));
        return false;
    }

    if (header_.version != 104 && header_.version != 105) {
        logger::info("BSAMmap: Unsupported BSA version {}: {}",
            header_.version, PathForLog(path_));
        return false;
    }

    if (header_.folderOffset < sizeof(Header) || header_.folderOffset > fileSize_) {
        logger::warn("BSAMmap: Invalid folder-record offset in {}", PathForLog(path_));
        return false;
    }

    const auto nameBytes = static_cast<std::uint64_t>(header_.totalFolderNameLength) +
        static_cast<std::uint64_t>(header_.totalFileNameLength);
    constexpr std::uint32_t kMaxFiles = 1'000'000;
    constexpr std::uint32_t kMaxFolders = 250'000;
    if (nameBytes > fileSize_ ||
        header_.fileCount > kMaxFiles ||
        header_.folderCount > kMaxFolders ||
        header_.fileCount > fileSize_ / sizeof(std::uint32_t)) {
        logger::warn("BSAMmap: Implausible BSA header counts in {}", PathForLog(path_));
        return false;
    }

    defaultCompressed_ = (header_.archiveFlags & ArchiveFlag::kDefaultCompressed) != 0;

    return true;
}

bool MappedArchive::ComputeFingerprint()
{
    constexpr std::uint64_t kFnvOffset = 14695981039346656037ull;
    constexpr std::uint64_t kFnvPrime = 1099511628211ull;
    constexpr std::uint64_t kSampleSize = 4096;

    if (fileSize_ == 0)
        return false;

    std::uint64_t hash = kFnvOffset;
    const auto mix = [&hash](const void* a_data, const std::size_t a_size) noexcept {
        const auto* bytes = static_cast<const std::uint8_t*>(a_data);
        for (std::size_t i = 0; i < a_size; ++i) {
            hash ^= bytes[i];
            hash *= kFnvPrime;
        }
    };
    mix(&fileSize_, sizeof(fileSize_));

    // File identity catches the common mod-manager/update case where a BSA is
    // replaced by another same-sized file whose timestamp was preserved. It is
    // cheap to obtain from the already-open handle and complements the bounded
    // content samples below without forcing a full archive scan at startup.
    BY_HANDLE_FILE_INFORMATION fileInfo{};
    if (fileHandle_ && fileHandle_ != INVALID_HANDLE_VALUE &&
        GetFileInformationByHandle(static_cast<HANDLE>(fileHandle_), &fileInfo)) {
        mix(&fileInfo.dwVolumeSerialNumber, sizeof(fileInfo.dwVolumeSerialNumber));
        mix(&fileInfo.nFileIndexHigh, sizeof(fileInfo.nFileIndexHigh));
        mix(&fileInfo.nFileIndexLow, sizeof(fileInfo.nFileIndexLow));
    }

    const auto sampleBytes = (std::min)(fileSize_, kSampleSize);
    const auto middle = fileSize_ > sampleBytes ?
        (std::min)(fileSize_ - sampleBytes, fileSize_ / 2) : 0;
    const std::array<std::uint64_t, 3> offsets{
        0,
        middle,
        fileSize_ - sampleBytes
    };
    std::array<std::uint8_t, kSampleSize> buffer{};

    std::uint64_t previous = (std::numeric_limits<std::uint64_t>::max)();
    for (const auto offset : offsets) {
        if (offset == previous)
            continue;
        previous = offset;
        mix(&offset, sizeof(offset));

        if (base_) {
            mix(base_ + offset, static_cast<std::size_t>(sampleBytes));
            continue;
        }

        if (!fileHandle_ || fileHandle_ == INVALID_HANDLE_VALUE)
            return false;
        LARGE_INTEGER position{};
        position.QuadPart = static_cast<LONGLONG>(offset);
        if (!SetFilePointerEx(static_cast<HANDLE>(fileHandle_), position, nullptr, FILE_BEGIN)) {
            logger::warn("BSAMmap: Fingerprint seek failed ({}): {}",
                GetLastError(), PathForLog(path_));
            return false;
        }
        DWORD bytesRead = 0;
        if (!ReadFile(
                static_cast<HANDLE>(fileHandle_),
                buffer.data(),
                static_cast<DWORD>(sampleBytes),
                &bytesRead,
                nullptr) || bytesRead != sampleBytes) {
            logger::warn("BSAMmap: Fingerprint read failed ({}): {}",
                GetLastError(), PathForLog(path_));
            return false;
        }
        mix(buffer.data(), bytesRead);
    }

    fingerprint_ = hash != 0 ? hash : 1;
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
    std::lock_guard lock(managerMtx_);

    std::error_code ec;
    auto normalizedPath = std::filesystem::absolute(dataPath, ec);
    if (ec) {
        logger::error("BSAMmap: Cannot resolve Data path {}: {}",
            PathForLog(dataPath), ec.message());
        return false;
    }
    normalizedPath = normalizedPath.lexically_normal();

    // Baseline mode intentionally avoids reserving whole BSA views. The
    // verified ArchiveStream vtable path remains available independently of
    // the legacy compatibility setting.
    const bool mapFull = Settings::bEnableMmap &&
        !Settings::bBaselineMode && !Settings::bWine;

    if (!archives_.empty()) {
        if (initializedPath_ == normalizedPath && initializedMapFull_ == mapFull) {
            logger::debug("BSAMmap: Archive manager already initialized");
            return true;
        }
        logger::error("BSAMmap: Refusing to reinitialize live archive mappings");
        return false;
    }

    logger::info("BSAMmap: Scanning for BSA archives in {}", PathForLog(normalizedPath));
    if (!std::filesystem::is_directory(normalizedPath, ec) || ec) {
        logger::error("BSAMmap: Data path is not an accessible directory: {}",
            PathForLog(normalizedPath));
        return false;
    }

    std::vector<std::filesystem::path> paths;
    std::filesystem::directory_iterator iter(
        normalizedPath,
        std::filesystem::directory_options::skip_permission_denied,
        ec);
    const std::filesystem::directory_iterator end;
    while (!ec && iter != end) {
        std::error_code entryEc;
        if (iter->is_regular_file(entryEc) && !entryEc) {
            auto ext = LowerASCII(PathForLog(iter->path().extension()));
            if (ext == ".bsa")
                paths.push_back(iter->path());
        }
        iter.increment(ec);
    }
    if (ec)
        logger::warn("BSAMmap: Archive scan ended early: {}", ec.message());

    std::sort(paths.begin(), paths.end(), [](const auto& a_lhs, const auto& a_rhs) {
        return LowerASCII(PathForLog(a_lhs.filename())) <
            LowerASCII(PathForLog(a_rhs.filename()));
    });

    std::uint32_t loaded = 0;
    std::uint32_t mapped = 0;
    for (const auto& path : paths) {
        MappedArchive archive;
        if (!archive.Open(path, mapFull))
            continue;

        const auto filename = PathForLog(path.filename());
        const auto lowerName = LowerASCII(filename);
        if (nameIndex_.contains(lowerName)) {
            logger::warn("BSAMmap: Ignoring duplicate archive filename {}", filename);
            continue;
        }

        logger::debug("BSAMmap: Loaded {:>45s}  {:>5} entries  {:>7.1f} MB  {}{}",
            filename,
            archive.GetEntryCount(),
            archive.GetFileSize() / (1024.0 * 1024.0),
            archive.IsDefaultCompressed() ? "[default compressed]" : "[uncompressed]",
            archive.IsMapped() ? " [mapped]" : " [header only]");

        const auto idx = static_cast<std::uint32_t>(archives_.size());
        nameIndex_.emplace(lowerName, idx);
        if (archive.IsMapped())
            ++mapped;
        archives_.push_back(std::move(archive));
        ++loaded;
    }

    if (loaded > 0) {
        initializedPath_ = std::move(normalizedPath);
        initializedMapFull_ = mapFull;
    }

    std::uint64_t mappedBytes = 0;
    for (const auto& archive : archives_) {
        if (archive.IsMapped())
            mappedBytes += archive.GetFileSize();
    }
    logger::info("BSAMmap: Scan complete — {} BSAs discovered, {} loaded, {} mapped ({:.1f} MB)",
        paths.size(), loaded, mapped, mappedBytes / (1024.0 * 1024.0));
    return loaded > 0;
}

void MemoryMapManager::Shutdown()
{
    std::lock_guard lock(managerMtx_);
    if (archives_.empty())
        return;
    nameIndex_.clear();
    archives_.clear();
    initializedPath_.clear();
    initializedMapFull_ = false;
    logger::info("BSAMmap: All memory maps released");
}

const MappedArchive* MemoryMapManager::FindByName(std::string_view filename) const
{
    const auto lower = LowerASCII(std::string(filename));

    auto it = nameIndex_.find(lower);
    return (it != nameIndex_.end() && it->second < archives_.size())
        ? &archives_[it->second]
        : nullptr;
}

uint64_t MemoryMapManager::GetTotalMappedBytes() const
{
    uint64_t total = 0;
    for (const auto& a : archives_)
        if (a.IsMapped())            // header-only archives reserve no address space
            total += a.GetFileSize();
    return total;
}

}  // namespace BSA
