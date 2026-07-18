#pragma once
// BSA Memory Map — BSA file format parser and memory-mapping manager
//
// Scans the game's Data directory for BSA archives. Whole-file, read-only
// mappings are created only when direct uncompressed reads are enabled;
// otherwise bounded header/fingerprint reads support the decompression cache.
//
// The hook layer (Hooks.cpp) uses this to serve archive reads directly from
// the page cache, eliminating ReadFile syscalls for both compressed and
// uncompressed entries (hybrid mmap + decompression mode).

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace BSA
{

// ── BSA file format structures (v104/v105) ─────────────────────────────────
// Reference: https://en.uesp.net/wiki/Skyrim_Mod:Archive_File_Format

#pragma pack(push, 1)

struct Header
{
    char     magic[4];              // "BSA\0"
    uint32_t version;               // 104 (Oblivion/FO3/FNV/Skyrim LE) or 105 (Skyrim SE/AE)
    uint32_t folderOffset;          // offset to folder records (typically 36)
    uint32_t archiveFlags;          // see ArchiveFlag enum
    uint32_t folderCount;
    uint32_t fileCount;
    uint32_t totalFolderNameLength;
    uint32_t totalFileNameLength;
    uint32_t fileFlags;
};
static_assert(sizeof(Header) == 36);

enum ArchiveFlag : uint32_t
{
    kIncludeDirectoryNames = 1 << 0,
    kIncludeFileNames      = 1 << 1,
    kDefaultCompressed     = 1 << 2,   // if set, entries are compressed by default
    kRetainDirectoryNames  = 1 << 3,
    kRetainFileNames       = 1 << 4,
    kRetainFileNameOffsets = 1 << 5,
    kXbox360Archive        = 1 << 6,
    kRetainStringsDuringStartup = 1 << 7,
    kEmbedFileNames        = 1 << 8,   // v105: file names embedded in data block
    kXMemCodec             = 1 << 9,
};

#pragma pack(pop)

// ── Mapped archive ─────────────────────────────────────────────────────────
// Represents a single BSA file that has been memory-mapped into our address
// space when requested. The mapping is read-only and remains for the lifetime
// of the object; it reserves address space but pages enter RAM only on demand.

class MappedArchive
{
public:
    MappedArchive() = default;
    ~MappedArchive();

    MappedArchive(const MappedArchive&) = delete;
    MappedArchive& operator=(const MappedArchive&) = delete;
    MappedArchive(MappedArchive&& other) noexcept;
    MappedArchive& operator=(MappedArchive&& other) noexcept;

    // Open and parse the BSA header. When a_mapFull is true the entire file is
    // memory-mapped (needed only by the uncompressed mmap read path). When
    // false, only the header and bounded fingerprint samples are read and no
    // whole-file view is kept. A read-only file handle remains available for
    // small metadata reads. Wine/Proton and baseline mode use this form.
    bool Open(const std::filesystem::path& archivePath, bool a_mapFull = true);
    void Close();

    // Valid = header parsed OK. Decoupled from base_ so header-only archives
    // (no whole-file view) still count as open for the decomp cache.
    bool IsOpen() const { return valid_; }
    bool IsMapped() const { return base_ != nullptr; }
    bool IsDefaultCompressed() const { return defaultCompressed_; }
    bool HasEmbeddedFileNames() const
    {
        return (header_.archiveFlags & ArchiveFlag::kEmbedFileNames) != 0;
    }

    const std::filesystem::path& GetPath() const { return path_; }
    const uint8_t* GetBase() const { return base_; }
    uint64_t       GetFileSize() const { return fileSize_; }
    uint32_t       GetEntryCount() const { return header_.fileCount; }
    std::uint64_t  GetFingerprint() const { return fingerprint_; }

    // Return a pointer into mapped memory at the given byte offset.
    // Returns nullptr if offset + size would exceed the file.
    const uint8_t* At(uint64_t offset, uint64_t size = 0) const
    {
        if (!base_) return nullptr;  // header-only archive — not mapped for reads
        if (size > fileSize_ || offset > fileSize_ - size) return nullptr;
        return base_ + offset;
    }

    // Copy a bounded byte range from the archive. Whole-file mappings use a
    // direct memory copy; header-only mode uses the archive's retained handle.
    // Unlike At(), this therefore works when mmap delivery is disabled.
    [[nodiscard]] bool ReadAt(
        std::uint64_t offset, void* destination, std::size_t size) const noexcept;

    // Resolve the authoritative little-endian decompressed-size prefix stored
    // in this BSA data block. Embedded-name archives place a one-byte length
    // and that many name bytes before the prefix. Results (including invalid
    // blocks) are memoized for this immutable, fingerprinted archive
    // generation so repeated cache hits never fault the original BSA again.
    [[nodiscard]] std::optional<std::uint32_t> GetDeclaredDecompressedSize(
        std::uint32_t startOffset) const noexcept;

private:
    bool ParseHeader(const uint8_t* a_hdr);
    bool ComputeFingerprint();

    std::filesystem::path path_;
    void*          fileHandle_ = nullptr;   // HANDLE
    void*          mapHandle_  = nullptr;   // HANDLE
    const uint8_t* base_       = nullptr;   // whole-file view (null = header-only)
    uint64_t       fileSize_   = 0;
    std::uint64_t  fingerprint_ = 0;

    Header   header_{};
    bool     defaultCompressed_ = false;
    bool     valid_             = false;    // header parsed OK
    mutable std::mutex readMtx_;
    // A zero value is a memoized failure; valid BSA declarations are nonzero.
    mutable std::shared_mutex declaredSizeMtx_;
    mutable std::unordered_map<std::uint32_t, std::uint32_t> declaredSizes_;
};

// ── Memory-map manager (singleton) ─────────────────────────────────────────
// Scans a directory for .bsa files and provides fast name-based lookup.

class MemoryMapManager
{
public:
    static MemoryMapManager& GetSingleton();

    // Scan dataPath for .bsa files; map payloads only when enabled.
    bool Initialize(const std::filesystem::path& dataPath);
    void Shutdown();

    // Lookup by lowercase archive filename (e.g. "skyrim - meshes0.bsa").
    const MappedArchive* FindByName(std::string_view filename) const;

    uint32_t GetArchiveCount() const { return static_cast<uint32_t>(archives_.size()); }
    uint64_t GetTotalMappedBytes() const;

    const std::vector<MappedArchive>& GetArchives() const { return archives_; }

private:
    MemoryMapManager() = default;

    mutable std::mutex managerMtx_;
    std::vector<MappedArchive> archives_;
    std::unordered_map<std::string, uint32_t> nameIndex_;
    std::filesystem::path initializedPath_;
    bool initializedMapFull_{ false };
};

}  // namespace BSA
