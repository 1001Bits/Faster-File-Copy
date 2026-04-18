#pragma once
// BSA Memory Map — BSA file format parser and memory-mapping manager
//
// Scans the game's Data directory for BSA archives, memory-maps ALL of them
// (not just uncompressed — Skyrim BSAs are mostly compressed), and provides
// O(1) access to any byte range within the mapped files.
//
// The hook layer (Hooks.cpp) uses this to serve archive reads directly from
// the page cache, eliminating ReadFile syscalls for both compressed and
// uncompressed entries (hybrid mmap + decompression mode).

#include <cstdint>
#include <filesystem>
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
// space.  The mapping is read-only and remains for the lifetime of the object.

class MappedArchive
{
public:
    MappedArchive() = default;
    ~MappedArchive();

    MappedArchive(const MappedArchive&) = delete;
    MappedArchive& operator=(const MappedArchive&) = delete;
    MappedArchive(MappedArchive&& other) noexcept;
    MappedArchive& operator=(MappedArchive&& other) noexcept;

    // Open, memory-map, and parse the BSA header.
    bool Open(const std::filesystem::path& archivePath);
    void Close();

    bool IsOpen() const { return base_ != nullptr; }
    bool IsDefaultCompressed() const { return defaultCompressed_; }

    const std::filesystem::path& GetPath() const { return path_; }
    const uint8_t* GetBase() const { return base_; }
    uint64_t       GetFileSize() const { return fileSize_; }
    uint32_t       GetEntryCount() const { return header_.fileCount; }

    // Touch every page to prefault into OS page cache (call from background thread)
    void Prefault() const
    {
        if (!base_ || fileSize_ == 0) return;
        volatile std::uint8_t dummy = 0;
        for (std::uint64_t off = 0; off < fileSize_; off += 4096)
            dummy += base_[off];
        (void)dummy;
    }

    // Return a pointer into mapped memory at the given byte offset.
    // Returns nullptr if offset + size would exceed the file.
    const uint8_t* At(uint64_t offset, uint64_t size = 0) const
    {
        if (size > fileSize_ || offset > fileSize_ - size) return nullptr;
        return base_ + offset;
    }

private:
    bool ParseHeader();

    std::filesystem::path path_;
    void*          fileHandle_ = nullptr;   // HANDLE
    void*          mapHandle_  = nullptr;   // HANDLE
    const uint8_t* base_       = nullptr;
    uint64_t       fileSize_   = 0;

    Header   header_{};
    bool     defaultCompressed_ = false;
};

// ── Memory-map manager (singleton) ─────────────────────────────────────────
// Scans a directory for .bsa files, memory-maps ALL of them, and provides
// fast name-based lookup.

class MemoryMapManager
{
public:
    static MemoryMapManager& GetSingleton();

    // Scan dataPath for .bsa files and memory-map them.
    bool Initialize(const std::filesystem::path& dataPath);
    void Shutdown();

    // Lookup by lowercase archive filename (e.g. "skyrim - meshes0.bsa").
    const MappedArchive* FindByName(std::string_view filename) const;

    uint32_t GetArchiveCount() const { return static_cast<uint32_t>(archives_.size()); }
    uint64_t GetTotalMappedBytes() const;

    const std::vector<MappedArchive>& GetArchives() const { return archives_; }

private:
    MemoryMapManager() = default;

    std::vector<MappedArchive> archives_;
    std::unordered_map<std::string, uint32_t> nameIndex_;
};

}  // namespace BSA
