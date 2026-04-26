#pragma once
// BA2 Memory Map — BA2 file format parser and memory-mapping manager
//
// Scans the game's Data directory for uncompressed BA2 archives, memory-maps
// them via CreateFileMapping/MapViewOfFile, and provides O(1) access to any
// byte range within the mapped files.  The hook layer (Hooks.cpp) uses this
// to serve archive reads directly from the page cache, eliminating ReadFile
// syscalls and the kernel-to-user copy.

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace BA2
{
// ── BA2 file format structures ──────────────────────────────────────────────
// Reference: https://wiki.nexusmods.com/index.php/BA2_File_Format

#pragma pack(push, 1)

struct Header
{
    char     magic[4];           // "BTDX"
    uint32_t version;            // 1 for Fallout 4
    char     type[4];            // "GNRL" or "DX10"
    uint32_t fileCount;
    uint64_t nameTableOffset;    // absolute offset of the name table
};
static_assert(sizeof(Header) == 24);

struct GeneralFileRecord
{
    uint32_t nameHash;
    char     extension[4];
    uint32_t dirHash;
    uint32_t flags;
    uint64_t offset;             // absolute offset of data in the BA2
    uint32_t packedSize;         // 0 = stored uncompressed
    uint32_t unpackedSize;
    uint32_t bnam;               // 0xBAADF00D sentinel
};
static_assert(sizeof(GeneralFileRecord) == 36);

struct DX10Header
{
    uint32_t nameHash;
    char     extension[4];
    uint32_t dirHash;
    uint8_t  unknownFlag;
    uint8_t  numChunks;
    uint16_t chunkHeaderSize;    // typically 24
    uint16_t height;
    uint16_t width;
    uint8_t  numMips;
    uint8_t  format;             // DXGI_FORMAT
    uint16_t isCubeMap;          // 0x0800 if cube map
};
static_assert(sizeof(DX10Header) == 24);

struct DX10Chunk
{
    uint64_t offset;
    uint32_t packedSize;         // 0 = stored uncompressed
    uint32_t unpackedSize;
    uint16_t startMip;
    uint16_t endMip;
    uint32_t bnam;               // 0xBAADF00D
};
static_assert(sizeof(DX10Chunk) == 24);

#pragma pack(pop)

// A compressed entry within a BA2 archive
struct BA2Entry
{
    uint32_t     startOffset;    // absolute offset in the BA2 file
    uint32_t     packedSize;     // compressed size (zlib)
    uint32_t     unpackedSize;   // decompressed size
    bool         isCompressed;   // true if packedSize != 0
};

// ── Mapped archive ──────────────────────────────────────────────────────────
// Represents a single BA2 file that has been memory-mapped into our address
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

    // Open, memory-map, and parse the BA2 header.
    bool Open(const std::filesystem::path& archivePath);
    void Close();

    bool     IsOpen() const                   { return base_ != nullptr; }
    bool     HasUncompressedEntries() const   { return uncompressedCount_ > 0; }
    bool     IsFullyUncompressed() const      { return fullyUncompressed_; }
    bool     IsGNRL() const                   { return type_ == Type::GNRL; }
    bool     IsDX10() const                   { return type_ == Type::DX10; }

    const std::filesystem::path& GetPath() const  { return path_; }
    const uint8_t* GetBase() const                 { return base_; }
    uint64_t       GetFileSize() const             { return fileSize_; }
    uint32_t       GetEntryCount() const           { return header_.fileCount; }
    uint32_t       GetUncompressedCount() const    { return uncompressedCount_; }

    // Return a pointer into mapped memory at the given byte offset.
    // Returns nullptr if offset + size would exceed the file.
    const uint8_t* At(uint64_t offset, uint64_t size = 0) const
    {
        if (offset + size > fileSize_) return nullptr;
        return base_ + offset;
    }

    // Enumerate all entries in this archive.
    // Populates the given vector with BA2Entry structs for each entry.
    void EnumerateEntries(std::vector<BA2Entry>& outEntries) const;

private:
    enum class Type { Unknown, GNRL, DX10 };

    bool ParseHeader();

    std::filesystem::path path_;
    void*          fileHandle_ = nullptr;   // HANDLE (avoid including Windows.h here)
    void*          mapHandle_  = nullptr;   // HANDLE
    const uint8_t* base_       = nullptr;
    uint64_t       fileSize_   = 0;

    Header   header_{};
    Type     type_              = Type::Unknown;
    bool     fullyUncompressed_ = false;
    uint32_t uncompressedCount_ = 0;
};

// ── Memory-map manager (singleton) ──────────────────────────────────────────
// Scans a directory for .ba2 files, memory-maps those with uncompressed
// entries, and provides fast name-based lookup.

class MemoryMapManager
{
public:
    static MemoryMapManager& GetSingleton();

    // Scan dataPath for .ba2 files and memory-map the qualifying ones.
    bool Initialize(const std::filesystem::path& dataPath);
    void Shutdown();

    // Lookup by lowercase archive filename (e.g. "fallout4 - meshes.ba2").
    const MappedArchive* FindByName(std::string_view filename) const;

    uint32_t GetArchiveCount() const { return static_cast<uint32_t>(archives_.size()); }
    uint64_t GetTotalMappedBytes() const;

    const std::vector<MappedArchive>& GetArchives() const { return archives_; }

private:
    MemoryMapManager() = default;

    std::vector<MappedArchive> archives_;
    // lowercase filename -> index into archives_
    std::unordered_map<std::string, uint32_t> nameIndex_;
};

}  // namespace BA2
