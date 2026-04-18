#pragma once
// BSA Memory Map — MmapStream
//
// A concrete BSResource::Stream backed entirely by memory-mapped file data.
// Skyrim's Stream has 12 virtual methods (indices 0x00-0x0B), unlike FO4's 20.
//
// Injected via a GlobalLocations::DoCreateStream post-hook so that the
// game's resource pipeline works with mapped memory from the start —
// no ReadFile syscalls, no kernel copies.

#include "BSAMemoryMap.h"
#include "DecompCache.h"

namespace BSA
{

class MmapStream final : public RE::BSResource::Stream
{
public:
    // Construct a read-only stream over [data, data + size) in a mapped archive.
    // a_viewOwner pins a decomp-cache MappedView for the stream's lifetime so a
    // background cache rewrite can't unmap the data we're reading. Pass an empty
    // shared_ptr for streams backed by a permanently-mapped BSA (no rewrite risk).
    MmapStream(
        const std::uint8_t*           a_data,
        std::uint32_t                 a_size,
        RE::BSFixedString             a_name,
        const BSA::MappedArchive*     a_archive,
        void*                         a_source     = nullptr,
        std::uint32_t                 a_startOffset = 0,
        std::uint32_t                 a_cursor      = 0,
        std::shared_ptr<BSA::MappedView> a_viewOwner = {});

    ~MmapStream() override = default;

    // ── StreamBase overrides (0x00-0x04) ─────────────────────────────────
    RE::BSResource::ErrorCode DoOpen() override;                            // 01
    void                      DoClose() override;                           // 02
    std::uint64_t             DoGetKey() const override;                    // 03
    RE::BSResource::ErrorCode DoGetInfo(RE::BSResource::Info& a_info) override; // 04

    // ── Stream overrides (0x05-0x0B) ─────────────────────────────────────
    void DoClone(RE::BSTSmartPointer<RE::BSResource::Stream>& a_result) const override;  // 05

    RE::BSResource::ErrorCode DoRead(
        void*          a_buffer,
        std::uint64_t  a_bytes,
        std::uint64_t& a_read) const override;                              // 06

    RE::BSResource::ErrorCode DoWrite(
        const void*    a_buffer,
        std::uint64_t  a_bytes,
        std::uint64_t& a_write) const override;                             // 07

    RE::BSResource::ErrorCode DoSeek(
        std::uint64_t              a_offset,      // uint64_t in Skyrim (not int64_t like FO4)
        RE::BSResource::SeekMode   a_seekMode,
        std::uint64_t&             a_pos) const override;                   // 08

    RE::BSResource::ErrorCode DoSetEndOfStream() override;                  // 09

    bool DoGetName(RE::BSFixedString& a_result) const override;             // 0A

    RE::BSResource::ErrorCode DoCreateAsync(
        RE::BSTSmartPointer<RE::BSResource::AsyncStream>& a_result) const override; // 0B

    // GetDataSize — vtable[12], called by engine to get the file's data size.
    // CompressedArchiveStream adds this as a new virtual; we must match.
    virtual std::uint32_t GetDataSize() const;                                      // 0C

    // ── Zero-copy extension ──────────────────────────────────────────────

    // Defined in MmapStream.cpp (needs BSResource::Field::CurrentOffset).
    [[nodiscard]] const std::uint8_t* GetDirectPointer() const;
    [[nodiscard]] const std::uint8_t* GetBasePointer() const { return data_; }
    [[nodiscard]] std::uint32_t GetEntrySize() const { return size_; }
    [[nodiscard]] const BSA::MappedArchive* GetArchive() const { return archive_; }

    // Check whether a BSResource::Stream* is actually an MmapStream.
    static bool IsMmapStream(const RE::BSResource::Stream* a_stream);
    static const MmapStream* As(const RE::BSResource::Stream* a_stream);

    // operator new — TES heap (same as StreamBase's TES_HEAP_REDEFINE_NEW).
    [[nodiscard]] static void* operator new(std::size_t a_count)
    {
        auto* mem = RE::malloc(a_count);
        if (!mem) RE::stl::report_and_fail("out of memory"sv);
        return mem;
    }
    [[nodiscard]] constexpr static void* operator new(std::size_t, void* a_ptr) noexcept { return a_ptr; }

    // operator delete — INTENTIONALLY LEAKS. See MmapStream.cpp for rationale.
    // Overrides StreamBase's TES_HEAP_REDEFINE_NEW delete so that engine
    // teardown of an MmapStream does not free the memory.
    static void operator delete(void* a_ptr) noexcept;
    static void operator delete(void* a_ptr, std::size_t) noexcept;

private:
    // ── ArchiveStream-compatible fields ──────────────────────────────
    // Engine code reads these offsets directly, not through vtable.
    // Layout differs between SE (0x10+) and AE (0x10+, with streamFlags gap).
    //
    // SE layout:  [0x10] source  [0x18] startOff [0x1C] curOff [0x20] name  → total 0x28
    // AE layout:  [0x10] flags   [0x18] source   [0x20] startOff [0x24] curOff [0x28] name → total 0x30
    // VR layout:  same as SE
    //
    // We allocate max size (AE) and use accessor methods for correct offsets.
    std::uint8_t archiveFields_[0x20]{ 0 };  // 0x10-0x2F, enough for AE layout

    // ── MmapStream data (0x30+) ──────────────────────────────────────
    // Position tracking: we use the archiveFields_ CurrentOffset slot
    // (at Field::CurrentOffset) as the canonical cursor. The engine reads
    // it directly, so maintaining a separate mirror would mean two writes
    // on every DoRead. startOffset_ is cached so DoRead can convert
    // absolute↔relative without re-reading archiveFields_.
    const std::uint8_t*       data_;
    std::uint32_t             size_;
    std::uint32_t             startOffset_;  // cached copy of Field::StartOffset
    const BSA::MappedArchive* archive_;
    RE::BSFixedString         nameStorage_;  // actual storage for name string
    std::shared_ptr<BSA::MappedView> viewOwner_;  // pins decomp-cache view; empty for BSA-backed streams

    void InitArchiveFields(void* a_source, std::uint32_t a_startOffset, const RE::BSFixedString& a_name);
};

}  // namespace BSA
