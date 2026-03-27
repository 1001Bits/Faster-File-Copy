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

namespace BSA
{

class MmapStream final : public RE::BSResource::Stream
{
public:
    // Construct a read-only stream over [data, data + size) in a mapped archive.
    MmapStream(
        const std::uint8_t*       a_data,
        std::uint32_t             a_size,
        RE::BSFixedString         a_name,
        const BSA::MappedArchive* a_archive);

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

    // ── Zero-copy extension ──────────────────────────────────────────────

    [[nodiscard]] const std::uint8_t* GetDirectPointer() const { return data_ + cursor_; }
    [[nodiscard]] const std::uint8_t* GetBasePointer() const { return data_; }
    [[nodiscard]] std::uint32_t GetEntrySize() const { return size_; }
    [[nodiscard]] const BSA::MappedArchive* GetArchive() const { return archive_; }

    // Check whether a BSResource::Stream* is actually an MmapStream.
    static bool IsMmapStream(const RE::BSResource::Stream* a_stream);
    static const MmapStream* As(const RE::BSResource::Stream* a_stream);

private:
    const std::uint8_t*       data_;
    std::uint32_t             size_;
    mutable std::uint32_t     cursor_;   // mutable: DoRead/DoSeek are const
    RE::BSFixedString         name_;
    const BSA::MappedArchive* archive_;
};

}  // namespace BSA
