#pragma once
// BA2 Memory Map — MmapStream
//
// A concrete BSResource::Stream backed entirely by memory-mapped file data.
// Injected via a GlobalLocations::DoCreateStream post-hook so that the
// game's resource pipeline works with mapped memory from the start —
// no ReadFile syscalls, no kernel copies.
//
// The stream also exposes GetDirectPointer() for consumers that can bypass
// DoRead entirely and work with the raw mapped page directly (true zero-copy).

#include "BA2MemoryMap.h"

#include <atomic>
#include <memory>

namespace BA2 { struct MappedView; }

namespace BA2
{

// Histogram of MmapStream / OverrideDoRead call sizes + per-bucket cumulative ns.
// 11 buckets: 0B, 1-16, 17-64, 65-256, 257-1k, 1k-4k, 4k-16k, 16k-64k,
// 64k-256k, 256k-1M, >1M. Helps answer "what does our replacement DoRead
// actually cost?" and whether a small-read bypass would help.
constexpr int kMmapHistBuckets = 11;
extern std::atomic<std::uint64_t> g_mmapDoReadCalls[kMmapHistBuckets];
extern std::atomic<std::uint64_t> g_mmapDoReadNs[kMmapHistBuckets];

inline int MmapSizeBucket(std::uint64_t n)
{
    if (n == 0)         return 0;
    if (n <= 16)        return 1;
    if (n <= 64)        return 2;
    if (n <= 256)       return 3;
    if (n <= 1024)      return 4;
    if (n <= 4096)      return 5;
    if (n <= 16384)     return 6;
    if (n <= 65536)     return 7;
    if (n <= 262144)    return 8;
    if (n <= 1048576)   return 9;
    return 10;
}

class MmapStream final : public RE::BSResource::Stream
{
public:
    // Construct a read-only stream over [data, data + size) in a mapped archive.
    MmapStream(
        const std::uint8_t*      a_data,
        std::uint32_t            a_size,
        RE::BSFixedString        a_name,
        const BA2::MappedArchive* a_archive);

    // Cache-backed variant: data points into a DecompCache MappedView. The
    // shared_ptr keeps the view alive for the stream's lifetime so a concurrent
    // cache flush/rewrite cannot unmap it while the engine still holds the
    // stream. Used by the factory-level compressed-cache stream replacement
    // (HookedFactory + Settings::bFactoryReplaceCompressed).
    MmapStream(
        const std::uint8_t*                      a_data,
        std::uint32_t                            a_size,
        RE::BSFixedString                        a_name,
        const BA2::MappedArchive*                a_archive,
        std::shared_ptr<BA2::MappedView>         a_viewOwner);

    ~MmapStream() override = default;

    // ── StreamBase overrides ────────────────────────────────────────────
    RE::BSResource::ErrorCode DoOpen() override;                          // 01
    void                      DoClose() override;                         // 02
    std::uint64_t             DoGetKey() const override;                  // 03
    RE::BSResource::ErrorCode DoGetInfo(RE::BSResource::Info& a_info) override; // 04

    // ── Stream overrides ────────────────────────────────────────────────
    void DoClone(RE::BSTSmartPointer<RE::BSResource::Stream>& a_result) const override;  // 05

    RE::BSResource::ErrorCode DoRead(
        void*          a_buffer,
        std::uint64_t  a_bytes,
        std::uint64_t& a_read) const override;                           // 06

    RE::BSResource::ErrorCode DoReadAt(
        void*          a_buffer,
        std::uint64_t  a_bytes,
        std::uint64_t  a_pos,
        std::uint64_t& a_read) const override;                           // 07

    RE::BSResource::ErrorCode DoWrite(
        const void*    a_buffer,
        std::uint64_t  a_bytes,
        std::uint64_t& a_write) const override;                          // 08

    RE::BSResource::ErrorCode DoSeek(
        std::int64_t                a_offset,
        RE::BSResource::SeekMode    a_seekMode,
        std::uint64_t&              a_pos) const override;               // 09

    RE::BSResource::ErrorCode DoSetEndOfStream() override;               // 0A

    RE::BSResource::ErrorCode DoPrefetchAt(
        std::uint64_t  a_bytes,
        std::uint64_t  a_offset,
        std::uint32_t  a_priority) const override;                       // 0B

    RE::BSResource::ErrorCode DoStartTaggedPrioritizedRead(
        void*                     a_buffer,
        std::uint64_t             a_bytes,
        std::uint64_t             a_offset,
        std::uint32_t             a_priority,
        volatile std::uint32_t*   a_completionTag,
        std::uint32_t&            a_completionTagWaitValue,
        RE::BSEventFlag*          a_eventFlag) const override;           // 0C

    RE::BSResource::ErrorCode DoWaitTags(
        volatile std::uint32_t*   a_completionTag,
        std::uint32_t             a_completionTagWaitValue,
        RE::BSEventFlag*          a_eventFlag) const override;           // 0D

    RE::BSResource::ErrorCode DoPrefetchAll(
        std::uint32_t a_priority) const override;                        // 0E

    bool DoGetName(RE::BSFixedString& a_result) const override;          // 0F

    RE::BSResource::ErrorCode DoCreateAsync(
        RE::BSTSmartPointer<RE::BSResource::AsyncStream>& a_result) const override; // 10

    bool DoQTaggedPrioritizedReadSupported() const override;             // 11

    RE::BSResource::ErrorCode DoCreateOp(
        RE::BSTSmartPointer<RE::BSResource::ICacheDriveOp>& a_result,
        char const* a_arg2) const override;                              // 12

    bool DoGetIsFromArchive() const override;                            // 13

    // ── Zero-copy extension ─────────────────────────────────────────────

    // Direct pointer to the entry data at the current cursor position.
    // Valid as long as the MappedArchive is alive (entire game session).
    [[nodiscard]] const std::uint8_t* GetDirectPointer() const { return data_ + cursor_; }

    // Direct pointer to the base of this entry's data.
    [[nodiscard]] const std::uint8_t* GetBasePointer() const { return data_; }

    // Total entry size in bytes.
    [[nodiscard]] std::uint32_t GetEntrySize() const { return size_; }

    // The archive this stream reads from.
    [[nodiscard]] const BA2::MappedArchive* GetArchive() const { return archive_; }

    // Check whether a BSResource::Stream* is actually an MmapStream.
    // Compares the vtable pointer against our class's vtable.
    static bool IsMmapStream(const RE::BSResource::Stream* a_stream);

    // Downcast helper (returns nullptr if not an MmapStream).
    static const MmapStream* As(const RE::BSResource::Stream* a_stream);

private:
    const std::uint8_t*       data_;     // mapped memory pointer
    std::uint32_t             size_;     // entry data size
    mutable std::uint32_t     cursor_;   // current read position (mutable: DoRead is const)
    RE::BSFixedString         name_;     // entry name
    const BA2::MappedArchive* archive_;  // owning archive (not ref-counted, lives for session)
    // Optional pin on a DecompCache MappedView. Null for archive-mmap-backed
    // streams (BA2 mapping is owned by MappedArchive for full session). Held
    // when data_ points into a cache file mapping that could be rewritten by
    // a concurrent flush.
    std::shared_ptr<BA2::MappedView> viewOwner_;
};

}  // namespace BA2
