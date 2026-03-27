#include "PCH.h"
#include "MmapStream.h"

namespace BSA
{

// ── Construction ───────────────────────────────────────────────────────────

MmapStream::MmapStream(
    const std::uint8_t*       a_data,
    std::uint32_t             a_size,
    RE::BSFixedString         a_name,
    const BSA::MappedArchive* a_archive)
    : Stream(a_size)            // Skyrim Stream ctor: 1 param (totalSize), no writable bool
    , data_(a_data)
    , size_(a_size)
    , cursor_(0)
    , name_(std::move(a_name))
    , archive_(a_archive)
{
}

// ── StreamBase ─────────────────────────────────────────────────────────────

RE::BSResource::ErrorCode MmapStream::DoOpen()
{
    return RE::BSResource::ErrorCode::kNone;
}

void MmapStream::DoClose()
{
    cursor_ = 0;
}

std::uint64_t MmapStream::DoGetKey() const
{
    return 0;
}

RE::BSResource::ErrorCode MmapStream::DoGetInfo(RE::BSResource::Info& a_info)
{
    std::memset(&a_info, 0, sizeof(a_info));
    a_info.fileSize = size_;
    return RE::BSResource::ErrorCode::kNone;
}

// ── Stream ─────────────────────────────────────────────────────────────────

void MmapStream::DoClone(RE::BSTSmartPointer<RE::BSResource::Stream>& a_result) const
{
    auto* clone = new MmapStream(data_, size_, name_, archive_);
    a_result.reset(clone);
}

RE::BSResource::ErrorCode MmapStream::DoRead(
    void*          a_buffer,
    std::uint64_t  a_bytes,
    std::uint64_t& a_read) const
{
    const std::uint64_t remaining = (cursor_ < size_) ? (size_ - cursor_) : 0;
    const std::uint64_t n         = std::min(a_bytes, remaining);

    if (n > 0) {
        std::memcpy(a_buffer, data_ + cursor_, static_cast<std::size_t>(n));
        cursor_ += static_cast<std::uint32_t>(n);
    }

    a_read = n;
    return RE::BSResource::ErrorCode::kNone;
}

RE::BSResource::ErrorCode MmapStream::DoWrite(
    const void*, std::uint64_t, std::uint64_t& a_write) const
{
    a_write = 0;
    return RE::BSResource::ErrorCode::kUnsupported;
}

RE::BSResource::ErrorCode MmapStream::DoSeek(
    std::uint64_t              a_offset,       // Skyrim uses uint64_t (not int64_t like FO4)
    RE::BSResource::SeekMode   a_seekMode,
    std::uint64_t&             a_pos) const
{
    std::int64_t newPos = 0;
    const auto signedOffset = static_cast<std::int64_t>(a_offset);

    switch (a_seekMode) {
    case RE::BSResource::SeekMode::kSet:
        newPos = signedOffset;
        break;
    case RE::BSResource::SeekMode::kCur:
        newPos = static_cast<std::int64_t>(cursor_) + signedOffset;
        break;
    case RE::BSResource::SeekMode::kEnd:
        newPos = static_cast<std::int64_t>(size_) + signedOffset;
        break;
    default:
        return RE::BSResource::ErrorCode::kInvalidParam;
    }

    newPos  = std::clamp(newPos, std::int64_t{ 0 }, static_cast<std::int64_t>(size_));
    cursor_ = static_cast<std::uint32_t>(newPos);
    a_pos   = cursor_;
    return RE::BSResource::ErrorCode::kNone;
}

RE::BSResource::ErrorCode MmapStream::DoSetEndOfStream()
{
    return RE::BSResource::ErrorCode::kUnsupported;
}

bool MmapStream::DoGetName(RE::BSFixedString& a_result) const
{
    a_result = name_;
    return true;
}

RE::BSResource::ErrorCode MmapStream::DoCreateAsync(
    RE::BSTSmartPointer<RE::BSResource::AsyncStream>& /*a_result*/) const
{
    return RE::BSResource::ErrorCode::kUnsupported;
}

// ── Static helpers ─────────────────────────────────────────────────────────

static const std::uintptr_t* GetMmapStreamVtable()
{
    static const std::uintptr_t s_vtable = []() -> std::uintptr_t {
        alignas(MmapStream) std::uint8_t buf[sizeof(MmapStream)]{};
        auto* tmp = new (buf) MmapStream(nullptr, 0, {}, nullptr);
        auto  vt  = *reinterpret_cast<std::uintptr_t*>(tmp);
        tmp->~MmapStream();
        return vt;
    }();
    return &s_vtable;
}

bool MmapStream::IsMmapStream(const RE::BSResource::Stream* a_stream)
{
    if (!a_stream) return false;
    auto objVtbl = *reinterpret_cast<const std::uintptr_t*>(a_stream);
    return objVtbl == *GetMmapStreamVtable();
}

const MmapStream* MmapStream::As(const RE::BSResource::Stream* a_stream)
{
    return IsMmapStream(a_stream)
        ? static_cast<const MmapStream*>(a_stream)
        : nullptr;
}

}  // namespace BSA
