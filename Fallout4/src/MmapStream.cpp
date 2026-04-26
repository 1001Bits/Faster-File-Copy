#include "PCH.h"
#include "MmapStream.h"
#include "DecompCache.h"
#include "FastCopy.h"
#include "Settings.h"

#include <algorithm>
#include <cstring>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

namespace BA2
{
std::atomic<std::uint64_t> g_mmapDoReadCalls[kMmapHistBuckets]{};
std::atomic<std::uint64_t> g_mmapDoReadNs[kMmapHistBuckets]{};

static std::int64_t s_mmapQpcFreq = [] {
    LARGE_INTEGER f; QueryPerformanceFrequency(&f); return f.QuadPart;
}();
}  // namespace BA2

// PrefetchVirtualMemory requires Win8+ (_WIN32_WINNT >= 0x0602).
// Define the required types and load the function at runtime.
struct MEMORY_RANGE_ENTRY_ {
    PVOID  VirtualAddress;
    SIZE_T NumberOfBytes;
};

using PrefetchVirtualMemory_t = BOOL(WINAPI*)(HANDLE, ULONG_PTR, MEMORY_RANGE_ENTRY_*, ULONG);

static PrefetchVirtualMemory_t GetPrefetchFn()
{
    static auto fn = reinterpret_cast<PrefetchVirtualMemory_t>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "PrefetchVirtualMemory"));
    return fn;
}

static void DoPrefetch(const void* addr, SIZE_T size)
{
    auto fn = GetPrefetchFn();
    if (fn) {
        MEMORY_RANGE_ENTRY_ range{};
        range.VirtualAddress = const_cast<void*>(addr);
        range.NumberOfBytes  = size;
        fn(GetCurrentProcess(), 1, &range, 0);
    }
}

namespace BA2
{

// ── Construction ────────────────────────────────────────────────────────────

MmapStream::MmapStream(
    const std::uint8_t*       a_data,
    std::uint32_t             a_size,
    RE::BSFixedString         a_name,
    const BA2::MappedArchive* a_archive)
    : Stream(a_size, false)      // StreamBase: totalSize = a_size, writable = false
    , data_(a_data)
    , size_(a_size)
    , cursor_(0)
    , name_(std::move(a_name))
    , archive_(a_archive)
{
}

MmapStream::MmapStream(
    const std::uint8_t*                a_data,
    std::uint32_t                      a_size,
    RE::BSFixedString                  a_name,
    const BA2::MappedArchive*          a_archive,
    std::shared_ptr<BA2::MappedView>   a_viewOwner)
    : Stream(a_size, false)
    , data_(a_data)
    , size_(a_size)
    , cursor_(0)
    , name_(std::move(a_name))
    , archive_(a_archive)
    , viewOwner_(std::move(a_viewOwner))
{
}

// ── StreamBase ──────────────────────────────────────────────────────────────

RE::BSResource::ErrorCode MmapStream::DoOpen()
{
    return RE::BSResource::ErrorCode::kNone;
}

void MmapStream::DoClose()
{
    // Nothing to close — the mapping is owned by MappedArchive.
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

// ── Stream ──────────────────────────────────────────────────────────────────

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
    const bool timing = Settings::bEnableStats;
    LARGE_INTEGER t0{};
    if (timing) QueryPerformanceCounter(&t0);

    const std::uint64_t remaining = (cursor_ < size_) ? (size_ - cursor_) : 0;
    const std::uint64_t n         = std::min(a_bytes, remaining);

    if (n > 0) {
        BA2::FastCopyLarge(a_buffer, data_ + cursor_, static_cast<std::size_t>(n));
        cursor_ += static_cast<std::uint32_t>(n);
    }

    a_read = n;

    if (timing) {
        LARGE_INTEGER t1; QueryPerformanceCounter(&t1);
        const int b = BA2::MmapSizeBucket(n);
        BA2::g_mmapDoReadCalls[b].fetch_add(1, std::memory_order_relaxed);
        BA2::g_mmapDoReadNs[b].fetch_add(
            static_cast<std::uint64_t>(
                (t1.QuadPart - t0.QuadPart) * 1000000000LL / s_mmapQpcFreq),
            std::memory_order_relaxed);
    }
    return RE::BSResource::ErrorCode::kNone;
}

RE::BSResource::ErrorCode MmapStream::DoReadAt(
    void*          a_buffer,
    std::uint64_t  a_bytes,
    std::uint64_t  a_pos,
    std::uint64_t& a_read) const
{
    if (a_pos >= size_) {
        a_read = 0;
        return RE::BSResource::ErrorCode::kNone;
    }

    const std::uint64_t available = size_ - a_pos;
    const std::uint64_t n         = std::min(a_bytes, available);

    if (n > 0)
        BA2::FastCopyLarge(a_buffer, data_ + a_pos, static_cast<std::size_t>(n));

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
    std::int64_t             a_offset,
    RE::BSResource::SeekMode a_seekMode,
    std::uint64_t&           a_pos) const
{
    std::int64_t newPos = 0;

    switch (a_seekMode) {
    case RE::BSResource::SeekMode::kSet:
        newPos = a_offset;
        break;
    case RE::BSResource::SeekMode::kCurrent:
        newPos = static_cast<std::int64_t>(cursor_) + a_offset;
        break;
    case RE::BSResource::SeekMode::kEnd:
        newPos = static_cast<std::int64_t>(size_) + a_offset;
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

RE::BSResource::ErrorCode MmapStream::DoPrefetchAt(
    std::uint64_t a_bytes,
    std::uint64_t a_offset,
    std::uint32_t /*a_priority*/) const
{
    if (a_offset >= size_)
        return RE::BSResource::ErrorCode::kNone;

    const std::uint64_t n = std::min(a_bytes, static_cast<std::uint64_t>(size_) - a_offset);

    DoPrefetch(data_ + a_offset, static_cast<SIZE_T>(n));

    return RE::BSResource::ErrorCode::kNone;
}

RE::BSResource::ErrorCode MmapStream::DoStartTaggedPrioritizedRead(
    void*                   a_buffer,
    std::uint64_t           a_bytes,
    std::uint64_t           a_offset,
    std::uint32_t           /*a_priority*/,
    volatile std::uint32_t* a_completionTag,
    std::uint32_t&          a_completionTagWaitValue,
    RE::BSEventFlag*        /*a_eventFlag*/) const
{
    // Data is already in the page cache — complete the read synchronously.
    std::uint64_t read = 0;
    auto err = DoReadAt(a_buffer, a_bytes, a_offset, read);

    // Signal completion immediately.
    if (a_completionTag) {
        a_completionTagWaitValue = *a_completionTag;
    }

    return err;
}

RE::BSResource::ErrorCode MmapStream::DoWaitTags(
    volatile std::uint32_t* /*a_completionTag*/,
    std::uint32_t           /*a_completionTagWaitValue*/,
    RE::BSEventFlag*        /*a_eventFlag*/) const
{
    // Tagged reads complete synchronously in DoStartTaggedPrioritizedRead,
    // so there is never anything to wait for.
    return RE::BSResource::ErrorCode::kNone;
}

RE::BSResource::ErrorCode MmapStream::DoPrefetchAll(std::uint32_t /*a_priority*/) const
{
    DoPrefetch(data_, static_cast<SIZE_T>(size_));

    return RE::BSResource::ErrorCode::kNone;
}

bool MmapStream::DoGetName(RE::BSFixedString& a_result) const
{
    a_result = name_;
    return true;
}

RE::BSResource::ErrorCode MmapStream::DoCreateAsync(
    RE::BSTSmartPointer<RE::BSResource::AsyncStream>& /*a_result*/) const
{
    // Async reads are unnecessary — our DoRead is already sub-microsecond
    // for cached pages.  Returning kUnsupported causes the engine to fall
    // back to synchronous reads through DoRead.
    return RE::BSResource::ErrorCode::kUnsupported;
}

bool MmapStream::DoQTaggedPrioritizedReadSupported() const
{
    // We implement DoStartTaggedPrioritizedRead with synchronous completion,
    // which is the fastest possible path.
    return true;
}

RE::BSResource::ErrorCode MmapStream::DoCreateOp(
    RE::BSTSmartPointer<RE::BSResource::ICacheDriveOp>& /*a_result*/,
    char const* /*a_arg2*/) const
{
    return RE::BSResource::ErrorCode::kUnsupported;
}

bool MmapStream::DoGetIsFromArchive() const
{
    return true;
}

// ── Static helpers ──────────────────────────────────────────────────────────

// We identify our streams by comparing their vtable pointer against the
// vtable the compiler emits for MmapStream.  This is a single pointer
// comparison — O(1), no RTTI overhead.

static const std::uintptr_t* GetMmapStreamVtable()
{
    // Construct a throwaway object to capture the vtable pointer.
    // This runs once (static local).
    static const std::uintptr_t s_vtable = []() -> std::uintptr_t {
        // The vtable is the first pointer-sized value in any polymorphic object.
        alignas(MmapStream) std::uint8_t buf[sizeof(MmapStream)]{};
        // Placement-new a temporary; its vtable pointer is at offset 0.
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

}  // namespace BA2
