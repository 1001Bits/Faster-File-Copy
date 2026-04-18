#include "PCH.h"
#include "MmapStream.h"
#include "ArchiveStream.h"
#include "DecompCache.h"
#include "Hooks.h"
#include "Settings.h"

namespace BSA
{

// ── Construction ───────────────────────────────────────────────────────────

MmapStream::MmapStream(
    const std::uint8_t*              a_data,
    std::uint32_t                    a_size,
    RE::BSFixedString                a_name,
    const BSA::MappedArchive*        a_archive,
    void*                            a_source,
    std::uint32_t                    a_startOffset,
    std::uint32_t                    a_cursor,
    std::shared_ptr<BSA::MappedView> a_viewOwner)
    : Stream(a_size)
    , archiveFields_{}
    , data_(a_data)
    , size_(a_size)
    , startOffset_(a_startOffset)
    , archive_(a_archive)
    , nameStorage_(std::move(a_name))
    , viewOwner_(std::move(a_viewOwner))
{
    static_assert(offsetof(MmapStream, archiveFields_) == 0x10, "archiveFields_ must be at 0x10");
    InitArchiveFields(a_source, a_startOffset, nameStorage_);
    // InitArchiveFields writes CurrentOffset = startOffset. Apply the
    // caller-supplied relative cursor on top (used by DoClone).
    if (a_cursor > 0) {
        BSResource::FieldAt<std::uint32_t>(this, BSResource::Field::CurrentOffset) =
            a_startOffset + a_cursor;
    }
}

void MmapStream::InitArchiveFields(void* a_source, std::uint32_t a_startOffset, const RE::BSFixedString& a_name)
{
    auto* base = reinterpret_cast<char*>(this);

    // Set stream ready flag (bit 4 = 0x10) in the ref count / flags field.
    // AE: separate streamFlags at offset 0x10 (ref count in bits 12+, flags in bits 0-11)
    // SE/VR: combined at offset 0x0C (ref count in bits 12+, flags in bits 0-11)
    if (BSResource::Field::Source == 0x18) {
        // AE: streamFlags at 0x10
        *reinterpret_cast<std::uint32_t*>(base + 0x10) = 0x1010;  // 1 ref + ready flag
    } else {
        // SE/VR: flags at 0x0C — OR in the ready flag without clobbering ref count
        auto& flags = *reinterpret_cast<std::uint32_t*>(base + 0x0C);
        flags |= 0x10;  // set bit 4 (stream ready)
    }

    // Write fields at the correct offsets for this game version
    *reinterpret_cast<void**>(base + BSResource::Field::Source) = a_source;
    *reinterpret_cast<std::uint32_t*>(base + BSResource::Field::StartOffset) = a_startOffset;
    *reinterpret_cast<std::uint32_t*>(base + BSResource::Field::CurrentOffset) = a_startOffset;
    *reinterpret_cast<RE::BSFixedString*>(base + BSResource::Field::Name) = a_name;
}

// ── StreamBase ─────────────────────────────────────────────────────────────

RE::BSResource::ErrorCode MmapStream::DoOpen()
{
    return RE::BSResource::ErrorCode::kNone;
}

void MmapStream::DoClose()
{
    // Reset CurrentOffset to the start of the entry (relative cursor = 0).
    std::atomic_ref<std::uint32_t> curOff{
        BSResource::FieldAt<std::uint32_t>(this, BSResource::Field::CurrentOffset) };
    curOff.store(startOffset_, std::memory_order_release);
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
    std::atomic_ref<std::uint32_t> curOffRef{
        BSResource::FieldAt<std::uint32_t>(
            const_cast<MmapStream*>(this), BSResource::Field::CurrentOffset) };
    const auto curOff = curOffRef.load(std::memory_order_acquire);
    const auto cursor = curOff - startOffset_;
    auto* clone = new MmapStream(data_, size_, nameStorage_, archive_,
        BSResource::FieldAt<void* const>(this, BSResource::Field::Source),
        startOffset_,
        cursor,
        viewOwner_);  // share view ownership with the clone
    a_result.reset(clone);
}

RE::BSResource::ErrorCode MmapStream::DoRead(
    void*          a_buffer,
    std::uint64_t  a_bytes,
    std::uint64_t& a_read) const
{
    // CAS loop to atomically claim [oldOff, oldOff + n) so concurrent DoRead
    // calls (e.g., MuImpactFramework's parallel_for config loader) get
    // non-overlapping ranges instead of racing on the cursor.
    std::atomic_ref<std::uint32_t> curOff{
        BSResource::FieldAt<std::uint32_t>(
            const_cast<MmapStream*>(this), BSResource::Field::CurrentOffset) };

    std::uint32_t oldOff = curOff.load(std::memory_order_acquire);
    std::uint32_t n = 0;
    std::uint32_t cursor = 0;
    while (true) {
        cursor = oldOff - startOffset_;
        const std::uint32_t remaining = (cursor < size_) ? (size_ - cursor) : 0;
        n = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(a_bytes, remaining));
        const std::uint32_t newOff = oldOff + n;
        if (curOff.compare_exchange_weak(
                oldOff, newOff,
                std::memory_order_release,
                std::memory_order_acquire)) {
            break;
        }
        // oldOff was updated by compare_exchange_weak; retry with fresh value.
    }

    if (n > 0) {
        const bool measure = Settings::bMeasureStats;
        LARGE_INTEGER t0{}, t1{};
        if (measure) QueryPerformanceCounter(&t0);
        std::memcpy(a_buffer, data_ + cursor, n);
        if (measure) {
            QueryPerformanceCounter(&t1);
            Hooks::RecordCacheRead(n, t1.QuadPart - t0.QuadPart);
        }
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
    std::atomic_ref<std::uint32_t> curOff{
        BSResource::FieldAt<std::uint32_t>(
            const_cast<MmapStream*>(this), BSResource::Field::CurrentOffset) };
    const auto signedOffset = static_cast<std::int64_t>(a_offset);

    // CAS loop for kCur — relative seeks must observe the current cursor
    // atomically to avoid losing an update on concurrent seek/read.
    std::uint32_t oldOff = curOff.load(std::memory_order_acquire);
    std::uint32_t newRel = 0;
    while (true) {
        const std::uint32_t cursor = oldOff - startOffset_;
        std::int64_t newPos = 0;
        switch (a_seekMode) {
        case RE::BSResource::SeekMode::kSet:
            newPos = signedOffset;
            break;
        case RE::BSResource::SeekMode::kCur:
            newPos = static_cast<std::int64_t>(cursor) + signedOffset;
            break;
        case RE::BSResource::SeekMode::kEnd:
            newPos = static_cast<std::int64_t>(size_) + signedOffset;
            break;
        default:
            return RE::BSResource::ErrorCode::kInvalidParam;
        }

        newPos = std::clamp(newPos, std::int64_t{ 0 }, static_cast<std::int64_t>(size_));
        newRel = static_cast<std::uint32_t>(newPos);
        const std::uint32_t newOff = startOffset_ + newRel;
        if (curOff.compare_exchange_weak(
                oldOff, newOff,
                std::memory_order_release,
                std::memory_order_acquire)) {
            break;
        }
    }

    a_pos = newRel;
    return RE::BSResource::ErrorCode::kNone;
}

RE::BSResource::ErrorCode MmapStream::DoSetEndOfStream()
{
    return RE::BSResource::ErrorCode::kUnsupported;
}

bool MmapStream::DoGetName(RE::BSFixedString& a_result) const
{
    a_result = nameStorage_;
    return true;
}

RE::BSResource::ErrorCode MmapStream::DoCreateAsync(
    RE::BSTSmartPointer<RE::BSResource::AsyncStream>& /*a_result*/) const
{
    return RE::BSResource::ErrorCode::kUnsupported;
}

std::uint32_t MmapStream::GetDataSize() const
{
    return size_;
}

const std::uint8_t* MmapStream::GetDirectPointer() const
{
    std::atomic_ref<std::uint32_t> curOff{
        BSResource::FieldAt<std::uint32_t>(
            const_cast<MmapStream*>(this), BSResource::Field::CurrentOffset) };
    return data_ + (curOff.load(std::memory_order_acquire) - startOffset_);
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

// ── Leaky delete — double-DecRef workaround ────────────────────────────────
//
// CommonLibSSE-NG's BSResourceNiBinaryStream binding has a latent double-
// DecRef: the engine-internal dtor (SE 0x140c76340) DecRefs `this->stream`
// and conditionally invokes the scalar-deleting destructor, but leaves the
// smart-pointer slot at offset 0x20 non-null. The compiler-generated C++
// dtor then runs `~BSTSmartPointer<Stream>()`, which calls Release() →
// DecRef on the same (now freed) object. When the freed block happens to
// carry refcount bits == 0x1000, the second Release takes the delete branch
// and dispatches through vtable[0] on zeroed memory → access violation.
//
// We can't patch the engine dtor or consumer plugins (InventoryInjector,
// MuImpactFramework). But because the factory hook replaces the stream with
// our MmapStream, we own `operator delete` — so we keep the memory alive
// and zero the flags field at offset 0x0C. The second Release's DecRef
// then CAS-underflows 0 → 0xFFFFF000, returns non-zero, and skips delete.
// The vtable at offset 0x00 remains valid, so even if some other path were
// to dispatch through it, control lands right back in our leaky delete.
//
// Cost: ~96 bytes per BSA stream created this session. A long play session
// at ~50k stream replacements is ~5 MB — negligible next to the pinned
// decomp cache. Avoiding the RE::free call slightly speeds teardown.
// ─────────────────────────────────────────────────────────────────────────

void MmapStream::operator delete(void* a_ptr) noexcept
{
    if (!a_ptr) return;
    *reinterpret_cast<volatile std::uint32_t*>(
        static_cast<char*>(a_ptr) + 0x0C) = 0;
}

void MmapStream::operator delete(void* a_ptr, std::size_t) noexcept
{
    MmapStream::operator delete(a_ptr);
}

}  // namespace BSA
