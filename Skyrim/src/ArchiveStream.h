#pragma once

// ============================================================================
// BSResource::ArchiveStream — Verified Field Layout for Skyrim SE/AE
// ============================================================================
//
// Reverse-engineered from SkyrimSE.exe AE 1.6.1170 via disassembly of:
//   - ArchiveStream::DoRead, DoSeek, DoGetName, DoOpen, DoClose, DoClone
//   - ArchiveStream copy constructor (0x140d01fd0)
//   - CompressedArchiveStream::DoRead, DoOpen, DoClose, DoClone
//
// CommonLibSSE-NG has NO header for these classes. Only vtable IDs exist.
//
// ---- Vtable Addresses ----
//
//   Class                       REL::ID(SE,AE)       SE RVA      AE VA
//   ─────────────────────────── ──────────────────── ────────── ────────────
//   StreamBase                  (285759, 236968)     0x1762368
//   Stream                     (560082, 236972)     0x17623F8
//   ArchiveStream              (285761, 236985)     0x1762460  0x1419a88e8
//   CompressedArchiveStream    (285762, 236987)     0x17624D0  0x1419a8958
//   GlobalLocations            (285855, 237007)     0x17634A0  0x1419a9848
//
// ---- Key AE Function Addresses (1.6.1170) ----
//
//   ArchiveStream vtable (13 entries, 0-12):
//     [0]  0x140d05c90  dtor
//     [1]  0x140d022a0  DoOpen
//     [2]  0x140d02490  DoClose
//     [3]  0x140d02630  DoGetKey
//     [4]  0x140d06fd0  DoGetInfo
//     [5]  0x140d02220  DoClone
//     [6]  0x140d02330  DoRead         <-- hook target (fallback)
//     [7]  0x140d07150  DoWrite
//     [8]  0x140d023f0  DoSeek
//     [9]  0x140d07060  DoSetEndOfStream
//     [10] 0x140d024b0  DoGetName
//     [11] 0x140d024e0  DoCreateAsync
//     [12] 0x140d07c40  GetDataSize    (returns totalSize from StreamBase)
//
//   CompressedArchiveStream vtable (13 entries):
//     [6]  0x140d03130  DoRead         (branches on streamFlags bit 4)
//     [12] 0x140d02780  GetDataSize    (returns stored/compressed bytes on the
//                                      verified runtime/path; never use this as
//                                      decompression-cache payload length)
//
// ========================================================================

#include "RE/Skyrim.h"

namespace BSResource
{
    // ────────────────────────────────────────────────────────────────────
    // BSResource::ArchiveStream layout (0x30 bytes)
    //
    // Verified from AE 1.6.1170 disassembly.  Significantly different
    // from FO4's ReaderStream (0x40 bytes):
    //   - No separate compressedSize field (compression via streamFlags bits)
    //   - No void* context field
    //   - Offsets are uint32_t (BSA uses 32-bit), not uint64_t (BA2 uses 64-bit)
    //   - Cursor is absolute position, not relative to start
    //   - Struct is 0x30 bytes, not 0x40
    //
    //   FO4 ReaderStream (0x40):           Skyrim ArchiveStream (0x30):
    //     0x00 vtable                        0x00 vtable
    //     0x08 totalSize                     0x08 totalSize (data length)
    //     0x0C flags (refcount)              0x0C refCountFlags
    //     0x10 BSTSmartPointer source        0x10 streamFlags (bit field)
    //     0x18 void* context                 0x14 (padding)
    //     0x20 uint64 startOffset            0x18 source (ref-counted ptr)
    //     0x28 BSFixedString name            0x20 startOffset (uint32)
    //     0x30 uint32 relativeOffset         0x24 currentOffset (uint32)
    //     0x34 uint32 compressedSize         0x28 name (BSFixedString)
    //     0x38 uint32 uncompressedSize
    //     0x3C uint32 flags
    // ────────────────────────────────────────────────────────────────────

    // ── Runtime-selectable field offsets ────────────────────────────────
    //
    // SE (1.5.97): ArchiveStream is 0x28 bytes, no streamFlags field.
    // AE (1.6.x):  ArchiveStream is 0x30 bytes, has streamFlags at 0x10.
    //
    //   Field          SE      AE
    //   ─────────────  ─────   ─────
    //   totalSize      0x08    0x08   (StreamBase)
    //   refCountFlags  0x0C    0x0C   (StreamBase)
    //   streamFlags    N/A     0x10
    //   source         0x10    0x18
    //   startOffset    0x18    0x20
    //   currentOffset  0x1C    0x24
    //   name           0x20    0x28

    namespace Field
    {
        // Plain ArchiveStream uses this as its entry length. On the verified
        // CompressedArchiveStream path it is the stored/compressed byte count;
        // decompression-cache identity must use the BSA block prefix instead.
        constexpr std::size_t TotalSize     = 0x08;

        // ArchiveStream — use REL::Relocate(SE, AE) at runtime
        // Safe SE/VR defaults also keep diagnostic construction well-formed
        // before plugin initialization. Init() selects AE where appropriate.
        inline std::size_t Source{ 0x10 };
        inline std::size_t StartOffset{ 0x18 };
        inline std::size_t CurrentOffset{ 0x1C };
        inline std::size_t Name{ 0x20 };

        inline void Init()
        {
            Source        = REL::Relocate(0x10, 0x18);
            StartOffset   = REL::Relocate(0x18, 0x20);
            CurrentOffset = REL::Relocate(0x1C, 0x24);
            Name          = REL::Relocate(0x20, 0x28);
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // Safe field accessors
    // ────────────────────────────────────────────────────────────────────

    template <typename T>
    inline T& FieldAt(void* obj, std::size_t offset)
    {
        return *reinterpret_cast<T*>(static_cast<char*>(obj) + offset);
    }

    template <typename T>
    inline const T& FieldAt(const void* obj, std::size_t offset)
    {
        return *reinterpret_cast<const T*>(static_cast<const char*>(obj) + offset);
    }

}  // namespace BSResource
