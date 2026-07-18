#include "PCH.h"
#include "DecompCache.h"
#include "CacheWarmPolicy.h"
#include "Settings.h"

#include <chrono>
#include <cwctype>
#include <fstream>
#include <limits>

namespace BSA
{

namespace
{
    constexpr int           kBackgroundFlushIntervalSec = 60;
    constexpr std::uint64_t kBytesPerMB = 1024ull * 1024ull;
    constexpr std::uint64_t kColdMs = 60ull * 1000ull;
    constexpr std::uint64_t kMaxPendingMemoryBytes = 256ull * kBytesPerMB;
    constexpr std::uint64_t kFlushWakeBytes = 32ull * kBytesPerMB;
    constexpr std::uint64_t kWarmChunkBytes = 8ull * kBytesPerMB;
    // Bound the longest uncancellable synchronous write when Skyrim starts a
    // new load while the low-priority cache worker is active.
    constexpr DWORD         kWriteChunk = 8u * 1024u * 1024u;

    constexpr std::uint8_t kVerifyUnknown = 0;
    constexpr std::uint8_t kVerifyBusy    = 1;
    constexpr std::uint8_t kVerifyValid   = 2;
    constexpr std::uint8_t kVerifyInvalid = 3;

    class UniqueHandle
    {
    public:
        UniqueHandle() = default;
        explicit UniqueHandle(HANDLE a_handle) : handle(a_handle) {}
        UniqueHandle(const UniqueHandle&) = delete;
        UniqueHandle& operator=(const UniqueHandle&) = delete;
        UniqueHandle(UniqueHandle&& a_other) noexcept : handle(a_other.release()) {}
        ~UniqueHandle() { reset(); }

        bool valid() const { return handle && handle != INVALID_HANDLE_VALUE; }
        HANDLE get() const { return handle; }
        HANDLE release() { auto result = handle; handle = nullptr; return result; }
        void reset(HANDLE a_handle = nullptr) {
            if (valid()) CloseHandle(handle);
            handle = a_handle;
        }

    private:
        HANDLE handle{ nullptr };
    };

    class UniqueView
    {
    public:
        UniqueView() = default;
        explicit UniqueView(const std::uint8_t* a_view) : view(a_view) {}
        UniqueView(const UniqueView&) = delete;
        UniqueView& operator=(const UniqueView&) = delete;
        ~UniqueView() { reset(); }

        const std::uint8_t* get() const { return view; }
        const std::uint8_t* release() { auto result = view; view = nullptr; return result; }
        void reset(const std::uint8_t* a_view = nullptr) {
            if (view) UnmapViewOfFile(view);
            view = a_view;
        }

    private:
        const std::uint8_t* view{ nullptr };
    };

    class ExclusiveFileLock
    {
    public:
        explicit ExclusiveFileLock(HANDLE a_file, bool a_attempt = true) : file(a_file) {
            if (!a_attempt) return;
            OVERLAPPED ov{};
            locked = LockFileEx(
                file, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0, MAXDWORD, MAXDWORD, &ov) != FALSE;
        }
        ~ExclusiveFileLock() {
            if (locked) {
                OVERLAPPED ov{};
                UnlockFileEx(file, 0, MAXDWORD, MAXDWORD, &ov);
            }
        }
        explicit operator bool() const { return locked; }

    private:
        HANDLE file{ nullptr };
        bool   locked{ false };
    };

    std::string PathForLog(const std::filesystem::path& a_path)
    {
        const auto wide = a_path.wstring();
        if (wide.empty()) return {};
        const int needed = WideCharToMultiByte(
            CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
            nullptr, 0, nullptr, nullptr);
        if (needed <= 0) return "<path>";
        std::string result(static_cast<std::size_t>(needed), '\0');
        WideCharToMultiByte(
            CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
            result.data(), needed, nullptr, nullptr);
        return result;
    }

    std::wstring PathKey(const std::filesystem::path& a_path)
    {
        auto key = a_path.lexically_normal().wstring();
        std::transform(key.begin(), key.end(), key.begin(),
            [](wchar_t a_ch) { return static_cast<wchar_t>(std::towlower(a_ch)); });
        return key;
    }

    bool AddChecked(std::uint64_t a_lhs, std::uint64_t a_rhs, std::uint64_t& a_out)
    {
        if (a_rhs > (std::numeric_limits<std::uint64_t>::max)() - a_lhs)
            return false;
        a_out = a_lhs + a_rhs;
        return true;
    }

    // File-backed mapping faults are structured exceptions under /EHsc. Keep
    // the raw page walk isolated from objects requiring C++ unwinding so an
    // in-page storage error disables this warm pass instead of killing Skyrim.
    bool TouchMappedPages(const std::uint8_t* a_base, std::uint64_t a_begin,
                          std::uint64_t a_end, std::size_t a_pageSize) noexcept
    {
        if (!a_base || a_begin >= a_end || a_pageSize == 0) return true;
#if defined(_MSC_VER)
        __try {
            volatile std::uint8_t sink = 0;
            sink = static_cast<std::uint8_t>(sink ^
                *reinterpret_cast<const volatile std::uint8_t*>(a_base + a_begin));
            const auto misalignment = a_begin % a_pageSize;
            const auto advance = misalignment == 0
                ? static_cast<std::uint64_t>(a_pageSize)
                : static_cast<std::uint64_t>(a_pageSize) - misalignment;
            if (advance < a_end - a_begin) {
                for (auto offset = a_begin + advance; offset < a_end;) {
                    sink = static_cast<std::uint8_t>(sink ^
                        *reinterpret_cast<const volatile std::uint8_t*>(
                            a_base + offset));
                    if (a_end - offset <= a_pageSize) break;
                    offset += a_pageSize;
                }
            }
            // Explicitly cover a final partial page when a_begin was not page
            // aligned. PrefetchVirtualMemory is advisory and cannot substitute
            // for this deterministic fault.
            sink = static_cast<std::uint8_t>(sink ^
                *reinterpret_cast<const volatile std::uint8_t*>(a_base + a_end - 1));
            (void)sink;
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
#else
        volatile std::uint8_t sink = 0;
        auto touch = [&](std::uint64_t offset) {
            sink = static_cast<std::uint8_t>(sink ^ a_base[offset]);
        };
        touch(a_begin);
        const auto misalignment = a_begin % a_pageSize;
        const auto advance = misalignment == 0
            ? static_cast<std::uint64_t>(a_pageSize)
            : static_cast<std::uint64_t>(a_pageSize) - misalignment;
        if (advance < a_end - a_begin) {
            for (auto offset = a_begin + advance; offset < a_end;
                 offset += a_pageSize)
                touch(offset);
        }
        touch(a_end - 1);
        (void)sink;
        return true;
#endif
    }

    void AdvisePrefetch(const std::uint8_t* a_base, std::uint64_t a_begin,
                        std::uint64_t a_size) noexcept
    {
        if (!a_base || a_size == 0 ||
            a_size > static_cast<std::uint64_t>((std::numeric_limits<SIZE_T>::max)()))
            return;
        // Keep the ABI local because older _WIN32_WINNT declarations hide the
        // SDK's WIN32_MEMORY_RANGE_ENTRY even though the runtime API is present.
        struct MemoryRangeEntry
        {
            PVOID VirtualAddress;
            SIZE_T NumberOfBytes;
        };
        using PrefetchVirtualMemory_t = BOOL (WINAPI *)(
            HANDLE, ULONG_PTR, MemoryRangeEntry*, ULONG);
        static const auto fn = []() noexcept -> PrefetchVirtualMemory_t {
            const auto kernel = GetModuleHandleW(L"kernel32.dll");
            return kernel ? reinterpret_cast<PrefetchVirtualMemory_t>(
                GetProcAddress(kernel, "PrefetchVirtualMemory")) : nullptr;
        }();
        if (!fn) return;
        MemoryRangeEntry range{};
        range.VirtualAddress = const_cast<std::uint8_t*>(a_base + a_begin);
        range.NumberOfBytes = static_cast<SIZE_T>(a_size);
        (void)fn(GetCurrentProcess(), 1, &range, 0);
    }

    bool TryChecksumMapped(const std::uint8_t* a_data, std::size_t a_size,
                           std::uint32_t& a_checksum) noexcept
    {
        if (!a_data || a_size == 0) return false;
#if defined(_MSC_VER)
        __try {
            a_checksum = CacheFormat::Checksum(a_data, a_size);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            a_checksum = 0;
            return false;
        }
#else
        a_checksum = CacheFormat::Checksum(a_data, a_size);
        return true;
#endif
    }

    bool GetHandleSize(HANDLE a_file, std::uint64_t& a_size)
    {
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(a_file, &size) || size.QuadPart < 0)
            return false;
        a_size = static_cast<std::uint64_t>(size.QuadPart);
        return true;
    }

    bool Seek(HANDLE a_file, std::uint64_t a_offset)
    {
        if (a_offset > static_cast<std::uint64_t>((std::numeric_limits<LONGLONG>::max)()))
            return false;
        LARGE_INTEGER pos{};
        pos.QuadPart = static_cast<LONGLONG>(a_offset);
        return SetFilePointerEx(a_file, pos, nullptr, FILE_BEGIN) != FALSE;
    }

    bool Truncate(HANDLE a_file, std::uint64_t a_size)
    {
        return Seek(a_file, a_size) && SetEndOfFile(a_file) != FALSE;
    }

    bool WriteAt(HANDLE a_file, std::uint64_t a_offset, const void* a_data,
                 std::uint64_t a_size,
                 const std::atomic<bool>* a_cancel = nullptr)
    {
        if (!Seek(a_file, a_offset)) return false;
        const auto* in = static_cast<const std::uint8_t*>(a_data);
        while (a_size > 0) {
            if (a_cancel && a_cancel->load(std::memory_order_acquire))
                return false;
            const DWORD chunk = static_cast<DWORD>((std::min<std::uint64_t>)(a_size, kWriteChunk));
            DWORD written = 0;
            if (!WriteFile(a_file, in, chunk, &written, nullptr) || written != chunk)
                return false;
            in += written;
            a_size -= written;
        }
        return true;
    }

    struct VerificationResult
    {
        bool valid{ false };
        bool computed{ false };
        bool waited{ false };
        std::uint64_t qpcTicks{ 0 };
    };

    VerificationResult VerifyEntry(const CachedEntry& a_entry)
    {
        if (!a_entry.data || a_entry.size == 0 || !a_entry.verification)
            return {};

        auto& state = *a_entry.verification;
        bool waited = false;
        for (;;) {
            auto current = state.load(std::memory_order_acquire);
            if (current == kVerifyValid) return { true, false, waited, 0 };
            if (current == kVerifyInvalid) return { false, false, waited, 0 };
            if (current == kVerifyUnknown) {
                if (state.compare_exchange_strong(
                        current, kVerifyBusy,
                        std::memory_order_acq_rel, std::memory_order_acquire)) {
                    LARGE_INTEGER started{};
                    if (Settings::bMeasureStats)
                        QueryPerformanceCounter(&started);
                    std::uint32_t checksum = 0;
                    const bool readable = TryChecksumMapped(
                        a_entry.data, a_entry.size, checksum);
                    const bool valid = readable && checksum == a_entry.checksum;
                    std::uint64_t ticks = 0;
                    if (Settings::bMeasureStats) {
                        LARGE_INTEGER finished{};
                        QueryPerformanceCounter(&finished);
                        ticks = finished.QuadPart >= started.QuadPart
                            ? static_cast<std::uint64_t>(
                                finished.QuadPart - started.QuadPart)
                            : 0;
                    }
                    state.store(valid ? kVerifyValid : kVerifyInvalid,
                        std::memory_order_release);
                    state.notify_all();
                    return { valid, true, waited, ticks };
                }
                continue;
            }
            waited = true;
            state.wait(kVerifyBusy, std::memory_order_acquire);
        }
    }

    struct PreparedPending
    {
        std::uint32_t off{ 0 };
        const std::uint8_t* data{ nullptr };
        std::uint32_t size{ 0 };
        std::uint32_t checksum{ 0 };
    };

    struct OLPending
    {
        std::uint32_t off{ 0 };
        std::uint64_t accountedBytes{ 0 };
        std::vector<std::uint8_t> data;
    };

    struct OLWork
    {
        const MappedArchive* archive{ nullptr };
        std::filesystem::path basePath;
        std::uint64_t bsaFileSize{ 0 };
        std::uint64_t bsaLastWrite{ 0 };
        std::uint64_t bsaFingerprint{ 0 };
        std::uint32_t bsaEntryCount{ 0 };
        const std::atomic<bool>* cancel{ nullptr };
        bool resetFile{ false };
        std::shared_ptr<MappedView> sourceView;
        std::unordered_set<std::uint32_t> verifiedOffsets;
        std::vector<OLPending> pending;
    };

    struct OLResult
    {
        bool ok{ false };
        std::shared_ptr<MappedView> view;
        std::unordered_map<std::uint32_t, CachedEntry> index;
        std::uint64_t fileSize{ 0 };
    };

    CacheFormat::ArchiveIdentity IdentityFor(const OLWork& a_work)
    {
        return {
            a_work.bsaFileSize,
            a_work.bsaLastWrite,
            a_work.bsaFingerprint,
            a_work.bsaEntryCount
        };
    }

    bool Cancelled(const OLWork& a_work) noexcept
    {
        return a_work.cancel && a_work.cancel->load(std::memory_order_acquire);
    }

    OLResult MapCommittedFile(
        const std::filesystem::path& a_path,
        const CacheFormat::ArchiveIdentity& a_identity,
        const std::unordered_set<std::uint32_t>& a_knownValid)
    {
        OLResult result;
        UniqueHandle file(CreateFileW(
            a_path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!file.valid()) return result;

        std::uint64_t fileSize = 0;
        if (!GetHandleSize(file.get(), fileSize) ||
            fileSize < sizeof(CacheFormat::Header) ||
            fileSize > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
            return result;

        UniqueHandle mapping(CreateFileMappingW(
            file.get(), nullptr, PAGE_READONLY, 0, 0, nullptr));
        if (!mapping.valid()) return result;
        UniqueView bytes(static_cast<const std::uint8_t*>(
            MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, 0)));
        if (!bytes.get()) return result;

        CacheFormat::ValidationResult validation;
        try {
            validation = CacheFormat::Validate(
                bytes.get(), static_cast<std::size_t>(fileSize), &a_identity,
                CacheFormat::ValidationMode::StructuralOnly, false);
        } catch (...) {
            return result;
        }
        if (!validation) return result;

        auto owner = std::make_shared<MappedView>();
        owner->verificationCount = validation.header.entryCount;
        owner->verification =
            std::make_unique<std::atomic<std::uint8_t>[]>(owner->verificationCount);
        owner->base = bytes.release();
        owner->mapHandle = mapping.release();
        owner->size = fileSize;
        owner->committedSize = validation.validSize;
        owner->prefaultedThrough.store(0, std::memory_order_relaxed);

        result.index.reserve(validation.header.entryCount);
        for (std::uint32_t i = 0; i < validation.header.entryCount; ++i) {
            CacheFormat::Entry entry{};
            std::memcpy(
                &entry,
                owner->base + sizeof(CacheFormat::Header) +
                    static_cast<std::size_t>(i) * sizeof(CacheFormat::Entry),
                sizeof(entry));
            auto& state = owner->verification[i];
            state.store(a_knownValid.contains(entry.startOffset) ?
                kVerifyValid : kVerifyUnknown, std::memory_order_relaxed);
            result.index.emplace(entry.startOffset, CachedEntry{
                owner->base + entry.cacheOffset,
                entry.decompSize,
                entry.checksum,
                &state
            });
        }
        result.fileSize = fileSize;
        result.view = std::move(owner);
        result.ok = true;
        return result;
    }

    std::filesystem::path TempPathFor(const std::filesystem::path& a_base)
    {
        static std::atomic<std::uint64_t> generation{ 0 };
        auto path = a_base;
        path += L".tmp.";
        path += std::to_wstring(GetCurrentProcessId());
        path += L".";
        path += std::to_wstring(generation.fetch_add(1, std::memory_order_relaxed) + 1);
        return path;
    }

    std::vector<PreparedPending> PreparePending(const OLWork& a_work)
    {
        std::vector<PreparedPending> result;
        result.reserve(a_work.pending.size());
        for (const auto& pending : a_work.pending) {
            if (Cancelled(a_work)) return {};
            if (pending.data.empty() ||
                pending.data.size() > (std::numeric_limits<std::uint32_t>::max)())
                return {};
            const auto checksum =
                CacheFormat::Checksum(pending.data.data(), pending.data.size());
            if (Cancelled(a_work)) return {};
            result.push_back({
                pending.off,
                pending.data.data(),
                static_cast<std::uint32_t>(pending.data.size()),
                checksum
            });
        }
        return result;
    }

    OLResult WriteFreshFile(
        const OLWork& a_work,
        const std::vector<PreparedPending>& a_pending)
    {
        OLResult failure;
        if (a_pending.empty() || a_pending.size() > a_work.bsaEntryCount ||
            Cancelled(a_work))
            return failure;

        // Serialize replacement with an appender in another game process when
        // a destination generation already exists. First-writer races on a
        // genuinely missing file remain harmless: each temp is complete and
        // the last atomic replacement wins.
        UniqueHandle destination(CreateFileW(
            a_work.basePath.c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        ExclusiveFileLock destinationLock(destination.get(), destination.valid());
        if (destination.valid() && !destinationLock)
            return failure;

        std::unordered_set<std::uint32_t> offsets;
        offsets.reserve(a_pending.size());
        for (const auto& pending : a_pending) {
            if (!offsets.insert(pending.off).second)
                return failure;
        }

        std::uint64_t indexBytes =
            static_cast<std::uint64_t>(a_work.bsaEntryCount) * sizeof(CacheFormat::Entry);
        std::uint64_t dataStart = 0;
        if (!AddChecked(sizeof(CacheFormat::Header), indexBytes, dataStart))
            return failure;

        std::vector<CacheFormat::Entry> entries;
        entries.reserve(a_pending.size());
        std::uint64_t cursor = dataStart;
        for (const auto& pending : a_pending) {
            CacheFormat::Entry entry{
                pending.off, pending.size, cursor, pending.checksum
            };
            entries.push_back(entry);
            if (!AddChecked(cursor, pending.size, cursor))
                return failure;
        }

        CacheFormat::Header header{};
        std::memcpy(header.magic, CacheFormat::kMagic, sizeof(header.magic));
        header.version = CacheFormat::kVersion;
        header.bsaFileSize = a_work.bsaFileSize;
        header.bsaLastWrite = a_work.bsaLastWrite;
        header.bsaFingerprint = a_work.bsaFingerprint;
        header.bsaEntryCount = a_work.bsaEntryCount;
        header.indexCapacity = a_work.bsaEntryCount;
        header.entryCount = static_cast<std::uint32_t>(entries.size());

        const auto tempPath = TempPathFor(a_work.basePath);
        UniqueHandle file(CreateFileW(
            tempPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
            nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!file.valid()) return failure;

        bool ok = WriteAt(file.get(), 0, &header, sizeof(header), a_work.cancel) &&
            WriteAt(file.get(), sizeof(header), entries.data(),
                static_cast<std::uint64_t>(entries.size()) * sizeof(CacheFormat::Entry),
                a_work.cancel);
        if (ok) {
            std::uint64_t payloadOffset = dataStart;
            for (const auto& pending : a_pending) {
                if (!WriteAt(file.get(), payloadOffset, pending.data, pending.size,
                        a_work.cancel)) {
                    ok = false;
                    break;
                }
                payloadOffset += pending.size;
            }
        }
        if (ok && !Cancelled(a_work)) ok = FlushFileBuffers(file.get()) != FALSE;
        file.reset();

        if (!ok || !MoveFileExW(
                tempPath.c_str(), a_work.basePath.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            std::error_code ec;
            std::filesystem::remove(tempPath, ec);
            return failure;
        }

        return MapCommittedFile(a_work.basePath, IdentityFor(a_work), offsets);
    }

    OLResult AppendFile(const OLWork& a_work)
    {
        if (Cancelled(a_work)) return {};
        auto prepared = PreparePending(a_work);
        if (prepared.size() != a_work.pending.size()) return {};
        if (a_work.resetFile)
            return WriteFreshFile(a_work, prepared);

        bool useFresh = false;
        std::unordered_set<std::uint32_t> knownValid = a_work.verifiedOffsets;
        std::vector<PreparedPending> newEntries;

        {
            UniqueHandle file(CreateFileW(
                a_work.basePath.c_str(), GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
            if (!file.valid())
                return WriteFreshFile(a_work, prepared);

            ExclusiveFileLock lock(file.get());
            if (!lock) return {};

            std::uint64_t physicalSize = 0;
            if (!GetHandleSize(file.get(), physicalSize) ||
                physicalSize < sizeof(CacheFormat::Header) ||
                physicalSize > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
                useFresh = true;

            CacheFormat::ValidationResult validation;
            UniqueHandle mapping;
            UniqueView view;
            if (!useFresh) {
                mapping.reset(CreateFileMappingW(file.get(), nullptr, PAGE_READONLY, 0, 0, nullptr));
                if (!mapping.valid()) {
                    useFresh = true;
                } else {
                    view.reset(static_cast<const std::uint8_t*>(
                        MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, 0)));
                    if (!view.get()) {
                        useFresh = true;
                    } else {
                        try {
                            const auto identity = IdentityFor(a_work);
                            validation = CacheFormat::Validate(
                                view.get(), static_cast<std::size_t>(physicalSize), &identity,
                                CacheFormat::ValidationMode::StructuralOnly, true);
                        } catch (...) {
                            useFresh = true;
                        }
                        if (!validation) useFresh = true;
                    }
                }
            }

            if (!useFresh) {
                std::unordered_map<std::uint32_t, CacheFormat::Entry> existing;
                existing.reserve(validation.header.entryCount);
                for (std::uint32_t i = 0; i < validation.header.entryCount; ++i) {
                    CacheFormat::Entry entry{};
                    std::memcpy(
                        &entry,
                        view.get() + sizeof(CacheFormat::Header) +
                            static_cast<std::size_t>(i) * sizeof(CacheFormat::Entry),
                        sizeof(entry));
                    existing.emplace(entry.startOffset, entry);
                }

                for (const auto& pending : prepared) {
                    auto found = existing.find(pending.off);
                    if (found == existing.end()) {
                        newEntries.push_back(pending);
                    } else if (found->second.decompSize == pending.size &&
                               found->second.checksum == pending.checksum) {
                        // This is normally a prior commit whose remap failed.
                        // Do not trust matching metadata alone: verify the
                        // already-persisted bytes before marking the new view
                        // valid without a lazy checksum.
                        const auto* persisted = view.get() + found->second.cacheOffset;
                        if (CacheFormat::Checksum(persisted, found->second.decompSize) ==
                            found->second.checksum) {
                            knownValid.insert(pending.off);
                        } else {
                            useFresh = true;
                            break;
                        }
                    } else {
                        useFresh = true;
                        break;
                    }
                }

                if (!useFresh &&
                    newEntries.size() >
                        validation.header.indexCapacity - validation.header.entryCount)
                    useFresh = true;
            }

            view.reset();
            mapping.reset();

            if (!useFresh) {
                const auto oldHeader = validation.header;
                const auto oldCommittedSize = validation.validSize;
                if (Cancelled(a_work)) return {};
                bool ok = !Cancelled(a_work) && Truncate(file.get(), oldCommittedSize);

                std::vector<CacheFormat::Entry> appendedIndex;
                appendedIndex.reserve(newEntries.size());
                std::uint64_t cursor = oldCommittedSize;
                for (const auto& pending : newEntries) {
                    appendedIndex.push_back({
                        pending.off, pending.size, cursor, pending.checksum
                    });
                    if (!AddChecked(cursor, pending.size, cursor)) {
                        ok = false;
                        break;
                    }
                }

                if (ok) {
                    std::uint64_t payloadOffset = oldCommittedSize;
                    for (const auto& pending : newEntries) {
                        if (!WriteAt(file.get(), payloadOffset, pending.data, pending.size,
                                a_work.cancel)) {
                            ok = false;
                            break;
                        }
                        payloadOffset += pending.size;
                    }
                }
                if (ok && !Cancelled(a_work)) ok = FlushFileBuffers(file.get()) != FALSE;

                if (ok && !appendedIndex.empty()) {
                    const std::uint64_t indexOffset = sizeof(CacheFormat::Header) +
                        static_cast<std::uint64_t>(oldHeader.entryCount) *
                            sizeof(CacheFormat::Entry);
                    ok = WriteAt(file.get(), indexOffset, appendedIndex.data(),
                        static_cast<std::uint64_t>(appendedIndex.size()) *
                            sizeof(CacheFormat::Entry), a_work.cancel);
                    if (ok) ok = FlushFileBuffers(file.get()) != FALSE;
                }

                auto newHeader = oldHeader;
                newHeader.entryCount += static_cast<std::uint32_t>(appendedIndex.size());
                if (ok && !appendedIndex.empty()) {
                    ok = WriteAt(file.get(), 0, &newHeader, sizeof(newHeader),
                        a_work.cancel);
                    if (ok) ok = FlushFileBuffers(file.get()) != FALSE;
                }

                if (!ok) {
                    // Restore the last committed header and length. Pending
                    // buffers remain owned by OLWork and will be requeued.
                    WriteAt(file.get(), 0, &oldHeader, sizeof(oldHeader));
                    Truncate(file.get(), oldCommittedSize);
                    FlushFileBuffers(file.get());
                    return {};
                }
                for (const auto& pending : prepared)
                    knownValid.insert(pending.off);
            }
        }

        if (useFresh)
            return WriteFreshFile(a_work, prepared);
        return MapCommittedFile(a_work.basePath, IdentityFor(a_work), knownValid);
    }
}

MappedView::~MappedView()
{
    if (base) UnmapViewOfFile(base);
    if (mapHandle) CloseHandle(static_cast<HANDLE>(mapHandle));
}

DecompCache& DecompCache::GetSingleton()
{
    static DecompCache instance;
    return instance;
}

DecompCache::~DecompCache()
{
    if (m_flushThread.joinable()) {
        // The same flag checked between bounded write chunks also makes DLL/
        // process shutdown prompt instead of waiting for a large cache commit.
        {
            // Pair stop publication with the same mutex used by wait_for so a
            // notify cannot land between its predicate check and atomic wait
            // transition, which would otherwise delay shutdown by 60 seconds.
            std::lock_guard workerLock(m_workerMtx);
            m_loadActive.store(true, std::memory_order_release);
            m_flushThread.request_stop();
        }
        m_workerCv.notify_all();
        m_flushThread.join();
    }
}

void DecompCache::ArchiveCache::Close()
{
    index.clear();
    view.reset();
    activePath.clear();
    onDiskBytes = 0;
    diskInvalidated.store(false, std::memory_order_relaxed);
    needsReplacement = false;
    std::lock_guard lock(pendingMtx);
    pending.clear();
    bufferedOffsets.clear();
}

std::filesystem::path DecompCache::CachePathFor(const MappedArchive* a_archive) const
{
    auto name = a_archive->GetPath().filename().wstring() + L".decomp";
    return m_cachePath / name;
}

void DecompCache::LoadWarmPriority() noexcept
{
    try {
        std::ifstream file(m_cachePath / L"warm_priority.txt");
        if (!file.is_open())
            return;
        std::vector<std::wstring> names;
        std::string line;
        while (std::getline(file, line) && names.size() < 4096) {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                line.pop_back();
            if (line.empty())
                continue;
            const auto wide = MultiByteToWideChar(CP_UTF8, 0,
                line.c_str(), static_cast<int>(line.size()), nullptr, 0);
            if (wide <= 0)
                continue;
            std::wstring name(static_cast<std::size_t>(wide), L'\0');
            MultiByteToWideChar(CP_UTF8, 0, line.c_str(),
                static_cast<int>(line.size()), name.data(), wide);
            names.push_back(std::move(name));
        }
        // First line = most recently served last session = highest rank.
        std::uint64_t rank = names.size();
        for (auto& name : names)
            m_warmPriorityRank.try_emplace(std::move(name), rank--);
        if (!m_warmPriorityRank.empty())
            logger::info("BSAMmap: warm priority loaded for {} archive(s)",
                m_warmPriorityRank.size());
    } catch (...) {
        // Priority is an optimization; an unreadable file means default order.
    }
}

void DecompCache::SaveWarmPriority() noexcept
{
    try {
        std::vector<std::pair<std::wstring, std::uint64_t>> served;
        {
            std::shared_lock cacheLock(m_cacheMtx);
            served.reserve(m_caches.size());
            for (const auto& [archive, cache] : m_caches) {
                const auto last =
                    cache.lastAccessMs.load(std::memory_order_relaxed);
                if (last == 0 || cache.activePath.empty())
                    continue;
                served.emplace_back(cache.activePath.filename().wstring(), last);
            }
        }
        if (served.empty())
            return;
        std::sort(served.begin(), served.end(),
            [](const auto& a_lhs, const auto& a_rhs) {
                return a_lhs.second > a_rhs.second;
            });
        std::ofstream file(m_cachePath / L"warm_priority.txt",
            std::ios::trunc);
        if (!file.is_open())
            return;
        for (const auto& [name, last] : served) {
            const auto narrow = WideCharToMultiByte(CP_UTF8, 0,
                name.c_str(), static_cast<int>(name.size()),
                nullptr, 0, nullptr, nullptr);
            if (narrow <= 0)
                continue;
            std::string utf8(static_cast<std::size_t>(narrow), '\0');
            WideCharToMultiByte(CP_UTF8, 0, name.c_str(),
                static_cast<int>(name.size()), utf8.data(), narrow,
                nullptr, nullptr);
            file << utf8 << '\n';
        }
    } catch (...) {
        // Best-effort persistence only.
    }
}

bool DecompCache::IsCacheFilePath(const std::filesystem::path& a_path)
{
    auto name = a_path.filename().wstring();
    std::transform(name.begin(), name.end(), name.begin(),
        [](wchar_t a_ch) { return static_cast<wchar_t>(std::towlower(a_ch)); });
    return name.ends_with(L".decomp") ||
           name.ends_with(L".gdcache") ||  // retired DirectStorage sidecars
           name.find(L".decomp.tmp.") != std::wstring::npos;
}

std::uint64_t DecompCache::GetFileLastWrite(const std::filesystem::path& a_path)
{
    WIN32_FILE_ATTRIBUTE_DATA attr{};
    if (GetFileAttributesExW(a_path.c_str(), GetFileExInfoStandard, &attr)) {
        return (static_cast<std::uint64_t>(attr.ftLastWriteTime.dwHighDateTime) << 32) |
               attr.ftLastWriteTime.dwLowDateTime;
    }
    return 0;
}

void DecompCache::Initialize(
    const std::filesystem::path& a_dataPath,
    const std::vector<MappedArchive>& a_archives)
{
    {
        std::unique_lock lock(m_cacheMtx);
        m_ready.store(false, std::memory_order_relaxed);
        m_building.store(false, std::memory_order_relaxed);
        m_flushRequested.store(false, std::memory_order_relaxed);
        m_warmRequested.store(false, std::memory_order_relaxed);
        m_prefaultEnabled.store(
            Settings::bPrefaultDecompCache, std::memory_order_relaxed);
        m_warmComplete.store(
            !Settings::bPrefaultDecompCache, std::memory_order_relaxed);
        m_pendingBytes.store(0, std::memory_order_relaxed);
        m_committedReservations.store(0, std::memory_order_relaxed);
        m_totalCacheBytes.store(0, std::memory_order_relaxed);
        m_requiredHeadroom.store(0, std::memory_order_relaxed);
        m_lastOverCapNotifyMs.store(0, std::memory_order_relaxed);
        m_queuedEntries.store(0, std::memory_order_relaxed);
        m_duplicateEntries.store(0, std::memory_order_relaxed);
        m_pendingCapRejects.store(0, std::memory_order_relaxed);
        m_diskCapRejects.store(0, std::memory_order_relaxed);
        m_lookupAttempts.store(0, std::memory_order_relaxed);
        m_lookupHits.store(0, std::memory_order_relaxed);
        m_lookupArchiveMisses.store(0, std::memory_order_relaxed);
        m_lookupInvalidMisses.store(0, std::memory_order_relaxed);
        m_lookupEntryMisses.store(0, std::memory_order_relaxed);
        m_lookupColdMisses.store(0, std::memory_order_relaxed);
        m_lookupColdBytes.store(0, std::memory_order_relaxed);
        m_checksumComputations.store(0, std::memory_order_relaxed);
        m_checksumBytes.store(0, std::memory_order_relaxed);
        m_checksumQpcTicks.store(0, std::memory_order_relaxed);
        m_checksumFailures.store(0, std::memory_order_relaxed);
        m_checksumWaits.store(0, std::memory_order_relaxed);
        m_warmRequests.store(0, std::memory_order_relaxed);
        m_warmPassesStarted.store(0, std::memory_order_relaxed);
        m_warmPassesCompleted.store(0, std::memory_order_relaxed);
        m_warmInterruptedLoad.store(0, std::memory_order_relaxed);
        m_warmInterruptedFlush.store(0, std::memory_order_relaxed);
        m_warmInterruptedEpoch.store(0, std::memory_order_relaxed);
        m_warmInterruptedStop.store(0, std::memory_order_relaxed);
        m_warmIoFailures.store(0, std::memory_order_relaxed);
        m_warmBytesTouched.store(0, std::memory_order_relaxed);
        m_warmQpcTicks.store(0, std::memory_order_relaxed);
        m_lastWarmRequestQpc.store(0, std::memory_order_relaxed);
        m_cacheEpoch.store(0, std::memory_order_relaxed);
        m_warmedBytes.store(0, std::memory_order_relaxed);
        m_caches.clear();
        m_sessionStartMs = GetTickCount64();

        m_cachePath = Settings::sCacheDir.empty() ?
            a_dataPath / L"SKSE" / L"Plugins" / L"FasterFileCopy_cache" :
            std::filesystem::path(Settings::sCacheDir);

        std::error_code ec;
        std::filesystem::create_directories(m_cachePath, ec);
        if (ec) {
            logger::error("BSAMmap: DecompCache cannot create cache directory {} (error {})",
                PathForLog(m_cachePath), ec.value());
            return;
        }

        std::uint32_t loaded = 0;
        std::uint32_t stale = 0;
        for (const auto& archive : a_archives) {
            if (!archive.IsOpen() || archive.GetEntryCount() == 0)
                continue;
            auto& cache = m_caches[&archive];
            cache.bsaFingerprint = archive.GetFingerprint();
            if (cache.bsaFingerprint != 0 && LoadCacheFile(&archive, cache))
                ++loaded;
            else
                ++stale;
        }

        m_ready.store(loaded > 0, std::memory_order_release);
        // Every cache file is intentionally partial. Startup mode therefore
        // learns misses until kDataLoaded on every run, rather than freezing
        // forever merely because each archive has *some* cached entries.
        // Gameplay mode keeps the same gate enabled after that flush.
        m_building.store(true, std::memory_order_release);

        logger::info(
            "BSAMmap: DecompCache initialized: {} loaded, {} stale/missing, gameplay learning {}",
            loaded, stale, Settings::iDecompCacheMode >= 1 ? "continuous" : "startup window");
        // Load last session's serve order before the worker thread exists so
        // the first warm pass touches the archives the player actually uses.
        LoadWarmPriority();
    }

    // Reconciliation sees invalid/outdated/temp generations as unowned. Only
    // successful deletion changes the physical-byte total.
    ReconcileDiskAccounting();
    RemoveUnownedFiles();
    ReconcileDiskAccounting();
    // Hooks are installed only after Initialize returns, so this is the one
    // point where an inherited over-cap cache can be trimmed without any live
    // stream owning its views. The complete remaining cache is what we warm.
    EnforceSizeLimit(true);
    {
        std::shared_lock lock(m_cacheMtx);
        const bool anyUsable = std::ranges::any_of(m_caches, [](const auto& pair) {
            const auto& cache = pair.second;
            return cache.view && !cache.diskInvalidated.load(std::memory_order_acquire);
        });
        m_ready.store(anyUsable, std::memory_order_release);
    }
    logger::info("BSAMmap: DecompCache physical size {:.1f} MB",
        m_totalCacheBytes.load(std::memory_order_relaxed) / (1024.0 * 1024.0));
}

bool DecompCache::LoadCacheFile(const MappedArchive* a_archive, ArchiveCache& a_cache)
{
    const auto path = CachePathFor(a_archive);
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec) || ec)
        return false;
    return LoadCacheFile(a_archive, a_cache, path);
}

bool DecompCache::LoadCacheFile(
    const MappedArchive* a_archive,
    ArchiveCache& a_cache,
    const std::filesystem::path& a_path)
{
    UniqueHandle file(CreateFileW(
        a_path.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    bool writable = file.valid();
    if (!writable) {
        file.reset(CreateFileW(
            a_path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    }
    if (!file.valid()) return false;

    // Cache writers use the same byte-range lock. Holding it makes the
    // header/index snapshot coherent and permits safe tail recovery before
    // this process publishes a mapping.
    ExclusiveFileLock fileLock(file.get(), writable);
    if (writable && !fileLock) {
        file.reset(CreateFileW(
            a_path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        writable = false;
        if (!file.valid()) return false;
    }

    std::uint64_t fileSize = 0;
    if (!GetHandleSize(file.get(), fileSize) ||
        fileSize < sizeof(CacheFormat::Header) ||
        fileSize > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
        return false;

    UniqueHandle mapping(CreateFileMappingW(file.get(), nullptr, PAGE_READONLY, 0, 0, nullptr));
    if (!mapping.valid()) return false;
    UniqueView bytes(static_cast<const std::uint8_t*>(
        MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, 0)));
    if (!bytes.get()) return false;

    const CacheFormat::ArchiveIdentity identity{
        a_archive->GetFileSize(),
        GetFileLastWrite(a_archive->GetPath()),
        a_cache.bsaFingerprint,
        a_archive->GetEntryCount()
    };
    CacheFormat::ValidationResult validation;
    try {
        validation = CacheFormat::Validate(
            bytes.get(), static_cast<std::size_t>(fileSize), &identity,
            CacheFormat::ValidationMode::StructuralOnly, true);
    } catch (const std::exception& e) {
        logger::warn("BSAMmap: DecompCache validation allocation failed for {}: {}",
            PathForLog(a_path.filename()), e.what());
        return false;
    }
    if (!validation) {
        if (validation.error == CacheFormat::ValidationError::UnsupportedVersion) {
            logger::info("BSAMmap: DecompCache version {} is obsolete (expected {}) for {}",
                validation.header.version, CacheFormat::kVersion,
                PathForLog(a_archive->GetPath().filename()));
        } else {
            logger::warn("BSAMmap: DecompCache rejected {}: {} (entry {})",
                PathForLog(a_path.filename()), CacheFormat::ErrorName(validation.error),
                validation.invalidEntry);
        }
        return false;
    }

    const auto originalFileSize = fileSize;
    bool needsReplacement = validation.validSize != fileSize;
    if (needsReplacement && writable) {
        // Windows will not shrink a file below a live section extent. Drop
        // our temporary view first, truncate to the committed prefix, then
        // recreate the read-only mapping that will be published below.
        bytes.reset();
        mapping.reset();
        if (Truncate(file.get(), validation.validSize)) {
            FlushFileBuffers(file.get());
            fileSize = validation.validSize;
            needsReplacement = false;
        }
        mapping.reset(CreateFileMappingW(
            file.get(), nullptr, PAGE_READONLY, 0, 0, nullptr));
        if (!mapping.valid()) return false;
        bytes.reset(static_cast<const std::uint8_t*>(
            MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, 0)));
        if (!bytes.get()) return false;
    }

    auto owner = std::make_shared<MappedView>();
    owner->verificationCount = validation.header.entryCount;
    owner->verification =
        std::make_unique<std::atomic<std::uint8_t>[]>(owner->verificationCount);
    owner->base = bytes.release();
    owner->mapHandle = mapping.release();
    owner->size = fileSize;
    owner->committedSize = validation.validSize;
    owner->prefaultedThrough.store(0, std::memory_order_relaxed);

    std::unordered_map<std::uint32_t, CachedEntry> newIndex;
    newIndex.reserve(validation.header.entryCount);
    for (std::uint32_t i = 0; i < validation.header.entryCount; ++i) {
        CacheFormat::Entry entry{};
        std::memcpy(
            &entry,
            owner->base + sizeof(CacheFormat::Header) +
                static_cast<std::size_t>(i) * sizeof(CacheFormat::Entry),
            sizeof(entry));
        auto& state = owner->verification[i];
        state.store(kVerifyUnknown, std::memory_order_relaxed);
        newIndex.emplace(entry.startOffset, CachedEntry{
            owner->base + entry.cacheOffset,
            entry.decompSize,
            entry.checksum,
            &state
        });
    }

    a_cache.index = std::move(newIndex);
    a_cache.view = std::move(owner);
    a_cache.activePath = a_path;
    a_cache.onDiskBytes = fileSize;
    a_cache.diskInvalidated.store(false, std::memory_order_relaxed);
    a_cache.needsReplacement = needsReplacement;
    m_cacheEpoch.fetch_add(1, std::memory_order_acq_rel);

    if (needsReplacement) {
        logger::warn("BSAMmap: DecompCache found an uncommitted tail in {}; the next append will replace it",
            PathForLog(a_path.filename()));
    } else if (validation.validSize != originalFileSize) {
        logger::info("BSAMmap: DecompCache removed an interrupted append from {}",
            PathForLog(a_path.filename()));
    }
    logger::debug("BSAMmap: DecompCache loaded {} entries for {} (payload checksums lazy)",
        validation.header.entryCount, PathForLog(a_archive->GetPath().filename()));
    return true;
}

LookupResult DecompCache::Lookup(
    const MappedArchive* a_archive,
    std::uint32_t a_startOffset)
{
    const bool measure = Settings::bMeasureStats;
    if (measure)
        m_lookupAttempts.fetch_add(1, std::memory_order_relaxed);

    auto makeResult = [&](const ArchiveCache& a_cache,
                          const CachedEntry& a_entry) -> LookupResult {
        const auto verification = VerifyEntry(a_entry);
        if (measure) {
            if (verification.computed) {
                m_checksumComputations.fetch_add(1, std::memory_order_relaxed);
                m_checksumBytes.fetch_add(a_entry.size, std::memory_order_relaxed);
                m_checksumQpcTicks.fetch_add(
                    verification.qpcTicks, std::memory_order_relaxed);
            }
            if (verification.waited)
                m_checksumWaits.fetch_add(1, std::memory_order_relaxed);
        }
        if (!verification.valid) {
            if (measure)
                m_checksumFailures.fetch_add(1, std::memory_order_relaxed);
            if (a_cache.view) {
                a_cache.view->unusable.store(true, std::memory_order_release);
            }
            if (!a_cache.diskInvalidated.exchange(true, std::memory_order_acq_rel)) {
                m_cacheEpoch.fetch_add(1, std::memory_order_acq_rel);
                logger::error("BSAMmap: DecompCache lazy checksum failed at offset {:X}; invalidating {}",
                    a_startOffset, PathForLog(a_cache.activePath.filename()));
                // Keep the old physical generation until its transactional
                // replacement is committed. Its existing header/index bytes
                // then remain conservatively represented in disk accounting.
                RequestFlush();
                RequestWarmup();
            }
            return {};
        }
        if (measure)
            m_lookupHits.fetch_add(1, std::memory_order_relaxed);
        LookupResult result;
        result.data = a_entry.data;
        result.size = a_entry.size;
        result.owner = a_cache.view;
        return result;
    };

    std::shared_lock lock(m_cacheMtx);
    auto cacheIt = m_caches.find(a_archive);
    if (cacheIt == m_caches.end()) {
        if (measure)
            m_lookupArchiveMisses.fetch_add(1, std::memory_order_relaxed);
        return {};
    }
    if (!cacheIt->second.view ||
        cacheIt->second.view->unusable.load(std::memory_order_acquire) ||
        cacheIt->second.diskInvalidated.load(std::memory_order_acquire)) {
        if (measure)
            m_lookupInvalidMisses.fetch_add(1, std::memory_order_relaxed);
        return {};
    }
    auto entryIt = cacheIt->second.index.find(a_startOffset);
    if (entryIt == cacheIt->second.index.end()) {
        if (measure)
            m_lookupEntryMisses.fetch_add(1, std::memory_order_relaxed);
        return {};
    }
    // Expanded cache data is only useful as the fast path after the managed
    // warm pass has explicitly faulted the complete entry. Until then, let the
    // native compressed stream run rather than risk reading a larger cold file.
    const auto& owner = cacheIt->second.view;
    const auto baseAddress = reinterpret_cast<std::uintptr_t>(owner->base);
    const auto dataAddress = reinterpret_cast<std::uintptr_t>(entryIt->second.data);
    if (dataAddress < baseAddress) {
        if (measure)
            m_lookupInvalidMisses.fetch_add(1, std::memory_order_relaxed);
        return {};
    }
    const auto dataOffset = static_cast<std::uint64_t>(dataAddress - baseAddress);
    if (Settings::bPrefaultDecompCache && !CacheWarmPolicy::IsRangeWarm(
            dataOffset, entryIt->second.size, owner->committedSize,
            owner->prefaultedThrough.load(std::memory_order_acquire))) {
        if (measure) {
            m_lookupColdMisses.fetch_add(1, std::memory_order_relaxed);
            m_lookupColdBytes.fetch_add(
                entryIt->second.size, std::memory_order_relaxed);
        }
        return {};
    }
    cacheIt->second.lastAccessMs.store(GetTickCount64(), std::memory_order_relaxed);
    return makeResult(cacheIt->second, entryIt->second);
}

void DecompCache::ReportMappingIoFailure(
    const std::shared_ptr<MappedView>& a_owner)
{
    if (!a_owner) return;
    a_owner->unusable.store(true, std::memory_order_release);
    bool newlyInvalidated = false;
    {
        std::shared_lock cacheLock(m_cacheMtx);
        for (auto& [archive, cache] : m_caches) {
            if (cache.view == a_owner) {
                newlyInvalidated = !cache.diskInvalidated.exchange(
                    true, std::memory_order_acq_rel);
                break;
            }
        }
    }
    if (newlyInvalidated) {
        m_cacheEpoch.fetch_add(1, std::memory_order_acq_rel);
        RequestFlush();
        RequestWarmup();
    }
}

void DecompCache::ReportCacheValidationFailure(
    const std::shared_ptr<MappedView>& a_owner)
{
    // Structural validation succeeded when the file was mapped, but a live BSA
    // invariant disproved an entry. Retire the complete cache generation using
    // the same transactional path as a mapping fault; no sibling entry from a
    // suspect file may remain eligible for delivery.
    ReportMappingIoFailure(a_owner);
}

void DecompCache::RecordDecompressed(
    const MappedArchive* a_archive,
    std::uint32_t a_startOffset,
    const void* a_data,
    std::uint32_t a_size)
{
    if (!m_building.load(std::memory_order_acquire) || !a_data || a_size == 0 ||
        a_size > CacheFormat::kMaxPayloadSize) return;
    std::vector<std::uint8_t> payload(a_size);
    std::memcpy(payload.data(), a_data, a_size);
    RecordDecompressed(a_archive, a_startOffset, std::move(payload));
}

void DecompCache::RecordDecompressed(
    const MappedArchive* a_archive,
    std::uint32_t a_startOffset,
    std::vector<std::uint8_t>&& a_payload)
{
    if (!m_building.load(std::memory_order_acquire) || !a_archive ||
        a_payload.empty() ||
        a_payload.size() > CacheFormat::kMaxPayloadSize)
        return;
    const auto size = static_cast<std::uint32_t>(a_payload.size());
    try {
        std::shared_lock cacheLock(m_cacheMtx);
        if (!m_building.load(std::memory_order_acquire)) return;
        auto cacheIt = m_caches.find(a_archive);
        if (cacheIt == m_caches.end()) return;
        auto& cache = cacheIt->second;

        const bool generationInvalid =
            cache.diskInvalidated.load(std::memory_order_acquire);
        auto existing = cache.index.find(a_startOffset);
        if (!generationInvalid && existing != cache.index.end() &&
            existing->second.verification &&
            existing->second.verification->load(std::memory_order_acquire) != kVerifyInvalid) {
            m_duplicateEntries.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        std::lock_guard pendingLock(cache.pendingMtx);
        if (cache.bufferedOffsets.contains(a_startOffset)) {
            m_duplicateEntries.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        // A brand-new per-BSA cache reserves its fixed header/index footprint
        // with the first buffered entry. This closes the old cap hole where
        // payload admission fit but the on-disk reserved index pushed the file
        // (and therefore the full-RAM warm set) past the 25% ceiling.
        std::uint64_t fixedOverhead = 0;
        if ((!cache.view || generationInvalid) && cache.bufferedOffsets.empty()) {
            const auto indexBytes =
                static_cast<std::uint64_t>(a_archive->GetEntryCount()) *
                sizeof(CacheFormat::Entry);
            if (!AddChecked(sizeof(CacheFormat::Header), indexBytes, fixedOverhead)) {
                m_diskCapRejects.fetch_add(1, std::memory_order_relaxed);
                return;
            }
        }
        std::uint64_t admissionBytes = 0;
        if (!AddChecked(size, fixedOverhead, admissionBytes)) {
            m_diskCapRejects.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        const std::uint64_t diskCap = Settings::uDecompCacheMaxBytes;
        {
            // Keep the disk-total/pending handoff and this admission decision
            // in one ordering domain. Otherwise a recorder could observe the
            // post-transfer pending value with the pre-transfer disk total.
            std::lock_guard accountingLock(m_accountingMtx);
            const auto buffered = m_pendingBytes.load(std::memory_order_acquire);
            if (buffered > kMaxPendingMemoryBytes ||
                admissionBytes > kMaxPendingMemoryBytes - buffered) {
                m_pendingCapRejects.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            const auto disk = m_totalCacheBytes.load(std::memory_order_relaxed);
            if (diskCap == 0 || disk >= diskCap || buffered > diskCap - disk ||
                admissionBytes > diskCap - disk - buffered) {
                m_diskCapRejects.fetch_add(1, std::memory_order_relaxed);
                if (diskCap > 0 && admissionBytes <= diskCap) {
                    // EnforceSizeLimit subtracts this value from the cap to
                    // produce its target. Reserve the complete future demand,
                    // not merely today's deficit, or a near-cap cache can be
                    // "under target" without ever making the entry admissible.
                    const auto required = CacheLimitPolicy::RequiredHeadroom(
                        diskCap, buffered, admissionBytes);
                    auto requested = m_requiredHeadroom.load(std::memory_order_relaxed);
                    while (requested < required &&
                           !m_requiredHeadroom.compare_exchange_weak(
                               requested, required,
                               std::memory_order_acq_rel, std::memory_order_relaxed)) {
                    }
                    const auto nowMs = GetTickCount64();
                    auto lastMs = m_lastOverCapNotifyMs.load(std::memory_order_relaxed);
                    if ((lastMs == 0 || nowMs - lastMs >= kColdMs) &&
                        m_lastOverCapNotifyMs.compare_exchange_strong(
                            lastMs, nowMs, std::memory_order_acq_rel,
                            std::memory_order_relaxed)) {
                        RequestFlush();
                    }
                }
                return;
            }
            m_pendingBytes.fetch_add(admissionBytes, std::memory_order_acq_rel);
        }

        bool reservationHeld = true;
        const auto releaseReservation = [&]() noexcept {
            if (reservationHeld) {
                m_pendingBytes.fetch_sub(admissionBytes, std::memory_order_acq_rel);
                reservationHeld = false;
            }
        };

        bool markerInserted = false;
        try {
            markerInserted = cache.bufferedOffsets.insert(a_startOffset).second;
            if (!markerInserted) {
                m_duplicateEntries.fetch_add(1, std::memory_order_relaxed);
                releaseReservation();
                return;
            }
            cache.pending.push_back({
                a_startOffset, admissionBytes, std::move(a_payload) });
        } catch (...) {
            if (markerInserted) cache.bufferedOffsets.erase(a_startOffset);
            releaseReservation();
            throw;
        }
        cache.lastAccessMs.store(GetTickCount64(), std::memory_order_relaxed);
        m_queuedEntries.fetch_add(1, std::memory_order_relaxed);
        reservationHeld = false;  // pending queue now owns this reservation
        if (m_pendingBytes.load(std::memory_order_relaxed) >= kFlushWakeBytes) {
            RequestFlush();
        }
    } catch (...) {
        throw;
    }
}

DecompCacheDiagnostics DecompCache::GetDiagnostics() const noexcept
{
    return {
        m_queuedEntries.load(std::memory_order_relaxed),
        m_duplicateEntries.load(std::memory_order_relaxed),
        m_pendingCapRejects.load(std::memory_order_relaxed),
        m_diskCapRejects.load(std::memory_order_relaxed),
        m_lookupAttempts.load(std::memory_order_relaxed),
        m_lookupHits.load(std::memory_order_relaxed),
        m_lookupArchiveMisses.load(std::memory_order_relaxed),
        m_lookupInvalidMisses.load(std::memory_order_relaxed),
        m_lookupEntryMisses.load(std::memory_order_relaxed),
        m_lookupColdMisses.load(std::memory_order_relaxed),
        m_lookupColdBytes.load(std::memory_order_relaxed),
        m_checksumComputations.load(std::memory_order_relaxed),
        m_checksumBytes.load(std::memory_order_relaxed),
        m_checksumQpcTicks.load(std::memory_order_relaxed),
        m_checksumFailures.load(std::memory_order_relaxed),
        m_checksumWaits.load(std::memory_order_relaxed),
        m_warmRequests.load(std::memory_order_relaxed),
        m_warmPassesStarted.load(std::memory_order_relaxed),
        m_warmPassesCompleted.load(std::memory_order_relaxed),
        m_warmInterruptedLoad.load(std::memory_order_relaxed),
        m_warmInterruptedFlush.load(std::memory_order_relaxed),
        m_warmInterruptedEpoch.load(std::memory_order_relaxed),
        m_warmInterruptedStop.load(std::memory_order_relaxed),
        m_warmIoFailures.load(std::memory_order_relaxed),
        m_warmBytesTouched.load(std::memory_order_relaxed),
        m_warmQpcTicks.load(std::memory_order_relaxed)
    };
}

DecompCacheBenchmarkSnapshot DecompCache::GetBenchmarkSnapshot(
    const bool a_measureResidency) const
{
    struct ResidentRange
    {
        std::shared_ptr<MappedView> owner;
        std::uint64_t bytes{ 0 };
    };

    DecompCacheBenchmarkSnapshot result{};
    result.diagnostics = GetDiagnostics();
    result.physicalBytes = m_totalCacheBytes.load(std::memory_order_relaxed);
    result.pendingBytes = m_pendingBytes.load(std::memory_order_relaxed);
    result.prefaultEnabled =
        m_prefaultEnabled.load(std::memory_order_acquire);
    result.warmComplete = result.prefaultEnabled &&
        m_warmComplete.load(std::memory_order_acquire);

    std::vector<ResidentRange> ranges;
    {
        std::shared_lock cacheLock(m_cacheMtx);
        ranges.reserve(m_caches.size());
        for (const auto& [archive, cache] : m_caches) {
            (void)archive;
            if (!cache.view || !cache.view->base ||
                cache.view->unusable.load(std::memory_order_acquire) ||
                cache.diskInvalidated.load(std::memory_order_acquire)) {
                continue;
            }

            const auto committed = (std::min)(
                cache.view->committedSize, cache.view->size);
            if (committed == 0)
                continue;
            const auto warmed = (std::min)(
                cache.view->prefaultedThrough.load(std::memory_order_acquire),
                committed);
            result.mappingCount += 1;
            result.selectedMappingBytes += committed;
            result.historicallyWarmedBytes += warmed;
            ranges.push_back({ cache.view, committed });

            const auto baseAddress =
                reinterpret_cast<std::uintptr_t>(cache.view->base);
            for (const auto& [offset, entry] : cache.index) {
                (void)offset;
                result.entryCount += 1;
                result.payloadBytes += entry.size;
                if (entry.verification &&
                    entry.verification->load(std::memory_order_acquire) ==
                        kVerifyValid) {
                    result.verifiedEntryCount += 1;
                    result.verifiedPayloadBytes += entry.size;
                }
                const auto dataAddress =
                    reinterpret_cast<std::uintptr_t>(entry.data);
                if (dataAddress < baseAddress)
                    continue;
                const auto dataOffset = static_cast<std::uint64_t>(
                    dataAddress - baseAddress);
                const bool eligible = !Settings::bPrefaultDecompCache ||
                    CacheWarmPolicy::IsRangeWarm(
                        dataOffset, entry.size, committed, warmed);
                if (eligible) {
                    result.eligibleEntryCount += 1;
                    result.eligiblePayloadBytes += entry.size;
                }
            }
        }
    }

    // The deterministic benchmark checkpoint must also prove residency in
    // timing-only runs. The caller keeps this scan outside the load timer;
    // normal gameplay never requests it merely because statistics are off.
    if (!a_measureResidency || ranges.empty())
        return result;

    SYSTEM_INFO systemInfo{};
    GetSystemInfo(&systemInfo);
    const auto pageSize = static_cast<std::uint64_t>(systemInfo.dwPageSize);
    if (pageSize == 0)
        return result;

    constexpr std::size_t kResidencyBatchPages = 16384;
    std::vector<PSAPI_WORKING_SET_EX_INFORMATION> pages;
    std::vector<std::uint32_t> pageBytes;
    pages.reserve(kResidencyBatchPages);
    pageBytes.reserve(kResidencyBatchPages);

    LARGE_INTEGER started{}, finished{}, frequency{};
    QueryPerformanceCounter(&started);
    bool queryOk = true;
    const auto queryBatch = [&]() {
        if (pages.empty())
            return true;
        const auto bytes = pages.size() * sizeof(pages.front());
        if (bytes > (std::numeric_limits<DWORD>::max)() ||
            !K32QueryWorkingSetEx(
                GetCurrentProcess(), pages.data(), static_cast<DWORD>(bytes))) {
            return false;
        }
        for (std::size_t i = 0; i < pages.size(); ++i) {
            result.totalPages += 1;
            if (pages[i].VirtualAttributes.Valid) {
                result.residentPages += 1;
                result.residentBytes += pageBytes[i];
            }
        }
        pages.clear();
        pageBytes.clear();
        return true;
    };

    for (const auto& range : ranges) {
        for (std::uint64_t offset = 0; offset < range.bytes;
             offset += pageSize) {
            PSAPI_WORKING_SET_EX_INFORMATION page{};
            page.VirtualAddress = const_cast<std::uint8_t*>(
                range.owner->base + offset);
            pages.push_back(page);
            pageBytes.push_back(static_cast<std::uint32_t>((std::min)(
                pageSize, range.bytes - offset)));
            if (pages.size() == kResidencyBatchPages && !queryBatch()) {
                queryOk = false;
                break;
            }
        }
        if (!queryOk)
            break;
    }
    if (queryOk)
        queryOk = queryBatch();

    QueryPerformanceCounter(&finished);
    QueryPerformanceFrequency(&frequency);
    if (frequency.QuadPart > 0 && finished.QuadPart >= started.QuadPart) {
        result.residencyQueryMicros = static_cast<std::uint64_t>(
            (finished.QuadPart - started.QuadPart) * 1'000'000ll /
            frequency.QuadPart);
    }
    result.residencyMeasured = queryOk;
    if (!queryOk) {
        result.residentBytes = 0;
        result.residentPages = 0;
        result.totalPages = 0;
    }
    return result;
}

void DecompCache::FlushToDisk()
{
    std::lock_guard flushLock(m_flushMtx);
    if (m_loadActive.load(std::memory_order_acquire)) return;

    const bool startupOnly = Settings::iDecompCacheMode == 0;
    if (startupOnly) {
        // Stop capture first, then take the exclusive cache lock below. Any
        // recorder that passed its first check must re-check after that barrier.
        m_building.store(false, std::memory_order_release);
    } else if (!m_building.load(std::memory_order_acquire)) {
        return;
    }

    if (Settings::uDecompCacheMaxBytes > 0 &&
        !m_loadActive.load(std::memory_order_acquire) &&
        (m_requiredHeadroom.load(std::memory_order_acquire) > 0 ||
         m_totalCacheBytes.load(std::memory_order_relaxed) >=
            Settings::uDecompCacheMaxBytes))
        EnforceSizeLimit(true);

    // A generation that failed checksum or mapped I/O must not poison every
    // future launch when no replacement payload is currently queued. Remove
    // only the still-current, idle file; shared_ptr owners keep any in-flight
    // mapping object alive, but its `unusable` flag prevents another read.
    std::uint32_t invalidRemoved = 0;
    {
        std::unique_lock cacheLock(m_cacheMtx);
        for (auto& [archive, cache] : m_caches) {
            if (m_loadActive.load(std::memory_order_acquire)) break;
            std::lock_guard pendingLock(cache.pendingMtx);
            if (!cache.diskInvalidated.load(std::memory_order_acquire) ||
                !cache.pending.empty() || !cache.bufferedOffsets.empty())
                continue;

            bool removed = cache.activePath.empty();
            DWORD removeError = ERROR_SUCCESS;
            if (!removed) {
                removed = DeleteFileW(cache.activePath.c_str()) != FALSE;
                if (!removed) {
                    removeError = GetLastError();
                    if (removeError == ERROR_FILE_NOT_FOUND) removed = true;
                }
            }
            if (!removed) {
                logger::warn(
                    "BSAMmap: DecompCache could not retire invalid generation {} (error {})",
                    PathForLog(cache.activePath.filename()), removeError);
                continue;
            }

            cache.index.clear();
            cache.view.reset();
            cache.activePath.clear();
            cache.onDiskBytes = 0;
            cache.diskInvalidated.store(false, std::memory_order_release);
            cache.needsReplacement = false;
            m_cacheEpoch.fetch_add(1, std::memory_order_acq_rel);
            ++invalidRemoved;
        }
        if (invalidRemoved > 0) {
            const bool anyUsable = std::ranges::any_of(
                m_caches, [](const auto& pair) {
                    const auto& cache = pair.second;
                    return cache.view && !cache.diskInvalidated.load(
                        std::memory_order_acquire);
                });
            m_ready.store(anyUsable, std::memory_order_release);
        }
    }
    if (invalidRemoved > 0) {
        logger::info("BSAMmap: DecompCache retired {} invalid cache generation(s)",
            invalidRemoved);
        RequestWarmup();
    }

    std::vector<OLWork> work;
    try {
        std::unique_lock cacheLock(m_cacheMtx);
        // Two-phase snapshot: finish every allocation for every archive before
        // moving the first payload. An exception in path/set/vector setup then
        // leaves all transactional queues and accounting untouched.
        work.reserve(m_caches.size());
        for (auto& [archive, cache] : m_caches) {
            std::lock_guard pendingLock(cache.pendingMtx);
            if (cache.pending.empty()) continue;

            work.emplace_back();
            auto& item = work.back();
            item.archive = archive;
            item.basePath = CachePathFor(archive);
            item.bsaFileSize = archive->GetFileSize();
            item.bsaLastWrite = GetFileLastWrite(archive->GetPath());
            item.bsaFingerprint = cache.bsaFingerprint;
            item.bsaEntryCount = archive->GetEntryCount();
            item.cancel = &m_loadActive;
            item.resetFile = cache.diskInvalidated.load(std::memory_order_acquire) ||
                             cache.needsReplacement || !cache.view ||
                             cache.activePath != item.basePath;
            if (!item.resetFile) item.sourceView = cache.view;
            if (!item.resetFile) {
                item.verifiedOffsets.reserve(cache.index.size());
                for (const auto& [off, entry] : cache.index) {
                    if (entry.verification &&
                        entry.verification->load(std::memory_order_acquire) == kVerifyValid)
                        item.verifiedOffsets.insert(off);
                }
            }
            item.pending.reserve(cache.pending.size());
        }

        // All destination capacities now exist. Moves below are allocation-
        // free; the exclusive cache lock prevents recorders from changing a
        // pending queue between the planning and transfer passes.
        for (auto& item : work) {
            auto cacheIt = m_caches.find(item.archive);
            if (cacheIt == m_caches.end()) {
                continue;
            }
            auto& cache = cacheIt->second;
            std::lock_guard pendingLock(cache.pendingMtx);
            for (auto& pending : cache.pending)
                item.pending.push_back({ pending.startOffset,
                    pending.accountedBytes, std::move(pending.data) });
            cache.pending.clear();
        }
    } catch (const std::exception& e) {
        try {
            logger::warn(
                "BSAMmap: DecompCache could not plan a flush; pending data retained: {}",
                e.what());
        } catch (...) {
            OutputDebugStringA("FasterFileCopy: cache flush planning failed\n");
        }
        return;
    } catch (...) {
        OutputDebugStringA("FasterFileCopy: cache flush planning failed\n");
        return;
    }

    std::uint32_t filesWritten = 0;
    std::uint64_t bytesCommitted = 0;
    for (auto& item : work) {
        OLResult result;
        if (!m_loadActive.load(std::memory_order_acquire)) {
            try {
                result = AppendFile(item);
            } catch (const std::exception& e) {
                logger::error("BSAMmap: DecompCache flush failed for {}: {}",
                    PathForLog(item.basePath.filename()), e.what());
            } catch (...) {
                logger::error("BSAMmap: DecompCache flush failed for {} with unknown exception",
                    PathForLog(item.basePath.filename()));
            }
        }

        std::unique_lock cacheLock(m_cacheMtx);
        auto cacheIt = m_caches.find(item.archive);
        if (cacheIt == m_caches.end()) {
            continue;
        }
        auto& cache = cacheIt->second;
        std::lock_guard pendingLock(cache.pendingMtx);

        if (result.ok && !item.resetFile &&
            (cache.view != item.sourceView ||
             cache.diskInvalidated.load(std::memory_order_acquire))) {
            logger::warn(
                "BSAMmap: DecompCache append result for {} became stale after source invalidation; pending entries retained for fresh replacement",
                PathForLog(item.basePath.filename()));
            result = {};
        }

        if (result.ok) {
            cache.view = std::move(result.view);
            cache.index = std::move(result.index);
            cache.activePath = std::move(item.basePath);
            cache.onDiskBytes = result.fileSize;
            cache.diskInvalidated.store(false, std::memory_order_release);
            cache.needsReplacement = false;
            m_cacheEpoch.fetch_add(1, std::memory_order_acq_rel);

            std::uint64_t committed = 0;
            for (const auto& pending : item.pending) {
                cache.bufferedOffsets.erase(pending.off);
                committed += pending.accountedBytes;
            }
            // The committed mapping now owns the bytes. Destroy the moved
            // payload vectors immediately so the 256 MiB pending-memory bound
            // remains a real allocation bound while accounting is reconciled.
            item.pending.clear();
            // Keep the charge in m_pendingBytes until a complete directory
            // scan transfers authority to m_totalCacheBytes. Releasing it here
            // would briefly undercount both sides of the hard-cap equation.
            {
                std::lock_guard accountingLock(m_accountingMtx);
                m_committedReservations.fetch_add(
                    committed, std::memory_order_acq_rel);
            }
            bytesCommitted += committed;
            ++filesWritten;
            m_ready.store(true, std::memory_order_release);
        } else {
            // Transactional rollback: ownership returns to the pending queue.
            // bufferedOffsets and m_pendingBytes deliberately remain unchanged.
            try {
                cache.pending.reserve(cache.pending.size() + item.pending.size());
            } catch (...) {
                // An out-of-memory failure cannot be requeued without storage.
                // Repair ownership/accounting so these offsets can be learned
                // again instead of remaining permanently charged and blocked.
                std::uint64_t released = 0;
                std::uint64_t fixedOverhead = 0;
                for (const auto& pending : item.pending) {
                    cache.bufferedOffsets.erase(pending.off);
                    released += pending.accountedBytes;
                    const auto payloadBytes =
                        static_cast<std::uint64_t>(pending.data.size());
                    if (pending.accountedBytes > payloadBytes)
                        fixedOverhead += pending.accountedBytes - payloadBytes;
                }
                // A later recorder may have queued entries while the failed
                // transaction was off-lock. Transfer the absent file's sole
                // header/index reservation to one survivor before dropping the
                // original owner, or the future file could exceed the cap.
                if (fixedOverhead > 0 &&
                    (!cache.view || cache.diskInvalidated.load(
                        std::memory_order_acquire)) &&
                    !cache.pending.empty()) {
                    std::uint64_t transferred = 0;
                    if (AddChecked(cache.pending.front().accountedBytes,
                            fixedOverhead, transferred)) {
                        cache.pending.front().accountedBytes = transferred;
                        released -= fixedOverhead;
                    }
                }
                m_pendingBytes.fetch_sub(released, std::memory_order_acq_rel);
                logger::error(
                    "BSAMmap: DecompCache rollback allocation failed for {}; {} entry/entries released for recapture",
                    PathForLog(item.basePath.filename()), item.pending.size());
                continue;
            }
            for (auto& pending : item.pending)
                cache.pending.push_back({ pending.off, pending.accountedBytes,
                    std::move(pending.data) });
        }
    }

    if (!m_loadActive.load(std::memory_order_acquire)) {
        ReconcileDiskAccounting();
        if (!m_loadActive.load(std::memory_order_acquire) &&
            Settings::uDecompCacheMaxBytes > 0)
            EnforceSizeLimit(true);
    }

    if (filesWritten > 0) {
        logger::info("BSAMmap: DecompCache appended {:.1f} MB across {} archive(s)",
            bytesCommitted / (1024.0 * 1024.0), filesWritten);
        RequestWarmup();
    }

    // Persist this session's serve order so the next launch warms the most
    // recently used archives first.
    SaveWarmPriority();

    if (startupOnly) {
        // Capture remains stopped. A failed write stays pending and a later
        // explicit FlushToDisk call can retry it without data loss.
    }
}

bool DecompCache::HasPending() const
{
    if (m_pendingBytes.load(std::memory_order_relaxed) == 0)
        return false;
    std::shared_lock cacheLock(m_cacheMtx);
    for (const auto& [archive, cache] : m_caches) {
        std::lock_guard pendingLock(cache.pendingMtx);
        if (!cache.pending.empty()) return true;
    }
    return false;
}

bool DecompCache::HasInvalidGeneration() const
{
    std::shared_lock cacheLock(m_cacheMtx);
    return std::ranges::any_of(m_caches, [](const auto& pair) {
        return pair.second.diskInvalidated.load(std::memory_order_acquire);
    });
}

void DecompCache::RequestFlush()
{
    bool notify = false;
    {
        // Sharing the wait mutex closes the predicate-check/wait gap. Coalesce
        // repeated requests while one is already pending so the 32 MiB
        // threshold does not turn every newly queued entry into a notify.
        std::lock_guard workerLock(m_workerMtx);
        notify = !m_flushRequested.exchange(true, std::memory_order_acq_rel);
    }
    if (notify) {
        m_workerCv.notify_all();
    }
}

void DecompCache::RequestWarmup()
{
    if (!Settings::bPrefaultDecompCache) {
        m_warmedBytes.store(0, std::memory_order_release);
        m_warmComplete.store(true, std::memory_order_release);
        return;
    }
    if (Settings::bMeasureStats)
        m_warmRequests.fetch_add(1, std::memory_order_relaxed);
    bool notify = false;
    {
        std::lock_guard workerLock(m_workerMtx);
        m_warmComplete.store(false, std::memory_order_release);
        notify = !m_warmRequested.exchange(true, std::memory_order_acq_rel);
        if (notify && Settings::bMeasureStats) {
            LARGE_INTEGER now{};
            QueryPerformanceCounter(&now);
            m_lastWarmRequestQpc.store(
                static_cast<std::uint64_t>(now.QuadPart),
                std::memory_order_relaxed);
        }
    }
    if (notify) {
        m_workerCv.notify_all();
    }
}

void DecompCache::WarmMappedCaches(std::stop_token a_stop)
{
    if (!Settings::bPrefaultDecompCache) {
        m_warmedBytes.store(0, std::memory_order_release);
        m_warmComplete.store(true, std::memory_order_release);
        return;
    }

    const bool measure = Settings::bMeasureStats;
    const auto availablePhysicalBytes = []() noexcept {
        MEMORYSTATUSEX status{};
        status.dwLength = sizeof(status);
        return GlobalMemoryStatusEx(&status)
            ? static_cast<std::uint64_t>(status.ullAvailPhys)
            : std::uint64_t{ 0 };
    };
    const auto availableAtPassStart = availablePhysicalBytes();
    const auto passId = measure
        ? m_warmPassesStarted.fetch_add(1, std::memory_order_relaxed) + 1
        : 0;
    LARGE_INTEGER passStartedQpc{}, qpcFrequency{};
    QueryPerformanceCounter(&passStartedQpc);
    QueryPerformanceFrequency(&qpcFrequency);
    const auto requestQpc = m_lastWarmRequestQpc.load(std::memory_order_relaxed);
    const auto finishPass = [&](const char* a_status,
                                std::atomic<std::uint64_t>* a_counter,
                                const std::uint64_t a_touched) {
        LARGE_INTEGER now{};
        QueryPerformanceCounter(&now);
        const auto ticks = now.QuadPart >= passStartedQpc.QuadPart
            ? static_cast<std::uint64_t>(now.QuadPart - passStartedQpc.QuadPart)
            : 0;
        if (measure) {
            m_warmQpcTicks.fetch_add(ticks, std::memory_order_relaxed);
            if (a_counter)
                a_counter->fetch_add(1, std::memory_order_relaxed);
            const double activeMs = qpcFrequency.QuadPart > 0
                ? ticks * 1000.0 / qpcFrequency.QuadPart : 0.0;
            const auto availableAtPassEnd = availablePhysicalBytes();
            const double availableDeltaMiB =
                (static_cast<double>(availableAtPassEnd) -
                    static_cast<double>(availableAtPassStart)) /
                static_cast<double>(kBytesPerMB);
            logger::info(
                "BSAMmap: BENCH WARM_PASS run={} pass={} status={} active_ms={:.3f} covered_mib={:.3f} available_start_mib={:.3f} available_end_mib={:.3f} available_delta_mib={:.3f}",
                Settings::sBenchmarkRunTag.empty() ? "none" :
                    Settings::sBenchmarkRunTag,
                passId, a_status, activeMs,
                a_touched / static_cast<double>(kBytesPerMB),
                availableAtPassStart / static_cast<double>(kBytesPerMB),
                availableAtPassEnd / static_cast<double>(kBytesPerMB),
                availableDeltaMiB);
        }
    };

    struct WarmItem
    {
        const MappedArchive* archive{ nullptr };
        std::shared_ptr<MappedView> owner;
        std::filesystem::path path;
        std::uint64_t lastAccess{ 0 };
    };

    const auto epoch = m_cacheEpoch.load(std::memory_order_acquire);
    const auto publishFailure = [this, epoch, a_stop]() {
        std::lock_guard workerLock(m_workerMtx);
        if (epoch == m_cacheEpoch.load(std::memory_order_acquire) &&
            !m_warmRequested.load(std::memory_order_acquire) &&
            !m_flushRequested.load(std::memory_order_acquire) &&
            !m_loadActive.load(std::memory_order_acquire) &&
            !a_stop.stop_requested()) {
            m_warmedBytes.store(0, std::memory_order_release);
            m_warmComplete.store(false, std::memory_order_release);
        }
    };
    const auto publishComplete =
        [this, epoch, a_stop](std::uint64_t a_bytes) {
        std::lock_guard workerLock(m_workerMtx);
        if (epoch != m_cacheEpoch.load(std::memory_order_acquire) ||
            m_warmRequested.load(std::memory_order_acquire) ||
            m_flushRequested.load(std::memory_order_acquire) ||
            m_loadActive.load(std::memory_order_acquire) ||
            a_stop.stop_requested())
            return false;
        m_warmedBytes.store(a_bytes, std::memory_order_release);
        m_warmComplete.store(true, std::memory_order_release);
        return true;
    };
    std::vector<WarmItem> items;
    std::uint64_t committedBytes = 0;
    std::uint64_t remainingBytes = 0;
    bool accountingOverflow = false;
    try {
        std::shared_lock cacheLock(m_cacheMtx);
        items.reserve(m_caches.size());
        for (const auto& [archive, cache] : m_caches) {
            if (!cache.view || !cache.view->base ||
                cache.diskInvalidated.load(std::memory_order_acquire))
                continue;
            const auto committed = (std::min)(
                cache.view->committedSize, cache.view->size);
            if (committed == 0) continue;
            const auto warmed = (std::min)(
                cache.view->prefaultedThrough.load(std::memory_order_acquire),
                committed);
            if (!AddChecked(committedBytes, committed, committedBytes) ||
                !AddChecked(remainingBytes, committed - warmed, remainingBytes)) {
                accountingOverflow = true;
                break;
            }
            auto lastAccess =
                cache.lastAccessMs.load(std::memory_order_relaxed);
            if (lastAccess == 0 && !cache.activePath.empty()) {
                // Nothing served yet this session (e.g. the first warm pass
                // right after launch): fall back to last session's serve
                // order. Ranks are tiny versus GetTickCount64, so any live
                // access this session still outranks them.
                if (const auto rank = m_warmPriorityRank.find(
                        cache.activePath.filename().wstring());
                    rank != m_warmPriorityRank.end()) {
                    lastAccess = rank->second;
                }
            }
            items.push_back({ archive, cache.view, cache.activePath,
                lastAccess });
        }
    } catch (const std::exception& e) {
        logger::warn("BSAMmap: cache RAM warmup snapshot failed: {}", e.what());
        publishFailure();
        finishPass("snapshot_error", nullptr, 0);
        return;
    } catch (...) {
        logger::warn("BSAMmap: cache RAM warmup snapshot failed");
        publishFailure();
        finishPass("snapshot_error", nullptr, 0);
        return;
    }

    if (accountingOverflow) {
        logger::error("BSAMmap: cache RAM warmup size accounting overflowed; warm pass disabled");
        publishFailure();
        finishPass("accounting_overflow", nullptr, 0);
        return;
    }

    std::sort(items.begin(), items.end(), [](const WarmItem& a_lhs,
                                             const WarmItem& a_rhs) {
        return a_lhs.lastAccess > a_rhs.lastAccess;
    });
    if (Settings::uDecompCacheMaxBytes == 0 ||
        committedBytes > Settings::uDecompCacheMaxBytes) {
        logger::error(
            "BSAMmap: refusing cache RAM warmup because active mappings exceed the 25% RAM ceiling ({:.1f}/{:.1f} MiB)",
            committedBytes / static_cast<double>(kBytesPerMB),
            Settings::uDecompCacheMaxBytes / static_cast<double>(kBytesPerMB));
        publishFailure();
        finishPass("over_ram_ceiling", nullptr, 0);
        return;
    }
    const auto previouslyWarmed = committedBytes - remainingBytes;
    m_warmedBytes.store(previouslyWarmed, std::memory_order_release);
    SYSTEM_INFO systemInfo{};
    GetSystemInfo(&systemInfo);
    const auto pageSize = static_cast<std::size_t>(systemInfo.dwPageSize);
    if (pageSize == 0) {
        logger::error("BSAMmap: cache RAM warmup could not determine system page size");
        publishFailure();
        finishPass("page_size_error", nullptr, 0);
        return;
    }

    const auto started = std::chrono::steady_clock::now();
    const double queueMs = qpcFrequency.QuadPart > 0 && requestQpc > 0 &&
            static_cast<std::uint64_t>(passStartedQpc.QuadPart) >= requestQpc
        ? (static_cast<std::uint64_t>(passStartedQpc.QuadPart) - requestQpc) *
            1000.0 / qpcFrequency.QuadPart
        : 0.0;
    logger::info(
        "BSAMmap: cache RAM warmup started: {:.1f} MiB remaining across {} mapped archive(s)",
        remainingBytes / static_cast<double>(kBytesPerMB), items.size());
    if (measure) {
        logger::info(
            "BSAMmap: BENCH WARM_START run={} pass={} queue_ms={:.3f} mappings={} committed_mib={:.3f} already_mib={:.3f} remaining_mib={:.3f} available_ram_mib={:.3f}",
            Settings::sBenchmarkRunTag.empty() ? "none" :
                Settings::sBenchmarkRunTag,
            passId, queueMs, items.size(),
            committedBytes / static_cast<double>(kBytesPerMB),
            previouslyWarmed / static_cast<double>(kBytesPerMB),
            remainingBytes / static_cast<double>(kBytesPerMB),
            availableAtPassStart / static_cast<double>(kBytesPerMB));
    }

    std::uint64_t touchedThisPass = 0;
    for (const auto& item : items) {
        const auto committed = (std::min)(
            item.owner->committedSize, item.owner->size);
        auto cursor = (std::min)(
            item.owner->prefaultedThrough.load(std::memory_order_acquire),
            committed);
        while (cursor < committed) {
            if (a_stop.stop_requested()) {
                finishPass("interrupted_stop", &m_warmInterruptedStop,
                    touchedThisPass);
                return;
            }
            if (m_loadActive.load(std::memory_order_acquire)) {
                RequestWarmup();
                finishPass("interrupted_load", &m_warmInterruptedLoad,
                    touchedThisPass);
                return;
            }
            if (m_flushRequested.load(std::memory_order_acquire)) {
                RequestWarmup();
                finishPass("interrupted_flush", &m_warmInterruptedFlush,
                    touchedThisPass);
                return;
            }
            if (epoch != m_cacheEpoch.load(std::memory_order_acquire)) {
                RequestWarmup();
                finishPass("interrupted_epoch", &m_warmInterruptedEpoch,
                    touchedThisPass);
                return;
            }

            const auto chunk = (std::min)(
                kWarmChunkBytes, committed - cursor);
            AdvisePrefetch(item.owner->base, cursor, chunk);
            if (!TouchMappedPages(
                    item.owner->base, cursor, cursor + chunk, pageSize)) {
                logger::error(
                    "BSAMmap: cache RAM warmup hit an in-page I/O failure for {}; disabling that cache generation",
                    PathForLog(item.path.filename()));
                ReportMappingIoFailure(item.owner);
                finishPass("io_failure", &m_warmIoFailures, touchedThisPass);
                return;
            }
            cursor += chunk;
            touchedThisPass += chunk;
            if (measure)
                m_warmBytesTouched.fetch_add(chunk, std::memory_order_relaxed);
            m_warmedBytes.store(
                previouslyWarmed + touchedThisPass, std::memory_order_release);
            item.owner->prefaultedThrough.store(cursor, std::memory_order_release);
            SwitchToThread();
        }
    }

    // Prefaulting already pays the I/O cost to make every payload resident.
    // Verify all still-unknown checksums here as well, outside the save-load
    // timer, so the first cache hit is one memory copy rather than a checksum
    // scan followed by that copy. This also rejects a bad generation before a
    // benchmark or normal delayed load can attach it.
    for (const auto& item : items) {
        if (a_stop.stop_requested()) {
            finishPass("interrupted_stop", &m_warmInterruptedStop,
                touchedThisPass);
            return;
        }
        if (m_loadActive.load(std::memory_order_acquire)) {
            RequestWarmup();
            finishPass("interrupted_load", &m_warmInterruptedLoad,
                touchedThisPass);
            return;
        }
        if (m_flushRequested.load(std::memory_order_acquire)) {
            RequestWarmup();
            finishPass("interrupted_flush", &m_warmInterruptedFlush,
                touchedThisPass);
            return;
        }
        if (epoch != m_cacheEpoch.load(std::memory_order_acquire)) {
            RequestWarmup();
            finishPass("interrupted_epoch", &m_warmInterruptedEpoch,
                touchedThisPass);
            return;
        }

        enum class ValidationFailure : std::uint8_t
        {
            kNone,
            kDeclaredSizeUnavailable,
            kDeclaredSizeMismatch,
            kChecksum
        };
        std::shared_ptr<MappedView> invalidOwner;
        ValidationFailure validationFailure = ValidationFailure::kNone;
        std::uint32_t invalidOffset = 0;
        std::uint32_t cachedSize = 0;
        std::uint32_t declaredSize = 0;
        {
            std::shared_lock cacheLock(m_cacheMtx);
            const auto cacheIt = m_caches.find(item.archive);
            if (cacheIt == m_caches.end() || cacheIt->second.view != item.owner ||
                cacheIt->second.diskInvalidated.load(std::memory_order_acquire)) {
                RequestWarmup();
                finishPass("interrupted_epoch", &m_warmInterruptedEpoch,
                    touchedThisPass);
                return;
            }
            for (const auto& [offset, entry] : cacheIt->second.index) {
                if (a_stop.stop_requested() ||
                    m_loadActive.load(std::memory_order_acquire) ||
                    m_flushRequested.load(std::memory_order_acquire) ||
                    epoch != m_cacheEpoch.load(std::memory_order_acquire)) {
                    break;
                }
                // Prime the archive-generation memo before checksumming the
                // cache payload. A v7 entry is usable only when its complete
                // captured length equals the authoritative BSA prefix. Doing
                // this during prefault keeps original-BSA metadata faults out
                // of the first cache hit and rejects the whole suspect cache
                // generation before any stream can attach it.
                const auto authoritative =
                    item.archive->GetDeclaredDecompressedSize(offset);
                if (!authoritative || *authoritative != entry.size) {
                    invalidOwner = item.owner;
                    validationFailure = authoritative
                        ? ValidationFailure::kDeclaredSizeMismatch
                        : ValidationFailure::kDeclaredSizeUnavailable;
                    invalidOffset = offset;
                    cachedSize = entry.size;
                    declaredSize = authoritative.value_or(0);
                    break;
                }
                const auto verification = VerifyEntry(entry);
                if (measure) {
                    if (verification.computed) {
                        m_checksumComputations.fetch_add(
                            1, std::memory_order_relaxed);
                        m_checksumBytes.fetch_add(
                            entry.size, std::memory_order_relaxed);
                        m_checksumQpcTicks.fetch_add(
                            verification.qpcTicks, std::memory_order_relaxed);
                    }
                    if (verification.waited) {
                        m_checksumWaits.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                if (!verification.valid) {
                    m_checksumFailures.fetch_add(1, std::memory_order_relaxed);
                    invalidOwner = item.owner;
                    validationFailure = ValidationFailure::kChecksum;
                    invalidOffset = offset;
                    break;
                }
            }
        }
        if (invalidOwner) {
            switch (validationFailure) {
            case ValidationFailure::kDeclaredSizeUnavailable:
                logger::error(
                    "BSAMmap: cache RAM warmup could not resolve the BSA-declared decompressed size at 0x{:X} in {}; disabling that cache generation",
                    invalidOffset, PathForLog(item.path.filename()));
                break;
            case ValidationFailure::kDeclaredSizeMismatch:
                logger::error(
                    "BSAMmap: cache RAM warmup found cached size {} != BSA-declared size {} at 0x{:X} in {}; disabling that cache generation",
                    cachedSize, declaredSize, invalidOffset,
                    PathForLog(item.path.filename()));
                break;
            case ValidationFailure::kChecksum:
                logger::error(
                    "BSAMmap: cache RAM warmup found an invalid payload checksum at 0x{:X} in {}; disabling that cache generation",
                    invalidOffset, PathForLog(item.path.filename()));
                break;
            case ValidationFailure::kNone:
                break;
            }
            ReportCacheValidationFailure(invalidOwner);
            finishPass(
                validationFailure == ValidationFailure::kChecksum
                    ? "checksum_failure" : "declared_size_failure",
                nullptr, touchedThisPass);
            return;
        }
        if (a_stop.stop_requested() ||
            m_loadActive.load(std::memory_order_acquire) ||
            m_flushRequested.load(std::memory_order_acquire) ||
            epoch != m_cacheEpoch.load(std::memory_order_acquire)) {
            RequestWarmup();
            finishPass("interrupted_epoch", &m_warmInterruptedEpoch,
                touchedThisPass);
            return;
        }
    }

    if (epoch != m_cacheEpoch.load(std::memory_order_acquire) ||
        m_warmRequested.load(std::memory_order_acquire)) {
        RequestWarmup();
        finishPass("interrupted_epoch", &m_warmInterruptedEpoch,
            touchedThisPass);
        return;
    }

    const auto elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - started).count();
    if (!publishComplete(committedBytes)) {
        RequestWarmup();
        if (m_loadActive.load(std::memory_order_acquire)) {
            finishPass("interrupted_load", &m_warmInterruptedLoad,
                touchedThisPass);
        } else if (m_flushRequested.load(std::memory_order_acquire)) {
            finishPass("interrupted_flush", &m_warmInterruptedFlush,
                touchedThisPass);
        } else {
            finishPass("publish_race", &m_warmInterruptedEpoch,
                touchedThisPass);
        }
        return;
    }
    if (measure)
        m_warmPassesCompleted.fetch_add(1, std::memory_order_relaxed);
    logger::info(
        "BSAMmap: cache RAM warmup complete: {:.1f} MiB covered in {:.2f}s ({:.0f} MiB/s, {:.1f} MiB newly covered)",
        committedBytes / static_cast<double>(kBytesPerMB), elapsed,
        elapsed > 0.001 ?
            touchedThisPass / static_cast<double>(kBytesPerMB) / elapsed : 0.0,
        touchedThisPass / static_cast<double>(kBytesPerMB));
    finishPass("complete", nullptr, touchedThisPass);
    if (measure) {
        // Residency is sampled once at the quiescent pre-autoload checkpoint,
        // not on the warm worker.
        const auto snapshot = GetBenchmarkSnapshot(false);
        logger::info(
            "BSAMmap: BENCH CACHE_STATE run={} event=warm_complete mappings={} entries={}/{} verified_entries={}/{} payload_mib={:.3f}/{:.3f} verified_mib={:.3f} mapping_mib={:.3f} historical_mib={:.3f} resident_mib={:.3f} resident_pages={}/{} residency_us={} residency_measured={} physical_mib={:.3f} pending_mib={:.3f} prefault_enabled={} warm_complete={}",
            Settings::sBenchmarkRunTag.empty() ? "none" :
                Settings::sBenchmarkRunTag,
            snapshot.mappingCount, snapshot.eligibleEntryCount,
            snapshot.entryCount, snapshot.verifiedEntryCount,
            snapshot.entryCount,
            snapshot.eligiblePayloadBytes /
                static_cast<double>(kBytesPerMB),
            snapshot.payloadBytes / static_cast<double>(kBytesPerMB),
            snapshot.verifiedPayloadBytes / static_cast<double>(kBytesPerMB),
            snapshot.selectedMappingBytes / static_cast<double>(kBytesPerMB),
            snapshot.historicallyWarmedBytes /
                static_cast<double>(kBytesPerMB),
            snapshot.residentBytes / static_cast<double>(kBytesPerMB),
            snapshot.residentPages, snapshot.totalPages,
            snapshot.residencyQueryMicros,
            snapshot.residencyMeasured,
            snapshot.physicalBytes / static_cast<double>(kBytesPerMB),
            snapshot.pendingBytes / static_cast<double>(kBytesPerMB),
            snapshot.prefaultEnabled, snapshot.warmComplete);
    }
}

void DecompCache::SetLoadActive(bool a_active)
{
    bool wasActive = false;
    {
        // Serialize load transitions with warm-result publication so a pass
        // cannot declare completion concurrently with a new loading screen.
        std::lock_guard workerLock(m_workerMtx);
        wasActive = m_loadActive.exchange(a_active, std::memory_order_acq_rel);
    }
    if (wasActive != a_active) {
        m_workerCv.notify_all();
    }
    if (wasActive && !a_active) {
        RequestFlush();
        // Always revalidate the warm state after a load. If the exact mappings
        // are already fully touched this is an inexpensive completion check;
        // interrupted/new mappings resume or restart their bounded pass.
        RequestWarmup();
    }
}

void DecompCache::StartBackgroundFlush()
{
    if (!m_building.load(std::memory_order_acquire) && !HasPending() &&
        !m_ready.load(std::memory_order_acquire)) return;
    bool expected = false;
    if (!m_backgroundStarted.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel)) {
        RequestFlush();
        RequestWarmup();
        return;
    }

    try {
        m_flushThread = std::jthread([this](std::stop_token a_stop) {
        try {
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
            logger::info("BSAMmap: DecompCache managed background worker started ({}s interval)",
                kBackgroundFlushIntervalSec);

            std::unique_lock waitLock(m_workerMtx);
            while (!a_stop.stop_requested()) {
                m_workerCv.wait_for(waitLock,
                    std::chrono::seconds(kBackgroundFlushIntervalSec),
                    [&] {
                        return a_stop.stop_requested() ||
                               (!m_loadActive.load(std::memory_order_acquire) &&
                                (m_flushRequested.load(std::memory_order_acquire) ||
                                 m_warmRequested.load(std::memory_order_acquire)));
                    });
                if (a_stop.stop_requested()) break;
                if (m_loadActive.load(std::memory_order_acquire)) continue;

                const bool flushSignal = m_flushRequested.exchange(
                    false, std::memory_order_acq_rel);
                const bool warmSignal = m_warmRequested.exchange(
                    false, std::memory_order_acq_rel);
                waitLock.unlock();

                const bool overCap = Settings::uDecompCacheMaxBytes > 0 &&
                    m_totalCacheBytes.load(std::memory_order_relaxed) >=
                        Settings::uDecompCacheMaxBytes;
                const bool needsHeadroom =
                    m_requiredHeadroom.load(std::memory_order_acquire) > 0;
                const bool needsReconcile =
                    m_committedReservations.load(std::memory_order_acquire) > 0;
                if (flushSignal || HasPending() || overCap || needsHeadroom ||
                    needsReconcile || HasInvalidGeneration()) {
                    FlushToDisk();
                }

                const bool warmAfterFlush = m_warmRequested.exchange(
                    false, std::memory_order_acq_rel);
                if (Settings::bPrefaultDecompCache &&
                    !m_loadActive.load(std::memory_order_acquire) &&
                    (warmSignal || warmAfterFlush ||
                     !m_warmComplete.load(std::memory_order_acquire))) {
                    WarmMappedCaches(a_stop);
                }

                waitLock.lock();
            }
        } catch (const std::exception& e) {
            try {
                logger::error("BSAMmap: DecompCache background worker stopped: {}", e.what());
            } catch (...) {
                OutputDebugStringA("FasterFileCopy: cache worker exception\n");
            }
        } catch (...) {
            OutputDebugStringA("FasterFileCopy: unknown cache worker exception\n");
        }
        if (!a_stop.stop_requested())
            m_building.store(false, std::memory_order_release);
        m_backgroundStarted.store(false, std::memory_order_release);
        });
    } catch (...) {
        m_backgroundStarted.store(false, std::memory_order_release);
        m_building.store(false, std::memory_order_release);
        throw;
    }
    RequestFlush();
    if (Settings::bPrefaultDecompCache)
        RequestWarmup();
}

void DecompCache::ReconcileDiskAccounting()
{
    if (m_loadActive.load(std::memory_order_acquire)) return;
    std::unordered_set<std::wstring> active;
    {
        std::shared_lock lock(m_cacheMtx);
        active.reserve(m_caches.size());
        for (const auto& [archive, cache] : m_caches) {
            if (!cache.activePath.empty()) active.insert(PathKey(cache.activePath));
        }
    }

    // Successful commits take this same lock when they mark their existing
    // pending charge as committed. Holding it across the scan prevents a file
    // from appearing mid-scan and having its reservation released against a
    // total that did not include it.
    std::lock_guard accountingLock(m_accountingMtx);
    if (m_loadActive.load(std::memory_order_acquire)) {
        m_unownedFiles.clear();
        return;
    }
    std::uint64_t total = 0;
    std::vector<std::filesystem::path> unowned;
    std::error_code ec;
    bool complete = true;
    std::filesystem::directory_iterator it(m_cachePath, ec), end;
    while (!ec && it != end) {
        if (m_loadActive.load(std::memory_order_acquire)) {
            m_unownedFiles.clear();
            return;
        }
        std::error_code itemEc;
        const bool regular = it->is_regular_file(itemEc);
        if (itemEc) {
            ec = itemEc;
            complete = false;
            break;
        }
        if (regular && IsCacheFilePath(it->path())) {
            const auto size = it->file_size(itemEc);
            if (itemEc) {
                ec = itemEc;
                complete = false;
                break;
            }
            if (size > (std::numeric_limits<std::uint64_t>::max)() - total)
                total = (std::numeric_limits<std::uint64_t>::max)();
            else
                total += size;
            if (!active.contains(PathKey(it->path())))
                unowned.push_back(it->path());
        }
        it.increment(ec);
    }
    if (ec || !complete) {
        logger::warn("BSAMmap: DecompCache directory accounting incomplete (error {})", ec.value());
        // Fail closed for bytes/reservations. The old unowned snapshot is not
        // safe to retain because one of those paths may now be active.
        m_unownedFiles.clear();
        return;
    }
    if (m_loadActive.load(std::memory_order_acquire)) {
        m_unownedFiles.clear();
        return;
    }

    m_unownedFiles = std::move(unowned);
    m_totalCacheBytes.store(total, std::memory_order_release);
    const auto transferred = m_committedReservations.exchange(
        0, std::memory_order_acq_rel);
    if (transferred > 0) {
        m_pendingBytes.fetch_sub(transferred, std::memory_order_acq_rel);
    }
}

void DecompCache::RemoveUnownedFiles()
{
    if (m_loadActive.load(std::memory_order_acquire)) return;
    std::vector<std::filesystem::path> files;
    {
        std::lock_guard lock(m_accountingMtx);
        files = std::move(m_unownedFiles);
        m_unownedFiles.clear();
    }
    std::uint32_t removed = 0;
    for (const auto& path : files) {
        if (m_loadActive.load(std::memory_order_acquire)) break;
        const auto key = PathKey(path);
        // Hold a shared lookup lock through deletion. A cache-file install
        // needs the unique lock, so a stale reconciliation snapshot cannot
        // delete a path while it becomes the active generation.
        std::shared_lock cacheLock(m_cacheMtx);
        const bool activeNow = std::ranges::any_of(
            m_caches, [&](const auto& pair) {
                return !pair.second.activePath.empty() &&
                       PathKey(pair.second.activePath) == key;
            });
        if (activeNow) continue;
        std::error_code ec;
        if (std::filesystem::remove(path, ec)) {
            ++removed;
        } else if (ec) {
            logger::warn("BSAMmap: DecompCache could not remove stale/orphan file {} (error {})",
                PathForLog(path.filename()), ec.value());
        }
    }
    if (removed > 0)
        logger::info("BSAMmap: DecompCache removed {} stale/orphan/temp file(s)", removed);
}

void DecompCache::EnforceSizeLimit(bool a_forceColdEviction)
{
    if (Settings::uDecompCacheMaxBytes == 0 ||
        m_loadActive.load(std::memory_order_acquire)) return;
    const std::uint64_t maxBytes = Settings::uDecompCacheMaxBytes;
    const auto requestedHeadroom =
        m_requiredHeadroom.exchange(0, std::memory_order_acq_rel);
    const auto restoreHeadroom = [&]() {
        if (requestedHeadroom == 0) return;
        auto current = m_requiredHeadroom.load(std::memory_order_relaxed);
        while (current < requestedHeadroom &&
               !m_requiredHeadroom.compare_exchange_weak(
                   current, requestedHeadroom,
                   std::memory_order_acq_rel, std::memory_order_relaxed)) {
        }
    };
    const auto targetBytes = CacheLimitPolicy::EvictionTarget(
        maxBytes, requestedHeadroom);

    ReconcileDiskAccounting();
    if (m_loadActive.load(std::memory_order_acquire)) {
        restoreHeadroom();
        return;
    }
    if (m_totalCacheBytes.load(std::memory_order_relaxed) <= targetBytes) {
        m_lastOverCapNotifyMs.store(0, std::memory_order_release);
        return;
    }
    RemoveUnownedFiles();
    if (m_loadActive.load(std::memory_order_acquire)) {
        restoreHeadroom();
        return;
    }
    ReconcileDiskAccounting();
    if (m_loadActive.load(std::memory_order_acquire)) {
        restoreHeadroom();
        return;
    }
    if (m_totalCacheBytes.load(std::memory_order_relaxed) <= targetBytes) {
        m_lastOverCapNotifyMs.store(0, std::memory_order_release);
        return;
    }

    struct Candidate
    {
        const MappedArchive* archive;
        std::uint64_t lastAccess;
        std::uint64_t fileLastWrite;
        bool usedThisSession;
    };
    std::vector<Candidate> candidates;
    const auto now = GetTickCount64();
    {
        std::shared_lock lock(m_cacheMtx);
        candidates.reserve(m_caches.size());
        for (const auto& [archive, cache] : m_caches) {
            if (!cache.view || cache.activePath.empty()) continue;
            {
                std::lock_guard pendingLock(cache.pendingMtx);
                if (!cache.bufferedOffsets.empty()) continue;
            }
            const auto rawLast = cache.lastAccessMs.load(std::memory_order_relaxed);
            const auto effectiveLast = (std::max)(rawLast, m_sessionStartMs);
            if (a_forceColdEviction || now - effectiveLast >= kColdMs) {
                candidates.push_back({ archive, rawLast,
                    GetFileLastWrite(cache.activePath), rawLast != 0 });
            }
        }
    }
    std::sort(candidates.begin(), candidates.end(),
        [](const Candidate& a, const Candidate& b) {
            if (a.usedThisSession != b.usedThisSession)
                return !a.usedThisSession;
            return a.usedThisSession
                ? a.lastAccess < b.lastAccess
                : a.fileLastWrite < b.fileLastWrite;
        });

    std::uint32_t evicted = 0;
    std::uint64_t freed = 0;
    auto estimatedRemaining =
        m_totalCacheBytes.load(std::memory_order_acquire);
    for (const auto& candidate : candidates) {
        if (m_loadActive.load(std::memory_order_acquire)) break;
        if (estimatedRemaining <= targetBytes) break;
        std::unique_lock lock(m_cacheMtx);
        if (m_loadActive.load(std::memory_order_acquire)) break;
        auto found = m_caches.find(candidate.archive);
        if (found == m_caches.end()) continue;
        auto& cache = found->second;
        std::lock_guard pendingLock(cache.pendingMtx);
        if (!cache.view || !cache.bufferedOffsets.empty() || cache.activePath.empty())
            continue;

        std::error_code ec;
        const bool removed = std::filesystem::remove(cache.activePath, ec);
        if (!removed) {
            if (ec) {
                logger::warn("BSAMmap: DecompCache eviction failed for {} (error {})",
                    PathForLog(cache.activePath.filename()), ec.value());
            }
            continue;  // never decrement accounting on a failed deletion
        }

        const auto removedBytes = cache.onDiskBytes;
        freed = CacheLimitPolicy::AddSaturating(freed, removedBytes);
        estimatedRemaining = removedBytes >= estimatedRemaining
            ? 0
            : estimatedRemaining - removedBytes;
        cache.index.clear();
        cache.view.reset();
        cache.activePath.clear();
        cache.onDiskBytes = 0;
        cache.diskInvalidated.store(false, std::memory_order_relaxed);
        cache.needsReplacement = false;
        m_cacheEpoch.fetch_add(1, std::memory_order_acq_rel);
        ++evicted;
    }

    if (evicted > 0) {
        // One authoritative scan after the batch avoids quadratic startup work
        // when many inherited cache files must be removed.
        ReconcileDiskAccounting();
        logger::info("BSAMmap: DecompCache evicted {} archive cache(s), {:.1f} MB removed{}",
            evicted, freed / (1024.0 * 1024.0),
            a_forceColdEviction ? " to enforce the RAM-backed hard cap" : "");
        RequestWarmup();
    }
    const auto remainingBytes = m_totalCacheBytes.load(std::memory_order_relaxed);
    if (remainingBytes <= targetBytes) {
        m_lastOverCapNotifyMs.store(0, std::memory_order_release);
    }
    if (remainingBytes > targetBytes && requestedHeadroom > 0) {
        restoreHeadroom();
    }
    if (remainingBytes > maxBytes) {
        logger::info("BSAMmap: DecompCache remains over cap ({:.0f}/{:.0f} MiB); all remaining archives are hot, pending, or undeletable",
            remainingBytes / static_cast<double>(kBytesPerMB),
            maxBytes / static_cast<double>(kBytesPerMB));
    } else if (remainingBytes > targetBytes && requestedHeadroom > 0) {
        logger::debug("BSAMmap: DecompCache could not reserve {} MB of headroom yet; remaining archives are hot, pending, or undeletable",
            (requestedHeadroom + kBytesPerMB - 1) / kBytesPerMB);
    }
    {
        std::shared_lock lock(m_cacheMtx);
        const bool anyUsable = std::ranges::any_of(m_caches, [](const auto& pair) {
            const auto& cache = pair.second;
            return cache.view && !cache.diskInvalidated.load(std::memory_order_acquire);
        });
        m_ready.store(anyUsable, std::memory_order_release);
    }
}

}  // namespace BSA
