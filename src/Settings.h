#pragma once

#include "CacheLimitPolicy.h"

#include <cerrno>
#include <cwctype>
#include <limits>
#include <stdexcept>

struct Settings
{
    // Master switch — disable memory-map hooks without uninstalling.
    inline static bool bEnabled{ true };

    // Baseline mode — hooks are installed but always call the original functions.
    // Measures the cost of ReadFile (stock engine path) so you can compare
    // against the mmap path.  Both modes log identical timing stats.
    inline static bool bBaselineMode{ false };

    // Record per-read byte counters and emit periodic throughput logs.
    // Off (default) = zero hot-path overhead; on = benchmarking only.
    inline static bool bMeasureStats{ false };

    // Aggregate statistics interval in seconds.
    inline static int  iStatsIntervalSec{ 5 };

    // Log each individual mapped read (very verbose, debug only).
    inline static bool bLogReads{ false };

    // Enable memory-mapped I/O for uncompressed BSA entries.
    // When false, the ArchiveStream mmap path is disabled. The decompression
    // cache remains available through the verified stream-vtable delivery path.
    inline static bool bEnableMmap{ true };


    // Persistent decompression cache — caches decompressed BSA entry data on disk.
    // Subsequent launches prefault the complete effective cache into RAM and serve
    // pre-decompressed data, skipping zlib/LZ4 entirely.
    inline static bool bEnableDecompCache{ true };

    // Keep initialization/mapping identical while independently controlling
    // the two cache treatments needed for causal benchmarks. Normal gameplay
    // should leave both enabled. With prefault disabled, cache entries are
    // demand-paged and may incur mapped-file faults on first use.
    inline static bool bPrefaultDecompCache{ true };
    inline static bool bServeDecompCache{ true };

    // Benchmark/diagnostic phase control. When disabled, mapped BSA delivery
    // and decompression-cache delivery pass through to the engine while an
    // engine load is active; mapping and prefault work remain identical. Keep
    // enabled for normal gameplay.
    inline static bool bEnableDuringSaveLoad{ true };

    // Decomp cache mode:
    // 0 = startup only — cache entries from initial load, small and safe
    // 1 = startup + gameplay — cache grows as you explore, background flush every 60s
    inline static int iDecompCacheMode{ 1 };

    // User cache ceiling in MiB. 0 = automatic (25% of total physical RAM).
    // Positive values are also clamped to 25% of physical RAM. The effective
    // byte value below is the sole runtime authority for admission and eviction.
    inline static int iDecompCacheMaxMB{ 2048 };
    inline static std::uint64_t uDecompCacheMaxBytes{ 0 };
    inline static std::uint64_t uTotalPhysicalMemoryBytes{ 0 };

    // Absolute directory for cache files (.decomp). Empty = default
    // (Data\SKSE\Plugins\FasterFileCopy_cache). Set an ABSOLUTE path to stop
    // Mod Organizer 2's virtual file system from redirecting cache writes into
    // the Overwrite folder — point it at the mod's real on-disk folder or any
    // dedicated cache directory (e.g. "D:\SkyrimCache" or
    // "D:\MO2\mods\FasterFileCopy\SKSE\Plugins\FasterFileCopy_cache").
    inline static std::filesystem::path sCacheDir{};

    // Opt-in deterministic benchmark driver. An explicit save basename can be
    // loaded after DataLoaded, optionally waiting for the managed warm pass.
    // Empty save = disabled. These controls never affect normal installations.
    inline static std::string sBenchmarkRunTag{};
    inline static std::string sBenchmarkAutoLoadSave{};
    inline static bool bBenchmarkWaitForWarm{ false };
    inline static int iBenchmarkAutoLoadDelaySec{ 0 };

    // Set at Load() when running under WINE/Proton (ntdll!wine_get_version).
    // Exposed in diagnostics because filesystem/cache behavior can differ.
    inline static bool bWine{ false };

    static std::string PathForLog(const std::filesystem::path& a_path) noexcept
    {
        try {
            const auto utf8 = a_path.u8string();
            return { reinterpret_cast<const char*>(utf8.data()), utf8.size() };
        } catch (...) {
            return "<unprintable path>";
        }
    }

    static std::filesystem::path ModulePath(const HMODULE a_module)
    {
        std::vector<wchar_t> buffer(512);
        while (buffer.size() <= 32768) {
            SetLastError(ERROR_SUCCESS);
            const auto copied = GetModuleFileNameW(
                a_module, buffer.data(), static_cast<DWORD>(buffer.size()));
            if (copied == 0)
                throw std::runtime_error("GetModuleFileNameW failed");
            if (copied < buffer.size())
                return std::filesystem::path(buffer.data(), buffer.data() + copied);
            buffer.resize(buffer.size() * 2);
        }
        throw std::runtime_error("Module path exceeds the Win32 path limit");
    }

    static std::filesystem::path Win32LongPath(const std::filesystem::path& a_path)
    {
        const auto& native = a_path.native();
        if (native.starts_with(L"\\\\?\\") || native.size() < 248)
            return a_path;
        if (native.starts_with(L"\\\\"))
            return std::filesystem::path(L"\\\\?\\UNC\\" + native.substr(2));
        return std::filesystem::path(L"\\\\?\\" + native);
    }

    static std::wstring ReadProfileString(
        const std::filesystem::path& a_ini,
        const wchar_t*               a_section,
        const wchar_t*               a_key)
    {
        std::vector<wchar_t> buffer(512);
        while (buffer.size() <= 32768) {
            const auto copied = GetPrivateProfileStringW(
                a_section,
                a_key,
                L"",
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                a_ini.c_str());
            if (copied < buffer.size() - 1)
                return { buffer.data(), copied };
            buffer.resize(buffer.size() * 2);
        }
        throw std::runtime_error("INI value exceeds the Win32 path limit");
    }

    static std::string Utf8(const std::wstring& a_value)
    {
        if (a_value.empty())
            return {};
        const auto required = WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, a_value.data(),
            static_cast<int>(a_value.size()), nullptr, 0, nullptr, nullptr);
        if (required <= 0)
            throw std::runtime_error("Could not convert INI text to UTF-8");
        std::string result(static_cast<std::size_t>(required), '\0');
        if (WideCharToMultiByte(
                CP_UTF8, WC_ERR_INVALID_CHARS, a_value.data(),
                static_cast<int>(a_value.size()), result.data(), required,
                nullptr, nullptr) != required) {
            throw std::runtime_error("Could not convert INI text to UTF-8");
        }
        return result;
    }

    static int ReadProfileInt(
        const std::filesystem::path& a_ini,
        const wchar_t*               a_key,
        const int                    a_default)
    {
        const auto text = TrimPathValue(
            ReadProfileString(a_ini, L"General", a_key));
        if (text.empty())
            return a_default;

        errno = 0;
        wchar_t* end = nullptr;
        const auto parsed = std::wcstoll(text.c_str(), &end, 10);
        while (end && *end != L'\0' && std::iswspace(*end))
            ++end;
        if (errno == ERANGE || end == text.c_str() || !end || *end != L'\0' ||
            parsed < (std::numeric_limits<int>::min)() ||
            parsed > (std::numeric_limits<int>::max)()) {
            logger::warn("BSAMmap: Invalid numeric setting {}; using default {}",
                PathForLog(std::filesystem::path(a_key)), a_default);
            return a_default;
        }
        return static_cast<int>(parsed);
    }

    static std::wstring ExpandEnvironment(std::wstring a_value)
    {
        if (a_value.find(L'%') == std::wstring::npos)
            return a_value;
        const auto required = ExpandEnvironmentStringsW(a_value.c_str(), nullptr, 0);
        if (required == 0 || required > 32768)
            throw std::runtime_error("Could not expand sCacheDir environment variables");
        std::vector<wchar_t> expanded(required);
        if (ExpandEnvironmentStringsW(a_value.c_str(), expanded.data(), required) != required)
            throw std::runtime_error("Could not expand sCacheDir environment variables");
        return { expanded.data() };
    }

    static std::wstring TrimPathValue(std::wstring a_value)
    {
        while (!a_value.empty() && std::iswspace(a_value.front()))
            a_value.erase(a_value.begin());
        while (!a_value.empty() && std::iswspace(a_value.back()))
            a_value.pop_back();
        if (a_value.size() >= 2 &&
            ((a_value.front() == L'"' && a_value.back() == L'"') ||
             (a_value.front() == L'\'' && a_value.back() == L'\''))) {
            a_value = a_value.substr(1, a_value.size() - 2);
            while (!a_value.empty() && std::iswspace(a_value.front()))
                a_value.erase(a_value.begin());
            while (!a_value.empty() && std::iswspace(a_value.back()))
                a_value.pop_back();
        }
        return a_value;
    }

    static void Load()
    {
        HMODULE module = nullptr;
        if (!GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(&Load),
                &module)) {
            throw std::runtime_error("Could not resolve the plugin module path");
        }

        auto iniPath = ModulePath(module).replace_extension(L".ini");
        const auto iniForApi = Win32LongPath(iniPath);
        std::error_code iniEc;
        if (!std::filesystem::is_regular_file(iniForApi, iniEc) || iniEc) {
            logger::warn("BSAMmap: INI not found or inaccessible at {}; using built-in defaults",
                PathForLog(iniPath));
        }

        bEnabled = ReadProfileInt(iniForApi, L"bEnabled", 1) != 0;
        bBaselineMode = ReadProfileInt(iniForApi, L"bBaselineMode", 0) != 0;
        bMeasureStats = ReadProfileInt(iniForApi, L"bMeasureStats", 0) != 0;
        iStatsIntervalSec = (std::max)(1,
            ReadProfileInt(iniForApi, L"iStatsIntervalSec", 5));
        bLogReads = ReadProfileInt(iniForApi, L"bLogReads", 0) != 0;
        bEnableMmap = ReadProfileInt(iniForApi, L"bEnableMmap", 1) != 0;
        bEnableDecompCache =
            ReadProfileInt(iniForApi, L"bEnableDecompCache", 1) != 0;
        bPrefaultDecompCache =
            ReadProfileInt(iniForApi, L"bPrefaultDecompCache", 1) != 0;
        bServeDecompCache =
            ReadProfileInt(iniForApi, L"bServeDecompCache", 1) != 0;
        bEnableDuringSaveLoad =
            ReadProfileInt(iniForApi, L"bEnableDuringSaveLoad", 1) != 0;
        iDecompCacheMode = (std::clamp)(
            ReadProfileInt(iniForApi, L"iDecompCacheMode", 1), 0, 1);
        iDecompCacheMaxMB =
            ReadProfileInt(iniForApi, L"iDecompCacheMaxMB", 0);
        if (iDecompCacheMaxMB < 0) {
            logger::warn(
                "BSAMmap: negative iDecompCacheMaxMB={} is invalid; using the 2048 MiB default (still clamped to 25% of RAM)",
                iDecompCacheMaxMB);
            iDecompCacheMaxMB = 2048;
        }

        auto cacheValue = TrimPathValue(
            ReadProfileString(iniForApi, L"General", L"sCacheDir"));
        if (!cacheValue.empty()) {
            cacheValue = ExpandEnvironment(std::move(cacheValue));
            auto candidate = std::filesystem::path(cacheValue).lexically_normal();
            if (!candidate.is_absolute()) {
                sCacheDir.clear();
                logger::error(
                    "BSAMmap: sCacheDir must be absolute; decompression cache disabled (value={})",
                    PathForLog(candidate));
                bEnableDecompCache = false;
            } else {
                sCacheDir = Win32LongPath(candidate);
            }
        } else {
            sCacheDir.clear();
        }


        sBenchmarkRunTag = Utf8(TrimPathValue(
            ReadProfileString(iniForApi, L"General", L"sBenchmarkRunTag")));
        sBenchmarkAutoLoadSave = Utf8(TrimPathValue(
            ReadProfileString(iniForApi, L"General", L"sBenchmarkAutoLoadSave")));
        bBenchmarkWaitForWarm =
            ReadProfileInt(iniForApi, L"bBenchmarkWaitForWarm", 0) != 0;
        iBenchmarkAutoLoadDelaySec = (std::clamp)(
            ReadProfileInt(iniForApi, L"iBenchmarkAutoLoadDelaySec", 0), 0, 300);

        uDecompCacheMaxBytes = 0;
        uTotalPhysicalMemoryBytes = 0;
        if (bEnabled && bEnableDecompCache && !bBaselineMode) {
            MEMORYSTATUSEX memory{};
            memory.dwLength = sizeof(memory);
            if (!GlobalMemoryStatusEx(&memory) || memory.ullTotalPhys == 0) {
                bEnableDecompCache = false;
                logger::error(
                    "BSAMmap: physical RAM detection failed; decompression cache disabled to preserve the 25% safety ceiling");
            } else {
                uTotalPhysicalMemoryBytes = memory.ullTotalPhys;
                const auto decision = CacheLimitPolicy::Decide(
                    static_cast<std::uint64_t>(iDecompCacheMaxMB),
                    uTotalPhysicalMemoryBytes);
                if (!decision) {
                    bEnableDecompCache = false;
                    logger::error(
                        "BSAMmap: physical RAM is too small for a decompression cache; cache disabled");
                } else {
                    uDecompCacheMaxBytes = decision.effectiveBytes;
                    const auto configured = iDecompCacheMaxMB == 0
                        ? std::string("auto")
                        : std::to_string(iDecompCacheMaxMB) + " MiB";
                    const char* reason = decision.mode == CacheLimitPolicy::Mode::kClamped
                        ? "clamped to 25% of physical RAM"
                        : decision.mode == CacheLimitPolicy::Mode::kAutomatic
                            ? "automatic 25% of physical RAM"
                            : "configured ceiling";
                    logger::info(
                        "BSAMmap: cache RAM policy: configured={}, physical RAM={:.0f} MiB, 25% ceiling={:.0f} MiB, effective={:.0f} MiB ({})",
                        configured,
                        decision.physicalBytes / static_cast<double>(CacheLimitPolicy::kBytesPerMiB),
                        decision.automaticCeilingBytes / static_cast<double>(CacheLimitPolicy::kBytesPerMiB),
                        decision.effectiveBytes / static_cast<double>(CacheLimitPolicy::kBytesPerMiB),
                        reason);
                }
            }
        }

        bWine = []() noexcept {
            if (const auto ntdll = GetModuleHandleW(L"ntdll.dll"))
                return GetProcAddress(ntdll, "wine_get_version") != nullptr;
            return false;
        }();
        const auto legacyCompatibility =
            ReadProfileInt(iniForApi, L"bCompatibilityMode", 0) != 0;
        if (legacyCompatibility) {
            logger::warn("BSAMmap: Legacy bCompatibilityMode is ignored; safe vtable delivery is always used");
        }
        if (bWine && bEnableMmap) {
            bEnableMmap = false;
            logger::info("BSAMmap: Uncompressed whole-BSA mmap disabled on WINE/Proton; decompression cache remains independently available");
        }
        if (bBaselineMode) {
            bEnableMmap = false;
            bEnableDecompCache = false;
        }

        if (!bEnableDecompCache) {
            bPrefaultDecompCache = false;
            bServeDecompCache = false;
        }

        if (!bPrefaultDecompCache && bServeDecompCache) {
            logger::warn(
                "BSAMmap: benchmark demand-paged cache treatment active; entries may fault on first use");
        }
        if (bEnableDecompCache && !bServeDecompCache) {
            logger::warn(
                "BSAMmap: benchmark cache-serve control active; cache will map/warm but not deliver entries");
        }
        if (bEnabled && !bEnableDuringSaveLoad) {
            logger::warn(
                "BSAMmap: benchmark load-phase control active; acceleration will pass through during engine loads and resume during gameplay");
        }

        logger::info(
            "BSAMmap: Settings loaded (enabled={}, mmap={}, baseline={}, measureStats={}, "
            "decompCache={}, prefault={}, serveCache={}, duringSaveLoad={}, cacheMode={}, effectiveCacheMiB={:.0f}, logReads={}, wine={}, runTag={})",
            bEnabled,
            bEnableMmap,
            bBaselineMode,
            bMeasureStats,
            bEnableDecompCache,
            bPrefaultDecompCache,
            bServeDecompCache,
            bEnableDuringSaveLoad,
            iDecompCacheMode,
            uDecompCacheMaxBytes /
                static_cast<double>(CacheLimitPolicy::kBytesPerMiB),
            bLogReads,
            bWine,
            sBenchmarkRunTag.empty() ? "none" : sBenchmarkRunTag);
        if (!sCacheDir.empty())
            logger::info("BSAMmap: Cache directory overridden: {}", PathForLog(sCacheDir));
        if (bWine)
            logger::info("BSAMmap: WINE/Proton detected");
        if (bBaselineMode)
            logger::info("BSAMmap: *** BASELINE MODE — mmap/cache disabled; hooks pass through to the engine ***");
    }
};
