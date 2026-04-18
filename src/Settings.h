#pragma once

struct Settings
{
    // Master switch — disable memory-map hooks without uninstalling.
    inline static bool bEnabled{ true };

    // Baseline mode — hooks are installed but always call the original functions.
    // Measures the cost of ReadFile (stock engine path) so you can compare
    // against the mmap path.  Both modes log identical timing stats.
    inline static bool bBaselineMode{ false };

    // Record per-read byte/timing stats and emit periodic throughput logs.
    // Off (default) = zero hot-path overhead; on = benchmarking only.
    inline static bool bMeasureStats{ false };

    // Stats log interval in seconds (first few are faster, then slows down).
    inline static int  iStatsIntervalSec{ 5 };

    // Log each individual mapped read (very verbose, debug only).
    inline static bool bLogReads{ false };

    // Enable memory-mapped I/O for uncompressed BSA entries.
    // When false, ReadFromSource hook and ArchiveStream mmap path are disabled.
    // Decompression cache still works (factory or inline delivery).
    inline static bool bEnableMmap{ true };


    // Persistent decompression cache — caches decompressed BSA entry data on disk.
    // Subsequent launches serve pre-decompressed data, skipping zlib/LZ4 entirely.
    // Requires extra disk space (~60 MB startup, grows with gameplay if mode=1).
    inline static bool bEnableDecompCache{ false };

    // Decomp cache mode:
    // 0 = startup only — cache entries from initial load, small and safe
    // 1 = startup + gameplay — cache grows as you explore, background flush every 60s
    inline static int iDecompCacheMode{ 0 };

    // Max cache size in MB (0 = unlimited). Oldest cache files evicted when limit reached.
    // Default 2048 MB — fits comfortably in the OS page cache on a 16 GB system, which
    // is the target for the always-on startup prefault (touching every page to pin the
    // cache in RAM). Users with 32 GB+ can safely raise this based on available RAM.
    inline static int iDecompCacheMaxMB{ 2048 };

    // Compatibility mode:
    // false = Factory hook on — lowest overhead, zero decompression
    // true  = Inline cache serve, no mmap/factory/ReadFromSource hooks.
    //         Enable in case of crashes/compatibility issues. Slightly more overhead.
    inline static bool bCompatibilityMode{ false };

    static void Load()
    {
        HMODULE hm = nullptr;
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(&Load), &hm);

        char dllPath[MAX_PATH]{};
        DWORD pathLen = GetModuleFileNameA(hm, dllPath, MAX_PATH);
        if (pathLen == 0 || pathLen >= MAX_PATH) return;
        auto iniPath = std::filesystem::path(dllPath).replace_extension(".ini");

        auto ini = iniPath.string();
        bEnabled      = GetPrivateProfileIntA("General", "bEnabled", 1, ini.c_str()) != 0;
        bBaselineMode = GetPrivateProfileIntA("General", "bBaselineMode", 0, ini.c_str()) != 0;
        bMeasureStats = GetPrivateProfileIntA("General", "bMeasureStats", 0, ini.c_str()) != 0;
        iStatsIntervalSec = (std::max)(1, static_cast<int>(GetPrivateProfileIntA("General", "iStatsIntervalSec", 5, ini.c_str())));
        bLogReads     = GetPrivateProfileIntA("General", "bLogReads", 0, ini.c_str()) != 0;
        bEnableMmap   = GetPrivateProfileIntA("General", "bEnableMmap", 1, ini.c_str()) != 0;
        bEnableDecompCache = GetPrivateProfileIntA("General", "bEnableDecompCache", 0, ini.c_str()) != 0;
        iDecompCacheMode = (std::clamp)(static_cast<int>(GetPrivateProfileIntA("General", "iDecompCacheMode", 0, ini.c_str())), 0, 1);
        iDecompCacheMaxMB = (std::max)(0, static_cast<int>(GetPrivateProfileIntA("General", "iDecompCacheMaxMB", 2048, ini.c_str())));

        // WINE auto-detect: on WINE, trampoline+near-code VirtualAlloc scans
        // collide with other plugins (reported "couldn't create trampoline"
        // cascades on AE 1.6.1170 under Linux). Default bCompatibilityMode to 1
        // when ntdll!wine_get_version is exported; a user INI value still wins.
        const bool onWine = []() {
            if (auto* nt = GetModuleHandleA("ntdll.dll"))
                return GetProcAddress(nt, "wine_get_version") != nullptr;
            return false;
        }();
        const int compatDefault = onWine ? 1 : 0;
        bCompatibilityMode = GetPrivateProfileIntA("General", "bCompatibilityMode", compatDefault, ini.c_str()) != 0;

        logger::info("BSAMmap: Settings loaded (enabled={}, mmap={}, baseline={}, measureStats={}, decompCache={}, cacheMode={}, compatibilityMode={}, logReads={}, wine={})",
            bEnabled, bEnableMmap, bBaselineMode, bMeasureStats, bEnableDecompCache, iDecompCacheMode, bCompatibilityMode, bLogReads, onWine);
        if (onWine)
            logger::info("BSAMmap: WINE detected (ntdll!wine_get_version present) — bCompatibilityMode default is 1; set bCompatibilityMode=0 in INI to force factory mode.");

        if (bBaselineMode)
            logger::info("BSAMmap: *** BASELINE MODE — hooks pass through to original ReadFile ***");
    }
};
