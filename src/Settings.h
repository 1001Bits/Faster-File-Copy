#pragma once

struct Settings
{
    // Master switch — disable memory-map hooks without uninstalling.
    inline static bool bEnabled{ true };

    // Baseline mode — hooks are installed but always call the original functions.
    // Measures the cost of ReadFile (stock engine path) so you can compare
    // against the mmap path.  Both modes log identical timing stats.
    inline static bool bBaselineMode{ false };

    // Enable stats logging (timing, throughput).  Required for benchmarking.
    inline static bool bEnableStats{ true };

    // Stats log interval in seconds (first few are faster, then slows down).
    inline static int  iStatsIntervalSec{ 5 };

    // Log each individual mapped read (very verbose, debug only).
    inline static bool bLogReads{ false };

    static void Load()
    {
        HMODULE hm = nullptr;
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(&Load), &hm);

        char dllPath[MAX_PATH]{};
        GetModuleFileNameA(hm, dllPath, MAX_PATH);
        auto iniPath = std::filesystem::path(dllPath).replace_extension(".ini");

        auto ini = iniPath.string();
        bEnabled      = GetPrivateProfileIntA("General", "bEnabled", 1, ini.c_str()) != 0;
        bBaselineMode = GetPrivateProfileIntA("General", "bBaselineMode", 0, ini.c_str()) != 0;
        bEnableStats  = GetPrivateProfileIntA("General", "bEnableStats", 1, ini.c_str()) != 0;
        iStatsIntervalSec = GetPrivateProfileIntA("General", "iStatsIntervalSec", 5, ini.c_str());
        bLogReads     = GetPrivateProfileIntA("General", "bLogReads", 0, ini.c_str()) != 0;

        logger::info("BSAMmap: Settings loaded (enabled={}, baseline={}, stats={}, logReads={})",
            bEnabled, bBaselineMode, bEnableStats, bLogReads);

        if (bBaselineMode)
            logger::info("BSAMmap: *** BASELINE MODE — hooks pass through to original ReadFile ***");
    }
};
