#include "PCH.h"
#include "ArchiveStream.h"
#include "DecompCache.h"
#include "Settings.h"
#include "BSAMemoryMap.h"
#include "Hooks.h"

#include <ShlObj.h>
#include <psapi.h>
#include <spdlog/sinks/basic_file_sink.h>

namespace
{
    void InitializeLog()
    {
        std::filesystem::path logPath;
        wchar_t docsBuf[MAX_PATH]{};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PERSONAL, nullptr, 0, docsBuf))) {
            std::filesystem::path docs(docsBuf);
            const wchar_t* gameName =
                REL::Module::IsVR() ? L"Skyrim VR" : L"Skyrim Special Edition";
            auto skseDir = docs / "My Games" / gameName / "SKSE";
            std::filesystem::create_directories(skseDir);
            logPath = skseDir / "BSAMemoryMap.log";
        } else {
            HMODULE hm = nullptr;
            GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCSTR>(&InitializeLog), &hm);
            char buf[MAX_PATH]{};
            GetModuleFileNameA(hm, buf, MAX_PATH);
            logPath = std::filesystem::path(buf).parent_path() / "BSAMemoryMap.log";
        }

        auto sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(logPath.string(), true);
        auto log  = std::make_shared<spdlog::logger>("global log"s, std::move(sink));
        log->set_level(spdlog::level::warn);
        log->flush_on(spdlog::level::warn);
        spdlog::set_default_logger(std::move(log));
        spdlog::set_pattern("[%H:%M:%S.%e] [%t] [%l] %v");
    }

    static LARGE_INTEGER s_saveLoadStart{};
    static LARGE_INTEGER s_qpcFreq{};
    static std::uint64_t s_preLoadMmap{}, s_preLoadCache{}, s_preLoadDecomp{}, s_preLoadFallback{};
    static std::uint64_t s_preLoadSourceMmap{}, s_preLoadSourceFallback{};
    static DWORD s_preLoadFaults{};

    static DWORD SnapshotPageFaults()
    {
        PROCESS_MEMORY_COUNTERS pmc{};
        pmc.cb = sizeof(pmc);
        return K32GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))
            ? pmc.PageFaultCount : 0;
    }

    void OnDataReady(SKSE::MessagingInterface::Message* a_msg)
    {
        if (!a_msg) return;

        switch (a_msg->type) {
        case SKSE::MessagingInterface::kDataLoaded:
        {
            QueryPerformanceFrequency(&s_qpcFreq);
            Hooks::FreezeSourceCache();

            // Flush decompression cache to disk (if building)
            if (Settings::bEnableDecompCache) {
                auto& dcache = BSA::DecompCache::GetSingleton();
                dcache.FlushToDisk();

                // Mode 1: start background flush thread for gameplay entries
                dcache.StartBackgroundFlush();

                // Pin the whole cache in RAM by touching every page.
                dcache.PrefaultAll();
            }
            // Always-fires marker so external benchmark drivers can detect
            // main-menu readiness regardless of cache settings.
            logger::info("BSAMmap: Data loaded — main menu ready");
            break;
        }
        case SKSE::MessagingInterface::kPreLoadGame:
            QueryPerformanceCounter(&s_saveLoadStart);
            s_preLoadMmap     = Hooks::GetMappedBytesServed();
            s_preLoadCache    = Hooks::GetCacheBytesServed();
            s_preLoadDecomp   = Hooks::GetDecompBytesServed();
            s_preLoadFallback = Hooks::GetFallbackBytesServed();
            s_preLoadSourceMmap = Hooks::GetMappedSourceBytes();
            s_preLoadSourceFallback = Hooks::GetFallbackSourceBytes();
            s_preLoadFaults = SnapshotPageFaults();
            logger::info("BSAMmap: Save load started");
            break;

        case SKSE::MessagingInterface::kPostLoadGame:
        {
            LARGE_INTEGER now;
            QueryPerformanceCounter(&now);
            double sec = static_cast<double>(now.QuadPart - s_saveLoadStart.QuadPart)
                       / s_qpcFreq.QuadPart;
            double mmapMB     = (Hooks::GetMappedBytesServed()   - s_preLoadMmap)     / (1024.0 * 1024.0);
            double cacheMB    = (Hooks::GetCacheBytesServed()    - s_preLoadCache)    / (1024.0 * 1024.0);
            double decompMB   = (Hooks::GetDecompBytesServed()   - s_preLoadDecomp)   / (1024.0 * 1024.0);
            double fallbackMB = (Hooks::GetFallbackBytesServed() - s_preLoadFallback) / (1024.0 * 1024.0);
            double sourceMmapMB = (Hooks::GetMappedSourceBytes() - s_preLoadSourceMmap) / (1024.0 * 1024.0);
            double sourceFallbackMB = (Hooks::GetFallbackSourceBytes() - s_preLoadSourceFallback) / (1024.0 * 1024.0);
            double totalMB = mmapMB + cacheMB + decompMB + fallbackMB;
            double throughput = (sec > 0.001) ? totalMB / sec : 0.0;

            double pMmap = totalMB > 0.001 ? (mmapMB / totalMB * 100) : 0;
            double pCache = totalMB > 0.001 ? (cacheMB / totalMB * 100) : 0;
            double pDecomp = totalMB > 0.001 ? (decompMB / totalMB * 100) : 0;
            double pFallback = totalMB > 0.001 ? (fallbackMB / totalMB * 100) : 0;

            logger::info("BSAMmap: SAVE LOAD TIME: {:.3f}s | {:.1f} MB payload total | "
                "direct mmap {:.1f}/{:.0f}% + cache {:.1f}/{:.0f}% + "
                "compressed path {:.1f}/{:.0f}% + native direct {:.1f}/{:.0f}% | {:.1f} MB/s",
                sec, totalMB,
                mmapMB, pMmap, cacheMB, pCache,
                decompMB, pDecomp, fallbackMB, pFallback,
                throughput);
            logger::info("BSAMmap: SAVE LOAD SOURCE I/O: mapped {:.1f} MB + fallback {:.1f} MB",
                sourceMmapMB, sourceFallbackMB);

            // Page fault delta — proxy for how much of the save load hit disk
            // vs RAM. Low delta relative to bytes served ⇒ mmap/cache served
            // from page cache. Per-fault cost is trivial (two K32 syscalls).
            DWORD faultsNow = SnapshotPageFaults();
            DWORD faultsDelta = faultsNow - s_preLoadFaults;  // DWORD wraps cleanly
            logger::info("BSAMmap: SAVE LOAD PAGE FAULTS: {} ({:.0f} per MB served)",
                faultsDelta,
                totalMB > 0.001 ? faultsDelta / totalMB : 0.0);

            // Start gameplay measurement after a delay (let post-load streaming settle)
            std::thread([]() {
                std::this_thread::sleep_for(std::chrono::seconds(10));
                Hooks::SnapshotGameplayStart();
            }).detach();
            break;
        }
        }
    }
}

SKSEPluginLoad(const SKSE::LoadInterface* a_skse)
{
    SKSE::Init(a_skse);
    InitializeLog();

    const char* runtime = REL::Module::IsVR() ? "VR" : "SE/AE";
    logger::warn("BSAMemoryMap v1.8.0 (runtime={}, game={})",
        runtime, REL::Module::get().version().string());

    Settings::Load();
    BSResource::Field::Init();

    if (!Settings::bEnabled) {
        logger::info("BSAMmap: Disabled via settings — skipping");
        return true;
    }

    // Register for data-loaded message to log stats.
    auto* messaging = SKSE::GetMessagingInterface();
    if (messaging)
        messaging->RegisterListener(OnDataReady);

    // Resolve the game's Data directory.
    std::filesystem::path dataPath;
    {
        wchar_t exePath[MAX_PATH]{};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        dataPath = std::filesystem::path(exePath).parent_path() / "Data";
    }

    if (!std::filesystem::exists(dataPath)) {
        logger::error("BSAMmap: Data directory not found: {}", dataPath.string());
        return true;
    }

    // Memory-map all BSA archives.
    auto& mgr = BSA::MemoryMapManager::GetSingleton();
    if (!mgr.Initialize(dataPath)) {
        logger::warn("BSAMmap: No archives were memory-mapped");
        return true;
    }

    // Initialize decompression cache (if enabled)
    if (Settings::bEnableDecompCache) {
        BSA::DecompCache::GetSingleton().Initialize(dataPath, mgr.GetArchives());
    }

    // Install hooks.
    Hooks::Install();

    // Start background stats logging (if enabled).
    Hooks::StartStatsThread();

    return true;
}
