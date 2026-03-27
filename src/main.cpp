#include "PCH.h"
#include "ArchiveStream.h"
#include "Settings.h"
#include "BSAMemoryMap.h"
#include "Hooks.h"

#include <ShlObj.h>
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
        log->set_level(spdlog::level::info);
        log->flush_on(spdlog::level::info);
        spdlog::set_default_logger(std::move(log));
        spdlog::set_pattern("[%H:%M:%S.%e] [%t] [%l] %v");
    }

    void OnDataReady(SKSE::MessagingInterface::Message* a_msg)
    {
        if (a_msg && a_msg->type == SKSE::MessagingInterface::kDataLoaded) {
            // Freeze source cache to prevent deadlocks during save load
            Hooks::FreezeSourceCache();

            logger::info("BSAMmap: Data loaded — {} stream replacements, "
                         "{} mapped reads ({:.1f} MB), {} fallback reads",
                Hooks::GetStreamReplacements(),
                Hooks::GetMappedReadCount(),
                Hooks::GetMappedBytesServed() / (1024.0 * 1024.0),
                Hooks::GetFallbackReadCount());
        }
    }
}

SKSEPluginLoad(const SKSE::LoadInterface* a_skse)
{
    SKSE::Init(a_skse);
    InitializeLog();

    const char* runtime = REL::Module::IsVR() ? "VR" : "SE/AE";
    logger::info("BSAMemoryMap v1.0.0 (runtime={}, game={})",
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

    // Allocate SKSE trampoline for call-site hooks
    SKSE::AllocTrampoline(64);

    // Install hooks.
    Hooks::Install();

    // Start background stats logging (if enabled).
    Hooks::StartStatsThread();

    return true;
}
