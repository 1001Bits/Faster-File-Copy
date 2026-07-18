#include "PCH.h"
#include "ArchiveStream.h"
#include "DecompCache.h"
#include "Hooks.h"
#include "Settings.h"
#include "BSAMemoryMap.h"

#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/msvc_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>

#include <chrono>
#include <condition_variable>
#include <optional>
#include <thread>

#ifndef FFC_VERSION_STRING
#define FFC_VERSION_STRING "development"
#endif

namespace
{
    void ConfigureLogger(std::shared_ptr<spdlog::logger> a_log)
    {
        a_log->set_level(spdlog::level::info);
        // Flush every info line so startup + metrics survive a hang or crash.
        // An unclean exit never runs spdlog's destructor flush, so with the
        // previous flush_on(warn) an info-only session left the log empty.
        a_log->flush_on(spdlog::level::info);
        a_log->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%t] [%l] %v");
        spdlog::set_default_logger(std::move(a_log));
    }

    // Raw-WinAPI breadcrumb: records WHY file logging failed via a path that
    // cannot itself be swallowed by spdlog. Best-effort, never throws.
    void WriteLogInitBreadcrumb(
        const std::filesystem::path& a_dir, const std::string& a_reason) noexcept
    {
        try {
            const auto debugReason = a_reason + "\n";
            OutputDebugStringA(debugReason.c_str());
            const auto path = a_dir / L"FasterFileCopy_loginit.txt";
            const HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE,
                FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (h && h != INVALID_HANDLE_VALUE) {
                DWORD written = 0;
                WriteFile(h, a_reason.data(),
                    static_cast<DWORD>(a_reason.size()), &written, nullptr);
                CloseHandle(h);
            }
        } catch (...) {
        }
    }

    // Resolve a writable directory for the log. SKSE::log::log_directory() can
    // be empty this early at plugin load (the 1.7.1 "no log at all" symptom),
    // so fall back to the DLL's own folder (Data\SKSE\Plugins).
    // The GOG release ships the Galaxy client library beside the executable;
    // Steam builds never do.  This is checked against the install on disk rather
    // than the runtime version because GOG AE (1.6.1179) is otherwise just
    // another AE build.
    [[nodiscard]] bool IsGogInstall() noexcept
    {
        try {
            const auto root = Settings::ModulePath(nullptr).parent_path();
            std::error_code ec;
            return std::filesystem::exists(root / L"Galaxy64.dll", ec);
        } catch (...) {
            return false;
        }
    }

    [[nodiscard]] std::filesystem::path ResolveLogDir() noexcept
    {
        // SKSE::log::log_directory() resolves the Documents\My Games root, but it
        // reports the wrong game folder ("Skyrim.INI" instead of the real name),
        // so rebuild the path so the log lands beside every other plugin's log.
        //
        // The folder name is store-specific: the GOG build of AE keeps its INIs
        // and saves under "Skyrim Special Edition GOG", so a hardcoded
        // "Skyrim Special Edition" silently drops GOG users' logs into the Steam
        // folder.  Detect the store from the install itself (GOG ships
        // Galaxy64.dll next to the exe) rather than from the runtime version,
        // because a GOG install is otherwise indistinguishable from Steam AE.
        try {
            if (const auto d = SKSE::log::log_directory(); d && !d->empty()) {
                const auto leaf = d->filename().wstring();
                if (CompareStringOrdinal(
                        leaf.c_str(), -1, L"SKSE", -1, TRUE) != CSTR_EQUAL) {
                    return *d;
                }
                const auto myGames = d->parent_path().parent_path();
                const auto myGamesName = myGames.filename().wstring();
                if (CompareStringOrdinal(
                        myGamesName.c_str(), -1, L"My Games", -1, TRUE) ==
                    CSTR_EQUAL) {
                    const wchar_t* game = REL::Module::IsVR() ? L"Skyrim VR" :
                        IsGogInstall() ? L"Skyrim Special Edition GOG" :
                                         L"Skyrim Special Edition";
                    return myGames / game / L"SKSE";
                }
                return *d;
            }
        } catch (...) {
        }
        try {
            HMODULE self = nullptr;
            if (GetModuleHandleExW(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    reinterpret_cast<LPCWSTR>(&ResolveLogDir), &self) && self) {
                return Settings::ModulePath(self).parent_path();
            }
        } catch (...) {
        }
        return {};
    }

    bool InitializeLog() noexcept
    {
        // Rotate-on-open file sink: the current session is always
        // FasterFileCopy.log and the three previous sessions are preserved as
        // .1/.2/.3. A truncating sink here once destroyed a benchmark
        // session's records — multi-session comparisons need history.
        // ResolveLogDir() additionally falls back to the DLL folder when
        // SKSE's log directory is unavailable this early.
        const std::filesystem::path logDir = ResolveLogDir();
        std::string primaryFailure;
        if (!logDir.empty()) {
            try {
                std::error_code ec;
                std::filesystem::create_directories(logDir, ec);
                const auto logPath = logDir / "FasterFileCopy.log";
                auto sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                    logPath.string(), 16u * 1024u * 1024u, 3u,
                    true /*rotate_on_open*/);
                ConfigureLogger(std::make_shared<spdlog::logger>(
                    "FasterFileCopy", std::move(sink)));
                return true;
            } catch (const std::exception& e) {
                primaryFailure = e.what();
            } catch (...) {
                primaryFailure = "unknown logging exception";
            }
            WriteLogInitBreadcrumb(logDir,
                "FasterFileCopy primary log init failed: " + primaryFailure);
        } else {
            primaryFailure =
                "no writable log directory (SKSE + module path both unavailable)";
        }

        // Fallback: %TEMP%.
        try {
            std::error_code ec;
            const auto fbDir = std::filesystem::temp_directory_path(ec);
            if (!ec && !fbDir.empty()) {
                const auto fbPath = fbDir /
                    ("FasterFileCopy_fallback_" +
                     std::to_string(GetCurrentProcessId()) + ".log");
                auto sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(
                    fbPath.string(), true);
                ConfigureLogger(std::make_shared<spdlog::logger>(
                    "FasterFileCopy", std::move(sink)));
                logger::error("Primary log init failed ({}); using %TEMP% fallback",
                    primaryFailure);
                return true;
            }
        } catch (...) {
        }

        // Last resort: debugger-only sink (invisible without a debugger).
        try {
            auto sink = std::make_shared<spdlog::sinks::msvc_sink_mt>();
            ConfigureLogger(std::make_shared<spdlog::logger>(
                "FasterFileCopy", std::move(sink)));
            logger::error("File logging unavailable: {}", primaryFailure);
        } catch (...) {
            OutputDebugStringA("FasterFileCopy: failed to initialize logging\n");
        }
        return false;
    }

    void ReportUnhandled(const char* a_context, const char* a_detail) noexcept
    {
        try {
            logger::critical("BSAMmap: {}: {}", a_context, a_detail);
            if (const auto log = spdlog::default_logger())
                log->flush();
        } catch (...) {
            OutputDebugStringA("FasterFileCopy: unhandled plugin exception\n");
        }
    }

    static LARGE_INTEGER s_saveLoadStart{};
    static LARGE_INTEGER s_qpcFreq{};
    static LARGE_INTEGER s_pluginLoadStart{};
    static Hooks::IoStatsSnapshot s_preLoadIo{};
    static BSA::DecompCacheBenchmarkSnapshot s_preLoadCacheState{};
    static bool s_saveLoadMeasured{ false };
    static bool s_saveLoadTimed{ false };

    struct ProcessSnapshot
    {
        std::uint64_t workingSetBytes{ 0 };
        std::uint64_t privateBytes{ 0 };
        std::uint64_t pageFaults{ 0 };
        std::uint64_t readOperations{ 0 };
        std::uint64_t readBytes{ 0 };
        std::uint64_t cpu100ns{ 0 };
        std::uint64_t availablePhysicalBytes{ 0 };
        bool valid{ false };
    };

    static ProcessSnapshot s_preLoadProcess{};

    [[nodiscard]] std::uint64_t FileTimeValue(const FILETIME& a_time) noexcept
    {
        ULARGE_INTEGER value{};
        value.LowPart = a_time.dwLowDateTime;
        value.HighPart = a_time.dwHighDateTime;
        return value.QuadPart;
    }

    [[nodiscard]] ProcessSnapshot CaptureProcessSnapshot() noexcept
    {
        ProcessSnapshot result{};
        PROCESS_MEMORY_COUNTERS_EX memory{};
        memory.cb = sizeof(memory);
        IO_COUNTERS io{};
        FILETIME created{}, exited{}, kernel{}, user{};
        MEMORYSTATUSEX systemMemory{};
        systemMemory.dwLength = sizeof(systemMemory);
        const auto process = GetCurrentProcess();
        if (!K32GetProcessMemoryInfo(process,
                reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory),
                sizeof(memory)) ||
            !GetProcessIoCounters(process, &io) ||
            !GetProcessTimes(process, &created, &exited, &kernel, &user) ||
            !GlobalMemoryStatusEx(&systemMemory)) {
            return result;
        }
        result.workingSetBytes = memory.WorkingSetSize;
        result.privateBytes = memory.PrivateUsage;
        result.pageFaults = memory.PageFaultCount;
        result.readOperations = io.ReadOperationCount;
        result.readBytes = io.ReadTransferCount;
        result.cpu100ns = FileTimeValue(kernel) + FileTimeValue(user);
        result.availablePhysicalBytes = systemMemory.ullAvailPhys;
        result.valid = true;
        return result;
    }

    [[nodiscard]] std::string BenchmarkSaveName(
        const SKSE::MessagingInterface::Message* a_message) noexcept
    {
        try {
            if (!a_message || !a_message->data || a_message->dataLen == 0)
                return {};
            constexpr std::size_t kMaxSaveMessageBytes = 4096;
            auto length = (std::min)(
                static_cast<std::size_t>(a_message->dataLen),
                kMaxSaveMessageBytes);
            const auto* bytes = static_cast<const char*>(a_message->data);
            if (const auto* nul = static_cast<const char*>(
                    std::memchr(bytes, '\0', length))) {
                length = static_cast<std::size_t>(nul - bytes);
            }
            if (length == 0)
                return {};
            auto name = std::filesystem::path(
                std::string{ bytes, length }).filename().string();
            auto extension = std::filesystem::path(name).extension().string();
            std::ranges::transform(
                extension, extension.begin(), [](const unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
            if (extension == ".ess" || extension == ".skse")
                name.resize(name.size() - extension.size());
            return name;
        } catch (...) {
            return {};
        }
    }

    void LogCacheState(const char* a_event, const bool a_measureResidency,
        const bool a_forceBenchmarkCheckpoint = false)
    {
        const bool benchmarkCheckpoint = a_forceBenchmarkCheckpoint &&
            (!Settings::sBenchmarkRunTag.empty() ||
                !Settings::sBenchmarkAutoLoadSave.empty());
        if ((!Settings::bMeasureStats && !benchmarkCheckpoint) ||
            !Settings::bEnableDecompCache)
            return;
        const auto state = BSA::DecompCache::GetSingleton().GetBenchmarkSnapshot(
            a_measureResidency);
        constexpr double mib = 1024.0 * 1024.0;
        const double frequency = static_cast<double>((std::max)(
            s_qpcFreq.QuadPart, LONGLONG{ 1 }));
        logger::info(
            "BSAMmap: BENCH CACHE_STATE run={} event={} mappings={} entries={}/{} verified_entries={}/{} payload_mib={:.3f}/{:.3f} verified_mib={:.3f} mapping_mib={:.3f} historical_mib={:.3f} resident_mib={:.3f} resident_pages={}/{} residency_us={} residency_measured={} physical_mib={:.3f} pending_mib={:.3f} prefault_enabled={} warm_complete={} warm_passes={} warm_completed={} warm_covered_mib={:.3f} warm_active_ms={:.3f}",
            Settings::sBenchmarkRunTag.empty() ? "none" :
                Settings::sBenchmarkRunTag,
            a_event, state.mappingCount, state.eligibleEntryCount,
            state.entryCount, state.verifiedEntryCount, state.entryCount,
            state.eligiblePayloadBytes / mib, state.payloadBytes / mib,
            state.verifiedPayloadBytes / mib, state.selectedMappingBytes / mib,
            state.historicallyWarmedBytes / mib, state.residentBytes / mib,
            state.residentPages, state.totalPages,
            state.residencyQueryMicros, state.residencyMeasured,
            state.physicalBytes / mib, state.pendingBytes / mib,
            state.prefaultEnabled, state.warmComplete,
            state.diagnostics.warmPassesStarted,
            state.diagnostics.warmPassesCompleted,
            state.diagnostics.warmBytesTouched / mib,
            state.diagnostics.warmQpcTicks * 1000.0 / frequency);
    }

    enum class LoadProducer : std::uint8_t
    {
        kSaveMessage = 1u << 0,
        kLoadingMenu = 1u << 1,
        kBenchmarkDispatch = 1u << 2
    };

    std::mutex s_loadGateMutex;
    std::uint8_t s_loadProducerMask{ 0 };
    std::atomic<bool> s_mainMenuReady{ false };

    // Wall-clock measurement of every load gate window (save loads, door
    // transitions, fast travel — anything that opens the LoadingMenu).
    // Guarded by s_loadGateMutex.
    struct LoadWindowSnapshot
    {
        LARGE_INTEGER started{};
        std::uint64_t mmapBytes{ 0 };
        std::uint64_t cacheBytes{ 0 };
        std::uint64_t decompBytes{ 0 };
        std::uint64_t stockBytes{ 0 };
    };
    LoadWindowSnapshot s_loadWindow{};

    void SetLoadProducer(const LoadProducer a_producer, const bool a_active)
    {
        bool logClose = false;
        double seconds = 0.0;
        double mmapMB = 0.0, cacheMB = 0.0, decompMB = 0.0, stockMB = 0.0;
        {
            std::lock_guard lock(s_loadGateMutex);
            const bool wasActive = s_loadProducerMask != 0;
            const auto bit = static_cast<std::uint8_t>(a_producer);
            if (a_active)
                s_loadProducerMask |= bit;
            else
                s_loadProducerMask &= static_cast<std::uint8_t>(~bit);

            const bool isActive = s_loadProducerMask != 0;
            if (wasActive != isActive) {
                Hooks::SetLoadActive(isActive);
                if (Settings::bEnableDecompCache) {
                    BSA::DecompCache::GetSingleton().SetLoadActive(isActive);
                }

                if (isActive) {
                    QueryPerformanceCounter(&s_loadWindow.started);
                    s_loadWindow.mmapBytes = Hooks::GetMappedBytesServed();
                    s_loadWindow.cacheBytes = Hooks::GetCacheBytesServed();
                    s_loadWindow.decompBytes = Hooks::GetDecompBytesServed();
                    s_loadWindow.stockBytes = Hooks::GetFallbackBytesServed();
                } else if (s_loadWindow.started.QuadPart != 0) {
                    LARGE_INTEGER now;
                    QueryPerformanceCounter(&now);
                    seconds =
                        static_cast<double>(now.QuadPart -
                                            s_loadWindow.started.QuadPart) /
                        static_cast<double>(
                            (std::max)(s_qpcFreq.QuadPart, LONGLONG{ 1 }));
                    constexpr double kMiB = 1024.0 * 1024.0;
                    mmapMB = static_cast<double>(
                        Hooks::GetMappedBytesServed() - s_loadWindow.mmapBytes) / kMiB;
                    cacheMB = static_cast<double>(
                        Hooks::GetCacheBytesServed() - s_loadWindow.cacheBytes) / kMiB;
                    decompMB = static_cast<double>(
                        Hooks::GetDecompBytesServed() - s_loadWindow.decompBytes) / kMiB;
                    stockMB = static_cast<double>(
                        Hooks::GetFallbackBytesServed() - s_loadWindow.stockBytes) / kMiB;
                    s_loadWindow.started.QuadPart = 0;
                    logClose = true;
                }
            }
        }

        if (logClose) {
            try {
                logger::info(
                    "BSAMmap: LOADING SCREEN: {:.3f}s | mmap {:.1f} MB + cache {:.1f} MB + decompressor {:.1f} MB + stock {:.1f} MB",
                    seconds, mmapMB, cacheMB, decompMB, stockMB);
            } catch (...) {
            }
        }
    }

    [[nodiscard]] bool IsLoadProducerActive(const LoadProducer a_producer)
    {
        std::lock_guard lock(s_loadGateMutex);
        return (s_loadProducerMask & static_cast<std::uint8_t>(a_producer)) != 0;
    }

    class GameplaySnapshotScheduler
    {
    public:
        static GameplaySnapshotScheduler& GetSingleton()
        {
            static GameplaySnapshotScheduler scheduler;
            return scheduler;
        }

        ~GameplaySnapshotScheduler()
        {
            worker_.request_stop();
            cv_.notify_all();
        }

        void Schedule()
        {
            std::lock_guard lock(mutex_);
            summaryPending_ = false;
            deadline_ = std::chrono::steady_clock::now() + std::chrono::seconds(10);
            cv_.notify_all();
        }

        void Cancel()
        {
            std::lock_guard lock(mutex_);
            deadline_.reset();
            summaryPending_ = false;
            cv_.notify_all();
        }

    private:
        GameplaySnapshotScheduler() : worker_([this](const std::stop_token a_stop) {
            Run(a_stop);
        }) {}

        void Run(const std::stop_token a_stop)
        {
            std::unique_lock lock(mutex_);
            while (!a_stop.stop_requested()) {
                if (!deadline_) {
                    cv_.wait(lock, [&] {
                        return a_stop.stop_requested() || deadline_.has_value();
                    });
                    continue;
                }

                const auto due = *deadline_;
                if (cv_.wait_until(lock, due, [&] {
                        return a_stop.stop_requested() || !deadline_ || *deadline_ != due;
                    })) {
                    continue;
                }

                const bool emitSummary = summaryPending_;
                if (emitSummary) {
                    deadline_.reset();
                    summaryPending_ = false;
                } else {
                    // PerformanceMod's controlled sample runs from roughly
                    // post-load +5s to +35s. Emit a stable gameplay record at
                    // +30s, before its benchmark process exits.
                    summaryPending_ = true;
                    deadline_ = std::chrono::steady_clock::now() +
                        std::chrono::seconds(20);
                }
                lock.unlock();
                try {
                    if (emitSummary)
                        Hooks::LogGameplaySummary();
                    else
                        Hooks::SnapshotGameplayStart();
                } catch (const std::exception& e) {
                    ReportUnhandled("gameplay statistics task failed", e.what());
                } catch (...) {
                    ReportUnhandled("gameplay statistics task failed", "unknown exception");
                }
                lock.lock();
            }
        }

        std::mutex mutex_;
        std::condition_variable cv_;
        std::optional<std::chrono::steady_clock::time_point> deadline_;
        bool summaryPending_{ false };
        std::jthread worker_;
    };

    class BenchmarkAutoLoader
    {
    public:
        static BenchmarkAutoLoader& GetSingleton()
        {
            static BenchmarkAutoLoader loader;
            return loader;
        }

        ~BenchmarkAutoLoader()
        {
            worker_.request_stop();
        }

        void Schedule()
        {
            if (Settings::sBenchmarkAutoLoadSave.empty() || worker_.joinable())
                return;
            const auto save = Settings::sBenchmarkAutoLoadSave;
            worker_ = std::jthread([save](const std::stop_token a_stop) {
                bool dispatchGateArmed = false;
                try {
                    const auto scheduledAt = std::chrono::steady_clock::now();
                    const auto deadline = scheduledAt +
                        std::chrono::minutes(10);
                    std::optional<std::chrono::steady_clock::time_point> readyAt;
                    while (!a_stop.stop_requested() &&
                           std::chrono::steady_clock::now() < deadline) {
                        const bool warmReady =
                            !Settings::bBenchmarkWaitForWarm ||
                            !Settings::bEnableDecompCache ||
                            !Settings::bPrefaultDecompCache ||
                            BSA::DecompCache::GetSingleton().IsRamWarm();
                        // Main-menu state is published by the engine event
                        // thread. Do not inspect UI-owned state here.
                        if (s_mainMenuReady.load(std::memory_order_acquire) &&
                            warmReady) {
                            readyAt = std::chrono::steady_clock::now();
                            break;
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                    if (a_stop.stop_requested())
                        return;
                    if (!readyAt) {
                        logger::error(
                            "BSAMmap: BENCH AUTOLOAD run={} status=timeout save=\"{}\"",
                            Settings::sBenchmarkRunTag.empty() ? "none" :
                                Settings::sBenchmarkRunTag,
                            save);
                        return;
                    }

                    // Let the configured post-readiness settle interval elapse
                    // before measuring residency. The checkpoint therefore
                    // proves which pages survived that interval instead of
                    // becoming stale while the runner waits to dispatch.
                    const auto settle = std::chrono::seconds(
                        Settings::iBenchmarkAutoLoadDelaySec);
                    while (!a_stop.stop_requested() &&
                           std::chrono::steady_clock::now() - *readyAt < settle) {
                        if (!s_mainMenuReady.load(std::memory_order_acquire)) {
                            logger::error(
                                "BSAMmap: BENCH AUTOLOAD run={} status=cancelled_during_settle save=\"{}\"",
                                Settings::sBenchmarkRunTag.empty() ? "none" :
                                    Settings::sBenchmarkRunTag,
                                save);
                            return;
                        }
                        if (std::chrono::steady_clock::now() >= deadline) {
                            logger::error(
                                "BSAMmap: BENCH AUTOLOAD run={} status=timeout_during_settle save=\"{}\"",
                                Settings::sBenchmarkRunTag.empty() ? "none" :
                                    Settings::sBenchmarkRunTag,
                                save);
                            return;
                        }
                        std::this_thread::sleep_for(
                            std::chrono::milliseconds(100));
                    }
                    const auto settleFinished =
                        std::chrono::steady_clock::now();
                    if (a_stop.stop_requested())
                        return;
                    if (!s_mainMenuReady.load(std::memory_order_acquire)) {
                        logger::error(
                            "BSAMmap: BENCH AUTOLOAD run={} status=cancelled_after_settle save=\"{}\"",
                            Settings::sBenchmarkRunTag.empty() ? "none" :
                                Settings::sBenchmarkRunTag,
                            save);
                        return;
                    }

                    // Close the checkpoint-to-load gap. kPreLoadGame hands this
                    // producer off to kSaveMessage without exposing an ungated
                    // window.
                    SetLoadProducer(LoadProducer::kBenchmarkDispatch, true);
                    dispatchGateArmed = true;
                    const auto checkpointStarted =
                        std::chrono::steady_clock::now();
                    LogCacheState("pre_autoload", true, true);
                    const auto checkpointFinished =
                        std::chrono::steady_clock::now();

                    // Keep a small, arm-independent quiet period after the
                    // residency query and synchronous proof log so their CPU
                    // and log I/O do not carry directly into save loading.
                    constexpr auto kPostCheckpointQuiet =
                        std::chrono::milliseconds(250);
                    while (!a_stop.stop_requested() &&
                           std::chrono::steady_clock::now() -
                                   checkpointFinished < kPostCheckpointQuiet) {
                        if (!s_mainMenuReady.load(std::memory_order_acquire)) {
                            SetLoadProducer(
                                LoadProducer::kBenchmarkDispatch, false);
                            dispatchGateArmed = false;
                            logger::error(
                                "BSAMmap: BENCH AUTOLOAD run={} status=cancelled_post_checkpoint save=\"{}\"",
                                Settings::sBenchmarkRunTag.empty() ? "none" :
                                    Settings::sBenchmarkRunTag,
                                save);
                            return;
                        }
                        if (std::chrono::steady_clock::now() >= deadline) {
                            SetLoadProducer(
                                LoadProducer::kBenchmarkDispatch, false);
                            dispatchGateArmed = false;
                            logger::error(
                                "BSAMmap: BENCH AUTOLOAD run={} status=timeout_post_checkpoint save=\"{}\"",
                                Settings::sBenchmarkRunTag.empty() ? "none" :
                                    Settings::sBenchmarkRunTag,
                                save);
                            return;
                        }
                        std::this_thread::sleep_for(
                            std::chrono::milliseconds(25));
                    }
                    if (a_stop.stop_requested()) {
                        SetLoadProducer(
                            LoadProducer::kBenchmarkDispatch, false);
                        dispatchGateArmed = false;
                        return;
                    }

                    const auto dispatchReady =
                        std::chrono::steady_clock::now();
                    auto* tasks = SKSE::GetTaskInterface();
                    if (!tasks) {
                        SetLoadProducer(LoadProducer::kBenchmarkDispatch, false);
                        dispatchGateArmed = false;
                        logger::error(
                            "BSAMmap: BENCH AUTOLOAD run={} status=no_task_interface save=\"{}\"",
                            Settings::sBenchmarkRunTag.empty() ? "none" :
                                Settings::sBenchmarkRunTag,
                            save);
                        return;
                    }
                    const bool warmReadyAtDispatch =
                        !Settings::bBenchmarkWaitForWarm ||
                        !Settings::bEnableDecompCache ||
                        !Settings::bPrefaultDecompCache ||
                        BSA::DecompCache::GetSingleton().IsRamWarm();
                    logger::info(
                        "BSAMmap: BENCH AUTOLOAD run={} status=dispatching save=\"{}\" wait_warm={} warm_ready={} main_menu_ready={} settle_s={} post_checkpoint_target_ms={} condition_ms={:.3f} predispatch_ms={:.3f} settle_ms={:.3f} gate_ms={:.3f} checkpoint_ms={:.3f} post_checkpoint_ms={:.3f}",
                        Settings::sBenchmarkRunTag.empty() ? "none" :
                            Settings::sBenchmarkRunTag,
                        save, Settings::bBenchmarkWaitForWarm,
                        warmReadyAtDispatch,
                        s_mainMenuReady.load(std::memory_order_acquire),
                        Settings::iBenchmarkAutoLoadDelaySec,
                        kPostCheckpointQuiet.count(),
                        std::chrono::duration<double, std::milli>(
                            *readyAt - scheduledAt).count(),
                        std::chrono::duration<double, std::milli>(
                            dispatchReady - scheduledAt).count(),
                        std::chrono::duration<double, std::milli>(
                            settleFinished - *readyAt).count(),
                        std::chrono::duration<double, std::milli>(
                            checkpointStarted - settleFinished).count(),
                        std::chrono::duration<double, std::milli>(
                            checkpointFinished - checkpointStarted).count(),
                        std::chrono::duration<double, std::milli>(
                            dispatchReady - checkpointFinished).count());
                    tasks->AddTask([save] {
                        const auto run = Settings::sBenchmarkRunTag.empty() ?
                            std::string{ "none" } : Settings::sBenchmarkRunTag;
                        if (!s_mainMenuReady.load(std::memory_order_acquire)) {
                            SetLoadProducer(
                                LoadProducer::kBenchmarkDispatch, false);
                            logger::error(
                                "BSAMmap: BENCH AUTOLOAD run={} status=cancelled_not_main_menu save=\"{}\"",
                                run, save);
                            return;
                        }
                        if (auto* manager =
                                RE::BGSSaveLoadManager::GetSingleton()) {
                            // This marker is the authoritative proof that the
                            // exact-name load API is about to be called on the
                            // engine task thread. The A/B runner rejects a run
                            // if it is absent or follows kPreLoadGame.
                            logger::info(
                                "BSAMmap: BENCH AUTOLOAD run={} status=calling_load save=\"{}\"",
                                run, save);
                            manager->Load(save.c_str());
                            logger::info(
                                "BSAMmap: BENCH AUTOLOAD run={} status=returned save=\"{}\"",
                                run, save);
                        } else {
                            SetLoadProducer(
                                LoadProducer::kBenchmarkDispatch, false);
                            logger::error(
                                "BSAMmap: BENCH AUTOLOAD run={} status=no_save_manager save=\"{}\"",
                                run, save);
                        }
                    });
                    // The task now owns this producer: kPreLoadGame hands it to
                    // kSaveMessage, or the no-manager branch releases it.
                    dispatchGateArmed = false;
                } catch (const std::exception& e) {
                    if (dispatchGateArmed) {
                        SetLoadProducer(
                            LoadProducer::kBenchmarkDispatch, false);
                    }
                    ReportUnhandled("benchmark auto-load failed", e.what());
                } catch (...) {
                    if (dispatchGateArmed) {
                        SetLoadProducer(
                            LoadProducer::kBenchmarkDispatch, false);
                    }
                    ReportUnhandled(
                        "benchmark auto-load failed", "unknown exception");
                }
            });
        }

    private:
        std::jthread worker_{};
    };

    // Loading-screen gate. kPreLoadGame only fires for SAVE loads, not cell
    // transitions / fast travel / door loads — but every one of those shows
    // the LoadingMenu. Tracking that menu's open/close marks the cache
    // "load active" for ALL loads, so background flush + eviction stand down
    // and never collide with a load (the v1.6.4 VR infinite-load class).
    class LoadMenuSink : public RE::BSTEventSink<RE::MenuOpenCloseEvent>
    {
    public:
        static LoadMenuSink* GetSingleton()
        {
            static LoadMenuSink s;
            return &s;
        }

        RE::BSEventNotifyControl ProcessEvent(
            const RE::MenuOpenCloseEvent*               a_event,
            RE::BSTEventSource<RE::MenuOpenCloseEvent>*) override
        {
            try {
                if (a_event && a_event->menuName == RE::LoadingMenu::MENU_NAME) {
                    SetLoadProducer(LoadProducer::kLoadingMenu, a_event->opening);
                } else if (a_event &&
                           a_event->menuName == RE::MainMenu::MENU_NAME) {
                    s_mainMenuReady.store(
                        a_event->opening, std::memory_order_release);
                }
            } catch (const std::exception& e) {
                ReportUnhandled("loading-menu event failed", e.what());
            } catch (...) {
                ReportUnhandled("loading-menu event failed", "unknown exception");
            }
            return RE::BSEventNotifyControl::kContinue;
        }
    };

    void HandleMessage(SKSE::MessagingInterface::Message* a_msg)
    {
        if (!a_msg) return;

        switch (a_msg->type) {
        case SKSE::MessagingInterface::kDataLoaded:
        {
            // UI queries and menu-event publication stay on this engine event
            // thread. The benchmark worker consumes only atomics.
            static bool sinkInstalled = false;
            if (!sinkInstalled) {
                if (auto* ui = RE::UI::GetSingleton()) {
                    ui->AddEventSink<RE::MenuOpenCloseEvent>(
                        LoadMenuSink::GetSingleton());
                    sinkInstalled = true;
                    SetLoadProducer(LoadProducer::kLoadingMenu,
                        ui->IsMenuOpen(RE::LoadingMenu::MENU_NAME));
                    s_mainMenuReady.store(
                        ui->IsMenuOpen(RE::MainMenu::MENU_NAME),
                        std::memory_order_release);
                } else {
                    logger::warn(
                        "BSAMmap: UI unavailable at DataLoaded; load-phase gating and benchmark auto-load are unavailable");
                }
            }

            // Start the managed cache-commit worker (if building).
            if (Settings::bEnableDecompCache) {
                auto& dcache = BSA::DecompCache::GetSingleton();
                // The managed worker performs the initial commit immediately
                // without blocking Skyrim's DataLoaded/main-menu thread.
                dcache.StartBackgroundFlush();
            }
            // Always-fires marker so external benchmark drivers can detect
            // main-menu readiness regardless of cache settings.
            logger::info("BSAMmap: Data loaded — main menu ready");
            {
                LARGE_INTEGER nowStartup;
                QueryPerformanceCounter(&nowStartup);
                const double startupSec =
                    static_cast<double>(nowStartup.QuadPart - s_pluginLoadStart.QuadPart) /
                    static_cast<double>((std::max)(s_qpcFreq.QuadPart, LONGLONG{ 1 }));
                logger::info("BSAMmap: STARTUP TIME (plugin load -> main menu): {:.3f}s", startupSec);
                if (Settings::bMeasureStats) {
                    const auto process = CaptureProcessSnapshot();
                    constexpr double mib = 1024.0 * 1024.0;
                    logger::info(
                        "BSAMmap: BENCH STARTUP run={} seconds={:.6f} process_valid={} working_set_mib={:.3f} private_mib={:.3f} page_faults={} read_ops={} read_mib={:.3f} cpu_ms={:.3f} available_ram_mib={:.3f}",
                        Settings::sBenchmarkRunTag.empty() ? "none" :
                            Settings::sBenchmarkRunTag,
                        startupSec, process.valid, process.workingSetBytes / mib,
                        process.privateBytes / mib, process.pageFaults,
                        process.readOperations, process.readBytes / mib,
                        process.cpu100ns / 10'000.0,
                        process.availablePhysicalBytes / mib);
                }
            }
            LogCacheState("data_loaded", false);
            BenchmarkAutoLoader::GetSingleton().Schedule();
            break;
        }
        case SKSE::MessagingInterface::kPreLoadGame:
        {
            const auto requestedSave = BenchmarkSaveName(a_msg);
            const bool benchmarkDispatched =
                IsLoadProducerActive(LoadProducer::kBenchmarkDispatch);
            SetLoadProducer(LoadProducer::kSaveMessage, true);
            SetLoadProducer(LoadProducer::kBenchmarkDispatch, false);
            s_saveLoadMeasured = Settings::bMeasureStats;
            s_saveLoadTimed = s_saveLoadMeasured ||
                !Settings::sBenchmarkRunTag.empty() ||
                !Settings::sBenchmarkAutoLoadSave.empty();
            if (!s_saveLoadTimed)
                break;

            GameplaySnapshotScheduler::GetSingleton().Cancel();
            logger::info(
                "BSAMmap: BENCH SAVE_LOAD_BEGIN run={} benchmark_dispatch={} requested_save=\"{}\"",
                Settings::sBenchmarkRunTag.empty() ? "none" :
                    Settings::sBenchmarkRunTag,
                benchmarkDispatched,
                requestedSave.empty() ? "none" : requestedSave);
            if (!s_saveLoadMeasured) {
                s_preLoadProcess = CaptureProcessSnapshot();
                QueryPerformanceCounter(&s_saveLoadStart);
                break;
            }

            s_preLoadCacheState = Settings::bEnableDecompCache
                ? BSA::DecompCache::GetSingleton().GetBenchmarkSnapshot(false)
                : BSA::DecompCacheBenchmarkSnapshot{};
            logger::info(
                "BSAMmap: Save load started (warm_complete={}, eligible_entries={}/{}, eligible_payload_mib={:.3f}/{:.3f}, historical_warm_mib={:.3f})",
                s_preLoadCacheState.warmComplete,
                s_preLoadCacheState.eligibleEntryCount,
                s_preLoadCacheState.entryCount,
                s_preLoadCacheState.eligiblePayloadBytes / (1024.0 * 1024.0),
                s_preLoadCacheState.payloadBytes / (1024.0 * 1024.0),
                s_preLoadCacheState.historicallyWarmedBytes / (1024.0 * 1024.0));
            // Expensive cache enumeration/logging is outside the load timer.
            // Capture counters/process state next, then start QPC immediately
            // before returning to the engine.
            s_preLoadIo = Hooks::GetIoStatsSnapshot();
            s_preLoadProcess = CaptureProcessSnapshot();
            QueryPerformanceCounter(&s_saveLoadStart);
            break;
        }

        case SKSE::MessagingInterface::kPostLoadGame:
        {
            // SKSE encodes the engine LoadGame result in Message::data.
            const bool loadSuccess = a_msg->data != nullptr;
            if (!s_saveLoadTimed) {
                SetLoadProducer(LoadProducer::kSaveMessage, false);
                break;
            }
            const bool detailed = s_saveLoadMeasured;
            s_saveLoadMeasured = false;
            s_saveLoadTimed = false;

            LARGE_INTEGER now;
            QueryPerformanceCounter(&now);
            const auto postIo = detailed
                ? Hooks::GetIoStatsSnapshot()
                : Hooks::IoStatsSnapshot{};
            const auto postProcess = CaptureProcessSnapshot();
            const auto postCacheState = detailed && Settings::bEnableDecompCache
                ? BSA::DecompCache::GetSingleton().GetBenchmarkSnapshot(false)
                : BSA::DecompCacheBenchmarkSnapshot{};
            const double sec = static_cast<double>(
                now.QuadPart - s_saveLoadStart.QuadPart) /
                static_cast<double>((std::max)(
                    s_qpcFreq.QuadPart, LONGLONG{ 1 }));
            const auto safeDelta = [](const std::uint64_t a_end,
                                      const std::uint64_t a_begin) {
                return a_end >= a_begin ? a_end - a_begin : 0;
            };
            constexpr double mib = 1024.0 * 1024.0;
            logger::info(
                "BSAMmap: BENCH SAVE_LOAD_TIMING run={} seconds={:.6f} load_success={} process_valid={} page_faults={} process_read_ops={} process_read_mib={:.3f} process_cpu_ms={:.3f}",
                Settings::sBenchmarkRunTag.empty() ? "none" :
                    Settings::sBenchmarkRunTag,
                sec, loadSuccess,
                s_preLoadProcess.valid && postProcess.valid,
                safeDelta(postProcess.pageFaults, s_preLoadProcess.pageFaults),
                safeDelta(postProcess.readOperations,
                    s_preLoadProcess.readOperations),
                safeDelta(postProcess.readBytes,
                    s_preLoadProcess.readBytes) / mib,
                safeDelta(postProcess.cpu100ns,
                    s_preLoadProcess.cpu100ns) / 10'000.0);

            if (!detailed) {
                SetLoadProducer(LoadProducer::kSaveMessage, false);
                break;
            }

            const auto deltaPath = [](const Hooks::ReadPathStats& a_end,
                                      const Hooks::ReadPathStats& a_begin) {
                return Hooks::ReadPathStats{
                    a_end.calls - a_begin.calls,
                    a_end.requestedBytes - a_begin.requestedBytes,
                    a_end.returnedBytes - a_begin.returnedBytes,
                    a_end.failures - a_begin.failures,
                    a_end.qpcTicks - a_begin.qpcTicks
                };
            };
            const auto mmap = deltaPath(postIo.directMmap, s_preLoadIo.directMmap);
            const auto cache = deltaPath(postIo.cache, s_preLoadIo.cache);
            const auto decomp = deltaPath(
                postIo.decompressor, s_preLoadIo.decompressor);
            const auto fallback = deltaPath(
                postIo.directStock, s_preLoadIo.directStock);
            const auto sourceMmap = deltaPath(
                postIo.compressedSourceMmap,
                s_preLoadIo.compressedSourceMmap);
            const auto sourceStock = deltaPath(
                postIo.compressedSourceStock,
                s_preLoadIo.compressedSourceStock);
            const double mmapMB = mmap.returnedBytes / mib;
            const double cacheMB = cache.returnedBytes / mib;
            const double decompMB = decomp.returnedBytes / mib;
            const double fallbackMB = fallback.returnedBytes / mib;
            const double totalMB = mmapMB + cacheMB + decompMB + fallbackMB;
            const double throughput = (sec > 0.001) ? totalMB / sec : 0.0;

            const double pMmap = totalMB > 0.001 ? (mmapMB / totalMB * 100) : 0;
            const double pCache = totalMB > 0.001 ? (cacheMB / totalMB * 100) : 0;
            const double pDecomp = totalMB > 0.001 ? (decompMB / totalMB * 100) : 0;
            const double pFallback = totalMB > 0.001 ? (fallbackMB / totalMB * 100) : 0;

            logger::info("BSAMmap: SAVE LOAD TIME: {:.3f}s | {:.1f} MB payload total | "
                "direct mmap {:.1f}/{:.0f}% + cache {:.1f}/{:.0f}% + "
                "compressed path {:.1f}/{:.0f}% + native direct {:.1f}/{:.0f}% | {:.1f} MB/s",
                sec, totalMB,
                mmapMB, pMmap, cacheMB, pCache,
                decompMB, pDecomp, fallbackMB, pFallback,
                throughput);
            logger::info(
                "BSAMmap: SAVE LOAD SOURCE I/O: mapped {:.1f} MB + stock {:.1f} MB (not included in logical payload total)",
                sourceMmap.returnedBytes / mib,
                sourceStock.returnedBytes / mib);

            const auto& beforeDiag = s_preLoadCacheState.diagnostics;
            const auto& afterDiag = postCacheState.diagnostics;
            const auto lookupAttempts = safeDelta(
                afterDiag.lookupAttempts, beforeDiag.lookupAttempts);
            const auto lookupHits = safeDelta(
                afterDiag.lookupHits, beforeDiag.lookupHits);
            const auto lookupArchiveMisses = safeDelta(
                afterDiag.lookupArchiveMisses, beforeDiag.lookupArchiveMisses);
            const auto lookupInvalidMisses = safeDelta(
                afterDiag.lookupInvalidMisses, beforeDiag.lookupInvalidMisses);
            const auto lookupCold = safeDelta(
                afterDiag.lookupColdMisses, beforeDiag.lookupColdMisses);
            const auto lookupAbsent = safeDelta(
                afterDiag.lookupEntryMisses, beforeDiag.lookupEntryMisses);
            const auto checksumComputations = safeDelta(
                afterDiag.checksumComputations,
                beforeDiag.checksumComputations);
            const auto checksumBytes = safeDelta(
                afterDiag.checksumBytes, beforeDiag.checksumBytes);
            const auto checksumTicks = safeDelta(
                afterDiag.checksumQpcTicks, beforeDiag.checksumQpcTicks);
            const auto checksumFailures = safeDelta(
                afterDiag.checksumFailures, beforeDiag.checksumFailures);
            const auto checksumWaits = safeDelta(
                afterDiag.checksumWaits, beforeDiag.checksumWaits);
            const auto attachments = safeDelta(
                postIo.cacheAttachments, s_preLoadIo.cacheAttachments);
            const auto sizeMismatches = safeDelta(
                postIo.cacheSizeMismatches,
                s_preLoadIo.cacheSizeMismatches);
            const auto cacheNotReady = safeDelta(
                postIo.cacheNotReady, s_preLoadIo.cacheNotReady);
            const auto cacheServeDisabled = safeDelta(
                postIo.cacheServeDisabled, s_preLoadIo.cacheServeDisabled);
            const auto loadPhaseUncompressedCalls = safeDelta(
                postIo.loadPhaseUncompressedCalls,
                s_preLoadIo.loadPhaseUncompressedCalls);
            const auto loadPhaseUncompressedBytes = safeDelta(
                postIo.loadPhaseUncompressedRequestedBytes,
                s_preLoadIo.loadPhaseUncompressedRequestedBytes);
            const auto loadPhaseCompressedCalls = safeDelta(
                postIo.loadPhaseCompressedCalls,
                s_preLoadIo.loadPhaseCompressedCalls);
            const auto loadPhaseCompressedBytes = safeDelta(
                postIo.loadPhaseCompressedRequestedBytes,
                s_preLoadIo.loadPhaseCompressedRequestedBytes);
            const auto loadPhaseGrandfathered = safeDelta(
                postIo.loadPhaseGrandfatheredCacheCalls,
                s_preLoadIo.loadPhaseGrandfatheredCacheCalls);
            const double compressedOutput = cacheMB + decompMB;
            const double cacheCompressedShare = compressedOutput > 0.0
                ? cacheMB * 100.0 / compressedOutput : 0.0;
            const double lookupHitRate = lookupAttempts > 0
                ? lookupHits * 100.0 / lookupAttempts : 0.0;
            const double frequency = static_cast<double>((std::max)(
                s_qpcFreq.QuadPart, LONGLONG{ 1 }));

            logger::info(
                "BSAMmap: BENCH SAVE_LOAD run={} seconds={:.6f} load_success={} logical_mib={:.3f} logical_mib_s={:.3f} mmap_mib={:.3f} cache_mib={:.3f} decompressor_mib={:.3f} stock_mib={:.3f} cache_compressed_share_pct={:.3f} source_mmap_mib={:.3f} source_stock_mib={:.3f} calls={}/{}/{}/{} failures={}/{}/{}/{} path_operation_ms={:.3f}/{:.3f}/{:.3f}/{:.3f} lookup_attempts={} lookup_hits={} lookup_hit_pct={:.3f} lookup_archive_miss={} lookup_invalid_miss={} lookup_absent={} lookup_cold={} cache_not_ready={} serve_disabled={} attachments={} size_mismatch={} checksum_count={} checksum_mib={:.3f} checksum_ms={:.3f} checksum_failures={} checksum_waits={} eligible_entries={}/{} eligible_payload_mib={:.3f}/{:.3f} prefault_enabled={} warm_complete={} during_save_load={} load_phase_calls={}/{}/{} load_phase_requested_mib={:.3f}/{:.3f} process_valid={} page_faults={} process_read_ops={} process_read_mib={:.3f} process_cpu_ms={:.3f} ws_before_mib={:.3f} ws_after_mib={:.3f} private_before_mib={:.3f} private_after_mib={:.3f} avail_ram_before_mib={:.3f} avail_ram_after_mib={:.3f}",
                Settings::sBenchmarkRunTag.empty() ? "none" :
                    Settings::sBenchmarkRunTag,
                sec, loadSuccess, totalMB, throughput, mmapMB, cacheMB, decompMB,
                fallbackMB, cacheCompressedShare,
                sourceMmap.returnedBytes / mib,
                sourceStock.returnedBytes / mib,
                mmap.calls, cache.calls, decomp.calls, fallback.calls,
                mmap.failures, cache.failures, decomp.failures,
                fallback.failures,
                mmap.qpcTicks * 1000.0 / frequency,
                cache.qpcTicks * 1000.0 / frequency,
                decomp.qpcTicks * 1000.0 / frequency,
                fallback.qpcTicks * 1000.0 / frequency,
                lookupAttempts, lookupHits, lookupHitRate,
                lookupArchiveMisses, lookupInvalidMisses,
                lookupAbsent, lookupCold, cacheNotReady, cacheServeDisabled,
                attachments, sizeMismatches,
                checksumComputations, checksumBytes / mib,
                checksumTicks * 1000.0 / frequency,
                checksumFailures, checksumWaits,
                s_preLoadCacheState.eligibleEntryCount,
                s_preLoadCacheState.entryCount,
                s_preLoadCacheState.eligiblePayloadBytes / mib,
                s_preLoadCacheState.payloadBytes / mib,
                s_preLoadCacheState.prefaultEnabled,
                s_preLoadCacheState.warmComplete,
                Settings::bEnableDuringSaveLoad,
                loadPhaseUncompressedCalls, loadPhaseCompressedCalls,
                loadPhaseGrandfathered,
                loadPhaseUncompressedBytes / mib,
                loadPhaseCompressedBytes / mib,
                s_preLoadProcess.valid && postProcess.valid,
                safeDelta(postProcess.pageFaults, s_preLoadProcess.pageFaults),
                safeDelta(postProcess.readOperations,
                    s_preLoadProcess.readOperations),
                safeDelta(postProcess.readBytes,
                    s_preLoadProcess.readBytes) / mib,
                safeDelta(postProcess.cpu100ns,
                    s_preLoadProcess.cpu100ns) / 10'000.0,
                s_preLoadProcess.workingSetBytes / mib,
                postProcess.workingSetBytes / mib,
                s_preLoadProcess.privateBytes / mib,
                postProcess.privateBytes / mib,
                s_preLoadProcess.availablePhysicalBytes / mib,
                postProcess.availablePhysicalBytes / mib);
            LogCacheState("post_load", true);
            // Release the worker only after the end timestamp, all process/I/O
            // snapshots, and the residency query have completed. Otherwise a
            // resumed flush/warm pass contaminates the measured save-load arm.
            SetLoadProducer(LoadProducer::kSaveMessage, false);
            // One managed worker coalesces repeated loads and lets post-load
            // streaming settle before the gameplay benchmark begins.
            GameplaySnapshotScheduler::GetSingleton().Schedule();
            break;
        }
        }
    }

    void OnDataReady(SKSE::MessagingInterface::Message* a_message)
    {
        try {
            HandleMessage(a_message);
        } catch (const std::exception& e) {
            ReportUnhandled("SKSE message handler failed", e.what());
        } catch (...) {
            ReportUnhandled("SKSE message handler failed", "unknown exception");
        }
    }
}

namespace
{
    bool LoadPlugin(const SKSE::LoadInterface* a_skse, bool& a_runtimeMutated)
    {
        SKSE::Init(a_skse);
        InitializeLog();
        QueryPerformanceFrequency(&s_qpcFreq);
        LARGE_INTEGER archiveInitStart{}, archiveInitEnd{};
        LARGE_INTEGER cacheInitStart{}, cacheInitEnd{};
        LARGE_INTEGER hookInitStart{}, hookInitEnd{};

        HMODULE self = nullptr;
        if (!GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(&LoadPlugin),
                &self)) {
            throw std::runtime_error("Could not resolve the current plugin module");
        }
        if (const auto legacy = GetModuleHandleW(L"BSAMemoryMap.dll");
            legacy && legacy != self) {
            logger::critical(
                "FasterFileCopy: legacy BSAMemoryMap.dll is already loaded. "
                "This instance will remain inactive to prevent double hooks; remove the old DLL.");
            return true;
        }

        const char* runtime = REL::Module::IsVR() ? "VR" : "SE/AE";
        logger::info("FasterFileCopy v{} (runtime={}, game={})",
            FFC_VERSION_STRING,
            runtime, REL::Module::get().version().string());

        Settings::Load();
        if (const auto log = spdlog::default_logger()) {
            log->set_level(Settings::bLogReads ?
                spdlog::level::debug : spdlog::level::info);
        }
        BSResource::Field::Init();

        if (!Settings::bEnabled) {
            logger::info("BSAMmap: Disabled via settings — skipping");
            return true;
        }
        if (!Settings::bBaselineMode && !Settings::bEnableMmap &&
            !Settings::bEnableDecompCache) {
            logger::info("BSAMmap: All acceleration features are disabled — skipping");
            return true;
        }

        auto& manager = BSA::MemoryMapManager::GetSingleton();
        bool managerInitialized = false;
        if (!Settings::bBaselineMode) {
            auto dataPath = Settings::Win32LongPath(
                Settings::ModulePath(nullptr).parent_path() / L"Data");
            std::error_code pathError;
            if (!std::filesystem::is_directory(dataPath, pathError) || pathError) {
                logger::error("BSAMmap: Data directory not found or inaccessible: {}",
                    Settings::PathForLog(dataPath));
                return true;
            }

            QueryPerformanceCounter(&archiveInitStart);
            if (!manager.Initialize(dataPath)) {
                logger::warn("BSAMmap: No valid BSA archives were found; plugin inactive");
                return true;
            }
            QueryPerformanceCounter(&archiveInitEnd);
            managerInitialized = true;

            if (Settings::bEnableDecompCache) {
                try {
                    QueryPerformanceCounter(&cacheInitStart);
                    BSA::DecompCache::GetSingleton().Initialize(
                        dataPath, manager.GetArchives());
                    QueryPerformanceCounter(&cacheInitEnd);
                    // Start the managed worker now, not at kDataLoaded: the
                    // below-normal warm pass then overlaps the engine's long
                    // main-menu load, so the FIRST save load after launch
                    // already finds cache pages RAM-resident (a fresh launch
                    // previously served 0% cache because warming had not
                    // finished by the time the player hit Load).
                    BSA::DecompCache::GetSingleton().StartBackgroundFlush();
                } catch (const std::exception& e) {
                    QueryPerformanceCounter(&cacheInitEnd);
                    Settings::bEnableDecompCache = false;
                    logger::error(
                        "BSAMmap: Decompression cache initialization failed; direct mmap remains available: {}",
                        e.what());
                } catch (...) {
                    QueryPerformanceCounter(&cacheInitEnd);
                    Settings::bEnableDecompCache = false;
                    logger::error(
                        "BSAMmap: Decompression cache initialization failed; direct mmap remains available");
                }
            }
            if (!Settings::bEnableMmap && !Settings::bEnableDecompCache) {
                logger::warn("BSAMmap: No acceleration feature initialized successfully; plugin inactive");
                manager.Shutdown();
                return true;
            }
        }

        auto* messaging = SKSE::GetMessagingInterface();
        if (!messaging || !messaging->RegisterListener(OnDataReady)) {
            logger::error("BSAMmap: Could not register the SKSE lifecycle listener; plugin inactive");
            if (managerInitialized)
                manager.Shutdown();
            return false;
        }

        // Keep the DLL loaded if anything below throws: hook installation can
        // mutate executable state before returning.
        a_runtimeMutated = true;
        QueryPerformanceCounter(&hookInitStart);
        Hooks::Install();
        Hooks::StartStatsThread();
        QueryPerformanceCounter(&hookInitEnd);

        if (Settings::bMeasureStats) {
            const auto milliseconds = [](const LARGE_INTEGER& a_start,
                                         const LARGE_INTEGER& a_end) {
                return a_start.QuadPart > 0 && a_end.QuadPart >= a_start.QuadPart
                    ? (a_end.QuadPart - a_start.QuadPart) * 1000.0 /
                        static_cast<double>((std::max)(
                            s_qpcFreq.QuadPart, LONGLONG{ 1 }))
                    : 0.0;
            };
            logger::info(
                "BSAMmap: BENCH INIT_PHASES run={} archive_scan_map_ms={:.3f} cache_scan_map_ms={:.3f} hook_install_ms={:.3f}",
                Settings::sBenchmarkRunTag.empty() ? "none" :
                    Settings::sBenchmarkRunTag,
                milliseconds(archiveInitStart, archiveInitEnd),
                milliseconds(cacheInitStart, cacheInitEnd),
                milliseconds(hookInitStart, hookInitEnd));
        }

        return true;
    }
}

SKSEPluginLoad(const SKSE::LoadInterface* a_skse)
{
    QueryPerformanceCounter(&s_pluginLoadStart);
    bool runtimeMutated = false;
    try {
        return LoadPlugin(a_skse, runtimeMutated);
    } catch (const std::exception& e) {
        ReportUnhandled("plugin load failed", e.what());
    } catch (...) {
        ReportUnhandled("plugin load failed", "unknown exception");
    }
    // Returning false may allow SKSE to unload the DLL. That is safe only
    // before hooks have possibly been installed.
    return runtimeMutated;
}
