#include "PCH.h"
#include "Plugin.h"
#include "Settings.h"
#include "BA2MemoryMap.h"
#include "DecompCache.h"
#include "Hooks.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <system_error>
#include <thread>
#include <vector>

// BA2 Memory Map — F4SE plugin that memory-maps uncompressed BA2 archives
// and serves asset reads directly from the page cache, eliminating ReadFile
// syscalls and the kernel-to-user buffer copy.
//
// Supports: Fallout 4 OG (1.10.163), NG (1.10.984+), VR (1.2.72)
// Based on CommonLibF4-NG (alandtse fork) with REL::Relocate

#include <string_view>
using namespace F4SE;
using namespace REL;
using namespace std::literals;

constexpr size_t TRAMPOLINE_SIZE = 1u << 11;

const auto RUNTIME_VERSION_MIN = Relocate(
    F4SE::RUNTIME_1_10_163,
    F4SE::RUNTIME_1_10_984,
    F4SE::RUNTIME_VR_1_2_72
);
const auto RUNTIME_VERSION_MAX = Relocate(
    F4SE::RUNTIME_1_10_163,
    REL::Version{ 1, 11, 191, 0 },
    F4SE::RUNTIME_VR_1_2_72
);

inline void StartSavePrefetchThread();
inline void StartPluginPrewarmThread(const std::filesystem::path& dataPath);

// ── Lifecycle hooks ─────────────────────────────────────────────────────────

inline void OnModuleLoad()
{
    logger::info("OnModuleLoad");

    // Resolve the game's Data directory.
    // F4SE's log_directory gives us  <Documents>/My Games/Fallout4/F4SE
    // The Data dir is next to the game executable.
    std::filesystem::path dataPath;
    {
        // Get the game executable path and go up to the install directory.
        wchar_t exePath[MAX_PATH]{};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        dataPath = std::filesystem::path(exePath).parent_path() / "Data";
    }

    if (!std::filesystem::exists(dataPath)) {
        logger::error("FFC4: Data directory not found: {}", dataPath.string());
        return;
    }

    // Plugin pre-warm starts NOW, before any other init, to maximize the head
    // start before the engine begins parsing plugins. Skipped in baseline mode
    // for benchmark fairness.
    if (!Settings::bBaselineMode)
        StartPluginPrewarmThread(dataPath);

    // Baseline mode: install hooks + stats thread only. Skip BA2 mmap and
    // DecompCache init so the plugin behaves like it's disabled on every
    // hot path while timing instrumentation still runs.
    //
    // Also skip BA2 mmap init when bEnableMmap is off — the 22+ GB of mapped
    // virtual address space affects the process layout even when we never
    // serve from it, and non-baseline+mmap-off was still crashing engine code
    // upstream (distinctive rdi=0x000700000020 at Fallout4.exe+0x2DD4F5
    // during save-load on AE). Matches the baseline "skip mapping entirely"
    // path, leaving bEnableMmap=false as a true "disabled" mode.
    if (Settings::bBaselineMode || !Settings::bEnableMmap) {
        logger::info("FFC4: mmap init skipped (baseline={}, enableMmap={})",
            Settings::bBaselineMode, Settings::bEnableMmap);
        Hooks::Install();
        Hooks::StartStatsThread();
        return;
    }

    // Memory-map all BA2 archives.
    auto& mgr = BA2::MemoryMapManager::GetSingleton();
    if (!mgr.Initialize(dataPath)) {
        logger::warn("FFC4: No archives were memory-mapped");
        return;
    }

    // Initialize decompression cache
    if (Settings::bEnableDecompCache) {
        auto& dc = BA2::DecompCache::GetSingleton();
        dc.Initialize(dataPath, mgr.GetArchives());

        // Proactive cache building disabled — it races with the game's
        // archive loading and causes crashes. We'll rely on passive
        // caching (entries captured during normal gameplay).
        // TODO: Fix BuildAllCache thread safety before re-enabling.
    }

    Hooks::Install();
    Hooks::StartStatsThread();

    // Build the texture fingerprint index eagerly on a background thread
    // (runs concurrently with main-menu intro BK2s and prefault). Keeps the
    // HookedInflate hot path non-blocking during save load — it checks the
    // ready flag and falls through if the build hasn't finished yet.
    if (Settings::bEnableDecompCache)
        Hooks::BuildCompFingerprintIndexAsync(dataPath);
}

inline void OnGameDataReady()
{
    logger::info("OnGameDataReady");

    if (Settings::bBaselineMode)
        return;

    // Only freeze source cache in startup-only mode (iMode == 0).
    // When iMode >= 1 (gameplay + background flush), we need to keep
    // resolving new source→archive mappings encountered during play.
    if (Settings::iDecompCacheMode == 0)
        Hooks::FreezeSourceCache();

    // Flush startup-load captures to disk now. Background flush thread is
    // deferred to first OnPreLoadGame — the main-menu period is mostly
    // capture-free, so running the flush thread there only competes with
    // the main-menu prefault for disk bandwidth.
    if (Settings::bEnableDecompCache) {
        auto& dc = BA2::DecompCache::GetSingleton();
        dc.FlushToDisk();
        logger::info("DecompCache: {} hits ({:.1f} MB), {} misses, {:.1f} MB on disk",
            dc.GetCacheHits(), dc.GetCacheHitBytes() / (1024.0 * 1024.0),
            dc.GetCacheMisses(), dc.GetTotalCacheBytes() / (1024.0 * 1024.0));
    }

    // Prefault + save prefetch are both detached background threads with
    // cooperative yields — they naturally throttle against intro BK2 I/O
    // without needing a MainMenu event trigger. Avoids the AE 1.11
    // RegisterSink AV at Fallout4.exe+02DD4F5.
    if (Settings::bEnableDecompCache)
        BA2::DecompCache::GetSingleton().PrefaultCachePages();
    StartSavePrefetchThread();
}

inline void StartSavePrefetchThread()
{
    if (!Settings::bPrefetchRecentSaves || Settings::iPrefetchSaveCount <= 0)
        return;

    static std::atomic<bool> s_started{ false };
    if (s_started.exchange(true, std::memory_order_acq_rel))
        return;

    std::thread([]() {
        wchar_t profile[MAX_PATH]{};
        if (!GetEnvironmentVariableW(L"USERPROFILE", profile, MAX_PATH))
            return;

        const wchar_t* gameDir = REL::Module::IsVR() ? L"Fallout4VR" : L"Fallout4";
        std::filesystem::path savesDir =
            std::filesystem::path(profile) / L"Documents" / L"My Games" / gameDir / L"Saves";

        std::error_code ec;
        if (!std::filesystem::exists(savesDir, ec)) return;

        struct Entry {
            std::filesystem::path             path;
            std::filesystem::file_time_type   mtime;
        };
        std::vector<Entry> saves;
        for (auto& e : std::filesystem::directory_iterator(savesDir, ec)) {
            if (!e.is_regular_file(ec)) continue;
            const auto ext = e.path().extension().wstring();
            if (ext == L".fos")
                saves.push_back({ e.path(), e.last_write_time(ec) });
        }
        std::sort(saves.begin(), saves.end(),
            [](const Entry& a, const Entry& b) { return a.mtime > b.mtime; });

        const int n = (std::min)(Settings::iPrefetchSaveCount, static_cast<int>(saves.size()));
        if (n <= 0) return;

        std::vector<char> buf(1u << 20);   // 1 MB scratch
        std::uint64_t totalBytes = 0;
        int            files     = 0;

        auto readSequential = [&](const std::filesystem::path& p) {
            HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (h == INVALID_HANDLE_VALUE) return;
            DWORD read = 0;
            while (ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()), &read, nullptr) && read > 0)
                totalBytes += read;
            CloseHandle(h);
            ++files;
        };

        for (int i = 0; i < n; ++i) {
            readSequential(saves[i].path);
            // F4SE cosave lives alongside with .f4se extension (same stem).
            auto cosave = saves[i].path;
            cosave.replace_extension(L".f4se");
            if (std::filesystem::exists(cosave, ec))
                readSequential(cosave);
        }

        logger::info("SavePrefetch: warmed {} file(s), {:.1f} MB",
            files, totalBytes / (1024.0 * 1024.0));
    }).detach();
}

// Plugin pre-warm — sequentially reads every *.esm/.esp/.esl in Data/ through
// a 1 MB scratch buffer so bytes land in the OS file cache. Engine's later
// plugin parsing reads from warm cache. Sequential read (not mmap+pin) keeps
// the bytes in OS-managed file cache (evictable under pressure) instead of
// our process working set — critical on RAM-tight rigs where the decomp
// cache is already pinned via VirtualLock. Runs in a low-priority background
// thread spawned at OnModuleLoad. Skipped in bBaselineMode for benchmark
// fairness.
static std::atomic<bool> s_pluginPrewarmStarted{ false };

inline void StartPluginPrewarmThread(const std::filesystem::path& dataPath)
{
    if (!Settings::bPrewarmPlugins) return;
    if (s_pluginPrewarmStarted.exchange(true, std::memory_order_acq_rel)) return;

    std::thread([dataPath]() {
        // Lower thread priority so the engine's own plugin reads + the cache
        // VirtualLock thread take precedence on disk + memory bandwidth.
        // We're a hint to the OS file cache, not a critical-path consumer.
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

        LARGE_INTEGER t0{}, t1{}, freq{};
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&t0);

        std::error_code ec;
        if (!std::filesystem::exists(dataPath, ec)) return;

        // Resolve PrefetchVirtualMemory at runtime — Win8+ only. Used only
        // by the bMmapPlugins path; for sequential read it's never called.
        struct MEMORY_RANGE_ENTRY_ {
            PVOID  VirtualAddress;
            SIZE_T NumberOfBytes;
        };
        using PrefetchFn = BOOL(WINAPI*)(HANDLE, ULONG_PTR, MEMORY_RANGE_ENTRY_*, ULONG);
        auto pPrefetch = reinterpret_cast<PrefetchFn>(GetProcAddress(
            GetModuleHandleW(L"kernel32.dll"), "PrefetchVirtualMemory"));

        // Static so the mappings (and their handles) live for game session.
        // Empty in sequential-read mode.
        struct MappedPlugin {
            HANDLE              fh   = nullptr;
            HANDLE              mh   = nullptr;
            const std::uint8_t* base = nullptr;
            std::uint64_t       size = 0;
        };
        static std::vector<MappedPlugin> s_pluginMaps;

        // 1 MB scratch buffer for sequential-read fallback.
        std::vector<char> buf(1u << 20);

        std::uint64_t totalBytes = 0;
        int           fileCount  = 0;
        int           failCount  = 0;

        const bool useMmap = Settings::bMmapPlugins;

        for (auto& e : std::filesystem::directory_iterator(dataPath, ec)) {
            if (ec) break;
            if (!e.is_regular_file(ec)) continue;
            const auto ext = e.path().extension().wstring();
            if (ext != L".esm" && ext != L".esp" && ext != L".esl")
                continue;

            if (useMmap) {
                // mmap path: open with RANDOM_ACCESS (good standby retention),
                // map the whole file, prefault pages into OS file cache (NOT
                // pinned — process working set isn't owned by us).
                HANDLE fh = CreateFileW(e.path().c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, nullptr);
                if (fh == INVALID_HANDLE_VALUE) { ++failCount; continue; }

                LARGE_INTEGER sz{};
                if (!GetFileSizeEx(fh, &sz) || sz.QuadPart == 0) {
                    CloseHandle(fh); ++failCount; continue;
                }

                HANDLE mh = CreateFileMappingW(fh, nullptr, PAGE_READONLY, 0, 0, nullptr);
                if (!mh) { CloseHandle(fh); ++failCount; continue; }

                void* view = MapViewOfFile(mh, FILE_MAP_READ, 0, 0, 0);
                if (!view) {
                    CloseHandle(mh); CloseHandle(fh); ++failCount; continue;
                }

                if (pPrefetch) {
                    MEMORY_RANGE_ENTRY_ range{};
                    range.VirtualAddress = view;
                    range.NumberOfBytes  = static_cast<SIZE_T>(sz.QuadPart);
                    pPrefetch(GetCurrentProcess(), 1, &range, 0);
                }

                s_pluginMaps.push_back({
                    fh, mh, static_cast<const std::uint8_t*>(view),
                    static_cast<std::uint64_t>(sz.QuadPart)
                });
                totalBytes += static_cast<std::uint64_t>(sz.QuadPart);
                ++fileCount;
            } else {
                // Sequential read path: walk the file once to warm OS cache.
                HANDLE fh = CreateFileW(e.path().c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                    FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
                if (fh == INVALID_HANDLE_VALUE) { ++failCount; continue; }

                DWORD read = 0;
                std::uint64_t fileBytes = 0;
                while (ReadFile(fh, buf.data(), static_cast<DWORD>(buf.size()),
                                &read, nullptr) && read > 0)
                    fileBytes += read;
                CloseHandle(fh);

                totalBytes += fileBytes;
                ++fileCount;
            }
        }

        QueryPerformanceCounter(&t1);
        const double sec = (t1.QuadPart - t0.QuadPart) /
                           static_cast<double>(freq.QuadPart);
        logger::info("FFC4 plugins prewarm: {} {} file(s), {:.1f} MB in {:.2f}s ({:.0f} MB/s){}",
            useMmap ? "mmap+prefault" : "read",
            fileCount, totalBytes / (1024.0 * 1024.0), sec,
            sec > 0 ? totalBytes / (1024.0 * 1024.0) / sec : 0.0,
            failCount > 0 ? std::format(", {} failed", failCount) : std::string{});
    }).detach();
}

// Sequence-numbered preload/postload pair. The engine fires a phantom
// kPreLoadGame/kPostLoadGame pair (~1 ms) at main menu before the real save
// load; we can't tell phantom from real at OnPreLoadGame time. Deferring the
// prefault cancel by ~150 ms and aborting it if the matching OnPostLoadGame
// arrives fast (phantom) cleanly distinguishes the two without tearing into
// an ongoing main-menu prefault.
static std::atomic<std::uint64_t> s_preLoadSeq{ 0 };
static std::atomic<std::uint64_t> s_postLoadSeq{ 0 };

inline void OnPreLoadGame()
{
    // Measurement plumbing always runs (so SAVE LOAD timing emits in
    // baseline mode too). Cache-specific actions gate on baseline.
    if (!Settings::bBaselineMode && Settings::bEnableDecompCache) {
        const auto myNumber = s_preLoadSeq.fetch_add(1, std::memory_order_acq_rel) + 1;
        std::thread([myNumber]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            // If a matching kPostLoadGame already arrived, this was the
            // phantom pair at main menu — do NOT cancel the prefault.
            if (s_postLoadSeq.load(std::memory_order_acquire) >= myNumber)
                return;
            BA2::DecompCache::GetSingleton().CancelPrefault();
        }).detach();
    }

    // Background flush thread starts on first save load — that's when
    // capture activity peaks (cell streaming, texture loads). Running it
    // earlier just races the main-menu prefault for disk bandwidth.
    if (!Settings::bBaselineMode && Settings::bEnableDecompCache &&
        Settings::iDecompCacheMode >= 1)
    {
        static std::atomic<bool> s_flushStarted{ false };
        if (!s_flushStarted.exchange(true, std::memory_order_acq_rel))
            BA2::DecompCache::GetSingleton().StartBackgroundFlush();
    }

    Hooks::OnPreLoadGame();
}

inline void OnPostLoadGame()
{
    // Measurement plumbing always runs (SAVE LOAD line + GAMEPLAY window).
    s_postLoadSeq.fetch_add(1, std::memory_order_acq_rel);
    double loadSec = Hooks::OnPostLoadGame();

    // Start gameplay measurement only after a REAL save load (the engine fires
    // a 0.001s phantom kPreLoadGame/kPostLoadGame pair at main menu before the
    // actual load; skip that and anchor gameplay window at real load completion).
    static bool s_gameplayStarted = false;
    if (!s_gameplayStarted && loadSec > 1.0) {
        Hooks::SnapshotGameplayStart();
        s_gameplayStarted = true;
    }
}

// ── F4SE entry points ───────────────────────────────────────────────────────

namespace
{
    static std::int64_t g_loadStartTick = 0;

    void F4SEAPI MessageHandler(F4SE::MessagingInterface::Message* a_message)
    {
        if (!a_message) return;

        switch (a_message->type) {
        case F4SE::MessagingInterface::kPostLoad:
            // Every F4SE plugin has finished its Load callback — safe to
            // install the inflate Detours hook last, so we chain *after*
            // FastDecompress (LIFO) and our hook gets control first.
            // Inflate hook installs even in baseline mode; the hook itself
            // pass-through-returns when Settings::bBaselineMode is true.
            Hooks::InstallInflateHook();
            if (g_loadStartTick != 0) {
                LARGE_INTEGER now, freq;
                QueryPerformanceCounter(&now);
                QueryPerformanceFrequency(&freq);
                double sec = static_cast<double>(now.QuadPart - g_loadStartTick) /
                             static_cast<double>(freq.QuadPart);
                logger::info("FFC4 STARTUP: kPostLoad at {:.3f}s", sec);
            }
            break;
        case F4SE::MessagingInterface::kPostPostLoad:
            if (g_loadStartTick != 0) {
                LARGE_INTEGER now, freq;
                QueryPerformanceCounter(&now);
                QueryPerformanceFrequency(&freq);
                double sec = static_cast<double>(now.QuadPart - g_loadStartTick) /
                             static_cast<double>(freq.QuadPart);
                logger::info("FFC4 STARTUP: kPostPostLoad at {:.3f}s", sec);
            }
            break;
        case F4SE::MessagingInterface::kGameDataReady:
            if (g_loadStartTick != 0) {
                LARGE_INTEGER now, freq;
                QueryPerformanceCounter(&now);
                QueryPerformanceFrequency(&freq);
                double sec = static_cast<double>(now.QuadPart - g_loadStartTick) /
                             static_cast<double>(freq.QuadPart);
                logger::info("FFC4 STARTUP: kGameDataReady at {:.3f}s — engine data load complete", sec);
            }
            OnGameDataReady();
            break;
        case F4SE::MessagingInterface::kInputLoaded:
            if (g_loadStartTick != 0) {
                LARGE_INTEGER now, freq;
                QueryPerformanceCounter(&now);
                QueryPerformanceFrequency(&freq);
                double sec = static_cast<double>(now.QuadPart - g_loadStartTick) /
                             static_cast<double>(freq.QuadPart);
                logger::info("FFC4 STARTUP: kInputLoaded at {:.3f}s — main menu usable", sec);
                g_loadStartTick = 0;
            }
            break;
        case F4SE::MessagingInterface::kNewGame:
            logger::info("FFC4 STARTUP: kNewGame fired");
            break;
        case F4SE::MessagingInterface::kPreLoadGame:
            OnPreLoadGame();
            break;
        case F4SE::MessagingInterface::kPostLoadGame:
            OnPostLoadGame();
            break;
        // Note: F4SE does not have a kExitGame message.
        // Background threads will be terminated when the process exits.
        }
    }
}

extern "C" DLLEXPORT bool F4SEAPI F4SEPlugin_Query(const F4SE::QueryInterface* a_f4se, F4SE::PluginInfo* a_info)
{
    if (!a_f4se || !a_info) return false;

    // Note: log init deferred to F4SE::Init() in F4SEPlugin_Load. Calling
    // log::init() here would happen before saveFolderName is populated,
    // so the log would land in My Games/Fallout4/F4SE even on VR.

    a_info->infoVersion = F4SE::PluginInfo::kVersion;
    a_info->name = Plugin::NAME.data();
    a_info->version = Plugin::VERSION[0];

    if (a_f4se->IsEditor()) {
        logger::critical("Loading into editor, aborting.");
        return false;
    }

    return true;
}

extern "C" DLLEXPORT bool F4SEAPI F4SEPlugin_Load(const F4SE::LoadInterface* a_f4se)
{
    if (!a_f4se) return false;

    {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        g_loadStartTick = now.QuadPart;
    }

    F4SE::Init(a_f4se);

    logger::info("{} v{}.{}.{} [{} {}] is loading",
        Plugin::NAME, Plugin::VERSION[0], Plugin::VERSION[1], Plugin::VERSION[2],
        __DATE__, __TIME__);

    const auto ver = Module::get().version();
    logger::info("Detected runtime: Fallout 4{} (v{}).", Module::IsVR() ? " VR" : "", ver.string());

    if (ver < RUNTIME_VERSION_MIN || RUNTIME_VERSION_MAX < ver) {
        logger::critical("Runtime version is not supported, aborting.");
        return false;
    }

    const auto messaging = F4SE::GetMessagingInterface();
    if (!messaging || !messaging->RegisterListener(MessageHandler)) {
        logger::critical("Failed to get message interface, aborting.");
        return false;
    }

    Settings::Load();
    F4SE::AllocTrampoline(TRAMPOLINE_SIZE);
    OnModuleLoad();

    // Log gameplay-window summary on normal process exit so we can compare
    // post-save-load throughput across baseline vs FFC4 runs without needing
    // to parse per-interval delta lines.
    std::atexit([]() { Hooks::LogGameplaySummary(); });

    return true;
}

// ── NG version declaration (for Address Library) ────────────────────────────
F4SE_EXPORT auto F4SEPlugin_Version = []() noexcept {
    F4SE::PluginVersionData data{};
    data.PluginName(Plugin::NAME);
    data.PluginVersion(Plugin::VERSION);
    data.AuthorName("FasterFileCopyFO4");
    data.UsesAddressLibrary(true);
    data.UsesSigScanning(false);
    data.IsLayoutDependent(true);
    data.HasNoStructUse(false);
    data.CompatibleVersions({
        F4SE::RUNTIME_1_10_984,
        REL::Version{ 1, 11, 191, 0 }
    });
    return data;
}();
