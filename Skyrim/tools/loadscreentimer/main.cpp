// LoadScreenTimer — standalone loading-screen wall-clock logger.
//
// Logs one line per LoadingMenu open->close interval to LoadScreenTimer.log.
// Exists so A/B comparisons across FasterFileCopy versions (including released
// builds with no per-screen instrumentation) share one impartial clock. It
// installs no hooks and reads no archive state: a UI menu event sink only.

#include "RE/Skyrim.h"
#include "SKSE/SKSE.h"

#include <spdlog/sinks/basic_file_sink.h>

#include <Windows.h>

#include <atomic>
#include <filesystem>

using namespace std::literals;

SKSEPluginInfo(
    .Version = REL::Version{ 1, 0, 0, 0 },
    .Name = "LoadScreenTimer"sv,
    .Author = "FasterFileCopy contributors"sv,
    .StructCompatibility = SKSE::StructCompatibility::Independent,
    .RuntimeCompatibility =
        SKSE::VersionIndependence::AddressLibrary,
    .MinimumSKSEVersion = REL::Version{ 2, 0, 12, 0 }
)

namespace
{
    LARGE_INTEGER s_qpcFreq{};
    std::atomic<long long> s_openedQpc{ 0 };

    void InitializeLog() noexcept
    {
        try {
            auto dir = SKSE::log::log_directory();
            std::filesystem::path logDir;
            if (dir && !dir->empty()) {
                // Correct a wrong game-folder name the same way FFC does.
                const auto myGames = dir->parent_path().parent_path();
                if (myGames.filename() == std::filesystem::path(L"My Games")) {
                    logDir = myGames /
                        (REL::Module::IsVR() ? L"Skyrim VR"
                                             : L"Skyrim Special Edition") /
                        L"SKSE";
                } else {
                    logDir = *dir;
                }
            }
            if (logDir.empty())
                return;
            std::error_code ec;
            std::filesystem::create_directories(logDir, ec);
            const auto logPath = logDir / "LoadScreenTimer.log";
            auto sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(
                logPath.string(), false /*append: keep history across runs*/);
            auto log = std::make_shared<spdlog::logger>(
                "LoadScreenTimer", std::move(sink));
            log->set_level(spdlog::level::info);
            log->flush_on(spdlog::level::info);
            log->set_pattern("[%Y-%m-%d %H:%M:%S.%e] %v");
            spdlog::set_default_logger(std::move(log));
        } catch (...) {
        }
    }

    class Sink final : public RE::BSTEventSink<RE::MenuOpenCloseEvent>
    {
    public:
        static Sink* GetSingleton()
        {
            static Sink s;
            return &s;
        }

        RE::BSEventNotifyControl ProcessEvent(
            const RE::MenuOpenCloseEvent*               a_event,
            RE::BSTEventSource<RE::MenuOpenCloseEvent>*) override
        {
            try {
                if (!a_event ||
                    a_event->menuName != RE::LoadingMenu::MENU_NAME)
                    return RE::BSEventNotifyControl::kContinue;

                if (a_event->opening) {
                    LARGE_INTEGER now;
                    QueryPerformanceCounter(&now);
                    s_openedQpc.store(now.QuadPart, std::memory_order_release);
                } else {
                    const auto opened =
                        s_openedQpc.exchange(0, std::memory_order_acq_rel);
                    if (opened != 0) {
                        LARGE_INTEGER now;
                        QueryPerformanceCounter(&now);
                        const double seconds =
                            static_cast<double>(now.QuadPart - opened) /
                            static_cast<double>(
                                (std::max)(s_qpcFreq.QuadPart, LONGLONG{ 1 }));
                        SKSE::log::info("LOADING SCREEN: {:.3f}s", seconds);
                    }
                }
            } catch (...) {
            }
            return RE::BSEventNotifyControl::kContinue;
        }
    };

    void OnMessage(SKSE::MessagingInterface::Message* a_msg)
    {
        if (!a_msg || a_msg->type != SKSE::MessagingInterface::kDataLoaded)
            return;
        if (auto* ui = RE::UI::GetSingleton()) {
            ui->AddEventSink<RE::MenuOpenCloseEvent>(Sink::GetSingleton());
            SKSE::log::info("LoadScreenTimer active (session start)");
        }
    }
}

SKSEPluginLoad(const SKSE::LoadInterface* a_skse)
{
    SKSE::Init(a_skse);
    InitializeLog();
    QueryPerformanceFrequency(&s_qpcFreq);
    if (auto* messaging = SKSE::GetMessagingInterface())
        messaging->RegisterListener(OnMessage);
    return true;
}
