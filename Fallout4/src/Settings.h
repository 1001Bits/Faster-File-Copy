#pragma once

#include <cctype>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <unordered_map>

struct Settings
{
    // Baseline mode — plugin acts as if disabled (no mmap, no decomp cache,
    // no prefault, no save prefetch, no texture serve), but hooks are still
    // installed and stats/timing are still captured. Use as a kill switch
    // (no FFC4 effects) or for A/B benchmarking against the fully-enabled
    // plugin. The stats thread and SAVE LOAD / MEM instrumentation still run.
    inline static bool bBaselineMode{ false };
    inline static bool bEnableStats{ false };
    inline static int  iStatsIntervalMs{ 5000 };
    inline static bool bLogReads{ false };

    // Compatibility mode — single safe switch for problem setups (Buffout4
    // BSTextureStreamerLocalHeap on VR, WINE, reported mod conflicts). When
    // true, force-disables the aggressive hook paths (mmap, factory hooks,
    // texture direct/high-level serve) while keeping the decomp cache and
    // passive capture active. Cache still serves inline via HookedInflate —
    // same chokepoint approach as Skyrim BSAMemoryMap's bCompatibilityMode,
    // adapted to FO4's zlib-bridge architecture.
    inline static bool bCompatibilityMode{ false };

    // Archive mapping — factory replaces ReaderStream with MmapStream and
    // DoRead serves uncompressed bytes straight from the archive mmap.
    inline static bool bEnableMmap{ true };

    // Cache / mmap delivery strategy, borrowed from Skyrim BSAMemoryMap:
    //   0 = Factory  — InstallStreamOverride swaps vtable slots 0/6/7 on
    //                  uncompressed streams. Lowest per-call cost on swapped
    //                  streams (TLS fast path). Most invasive.
    //   1 = Inline   — no vtable swap; HookedDoRead serves uncompressed reads
    //                  from archive mmap directly. Safer for mods that inspect
    //                  the stream vtable (Buffout, third-party overrides).
    //   2 = Minimal  — no vtable swap, no inline mmap serve. Uncompressed reads
    //                  fall through to stock ReaderStream::DoRead. Only the
    //                  HookedInflate + DecompCache serve path stays active.
    //                  Maximum compatibility; gives up the uncompressed mmap win.
    inline static int iCacheDelivery{ 0 };

    // Short-circuit compressed DoRead when cache has the entry. Instead of
    // calling orig (→ source->vtbl[7] → ReadFile + zlib setup + HookedInflate
    // fp-serve), HookedDoRead memcpys cached decompressed bytes directly to
    // the caller buffer and advances the stream cursor. Skips ~50-150 µs of
    // per-compressed-DoRead source-side work. Conditions: stream cursor==0,
    // caller's a_toRead >= entry uncompressedSize. Default on — FFC4 analog
    // of BSAMemoryMap's iCacheDelivery=1 inline intercept; the main path
    // that converts cache hits into wall-time wins during the (mostly-sync)
    // startup phase. Partial reads still fall through to the bridge-set +
    // HookedInflate fp-serve path.
    inline static bool bCompressedDirectServe{ true };

    // Extend bCompressedDirectServe to AsyncReaderStream::DoRead. Default OFF —
    // benchmarked against vanilla 2026-04-25 and showed a +2s save-load
    // regression (FFC4 6.9s → 8.6s). Hypothesis: async DoRead has post-call
    // side effects (completion tag set, work-queue state) that we leave
    // dangling when we memcpy+return without invoking orig; engine compensates
    // with retries or waits on tags that never get set. The original code's
    // !isAsyncStream gate was there for exactly this reason. Only set true
    // for an A/B run with vanilla baseline as ground truth.
    inline static bool bCompressedDirectServeAsync{ false };

    // Inline serve at the deeper FUN_14169D530 compressed-read level (FO4
    // analog of Skyrim's CompressedArchiveStream::DoRead). Intercepts every
    // compressed read with cache-hit short-circuit + per-stream cursor
    // tracking. More aggressive than bCompressedDirectServe — covers chunked
    // reads (64 KB per call is typical), bypasses zlib + source reads + the
    // 128 KB staging buffer. Requires bEnableDecompCache. Opt-in.
    inline static bool bCompReadServe{ false };

    // Decompression cache (master toggle — auto-derived from bEnableGNRLCache
    // OR bEnableTextureCache). Set false to disable both.
    inline static bool bEnableDecompCache{ true };

    // GNRL (non-texture) cache — covers compressed scripts, materials, meshes,
    // BGSMs, animations, etc. When on, captures decompressed bytes during
    // gameplay (only) and serves cache hits via HookedDoRead direct-serve +
    // HookedInflate bridge-serve. Capture is gated to gameplay phase to keep
    // startup/initAllForms hook overhead minimal — the user-reported initAllForms
    // win comes from mmap, not the cache, so capturing during startup is wasted
    // work for that phase.
    inline static bool bEnableGNRLCache{ true };

    inline static int  iDecompCacheMode{ 1 };      // 0=startup-only, 1=gameplay+bg flush
    inline static int  iDecompCacheMaxMB{ 2048 };  // 0=unlimited; 2 GB default fits in OS page cache on 16 GB systems

    // Pin the .decomp cache views in the process working set with VirtualLock
    // so the OS cannot page them out. Default OFF — benchmarked 2026-04-25 AE,
    // pinning 2 GB cost +1.18s on save-load by squeezing the engine's working
    // set during asset processing. FILE_FLAG_RANDOM_ACCESS already keeps cache
    // pages in standby cache without pinning them in our working set, which
    // is the better tradeoff for tight-RAM rigs. Re-enable only if a specific
    // benchmark shows a net win (most likely on >32 GB systems). Auto-skipped
    // if locking would leave less than iLockCacheReserveMB free physical RAM.
    inline static bool bLockCacheInMemory{ false };

    // Minimum free physical RAM that must remain after locking the cache,
    // in MB. If locking would push free RAM below this, the lock is skipped
    // and we fall back to standby cache + prefault. 4 GB default leaves the
    // game and other plugins comfortable on 16 GB systems; raise on tighter
    // setups, lower if you have 32 GB+ and want maximum cache pinning.
    inline static int  iLockCacheReserveMB{ 4096 };

    // DX10 texture streamer cache — captures and serves texture chunks via
    // HookedInflate fp-serve (fingerprint match in compressed input → cache
    // memcpy in zlib output buffer). Both capture and serve are gated to
    // gameplay phase. The biggest gameplay throughput multiplier (6× vanilla
    // on streaming bursts).
    inline static bool bEnableTextureCache{ true };

    // Proactive DX10 cache build at startup. When true, StartBackgroundFlush
    // walks every texture BA2 and decompresses every chunk upfront — fast but
    // writes tens of GB to disk before gameplay starts. Leave false for
    // passive-only capture: the cache grows only with chunks the game reads.
    inline static bool bBuildTextureCache{ false };

    // Prefault texture-cache pages in a background thread once the main menu
    // is ready (kInputLoaded). Sequentially reads DX10 cache files to warm
    // the OS page cache — eliminates the low-res → high-res texture pop on
    // the first save load. Throttles I/O when the game is actively streaming.
    inline static bool bPrefaultCache{ true };
    inline static int  iPrefaultThreads{ 4 };  // clamped to [1, 8]

    // One-shot full prefault burst at kInputLoaded — no per-burst sleeps,
    // ignores m_prefaultCancel during first sweep, runs DX10 + GNRL to
    // completion at maximum disk bandwidth. Trades main-menu disk contention
    // (BK2 intro stutter, etc.) for guaranteed warm cache pages before save-load
    // fires. Use to confirm cache speedup is real when pages are paged in.
    inline static bool bPrefaultBurst{ false };

    // Use non-temporal AVX2 stores for cache-serve memcpy (>=128KB). Bypasses
    // CPU cache — fast for write but downstream consumer reads cold lines from
    // RAM. Disable to force regular memcpy: writes go through CPU cache so the
    // texture streamer's downstream consumer gets warm reads. A/B knob.
    inline static bool bUseNonTemporalCopy{ true };

    // Passive texture capture via HookedInflate. When a DX10 chunk misses
    // the decomp cache, HookedStreamInflate stashes (dst_buf, archive,
    // fileOffset, uncompSize). On the IO worker thread, HookedInflate
    // looks up next_out−total_out at Z_STREAM_END and records the bytes.
    inline static bool bPassiveTextureCapture{ true };

    // Direct-serve texture chunks from cache via HookedInflate fp-serve.
    // Default ON when bEnableTextureCache is on — the serve mechanism is
    // tightly coupled to the cache subsystem; without this flag, the cache
    // captures but never serves. This is the safe inline path (no allocator
    // interaction, no object substitution).
    inline static bool bTextureDirectServe{ true };

    // Hard-gate FFC4 to vanilla pass-through during save-load (gates both
    // cache AND mmap paths). Default ON — benchmark 2026-04-26 showed
    // mmap doesn't fire on save-load (compressed-dominated workload, mmap
    // serves only uncompressed entries), so leaving HookedDoRead's full
    // path running just costs ~1.8s of per-call hook overhead with no
    // mmap win to offset it. Save-load matches vanilla at 5.6s with this
    // on; without it, save-load regressed to 7.8s. The cache-only defer
    // (bDeferCacheUntilGameplay) handles startup phase separately, where
    // mmap DOES help (initAllForms uncompressed reads).
    inline static bool bShortCircuitDuringSaveLoad{ true };

    // Defer cache serve paths (compressed-direct-serve, bridge-set,
    // texture fp-serve) until after the first save-load completes. Mmap
    // path stays active throughout. Rationale: per user report, the big
    // startup win is mmap eliminating ReadFile syscall + kernel copy on
    // millions of small uncompressed reads during initAllForms. The cache
    // doesn't help that phase (those reads are uncompressed BA2 entries,
    // not zlib-compressed), and the cache lookups + bridge state add
    // per-call overhead with no benefit. Setting this true means cache
    // is dormant until kPostLoadGame fires for the first time, then full
    // cache delivery activates for gameplay streaming.
    inline static bool bDeferCacheUntilGameplay{ true };

    // High-level texture serve via BSTextureStreamer::ReadMipsToTexture
    // dispatcher. When the full requested mipchain hits in the decomp cache,
    // memcpy each mip into dst_buf and return without entering the per-chunk
    // vtbl[0x60]/vtbl[0x68] pipeline at all. This avoids the timing window
    // that exposed Buffout4's BSTextureStreamerLocalHeap + SmallBlockAllocator
    // uninit-read crashes on VR — we either do the full operation or let the
    // original run at baseline speed. On miss, HookedStartNextFetch does NOT
    // BridgeSet (to keep fall-through timing identical to stock).
    // HL texture serve — DEFAULT OFF on AE/VR. Documented crasher: stream+0xE0
    // is a packed-size scratch buffer in the engine's pipeline; HL memcpy of
    // UNPACKED bytes overflows it, corrupts the custom allocator, and the
    // texture streamer crashes at Fallout4.exe+0x17C9935 mov [r14+0xE0], rax
    // when it later tries to read from that scratch slot. See project memory
    // project_ae_hl_serve_crashes.md and project_vr_hl_serve_crash.md. Only
    // useful on runtimes where the dst-buf semantics differ (none confirmed).
    inline static bool bHighLevelTexServe{ false };

    // Factory hook target
    // false = LocationTree::DoCreateStream (REL::RelocationID 476824/2269550)
    //         — misses archive-direct callers (BGSInventory, Quest, Havok, Nif)
    // true  = BSResource::Archive2::ReaderStream primary ctor (8-param)
    //         — catches every BA2 stream creation
    //   OG 0x01B703C0 (PDB) · VR 0x01BEF7D0 (PDB) · NG/AE: vtable xref scan
    inline static bool bUseNewFactoryHook{ true };

    // Install the same DoRead intercept (bridge setup → call original →
    // decomp-cache populate) on BSResource::Archive2::AsyncReaderStream's
    // slot[6], not just the synchronous ReaderStream. Gameplay cell /
    // navmesh / non-texture streaming goes through ReaderStream::DoCreateAsync
    // which constructs an AsyncReaderStream with its own vtable; without this
    // hook, ~1 GB of zlib work bypasses the cache entirely during gameplay.
    inline static bool bHookAsyncReaderStream{ true };

    // When true and running on AE/NG, target the inlined BA2-chunk factory
    // `FUN_14169e3b0` (sig-scan on the prologue) instead of the ReaderStream
    // ctor. The ctor was inlined by MSVC into ~14 callsites — the out-of-line
    // version has zero code callers, so the ctor hook never fires on AE. The
    // chunk factory is the lowest shared funnel above the ~15 resource-cache
    // inserters.
    //
    // Monitor-only: populates s_streamHash, does NOT replace the stream. The
    // factory's output uses a shared_ptr<ReaderStream> variant whose ref-
    // counting is incompatible with MmapStream's intrusive refcount — safe
    // replacement needs follow-up reversing. Cache still serves via DoRead +
    // Inflate paths; this hook just lets DoRead skip SourceLookup on the
    // very first read for each stream.
    inline static bool bUseChunkFactoryHook{ false };

    // When true, the chunk factory hook replaces uncompressed-entry streams
    // with MmapStream (archive-mapped) and cached compressed-entry streams
    // with MmapStream over the decomp cache — same pattern as HookedFactory.
    // Relies on the factory's output matching BSTSmartPointer<Stream> layout
    // (T* at offset 0). Requires bUseChunkFactoryHook.
    inline static bool bChunkFactoryReplace{ false };

    // HookedFactory (LocationTree::DoCreateStream) substitutes the engine's
    // freshly-created CompressedReaderStream with a cache-backed MmapStream.
    // Default OFF — benchmarked 2026-04-25, FFC4 with bFactoryReplaceCompressed=true
    // was +2.6s slower than vanilla on save-load while saving ~2s on zlib —
    // engine spent +4.5s on "other" non-zlib work. Hypothesis: substitute
    // MmapStream is missing some vtable slot or downstream-introspectable
    // state (CompressedSize/Source fields, DoCreateAsync, refcount accounting)
    // that engine uses after DoRead returns. Gameplay (sync-dominant) was
    // unaffected; save-load (async-rich) regressed. Re-enable only after
    // identifying which post-DoRead path requires ReaderStream-specific state.
    inline static bool bFactoryReplaceCompressed{ false };

    // Save-game prefetch — at main-menu ready (kInputLoaded), a background
    // thread enumerates Documents\My Games\Fallout4[VR]\Saves\*.fos +
    // corresponding *.f4se cosaves, sorts by mtime, and sequentially reads
    // the top N into a discard buffer to warm the OS page cache. When the
    // user picks Continue / Load, the save blob is already resident.
    inline static bool bPrefetchRecentSaves{ true };
    inline static int  iPrefetchSaveCount{ 3 };   // clamped to [0, 16]

    // Plugin pre-warm — at FFC4 init (before engine parses plugins), a
    // background thread warms every *.esm/.esp/.esl in Data/ into the OS
    // file cache so the engine's later ReadFile-based plugin parse runs at
    // RAM speed. Skipped in bBaselineMode for benchmark fairness.
    inline static bool bPrewarmPlugins{ true };

    // Mmap plugins instead of sequential-reading them. When true, each
    // plugin file is opened with FILE_FLAG_RANDOM_ACCESS, MapViewOfFile'd
    // (reserves virtual address space — free on x64), and prefaulted via
    // PrefetchVirtualMemory. Mappings are held for the game session.
    //   • Same OS-file-cache effect as sequential read for plugin pages
    //     the engine reads.
    //   • Better page-cache RETENTION: the FILE_FLAG_RANDOM_ACCESS hint +
    //     active mmap keep pages in standby longer than sequential-read's
    //     "touch and forget" behavior; less likely to be evicted under
    //     general system pressure.
    //   • NO VirtualLock: pages are NOT pinned in our process working set.
    //     The OS can still evict them gracefully when the game needs RAM.
    //     Avoids the working-set tax that broke save-load on tight-RAM rigs.
    //   • Cost: one file-handle + one section-handle per plugin held for
    //     game session. 3000 plugins ≈ 6000 handles (well under Windows'
    //     ~16k default limit). ~100 MB of kernel page-table memory for a
    //     6 GB plugin set's PTEs.
    // Default OFF — sequential read is the safer baseline. Heavy-modlist
    // users (1000+ plugins) on >=16 GB systems may see better engine
    // plugin-parse times with this on, since plugin pages stay in standby
    // during the longer parse window. Users on tight-RAM rigs (8-12 GB)
    // should leave this off.
    inline static bool bMmapPlugins{ false };

private:
    struct IniMap
    {
        std::unordered_map<std::string, std::string> kv;

        static std::string trim(std::string_view s)
        {
            size_t b = 0, e = s.size();
            while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
            while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
            return std::string(s.substr(b, e - b));
        }

        bool parse(const std::filesystem::path& path)
        {
            std::ifstream f(path);
            if (!f) return false;
            std::string section, line;
            while (std::getline(f, line)) {
                // strip CR, comments (# or ;)
                if (!line.empty() && line.back() == '\r') line.pop_back();
                auto hashPos = line.find_first_of("#;");
                if (hashPos != std::string::npos) line.erase(hashPos);
                auto t = trim(line);
                if (t.empty()) continue;
                if (t.front() == '[' && t.back() == ']') {
                    section = trim(std::string_view(t).substr(1, t.size() - 2));
                    continue;
                }
                auto eq = t.find('=');
                if (eq == std::string::npos) continue;
                auto key = trim(std::string_view(t).substr(0, eq));
                auto val = trim(std::string_view(t).substr(eq + 1));
                kv[section + "." + key] = val;
            }
            return true;
        }

        bool getBool(const std::string& k, bool def) const
        {
            auto it = kv.find(k);
            if (it == kv.end()) return def;
            const auto& v = it->second;
            if (v == "true" || v == "1" || v == "True" || v == "TRUE")  return true;
            if (v == "false" || v == "0" || v == "False" || v == "FALSE") return false;
            return def;
        }

        int getInt(const std::string& k, int def) const
        {
            auto it = kv.find(k);
            if (it == kv.end()) return def;
            try { return std::stoi(it->second); } catch (...) { return def; }
        }
    };

public:
    static void Load()
    {
        const auto settingsPath = std::filesystem::path("Data") / "F4SE" / "Plugins" / "FasterFileCopyFO4.ini";

        IniMap ini;
        if (!ini.parse(settingsPath)) {
            logger::info("No settings file found — using defaults");
            return;
        }

        bBaselineMode        = ini.getBool("General.bBaselineMode", bBaselineMode);
        bCompatibilityMode   = ini.getBool("General.bCompatibilityMode", bCompatibilityMode);
        bEnableStats         = ini.getBool("General.bEnableStats", bEnableStats);
        iStatsIntervalMs     = ini.getInt("General.iStatsIntervalMs", iStatsIntervalMs);
        bLogReads            = ini.getBool("General.bLogReads", bLogReads);
        bEnableMmap          = ini.getBool("Archives.bEnableMmap", bEnableMmap);
        iCacheDelivery       = ini.getInt("Archives.iCacheDelivery", iCacheDelivery);
        if (iCacheDelivery < 0) iCacheDelivery = 0;
        if (iCacheDelivery > 2) iCacheDelivery = 2;
        bCompressedDirectServe = ini.getBool("Archives.bCompressedDirectServe", bCompressedDirectServe);
        bCompressedDirectServeAsync = ini.getBool("Archives.bCompressedDirectServeAsync", bCompressedDirectServeAsync);
        bCompReadServe         = ini.getBool("Archives.bCompReadServe", bCompReadServe);
        bEnableGNRLCache     = ini.getBool("DecompCache.bEnableGNRLCache", bEnableGNRLCache);
        bEnableTextureCache  = ini.getBool("DecompCache.bEnableTextureCache", bEnableTextureCache);
        // Master cache toggle is the OR of the two sub-caches. Internal
        // code still gates on bEnableDecompCache for "any cache infra needed".
        bEnableDecompCache   = bEnableGNRLCache || bEnableTextureCache;
        iDecompCacheMode     = ini.getInt("DecompCache.iMode", iDecompCacheMode);
        iDecompCacheMaxMB    = ini.getInt("DecompCache.iMaxMB", iDecompCacheMaxMB);
        bLockCacheInMemory   = ini.getBool("DecompCache.bLockInMemory", bLockCacheInMemory);
        iLockCacheReserveMB  = ini.getInt("DecompCache.iLockReserveMB", iLockCacheReserveMB);
        if (iLockCacheReserveMB < 512) iLockCacheReserveMB = 512;
        bBuildTextureCache     = ini.getBool("DecompCache.bBuildTextureCache", bBuildTextureCache);
        bPrefaultCache         = ini.getBool("DecompCache.bPrefaultCache", bPrefaultCache);
        bPrefaultBurst         = ini.getBool("DecompCache.bPrefaultBurst", bPrefaultBurst);
        bUseNonTemporalCopy    = ini.getBool("DecompCache.bUseNonTemporalCopy", bUseNonTemporalCopy);
        iPrefaultThreads       = ini.getInt("DecompCache.iPrefaultThreads", iPrefaultThreads);
        if (iPrefaultThreads < 1) iPrefaultThreads = 1;
        if (iPrefaultThreads > 8) iPrefaultThreads = 8;
        bPassiveTextureCapture = ini.getBool("DecompCache.bPassiveTextureCapture", bPassiveTextureCapture);
        bTextureDirectServe    = ini.getBool("DecompCache.bTextureDirectServe", bTextureDirectServe);
        bShortCircuitDuringSaveLoad = ini.getBool("DecompCache.bShortCircuitDuringSaveLoad", bShortCircuitDuringSaveLoad);
        bDeferCacheUntilGameplay = ini.getBool("DecompCache.bDeferCacheUntilGameplay", bDeferCacheUntilGameplay);
        bHighLevelTexServe     = ini.getBool("DecompCache.bHighLevelTexServe", bHighLevelTexServe);
        bHookAsyncReaderStream = ini.getBool("Factory.bHookAsyncReaderStream", bHookAsyncReaderStream);
        bUseNewFactoryHook    = ini.getBool("Factory.bUseNewFactoryHook", bUseNewFactoryHook);
        bUseChunkFactoryHook  = ini.getBool("Factory.bUseChunkFactoryHook", bUseChunkFactoryHook);
        bChunkFactoryReplace  = ini.getBool("Factory.bChunkFactoryReplace", bChunkFactoryReplace);
        bFactoryReplaceCompressed = ini.getBool("Factory.bFactoryReplaceCompressed", bFactoryReplaceCompressed);
        bPrefetchRecentSaves  = ini.getBool("Saves.bPrefetchRecentSaves", bPrefetchRecentSaves);
        iPrefetchSaveCount    = ini.getInt("Saves.iPrefetchSaveCount", iPrefetchSaveCount);
        if (iPrefetchSaveCount < 0)  iPrefetchSaveCount = 0;
        if (iPrefetchSaveCount > 16) iPrefetchSaveCount = 16;
        bPrewarmPlugins       = ini.getBool("Plugins.bPrewarmPlugins", bPrewarmPlugins);
        bMmapPlugins          = ini.getBool("Plugins.bMmapPlugins", bMmapPlugins);

        if (bCompatibilityMode) {
            // Compatibility mode = minimum hook invasiveness. Force off the
            // paths that substitute Stream objects, swap vtables, or touch
            // the game allocator (Buffout4 / TBB conflict surface). Cache
            // still serves via the safe inline HookedInflate paths (bridge
            // for GNRL, fp-serve for textures) — those run purely inside
            // zlib's existing dst buffer and never substitute objects.
            //
            // bEnableMmap is NOT forced — user controls. mmap loads BA2s
            // and warms the OS file cache regardless of iCacheDelivery; on
            // setups where mmap itself doesn't crash, leaving it on still
            // gives the initAllForms-style win without the vtable-swap that
            // iCacheDelivery=2 disables.
            iCacheDelivery       = 2;          // no vtable swap, no inline mmap-serve
            bUseNewFactoryHook   = false;
            bUseChunkFactoryHook = false;
            bChunkFactoryReplace = false;
            bFactoryReplaceCompressed = false;
            bHighLevelTexServe   = false;
            bCompressedDirectServe = false;    // skips outer-DoRead substitution
            bCompressedDirectServeAsync = false;
            bCompReadServe       = false;      // skips async source-read intercept
            logger::info("bCompatibilityMode=true — iCacheDelivery=2, factory/HL/direct-serve/comp-read OFF. Cache serves via HookedInflate inline (safe). bEnableMmap left to user (current={}).",
                bEnableMmap);
        }

        logger::info("Settings loaded from {}", settingsPath.string());
    }
};
