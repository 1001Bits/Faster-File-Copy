# Faster File Copy

Faster File Copy is an SKSE plugin for Skyrim SE/AE/VR that targets asset-load
latency. It does not raise steady-state frame rate and it does not allocate a
second private heap copy of every file.

The plugin has two conservative optimizations:

1. Uncompressed BSA entries can be copied from read-only, demand-paged archive
   mappings instead of going through the engine's buffered `ReadFile` chain.
2. Decompressed BSA entries can be persisted in a versioned cache. After the
   main menu appears, the managed cache worker faults the complete effective
   cache into RAM. A later request copies the already-decompressed payload from
   that read-only mapping, skips zlib/LZ4 work, and normally avoids storage I/O
   while Windows still considers the touched pages resident.

The selected decompression-cache file set and its current committed mappings
are capped at 25% of detected total physical RAM. `iDecompCacheMaxMB` is an
additional user ceiling; `0` selects the automatic 25% value. The warm pass
explicitly touches every committed cache page, but does not use `VirtualLock`:
Windows may still reclaim pages later if the system needs memory. New mappings
are warmed from byte zero after cache commits. `warmup complete` means every
page in that mapping generation has been touched at least once, not that all of
them are pinned or guaranteed to be resident at the same instant.

That 25% ceiling is not a claim about the plugin's entire transient working
set. In-progress capture buffers (bounded separately), page tables, demand-
paged BSA mappings, and old mapping generations still owned by an in-flight
read are outside the persistent-cache-file limit. Undeletable stale files can
also occupy extra disk space, but are not added to the RAM warm set. If an
inherited active cache cannot be deleted while it is over the ceiling, warmup
fails closed instead of loading an unsafe set into RAM.

Whole BSA mappings for the uncompressed path remain demand paged. Only the
bounded decompression cache is deliberately prefaulted because RAM residency is
the reason its larger, already-expanded payload can beat reading and
decompressing the smaller BSA data during gameplay.

Cache learning is also bounded: simultaneous incomplete captures and completed
entries awaiting disk commit are each capped at 256 MiB. A below-normal-priority
worker wakes at 32 MiB, pauses flush and warm work while a loading screen is
active, and yields between cancellable chunks to reduce gameplay contention.
New individual captures are capped at 64 MiB so one giant, partially consumed
asset cannot reserve most of the in-flight budget.

## What performance to expect

- The first run builds cache data and is not expected to be faster.
- Warm save loads, repeated cell transitions, and assets reopened across play
  sessions are the workloads most likely to improve.
- Before the RAM-warm log reports completion, entries whose complete payload
  has not yet been touched stay on Skyrim's native decompression path. Windows
  can later trim already warmed pages, so benchmarks should still wait for
  warmup completion and use controlled repeated runs.
- Assets Skyrim already keeps alive for the whole session do not benefit from a
  second cache. Normal gameplay FPS should not be advertised as a benefit.
- Loose files are not decompressed and are already handled by the Windows file
  cache; this plugin intentionally leaves them alone.
- An eligible compressed entry is learned after one complete sequential read;
  eviction favors recently used BSA caches as a whole. This captures reusable
  gameplay data but is not a per-file frequency-ranking system.

Use `bMeasureStats=1` only for controlled comparisons. It adds counters and
per-call QPC timing. The per-path operation times cover mapped copies on the
fast paths but full native calls on fallback/decompression paths, so they are
diagnostic rather than an apples-to-apples latency comparison. Validate every
instrumented result with a stats-off `BENCH SAVE_LOAD_TIMING` run. Compare
identical save/load routes after the cache inventory has stopped growing and
after the log reports `cache RAM warmup complete`; measure loading time or
stutter rather than average FPS.

Measurement mode also emits a compact cache-pipeline line. A healthy learning
run should show positive `source resolved`, `capture completed`, and `queued`
counts. `structural backoff`, `cursor unknown`, `budget reject`, and the two cap
rejection counters explain why a particular stream was deliberately left on
Skyrim's stock path without enabling expensive per-read logging.

## Installation and upgrades

Install `FasterFileCopy.dll` and `FasterFileCopy.ini` under `Data/SKSE/Plugins`.
Remove the legacy `BSAMemoryMap.dll` and `BSAMemoryMap.ini` when upgrading; both
DLLs must never be loaded together. The retired `BSAMemoryMap_cache` directory
can also be deleted while the game is closed.

Cache format changes invalidate old files automatically. It is always safe to
delete `Data/SKSE/Plugins/FasterFileCopy_cache` while the game is not running.

The structure-dependent runtime build is intentionally restricted to the
layouts tested by this project:

- Skyrim SE 1.5.97
- Skyrim AE 1.6.1170
- Skyrim VR 1.4.15

An unsupported runtime should fail closed instead of scanning for a function
that only resembles a known hook target.

## Configuration

The tracked [FasterFileCopy.ini](FasterFileCopy.ini) is the canonical template.
The default gameplay mode enables demand-paged BSA mappings and a bounded,
fully touched persistent decompression-cache mapping. A positive
`iDecompCacheMaxMB` is clamped to 25% of total physical RAM; `0` means use that
automatic ceiling. Negative values are invalid and fall back to the 2048 MiB
default before the 25% clamp. `sCacheDir`, when set, must be an absolute path.

If Windows cannot report total physical memory, the plugin disables the
decompression cache rather than guessing past the safety ceiling; the log will
contain `physical RAM detection failed`. Direct uncompressed-BSA mappings can
remain enabled independently.

Per-read logging is intentionally disabled. Measurement mode reports logical
output bytes/calls/time separately for direct mmap, decompression cache, native
decompression, and stock direct reads. Compressed source I/O is reported on a
separate layer and is never added to logical output. Lookup outcomes establish
entry-attempt hit rate; cache bytes divided by cache plus native-decompressor
bytes establishes the compressed-output byte share. Neither number by itself
is an end-to-end speedup, which requires a matched wall-clock A/B.

`bPrefaultDecompCache` and `bServeDecompCache` default to `1`. They exist to
isolate benchmark treatments and should remain enabled in normal gameplay:

- prefault `1`, serve `1`: normal RAM-warm cache;
- prefault `0`, serve `1`: demand-paged expanded cache control;
- prefault `1`, serve `0`: identical map/warm cost without cache delivery.

`bEnableDuringSaveLoad` also defaults to `1`. Its benchmark-only `0` treatment
keeps initialization, mapping, and prefaulting unchanged, but routes new save-
and transition-load reads through Skyrim. Acceleration resumes automatically
after the load, so this directly tests the proposal to reserve the mod for
gameplay streaming. A compressed stream that was already cache-backed remains
cache-backed across a phase boundary because switching its deliberately stale
native decompressor cursor would be incorrect.

The optional `sBenchmarkAutoLoadSave` setting accepts a save basename without
`.ess`. With `bBenchmarkWaitForWarm=1`, the plugin waits for both the main menu
and generation-specific warm completion. It then observes the configured settle
interval, measures current cache residency, waits a fixed 250 ms to isolate the
checkpoint's work, and dispatches that exact save. `sBenchmarkRunTag` is copied
into every
machine-readable `BENCH` record. Leave the save empty outside controlled runs.
`CACHE_STATE` distinguishes historical warm coverage from pages currently in
Skyrim's working set. Windows standby/file-cache pages are not counted as
working-set resident, so end-to-end load time remains the authoritative result.

## Building and testing

Set `VCPKG_ROOT`, then use the checked-in presets:

```powershell
cmake --preset vs2022-x64
cmake --build --preset release
ctest --preset release
cpack --config build\vs2022-x64\CPackConfig.cmake -C Release
```

Release packaging is driven by CMake/CPack so the DLL and canonical INI come
from the same source revision.

The implementation findings, prior-run evidence, limitations, and controlled
benchmark protocol are recorded in [AUDIT.md](AUDIT.md).
