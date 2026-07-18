# FasterFileCopy instrumented A/B runner

`Run-FasterFileCopyAB.ps1` runs matched, pinned-save tests while preserving the
shared Skyrim AE installation. It defaults to plan-only mode. Review that plan
before adding `-Execute`.

```powershell
pwsh -NoProfile -File tools\Run-FasterFileCopyAB.ps1 `
  -ManifestPath tools\faster_file_copy_ab.example.json
```

The example compares the current 1.7.1 WIP with prefaulting disabled/enabled.
Both arms use the same isolated v7 cache and matched two-second post-condition
delay. Two learning runs under the first arm are kept out of the aggregate.
Measured runs use AB/BA order to reduce ordering drift.

Before a longer A/B, use the one-second isolation smoke:

```powershell
pwsh -NoProfile -File tools\Run-FasterFileCopyAB.ps1 `
  -ManifestPath tools\faster_file_copy_ab_smoke.json
```

Its measured arms are ordered stock baseline, capture with serving disabled,
serve outside save load only, then full v7 serving. The runner first performs
an excluded stock-path probe and exactly one excluded mode-1 learning run with
serving disabled. Thus no cache-serving arm executes before the pinned save and
the newly learned v7 entries have both been exercised through safe controls.

For the first current-build decision—whether serving the warmed decompression
cache helps or hurts save loading—use the focused manifest. Its four arms share
one isolated v7 cache and separately test serve-throughout, save-load
suppression, serve-never, and prefault-off policies:

```powershell
pwsh -NoProfile -File tools\Run-FasterFileCopyAB.ps1 `
  -ManifestPath tools\faster_file_copy_ab_current_serve.json
```

Run that matrix first with detailed instrumentation, then repeat it with
`-TimingOnly`. Timing-only forces `bMeasureStats=0` in every arm while retaining
the run tag and deterministic loader, and parses `BENCH SAVE_LOAD_TIMING` as the
authoritative wall-clock result. This confirmation avoids treating the
path-dependent QPC/atomic cost of detailed instrumentation as product speed:

```powershell
pwsh -NoProfile -File tools\Run-FasterFileCopyAB.ps1 `
  -ManifestPath tools\faster_file_copy_ab_current_serve.json -TimingOnly
```

## Load drivers

- `"loadDriver": "ffc"` is for current instrumented builds. The runner sets
  `sBenchmarkAutoLoadSave`, `bBenchmarkWaitForWarm`, and
  `iBenchmarkAutoLoadDelaySec`. PerformanceMod uses `autoLoad=false`, so it only
  times/samples/exits after FasterFileCopy dispatches the pinned save. The
  configured delay is a post-readiness settle interval; the authoritative
  residency checkpoint follows it, then a fixed 250 ms quiet period separates
  checkpoint work from dispatch. The proof accounts for every interval.
- `"loadDriver": "legacy_prefault_console"` is the deterministic 1.6.4
  driver. PerformanceMod stays in manual/passive mode. The runner waits for the
  newly created `DecompCache prefault complete` line, waits the configured
  minimum post-condition delay, foregrounds Skyrim with DirectInput-compatible
  scancodes, and runs `bat ffcabload`. The transaction-owned game-root batch
  contains `load <exact pinned basename>`. A run is rejected unless the
  prefault marker also precedes FasterFileCopy's `Save load started` line.
  The proof records actual marker-to-dispatch time; focus and scancode overhead
  occur outside FasterFileCopy's measured save-load interval.
- `"loadDriver": "performance_mod"` exists only for arms where immediate
  main-menu dispatch is valid. It is not a valid comparator for released 1.6.4:
  that DLL begins its asynchronous v5 prefault at `DataLoaded`, so the immediate
  load races warmup.

For load-time comparisons, use FasterFileCopy's `SAVE LOAD TIME`, which spans
the actual save load. Do not compare PerformanceMod `load_ms` between arms with
different load drivers or warm waits: that timer starts at process/plugin load
and includes the intentional wait.

## Isolation and restoration

The runner acquires `C:\Development\SKYRIM_AE_GAMELOCK.json` before any deploy
or launch and refreshes its epoch during long runs. It refuses to continue if
Skyrim was already running. Before acquiring the lock, it also reads known
autonomous-loader configurations and refuses execution when, for example,
`SkyrimGPURendering.ini` has `[Measure] bEnabled=true` beside an active DLL. It
also checks FasterShadows' `[Debug] bAutoLoadNewestSave`. It reports the exact
plugin/config/setting and never disables a user mod. It
snapshots and hash-verifies restoration of:

- installed FasterFileCopy DLL and INI;
- active PerformanceMod DLL and INI (disabled/off variants are never touched);
- known FasterFileCopy, PerformanceMod, and SKSE log locations;
- FasterFileCopy's plugin-directory fallback log, log-init breadcrumbs, and
  PID-named `%TEMP%` fallback logs;
- the pinned `.ess`/`.skse` save files, including timestamps; and
- game-root `ffcabload.txt` when the legacy driver is present.

PerformanceMod is generated with `benchmarkOnly=true`, and every cache,
loader, threading, mipmap, and DDS feature is explicitly disabled. Only its
Bench harness is active.

Cache directories are inventory-only. The script contains no cache deletion,
truncation, rename, or move operation. Persistent growth caused by a tested DLL
is reported as before/after file and byte counts.

The released mod comparator is FasterFileCopy 1.6.4; Skyrim's runtime is a
separate version, 1.6.1170. The release matrix is:

```powershell
pwsh -NoProfile -File tools\Run-FasterFileCopyAB.ps1 `
  -ManifestPath tools\faster_file_copy_ab_164_vs_current.json
```

Run it once with detailed counters, then repeat with `-TimingOnly` for the
authoritative load-time claim. The exact 1.6.4 package DLL is read directly from
`package/FasterFileCopy-1.6.4.zip`. Its fixed v5 cache stays at the game default;
current v7 uses a separate workspace cache. Two excluded warm-ups per release
run in learning mode. Measured runs switch to startup-only mode and require an
unchanged cache inventory. The 65-second sample window lets 1.6.4's 60-second
background flush persist warm-up entries before process exit.

Current v6 cache files are intentionally inadmissible. A byte-for-byte audit of
the failed live smoke found that all 193/193 learned v6 entries used the BSA
stored/compressed size as their decompressed length. Every payload was an exact
but truncated prefix: 1,855,602 cached bytes versus 5,029,658 authoritative
bytes, with 3,174,056 bytes omitted. Current builds therefore require format
v7 and all current manifests use isolated `ffc-v7-*` directories. Never rename,
copy, or reuse an `ffc-v6-*` directory as v7. Released 1.6.4 remains isolated on
its own v5 format and fixed cache directory.

The release matrix is an end-to-end comparison, not a microbenchmark of one
copy primitive. Version 1.6.4 lacks current structured residency/lookup data,
and its path-accounting definitions differ, so only the matched FasterFileCopy
save-load interval and the common PerformanceMod gameplay sample are primary
cross-version metrics.

## Results

Each session is written under `artifacts/faster-file-copy-ab/` and contains:

- `results.csv` — one row per run;
- `aggregates.json` — means/medians/min/max by arm;
- `comparisons.json` — deltas from the first arm using FFC save-load seconds;
- per-run deployed configs, both plugin logs, process samples, and `run.json`;
- the original-state transaction snapshot and `restore-audit.json`.

To test another question, copy the example manifest and change only the arm INI
overrides. Useful current-build pairs are warm-ready versus no-prefault and
serve-throughout versus suppress-during-load versus serve-never. Keep DLL,
cache format/directory, cache limit, pinned save, post-condition delay, and
PerformanceMod timings identical within each comparison.
