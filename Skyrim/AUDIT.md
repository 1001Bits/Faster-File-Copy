# Faster File Copy audit

## Outcome

The mod's useful optimization is real, but it is asset-load latency work rather
than a general FPS or RAM-disk optimization:

- Uncompressed `ArchiveStream` reads can copy directly from demand-paged BSA
  mappings.
- Fully observed, sequential compressed entries are persisted decompressed.
  Later streams copy from the mapped cache and skip the engine decompressor.
- The managed cache worker explicitly prefaults every committed decompression-
  cache page after the initial commit. Windows can still reclaim those pages
  later under pressure because they are warmed, not `VirtualLock`-pinned.

The effective decompression cache is automatically capped at the smaller of the
user ceiling and 25% of detected total physical RAM. This restores the original
RAM-backed-cache premise without making an unbounded or non-reclaimable memory
commit. The limit governs selected cache files/current mappings, not page
tables, transient capture buffers, demand-paged BSA views, or an old generation
temporarily retained by an in-flight stream. Whole BSA mappings remain demand
paged.

## Evidence from the previous installed build

Read-only inspection of the local AE 1.6.1170 test installation on 2026-07-12
found:

- A save load reported 1,054.7 MiB served by the decompression cache and zero
  bytes through the measured decompressor path. This proves cache delivery was
  active for that workload.
- That run took 15.768 seconds, but there is no matched baseline in the log, so
  it does **not** by itself prove a speedup.
- The old startup path prefetched 1,954.8 MiB of cache into RAM.
- The cache directory occupied 2,447,702,912 bytes despite a configured 2,048
  MiB cap and still contained retired `.gdcache` sidecars.
- Legacy compatibility mode was enabled, so the old run did not use direct BSA
  mmap reads.

Version 1.7.1 replaces the detached whole-cache prefetch with an owned,
cancellable warm pass, removes the compatibility path, counts physical cache
files through directory reconciliation, cleans retired sidecars/temp
generations, and performs proactive archive eviction when a new entry needs
headroom.

## 1.7.1 live-test regression and resolution

The first redesigned build did not reach the main menu on the AE 1.6.1170 test
installation. Memoizing failed source lookups stopped the runaway work, but a
subsequent run still reported `direct mmap 0` and `cache 0` while 2,068.9 MiB
went through the native compressed path. The cache directory remained empty.

Inspection of the actual executable established the shared root cause. AE
1.6.1170 contains two PE sections named `.text`: the primary executable code
range and a later 6.3 KiB writable data range. The old section loop retained
the last prefix match, then rejected the normal archive `DoGetName` virtual
target for not belonging to that false range. Every source therefore resolved
as unmapped; without negative memoization that failed validation was repeated
for every read chunk, and with permanent negative memoization all acceleration
was disabled.

The repaired resolver no longer uses a hand-selected `.text` ownership range.
It constrains the vtable itself to the executable's exact, readable `.rdata`
section and accepts a slot target on any executable page, which also permits a
legitimate plugin detour. Semantic misses and structural failures use bounded
negative caching, while positive `(source, owned backing stream)` mappings stay
on the allocation-free hot path. Aggregate diagnostics now distinguish source
resolution, structural backoff, unknown compressed cursors, completed capture,
queue admission, duplicates, and memory/disk-cap rejection.

## Correctness hardening

- Exact runtime allowlist and Address Library vtable hooks; no hardcoded
  function RVA, instruction-pattern match, factory ABI replacement, Detours, or
  custom engine stream object.
- Separate decompressed logical cursor for compressed streams, with coherent
  read/seek/clone/open/close/destructor lifecycle handling.
- A cache-backed stream never falls back to a stale native decompressor.
- Capture accepts only a complete, contiguous stream from logical offset zero;
  seeks, discontinuities, abnormal results, and oversized payloads invalidate
  that capture.
- A no-op current-position seek preserves a sequential capture; an actual seek
  invalidates it. Failed logical-cursor queries never default to byte zero.
- Successful stream open establishes a known cursor at zero. If decompressed
  size becomes available only after the first native read, that first chunk is
  retained while the immutable stream identity is upgraded.
- Versioned cache identity includes BSA size, timestamp, filesystem identity,
  bounded content samples, and BSA entry count.
- Structural bounds/overflow/duplicate validation at startup and lazy full
  XXH32 verification on first entry use.
- Fixed-capacity index plus append-only payload commits. Payload and index data
  are flushed before the committed entry count is advanced.
- Interrupted append tails are trimmed at startup or atomically replaced on the
  next commit; failed/cancelled writes are transactionally requeued.
- Cache-view ownership is retained by every live compressed-stream side state,
  preventing rewrite/eviction from invalidating an in-flight pointer.
- Loading producers are combined, so one close event cannot incorrectly clear
  another active load gate.

## Performance and memory behavior

- Startup scans cache indexes structurally, then the managed worker commits new
  entries and explicitly touches every page of every current cache mapping.
- `iDecompCacheMaxMB=0` means automatic 25% of total physical RAM. Positive
  values are hard-clamped to that same ceiling, and fixed file/index overhead is
  included in admission accounting. A failed physical-RAM query disables this
  cache path rather than applying an unsafe guessed limit.
- Warm work uses bounded chunks, shared mapping ownership, generation checks,
  mapped-I/O SEH containment, and the same loading-screen cancellation gate as
  cache writes. Every replacement mapping starts at a zero warm prefix and is
  touched in full; an interrupted pass retains progress only for that exact
  mapping generation.
- Lookup serves an expanded entry only after its entire mapped byte range has
  passed through the warm worker. Before that point the stream stays on the
  native compressed path instead of turning a cold, larger cache file into a
  regression.
- Full BSA mappings reserve virtual address space; they do not commit the whole
  archive to physical RAM.
- Simultaneous incomplete capture capacity is capped at 256 MiB. The complete
  entry is reserved and allocated once before appending, so vector spare
  capacity cannot exceed the accounting bound.
- A single newly learned entry is capped at 64 MiB (larger existing valid cache
  entries can still be served). This prevents a handful of partially consumed
  giant resources from monopolizing the capture budget.
- Completed entries awaiting commit are independently capped at 256 MiB.
- A completed vector retains its capture-budget charge until the pending queue
  accepts or rejects it, closing the transition window between the two bounds.
- The below-normal-priority worker wakes at 32 MiB or when a loading screen
  closes, yields and checks cancellation between 8 MiB write/warm chunks. It is
  not a pinned RAM disk or a guarantee of simultaneous residency.
- Normal mode has no per-read clocks or logging. Optional measurement mode adds
  byte-counter atomics; individual read logging remains explicitly opt-in.
- Cache checksums remain lazy. Their bytes should be resident immediately after
  a successful warm pass, but Windows is free to reclaim them before the first
  hit. The first actual hit verifies the full entry once. Both verification and
  delivery contain mapped-file in-page faults and invalidate the generation.
- Learning promotes every eligible entry after one complete sequential
  observation. Retention is whole-BSA recency, not per-entry frequency; a hot
  entry can therefore retain cold siblings, and evicting one archive can free
  more space than the incoming entry needs.
- A small append installs a new mapping and intentionally rewarm-touches that
  archive's complete cache. This is the cost of making the full-mapping RAM
  premise deterministic and should be included in mode-1 benchmarks.

## Expected wins and non-wins

Most likely to improve:

- repeated save loads and cell routes;
- assets released and reopened by the engine;
- large zlib/LZ4 entries whose decompression CPU cost exceeds the mapped-copy
  and page-fault cost;
- warm-cache play where Windows still has the reused pages resident.

Not expected to improve:

- steady-state FPS after assets are loaded;
- the first observation of a compressed entry;
- loose files, which already use the Windows file cache and need no BSA
  decompression;
- assets Skyrim retains for the entire session;
- cold cache hits whose expanded payload requires more storage I/O than the
  original compressed bytes.

## Benchmark protocol

1. Use the same runtime, mod list, save, route, graphics settings, and background
   workload for every run.
2. For cache mode, first perform a learning run and wait for both the cache
   append and `cache RAM warmup complete` messages.
3. Compare normal mode against the map/warm-identical serve-off control, the
   `bEnableDuringSaveLoad=0` phase control, and `bBaselineMode=1`. Baseline
   initializes no mappings or cache, so only serve-off isolates cache-delivery
   benefit; the phase control directly tests native loading followed by
   accelerated gameplay.
4. Measure both warm repeated loads and separately controlled cold starts; do
   not mix the two populations.
5. Record wall-clock save-load time; logical path bytes, calls and path-operation
   time;
   compressed-source I/O; lookup outcomes; checksum time; eligible payload;
   resident cache pages; process CPU/I/O; working set; and page faults. Process
   I/O counters and page faults still do not fully attribute mapped-file hard
   faults; use ETW/WPR when storage attribution matters.
6. Counterbalance several repetitions (for example ABBA) and report median and
   spread. Use isolated, fully trained cache directories for incompatible
   release versions (the released 1.6.4 cache format and current format are not
   interchangeable).
7. Repeat the decisive wall-clock pairs with `bMeasureStats=0`. Detailed
   per-read accounting has path-dependent overhead and must not be the sole
   evidence for a speedup.

The workspace runner implements the release comparison in
`tools/faster_file_copy_ab_164_vs_current.json`. Because 1.6.4 has no benchmark
API, its passive PerformanceMod arm waits for the freshly written legacy
`DecompCache prefault complete` marker, observes the same post-warm delay as
current as a minimum quiet period, then runs a transaction-owned game-root console batch that names the
exact pinned save. The run is invalid unless that marker precedes the legacy
`Save load started` record. V5 and v7 caches use separate directories; excluded
learning runs use mode 1 and measured runs use mode 0 with stable inventories.

The first instrumented warm-cache smoke exposed a systematic v6 correctness
failure rather than a timing result. All 193/193 persisted entries had learned
the BSA stored/compressed byte count as their decompressed length. Direct source
decompression proved every cached payload was an exact truncated prefix: the
cache contained 1,855,602 of 5,029,658 authoritative bytes and omitted
3,174,056 bytes in total. One served entry was the truncated
`meshes\Cameras\LSCameraPanZoomInSmall.nif` implicated by the immediate load
crash. Format v7 invalidation is therefore mandatory; no v6 cache or v6-serving
benchmark is admissible, and every current-WIP matrix uses a fresh isolated v7
directory. Released 1.6.4 retains its separate v5 cache for the historical
comparison.

The instrumented build additionally provides `bPrefaultDecompCache`,
`bServeDecompCache`, and `bEnableDuringSaveLoad` causal controls plus an
exact-save auto-loader. Its `BENCH`
records separate mutually exclusive logical output from nested compressed-
source I/O; earlier four-way totals must not be interpreted that way because
they could count both compressed input and decompressed output. Residency is
queried with `QueryWorkingSetEx` at the quiescent pre-autoload checkpoint and
after the load. Historical warm-prefix coverage remains separately reported
because it does not prove that Windows has retained those pages. Working-set
residency is conservative: standby/file-cache pages elsewhere in physical RAM
are not counted even though they may require only a soft fault.

The local Release build, cache-format/cursor tests, AE PE-section regression,
compressed-read policy tests, concurrent byte-budget test, cache-limit policy
and warm-range policy tests, deterministic runtime-install test, and ZIP
packaging checks pass. A matched in-game A/B run is still needed to quantify
the improvement on a particular player's hardware and mod list.
