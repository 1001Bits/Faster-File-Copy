#requires -Version 7.2

<#
.SYNOPSIS
Runs a transactional, instrumented FasterFileCopy A/B suite on the shared Skyrim AE testbed.

.DESCRIPTION
The script is plan-only unless -Execute is supplied. During execution it:

* acquires and refreshes C:\Development\SKYRIM_AE_GAMELOCK.json with the
  coordination protocol's atomic create/stale-lock rules;
* refuses to touch a Skyrim process that was already running;
* snapshots and later restores the installed FasterFileCopy/PerformanceMod
  DLLs, INIs, candidate logs, and the pinned save files;
* installs a manifest-selected FasterFileCopy DLL/INI for each arm;
* installs PerformanceMod strictly as a passive benchmark harness (all of its
  performance features are disabled);
* archives both plugin logs and an external process-memory timeline per run;
* inventories cache directories before/after without deleting, renaming, or
  truncating a cache file; and
* emits per-run JSON, a CSV, aggregate JSON, and pairwise comparison JSON.

For a current FasterFileCopy arm, use loadDriver="ffc". PerformanceMod then
waits passively while FasterFileCopy waits for warm-ready (if requested) and
loads the pinned save. Legacy DLLs that lack the benchmark auto-loader must use
loadDriver="legacy_prefault_console". The runner waits for the legacy prefault-
complete marker, observes the configured minimum delay, and invokes an exact-save game-
root console batch. loadDriver="performance_mod" remains an immediate, explicitly
limited control that cannot prove warm readiness.

.EXAMPLE
pwsh -NoProfile -File tools\Run-FasterFileCopyAB.ps1 `
  -ManifestPath tools\faster_file_copy_ab.example.json

Prints and validates the plan. Does not acquire the lock or modify any file.

.EXAMPLE
pwsh -NoProfile -File tools\Run-FasterFileCopyAB.ps1 `
  -ManifestPath tools\faster_file_copy_ab.example.json -Execute

Executes the suite transactionally and restores the testbed in a finally block.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ManifestPath = (Join-Path $PSScriptRoot 'faster_file_copy_ab_current_serve.json'),

    [Parameter()]
    [switch]$Execute,

    [Parameter()]
    [switch]$TimingOnly,

    [Parameter()]
    [string]$GameRoot = 'C:\Games\Skyrim AE 1.6',

    [Parameter()]
    [string]$PerformanceModDllPath =
        'C:\Development\New performance mod\MultiRuntime-SE-AE-VR\build\Release\PerformanceMod.dll',

    [Parameter()]
    [string]$OutputRoot = (Join-Path $PSScriptRoot '..\artifacts\faster-file-copy-ab'),

    [Parameter()]
    [string]$LockPath = 'C:\Development\SKYRIM_AE_GAMELOCK.json',

    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9_.-]+$')]
    [string]$LockHolder = "ffc-ab-$PID"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$Invariant = [System.Globalization.CultureInfo]::InvariantCulture
$ScriptPath = $PSCommandPath
$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))

function Resolve-NormalPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$BaseDirectory
    )

    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    if (-not [System.IO.Path]::IsPathRooted($expanded)) {
        $expanded = Join-Path $BaseDirectory $expanded
    }
    return [System.IO.Path]::GetFullPath($expanded)
}

function Get-OptionalProperty {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Name,
        [Parameter()]$Default = $null
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $Default }
    return $property.Value
}

function ConvertTo-IsoTimestampText {
    param([Parameter()]$Value)
    if ($Value -is [DateTimeOffset]) { return $Value.ToString('O') }
    if ($Value -is [DateTime]) { return $Value.ToString('O') }
    return [string]$Value
}

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Get-BytesSha256 {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [Convert]::ToHexString($sha.ComputeHash($Bytes))
    }
    finally {
        $sha.Dispose()
    }
}

function Get-ZipEntryBytes {
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$EntryName
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $wanted = $EntryName.Replace('\', '/').TrimStart('/')
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $entry = $zip.Entries | Where-Object {
            $_.FullName.Replace('\', '/').TrimStart('/') -ieq $wanted
        } | Select-Object -First 1
        if (-not $entry) {
            throw "ZIP entry '$EntryName' was not found in '$ZipPath'."
        }
        $stream = $entry.Open()
        try {
            $memory = [System.IO.MemoryStream]::new()
            try {
                $stream.CopyTo($memory)
                return $memory.ToArray()
            }
            finally {
                $memory.Dispose()
            }
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $zip.Dispose()
    }
}

function Get-ArmDllBytes {
    param([Parameter(Mandatory)]$Arm)

    if ($Arm.dllPath) {
        return [System.IO.File]::ReadAllBytes([string]$Arm.dllPath)
    }
    return Get-ZipEntryBytes -ZipPath ([string]$Arm.zipPath) -EntryName ([string]$Arm.zipDllEntry)
}

function Get-ArmIniText {
    param([Parameter(Mandatory)]$Arm)

    if ($Arm.iniPath) {
        return [System.IO.File]::ReadAllText([string]$Arm.iniPath)
    }
    if ($Arm.zipIniEntry) {
        $bytes = Get-ZipEntryBytes -ZipPath ([string]$Arm.zipPath) -EntryName ([string]$Arm.zipIniEntry)
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    }
    throw "Arm '$($Arm.name)' has neither iniPath nor zipIniEntry."
}

function Set-IniValue {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($line in [regex]::Split($Text, '\r?\n')) {
        $lines.Add($line)
    }

    $sectionStart = -1
    $sectionEnd = $lines.Count
    for ($i = 0; $i -lt $lines.Count; ++$i) {
        if ($lines[$i] -match '^\s*\[([^\]]+)\]\s*$') {
            if ($Matches[1].Trim() -ieq $Section) {
                $sectionStart = $i
                for ($j = $i + 1; $j -lt $lines.Count; ++$j) {
                    if ($lines[$j] -match '^\s*\[[^\]]+\]\s*$') {
                        $sectionEnd = $j
                        break
                    }
                }
                break
            }
        }
    }

    if ($sectionStart -lt 0) {
        if ($lines.Count -gt 0 -and $lines[$lines.Count - 1] -ne '') {
            $lines.Add('')
        }
        $lines.Add("[$Section]")
        $lines.Add("$Key=$Value")
    }
    else {
        $keyPattern = '^\s*' + [regex]::Escape($Key) + '\s*='
        $replaced = $false
        for ($i = $sectionStart + 1; $i -lt $sectionEnd; ++$i) {
            if ($lines[$i] -match $keyPattern) {
                $lines[$i] = "$Key=$Value"
                $replaced = $true
                break
            }
        }
        if (-not $replaced) {
            $lines.Insert($sectionEnd, "$Key=$Value")
        }
    }

    return (($lines -join "`r`n").TrimEnd("`r", "`n") + "`r`n")
}

function Get-IniValue {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Key
    )

    $inSection = $false
    foreach ($line in [regex]::Split($Text, '\r?\n')) {
        if ($line -match '^\s*\[([^\]]+)\]\s*$') {
            $inSection = $Matches[1].Trim() -ieq $Section
            continue
        }
        if ($inSection -and $line -match ('^\s*' + [regex]::Escape($Key) + '\s*=\s*(.*?)\s*$')) {
            return $Matches[1]
        }
    }
    return $null
}

function Get-KnownAutonomousLoaderStates {
    param([Parameter(Mandatory)][string]$GameRoot)

    # These plugins can independently load a save before this runner reaches
    # its checkpoint. Detection is deliberately read-only; user mods are never
    # disabled or rewritten by the benchmark transaction.
    $definitions = @(
        [pscustomobject]@{
            name = 'SkyrimGPURendering MeasureBot'
            plugin = 'Data\SKSE\Plugins\SkyrimGPURendering.dll'
            config = 'Data\SKSE\Plugins\SkyrimGPURendering.ini'
            section = 'Measure'
            key = 'bEnabled'
        },
        [pscustomobject]@{
            name = 'FasterShadows newest-save loader'
            plugin = 'Data\SKSE\Plugins\FasterShadows.dll'
            config = 'Data\SKSE\Plugins\FasterShadows.ini'
            section = 'Debug'
            key = 'bAutoLoadNewestSave'
        }
    )

    return @($definitions | ForEach-Object {
        $pluginPath = Join-Path $GameRoot $_.plugin
        $configPath = Join-Path $GameRoot $_.config
        $pluginPresent = Test-Path -LiteralPath $pluginPath -PathType Leaf
        $configPresent = Test-Path -LiteralPath $configPath -PathType Leaf
        $rawValue = $null
        if ($configPresent) {
            $rawValue = Get-IniValue `
                -Text ([System.IO.File]::ReadAllText($configPath)) `
                -Section $_.section -Key $_.key
        }
        $normalized = if ($null -eq $rawValue) { $null } else {
            ([string]$rawValue).Trim().Trim('"').ToLowerInvariant()
        }
        $settingEnabled = $null -ne $normalized -and
            $normalized -notin @('', '0', 'false', 'no', 'off', 'disabled')
        [pscustomobject][ordered]@{
            name = $_.name
            plugin_path = $pluginPath
            plugin_present = $pluginPresent
            config_path = $configPath
            config_present = $configPresent
            section = $_.section
            key = $_.key
            value = $rawValue
            enabled = [bool]($pluginPresent -and $settingEnabled)
        }
    })
}

function Assert-NoKnownAutonomousLoaders {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$States
    )

    $conflicts = @($States | Where-Object enabled)
    if ($conflicts.Count -eq 0) { return }
    $details = @($conflicts | ForEach-Object {
        "- $($_.name): plugin='$($_.plugin_path)'; config='$($_.config_path)'; setting=[$($_.section)] $($_.key)=$($_.value)"
    }) -join [Environment]::NewLine
    throw ("Execution refused because a known autonomous save loader is enabled " +
        "and could steal the pinned load before the benchmark checkpoint. " +
        "Disable it explicitly, then rerun; no user mod was changed." +
        [Environment]::NewLine + $details)
}

function Apply-IniOverrides {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter()]$Overrides
    )

    $result = $Text
    if (-not $Overrides) { return $result }
    foreach ($sectionProperty in $Overrides.PSObject.Properties) {
        if (-not $sectionProperty.Value) { continue }
        foreach ($keyProperty in $sectionProperty.Value.PSObject.Properties) {
            $result = Set-IniValue -Text $result -Section $sectionProperty.Name `
                -Key $keyProperty.Name -Value ([string]$keyProperty.Value)
        }
    }
    return $result
}

function Get-TotalPhysicalMemoryBytes {
    Add-Type -AssemblyName Microsoft.VisualBasic
    $info = [Microsoft.VisualBasic.Devices.ComputerInfo]::new()
    return [uint64]$info.TotalPhysicalMemory
}

function Get-CacheInventory {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return [pscustomobject]@{
            path = $Path
            exists = $false
            files = 0
            bytes = [uint64]0
        }
    }

    $measure = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction Stop |
        Measure-Object -Property Length -Sum
    return [pscustomobject]@{
        path = $Path
        exists = $true
        files = [int]$measure.Count
        bytes = [uint64]($measure.Sum ?? 0)
    }
}

function Get-LogCandidates {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter()][AllowEmptyCollection()][string[]]$AdditionalPaths = @()
    )

    $documents = [Environment]::GetFolderPath([Environment+SpecialFolder]::MyDocuments)
    $candidates = @(
        (Join-Path $documents "My Games\Skyrim Special Edition\SKSE\$Name.log"),
        (Join-Path $documents "My Games\Skyrim.INI\SKSE\$Name.log")
    ) + @($AdditionalPaths)
    return @($candidates | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_)
    } | ForEach-Object { [string]$_ } | Select-Object -Unique)
}

function Save-FileState {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$SnapshotDirectory,
        [Parameter(Mandatory)][string]$Label
    )

    $exists = Test-Path -LiteralPath $Path -PathType Leaf
    $snapshot = Join-Path $SnapshotDirectory ($Label + '.bin')
    $state = [ordered]@{
        label = $Label
        path = $Path
        existed = $exists
        snapshot = if ($exists) { $snapshot } else { $null }
        length = if ($exists) { (Get-Item -LiteralPath $Path).Length } else { $null }
        last_write_utc = if ($exists) { (Get-Item -LiteralPath $Path).LastWriteTimeUtc.ToString('O') } else { $null }
        sha256 = if ($exists) { Get-Sha256 -Path $Path } else { $null }
    }
    if ($exists) {
        Copy-Item -LiteralPath $Path -Destination $snapshot -Force
    }
    return [pscustomobject]$state
}

function New-AbsentFileState {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )

    return [pscustomobject][ordered]@{
        label = $Label
        path = $Path
        existed = $false
        snapshot = $null
        length = $null
        last_write_utc = $null
        sha256 = $null
    }
}

function Restore-FileState {
    param([Parameter(Mandatory)]$State)

    if ($State.existed) {
        $parent = Split-Path -Parent ([string]$State.path)
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        Copy-Item -LiteralPath ([string]$State.snapshot) -Destination ([string]$State.path) -Force
        (Get-Item -LiteralPath ([string]$State.path)).LastWriteTimeUtc =
            [datetime]::Parse([string]$State.last_write_utc, $Invariant,
                [System.Globalization.DateTimeStyles]::RoundtripKind)
    }
    elseif (Test-Path -LiteralPath ([string]$State.path) -PathType Leaf) {
        # Only transaction-owned plugin/log/benchmark-driver files can reach
        # this branch. Cache paths are never passed to these state functions.
        Remove-Item -LiteralPath ([string]$State.path) -Force
    }

    $actualExists = Test-Path -LiteralPath ([string]$State.path) -PathType Leaf
    $actualSha = if ($actualExists) { Get-Sha256 -Path ([string]$State.path) } else { $null }
    return [pscustomobject]@{
        label = $State.label
        path = $State.path
        expected_exists = [bool]$State.existed
        actual_exists = $actualExists
        expected_sha256 = $State.sha256
        actual_sha256 = $actualSha
        restored = (($actualExists -eq [bool]$State.existed) -and
            (-not $actualExists -or $actualSha -eq $State.sha256))
    }
}

function Invoke-LockCtl {
    param(
        [Parameter(Mandatory)][ValidateSet('acquire', 'release', 'status')][string]$Action,
        [Parameter()][string]$Intent = ''
    )

    $newPayload = {
        param([string]$Since)
        $now = [DateTimeOffset]::Now
        return ([ordered]@{
            holder = $LockHolder
            intent = $Intent
            since = if ($Since) { $Since } else { $now.ToString('O') }
            epoch = $now.ToUnixTimeSeconds()
            pid = $PID
        } | ConvertTo-Json -Compress) + "`n"
    }
    $readStreamJson = {
        param([System.IO.FileStream]$Stream)
        $Stream.Position = 0
        $bytes = [byte[]]::new([int]$Stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $Stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { break }
            $offset += $read
        }
        if ($offset -ne $bytes.Length) { throw 'Could not read the complete shared lock file.' }
        return $Utf8NoBom.GetString($bytes) | ConvertFrom-Json
    }
    $writeStreamJson = {
        param([System.IO.FileStream]$Stream, [string]$Json)
        $bytes = $Utf8NoBom.GetBytes($Json)
        $Stream.Position = 0
        $Stream.SetLength(0)
        $Stream.Write($bytes, 0, $bytes.Length)
        $Stream.Flush($true)
    }

    switch ($Action) {
        'status' {
            $text = if (Test-Path -LiteralPath $LockPath -PathType Leaf) {
                Get-Content -Raw -LiteralPath $LockPath
            } else { 'unlocked' }
            $game = if (Get-Process -Name 'SkyrimSE' -ErrorAction SilentlyContinue) {
                'game: RUNNING'
            } else { 'game: stopped' }
            return "$text`n$game"
        }
        'acquire' {
            $parent = Split-Path -Parent $LockPath
            if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
                throw "Shared lock parent directory does not exist: $parent"
            }
            try {
                $stream = [System.IO.File]::Open($LockPath,
                    [System.IO.FileMode]::CreateNew,
                    [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::None)
                try { & $writeStreamJson $stream (& $newPayload '') }
                finally { $stream.Dispose() }
                return "ACQUIRED by $LockHolder"
            }
            catch [System.IO.IOException] {
                if (-not (Test-Path -LiteralPath $LockPath -PathType Leaf)) { throw }
            }

            try {
                $stream = [System.IO.File]::Open($LockPath,
                    [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::ReadWrite,
                    [System.IO.FileShare]::None)
            }
            catch {
                throw 'Shared testbed lock is busy and could not be inspected exclusively.'
            }
            try {
                try { $current = & $readStreamJson $stream }
                catch { throw 'Shared testbed lock is malformed; refusing to steal it.' }
                $holder = [string](Get-OptionalProperty $current 'holder' '')
                $epoch = [int64](Get-OptionalProperty $current 'epoch' 0)
                $since = ConvertTo-IsoTimestampText (Get-OptionalProperty $current 'since' '')
                $age = [DateTimeOffset]::Now.ToUnixTimeSeconds() - $epoch
                if ($holder -eq $LockHolder) {
                    & $writeStreamJson $stream (& $newPayload $since)
                    return "ALREADY-HELD by $LockHolder"
                }
                if ($epoch -gt 0 -and $age -gt 900) {
                    if (Get-Process -Name 'SkyrimSE' -ErrorAction SilentlyContinue) {
                        throw "Stale lock is held by '$holder', but Skyrim is running; refusing to steal it."
                    }
                    & $writeStreamJson $stream (& $newPayload '')
                    return "STOLEN-STALE (was $holder, age ${age}s) now $LockHolder"
                }
                throw "BUSY held by '$holder' (age ${age}s)"
            }
            finally { $stream.Dispose() }
        }
        'release' {
            if (-not (Test-Path -LiteralPath $LockPath -PathType Leaf)) { return 'NOT-LOCKED' }
            try {
                $stream = [System.IO.File]::Open($LockPath,
                    [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Read,
                    [System.IO.FileShare]::None)
            }
            catch { throw 'Shared testbed lock could not be opened for release.' }
            try {
                $current = & $readStreamJson $stream
                $holder = [string](Get-OptionalProperty $current 'holder' '')
                if ($holder -ne $LockHolder) {
                    throw "REFUSE-release: held by '$holder', not '$LockHolder'."
                }
            }
            finally { $stream.Dispose() }
            Remove-Item -LiteralPath $LockPath -Force
            return 'RELEASED'
        }
    }
}

function Update-TestbedLockHeartbeat {
    param([Parameter(Mandatory)][string]$Intent)

    if (-not (Test-Path -LiteralPath $LockPath -PathType Leaf)) {
        throw 'Shared testbed lock disappeared while the suite was active.'
    }
    try {
        $stream = [System.IO.File]::Open($LockPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None)
    }
    catch { throw 'Shared testbed lock could not be opened for heartbeat.' }
    try {
        $bytes = [byte[]]::new([int]$stream.Length)
        [void]$stream.Read($bytes, 0, $bytes.Length)
        $current = $Utf8NoBom.GetString($bytes) | ConvertFrom-Json
        if ([string]$current.holder -ne $LockHolder) {
            throw "Shared testbed lock ownership changed to '$($current.holder)'."
        }
        $now = [DateTimeOffset]::Now
        $payload = ([ordered]@{
            holder = $LockHolder
            intent = $Intent
            since = ConvertTo-IsoTimestampText $current.since
            epoch = $now.ToUnixTimeSeconds()
            pid = $PID
        } | ConvertTo-Json -Compress) + "`n"
        $encoded = $Utf8NoBom.GetBytes($payload)
        $stream.Position = 0
        $stream.SetLength(0)
        $stream.Write($encoded, 0, $encoded.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
}

function Assert-NoSharedGameProcess {
    $processes = @(Get-Process -Name 'SkyrimSE', 'skse64_loader' -ErrorAction SilentlyContinue)
    if ($processes.Count -gt 0) {
        $description = ($processes | ForEach-Object { "$($_.ProcessName):$($_.Id)" }) -join ', '
        throw "The shared game was already running ($description). Refusing to deploy or stop it."
    }
}

function Register-OwnedProcess {
    param(
        [Parameter(Mandatory)][hashtable]$Registry,
        [Parameter(Mandatory)]$Process
    )
    try {
        $Registry[[int]$Process.Id] = [pscustomobject]@{
            name = [string]$Process.ProcessName
            start_time_utc = $Process.StartTime.ToUniversalTime().ToString('O')
        }
    }
    catch {
        # A short-lived launcher can exit before StartTime is queried; never
        # register an unverifiable PID because PID reuse must not be killable.
    }
}

function Stop-OwnedProcesses {
    param([Parameter(Mandatory)][hashtable]$Registry)
    foreach ($entry in @($Registry.GetEnumerator())) {
        $process = Get-Process -Id ([int]$entry.Key) -ErrorAction SilentlyContinue
        if (-not $process) { continue }
        try {
            $sameStart = $process.StartTime.ToUniversalTime().ToString('O') -eq
                [string]$entry.Value.start_time_utc
            $sameName = $process.ProcessName -eq [string]$entry.Value.name
            if ($sameStart -and $sameName -and
                $process.ProcessName -in @('SkyrimSE', 'skse64_loader')) {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            # Process exited or became inaccessible; do not broaden the kill.
        }
    }
}

function Initialize-FfcAbKeyboardInput {
    if ('FfcAb.NativeKeyboard' -as [type]) { return }

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace FfcAb
{
    public static class NativeKeyboard
    {
        [DllImport("user32.dll")]
        public static extern void keybd_event(
            byte virtualKey, byte scanCode, uint flags, UIntPtr extraInfo);

        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr window);

        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr window, int command);
    }
}
'@
}

function Send-FfcAbScanCode {
    param([Parameter(Mandatory)][byte]$ScanCode)

    $scanCodeFlag = [uint32]0x0008
    $keyUpFlag = [uint32]0x0002
    [FfcAb.NativeKeyboard]::keybd_event(
        0, $ScanCode, $scanCodeFlag, [UIntPtr]::Zero)
    Start-Sleep -Milliseconds 55
    [FfcAb.NativeKeyboard]::keybd_event(
        0, $ScanCode, ($scanCodeFlag -bor $keyUpFlag), [UIntPtr]::Zero)
}

function Invoke-LegacyPrefaultConsoleLoad {
    param(
        [Parameter(Mandatory)]$GameProcess,
        [Parameter(Mandatory)][int]$PostMarkerDelaySeconds
    )

    Initialize-FfcAbKeyboardInput
    if ($PostMarkerDelaySeconds -gt 0) {
        Start-Sleep -Seconds $PostMarkerDelaySeconds
    }

    # This is the same DirectInput-compatible foreground technique used by the
    # local PerformanceMod automation. SendKeys/WM_CHAR are not reliable for
    # Skyrim's fullscreen window.
    $window = [IntPtr]::Zero
    $windowDeadline = [DateTimeOffset]::UtcNow.AddSeconds(15)
    while ($window -eq [IntPtr]::Zero -and
           [DateTimeOffset]::UtcNow -lt $windowDeadline) {
        try {
            $GameProcess.Refresh()
            $window = $GameProcess.MainWindowHandle
        }
        catch { $window = [IntPtr]::Zero }
        if ($window -eq [IntPtr]::Zero) { Start-Sleep -Milliseconds 250 }
    }
    if ($window -eq [IntPtr]::Zero) {
        throw 'Legacy load driver could not obtain SkyrimSE MainWindowHandle.'
    }

    $scanCodeFlag = [uint32]0x0008
    $keyUpFlag = [uint32]0x0002
    $virtualAlt = [byte]0x12
    $scanAlt = [byte]0x38
    [FfcAb.NativeKeyboard]::keybd_event(
        $virtualAlt, $scanAlt, $scanCodeFlag, [UIntPtr]::Zero)
    Start-Sleep -Milliseconds 30
    [FfcAb.NativeKeyboard]::keybd_event(
        $virtualAlt, $scanAlt, ($scanCodeFlag -bor $keyUpFlag), [UIntPtr]::Zero)
    Start-Sleep -Milliseconds 50
    [void][FfcAb.NativeKeyboard]::ShowWindow($window, 9) # SW_RESTORE
    [void][FfcAb.NativeKeyboard]::SetForegroundWindow($window)
    Start-Sleep -Milliseconds 600
    if ([FfcAb.NativeKeyboard]::GetForegroundWindow() -ne $window) {
        throw 'Legacy load driver could not make SkyrimSE the foreground window.'
    }

    # Open the console and run game-root ffcabload.txt. That file contains the
    # exact pinned basename, avoiding the ambiguous main-menu Continue entry.
    Send-FfcAbScanCode -ScanCode ([byte]0x29) # ` / ~
    Start-Sleep -Milliseconds 500
    $commandScanCodes = [byte[]](
        0x30,       # b
        0x1E,       # a
        0x14,       # t
        0x39,       # space
        0x21, 0x21, # ff
        0x2E,       # c
        0x1E,       # a
        0x30,       # b
        0x26,       # l
        0x18,       # o
        0x1E,       # a
        0x20        # d
    )
    foreach ($scanCode in $commandScanCodes) {
        Send-FfcAbScanCode -ScanCode $scanCode
        Start-Sleep -Milliseconds 20
    }
    Send-FfcAbScanCode -ScanCode ([byte]0x1C) # Enter

    return [pscustomobject]@{
        command = 'bat ffcabload'
        window_handle = $window.ToInt64()
        dispatched_utc = [DateTimeOffset]::UtcNow.ToString('O')
    }
}

function New-PerformanceModIni {
    param(
        [Parameter(Mandatory)][bool]$AutoLoad,
        [Parameter(Mandatory)][string]$SaveName,
        [Parameter(Mandatory)][int]$SettleSeconds,
        [Parameter(Mandatory)][int]$SampleSeconds,
        [Parameter(Mandatory)][int]$LoadTimeoutSeconds
    )

    $auto = if ($AutoLoad) { 'true' } else { 'false' }
    return @"
[General]
enabled = true
enableStats = false
verboseLogging = false
benchmarkOnly = true

[LockReplacer]
enabled = false
spinCount = 80

[JobSystemExpander]
enabled = false
workers = 0

[PapyrusThreading]
enabled = false
async = false
workers = 0
batchSize = 8

[ParallelAssets]
enabled = false
workers = 0

[Cache]
bEnabled = 0
bBaselineMode = 0
bEnableRefCache = 0
bEnableByteCache = 0

[Loader]
enabled = false
loaderMode = 0
workers = 0
Denylist =

[MipmapStreaming]
enabled = false
tailMips = 4

[DDSStreamMod]
enabled = false
mutate = false
dropMips = 1
diffuseOnly = true
minDim = 512

[Bench]
enabled = true
continuous = false
autoLoad = $auto
save = $SaveName
settleSeconds = $SettleSeconds
sampleSeconds = $SampleSeconds
loadTimeoutSeconds = $LoadTimeoutSeconds
"@
}

function Get-LastRegexNumber {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter()][string]$Group = 'value'
    )

    $matches = [regex]::Matches($Text, $Pattern,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($matches.Count -eq 0) { return $null }
    $raw = $matches[$matches.Count - 1].Groups[$Group].Value
    $number = 0.0
    if ([double]::TryParse($raw,
            [System.Globalization.NumberStyles]::Float,
            $Invariant, [ref]$number)) {
        return $number
    }
    return $null
}

function Get-StructuredBenchMarkers {
    param([Parameter(Mandatory)][string]$Text)

    $markers = [System.Collections.Generic.List[object]]::new()
    $lineNumber = 0
    foreach ($line in [regex]::Split($Text, '\r?\n')) {
        ++$lineNumber
        if ($line -notmatch '(?i)BENCH') { continue }
        $values = [ordered]@{}
        foreach ($match in [regex]::Matches($line,
                '(?<key>[A-Za-z][A-Za-z0-9_.-]*)=(?<value>"[^"]*"|[^\s|,]+)')) {
            $values[$match.Groups['key'].Value] =
                $match.Groups['value'].Value.Trim('"')
        }
        $markers.Add([pscustomobject]@{
            line_number = $lineNumber
            line = $line
            values = [pscustomobject]$values
        })
    }
    return @($markers)
}

function Get-LastStructuredMarker {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Markers,
        [Parameter(Mandatory)][string]$Pattern
    )

    return $Markers | Where-Object { $_.line -match $Pattern } | Select-Object -Last 1
}

function Get-StructuredMarkerValues {
    param([Parameter()]$Marker)
    if (-not $Marker) { return $null }
    $property = $Marker.PSObject.Properties['values']
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-StructuredNumber {
    param(
        [Parameter()]$Values,
        [Parameter(Mandatory)][string]$Key
    )

    if (-not $Values) { return $null }
    $property = $Values.PSObject.Properties[$Key]
    if ($null -eq $property) { return $null }
    $number = 0.0
    if ([double]::TryParse([string]$property.Value,
            [System.Globalization.NumberStyles]::Float,
            $Invariant, [ref]$number)) {
        return $number
    }
    return $null
}

function Get-StructuredText {
    param(
        [Parameter()]$Values,
        [Parameter(Mandatory)][string]$Key
    )

    if (-not $Values) { return $null }
    $property = $Values.PSObject.Properties[$Key]
    if ($null -eq $property) { return $null }
    return [string]$property.Value
}

function Get-SkseLoadEvents {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $events = [System.Collections.Generic.List[object]]::new()
    $pendingSave = $null
    $pendingLine = 0
    $lineNumber = 0
    foreach ($line in [regex]::Split($Text, '\r?\n')) {
        ++$lineNumber
        $saveMatch = [regex]::Match($line,
            '^save name is\s+(?<save>.*?)\s*$',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($saveMatch.Success) {
            $pendingSave = $saveMatch.Groups['save'].Value
            $pendingLine = $lineNumber
            continue
        }

        $dispatchMatch = [regex]::Match($line,
            '^dispatch message \((?<type>-?\d+)\) to plugin listeners\s*$',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if (-not $dispatchMatch.Success) { continue }

        # Bind a save-name record only to the very next SKSE dispatch record.
        # Type 2 is kPreLoadGame; type 4 is kSaveGame/autosave.
        if ($null -ne $pendingSave -and
            [int]$dispatchMatch.Groups['type'].Value -eq 2) {
            $events.Add([pscustomobject]@{
                save = $pendingSave
                save_line_number = $pendingLine
                dispatch_line_number = $lineNumber
            })
        }
        $pendingSave = $null
        $pendingLine = 0
    }
    return @($events)
}

function Get-SlashNumber {
    param(
        [Parameter()][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][int]$Index
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $parts = $Text.Split('/')
    if ($Index -lt 0 -or $Index -ge $parts.Count) { return $null }
    $number = 0.0
    if ([double]::TryParse($parts[$Index],
            [System.Globalization.NumberStyles]::Float,
            $Invariant, [ref]$number)) {
        return $number
    }
    return $null
}

function Parse-RunMetrics {
    param(
        [Parameter(Mandatory)][string]$FfcLogPath,
        [Parameter(Mandatory)][string]$PerformanceLogPath,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ProcessSamples
    )

    $ffc = if (Test-Path -LiteralPath $FfcLogPath) {
        Get-Content -Raw -LiteralPath $FfcLogPath
    } else { '' }
    $perf = if (Test-Path -LiteralPath $PerformanceLogPath) {
        Get-Content -Raw -LiteralPath $PerformanceLogPath
    } else { '' }
    $structuredMarkers = @(Get-StructuredBenchMarkers -Text $ffc)
    $structuredStartupMarker = Get-LastStructuredMarker $structuredMarkers 'BENCH\s+STARTUP\b'
    $structuredTimingMarker = Get-LastStructuredMarker $structuredMarkers `
        'BENCH\s+SAVE_LOAD_TIMING\b'
    $structuredLoadBeginMarker = Get-LastStructuredMarker $structuredMarkers `
        'BENCH\s+SAVE_LOAD_BEGIN\b'
    $structuredSaveMarker = Get-LastStructuredMarker $structuredMarkers 'BENCH\s+SAVE_LOAD\b'
    $structuredGameplayMarker = Get-LastStructuredMarker $structuredMarkers 'BENCH\s+GAMEPLAY\b'
    $structuredInitMarker = Get-LastStructuredMarker $structuredMarkers 'BENCH\s+INIT_PHASES\b'
    $structuredAutoLoadMarker = $structuredMarkers | Where-Object {
        $_.line -match 'BENCH\s+AUTOLOAD\b' -and
        (Get-StructuredText $_.values 'status') -eq 'dispatching'
    } | Select-Object -First 1
    $structuredCallingLoadMarker = $structuredMarkers | Where-Object {
        $_.line -match 'BENCH\s+AUTOLOAD\b' -and
        (Get-StructuredText $_.values 'status') -eq 'calling_load'
    } | Select-Object -First 1
    $preDispatchWarmMarkers = [System.Collections.Generic.List[object]]::new()
    $preDispatchWarmStartMarkers = [System.Collections.Generic.List[object]]::new()
    foreach ($marker in $structuredMarkers) {
        if ($marker.line -match 'BENCH\s+AUTOLOAD\b' -and
            (Get-StructuredText $marker.values 'status') -eq 'dispatching') { break }
        # If an external/manual load beats the configured auto-loader, never
        # mislabel post-load warm passes as pre-dispatch work.
        if ($marker.line -match 'BENCH\s+SAVE_LOAD(?:_BEGIN|_TIMING)?\b') { break }
        if ($marker.line -match 'BENCH\s+WARM_START\b') {
            $preDispatchWarmStartMarkers.Add($marker)
        }
        if ($marker.line -match 'BENCH\s+WARM_PASS\b') {
            $preDispatchWarmMarkers.Add($marker)
        }
    }
    $structuredWarmMarker = $preDispatchWarmMarkers | Select-Object -Last 1
    $structuredWarmStartMarker = $preDispatchWarmStartMarkers | Select-Object -First 1
    $structuredCacheMarkers = @($structuredMarkers | Where-Object {
        $_.line -match 'BENCH\s+CACHE_STATE\b'
    })
    $preAutoloadCacheMarker = $structuredCacheMarkers | Where-Object {
        (Get-StructuredText $_.values 'event') -eq 'pre_autoload'
    } | Select-Object -First 1
    $warmCompleteCacheMarker = $preAutoloadCacheMarker ?? ($structuredCacheMarkers | Where-Object {
        (Get-StructuredText $_.values 'event') -eq 'warm_complete'
    } | Select-Object -First 1)
    $structuredStartupValues = Get-StructuredMarkerValues $structuredStartupMarker
    $structuredTimingValues = Get-StructuredMarkerValues $structuredTimingMarker
    $structuredSaveValues = Get-StructuredMarkerValues $structuredSaveMarker
    $structuredGameplayValues = Get-StructuredMarkerValues $structuredGameplayMarker
    $structuredWarmValues = Get-StructuredMarkerValues $structuredWarmMarker
    $structuredWarmStartValues = Get-StructuredMarkerValues $structuredWarmStartMarker
    $structuredInitValues = Get-StructuredMarkerValues $structuredInitMarker
    $structuredAutoLoadValues = Get-StructuredMarkerValues $structuredAutoLoadMarker
    $warmCompleteCacheValues = Get-StructuredMarkerValues $warmCompleteCacheMarker

    $benchMatches = [regex]::Matches($perf,
        'BENCH_DONE:\s*loaded=(?<loaded>[01])\s+load_ms=(?<load>[\d.]+)\s+' +
        'avg_fps=(?<fps>[\d.]+)\s+frametime_ms=(?<frame>[\d.]+)\s+frames=(?<frames>\d+)',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $bench = if ($benchMatches.Count -gt 0) { $benchMatches[$benchMatches.Count - 1] } else { $null }

    $saveMatches = [regex]::Matches($ffc,
        'SAVE LOAD TIME:\s*(?<seconds>[\d.]+)s\s*\|\s*(?<payload>[\d.]+)\s+M(?:i)?B payload total\s*\|' +
        '\s*direct mmap\s+(?<mmap>[\d.]+)/(?<mmapPct>[\d.]+)%\s*\+\s*' +
        'cache\s+(?<cache>[\d.]+)/(?<cachePct>[\d.]+)%\s*\+\s*' +
        'compressed path\s+(?<compressed>[\d.]+)/(?<compressedPct>[\d.]+)%\s*\+\s*' +
        'native direct\s+(?<native>[\d.]+)/(?<nativePct>[\d.]+)%\s*\|\s*' +
        '(?<throughput>[\d.]+)\s+M(?:i)?B/s',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $save = if ($saveMatches.Count -gt 0) { $saveMatches[$saveMatches.Count - 1] } else { $null }

    $peakWorking = 0L
    $peakPrivate = 0L
    $peakCpu = 0.0
    foreach ($sample in $ProcessSamples) {
        $peakWorking = [Math]::Max($peakWorking, [int64]$sample.working_set_bytes)
        $peakPrivate = [Math]::Max($peakPrivate, [int64]$sample.private_bytes)
        $peakCpu = [Math]::Max($peakCpu, [double]$sample.cpu_seconds)
    }

    $toDouble = {
        param($Group)
        if (-not $Group) { return $null }
        return [double]::Parse($Group.Value, $Invariant)
    }

    $startupSeconds = Get-LastRegexNumber -Text $ffc `
        -Pattern 'STARTUP TIME[^:\r\n]*:\s*(?<value>[\d.]+)s'
    if ($null -eq $startupSeconds) {
        $startupSeconds = Get-StructuredNumber $structuredStartupValues 'seconds'
    }
    $saveSeconds = Get-StructuredNumber $structuredTimingValues 'seconds'
    if ($null -eq $saveSeconds) {
        $saveSeconds = if ($save) { & $toDouble $save.Groups['seconds'] } else {
            Get-StructuredNumber $structuredSaveValues 'seconds'
        }
    }
    $payloadMiB = if ($save) { & $toDouble $save.Groups['payload'] } else {
        Get-StructuredNumber $structuredSaveValues 'logical_mib'
    }
    $mmapMiB = if ($save) { & $toDouble $save.Groups['mmap'] } else {
        Get-StructuredNumber $structuredSaveValues 'mmap_mib'
    }
    $cacheMiB = if ($save) { & $toDouble $save.Groups['cache'] } else {
        Get-StructuredNumber $structuredSaveValues 'cache_mib'
    }
    $decompressorMiB = if ($save) { & $toDouble $save.Groups['compressed'] } else {
        Get-StructuredNumber $structuredSaveValues 'decompressor_mib'
    }
    $nativeMiB = if ($save) { & $toDouble $save.Groups['native'] } else {
        Get-StructuredNumber $structuredSaveValues 'stock_mib'
    }
    $throughputMiBS = if ($save) { & $toDouble $save.Groups['throughput'] } else {
        Get-StructuredNumber $structuredSaveValues 'logical_mib_s'
    }
    $pathCalls = Get-StructuredText $structuredSaveValues 'calls'
    $pathFailures = Get-StructuredText $structuredSaveValues 'failures'
    $pathOperation = Get-StructuredText $structuredSaveValues 'path_operation_ms'
    if ($null -eq $pathOperation) {
        $pathOperation = Get-StructuredText $structuredSaveValues 'service_ms'
    }
    $mmapOperationMs = Get-SlashNumber $pathOperation 0
    $cacheOperationMs = Get-SlashNumber $pathOperation 1
    $decompressorOperationMs = Get-SlashNumber $pathOperation 2
    $nativeOperationMs = Get-SlashNumber $pathOperation 3
    $warmActiveTotalMs = 0.0
    $warmCoveredTotalMiB = 0.0
    foreach ($warmMarker in $preDispatchWarmMarkers) {
        $warmValues = Get-StructuredMarkerValues $warmMarker
        $active = Get-StructuredNumber $warmValues 'active_ms'
        $covered = Get-StructuredNumber $warmValues 'covered_mib'
        if ($null -eq $covered) { $covered = Get-StructuredNumber $warmValues 'touched_mib' }
        if ($null -ne $active) { $warmActiveTotalMs += $active }
        if ($null -ne $covered) { $warmCoveredTotalMiB += $covered }
    }
    if ($preDispatchWarmMarkers.Count -eq 0) {
        $warmActiveTotalMs = $null
        $warmCoveredTotalMiB = $null
    }
    $gameplayOperation = Get-StructuredText $structuredGameplayValues 'path_operation_ms'
    if ($null -eq $gameplayOperation) {
        $gameplayOperation = Get-StructuredText $structuredGameplayValues 'service_ms'
    }

    return [pscustomobject]@{
        performance = [pscustomobject]@{
            bench_done_found = ($null -ne $bench)
            loaded = if ($bench) { [int]$bench.Groups['loaded'].Value } else { $null }
            process_to_postload_ms = if ($bench) { & $toDouble $bench.Groups['load'] } else { $null }
            avg_fps = if ($bench) { & $toDouble $bench.Groups['fps'] } else { $null }
            frametime_ms = if ($bench) { & $toDouble $bench.Groups['frame'] } else { $null }
            frames = if ($bench) { [int64]$bench.Groups['frames'].Value } else { $null }
        }
        ffc = [pscustomobject]@{
            startup_seconds = $startupSeconds
            save_load_seconds = $saveSeconds
            payload_mib = $payloadMiB
            mmap_mib = $mmapMiB
            mmap_percent = if ($save) { & $toDouble $save.Groups['mmapPct'] } else { $null }
            cache_mib = $cacheMiB
            cache_percent = if ($save) { & $toDouble $save.Groups['cachePct'] } else { $null }
            compressed_mib = $decompressorMiB
            compressed_percent = if ($save) { & $toDouble $save.Groups['compressedPct'] } else { $null }
            native_mib = $nativeMiB
            native_percent = if ($save) { & $toDouble $save.Groups['nativePct'] } else { $null }
            throughput_mib_s = $throughputMiBS
            page_faults = Get-LastRegexNumber -Text $ffc `
                -Pattern 'SAVE LOAD PAGE FAULTS:\s*(?<value>\d+)'
            warm_mib = Get-LastRegexNumber -Text $ffc `
                -Pattern '(?:prefault|warm) complete[^\r\n]*?(?:—|committed[ =])\s*(?<value>[\d.]+)\s+M(?:i)?B'
            warm_seconds = Get-LastRegexNumber -Text $ffc `
                -Pattern '(?:prefault|warm) complete[^\r\n]*?\bin\s*(?<value>[\d.]+)s'
            warm_throughput_mib_s = Get-LastRegexNumber -Text $ffc `
                -Pattern '(?:prefault|warm) complete[^\r\n]*?\(\s*(?<value>[\d.]+)\s+M(?:i)?B/s'
            cache_compressed_share_percent = Get-StructuredNumber $structuredSaveValues `
                'cache_compressed_share_pct'
            source_mmap_mib = Get-StructuredNumber $structuredSaveValues 'source_mmap_mib'
            source_stock_mib = Get-StructuredNumber $structuredSaveValues 'source_stock_mib'
            path_calls = $pathCalls
            mmap_calls = Get-SlashNumber $pathCalls 0
            cache_calls = Get-SlashNumber $pathCalls 1
            decompressor_calls = Get-SlashNumber $pathCalls 2
            native_calls = Get-SlashNumber $pathCalls 3
            path_failures = $pathFailures
            mmap_failures = Get-SlashNumber $pathFailures 0
            cache_failures = Get-SlashNumber $pathFailures 1
            decompressor_failures = Get-SlashNumber $pathFailures 2
            native_failures = Get-SlashNumber $pathFailures 3
            path_operation_ms = $pathOperation
            mmap_operation_ms = $mmapOperationMs
            cache_operation_ms = $cacheOperationMs
            decompressor_operation_ms = $decompressorOperationMs
            native_operation_ms = $nativeOperationMs
            lookup_attempts = Get-StructuredNumber $structuredSaveValues 'lookup_attempts'
            lookup_hits = Get-StructuredNumber $structuredSaveValues 'lookup_hits'
            lookup_hit_percent = Get-StructuredNumber $structuredSaveValues 'lookup_hit_pct'
            lookup_archive_miss = Get-StructuredNumber $structuredSaveValues 'lookup_archive_miss'
            lookup_invalid_miss = Get-StructuredNumber $structuredSaveValues 'lookup_invalid_miss'
            lookup_absent = Get-StructuredNumber $structuredSaveValues 'lookup_absent'
            lookup_cold = Get-StructuredNumber $structuredSaveValues 'lookup_cold'
            cache_not_ready = Get-StructuredNumber $structuredSaveValues 'cache_not_ready'
            serve_disabled = Get-StructuredNumber $structuredSaveValues 'serve_disabled'
            cache_attachments = Get-StructuredNumber $structuredSaveValues 'attachments'
            size_mismatches = Get-StructuredNumber $structuredSaveValues 'size_mismatch'
            checksum_count = Get-StructuredNumber $structuredSaveValues 'checksum_count'
            checksum_mib = Get-StructuredNumber $structuredSaveValues 'checksum_mib'
            checksum_ms = Get-StructuredNumber $structuredSaveValues 'checksum_ms'
            checksum_failures = Get-StructuredNumber $structuredSaveValues 'checksum_failures'
            checksum_waits = Get-StructuredNumber $structuredSaveValues 'checksum_waits'
            eligible_entries = Get-StructuredText $structuredSaveValues 'eligible_entries'
            eligible_payload_mib = Get-StructuredText $structuredSaveValues 'eligible_payload_mib'
            prefault_enabled_at_load = Get-StructuredText $structuredSaveValues 'prefault_enabled'
            warm_complete_at_load = Get-StructuredText $structuredSaveValues 'warm_complete'
            during_save_load = Get-StructuredText $structuredSaveValues 'during_save_load'
            load_phase_calls = Get-StructuredText $structuredSaveValues 'load_phase_calls'
            load_phase_requested_mib = Get-StructuredText $structuredSaveValues 'load_phase_requested_mib'
            process_valid = Get-StructuredText $structuredTimingValues 'process_valid'
            load_success = Get-StructuredText $structuredTimingValues 'load_success'
            process_read_operations = Get-StructuredNumber $structuredTimingValues 'process_read_ops'
            process_read_mib = Get-StructuredNumber $structuredTimingValues 'process_read_mib'
            process_cpu_ms = Get-StructuredNumber $structuredTimingValues 'process_cpu_ms'
            timing_page_faults = Get-StructuredNumber $structuredTimingValues 'page_faults'
            working_set_before_mib = Get-StructuredNumber $structuredSaveValues 'ws_before_mib'
            working_set_after_mib = Get-StructuredNumber $structuredSaveValues 'ws_after_mib'
            private_before_mib = Get-StructuredNumber $structuredSaveValues 'private_before_mib'
            private_after_mib = Get-StructuredNumber $structuredSaveValues 'private_after_mib'
            available_ram_before_mib = Get-StructuredNumber $structuredSaveValues 'avail_ram_before_mib'
            available_ram_after_mib = Get-StructuredNumber $structuredSaveValues 'avail_ram_after_mib'
            resident_mib_after_warm = Get-StructuredNumber $warmCompleteCacheValues 'resident_mib'
            resident_pages_after_warm = Get-StructuredText $warmCompleteCacheValues 'resident_pages'
            selected_mapping_mib = Get-StructuredNumber $warmCompleteCacheValues 'mapping_mib'
            physical_cache_mib = Get-StructuredNumber $warmCompleteCacheValues 'physical_mib'
            verified_entries_after_warm = Get-StructuredText `
                $warmCompleteCacheValues 'verified_entries'
            verified_mib_after_warm = Get-StructuredNumber `
                $warmCompleteCacheValues 'verified_mib'
            warm_passes_before_autoload = $preDispatchWarmMarkers.Count
            warm_active_ms_before_autoload = $warmActiveTotalMs
            warm_covered_mib_before_autoload = $warmCoveredTotalMiB
            warm_queue_ms = Get-StructuredNumber $structuredWarmStartValues 'queue_ms'
            warm_available_start_mib = Get-StructuredNumber `
                $structuredWarmStartValues 'available_ram_mib'
            warm_available_end_mib = Get-StructuredNumber `
                $structuredWarmValues 'available_end_mib'
            autoload_condition_ms = Get-StructuredNumber $structuredAutoLoadValues 'condition_ms'
            autoload_predispatch_ms = Get-StructuredNumber $structuredAutoLoadValues 'predispatch_ms'
            autoload_settle_ms = Get-StructuredNumber $structuredAutoLoadValues 'settle_ms'
            autoload_gate_ms = Get-StructuredNumber $structuredAutoLoadValues 'gate_ms'
            autoload_checkpoint_ms = Get-StructuredNumber $structuredAutoLoadValues 'checkpoint_ms'
            autoload_post_checkpoint_ms = Get-StructuredNumber `
                $structuredAutoLoadValues 'post_checkpoint_ms'
            archive_scan_map_ms = Get-StructuredNumber $structuredInitValues 'archive_scan_map_ms'
            cache_scan_map_ms = Get-StructuredNumber $structuredInitValues 'cache_scan_map_ms'
            hook_install_ms = Get-StructuredNumber $structuredInitValues 'hook_install_ms'
            gameplay = [pscustomobject]@{
                seconds = Get-StructuredNumber $structuredGameplayValues 'seconds'
                logical_mib = Get-StructuredNumber $structuredGameplayValues 'logical_mib'
                mmap_mib = Get-StructuredNumber $structuredGameplayValues 'mmap_mib'
                cache_mib = Get-StructuredNumber $structuredGameplayValues 'cache_mib'
                decompressor_mib = Get-StructuredNumber $structuredGameplayValues 'decompressor_mib'
                stock_mib = Get-StructuredNumber $structuredGameplayValues 'stock_mib'
                source_mmap_mib = Get-StructuredNumber $structuredGameplayValues 'source_mmap_mib'
                source_stock_mib = Get-StructuredNumber $structuredGameplayValues 'source_stock_mib'
                path_calls = Get-StructuredText $structuredGameplayValues 'calls'
                path_operation_ms = $gameplayOperation
            }
            structured = [pscustomobject]@{
                startup = $structuredStartupMarker
                save_load_begin = $structuredLoadBeginMarker
                save_load_timing = $structuredTimingMarker
                save_load = $structuredSaveMarker
                gameplay = $structuredGameplayMarker
                autoload = $structuredAutoLoadMarker
                calling_load = $structuredCallingLoadMarker
                warm_start = $structuredWarmStartMarker
                warm_passes_before_autoload = @($preDispatchWarmMarkers)
                cache_states = $structuredCacheMarkers
                init_phases = $structuredInitMarker
                all_markers = $structuredMarkers
            }
        }
        process = [pscustomobject]@{
            sample_count = $ProcessSamples.Count
            peak_working_set_bytes = $peakWorking
            peak_private_bytes = $peakPrivate
            final_cpu_seconds = $peakCpu
        }
    }
}

function Get-Median {
    param([Parameter(Mandatory)][AllowEmptyCollection()][double[]]$Values)
    if ($Values.Count -eq 0) { return $null }
    $sorted = @($Values | Sort-Object)
    $middle = [int][Math]::Floor($sorted.Count / 2)
    if (($sorted.Count % 2) -eq 1) { return [double]$sorted[$middle] }
    return ([double]$sorted[$middle - 1] + [double]$sorted[$middle]) / 2.0
}

function Get-MetricSummary {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Values)
    $numbers = [System.Collections.Generic.List[double]]::new()
    foreach ($value in $Values) {
        if ($null -ne $value) { $numbers.Add([double]$value) }
    }
    if ($numbers.Count -eq 0) {
        return [pscustomobject]@{ n = 0; mean = $null; median = $null; min = $null; max = $null }
    }
    $measure = $numbers | Measure-Object -Average -Minimum -Maximum
    return [pscustomobject]@{
        n = $numbers.Count
        mean = [double]$measure.Average
        median = Get-Median -Values @($numbers)
        min = [double]$measure.Minimum
        max = [double]$measure.Maximum
    }
}

function ConvertTo-CsvRow {
    param([Parameter(Mandatory)]$Run)
    $m = $Run.metrics
    return [pscustomobject]@{
        run_id = $Run.run_id
        phase = $Run.phase
        repetition = $Run.repetition
        sequence = $Run.sequence
        arm = $Run.arm
        mod_version = $Run.mod_version
        skyrim_runtime = $Run.skyrim_runtime
        success = $Run.success
        load_driver = $Run.load_driver
        load_driver_proof_valid = $Run.load_driver_proof_valid
        legacy_marker_observed = if ($Run.load_driver -eq 'legacy_prefault_console') {
            $Run.load_driver_proof.marker_observed
        } else { $null }
        legacy_warm_before_save_load = if ($Run.load_driver -eq 'legacy_prefault_console') {
            $Run.load_driver_proof.warm_marker_before_save_load
        } else { $null }
        legacy_dispatch_utc = if ($Run.load_driver -eq 'legacy_prefault_console') {
            $Run.load_driver_proof.dispatch_utc
        } else { $null }
        legacy_marker_to_dispatch_ms = if ($Run.load_driver -eq 'legacy_prefault_console') {
            $Run.load_driver_proof.marker_to_dispatch_ms
        } else { $null }
        ffc_identity_valid = if ($Run.load_driver -eq 'ffc') {
            $Run.load_driver_proof.identity_valid
        } else { $null }
        ffc_ordering_valid = if ($Run.load_driver -eq 'ffc') {
            $Run.load_driver_proof.ordering_valid
        } else { $null }
        ffc_delay_valid = if ($Run.load_driver -eq 'ffc') {
            $Run.load_driver_proof.delay_valid
        } else { $null }
        ffc_condition_valid = if ($Run.load_driver -eq 'ffc') {
            $Run.load_driver_proof.condition_valid
        } else { $null }
        ffc_observed_delay_ms = if ($Run.load_driver -eq 'ffc') {
            $Run.load_driver_proof.observed_delay_ms
        } else { $null }
        skse_loaded_save = $Run.skse_loaded_save
        skse_save_proof_valid = $Run.skse_save_proof_valid
        wait_for_warm = $Run.wait_for_warm
        auto_load_delay_seconds = $Run.auto_load_delay_seconds
        measure_stats = $Run.measure_stats
        cache_mode = $Run.cache_mode
        prefault_enabled = $Run.prefault_enabled
        serve_enabled = $Run.serve_enabled
        serve_during_load = $Run.serve_during_load
        serving_policy = $Run.serving_policy
        comparison_limited = $Run.comparison_limited
        ffc_dll_sha256 = $Run.ffc_dll_sha256
        ffc_ini_sha256 = $Run.ffc_ini_sha256
        perf_process_to_postload_ms = $m.performance.process_to_postload_ms
        ffc_startup_seconds = $m.ffc.startup_seconds
        ffc_save_load_seconds = $m.ffc.save_load_seconds
        payload_mib = $m.ffc.payload_mib
        mmap_mib = $m.ffc.mmap_mib
        mmap_percent = $m.ffc.mmap_percent
        cache_mib = $m.ffc.cache_mib
        cache_percent = $m.ffc.cache_percent
        compressed_mib = $m.ffc.compressed_mib
        compressed_percent = $m.ffc.compressed_percent
        native_mib = $m.ffc.native_mib
        native_percent = $m.ffc.native_percent
        throughput_mib_s = $m.ffc.throughput_mib_s
        cache_compressed_share_percent = $m.ffc.cache_compressed_share_percent
        source_mmap_mib = $m.ffc.source_mmap_mib
        source_stock_mib = $m.ffc.source_stock_mib
        mmap_calls = $m.ffc.mmap_calls
        cache_calls = $m.ffc.cache_calls
        decompressor_calls = $m.ffc.decompressor_calls
        native_calls = $m.ffc.native_calls
        path_operation_ms = $m.ffc.path_operation_ms
        mmap_operation_ms = $m.ffc.mmap_operation_ms
        cache_operation_ms = $m.ffc.cache_operation_ms
        decompressor_operation_ms = $m.ffc.decompressor_operation_ms
        native_operation_ms = $m.ffc.native_operation_ms
        lookup_attempts = $m.ffc.lookup_attempts
        lookup_hits = $m.ffc.lookup_hits
        lookup_hit_percent = $m.ffc.lookup_hit_percent
        lookup_archive_miss = $m.ffc.lookup_archive_miss
        lookup_invalid_miss = $m.ffc.lookup_invalid_miss
        lookup_absent = $m.ffc.lookup_absent
        lookup_cold = $m.ffc.lookup_cold
        cache_not_ready = $m.ffc.cache_not_ready
        serve_disabled = $m.ffc.serve_disabled
        checksum_count = $m.ffc.checksum_count
        checksum_mib = $m.ffc.checksum_mib
        checksum_ms = $m.ffc.checksum_ms
        eligible_entries = $m.ffc.eligible_entries
        eligible_payload_mib = $m.ffc.eligible_payload_mib
        prefault_enabled_at_load = $m.ffc.prefault_enabled_at_load
        warm_complete_at_load = $m.ffc.warm_complete_at_load
        during_save_load = $m.ffc.during_save_load
        load_phase_calls = $m.ffc.load_phase_calls
        load_phase_requested_mib = $m.ffc.load_phase_requested_mib
        process_valid = $m.ffc.process_valid
        load_success = $m.ffc.load_success
        page_faults = $m.ffc.page_faults
        timing_page_faults = $m.ffc.timing_page_faults
        warm_mib = $m.ffc.warm_mib
        warm_seconds = $m.ffc.warm_seconds
        warm_throughput_mib_s = $m.ffc.warm_throughput_mib_s
        warm_passes_before_autoload = $m.ffc.warm_passes_before_autoload
        warm_active_ms_before_autoload = $m.ffc.warm_active_ms_before_autoload
        warm_covered_mib_before_autoload = $m.ffc.warm_covered_mib_before_autoload
        warm_queue_ms = $m.ffc.warm_queue_ms
        warm_available_start_mib = $m.ffc.warm_available_start_mib
        warm_available_end_mib = $m.ffc.warm_available_end_mib
        autoload_condition_ms = $m.ffc.autoload_condition_ms
        autoload_predispatch_ms = $m.ffc.autoload_predispatch_ms
        autoload_settle_ms = $m.ffc.autoload_settle_ms
        autoload_gate_ms = $m.ffc.autoload_gate_ms
        autoload_checkpoint_ms = $m.ffc.autoload_checkpoint_ms
        autoload_post_checkpoint_ms = $m.ffc.autoload_post_checkpoint_ms
        resident_mib_after_warm = $m.ffc.resident_mib_after_warm
        resident_pages_after_warm = $m.ffc.resident_pages_after_warm
        verified_entries_after_warm = $m.ffc.verified_entries_after_warm
        verified_mib_after_warm = $m.ffc.verified_mib_after_warm
        archive_scan_map_ms = $m.ffc.archive_scan_map_ms
        cache_scan_map_ms = $m.ffc.cache_scan_map_ms
        hook_install_ms = $m.ffc.hook_install_ms
        process_read_operations = $m.ffc.process_read_operations
        process_read_mib = $m.ffc.process_read_mib
        process_cpu_ms = $m.ffc.process_cpu_ms
        working_set_before_mib = $m.ffc.working_set_before_mib
        working_set_after_mib = $m.ffc.working_set_after_mib
        available_ram_before_mib = $m.ffc.available_ram_before_mib
        available_ram_after_mib = $m.ffc.available_ram_after_mib
        gameplay_seconds = $m.ffc.gameplay.seconds
        gameplay_logical_mib = $m.ffc.gameplay.logical_mib
        gameplay_mmap_mib = $m.ffc.gameplay.mmap_mib
        gameplay_cache_mib = $m.ffc.gameplay.cache_mib
        gameplay_decompressor_mib = $m.ffc.gameplay.decompressor_mib
        gameplay_stock_mib = $m.ffc.gameplay.stock_mib
        avg_fps = $m.performance.avg_fps
        frametime_ms = $m.performance.frametime_ms
        frames = $m.performance.frames
        peak_working_set_mib = [Math]::Round($m.process.peak_working_set_bytes / 1MB, 3)
        peak_private_mib = [Math]::Round($m.process.peak_private_bytes / 1MB, 3)
        cache_files_before = $Run.cache_before.files
        cache_bytes_before = $Run.cache_before.bytes
        cache_files_after = $Run.cache_after.files
        cache_bytes_after = $Run.cache_after.bytes
        cache_stable_by_inventory = $Run.cache_stable_by_inventory
        ffc_log = $Run.ffc_log
        performance_log = $Run.performance_log
        limitations = ($Run.limitations -join ' | ')
    }
}

# ------------------------------- Preflight -------------------------------

$manifestFullPath = Resolve-NormalPath -Path $ManifestPath -BaseDirectory $RepoRoot
if (-not (Test-Path -LiteralPath $manifestFullPath -PathType Leaf)) {
    throw "Manifest not found: $manifestFullPath"
}
$manifestDirectory = Split-Path -Parent $manifestFullPath
$manifest = Get-Content -Raw -LiteralPath $manifestFullPath | ConvertFrom-Json
if ([int]$manifest.schemaVersion -ne 1) {
    throw "Unsupported manifest schemaVersion '$($manifest.schemaVersion)'; expected 1."
}
if (-not $manifest.arms -or @($manifest.arms).Count -lt 2) {
    throw 'The A/B manifest must define at least two arms.'
}

$gameRootFull = Resolve-NormalPath -Path $GameRoot -BaseDirectory $RepoRoot
$pluginsDirectory = Join-Path $gameRootFull 'Data\SKSE\Plugins'
$loaderPath = Join-Path $gameRootFull 'skse64_loader.exe'
$installedFfcDll = Join-Path $pluginsDirectory 'FasterFileCopy.dll'
$installedFfcIni = Join-Path $pluginsDirectory 'FasterFileCopy.ini'
$installedFfcFallbackLog = Join-Path $pluginsDirectory 'FasterFileCopy.log'
$installedPerfDll = Join-Path $pluginsDirectory 'PerformanceMod.dll'
$installedPerfIni = Join-Path $pluginsDirectory 'PerformanceMod.ini'
$legacyBatchPath = Join-Path $gameRootFull 'ffcabload.txt'
$tempDirectory = [System.IO.Path]::GetTempPath()
$perfDllFull = Resolve-NormalPath -Path $PerformanceModDllPath -BaseDirectory $RepoRoot
$outputRootFull = Resolve-NormalPath -Path $OutputRoot -BaseDirectory $RepoRoot
$autonomousLoaderStates = @(Get-KnownAutonomousLoaderStates -GameRoot $gameRootFull)

foreach ($required in @($loaderPath, $perfDllFull)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required file not found: $required"
    }
}

$saveName = [string]$manifest.saveName
$skyrimRuntime = [string](Get-OptionalProperty $manifest 'skyrimRuntime' '1.6.1170')
if ([string]::IsNullOrWhiteSpace($saveName) -or
    $saveName.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0 -or
    $saveName -match '[\\/]') {
    throw "Manifest saveName is missing or unsafe: '$saveName'."
}
$documents = [Environment]::GetFolderPath([Environment+SpecialFolder]::MyDocuments)
$crashLogDirectory = Join-Path $documents 'My Games\Skyrim Special Edition\SKSE'
$saveBase = Join-Path $documents "My Games\Skyrim Special Edition\Saves\$saveName"
$saveEss = $saveBase + '.ess'
$saveSkse = $saveBase + '.skse'
if (-not (Test-Path -LiteralPath $saveEss -PathType Leaf)) {
    throw "Pinned save not found: $saveEss"
}

$repetitions = [int]($manifest.repetitions ?? 3)
$settleSeconds = [int]($manifest.settleSeconds ?? 5)
$sampleSeconds = [int]($manifest.sampleSeconds ?? 30)
$loadTimeoutSeconds = [int]($manifest.loadTimeoutSeconds ?? 240)
$runTimeoutSeconds = [int]($manifest.runTimeoutSeconds ??
    ($loadTimeoutSeconds + $settleSeconds + $sampleSeconds + 45))
$requirePopulatedCache = [bool](Get-OptionalProperty $manifest 'requirePopulatedCache' $true)
$requireStableCache = [bool](Get-OptionalProperty $manifest 'requireStableCache' $false)
if ($repetitions -lt 1 -or $settleSeconds -lt 0 -or $sampleSeconds -lt 1 -or
    $loadTimeoutSeconds -lt 30 -or $runTimeoutSeconds -le $loadTimeoutSeconds) {
    throw 'Manifest timing/repetition settings are invalid.'
}

$totalRamBytes = Get-TotalPhysicalMemoryBytes
$safeCacheMiB = [uint64][Math]::Floor(($totalRamBytes / 4.0) / 1MB)
$armNames = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$normalizedArms = [System.Collections.Generic.List[object]]::new()

foreach ($rawArm in @($manifest.arms)) {
    $name = [string]$rawArm.name
    if ($name -notmatch '^[A-Za-z0-9_.-]+$' -or -not $armNames.Add($name)) {
        throw "Arm name '$name' is empty, unsafe, or duplicated."
    }

    $rawDllPath = [string](Get-OptionalProperty $rawArm 'dllPath' '')
    $rawZipPath = [string](Get-OptionalProperty $rawArm 'zipPath' '')
    $rawZipDllEntry = [string](Get-OptionalProperty $rawArm 'zipDllEntry' '')
    $rawIniPath = [string](Get-OptionalProperty $rawArm 'iniPath' '')
    $rawZipIniEntry = [string](Get-OptionalProperty $rawArm 'zipIniEntry' '')
    $hasDll = -not [string]::IsNullOrWhiteSpace($rawDllPath)
    $hasZip = -not [string]::IsNullOrWhiteSpace($rawZipPath)
    if ($hasDll -eq $hasZip) {
        throw "Arm '$name' must specify exactly one of dllPath or zipPath."
    }
    if ($hasZip -and [string]::IsNullOrWhiteSpace($rawZipDllEntry)) {
        throw "Arm '$name' uses zipPath but has no zipDllEntry."
    }

    $loadDriver = ([string](Get-OptionalProperty $rawArm 'loadDriver' 'performance_mod')).ToLowerInvariant()
    if ($loadDriver -notin @('ffc', 'performance_mod', 'legacy_prefault_console')) {
        throw "Arm '$name' has unsupported loadDriver '$loadDriver'."
    }
    $waitForWarm = [bool](Get-OptionalProperty $rawArm 'waitForWarm' $false)
    $autoLoadDelay = [int](Get-OptionalProperty $rawArm 'autoLoadDelaySeconds' 0)
    if ($autoLoadDelay -lt 0) { throw "Arm '$name' has a negative autoLoadDelaySeconds." }
    if ($loadDriver -eq 'performance_mod' -and ($waitForWarm -or $autoLoadDelay -gt 0)) {
        throw "Arm '$name' requests wait/delay but uses the immediate PerformanceMod driver."
    }
    if ($loadDriver -eq 'legacy_prefault_console' -and -not $waitForWarm) {
        throw "Arm '$name' uses the legacy prefault driver but waitForWarm is false."
    }
    if ($loadDriver -eq 'legacy_prefault_console' -and
        $saveName -notmatch '^[A-Za-z0-9_.-]+$') {
        throw "Arm '$name' uses the legacy console driver with an unsafe save basename."
    }

    $arm = [ordered]@{
        name = $name
        modVersion = [string](Get-OptionalProperty $rawArm 'modVersion' $name)
        cacheFormat = [string](Get-OptionalProperty $rawArm 'cacheFormat' '')
        dllPath = if ($hasDll) {
            Resolve-NormalPath -Path $rawDllPath -BaseDirectory $manifestDirectory
        } else { $null }
        zipPath = if ($hasZip) {
            Resolve-NormalPath -Path $rawZipPath -BaseDirectory $manifestDirectory
        } else { $null }
        zipDllEntry = if ($hasZip) { $rawZipDllEntry } else { $null }
        iniPath = if (-not [string]::IsNullOrWhiteSpace($rawIniPath)) {
            Resolve-NormalPath -Path $rawIniPath -BaseDirectory $manifestDirectory
        } else { $null }
        zipIniEntry = if (-not [string]::IsNullOrWhiteSpace($rawZipIniEntry)) {
            $rawZipIniEntry
        } else { $null }
        iniOverrides = Get-OptionalProperty $rawArm 'iniOverrides' $null
        warmupIniOverrides = Get-OptionalProperty $rawArm 'warmupIniOverrides' $null
        effectiveCacheDir = Resolve-NormalPath -Path ([string](
            Get-OptionalProperty $rawArm 'effectiveCacheDir' '')) `
            -BaseDirectory $manifestDirectory
        zeroCacheLimitMeansAuto = [bool](Get-OptionalProperty $rawArm 'zeroCacheLimitMeansAuto' $false)
        loadDriver = $loadDriver
        waitForWarm = $waitForWarm
        autoLoadDelaySeconds = $autoLoadDelay
        warmupRuns = [int](Get-OptionalProperty $rawArm 'warmupRuns' 0)
        limitations = @((Get-OptionalProperty $rawArm 'limitations' @()) |
            ForEach-Object { [string]$_ })
    }
    if ($arm.warmupRuns -lt 0) { throw "Arm '$name' has a negative warmupRuns." }
    foreach ($source in @($arm.dllPath, $arm.zipPath, $arm.iniPath)) {
        if ($source -and -not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Arm '$name' input not found: $source"
        }
    }
    if (-not $arm.iniPath -and -not $arm.zipIniEntry) {
        throw "Arm '$name' must specify iniPath or zipIniEntry."
    }

    $armObject = [pscustomobject]$arm
    $dllBytes = Get-ArmDllBytes -Arm $armObject
    if ($dllBytes.Length -lt 65536 -or
        $dllBytes[0] -ne [byte][char]'M' -or $dllBytes[1] -ne [byte][char]'Z') {
        throw "Arm '$name' DLL source is not a plausible PE image."
    }
    $iniText = Apply-IniOverrides -Text (Get-ArmIniText -Arm $armObject) `
        -Overrides $armObject.iniOverrides
    $measureStatsOverride = if ($TimingOnly) { $false } else {
        Get-OptionalProperty $rawArm 'measureStats' $null
    }
    if ($null -ne $measureStatsOverride) {
        $iniText = Set-IniValue -Text $iniText -Section 'General' -Key 'bMeasureStats' `
            -Value $(if ([bool]$measureStatsOverride) { '1' } else { '0' })
    }
    $measureStatsText = Get-IniValue -Text $iniText -Section 'General' -Key 'bMeasureStats'
    $measureStats = $measureStatsText -notin @($null, '0', 'false', 'no')
    if ($measureStats) {
        $iniText = Set-IniValue -Text $iniText -Section 'General' `
            -Key 'iStatsIntervalSec' -Value '5'
    }
    if ($loadDriver -eq 'ffc') {
        $iniText = Set-IniValue -Text $iniText -Section 'General' `
            -Key 'sBenchmarkAutoLoadSave' -Value $saveName
        $iniText = Set-IniValue -Text $iniText -Section 'General' `
            -Key 'bBenchmarkWaitForWarm' -Value $(if ($waitForWarm) { '1' } else { '0' })
        $iniText = Set-IniValue -Text $iniText -Section 'General' `
            -Key 'iBenchmarkAutoLoadDelaySec' -Value ([string]$autoLoadDelay)
    }
    else {
        # Prevent a current DLL used with the PerformanceMod driver from also
        # dispatching the same save. Legacy DLLs simply ignore these keys.
        $iniText = Set-IniValue -Text $iniText -Section 'General' `
            -Key 'sBenchmarkAutoLoadSave' -Value ''
        $iniText = Set-IniValue -Text $iniText -Section 'General' `
            -Key 'bBenchmarkWaitForWarm' -Value '0'
        $iniText = Set-IniValue -Text $iniText -Section 'General' `
            -Key 'iBenchmarkAutoLoadDelaySec' -Value '0'
    }

    $maxText = Get-IniValue -Text $iniText -Section 'General' -Key 'iDecompCacheMaxMB'
    $maxMiB = 0L
    if ($null -eq $maxText -or -not [int64]::TryParse($maxText, [ref]$maxMiB)) {
        throw "Arm '$name' has no valid General.iDecompCacheMaxMB."
    }
    if ($maxMiB -lt 0 -or ($maxMiB -eq 0 -and -not $arm.zeroCacheLimitMeansAuto) -or
        ($maxMiB -gt 0 -and [uint64]$maxMiB -gt $safeCacheMiB)) {
        throw "Arm '$name' cache limit $maxMiB MiB violates the 25%-RAM safety policy " +
            "(safe maximum $safeCacheMiB MiB; zero-auto=$($arm.zeroCacheLimitMeansAuto))."
    }

    $configuredCacheDir = Get-IniValue -Text $iniText -Section 'General' -Key 'sCacheDir'
    $defaultCacheDir = Join-Path $pluginsDirectory 'FasterFileCopy_cache'
    $actualCacheDir = if ([string]::IsNullOrWhiteSpace($configuredCacheDir)) {
        [System.IO.Path]::GetFullPath($defaultCacheDir)
    }
    else {
        if (-not [System.IO.Path]::IsPathRooted($configuredCacheDir)) {
            throw "Arm '$name' has a relative sCacheDir, which FasterFileCopy rejects."
        }
        [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($configuredCacheDir))
    }
    if (-not $actualCacheDir.Equals([string]$arm.effectiveCacheDir,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Arm '$name' effectiveCacheDir does not match its INI. " +
            "Manifest='$($arm.effectiveCacheDir)', INI-effective='$actualCacheDir'."
    }

    if ($loadDriver -eq 'performance_mod') {
        $arm.limitations +=
            "PerformanceMod dispatches at main menu; this arm cannot prove FFC warm-ready before save load."
    }
    $arm['dllBytes'] = $dllBytes
    $arm['dllSha256'] = Get-BytesSha256 $dllBytes
    $arm['finalIniText'] = $iniText
    $arm['finalIniSha256'] = Get-BytesSha256 $Utf8NoBom.GetBytes($iniText)
    $arm['cacheLimitMiB'] = $maxMiB
    $arm['measureStats'] = $measureStats
    $arm['cacheMode'] = [int](Get-IniValue -Text $iniText -Section 'General' `
        -Key 'iDecompCacheMode')
    $decompCacheText = Get-IniValue -Text $iniText -Section 'General' `
        -Key 'bEnableDecompCache'
    $enabledText = Get-IniValue -Text $iniText -Section 'General' -Key 'bEnabled'
    $baselineText = Get-IniValue -Text $iniText -Section 'General' -Key 'bBaselineMode'
    $pluginEnabled = $null -eq $enabledText -or
        $enabledText -notin @('0', 'false', 'no')
    $baselineMode = $null -ne $baselineText -and
        $baselineText -notin @('0', 'false', 'no')
    $decompCacheEnabled = $pluginEnabled -and -not $baselineMode -and
        ($null -eq $decompCacheText -or
         $decompCacheText -notin @('0', 'false', 'no'))
    $prefaultText = Get-IniValue -Text $iniText -Section 'General' -Key 'bPrefaultDecompCache'
    $serveText = Get-IniValue -Text $iniText -Section 'General' -Key 'bServeDecompCache'
    $enableDuringText = Get-IniValue -Text $iniText -Section 'General' `
        -Key 'bEnableDuringSaveLoad'
    $serveDuringText = Get-IniValue -Text $iniText -Section 'General' `
        -Key 'bServeDecompCacheDuringLoad'
    $disableDuringText = Get-IniValue -Text $iniText -Section 'General' `
        -Key 'bDisableDecompCacheDuringLoad'
    $prefaultEnabled = if ($null -eq $prefaultText) { $null } else {
        $prefaultText -notin @('0', 'false', 'no')
    }
    $serveEnabled = if ($null -eq $serveText) { $null } else {
        $serveText -notin @('0', 'false', 'no')
    }
    if (-not $decompCacheEnabled) {
        $prefaultEnabled = $false
        $serveEnabled = $false
    }
    $serveDuringLoad = if ($serveEnabled -eq $false) { $false }
    elseif ($null -ne $enableDuringText) {
        $enableDuringText -notin @('0', 'false', 'no')
    }
    elseif ($null -ne $serveDuringText) {
        $serveDuringText -notin @('0', 'false', 'no')
    }
    elseif ($null -ne $disableDuringText) {
        $disableDuringText -in @('0', 'false', 'no')
    }
    else { $serveEnabled }
    $arm['prefaultEnabled'] = $prefaultEnabled
    $arm['baselineMode'] = $baselineMode
    $arm['decompCacheEnabled'] = $decompCacheEnabled
    $arm['serveEnabled'] = $serveEnabled
    $arm['serveDuringLoad'] = $serveDuringLoad
    $arm['servingPolicy'] = if ($serveEnabled -eq $false) { 'never' }
        elseif ($serveDuringLoad -eq $false) { 'suppress_during_load' }
        elseif ($serveEnabled -eq $true) { 'throughout' }
        else { 'legacy_unspecified' }
    $normalizedArms.Add([pscustomobject]$arm)
}


for ($i = 0; $i -lt $normalizedArms.Count; ++$i) {
    for ($j = $i + 1; $j -lt $normalizedArms.Count; ++$j) {
        $left = $normalizedArms[$i]
        $right = $normalizedArms[$j]
        if ($left.cacheFormat -and $right.cacheFormat -and
            $left.cacheFormat -ne $right.cacheFormat -and
            ([string]$left.effectiveCacheDir).Equals([string]$right.effectiveCacheDir,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Arms '$($left.name)' ($($left.cacheFormat)) and '$($right.name)' " +
                "($($right.cacheFormat)) cannot share cache directory '$($left.effectiveCacheDir)'."
        }
    }
}

$usesLegacyPrefaultDriver = @($normalizedArms | Where-Object {
    $_.loadDriver -eq 'legacy_prefault_console'
}).Count -gt 0
$mutationTargets = @(
    $installedFfcDll, $installedFfcIni, $installedPerfDll, $installedPerfIni
)
if ($usesLegacyPrefaultDriver) { $mutationTargets += $legacyBatchPath }

$schedule = [System.Collections.Generic.List[object]]::new()
$sequence = 0
foreach ($arm in $normalizedArms) {
    for ($i = 1; $i -le $arm.warmupRuns; ++$i) {
        ++$sequence
        $schedule.Add([pscustomobject]@{
            sequence = $sequence; phase = 'warmup'; repetition = $i; arm = $arm.name
        })
    }
}
for ($rep = 1; $rep -le $repetitions; ++$rep) {
    $order = if (($rep % 2) -eq 1) { @($normalizedArms) } else { @($normalizedArms)[-1..-$normalizedArms.Count] }
    foreach ($arm in $order) {
        ++$sequence
        $schedule.Add([pscustomobject]@{
            sequence = $sequence; phase = 'measured'; repetition = $rep; arm = $arm.name
        })
    }
}

$plan = [ordered]@{
    mode = if ($Execute) { 'execute' } else { 'plan-only' }
    timing_only = [bool]$TimingOnly
    manifest = $manifestFullPath
    skyrim_runtime = $skyrimRuntime
    game_root = $gameRootFull
    loader = $loaderPath
    performance_mod_dll = $perfDllFull
    performance_mod_sha256 = Get-Sha256 $perfDllFull
    pinned_save = $saveEss
    total_physical_ram_bytes = $totalRamBytes
    maximum_cache_mib_25_percent = $safeCacheMiB
    output_root = $outputRootFull
    arms = @($normalizedArms | ForEach-Object {
        [pscustomobject]@{
            name = $_.name
            mod_version = $_.modVersion
            cache_format = $_.cacheFormat
            dll_sha256 = $_.dllSha256
            ini_sha256 = $_.finalIniSha256
            cache_limit_mib = $_.cacheLimitMiB
            measured_cache_mode = $_.cacheMode
            effective_cache_dir = $_.effectiveCacheDir
            load_driver = $_.loadDriver
            wait_for_warm = $_.waitForWarm
            auto_load_delay_seconds = $_.autoLoadDelaySeconds
            measure_stats = $_.measureStats
            prefault_enabled = $_.prefaultEnabled
            serving_policy = $_.servingPolicy
            limitations = $_.limitations
        }
    })
    schedule = @($schedule)
    mutations_when_executed = @($mutationTargets)
    cache_policy = 'Inventory only. No cache file or directory is deleted, truncated, renamed, or moved.'
    require_populated_cache_for_measured_runs = $requirePopulatedCache
    require_stable_cache_for_measured_runs = $requireStableCache
    autonomous_loader_preflight = @($autonomousLoaderStates)
}

if (-not $Execute) {
    $plan | ConvertTo-Json -Depth 8
    return
}

Assert-NoKnownAutonomousLoaders -States $autonomousLoaderStates

# ------------------------------ Transaction ------------------------------

$lockAcquired = $false
$launchedAny = $false
$snapshotStates = [System.Collections.Generic.List[object]]::new()
$results = [System.Collections.Generic.List[object]]::new()
$restoreAudit = @()
$ownedProcesses = @{}
$trackedStatePaths = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$fatalError = $null
$sessionDirectory = $null
$snapshotDirectory = $null
$intent = "FasterFileCopy instrumented A/B: $([System.IO.Path]::GetFileName($manifestFullPath))"

try {
    Write-Host (Invoke-LockCtl -Action acquire -Intent $intent)
    $lockAcquired = $true
    Update-TestbedLockHeartbeat -Intent $intent
    Assert-NoSharedGameProcess

    $sessionId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + "-$PID"
    $sessionDirectory = Join-Path $outputRootFull $sessionId
    $snapshotDirectory = Join-Path $sessionDirectory 'original-state'
    New-Item -ItemType Directory -Path $snapshotDirectory -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $sessionDirectory 'plan.json'),
        ($plan | ConvertTo-Json -Depth 10), $Utf8NoBom)

    $ffcLogs = @(Get-LogCandidates -Name 'FasterFileCopy' `
        -AdditionalPaths @($installedFfcFallbackLog))
    $ffcLogInitBreadcrumbs = @($ffcLogs | ForEach-Object {
        Join-Path (Split-Path -Parent $_) 'FasterFileCopy_loginit.txt'
    } | Select-Object -Unique)
    $perfLogs = @(Get-LogCandidates -Name 'PerformanceMod')
    $skseLogs = @(Get-LogCandidates -Name 'skse64')
    $initialTempFallbackLogs = @(
        Get-ChildItem -LiteralPath $tempDirectory `
            -Filter 'FasterFileCopy_fallback_*.log' -File `
            -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
    )
    $stateTargets = [ordered]@{
        ffc_dll = $installedFfcDll
        ffc_ini = $installedFfcIni
        performance_mod_dll = $installedPerfDll
        performance_mod_ini = $installedPerfIni
        save_ess = $saveEss
    }
    # Track the SKSE co-save even when initially absent, so a co-save created by
    # the harness is removed during restoration rather than leaking test state.
    $stateTargets['save_skse'] = $saveSkse
    if ($usesLegacyPrefaultDriver) {
        $stateTargets['legacy_console_batch'] = $legacyBatchPath
    }
    for ($i = 0; $i -lt $ffcLogs.Count; ++$i) { $stateTargets["ffc_log_$i"] = $ffcLogs[$i] }
    for ($i = 0; $i -lt $ffcLogInitBreadcrumbs.Count; ++$i) {
        $stateTargets["ffc_loginit_$i"] = $ffcLogInitBreadcrumbs[$i]
    }
    for ($i = 0; $i -lt $initialTempFallbackLogs.Count; ++$i) {
        $stateTargets["ffc_temp_fallback_$i"] = $initialTempFallbackLogs[$i]
    }
    for ($i = 0; $i -lt $perfLogs.Count; ++$i) { $stateTargets["perf_log_$i"] = $perfLogs[$i] }
    for ($i = 0; $i -lt $skseLogs.Count; ++$i) { $stateTargets["skse_log_$i"] = $skseLogs[$i] }
    foreach ($entry in $stateTargets.GetEnumerator()) {
        $statePath = [string]$entry.Value
        if ([string]::IsNullOrWhiteSpace($statePath)) {
            throw "Transaction state target '$($entry.Key)' has no usable path."
        }
        $state = Save-FileState -Path $statePath `
            -SnapshotDirectory $snapshotDirectory -Label $entry.Key
        $snapshotStates.Add($state)
        [void]$trackedStatePaths.Add([System.IO.Path]::GetFullPath(
            $statePath))
    }
    [System.IO.File]::WriteAllText((Join-Path $snapshotDirectory 'state.json'),
        ($snapshotStates | ConvertTo-Json -Depth 6), $Utf8NoBom)

    foreach ($scheduled in $schedule) {
        Update-TestbedLockHeartbeat -Intent $intent
        Assert-NoSharedGameProcess
        $arm = $normalizedArms | Where-Object name -eq $scheduled.arm | Select-Object -First 1
        if (-not $arm) { throw "Internal error: scheduled arm '$($scheduled.arm)' not found." }

        $runId = '{0:D2}-{1}-r{2}-{3}' -f $scheduled.sequence, $scheduled.phase,
            $scheduled.repetition, $arm.name
        $runDirectory = Join-Path $sessionDirectory $runId
        New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
        $legacyDriverRequired = $arm.loadDriver -eq 'legacy_prefault_console'
        $ffcDriverRequired = $arm.loadDriver -eq 'ffc'
        $legacyDriverState = if ($legacyDriverRequired) {
            [ordered]@{
                driver = 'legacy_prefault_console'
                exact_save = $saveName
                batch_path = $legacyBatchPath
                batch_sha256 = $null
                warm_marker = 'DecompCache prefault complete'
                marker_observed = $false
                marker_observed_utc = $null
                marker_log_path = $null
                marker_line_number = $null
                marker_line = $null
                post_marker_delay_seconds = $arm.autoLoadDelaySeconds
                dispatch_attempted = $false
                dispatched = $false
                dispatch_utc = $null
                marker_to_dispatch_ms = $null
                command = $null
                window_handle = $null
                warm_marker_before_save_load = $false
                proof_error = $null
            }
        } else { $null }

        # Deploy from transaction-owned copies, then hash what was actually installed.
        $runIniText = $arm.finalIniText
        if ($scheduled.phase -eq 'warmup' -and $arm.warmupIniOverrides) {
            $runIniText = Apply-IniOverrides -Text $runIniText `
                -Overrides $arm.warmupIniOverrides
        }
        $runIniText = Set-IniValue -Text $runIniText -Section 'General' `
            -Key 'sBenchmarkRunTag' -Value $runId
        $runCacheMode = [int](Get-IniValue -Text $runIniText -Section 'General' `
            -Key 'iDecompCacheMode')
        $runIniSha256 = Get-BytesSha256 $Utf8NoBom.GetBytes($runIniText)
        [System.IO.File]::WriteAllBytes((Join-Path $runDirectory 'deployed-FasterFileCopy.dll'), $arm.dllBytes)
        [System.IO.File]::WriteAllText((Join-Path $runDirectory 'deployed-FasterFileCopy.ini'),
            $runIniText, $Utf8NoBom)
        Copy-Item -LiteralPath (Join-Path $runDirectory 'deployed-FasterFileCopy.dll') `
            -Destination $installedFfcDll -Force
        Copy-Item -LiteralPath (Join-Path $runDirectory 'deployed-FasterFileCopy.ini') `
            -Destination $installedFfcIni -Force
        Copy-Item -LiteralPath $perfDllFull -Destination $installedPerfDll -Force

        $perfAutoLoad = $arm.loadDriver -eq 'performance_mod'
        $perfIniText = New-PerformanceModIni -AutoLoad $perfAutoLoad -SaveName $saveName `
            -SettleSeconds $settleSeconds -SampleSeconds $sampleSeconds `
            -LoadTimeoutSeconds $loadTimeoutSeconds
        [System.IO.File]::WriteAllText($installedPerfIni, $perfIniText, $Utf8NoBom)
        [System.IO.File]::WriteAllText((Join-Path $runDirectory 'deployed-PerformanceMod.ini'),
            $perfIniText, $Utf8NoBom)

        $legacyBatchSha256 = $null
        if ($legacyDriverRequired) {
            $batchText = "load $saveName`r`n"
            $deployedBatch = Join-Path $runDirectory 'deployed-ffcabload.txt'
            [System.IO.File]::WriteAllText($deployedBatch, $batchText, $Utf8NoBom)
            Copy-Item -LiteralPath $deployedBatch -Destination $legacyBatchPath -Force
            $legacyBatchSha256 = Get-Sha256 $deployedBatch
            $legacyDriverState.batch_sha256 = $legacyBatchSha256
        }

        if ((Get-Sha256 $installedFfcDll) -ne $arm.dllSha256 -or
            (Get-Sha256 $installedFfcIni) -ne $runIniSha256 -or
            (Get-Sha256 $installedPerfDll) -ne (Get-Sha256 $perfDllFull) -or
            ($legacyDriverRequired -and
             (Get-Sha256 $legacyBatchPath) -ne $legacyBatchSha256)) {
            throw "Deployment hash verification failed for run '$runId'."
        }

        # Discover transaction-created %TEMP% fallback logs from an earlier arm
        # before clearing them. Paths absent at suite start are registered for
        # deletion during final restoration.
        $currentTempFallbackLogs = @(
            Get-ChildItem -LiteralPath $tempDirectory `
                -Filter 'FasterFileCopy_fallback_*.log' -File `
                -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
        )
        foreach ($tempLog in $currentTempFallbackLogs) {
            $fullTempLog = [System.IO.Path]::GetFullPath($tempLog)
            if ($trackedStatePaths.Add($fullTempLog)) {
                $label = 'ffc_temp_created_' + $snapshotStates.Count
                $snapshotStates.Add((New-AbsentFileState `
                    -Path $fullTempLog -Label $label))
            }
        }

        # Clear only transaction-tracked log/breadcrumb files, never a cache
        # path. This prevents stale BENCH_DONE or fallback evidence from
        # satisfying the current run.
        foreach ($logPath in @($ffcLogs + $ffcLogInitBreadcrumbs +
                $perfLogs + $skseLogs + $currentTempFallbackLogs)) {
            if (Test-Path -LiteralPath $logPath -PathType Leaf) {
                Remove-Item -LiteralPath $logPath -Force
            }
        }

        $cacheBefore = Get-CacheInventory -Path $arm.effectiveCacheDir
        if ($scheduled.phase -eq 'measured' -and $requirePopulatedCache -and
            ($cacheBefore.files -le 0 -or $cacheBefore.bytes -le 0)) {
            throw "Measured run '$runId' cache is not populated: $($arm.effectiveCacheDir)"
        }
        $crashPathsBefore = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
        if (Test-Path -LiteralPath $crashLogDirectory -PathType Container) {
            Get-ChildItem -LiteralPath $crashLogDirectory `
                -Filter 'crash-*.log' -File -ErrorAction SilentlyContinue |
                ForEach-Object { [void]$crashPathsBefore.Add($_.FullName) }
        }
        $startedUtc = [DateTimeOffset]::UtcNow
        Write-Host "[$runId] launching $($arm.name) ($($arm.loadDriver), waitWarm=$($arm.waitForWarm))"
        $launcher = Start-Process -FilePath $loaderPath -WorkingDirectory $gameRootFull -PassThru `
            -WindowStyle Normal
        Register-OwnedProcess -Registry $ownedProcesses -Process $launcher
        $launchedAny = $true
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds($runTimeoutSeconds)
        $samples = [System.Collections.Generic.List[object]]::new()
        $benchDone = $false
        $gameSeen = $false
        $lastHeartbeat = [DateTimeOffset]::MinValue

        while ([DateTimeOffset]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 500
            $now = [DateTimeOffset]::UtcNow
            if (($now - $lastHeartbeat).TotalSeconds -ge 10) {
                Update-TestbedLockHeartbeat -Intent $intent
                $lastHeartbeat = $now
            }

            $games = @(Get-Process -Name 'SkyrimSE' -ErrorAction SilentlyContinue)
            if ($games.Count -gt 0) { $gameSeen = $true }
            foreach ($game in $games) {
                Register-OwnedProcess -Registry $ownedProcesses -Process $game
                try {
                    $samples.Add([pscustomobject]@{
                        timestamp_utc = $now.ToString('O')
                        elapsed_seconds = ($now - $startedUtc).TotalSeconds
                        pid = $game.Id
                        working_set_bytes = $game.WorkingSet64
                        private_bytes = $game.PrivateMemorySize64
                        peak_working_set_bytes = $game.PeakWorkingSet64
                        cpu_seconds = $game.TotalProcessorTime.TotalSeconds
                        thread_count = $game.Threads.Count
                        handle_count = $game.HandleCount
                    })
                }
                catch {
                    # Process exited between enumeration and sampling.
                }
            }

            if ($legacyDriverRequired -and
                -not $legacyDriverState.dispatch_attempted -and
                $games.Count -gt 0) {
                $markerHit = $null
                $markerLog = $null
                foreach ($candidate in $ffcLogs) {
                    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
                    $hit = Select-String -LiteralPath $candidate `
                        -Pattern 'DecompCache prefault complete' -SimpleMatch `
                        -ErrorAction SilentlyContinue | Select-Object -Last 1
                    if ($hit) {
                        $markerHit = $hit
                        $markerLog = $candidate
                        break
                    }
                }
                if ($markerHit) {
                    $legacyDriverState.marker_observed = $true
                    $legacyDriverState.marker_observed_utc =
                        [DateTimeOffset]::UtcNow.ToString('O')
                    $legacyDriverState.marker_log_path = $markerLog
                    $legacyDriverState.marker_line_number = $markerHit.LineNumber
                    $legacyDriverState.marker_line = $markerHit.Line
                    $legacyDriverState.dispatch_attempted = $true
                    Write-Host "[$runId] legacy prefault complete; waiting $($arm.autoLoadDelaySeconds)s then loading exact pinned save"
                    try {
                        $dispatch = Invoke-LegacyPrefaultConsoleLoad `
                            -GameProcess $games[0] `
                            -PostMarkerDelaySeconds $arm.autoLoadDelaySeconds
                        $legacyDriverState.dispatched = $true
                        $legacyDriverState.dispatch_utc = $dispatch.dispatched_utc
                        $legacyDriverState.marker_to_dispatch_ms =
                            ([DateTimeOffset]::Parse($dispatch.dispatched_utc) -
                             [DateTimeOffset]::Parse(
                                $legacyDriverState.marker_observed_utc)).TotalMilliseconds
                        $legacyDriverState.command = $dispatch.command
                        $legacyDriverState.window_handle = $dispatch.window_handle
                    }
                    catch {
                        $legacyDriverState.proof_error = $_.Exception.Message
                        [System.IO.File]::WriteAllText(
                            (Join-Path $runDirectory 'legacy-load-driver.json'),
                            ($legacyDriverState | ConvertTo-Json -Depth 6), $Utf8NoBom)
                        throw
                    }
                    [System.IO.File]::WriteAllText(
                        (Join-Path $runDirectory 'legacy-load-driver.json'),
                        ($legacyDriverState | ConvertTo-Json -Depth 6), $Utf8NoBom)
                }
            }

            foreach ($candidate in $perfLogs) {
                if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
                if (Select-String -LiteralPath $candidate -Pattern 'BENCH_DONE:' `
                        -SimpleMatch -Quiet -ErrorAction SilentlyContinue) {
                    $benchDone = $true
                    break
                }
            }
            if ($benchDone) { break }
            if ($gameSeen -and $games.Count -eq 0 -and $now -gt $startedUtc.AddSeconds(30)) { break }
        }

        # BENCH_DONE is flushed immediately before ExitProcess. Give the process
        # a short grace period, then terminate only this transaction's game.
        $exitDeadline = [DateTimeOffset]::UtcNow.AddSeconds(15)
        while ((Get-Process -Name 'SkyrimSE' -ErrorAction SilentlyContinue) -and
               [DateTimeOffset]::UtcNow -lt $exitDeadline) {
            Start-Sleep -Milliseconds 250
        }
        $ownedSurvivors = @($ownedProcesses.Keys | Where-Object {
            Get-Process -Id ([int]$_) -ErrorAction SilentlyContinue
        })
        if ($ownedSurvivors.Count -gt 0) {
            Stop-OwnedProcesses -Registry $ownedProcesses
            Start-Sleep -Milliseconds 500
        }
        $runFinishedUtc = [DateTimeOffset]::UtcNow

        $runTempFallbackLogs = @(
            Get-ChildItem -LiteralPath $tempDirectory `
                -Filter 'FasterFileCopy_fallback_*.log' -File `
                -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
        )
        foreach ($tempLog in $runTempFallbackLogs) {
            $fullTempLog = [System.IO.Path]::GetFullPath($tempLog)
            if ($trackedStatePaths.Add($fullTempLog)) {
                $label = 'ffc_temp_created_' + $snapshotStates.Count
                $snapshotStates.Add((New-AbsentFileState `
                    -Path $fullTempLog -Label $label))
            }
        }
        [System.IO.File]::WriteAllText((Join-Path $snapshotDirectory 'state.json'),
            ($snapshotStates | ConvertTo-Json -Depth 6), $Utf8NoBom)

        $archivedFfc = [System.Collections.Generic.List[string]]::new()
        $archivedFfcBreadcrumbs = [System.Collections.Generic.List[string]]::new()
        $archivedPerf = [System.Collections.Generic.List[string]]::new()
        $archivedSkse = [System.Collections.Generic.List[string]]::new()
        $archivedCrash = [System.Collections.Generic.List[string]]::new()
        $runFfcLogs = @($ffcLogs + $runTempFallbackLogs | Select-Object -Unique)
        for ($i = 0; $i -lt $runFfcLogs.Count; ++$i) {
            if (Test-Path -LiteralPath $runFfcLogs[$i] -PathType Leaf) {
                $destination = Join-Path $runDirectory "FasterFileCopy-location-$i.log"
                Copy-Item -LiteralPath $runFfcLogs[$i] -Destination $destination -Force
                $archivedFfc.Add($destination)
            }
        }
        for ($i = 0; $i -lt $ffcLogInitBreadcrumbs.Count; ++$i) {
            if (Test-Path -LiteralPath $ffcLogInitBreadcrumbs[$i] -PathType Leaf) {
                $destination = Join-Path $runDirectory `
                    "FasterFileCopy-loginit-location-$i.txt"
                Copy-Item -LiteralPath $ffcLogInitBreadcrumbs[$i] `
                    -Destination $destination -Force
                $archivedFfcBreadcrumbs.Add($destination)
            }
        }
        for ($i = 0; $i -lt $perfLogs.Count; ++$i) {
            if (Test-Path -LiteralPath $perfLogs[$i] -PathType Leaf) {
                $destination = Join-Path $runDirectory "PerformanceMod-location-$i.log"
                Copy-Item -LiteralPath $perfLogs[$i] -Destination $destination -Force
                $archivedPerf.Add($destination)
            }
        }
        for ($i = 0; $i -lt $skseLogs.Count; ++$i) {
            if (Test-Path -LiteralPath $skseLogs[$i] -PathType Leaf) {
                $destination = Join-Path $runDirectory "skse64-location-$i.log"
                Copy-Item -LiteralPath $skseLogs[$i] -Destination $destination -Force
                $archivedSkse.Add($destination)
            }
        }
        if (Test-Path -LiteralPath $crashLogDirectory -PathType Container) {
            $recentCrashLogs = @(Get-ChildItem -LiteralPath $crashLogDirectory `
                -Filter 'crash-*.log' -File -ErrorAction SilentlyContinue | Where-Object {
                    -not $crashPathsBefore.Contains($_.FullName) -and
                    $_.LastWriteTimeUtc -ge $startedUtc.UtcDateTime.AddSeconds(-2) -and
                    $_.LastWriteTimeUtc -le $runFinishedUtc.UtcDateTime.AddSeconds(2)
                } | Sort-Object LastWriteTimeUtc)
            for ($i = 0; $i -lt $recentCrashLogs.Count; ++$i) {
                $destination = Join-Path $runDirectory `
                    ("crash-{0:D2}-{1}" -f $i, $recentCrashLogs[$i].Name)
                Copy-Item -LiteralPath $recentCrashLogs[$i].FullName `
                    -Destination $destination -Force
                $archivedCrash.Add($destination)
            }
        }
        [System.IO.File]::WriteAllText((Join-Path $runDirectory 'process-samples.json'),
            ($samples | ConvertTo-Json -Depth 5), $Utf8NoBom)

        $primaryFfc = $archivedFfc | Sort-Object { (Get-Item -LiteralPath $_).Length } -Descending |
            Select-Object -First 1
        $primaryPerf = $archivedPerf | Sort-Object { (Get-Item -LiteralPath $_).Length } -Descending |
            Select-Object -First 1
        $primarySkse = $archivedSkse | Sort-Object { (Get-Item -LiteralPath $_).Length } -Descending |
            Select-Object -First 1
        if (-not $primaryFfc) { $primaryFfc = Join-Path $runDirectory 'missing-FasterFileCopy.log' }
        if (-not $primaryPerf) { $primaryPerf = Join-Path $runDirectory 'missing-PerformanceMod.log' }
        if (-not $primarySkse) { $primarySkse = Join-Path $runDirectory 'missing-skse64.log' }
        $skseLoadedSave = $null
        $skseLoadEventCount = 0
        $skseLoadEvents = @()
        if (Test-Path -LiteralPath $primarySkse -PathType Leaf) {
            $skseText = Get-Content -LiteralPath $primarySkse -Raw
            $skseLoadEvents = @(Get-SkseLoadEvents -Text $skseText)
            $skseLoadEventCount = $skseLoadEvents.Count
            if ($skseLoadEvents.Count -gt 0) {
                $skseLoadedSave = $skseLoadEvents[$skseLoadEvents.Count - 1].save
            }
        }
        $skseSaveProof = [bool]($skseLoadEventCount -eq 1 -and
            $skseLoadedSave -ceq $saveName)
        $legacyDriverProof = -not $legacyDriverRequired
        $legacyDriverProofPath = $null
        if ($legacyDriverRequired) {
            $warmLine = $null
            $saveStartLine = $null
            if (Test-Path -LiteralPath $primaryFfc -PathType Leaf) {
                $warmLine = Select-String -LiteralPath $primaryFfc `
                    -Pattern 'DecompCache prefault complete' -SimpleMatch `
                    -ErrorAction SilentlyContinue | Select-Object -Last 1
                $saveStartLine = Select-String -LiteralPath $primaryFfc `
                    -Pattern 'Save load started' -SimpleMatch `
                    -ErrorAction SilentlyContinue | Select-Object -First 1
            }
            $legacyDriverState.warm_marker_before_save_load = [bool](
                $warmLine -and $saveStartLine -and
                $warmLine.LineNumber -lt $saveStartLine.LineNumber)
            $legacyDriverProof = [bool](
                $legacyDriverState.marker_observed -and
                $legacyDriverState.dispatched -and
                $legacyDriverState.warm_marker_before_save_load)
            if (-not $legacyDriverProof -and -not $legacyDriverState.proof_error) {
                $legacyDriverState.proof_error =
                    'Missing proof that prefault completed before kPreLoadGame.'
            }
            $legacyDriverProofPath = Join-Path $runDirectory 'legacy-load-driver.json'
            [System.IO.File]::WriteAllText($legacyDriverProofPath,
                ($legacyDriverState | ConvertTo-Json -Depth 6), $Utf8NoBom)
        }
        $metrics = Parse-RunMetrics -FfcLogPath $primaryFfc -PerformanceLogPath $primaryPerf `
            -ProcessSamples @($samples)
        $ffcDriverProof = -not $ffcDriverRequired
        $ffcDriverProofPath = $null
        $ffcDriverState = $null
        if ($ffcDriverRequired) {
            $allMarkers = @($metrics.ffc.structured.all_markers)
            $dispatchMarkers = @($allMarkers | Where-Object {
                $_.line -match 'BENCH\s+AUTOLOAD\b' -and
                (Get-StructuredText $_.values 'status') -eq 'dispatching' -and
                (Get-StructuredText $_.values 'run') -eq $runId
            })
            $callingMarkers = @($allMarkers | Where-Object {
                $_.line -match 'BENCH\s+AUTOLOAD\b' -and
                (Get-StructuredText $_.values 'status') -eq 'calling_load' -and
                (Get-StructuredText $_.values 'run') -eq $runId
            })
            $beginMarkers = @($allMarkers | Where-Object {
                $_.line -match 'BENCH\s+SAVE_LOAD_BEGIN\b' -and
                (Get-StructuredText $_.values 'run') -eq $runId
            })
            $timingMarkers = @($allMarkers | Where-Object {
                $_.line -match 'BENCH\s+SAVE_LOAD_TIMING\b' -and
                (Get-StructuredText $_.values 'run') -eq $runId
            })
            $preAutoloadMarkers = @($allMarkers | Where-Object {
                $_.line -match 'BENCH\s+CACHE_STATE\b' -and
                (Get-StructuredText $_.values 'event') -eq 'pre_autoload' -and
                (Get-StructuredText $_.values 'run') -eq $runId
            })
            $dispatchMarker = $dispatchMarkers | Select-Object -First 1
            $callingMarker = $callingMarkers | Select-Object -First 1
            $beginMarker = $beginMarkers | Select-Object -First 1
            $timingMarker = $timingMarkers | Select-Object -First 1
            $preAutoloadMarker = $preAutoloadMarkers | Select-Object -First 1
            $dispatchValues = Get-StructuredMarkerValues $dispatchMarker
            $callingValues = Get-StructuredMarkerValues $callingMarker
            $beginValues = Get-StructuredMarkerValues $beginMarker
            $timingValues = Get-StructuredMarkerValues $timingMarker
            $preAutoloadValues = Get-StructuredMarkerValues $preAutoloadMarker
            $conditionMs = Get-StructuredNumber $dispatchValues 'condition_ms'
            $predispatchMs = Get-StructuredNumber $dispatchValues 'predispatch_ms'
            $settleMs = Get-StructuredNumber $dispatchValues 'settle_ms'
            $gateMs = Get-StructuredNumber $dispatchValues 'gate_ms'
            $checkpointMs = Get-StructuredNumber $dispatchValues 'checkpoint_ms'
            $postCheckpointMs = Get-StructuredNumber `
                $dispatchValues 'post_checkpoint_ms'
            $postCheckpointTargetMs = Get-StructuredNumber `
                $dispatchValues 'post_checkpoint_target_ms'
            # settle_ms is the configured post-readiness interval. Residency is
            # measured after it; post_checkpoint_ms is a separate fixed quiet
            # period that keeps checkpoint work away from the measured load.
            $observedDelayMs = $settleMs
            $delayAccountingErrorMs = if ($null -ne $conditionMs -and
                                          $null -ne $predispatchMs -and
                                          $null -ne $settleMs -and
                                          $null -ne $gateMs -and
                                          $null -ne $checkpointMs -and
                                          $null -ne $postCheckpointMs) {
                $predispatchMs - ($conditionMs + $settleMs + $gateMs +
                    $checkpointMs + $postCheckpointMs)
            } else { $null }
            $delayAccountingValid = [bool](
                $null -ne $delayAccountingErrorMs -and
                [Math]::Abs($delayAccountingErrorMs) -le 0.1)
            $expectedPreAutoload = [bool]$arm.decompCacheEnabled
            $expectedWarmComplete = [bool]($arm.waitForWarm -and
                $arm.prefaultEnabled -and $arm.decompCacheEnabled)
            $expectedWaitText = if ($arm.waitForWarm) { 'true' } else { 'false' }
            $expectedPrefaultText = if ($arm.prefaultEnabled) { 'true' } else { 'false' }
            $residentPagesText = Get-StructuredText $preAutoloadValues 'resident_pages'
            $residentPages = Get-SlashNumber $residentPagesText 0
            $totalPages = Get-SlashNumber $residentPagesText 1
            $verifiedEntriesText = Get-StructuredText `
                $preAutoloadValues 'verified_entries'
            $verifiedEntries = Get-SlashNumber $verifiedEntriesText 0
            $totalEntries = Get-SlashNumber $verifiedEntriesText 1
            $markerCountsValid = [bool](
                $dispatchMarkers.Count -eq 1 -and
                $callingMarkers.Count -eq 1 -and
                $beginMarkers.Count -eq 1 -and
                $timingMarkers.Count -eq 1 -and
                ((-not $expectedPreAutoload -and $preAutoloadMarkers.Count -eq 0) -or
                 ($expectedPreAutoload -and $preAutoloadMarkers.Count -eq 1)))
            $prefaultStateValid = [bool](
                -not $expectedPreAutoload -or
                ((Get-StructuredText $preAutoloadValues 'prefault_enabled') -eq
                    $expectedPrefaultText -and
                 ($arm.prefaultEnabled -or
                  (Get-StructuredText $preAutoloadValues 'warm_complete') -eq 'false')))
            $warmStateValid = [bool](
                -not $expectedWarmComplete -or
                (Get-StructuredText $preAutoloadValues 'warm_complete') -eq 'true')
            $residencyValid = [bool](
                -not $expectedWarmComplete -or
                ((Get-StructuredText $preAutoloadValues 'residency_measured') -eq 'true' -and
                 $null -ne $residentPages -and $null -ne $totalPages -and
                 $totalPages -gt 0 -and $residentPages -eq $totalPages))
            $verificationValid = [bool](
                -not $expectedWarmComplete -or
                ($null -ne $verifiedEntries -and $null -ne $totalEntries -and
                 $totalEntries -gt 0 -and $verifiedEntries -eq $totalEntries))
            $identityValid = [bool](
                $markerCountsValid -and
                (Get-StructuredText $dispatchValues 'run') -eq $runId -and
                (Get-StructuredText $dispatchValues 'save') -eq $saveName -and
                (Get-StructuredText $callingValues 'run') -eq $runId -and
                (Get-StructuredText $callingValues 'save') -eq $saveName -and
                (Get-StructuredText $beginValues 'run') -eq $runId -and
                (Get-StructuredText $beginValues 'requested_save') -eq $saveName -and
                (Get-StructuredText $timingValues 'run') -eq $runId)
            $orderingValid = [bool](
                $markerCountsValid -and
                $dispatchMarker.line_number -lt $callingMarker.line_number -and
                $callingMarker.line_number -lt $beginMarker.line_number -and
                $beginMarker.line_number -lt $timingMarker.line_number -and
                (-not $expectedPreAutoload -or
                    ($preAutoloadMarker -and
                     $preAutoloadMarker.line_number -lt $dispatchMarker.line_number)))
            $delayValid = [bool](
                $null -ne $observedDelayMs -and
                (Get-StructuredNumber $dispatchValues 'settle_s') -eq
                    $arm.autoLoadDelaySeconds -and
                $observedDelayMs -ge ($arm.autoLoadDelaySeconds * 1000.0 - 25.0) -and
                $observedDelayMs -le ($arm.autoLoadDelaySeconds * 1000.0 + 1000.0) -and
                $postCheckpointTargetMs -eq 250.0 -and
                $postCheckpointMs -ge 249.0 -and
                $postCheckpointMs -le 1250.0 -and
                $delayAccountingValid)
            $conditionValid = [bool](
                (Get-StructuredText $dispatchValues 'wait_warm') -eq $expectedWaitText -and
                (Get-StructuredText $dispatchValues 'main_menu_ready') -eq 'true' -and
                (Get-StructuredText $beginValues 'benchmark_dispatch') -eq 'true' -and
                ((-not $arm.waitForWarm) -or
                    (Get-StructuredText $dispatchValues 'warm_ready') -eq 'true') -and
                $prefaultStateValid -and $warmStateValid -and
                $residencyValid -and $verificationValid)
            $loadResultValid = [bool](
                $timingMarkers.Count -eq 1 -and
                (Get-StructuredText $timingValues 'load_success') -eq 'true')
            $ffcDriverProof = [bool](
                $identityValid -and $orderingValid -and $delayValid -and
                $conditionValid -and $loadResultValid)
            $proofErrors = [System.Collections.Generic.List[string]]::new()
            if (-not $identityValid) {
                $proofErrors.Add('Missing or mismatched dispatch/calling/begin marker identity.')
            }
            if (-not $orderingValid) {
                $proofErrors.Add('Exact-load markers are missing or out of order.')
            }
            if (-not $delayValid) {
                $proofErrors.Add('Configured pre-checkpoint settle interval, fixed post-checkpoint quiet period, or complete dispatch-delay accounting was not proven.')
            }
            if (-not $conditionValid) {
                $proofErrors.Add('Main-menu, dispatch, prefault, warm-ready, full-verification, or full-residency condition was not proven.')
            }
            if (-not $loadResultValid) {
                $proofErrors.Add('A unique successful SKSE post-load result was not proven.')
            }
            $ffcDriverState = [pscustomobject][ordered]@{
                driver = 'ffc'
                valid = $ffcDriverProof
                exact_save = $saveName
                run_tag = $runId
                expected_delay_ms = $arm.autoLoadDelaySeconds * 1000
                observed_delay_ms = $observedDelayMs
                condition_ms = $conditionMs
                settle_ms = $settleMs
                gate_ms = $gateMs
                checkpoint_ms = $checkpointMs
                post_checkpoint_target_ms = $postCheckpointTargetMs
                post_checkpoint_ms = $postCheckpointMs
                delay_accounting_error_ms = $delayAccountingErrorMs
                delay_accounting_valid = $delayAccountingValid
                expected_pre_autoload_cache_state = $expectedPreAutoload
                expected_warm_complete = $expectedWarmComplete
                resident_pages = $residentPagesText
                verified_entries = $verifiedEntriesText
                identity_valid = $identityValid
                ordering_valid = $orderingValid
                delay_valid = $delayValid
                condition_valid = $conditionValid
                load_result_valid = $loadResultValid
                marker_counts = [pscustomobject]@{
                    dispatch = $dispatchMarkers.Count
                    calling_load = $callingMarkers.Count
                    save_load_begin = $beginMarkers.Count
                    save_load_timing = $timingMarkers.Count
                    pre_autoload = $preAutoloadMarkers.Count
                }
                dispatch_marker = $dispatchMarker
                calling_load_marker = $callingMarker
                save_load_begin_marker = $beginMarker
                save_load_timing_marker = $timingMarker
                pre_autoload_marker = $preAutoloadMarker
                proof_errors = @($proofErrors)
            }
            $ffcDriverProofPath = Join-Path $runDirectory 'ffc-load-driver.json'
            [System.IO.File]::WriteAllText($ffcDriverProofPath,
                ($ffcDriverState | ConvertTo-Json -Depth 10), $Utf8NoBom)
        }
        $cacheAfter = Get-CacheInventory -Path $arm.effectiveCacheDir
        $cacheStable = $cacheBefore.files -eq $cacheAfter.files -and
            $cacheBefore.bytes -eq $cacheAfter.bytes
        $success = [bool]($benchDone -and $metrics.performance.loaded -eq 1 -and
            $null -ne $metrics.ffc.save_load_seconds -and
            $legacyDriverProof -and $ffcDriverProof -and $skseSaveProof -and
            ($scheduled.phase -ne 'measured' -or -not $requireStableCache -or $cacheStable))

        $run = [pscustomobject][ordered]@{
            run_id = $runId
            phase = $scheduled.phase
            repetition = $scheduled.repetition
            sequence = $scheduled.sequence
            arm = $arm.name
            mod_version = $arm.modVersion
            skyrim_runtime = $skyrimRuntime
            success = $success
            started_utc = $startedUtc.ToString('O')
            finished_utc = $runFinishedUtc.ToString('O')
            load_driver = $arm.loadDriver
            load_driver_proof_valid = if ($legacyDriverRequired) {
                $legacyDriverProof
            } elseif ($ffcDriverRequired) { $ffcDriverProof } else { $null }
            load_driver_proof = if ($legacyDriverRequired) {
                $legacyDriverState
            } elseif ($ffcDriverRequired) { $ffcDriverState } else { $null }
            load_driver_proof_path = if ($legacyDriverRequired) {
                $legacyDriverProofPath
            } elseif ($ffcDriverRequired) { $ffcDriverProofPath } else { $null }
            wait_for_warm = $arm.waitForWarm
            auto_load_delay_seconds = $arm.autoLoadDelaySeconds
            measure_stats = $arm.measureStats
            cache_mode = $runCacheMode
            prefault_enabled = $arm.prefaultEnabled
            serve_enabled = $arm.serveEnabled
            serve_during_load = $arm.serveDuringLoad
            serving_policy = $arm.servingPolicy
            comparison_limited = $arm.limitations.Count -gt 0
            limitations = @($arm.limitations)
            ffc_dll_sha256 = $arm.dllSha256
            ffc_ini_sha256 = $runIniSha256
            performance_mod_sha256 = Get-Sha256 $perfDllFull
            cache_before = $cacheBefore
            cache_after = $cacheAfter
            cache_stable_by_inventory = $cacheStable
            ffc_log = $primaryFfc
            ffc_logs = @($archivedFfc)
            ffc_loginit_breadcrumbs = @($archivedFfcBreadcrumbs)
            ffc_temp_fallback_logs = @($runTempFallbackLogs)
            performance_log = $primaryPerf
            performance_logs = @($archivedPerf)
            skse_log = $primarySkse
            skse_logs = @($archivedSkse)
            skse_loaded_save = $skseLoadedSave
            skse_load_event_count = $skseLoadEventCount
            skse_load_events = @($skseLoadEvents)
            skse_save_proof_valid = $skseSaveProof
            crash_logs = @($archivedCrash)
            metrics = $metrics
        }
        $results.Add($run)
        [System.IO.File]::WriteAllText((Join-Path $runDirectory 'run.json'),
            ($run | ConvertTo-Json -Depth 12), $Utf8NoBom)
        @($results | ForEach-Object { ConvertTo-CsvRow $_ }) |
            Export-Csv -LiteralPath (Join-Path $sessionDirectory 'results.csv') -NoTypeInformation

        Write-Host ("[$runId] save={0}s cache={1}% startup={2}s success={3}" -f
            $metrics.ffc.save_load_seconds, $metrics.ffc.cache_percent,
            $metrics.ffc.startup_seconds, $success)
        if (-not $success) {
            throw "Run '$runId' failed BENCH_DONE, FFC timing, legacy marker proof, or measured-cache stability validation."
        }
    }

    $measured = @($results | Where-Object phase -eq 'measured')
    $aggregates = [System.Collections.Generic.List[object]]::new()
    foreach ($arm in $normalizedArms) {
        $armRuns = @($measured | Where-Object arm -eq $arm.name)
        $aggregates.Add([pscustomobject]@{
            arm = $arm.name
            successful_runs = @($armRuns | Where-Object success).Count
            save_load_seconds = Get-MetricSummary @($armRuns.metrics.ffc.save_load_seconds)
            startup_seconds = Get-MetricSummary @($armRuns.metrics.ffc.startup_seconds)
            cache_percent = Get-MetricSummary @($armRuns.metrics.ffc.cache_percent)
            cache_mib = Get-MetricSummary @($armRuns.metrics.ffc.cache_mib)
            cache_compressed_share_percent = Get-MetricSummary `
                @($armRuns.metrics.ffc.cache_compressed_share_percent)
            lookup_hit_percent = Get-MetricSummary @($armRuns.metrics.ffc.lookup_hit_percent)
            lookup_cold = Get-MetricSummary @($armRuns.metrics.ffc.lookup_cold)
            checksum_ms = Get-MetricSummary @($armRuns.metrics.ffc.checksum_ms)
            warm_seconds = Get-MetricSummary @($armRuns.metrics.ffc.warm_seconds)
            warm_active_ms_before_autoload = Get-MetricSummary `
                @($armRuns.metrics.ffc.warm_active_ms_before_autoload)
            autoload_condition_ms = Get-MetricSummary @($armRuns.metrics.ffc.autoload_condition_ms)
            autoload_predispatch_ms = Get-MetricSummary `
                @($armRuns.metrics.ffc.autoload_predispatch_ms)
            autoload_settle_ms = Get-MetricSummary `
                @($armRuns.metrics.ffc.autoload_settle_ms)
            autoload_gate_ms = Get-MetricSummary @($armRuns.metrics.ffc.autoload_gate_ms)
            autoload_checkpoint_ms = Get-MetricSummary `
                @($armRuns.metrics.ffc.autoload_checkpoint_ms)
            autoload_post_checkpoint_ms = Get-MetricSummary `
                @($armRuns.metrics.ffc.autoload_post_checkpoint_ms)
            resident_mib_after_warm = Get-MetricSummary `
                @($armRuns.metrics.ffc.resident_mib_after_warm)
            gameplay_logical_mib = Get-MetricSummary @($armRuns.metrics.ffc.gameplay.logical_mib)
            gameplay_cache_mib = Get-MetricSummary @($armRuns.metrics.ffc.gameplay.cache_mib)
            gameplay_decompressor_mib = Get-MetricSummary `
                @($armRuns.metrics.ffc.gameplay.decompressor_mib)
            avg_fps = Get-MetricSummary @($armRuns.metrics.performance.avg_fps)
            peak_working_set_bytes = Get-MetricSummary @($armRuns.metrics.process.peak_working_set_bytes)
            limitations = @($arm.limitations)
        })
    }

    $comparisons = [System.Collections.Generic.List[object]]::new()
    $reference = $aggregates[0]
    foreach ($candidate in @($aggregates | Select-Object -Skip 1)) {
        $base = $reference.save_load_seconds.mean
        $value = $candidate.save_load_seconds.mean
        $comparisons.Add([pscustomobject]@{
            reference_arm = $reference.arm
            candidate_arm = $candidate.arm
            primary_metric = 'ffc_save_load_seconds'
            reference_mean = $base
            candidate_mean = $value
            delta_seconds = if ($null -ne $base -and $null -ne $value) { $value - $base } else { $null }
            delta_percent = if ($null -ne $base -and $base -ne 0 -and $null -ne $value) {
                (($value - $base) / $base) * 100.0
            } else { $null }
            timing_only = [bool]$TimingOnly
            authoritative_for_load_claim = [bool]$TimingOnly
            process_to_postload_comparable = $false
            note = if ($TimingOnly) {
                'Authoritative stats-off FFC BENCH SAVE_LOAD_TIMING comparison.'
            } else {
                'Diagnostic instrumentation run; confirm load-time deltas with -TimingOnly. PerformanceMod load_ms includes startup and warm wait/delay.'
            }
        })
    }
    [System.IO.File]::WriteAllText((Join-Path $sessionDirectory 'aggregates.json'),
        ($aggregates | ConvertTo-Json -Depth 8), $Utf8NoBom)
    [System.IO.File]::WriteAllText((Join-Path $sessionDirectory 'comparisons.json'),
        ($comparisons | ConvertTo-Json -Depth 8), $Utf8NoBom)
}
catch {
    $fatalError = $_
    if ($sessionDirectory) {
        [System.IO.File]::WriteAllText((Join-Path $sessionDirectory 'failure.txt'),
            ($_ | Out-String), $Utf8NoBom)
    }
}
finally {
    if ($lockAcquired) {
        $cleanupErrors = [System.Collections.Generic.List[object]]::new()
        try {
            if ($launchedAny) {
                Stop-OwnedProcesses -Registry $ownedProcesses
                Start-Sleep -Milliseconds 500
            }
        }
        catch {
            $cleanupErrors.Add($_)
        }

        try {
            # A primary-log failure can create a PID-named %TEMP% log before the
            # main polling loop observes Skyrim. Register every newly discovered
            # fallback as transaction-created so final restoration removes it.
            $finalTempFallbackLogs = @(
                Get-ChildItem -LiteralPath $tempDirectory `
                    -Filter 'FasterFileCopy_fallback_*.log' -File `
                    -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
            )
            foreach ($tempLog in $finalTempFallbackLogs) {
                $fullTempLog = [System.IO.Path]::GetFullPath($tempLog)
                if ($trackedStatePaths.Add($fullTempLog)) {
                    $label = 'ffc_temp_created_' + $snapshotStates.Count
                    $snapshotStates.Add((New-AbsentFileState `
                        -Path $fullTempLog -Label $label))
                }
            }
            if ($sessionDirectory) {
                [System.IO.File]::WriteAllText(
                    (Join-Path $snapshotDirectory 'state.json'),
                    ($snapshotStates | ConvertTo-Json -Depth 6), $Utf8NoBom)
            }
        }
        catch {
            $cleanupErrors.Add($_)
        }

        # Restore every known state even if process cleanup, fallback discovery,
        # or another individual restore failed. Each failure remains auditable.
        foreach ($state in @($snapshotStates)) {
            try {
                $restoreAudit += Restore-FileState -State $state
            }
            catch {
                $cleanupErrors.Add($_)
                $restoreAudit += [pscustomobject]@{
                    label = $state.label
                    path = $state.path
                    expected_exists = [bool]$state.existed
                    actual_exists = Test-Path -LiteralPath ([string]$state.path) -PathType Leaf
                    expected_sha256 = $state.sha256
                    actual_sha256 = $null
                    restored = $false
                    error = $_.Exception.Message
                }
            }
        }

        try {
            if ($sessionDirectory) {
                [System.IO.File]::WriteAllText((Join-Path $sessionDirectory 'restore-audit.json'),
                    ($restoreAudit | ConvertTo-Json -Depth 6), $Utf8NoBom)
            }
        }
        catch {
            $cleanupErrors.Add($_)
        }

        $failedRestore = @($restoreAudit | Where-Object { -not $_.restored })
        if (-not $fatalError) {
            if ($failedRestore.Count -gt 0) {
                $fatalError = [System.Management.Automation.ErrorRecord]::new(
                    [InvalidOperationException]::new('One or more testbed files failed restoration verification.'),
                    'RestoreVerificationFailed',
                    [System.Management.Automation.ErrorCategory]::InvalidResult,
                    $failedRestore)
            }
            elseif ($cleanupErrors.Count -gt 0) {
                $fatalError = $cleanupErrors[0]
            }
        }
        try { Write-Host (Invoke-LockCtl -Action release) }
        catch { if (-not $fatalError) { $fatalError = $_ } }
    }
}

if ($fatalError) { throw $fatalError }
Write-Host "A/B suite complete: $sessionDirectory"
