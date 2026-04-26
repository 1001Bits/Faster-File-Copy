param(
    [string]$GamePath,
    [string]$TomlPath,
    [int]$PlaySec = 60,
    [string]$Label = "test",
    [int]$Baseline = -1,
    [int]$Mmap = -1,
    [int]$DecompCache = -1,
    [int]$Stats = -1,
    [int]$WipeCache = 0,
    [string]$CacheDir = ""
)

# Set a TOML scalar inside a specific [Section] header.
# `bEnabled` appears in both [General] (master switch) and [DecompCache]
# (cache toggle) — always scope by section so we hit the right one.
function Set-TomlValue {
    param([string]$Path, [string]$Section, [string]$Key, [string]$Value)
    $lines = Get-Content $Path
    $inSection = $false
    $replaced = $false
    $out = for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -match '^\s*\[([^\]]+)\]\s*$') {
            $inSection = ($Matches[1] -eq $Section)
            $line
        } elseif ($inSection -and -not $replaced -and $line -match "^(\s*$Key\s*=\s*).*$") {
            $replaced = $true
            "$($Matches[1])$Value"
        } else {
            $line
        }
    }
    $out | Set-Content $Path
}

function Bool($i) { if ($i -eq 1) { "true" } else { "false" } }

if ($TomlPath -and (Test-Path $TomlPath)) {
    if ($Baseline -ge 0)    { Set-TomlValue -Path $TomlPath -Section "General"     -Key "bBaselineMode" -Value (Bool $Baseline) }
    if ($Stats -ge 0)       { Set-TomlValue -Path $TomlPath -Section "General"     -Key "bEnableStats"  -Value (Bool $Stats) }
    if ($Mmap -ge 0)        { Set-TomlValue -Path $TomlPath -Section "Archives"    -Key "bEnableMmap"   -Value (Bool $Mmap) }
    if ($DecompCache -ge 0) { Set-TomlValue -Path $TomlPath -Section "DecompCache" -Key "bEnabled"      -Value (Bool $DecompCache) }
}

# Optionally wipe the decomp cache for cold-start runs
if ($WipeCache -eq 1 -and $CacheDir -and (Test-Path $CacheDir)) {
    Write-Host "Wiping decomp cache at $CacheDir..."
    Get-ChildItem $CacheDir -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}

Add-Type @'
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
[StructLayout(LayoutKind.Sequential)]
public struct HARDWAREINPUT { public uint uMsg; public ushort wParamL; public ushort wParamH; }
[StructLayout(LayoutKind.Sequential)]
public struct MOUSEINPUT { public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
[StructLayout(LayoutKind.Explicit)]
public struct INPUTUNION { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; [FieldOffset(0)] public HARDWAREINPUT hi; }
[StructLayout(LayoutKind.Sequential)]
public struct INPUT { public uint type; public INPUTUNION u; }

public class NativeInput {
    [DllImport("user32.dll", SetLastError = true)] public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    public const int SW_RESTORE = 9;

    public static bool ForceForeground(IntPtr hWnd) {
        if (hWnd == IntPtr.Zero) return false;
        ShowWindow(hWnd, SW_RESTORE);
        uint targetPid = 0;
        uint targetThread = GetWindowThreadProcessId(hWnd, out targetPid);
        uint myThread = GetCurrentThreadId();
        bool attached = false;
        if (targetThread != myThread) attached = AttachThreadInput(myThread, targetThread, true);
        BringWindowToTop(hWnd);
        bool ok = SetForegroundWindow(hWnd);
        if (attached) AttachThreadInput(myThread, targetThread, false);
        return ok;
    }

    public static void KeyDown(ushort scanCode) {
        INPUT[] inputs = new INPUT[1];
        inputs[0].type = 1; inputs[0].u.ki.wScan = scanCode; inputs[0].u.ki.dwFlags = 0x0008;
        SendInput(1, inputs, Marshal.SizeOf(typeof(INPUT)));
    }
    public static void KeyUp(ushort scanCode) {
        INPUT[] inputs = new INPUT[1];
        inputs[0].type = 1; inputs[0].u.ki.wScan = scanCode; inputs[0].u.ki.dwFlags = 0x000A;
        SendInput(1, inputs, Marshal.SizeOf(typeof(INPUT)));
    }
    public static void PressKey(ushort scanCode) {
        KeyDown(scanCode);
        System.Threading.Thread.Sleep(50);
        KeyUp(scanCode);
    }
}
'@

$LogPath = Join-Path $env:USERPROFILE "Documents\My Games\Fallout4\F4SE\FasterFileCopyFO4.log"

$SC_W = 0x11
$SC_A = 0x1E
$SC_S = 0x1F
$SC_D = 0x20
$SC_ENTER = 0x1C

Write-Host "=== Benchmark: $Label ==="
Write-Host "Game: $GamePath"
Write-Host "Play: ${PlaySec}s"

if ($PlaySec -le 0) { Write-Host "TOML updated only."; exit 0 }

# Kill any existing Fallout 4
Stop-Process -Name f4se_loader -Force -ErrorAction SilentlyContinue
Stop-Process -Name Fallout4 -Force -ErrorAction SilentlyContinue
for ($w = 0; $w -lt 30; $w++) {
    if (-not (Get-Process Fallout4 -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Seconds 1
}
Start-Sleep -Seconds 2

# Delete old log — retry a few times in case it's still locked
for ($d = 0; $d -lt 10; $d++) {
    if (-not (Test-Path $LogPath)) { break }
    Remove-Item $LogPath -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $LogPath)) { break }
    Start-Sleep -Seconds 1
}
if (Test-Path $LogPath) { Write-Host "WARNING: Could not delete old log!"; exit 1 }

# Launch, timestamping the wall-clock start in case LOAD TIME marker is missed
$launchTime = Get-Date
Start-Process -FilePath (Join-Path $GamePath "f4se_loader.exe") -WorkingDirectory $GamePath

Write-Host "Waiting for Fallout4 process..."
$proc = $null
for ($i = 0; $i -lt 60; $i++) {
    $proc = Get-Process Fallout4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($proc) { break }
    Start-Sleep -Milliseconds 500
}
if (-not $proc) { Write-Host "Fallout4 didn't start!"; exit 1 }

# Wait for main window handle so SendInput has something to focus. On OG the
# intro videos start playing once the window is up but BEFORE kInputLoaded —
# we want to start pressing Enter during the intro to skip it, not wait for
# the main menu marker.
Write-Host "Waiting for Fallout4 window handle..."
for ($i = 0; $i -lt 120; $i++) {
    $proc = Get-Process Fallout4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($proc -and $proc.MainWindowHandle -ne 0) { break }
    Start-Sleep -Milliseconds 500
}
if (-not $proc -or $proc.MainWindowHandle -eq 0) { Write-Host "Window never appeared!"; exit 1 }
Start-Sleep -Seconds 2

# Press Enter repeatedly until "Gameplay measurement started" marker appears.
# This marker only fires after the REAL save load (loadSec > 1.0 gate in
# main.cpp), so it's the reliable signal that menu/load phase is over and
# WASD should take over. Re-focus before each press in case the user Alt-Tabbed.
Write-Host "Spamming Enter until gameplay starts..."
$loadStarted = $false
for ($e = 0; $e -lt 90; $e++) {
    $proc = Get-Process Fallout4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $proc) { Write-Host "Process died during Enter spam!"; exit 1 }
    [NativeInput]::ForceForeground($proc.MainWindowHandle) | Out-Null
    [NativeInput]::PressKey($SC_ENTER)
    Start-Sleep -Seconds 2
    if (Test-Path $LogPath) {
        $m = Select-String -Path $LogPath -Pattern "Gameplay measurement started" -SimpleMatch -ErrorAction SilentlyContinue
        if ($m) { $loadStarted = $true; break }
    }
}
if (-not $loadStarted) { Write-Host "WARNING: gameplay never started -- may have gotten stuck in a menu" }
# Pause so any pending Enter keyup is flushed before we start WASD
Start-Sleep -Seconds 2

# Gameplay — walk forward and turn so something is being streamed
if ($PlaySec -gt 0) {
    Write-Host "Playing for ${PlaySec}s..."
    $proc = Get-Process Fallout4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($proc) { [NativeInput]::ForceForeground($proc.MainWindowHandle) | Out-Null }
    $elapsed = 0
    while ($elapsed -lt $PlaySec) {
        $proc = Get-Process Fallout4 -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $proc) { Write-Host "Process died during gameplay!"; break }

        $walkTime = [Math]::Min(2, $PlaySec - $elapsed)
        [NativeInput]::KeyDown($SC_W); Start-Sleep -Milliseconds ($walkTime * 1000); [NativeInput]::KeyUp($SC_W)
        $elapsed += $walkTime
        if ($elapsed -ge $PlaySec) { break }

        $turnTime = [Math]::Min(0.5, $PlaySec - $elapsed)
        [NativeInput]::KeyDown($SC_D); Start-Sleep -Milliseconds ($turnTime * 1000); [NativeInput]::KeyUp($SC_D)
        $elapsed += $turnTime
        if ($elapsed -ge $PlaySec) { break }

        $walkTime = [Math]::Min(2, $PlaySec - $elapsed)
        [NativeInput]::KeyDown($SC_W); Start-Sleep -Milliseconds ($walkTime * 1000); [NativeInput]::KeyUp($SC_W)
        $elapsed += $walkTime
        if ($elapsed -ge $PlaySec) { break }

        $turnTime = [Math]::Min(0.5, $PlaySec - $elapsed)
        [NativeInput]::KeyDown($SC_A); Start-Sleep -Milliseconds ($turnTime * 1000); [NativeInput]::KeyUp($SC_A)
        $elapsed += $turnTime
    }
}

# Wait for a GAMEPLAY line whose cumulative time >= PlaySec, up to PlaySec + 15s
# total (covers the 5s stats interval + slack). If not seen by then, just kill.
$waitMax = $PlaySec + 15
Write-Host "Waiting for gameplay summary covering >=${PlaySec}s (timeout ${waitMax}s)..."
$gameplayDone = $false
for ($i = 0; $i -lt $waitMax; $i++) {
    if (Test-Path $LogPath) {
        $last = Select-String -Path $LogPath -Pattern "GAMEPLAY:" -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -Last 1
        if ($last -and $last.Line -match "GAMEPLAY:\s*([\d.]+)s") {
            $cum = [double]$Matches[1]
            if ($cum -ge $PlaySec) { $gameplayDone = $true; break }
        }
    }
    Start-Sleep -Seconds 1
}
if (-not $gameplayDone) { Write-Host "NOTE: no GAMEPLAY line >= ${PlaySec}s within ${waitMax}s -- killing anyway" }

Stop-Process -Name Fallout4 -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5

if (Test-Path $LogPath) {
    $log = Get-Content $LogPath
    $settings = ($log | Select-String "Settings loaded" | Select-Object -Last 1)
    $loadTime = ($log | Select-String "FFC4 LOAD TIME" | Select-Object -Last 1)
    $saveload = ($log | Select-String "SAVE LOAD:" | Select-Object -First 1)

    # Prefer the plugin's own cumulative "GAMEPLAY:" summary line (emitted by
    # LogGameplaySummary each stats interval). Last one is the most complete.
    $gameplay = ($log | Select-String "GAMEPLAY:" -SimpleMatch | Select-Object -Last 1)

    Write-Host ""
    Write-Host "--- Results: $Label ---"
    if ($settings) { Write-Host "$settings" }
    if ($loadTime) { Write-Host "$loadTime" }
    if ($saveload) { Write-Host "$saveload" }
    if ($gameplay) { Write-Host "$gameplay" } else { Write-Host "GAMEPLAY: no summary captured" }

    $logCopy = Join-Path (Split-Path $LogPath) "FasterFileCopyFO4_${Label}.log"
    Copy-Item $LogPath $logCopy -Force -ErrorAction SilentlyContinue
    Write-Host "Log saved: $logCopy"
}
Write-Host "=== Done: $Label ==="
