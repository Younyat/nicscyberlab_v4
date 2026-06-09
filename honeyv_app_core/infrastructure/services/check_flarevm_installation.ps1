[CmdletBinding()]
param(
    [switch]$VerboseOutput,
    [string]$OutputJson = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Add-Result {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Details,
        [object]$Value = $null
    )

    $script:Results.Add([pscustomobject]@{
        Name    = $Name
        Status  = $Status
        Details = $Details
        Value   = $Value
    }) | Out-Null

    switch ($Status) {
        "PASS"    { Write-Host "[PASS] $Name - $Details" -ForegroundColor Green }
        "WARN"    { Write-Host "[WARN] $Name - $Details" -ForegroundColor Yellow }
        "FAIL"    { Write-Host "[FAIL] $Name - $Details" -ForegroundColor Red }
        default   { Write-Host "[INFO] $Name - $Details" -ForegroundColor White }
    }
}

function Safe-TestPath {
    param([string]$Path)
    try {
        return Test-Path -LiteralPath $Path
    } catch {
        return $false
    }
}

function Safe-GetCommand {
    param([string]$Name)
    try {
        return Get-Command $Name -ErrorAction Stop
    } catch {
        return $null
    }
}

function Safe-RunCommand {
    param(
        [string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 20
    )

    $tempOut = [System.IO.Path]::GetTempFileName()
    $tempErr = [System.IO.Path]::GetTempFileName()

    try {
        $proc = Start-Process -FilePath $FilePath `
                              -ArgumentList $Arguments `
                              -NoNewWindow `
                              -PassThru `
                              -RedirectStandardOutput $tempOut `
                              -RedirectStandardError $tempErr

        if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
            try { $proc.Kill() } catch {}
            return [pscustomobject]@{
                Success   = $false
                ExitCode  = $null
                StdOut    = ""
                StdErr    = "Timeout after $TimeoutSeconds seconds"
            }
        }

        $stdout = ""
        $stderr = ""

        try { $stdout = Get-Content -LiteralPath $tempOut -Raw -ErrorAction SilentlyContinue } catch {}
        try { $stderr = Get-Content -LiteralPath $tempErr -Raw -ErrorAction SilentlyContinue } catch {}

        return [pscustomobject]@{
            Success   = ($proc.ExitCode -eq 0)
            ExitCode  = $proc.ExitCode
            StdOut    = $stdout
            StdErr    = $stderr
        }
    } catch {
        return [pscustomobject]@{
            Success   = $false
            ExitCode  = $null
            StdOut    = ""
            StdErr    = $_.Exception.Message
        }
    } finally {
        Remove-Item -LiteralPath $tempOut -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $tempErr -Force -ErrorAction SilentlyContinue
    }
}

function Get-ChocoPackages {
    $cmd = Safe-GetCommand "choco"
    if (-not $cmd) {
        return @()
    }

    $result = Safe-RunCommand -FilePath $cmd.Source -Arguments @("list")
    if (-not $result.Success -and [string]::IsNullOrWhiteSpace($result.StdOut)) {
        return @()
    }

    $lines = @()
    if (-not [string]::IsNullOrWhiteSpace($result.StdOut)) {
        $lines = $result.StdOut -split "`r?`n"
    }

    $packages = New-Object System.Collections.Generic.List[object]

    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if ($trimmed -match "^Chocolatey v") { continue }
        if ($trimmed -match "packages installed\.$") { continue }

        if ($trimmed -match "^([A-Za-z0-9\.\-\+_]+)\s+(.+)$") {
            $packages.Add([pscustomobject]@{
                Name    = $matches[1]
                Version = $matches[2]
            }) | Out-Null
        }
    }

    return $packages
}

function Test-PackageInstalled {
    param(
        [System.Collections.Generic.List[object]]$Packages,
        [string]$PackageName
    )

    foreach ($pkg in $Packages) {
        if ($pkg.Name -ieq $PackageName) {
            return $pkg
        }
    }
    return $null
}

function Test-AnyPathExists {
    param([string[]]$Paths)

    foreach ($p in $Paths) {
        if (Safe-TestPath $p) {
            return $p
        }
    }
    return $null
}

$Results = New-Object System.Collections.Generic.List[object]

Write-Section "FLARE VM INSTALLATION CHECK"

$requiredBaseCommands = @(
    "choco",
    "boxstarter"
)

$corePackages = @(
    "common.vm",
    "installer.vm"
)

$importantPackages = @(
    "x64dbg.vm",
    "ghidra.vm",
    "cutter.vm",
    "idafree.vm",
    "windbg.vm",
    "didier-stevens-suite.vm"
)

$optionalPackages = @(
    "binaryninja.vm",
    "bindiff.vm",
    "ilspy.vm",
    "dnspyex.vm",
    "python3.vm"
)

$expectedPaths = @(
    "C:\Tools",
    "C:\Users\$env:USERNAME\Desktop\Tools",
    "C:\ProgramData\chocolatey",
    "C:\ProgramData\Boxstarter"
)

$toolChecks = @(
    @{
        Name = "x64dbg"
        Commands = @("x64dbg")
        Paths = @(
            "C:\ProgramData\chocolatey\bin\x64dbg.exe",
            "C:\Tools\x64dbg\x64dbg.exe"
        )
    },
    @{
        Name = "Detect It Easy"
        Commands = @("die", "diec", "diel")
        Paths = @(
            "C:\Tools\die\die.exe",
            "C:\Tools\die\diec.exe",
            "C:\Tools\die\diel.exe"
        )
    },
    @{
        Name = "Ghidra"
        Commands = @("ghidraRun")
        Paths = @(
            "C:\Tools\ghidra\ghidraRun.bat",
            "C:\Tools\ghidra_*\ghidraRun.bat"
        )
    },
    @{
        Name = "Cutter"
        Commands = @("cutter")
        Paths = @(
            "C:\Tools\Cutter\Cutter.exe",
            "C:\Tools\Cutter\Cutter-v*\Cutter.exe"
        )
    }
)

Write-Section "1. BASE COMMANDS"

foreach ($cmdName in $requiredBaseCommands) {
    $cmd = Safe-GetCommand $cmdName
    if ($cmd) {
        Add-Result -Name "Command: $cmdName" -Status "PASS" -Details "Found at $($cmd.Source)" -Value $cmd.Source
    } else {
        Add-Result -Name "Command: $cmdName" -Status "FAIL" -Details "Not found in PATH"
    }
}

Write-Section "2. EXPECTED DIRECTORIES"

foreach ($path in $expectedPaths) {
    if (Safe-TestPath $path) {
        Add-Result -Name "Path: $path" -Status "PASS" -Details "Exists" -Value $path
    } else {
        Add-Result -Name "Path: $path" -Status "WARN" -Details "Missing"
    }
}

Write-Section "3. CHOCOLATEY PACKAGE INVENTORY"

$allPackages = Get-ChocoPackages
$packageCount = @($allPackages).Count

if ($packageCount -gt 0) {
    Add-Result -Name "Chocolatey package inventory" -Status "PASS" -Details "$packageCount packages detected" -Value $packageCount
} else {
    Add-Result -Name "Chocolatey package inventory" -Status "FAIL" -Details "Could not retrieve package list"
}

Write-Section "4. CORE FLARE VM PACKAGES"

$corePass = 0
foreach ($pkgName in $corePackages) {
    $pkg = Test-PackageInstalled -Packages $allPackages -PackageName $pkgName
    if ($pkg) {
        $corePass++
        Add-Result -Name "Package: $pkgName" -Status "PASS" -Details "Installed version $($pkg.Version)" -Value $pkg.Version
    } else {
        Add-Result -Name "Package: $pkgName" -Status "FAIL" -Details "Missing"
    }
}

Write-Section "5. IMPORTANT TOOL PACKAGES"

$importantPass = 0
foreach ($pkgName in $importantPackages) {
    $pkg = Test-PackageInstalled -Packages $allPackages -PackageName $pkgName
    if ($pkg) {
        $importantPass++
        Add-Result -Name "Package: $pkgName" -Status "PASS" -Details "Installed version $($pkg.Version)" -Value $pkg.Version
    } else {
        Add-Result -Name "Package: $pkgName" -Status "WARN" -Details "Missing"
    }
}

Write-Section "6. OPTIONAL PACKAGES"

$optionalPass = 0
foreach ($pkgName in $optionalPackages) {
    $pkg = Test-PackageInstalled -Packages $allPackages -PackageName $pkgName
    if ($pkg) {
        $optionalPass++
        Add-Result -Name "Package: $pkgName" -Status "PASS" -Details "Installed version $($pkg.Version)" -Value $pkg.Version
    } else {
        Add-Result -Name "Package: $pkgName" -Status "WARN" -Details "Missing"
    }
}

Write-Section "7. TOOL PRESENCE CHECK"

$toolPresencePass = 0

foreach ($tool in $toolChecks) {
    $toolName = [string]$tool.Name
    $commands = @($tool.Commands)
    $paths = @($tool.Paths)

    $foundByCommand = $null
    foreach ($candidate in $commands) {
        $cmd = Safe-GetCommand $candidate
        if ($cmd) {
            $foundByCommand = $cmd.Source
            break
        }
    }

    $foundByPath = $null
    foreach ($pattern in $paths) {
        try {
            $resolved = Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($resolved) {
                $foundByPath = $resolved.FullName
                break
            }
        } catch {
        }
    }

    if ($foundByCommand) {
        $toolPresencePass++
        Add-Result -Name "Tool: $toolName" -Status "PASS" -Details "Accessible by command at $foundByCommand" -Value $foundByCommand
    } elseif ($foundByPath) {
        $toolPresencePass++
        Add-Result -Name "Tool: $toolName" -Status "PASS" -Details "Found on disk at $foundByPath" -Value $foundByPath
    } else {
        Add-Result -Name "Tool: $toolName" -Status "WARN" -Details "Not found by command or expected path"
    }
}

Write-Section "8. EXECUTABLE SANITY CHECK"

$sanityChecks = @()

$x64dbgCmd = Safe-GetCommand "x64dbg"
if ($x64dbgCmd) {
    $sanityChecks += [pscustomobject]@{
        Name = "x64dbg executable existence"
        Path = $x64dbgCmd.Source
    }
}

$diePath = Test-AnyPathExists @(
    "C:\Tools\die\die.exe"
)
if ($diePath) {
    $sanityChecks += [pscustomobject]@{
        Name = "Detect It Easy executable existence"
        Path = $diePath
    }
}

foreach ($check in $sanityChecks) {
    if (Safe-TestPath $check.Path) {
        Add-Result -Name $check.Name -Status "PASS" -Details "Exists at $($check.Path)" -Value $check.Path
    } else {
        Add-Result -Name $check.Name -Status "FAIL" -Details "Expected executable missing at $($check.Path)"
    }
}

Write-Section "9. SCORING"

$failCount = @($Results | Where-Object { $_.Status -eq "FAIL" }).Count
$warnCount = @($Results | Where-Object { $_.Status -eq "WARN" }).Count
$passCount = @($Results | Where-Object { $_.Status -eq "PASS" }).Count

$baseReady = ($null -ne (Safe-GetCommand "choco")) -and ($null -ne (Safe-GetCommand "boxstarter"))
$coreReady = ($corePass -eq $corePackages.Count)
$importantRatio = if ($importantPackages.Count -gt 0) { [double]$importantPass / [double]$importantPackages.Count } else { 0.0 }
$toolRatio = if ($toolChecks.Count -gt 0) { [double]$toolPresencePass / [double]$toolChecks.Count } else { 0.0 }

$finalStatus = "FAIL"
$finalReason = ""

if ($baseReady -and $coreReady -and $importantRatio -ge 0.60 -and $toolRatio -ge 0.50) {
    $finalStatus = "PASS"
    $finalReason = "FLARE VM appears correctly installed and functionally usable."
} elseif ($baseReady -and ($corePass -ge 1 -or $importantPass -ge 2)) {
    $finalStatus = "PARTIAL"
    $finalReason = "FLARE VM appears partially installed or usable but incomplete."
} else {
    $finalStatus = "FAIL"
    $finalReason = "FLARE VM installation appears missing, broken, or seriously incomplete."
}

switch ($finalStatus) {
    "PASS" {
        Write-Host ""
        Write-Host "FINAL STATUS: PASS" -ForegroundColor Green
        Write-Host $finalReason -ForegroundColor Green
    }
    "PARTIAL" {
        Write-Host ""
        Write-Host "FINAL STATUS: PARTIAL" -ForegroundColor Yellow
        Write-Host $finalReason -ForegroundColor Yellow
    }
    "FAIL" {
        Write-Host ""
        Write-Host "FINAL STATUS: FAIL" -ForegroundColor Red
        Write-Host $finalReason -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  PASS:    $passCount"
Write-Host "  WARN:    $warnCount"
Write-Host "  FAIL:    $failCount"
Write-Host "  Core packages present:      $corePass / $($corePackages.Count)"
Write-Host "  Important packages present: $importantPass / $($importantPackages.Count)"
Write-Host "  Optional packages present:  $optionalPass / $($optionalPackages.Count)"
Write-Host "  Tool checks passed:         $toolPresencePass / $($toolChecks.Count)"

if ($OutputJson) {
    $payload = [pscustomobject]@{
        Timestamp      = (Get-Date).ToString("s")
        FinalStatus    = $finalStatus
        FinalReason    = $finalReason
        Summary        = [pscustomobject]@{
            PassCount          = $passCount
            WarnCount          = $warnCount
            FailCount          = $failCount
            CorePass           = $corePass
            CoreTotal          = $corePackages.Count
            ImportantPass      = $importantPass
            ImportantTotal     = $importantPackages.Count
            OptionalPass       = $optionalPass
            OptionalTotal      = $optionalPackages.Count
            ToolPresencePass   = $toolPresencePass
            ToolPresenceTotal  = $toolChecks.Count
        }
        Results        = $Results
        InstalledPkgs  = $allPackages
    }

    try {
        $payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputJson -Encoding UTF8
        Write-Host ""
        Write-Host "JSON report saved to: $OutputJson" -ForegroundColor Cyan
    } catch {
        Write-Host ""
        Write-Host "Could not save JSON report: $($_.Exception.Message)" -ForegroundColor Red
    }
}

switch ($finalStatus) {
    "PASS"    { exit 0 }
    "PARTIAL" { exit 1 }
    "FAIL"    { exit 2 }
}