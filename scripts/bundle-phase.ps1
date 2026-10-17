<#
.SYNOPSIS
    Bundles repository changes, test logs, diffs, and full sources into a markdown snapshot for phase audit.

.DESCRIPTION
    Generates a phase audit snapshot at docs/audits/snapshots/$Phase-snapshot.md containing:
    - Metadata: Phase name, UTC timestamp, git commit, branch, base reference.
    - Section 1: Project tree and git status ([MODIFIED], [NEW], [DELETED]).
    - Section 2: Test & build verification logs (Maven / pnpm if present, or skipped).
    - Section 3: Git diff for modified files (excluding binaries, locks, and snapshots).
    - Section 4: Full source of new and modified files formatted in markdown code blocks.

.PARAMETER Phase
    Mandatory phase identifier (e.g., 'phase-02-setup', 'phase-03').

.PARAMETER BaseRef
    Base git reference for diff calculation (default: 'HEAD').

.PARAMETER SkipTests
    Switch to bypass test execution.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Phase identifier, e.g. phase-11 or 11")]
    [string]$Phase,

    [Parameter(Mandatory = $false, Position = 1)]
    [string]$BaseRef = "HEAD",

    [switch]$SkipTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Normalize numeric phase (e.g. "11" -> "phase-11")
if ($Phase -match '^\d+$') {
    $Phase = "phase-{0:D2}" -f [int]$Phase
}

# Markdown backtick and fence helpers
$bt = [char]96
$bt3 = [string]::new($bt, 3)
$fence4 = [string]::new($bt, 4)
$fence5 = [string]::new($bt, 5)

# ---------------------------------------------------------------------------
# 1. Environment & Paths Resolution
# ---------------------------------------------------------------------------
if ($PSScriptRoot) {
    $RepoRoot = (Get-Item "$PSScriptRoot/..").FullName
} else {
    $RepoRoot = (Get-Location).Path
}

Push-Location $RepoRoot
try {
    $SnapshotsDir = Join-Path $RepoRoot "docs/audits/snapshots"
    if (-not (Test-Path -Path $SnapshotsDir)) {
        New-Item -ItemType Directory -Path $SnapshotsDir -Force | Out-Null
    }

    $OutputFile = Join-Path $SnapshotsDir "$Phase-snapshot.md"

    # -----------------------------------------------------------------------
    # Helper Functions
    # -----------------------------------------------------------------------
    function Test-IsExcludedPath {
        param([string]$Path)
        $p = $Path.Replace('\', '/')
        if ($p -like "docs/audits/snapshots/*") { return $true }
        if ($p -like ".git/*" -or $p -eq ".git") { return $true }
        if ($p -like "*/node_modules/*" -or $p -like "node_modules/*") { return $true }
        if ($p -like "*/target/*" -or $p -like "target/*") { return $true }
        if ($p -like "*/dist/*" -or $p -like "dist/*") { return $true }
        if ($p -like "*.lock" -or $p -like "*pnpm-lock.yaml" -or $p -like "*package-lock.json") { return $true }
        return $false
    }

    function Test-IsBinaryPath {
        param([string]$Path)
        $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
        $binExts = @(
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svgz", ".webp",
            ".jar", ".war", ".ear", ".class", ".exe", ".dll", ".so", ".dylib",
            ".pdf", ".zip", ".tar", ".gz", ".7z", ".bin",
            ".woff", ".woff2", ".ttf", ".eot"
        )
        return ($binExts -contains $ext)
    }

    function Get-MarkdownLanguage {
        param([string]$Path)
        $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
        switch ($ext) {
            ".java"       { return "java" }
            ".vue"        { return "vue" }
            ".ts"         { return "typescript" }
            ".tsx"        { return "typescript" }
            ".js"         { return "javascript" }
            ".jsx"        { return "javascript" }
            ".json"       { return "json" }
            ".sql"        { return "sql" }
            ".xml"        { return "xml" }
            ".yml"        { return "yaml" }
            ".yaml"       { return "yaml" }
            ".md"         { return "markdown" }
            ".ps1"        { return "powershell" }
            ".psm1"       { return "powershell" }
            ".sh"         { return "bash" }
            ".bash"       { return "bash" }
            ".css"        { return "css" }
            ".scss"       { return "scss" }
            ".html"       { return "html" }
            ".properties" { return "properties" }
            ".env"        { return "properties" }
            ".example"    { return "properties" }
            ".toml"       { return "toml" }
            ".gitignore"  { return "gitignore" }
            default       { return "text" }
        }
    }

    # -----------------------------------------------------------------------
    # Metadata Header
    # -----------------------------------------------------------------------
    $Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $CommitHash = (git rev-parse --short HEAD 2>$null)
    if (-not $CommitHash) { $CommitHash = "N/A" }
    $Branch = (git rev-parse --abbrev-ref HEAD 2>$null)
    if (-not $Branch) { $Branch = "unknown" }

    $Lines = [System.Collections.Generic.List[string]]::new()
    $Lines.Add("# Phase Audit Snapshot: $Phase")
    $Lines.Add("")
    $Lines.Add("- **Phase**: $bt$Phase$bt")
    $Lines.Add("- **Timestamp (UTC)**: $Timestamp")
    $Lines.Add("- **Base Ref**: $bt$BaseRef$bt")
    $Lines.Add("- **Current Commit**: $bt$CommitHash$bt")
    $Lines.Add("- **Branch**: $bt$Branch$bt")
    $Lines.Add("- **Skip Tests**: $([string]$SkipTests.IsPresent)")
    $Lines.Add("")

    # -----------------------------------------------------------------------
    # Section 1: Project Tree & Git Status
    # -----------------------------------------------------------------------
    $Lines.Add("## Section 1: Project Tree & Git Status")
    $Lines.Add("")

    $NewFiles = [System.Collections.Generic.List[string]]::new()
    $ModifiedFiles = [System.Collections.Generic.List[string]]::new()
    $DeletedFiles = [System.Collections.Generic.List[string]]::new()
    $StatusEntries = [System.Collections.Generic.List[string]]::new()

    # Diff vs BaseRef
    $diffRaw = git diff --name-status $BaseRef 2>$null
    if ($diffRaw) {
        foreach ($dLine in $diffRaw) {
            if ([string]::IsNullOrWhiteSpace($dLine)) { continue }
            $parts = $dLine -split "`t"
            if ($parts.Count -lt 2) { continue }
            $statusCode = $parts[0].Trim()
            $filePath = if ($parts.Count -ge 3) { $parts[2].Trim() } else { $parts[1].Trim() }
            $filePath = $filePath.Replace('\', '/')

            if (Test-IsExcludedPath $filePath) { continue }

            if ($statusCode.StartsWith("A")) {
                if (-not $NewFiles.Contains($filePath)) { $NewFiles.Add($filePath) }
                $StatusEntries.Add("- $bt[NEW]$bt $filePath")
            } elseif ($statusCode.StartsWith("D")) {
                if (-not $DeletedFiles.Contains($filePath)) { $DeletedFiles.Add($filePath) }
                $StatusEntries.Add("- $bt[DELETED]$bt $filePath")
            } else {
                if (-not $ModifiedFiles.Contains($filePath)) { $ModifiedFiles.Add($filePath) }
                $StatusEntries.Add("- $bt[MODIFIED]$bt $filePath")
            }
        }
    }

    # Untracked files
    $untrackedRaw = git ls-files --others --exclude-standard 2>$null
    if ($untrackedRaw) {
        foreach ($uLine in $untrackedRaw) {
            if ([string]::IsNullOrWhiteSpace($uLine)) { continue }
            $filePath = $uLine.Trim().Replace('\', '/')
            if (Test-IsExcludedPath $filePath) { continue }

            if (-not $NewFiles.Contains($filePath)) {
                $NewFiles.Add($filePath)
                $StatusEntries.Add("- $bt[NEW]$bt $filePath")
            }
        }
    }

    if ($StatusEntries.Count -eq 0) {
        $Lines.Add("> No modified or new files detected relative to $bt$BaseRef$bt.")
    } else {
        foreach ($entry in $StatusEntries) {
            $Lines.Add($entry)
        }
    }
    $Lines.Add("")

    # -----------------------------------------------------------------------
    # Section 2: Test & Build Verification Logs
    # -----------------------------------------------------------------------
    $Lines.Add("## Section 2: Test & Build Verification Logs")
    $Lines.Add("")

    if ($SkipTests) {
        $Lines.Add("> [!NOTE]")
        $Lines.Add("> Test execution skipped ($bt-SkipTests$bt flag enabled).")
        $Lines.Add("")
    } else {
        $anyTestsRun = $false

        # Maven / Backend Check
        $mvnCmd = $null
        $mvnDir = $null
        if (Test-Path (Join-Path $RepoRoot "backend/mvnw.cmd")) {
            $mvnCmd = Join-Path $RepoRoot "backend/mvnw.cmd"
            $mvnDir = Join-Path $RepoRoot "backend"
        } elseif (Test-Path (Join-Path $RepoRoot "mvnw.cmd")) {
            $mvnCmd = Join-Path $RepoRoot "mvnw.cmd"
            $mvnDir = $RepoRoot
        }

        if ($mvnCmd) {
            $anyTestsRun = $true
            $Lines.Add("### Backend Verification (Maven)")
            $Lines.Add("")
            $dockerAvailable = $false
            try {
                $null = & docker info 2>&1
                if ($LASTEXITCODE -eq 0) { $dockerAvailable = $true }
            } catch {
                $dockerAvailable = $false
            }

            $mvnArgs = @("test")
            if (-not $dockerAvailable) {
                Write-Host "[!] Docker daemon not detected; executing unit tests (*Test) without Testcontainers..." -ForegroundColor Yellow
                $Lines.Add("> [!NOTE]")
                $Lines.Add("> Docker daemon offline on host: executing unit tests (${bt}*Test${bt}) to prevent Testcontainers timeout/failure.")
                $Lines.Add("")
                $mvnArgs = @("test", "-Dtest=*Test")
            }

            Write-Host "[*] Executing Maven tests: $mvnCmd $($mvnArgs -join ' ') in $mvnDir..." -ForegroundColor Cyan

            # Clean previous surefire reports so old runs don't leak into current snapshot
            $surefireDir = Join-Path $mvnDir "target/surefire-reports"
            if (Test-Path $surefireDir) {
                Remove-Item -Path "$surefireDir/*" -Recurse -Force -ErrorAction SilentlyContinue
            }

            Push-Location $mvnDir
            try {
                $mvnOutput = & $mvnCmd @mvnArgs 2>&1 | Out-String
                $mvnExit = $LASTEXITCODE
            } finally {
                Pop-Location
            }

            $Lines.Add("- **Exit Code**: $mvnExit")
            $Lines.Add("")
            $Lines.Add("${bt3}text")
            $cleanMvn = $mvnOutput -replace '\x1B\[[0-9;]*[a-zA-Z]', ''
            $rawLines = $cleanMvn -split "`r?`n"
            $matched = $rawLines | Where-Object {
                $_ -match "Tests run:" -or
                $_ -match "BUILD SUCCESS" -or
                $_ -match "BUILD FAILURE" -or
                $_ -match "^\[ERROR\]"
            }
            if ($matched) {
                foreach ($m in $matched) { $Lines.Add($m) }
            } else {
                $tail = $rawLines | Select-Object -Last 25
                foreach ($t in $tail) { $Lines.Add($t) }
            }
            $Lines.Add($bt3)
            $Lines.Add("")

            # Check for failed surefire reports
            $surefireReports = Get-ChildItem -Path $RepoRoot -Recurse -Filter "*.txt" -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName.Replace('\', '/') -match "/target/surefire-reports/" }
            
            $failureReports = @()
            foreach ($report in $surefireReports) {
                $rContent = Get-Content -Path $report.FullName -Raw -ErrorAction SilentlyContinue
                if ($rContent -cmatch "<<< FAILURE!|<<< ERROR!" -or $rContent -match "Failures:\s*[1-9]|Errors:\s*[1-9]") {
                    $failureReports += [PSCustomObject]@{
                        Name = $report.Name
                        Content = $rContent
                    }
                }
            }

            if ($failureReports.Count -gt 0) {
                $Lines.Add("#### Failed Test Reports")
                $Lines.Add("")
                foreach ($fr in $failureReports) {
                    $Lines.Add("##### $($fr.Name)")
                    $Lines.Add("${bt3}text")
                    $Lines.Add($fr.Content.Trim())
                    $Lines.Add($bt3)
                    $Lines.Add("")
                }
            }
        }

        # Frontend Check
        $fePkg = Join-Path $RepoRoot "frontend/package.json"
        if (Test-Path $fePkg) {
            $anyTestsRun = $true
            $Lines.Add("### Frontend Verification (pnpm)")
            $Lines.Add("")
            $feDir = Join-Path $RepoRoot "frontend"
            Write-Host "[*] Executing frontend tests in $feDir..." -ForegroundColor Cyan

            $pnpmCmd = $null
            if (Get-Command pnpm.cmd -ErrorAction SilentlyContinue) {
                $pnpmCmd = "pnpm.cmd"
            } elseif (Get-Command pnpm -ErrorAction SilentlyContinue) {
                $pnpmCmd = "pnpm"
            }

            if ($pnpmCmd) {
                Push-Location $feDir
                try {
                    $env:NO_COLOR = "1"
                    $pkgData = Get-Content $fePkg -Raw | ConvertFrom-Json
                    $hasTestRun = ($pkgData.scripts -and $pkgData.scripts.'test:run')
                    $hasTest = ($pkgData.scripts -and $pkgData.scripts.test)
                    $pnpmArgs = if ($hasTestRun) { @("run", "test:run") } elseif ($hasTest) { @("test", "--", "--run") } else { @("build") }

                    $feOutput = & $pnpmCmd @pnpmArgs 2>&1 | Out-String
                    $feExit = $LASTEXITCODE
                } catch {
                    $feOutput = $_.Exception.Message
                    $feExit = -1
                } finally {
                    $env:NO_COLOR = $null
                    Pop-Location
                }

                $Lines.Add("- **Exit Code**: $feExit")
                $Lines.Add("")
                $Lines.Add("${bt3}text")
                $cleanOutput = $feOutput -replace '\x1B\[[0-9;]*[a-zA-Z]', ''
                $feRaw = $cleanOutput -split "`r?`n" | Where-Object {
                    $_ -notmatch "FullyQualifiedErrorId" -and
                    $_ -notmatch "CategoryInfo" -and
                    $_ -notmatch "NativeCommandError"
                }
                $feMatched = $feRaw | Where-Object {
                    $_ -match "Tests|Passed|Failed|ERR|build|error"
                }
                if ($feMatched) {
                    foreach ($m in $feMatched) { $Lines.Add($m) }
                } else {
                    $feTail = $feRaw | Select-Object -Last 25
                    foreach ($t in $feTail) { $Lines.Add($t) }
                }
                $Lines.Add($bt3)
                $Lines.Add("")
            } else {
                $Lines.Add("> [!WARNING]")
                $Lines.Add("> ${bt}pnpm${bt} command not found on host system PATH.")
                $Lines.Add("")
            }
        }

        if (-not $anyTestsRun) {
            $Lines.Add("> [!NOTE]")
            $Lines.Add("> No test harness detected (neither backend Maven wrapper nor frontend package.json found).")
            $Lines.Add("")
        }
    }

    # -----------------------------------------------------------------------
    # Section 3: Git Diff for Modified Files
    # -----------------------------------------------------------------------
    $Lines.Add("## Section 3: Git Diff for Modified Files")
    $Lines.Add("")

    $diffCount = 0
    foreach ($mFile in $ModifiedFiles) {
        if (Test-IsExcludedPath $mFile) { continue }
        if (Test-IsBinaryPath $mFile) { continue }

        $diffContent = git diff $BaseRef -- $mFile 2>$null | Out-String
        if (-not [string]::IsNullOrWhiteSpace($diffContent)) {
            $diffCount++
            $Lines.Add("### Diff: $mFile")
            $Lines.Add("")
            $Lines.Add("${fence4}diff")
            $Lines.Add($diffContent.TrimEnd())
            $Lines.Add($fence4)
            $Lines.Add("")
        }
    }

    if ($diffCount -eq 0) {
        $Lines.Add("> No diff available for modified files.")
        $Lines.Add("")
    }

    # -----------------------------------------------------------------------
    # Section 4: Full Source of New & Modified Files
    # -----------------------------------------------------------------------
    $Lines.Add("## Section 4: Full Source of New & Modified Files")
    $Lines.Add("")

    $sourceCandidates = [System.Collections.Generic.List[string]]::new()
    foreach ($f in $NewFiles) {
        if (-not $sourceCandidates.Contains($f)) { $sourceCandidates.Add($f) }
    }
    foreach ($f in $ModifiedFiles) {
        if (-not $sourceCandidates.Contains($f)) { $sourceCandidates.Add($f) }
    }

    $sourceCount = 0
    foreach ($filePath in $sourceCandidates) {
        if (Test-IsExcludedPath $filePath) { continue }
        if (Test-IsBinaryPath $filePath) { continue }

        $absPath = Join-Path $RepoRoot $filePath
        if (-not (Test-Path -Path $absPath -PathType Leaf)) { continue }

        $fileItem = Get-Item -Path $absPath
        $fileSize = $fileItem.Length
        $lang = Get-MarkdownLanguage $filePath

        $rawContent = [System.IO.File]::ReadAllText($absPath, [System.Text.Encoding]::UTF8)

        $useFence = $fence4
        if ($rawContent.Contains($fence4)) {
            $useFence = $fence5
        }

        $sourceCount++
        $Lines.Add("### File: $filePath")
        $Lines.Add("")
        $Lines.Add("- **Path**: $bt$filePath$bt")
        $Lines.Add("- **Size**: $fileSize bytes")
        $Lines.Add("")
        $Lines.Add("$useFence$lang")
        $Lines.Add($rawContent.TrimEnd())
        $Lines.Add($useFence)
        $Lines.Add("")
    }

    if ($sourceCount -eq 0) {
        $Lines.Add("> No source files to display.")
        $Lines.Add("")
    }

    # -----------------------------------------------------------------------
    # Write Output File (UTF-8 without BOM)
    # -----------------------------------------------------------------------
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $allText = $Lines -join "`n"
    [System.IO.File]::WriteAllText($OutputFile, $allText, $utf8NoBom)

    Write-Host "[+] Phase audit snapshot generated: $OutputFile" -ForegroundColor Green
    Write-Host "    Size: $((Get-Item $OutputFile).Length) bytes" -ForegroundColor Green
} finally {
    Pop-Location
}
