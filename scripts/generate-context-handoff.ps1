<#
.SYNOPSIS
    Generates a compact current-state context bundle at docs/audits/snapshots/context-handoff-p10.md.

.DESCRIPTION
    Collects:
    1. Git commit log (last 20 commits) and full tracked file tree (git ls-files).
    2. All specification and ADR markdown files in docs/*.md and docs/adr/*.md.
    3. All production source and configuration files (backend/pom.xml, backend/src/main/**,
       frontend/package.json, frontend/vite.config.ts, frontend/src/** excluding tests).
#>

[CmdletBinding()]
param(
    [string]$OutputFile = "docs/audits/snapshots/context-handoff-p10.md"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$RepoRoot = (Get-Location).Path
$TargetFilePath = Join-Path $RepoRoot $OutputFile
$TargetDir = Split-Path -Parent $TargetFilePath
if (-not (Test-Path -Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
}

$sb = [System.Text.StringBuilder]::new()

function Append-Line([string]$line = "") {
    [void]$sb.AppendLine($line)
}

$headCommit = (git rev-parse HEAD).Trim()
$headSubject = (git log -1 --format="%s").Trim()
$timestampUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

Append-Line "# Ospysin Project: Current-State Context Handoff (Phase 10 HEAD)"
Append-Line ""
Append-Line "**Timestamp:** $timestampUtc  "
Append-Line "**Commit:** $headCommit ($headSubject)  "
Append-Line "**Branch:** main  "
Append-Line ""
Append-Line "---"
Append-Line ""
Append-Line "## 1. Git Commit History & Tracked File Tree"
Append-Line ""
Append-Line "### Git Log (Last 20 Commits)"
Append-Line ""
Append-Line '```text'
$gitLog = (git log -n 20 --oneline) -join "`n"
Append-Line $gitLog
Append-Line '```'
Append-Line ""
Append-Line "### Full Tracked File Tree (git ls-files)"
Append-Line ""
Append-Line '```text'
$gitFiles = (git ls-files) -join "`n"
Append-Line $gitFiles
Append-Line '```'
Append-Line ""
Append-Line "---"
Append-Line ""
Append-Line "## 2. Specification & ADR Documentation"
Append-Line ""

$specFiles = @(Get-ChildItem -Path (Join-Path $RepoRoot "docs") -Filter "*.md" -File | Sort-Object Name)
$adrDir = Join-Path $RepoRoot "docs/adr"
if (Test-Path -Path $adrDir) {
    $specFiles += @(Get-ChildItem -Path $adrDir -Filter "*.md" -File | Sort-Object Name)
}

foreach ($file in $specFiles) {
    $relPath = ($file.FullName.Substring($RepoRoot.Length + 1)).Replace("\", "/")
    Append-Line "### $relPath"
    Append-Line ""
    Append-Line '````markdown'
    $content = [System.IO.File]::ReadAllText($file.FullName, [System.Text.Encoding]::UTF8)
    Append-Line $content
    Append-Line '````'
    Append-Line ""
}

Append-Line "---"
Append-Line ""
Append-Line "## 3. Production Source & Configuration Files"
Append-Line ""

$prodFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

$pomFile = Get-Item -Path (Join-Path $RepoRoot "backend/pom.xml")
$prodFiles.Add($pomFile)

$backendMain = Join-Path $RepoRoot "backend/src/main"
if (Test-Path -Path $backendMain) {
    Get-ChildItem -Path $backendMain -Recurse -File | Sort-Object FullName | ForEach-Object { $prodFiles.Add($_) }
}

$frontendPkg = Get-Item -Path (Join-Path $RepoRoot "frontend/package.json")
$prodFiles.Add($frontendPkg)

$frontendVite = Get-Item -Path (Join-Path $RepoRoot "frontend/vite.config.ts")
$prodFiles.Add($frontendVite)

$frontendSrc = Join-Path $RepoRoot "frontend/src"
if (Test-Path -Path $frontendSrc) {
    Get-ChildItem -Path $frontendSrc -Recurse -File | Where-Object { $_.FullName -notmatch '__tests__' } | Sort-Object FullName | ForEach-Object { $prodFiles.Add($_) }
}

function Get-LanguageTag([string]$ext) {
    switch ($ext.ToLowerInvariant()) {
        ".java" { return "java" }
        ".ts" { return "typescript" }
        ".vue" { return "html" }
        ".yml" { return "yaml" }
        ".yaml" { return "yaml" }
        ".sql" { return "sql" }
        ".css" { return "css" }
        ".xml" { return "xml" }
        ".json" { return "json" }
        ".md" { return "markdown" }
        default { return "text" }
    }
}

foreach ($file in $prodFiles) {
    $relPath = ($file.FullName.Substring($RepoRoot.Length + 1)).Replace("\", "/")
    $lang = Get-LanguageTag $file.Extension
    Append-Line "### $relPath"
    Append-Line ""
    Append-Line "```$lang"
    $content = [System.IO.File]::ReadAllText($file.FullName, [System.Text.Encoding]::UTF8)
    Append-Line $content
    Append-Line '```'
    Append-Line ""
}

[System.IO.File]::WriteAllText($TargetFilePath, $sb.ToString(), [System.Text.Encoding]::UTF8)

$size = (Get-Item $TargetFilePath).Length
Write-Host "Successfully generated context bundle at $TargetFilePath ($size bytes)"
