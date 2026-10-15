<#
.SYNOPSIS
    Generates compact, non-truncating current-state context handoff bundles in docs/audits/snapshots/.

.DESCRIPTION
    Splits the current repository state into 4 focused markdown files (< 120 KB each) so LLM chat
    attachment parsers never truncate the context:
    1. handoff-1-docs.md          : Git log, full tracked file tree, and all docs/*.md + docs/adr/*.md
    2. handoff-2-backend-core.md  : backend/pom.xml, resources, and core modules (identity, projects, engagements, scope, sessions, policy, shared)
    3. handoff-3-backend-tools.md : execution, tools, observations, findings, evidence, llm, reporting
    4. handoff-4-frontend.md      : frontend config files and all frontend/src/** production code (excluding __tests__)
#>

[CmdletBinding()]
param(
    [string]$OutputPrefix = "handoff"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Safe Markdown backtick and fence helpers (avoids PowerShell backtick escaping bugs)
$bt = [char]96
$bt3 = [string]::new($bt, 3)
$fence4 = [string]::new($bt, 4)
$fence5 = [string]::new($bt, 5)

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

    $headCommit = (git rev-parse HEAD).Trim()
    $headShort = (git rev-parse --short HEAD).Trim()
    $headSubject = (git log -1 --format="%s").Trim()
    $branch = (git rev-parse --abbrev-ref HEAD).Trim()
    $timestampUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    function Get-LanguageTag([string]$ext) {
        switch ($ext.ToLowerInvariant()) {
            ".java"       { return "java" }
            ".ts"         { return "typescript" }
            ".vue"        { return "vue" }
            ".js"         { return "javascript" }
            ".yml"        { return "yaml" }
            ".yaml"       { return "yaml" }
            ".sql"        { return "sql" }
            ".css"        { return "css" }
            ".html"       { return "html" }
            ".xml"        { return "xml" }
            ".json"       { return "json" }
            ".md"         { return "markdown" }
            ".ps1"        { return "powershell" }
            ".properties" { return "properties" }
            default       { return "text" }
        }
    }

    function Add-Header([System.Collections.Generic.List[string]]$lines, [string]$title) {
        $lines.Add("# $title")
        $lines.Add("")
        $lines.Add("- **Timestamp (UTC)**: $timestampUtc")
        $lines.Add("- **Commit**: $bt$headShort$bt ($headCommit)")
        $lines.Add("- **Subject**: $headSubject")
        $lines.Add("- **Branch**: $bt$branch$bt")
        $lines.Add("")
        $lines.Add("---")
        $lines.Add("")
    }

    function Add-SourceFiles([System.Collections.Generic.List[string]]$lines, [System.IO.FileInfo[]]$files) {
        foreach ($file in $files) {
            if (-not $file -or -not $file.Exists) { continue }
            $relPath = ($file.FullName.Substring($RepoRoot.Length + 1)).Replace('\', '/')
            $lang = Get-LanguageTag $file.Extension
            $rawContent = [System.IO.File]::ReadAllText($file.FullName, [System.Text.Encoding]::UTF8)

            $useFence = $fence4
            if ($rawContent.Contains($fence4)) {
                $useFence = $fence5
            }

            $lines.Add("### File: $relPath")
            $lines.Add("")
            $lines.Add("${useFence}${lang}")
            $lines.Add($rawContent.TrimEnd())
            $lines.Add($useFence)
            $lines.Add("")
        }
    }

    function Save-Bundle([string]$fileName, [System.Collections.Generic.List[string]]$lines) {
        $outPath = Join-Path $SnapshotsDir $fileName
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($outPath, ($lines -join "`n"), $utf8NoBom)
        $size = (Get-Item $outPath).Length
        Write-Host "[+] Generated $fileName ($size bytes)" -ForegroundColor Green
    }

    # -------------------------------------------------------------------------
    # Part 1: Git History, File Tree, Specifications and ADRs
    # -------------------------------------------------------------------------
    $part1 = [System.Collections.Generic.List[string]]::new()
    Add-Header $part1 "Ospysin Context Handoff - Part 1: Architecture Specs, ADRs and Tree"

    $part1.Add("## 1. Git Commit History (Last 25 Commits)")
    $part1.Add("")
    $part1.Add("${bt3}text")
    $gitLog = (git log -n 25 --oneline) -join "`n"
    $part1.Add($gitLog)
    $part1.Add($bt3)
    $part1.Add("")

    $part1.Add("## 2. Full Tracked File Tree (git ls-files)")
    $part1.Add("")
    $part1.Add("${bt3}text")
    $gitFiles = (git ls-files) -join "`n"
    $part1.Add($gitFiles)
    $part1.Add($bt3)
    $part1.Add("")

    $part1.Add("## 3. Specification and ADR Documentation")
    $part1.Add("")

    $specFiles = @(Get-ChildItem -Path (Join-Path $RepoRoot "docs") -Filter "*.md" -File | Sort-Object Name)
    $adrDir = Join-Path $RepoRoot "docs/adr"
    if (Test-Path -Path $adrDir) {
        $specFiles += @(Get-ChildItem -Path $adrDir -Filter "*.md" -File | Sort-Object Name)
    }
    Add-SourceFiles $part1 $specFiles
    Save-Bundle "$OutputPrefix-1-docs.md" $part1

    # -------------------------------------------------------------------------
    # Part 2: Backend Core (pom.xml, resources, identity, projects, engagements, scope, sessions, policy, shared)
    # -------------------------------------------------------------------------
    $part2 = [System.Collections.Generic.List[string]]::new()
    Add-Header $part2 "Ospysin Context Handoff - Part 2: Backend Core, Security, Policy and Sessions"

    $coreFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $coreFiles.Add((Get-Item (Join-Path $RepoRoot "backend/pom.xml")))

    $backendResources = Join-Path $RepoRoot "backend/src/main/resources"
    if (Test-Path $backendResources) {
        Get-ChildItem -Path $backendResources -Recurse -File | Sort-Object FullName | ForEach-Object { $coreFiles.Add($_) }
    }

    $appJava = Join-Path $RepoRoot "backend/src/main/java/com/ospysin/OspysinApplication.java"
    if (Test-Path $appJava) { $coreFiles.Add((Get-Item $appJava)) }

    $corePackages = @("identity", "projects", "engagements", "scope", "sessions", "policy", "shared")
    foreach ($pkg in $corePackages) {
        $pkgPath = Join-Path $RepoRoot "backend/src/main/java/com/ospysin/$pkg"
        if (Test-Path $pkgPath) {
            Get-ChildItem -Path $pkgPath -Recurse -File | Sort-Object FullName | ForEach-Object { $coreFiles.Add($_) }
        }
    }
    Add-SourceFiles $part2 $coreFiles.ToArray()
    Save-Bundle "$OutputPrefix-2-backend-core.md" $part2

    # -------------------------------------------------------------------------
    # Part 3: Backend Execution Queue, SSE Hub, Tool Catalog and Probes
    # -------------------------------------------------------------------------
    $part3 = [System.Collections.Generic.List[string]]::new()
    Add-Header $part3 "Ospysin Context Handoff - Part 3: Backend Job Queue, SSE Hub, Tools and Probes"

    $toolFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $toolPackages = @("execution", "tools", "observations", "findings", "evidence", "llm", "reporting")
    foreach ($pkg in $toolPackages) {
        $pkgPath = Join-Path $RepoRoot "backend/src/main/java/com/ospysin/$pkg"
        if (Test-Path $pkgPath) {
            Get-ChildItem -Path $pkgPath -Recurse -File | Sort-Object FullName | ForEach-Object { $toolFiles.Add($_) }
        }
    }
    Add-SourceFiles $part3 $toolFiles.ToArray()
    Save-Bundle "$OutputPrefix-3-backend-tools.md" $part3

    # -------------------------------------------------------------------------
    # Part 4: Frontend Production Code and Configuration
    # -------------------------------------------------------------------------
    $part4 = [System.Collections.Generic.List[string]]::new()
    Add-Header $part4 "Ospysin Context Handoff - Part 4: Frontend Production Code (Vue 3 + TS)"

    $feFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    foreach ($cfg in @("frontend/package.json", "frontend/vite.config.ts", "frontend/tsconfig.json", "frontend/tailwind.config.js")) {
        $cfgPath = Join-Path $RepoRoot $cfg
        if (Test-Path $cfgPath) { $feFiles.Add((Get-Item $cfgPath)) }
    }

    $feSrc = Join-Path $RepoRoot "frontend/src"
    if (Test-Path $feSrc) {
        Get-ChildItem -Path $feSrc -Recurse -File |
            Where-Object { $_.FullName.Replace('\', '/') -notmatch '/__tests__/' } |
            Sort-Object FullName |
            ForEach-Object { $feFiles.Add($_) }
    }
    Add-SourceFiles $part4 $feFiles.ToArray()
    Save-Bundle "$OutputPrefix-4-frontend.md" $part4

} finally {
    Pop-Location
}