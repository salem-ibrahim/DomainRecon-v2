[CmdletBinding()]
param(
    [switch]$InstallDependencies,
    [switch]$InstallDevDependencies,
    [switch]$InstallPassiveTools,
    [switch]$InstallTools,
    [switch]$InstallPublicSuffixList
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSCommandPath
$tools = Join-Path $root 'tools'

function Get-Python {
    $pythonRoot = Join-Path $env:LocalAppData 'Programs\Python'
    $candidate = Get-ChildItem $pythonRoot -Directory -Filter 'Python3*' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending |
        ForEach-Object { Join-Path $_.FullName 'python.exe' } |
        Where-Object { Test-Path $_ } |
        Select-Object -First 1
    if (-not $candidate) { throw 'Python 3.12+ is required under %LOCALAPPDATA%\Programs\Python.' }
    return $candidate
}

function Invoke-Python([string[]]$Arguments) {
    & $script:python @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Python exited $LASTEXITCODE" }
}

function Assert-PinnedHttpxVersion([string]$VersionText) {
    $match = [regex]::Match($VersionText, '(?i)\bv?(\d+)\.(\d+)\.(\d+)\b')
    if (-not $match.Success) { throw 'Could not verify HTTPX version; pinned-IP probing is disabled.' }
    $found = [version]::new([int]$match.Groups[1].Value, [int]$match.Groups[2].Value, [int]$match.Groups[3].Value)
    if ($found -lt [version]'1.13.0') {
        throw ("HTTPX $found predates pinned target/IP input support; version 1.13.0 or newer is required. " +
               "As of the last check (2026-11-12) the newest published ProjectDiscovery release was v1.12.0; pinning (PR #2691) exists only on the dev branch. " +
               "No compatible release can be installed until ProjectDiscovery publishes one. A self-built binary may be supplied with --httpx and must pass: python main.py --check-httpx")
    }
}

function Install-VerifiedTool([string]$Tool, [string]$Repository) {
    $destination = Join-Path $tools $Tool
    $exe = Join-Path $destination "$Tool.exe"
    if (Test-Path $exe) {
        $versionOutput = (& $exe -version 2>&1 | Out-String)
        if ($LASTEXITCODE -eq 0) {
            if ($Tool -eq 'httpx') { Assert-PinnedHttpxVersion $versionOutput }
            Write-Host "$Tool verified executable already present; skipped."
            return
        }
    }

    $headers = @{ Accept = 'application/vnd.github+json'; 'User-Agent' = 'DomainRecon-v2' }
    $release = Invoke-RestMethod "https://api.github.com/repos/$Repository/releases/latest" -Headers $headers
    if ($Tool -eq 'httpx') { Assert-PinnedHttpxVersion ([string]$release.tag_name) }
    $zip = $release.assets | Where-Object { $_.name -match "^$Tool.*windows.*amd64.*\.zip$" } | Select-Object -First 1
    $sum = $release.assets | Where-Object { $_.name -match '(?i)(checksums?|sha256).*(txt|sum)$' } | Select-Object -First 1
    if (-not $zip -or -not $sum -or $zip.browser_download_url -notlike "https://github.com/$Repository/*") {
        throw "Official checksum-protected $Tool asset unavailable."
    }

    $temp = Join-Path ([IO.Path]::GetTempPath()) "DomainRecon-v2-$([guid]::NewGuid())"
    New-Item -ItemType Directory $temp | Out-Null
    try {
        $zipPath = Join-Path $temp $zip.name
        $sumPath = Join-Path $temp $sum.name
        Invoke-WebRequest $zip.browser_download_url -OutFile $zipPath -Headers $headers
        Invoke-WebRequest $sum.browser_download_url -OutFile $sumPath -Headers $headers
        $expected = (Get-Content $sumPath | Where-Object { $_ -match [regex]::Escape($zip.name) } | Select-Object -First 1) -replace '^\s*([a-fA-F0-9]{64}).*$', '$1'
        if ($expected -notmatch '^[a-fA-F0-9]{64}$' -or (Get-FileHash $zipPath -Algorithm SHA256).Hash -ine $expected) {
            throw "$Tool SHA-256 verification failed."
        }
        New-Item -ItemType Directory -Force $destination | Out-Null
        Expand-Archive $zipPath $destination -Force
        $found = Get-ChildItem $destination -Filter "$Tool.exe" -Recurse | Select-Object -First 1
        if (-not $found) { throw "$Tool executable missing from verified archive." }
        if ($found.FullName -ne $exe) { Move-Item $found.FullName $exe -Force }
        $versionOutput = (& $exe -version 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) { throw "$Tool post-install check failed." }
        if ($Tool -eq 'httpx') { Assert-PinnedHttpxVersion $versionOutput }
    }
    finally {
        if (Test-Path $temp) { Remove-Item $temp -Recurse -Force }
    }
}

try {
    $script:python = Get-Python
    $version = & $script:python --version
    if ($version -notmatch 'Python 3\.(1[2-9]|[2-9][0-9])') { throw "Unsupported $version" }
    New-Item -ItemType Directory -Force (Join-Path $root 'results'), (Join-Path $root 'logs'), $tools | Out-Null

    if ($InstallDependencies -and (Read-Host 'Install requirements.txt? Type YES') -eq 'YES') {
        Invoke-Python @('-m', 'pip', 'install', '-r', (Join-Path $root 'requirements.txt'))
    }
    if ($InstallDevDependencies -and (Read-Host 'Install requirements-dev.txt? Type YES') -eq 'YES') {
        Invoke-Python @('-m', 'pip', 'install', '-r', (Join-Path $root 'requirements-dev.txt'))
    }
    if ($InstallPassiveTools -and (Read-Host 'Install checksum-verified Subfinder and DNSx only? Type YES') -eq 'YES') {
        Install-VerifiedTool subfinder projectdiscovery/subfinder
        Install-VerifiedTool dnsx projectdiscovery/dnsx
    }
    if ($InstallTools -and (Read-Host 'Install verified Subfinder, DNSx and HTTPX? Type YES') -eq 'YES') {
        Install-VerifiedTool subfinder projectdiscovery/subfinder
        Install-VerifiedTool dnsx projectdiscovery/dnsx
        Install-VerifiedTool httpx projectdiscovery/httpx
        # Local loopback-only validation: version plus IPv4/IPv6 pinning gates. No external target is contacted.
        Push-Location $root
        try { & $script:python main.py --check-httpx; if ($LASTEXITCODE -ne 0) { Write-Warning 'HTTPX installed but did not pass the pinning gates; HTTP probing stays disabled.' } }
        finally { Pop-Location }
    }
    if ($InstallPublicSuffixList -and (Read-Host 'Download the official Public Suffix List from https://publicsuffix.org/? Type YES') -eq 'YES') {
        Push-Location $root
        try { Invoke-Python @('main.py', '--update-psl', '--confirm-download') }
        finally { Pop-Location }
    }

    Invoke-Python @('-m', 'compileall', '-q', (Join-Path $root 'domainrecon'))
    exit 0
}
catch {
    Write-Error $_
    exit 1
}
