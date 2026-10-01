# Fetches the Xenolith packer CLI from GitHub Releases, preferring CN mirrors,
# and verifies the extracted xenolith.exe against the release manifest before
# writing it. Called by build-release.bat when no local xenolith.exe was found.
#
# Env knobs:
#   XENOLITH_RELEASE_TAG  pin a release tag (e.g. v1.0.0-rc.4); default resolves
#                         the latest release that actually ships a Windows zip
#   XENOLITH_MIRRORS      semicolon-separated URL prefixes tried before direct
#                         github.com (prefix + full URL); "-" disables mirrors
#   XENOLITH_SHA256       optional hard pin; a mismatch fails the fetch
param(
    [string]$OutPath = ""
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$RepoOwner = 'HHT0rro'
$RepoName = 'Xenolith'
$DefaultMirrors = 'https://ghfast.top/;https://gh-proxy.com/;https://ghproxy.net/'

function Fail([string]$Message) {
    Write-Host "fetch-xenolith: $Message" -ForegroundColor Red
    exit 1
}

if ([string]::IsNullOrWhiteSpace($OutPath)) {
    $OutPath = Join-Path $PSScriptRoot 'embedded\xenolith.exe'
}

$Mirrors = $DefaultMirrors
if ($env:XENOLITH_MIRRORS) {
    $Mirrors = $env:XENOLITH_MIRRORS
}
$MirrorList = @()
if ($Mirrors -ne '-') {
    $MirrorList = $Mirrors.Split(';') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() }
}

# 1. Resolve the release tag and the Windows zip asset URL.
$AssetUrl = $null
$AssetName = $null
$Tag = $env:XENOLITH_RELEASE_TAG
if (-not $Tag) {
    try {
        $Releases = Invoke-RestMethod -Uri "https://api.github.com/repos/$RepoOwner/$RepoName/releases?per_page=10" `
            -Headers @{ 'User-Agent' = 'javashroud-build' } -TimeoutSec 60
    } catch {
        Fail ("GitHub releases API unreachable ({0}); set XENOLITH_RELEASE_TAG or provide xenolith.exe locally (XENOLITH_EXE)" -f $_.Exception.Message)
    }
    foreach ($Release in $Releases) {
        $Asset = $Release.assets | Where-Object { $_.name -like '*-Windows.zip' } | Select-Object -First 1
        if ($Asset) {
            $Tag = $Release.tag_name
            $AssetUrl = $Asset.browser_download_url
            $AssetName = $Asset.name
            break
        }
    }
    if (-not $AssetUrl) {
        Fail 'no Xenolith release with a *-Windows.zip asset was found'
    }
} else {
    try {
        $Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$RepoOwner/$RepoName/releases/tags/$Tag" `
            -Headers @{ 'User-Agent' = 'javashroud-build' } -TimeoutSec 60
    } catch {
        Fail ("release tag $Tag not found ({0})" -f $_.Exception.Message)
    }
    $Asset = $Release.assets | Where-Object { $_.name -like '*-Windows.zip' } | Select-Object -First 1
    if (-not $Asset) {
        Fail "release $Tag has no *-Windows.zip asset"
    }
    $AssetUrl = $Asset.browser_download_url
    $AssetName = $Asset.name
}

# 2. Download the zip through the mirror chain (direct github.com is the last resort).
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("javashroud-fetch-xenolith-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TempDir | Out-Null
$ZipPath = Join-Path $TempDir $AssetName
$Candidates = @()
foreach ($Prefix in $MirrorList) { $Candidates += $Prefix }
$Candidates += ''
try {
    $Downloaded = $false
    foreach ($Prefix in $Candidates) {
        $Url = "$Prefix$AssetUrl"
        $Label = if ($Prefix) { $Prefix } else { 'direct' }
        try {
            Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing -TimeoutSec 300
            if ((Get-Item $ZipPath).Length -lt 1024) { throw "suspiciously small download ($Label)" }
            Write-Host "fetch-xenolith: downloaded $AssetName via $Label"
            $Downloaded = $true
            break
        } catch {
            Write-Host "fetch-xenolith: mirror $Label failed ($($_.Exception.Message)); trying next" -ForegroundColor Yellow
        }
    }
    if (-not $Downloaded) {
        Fail "all download candidates failed for $AssetUrl (mirrors: $($MirrorList -join ', '))"
    }

    # 3. Extract and verify against the in-zip release manifest (fail-closed).
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $Archive = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $ManifestEntry = $Archive.Entries | Where-Object { $_.Name -eq 'manifest.json' } | Select-Object -First 1
        $ExeEntry = $Archive.Entries | Where-Object { $_.Name -eq 'xenolith.exe' } | Select-Object -First 1
        if (-not $ManifestEntry -or -not $ExeEntry) {
            Fail 'release zip is missing xenolith.exe or manifest.json'
        }
        $ManifestReader = New-Object System.IO.StreamReader($ManifestEntry.Open())
        $Manifest = $ManifestReader.ReadToEnd() | ConvertFrom-Json
        $ManifestReader.Close()
        $ManifestDigest = ($Manifest.artifacts | Where-Object { $_.name -eq 'xenolith.exe' }).sha256
        if (-not $ManifestDigest) {
            Fail 'manifest.json carries no sha256 for xenolith.exe'
        }
        $ExeTemp = Join-Path $TempDir 'xenolith.exe'
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($ExeEntry, $ExeTemp, $true)
        $Sha = [System.Security.Cryptography.SHA256]::Create()
        $Stream = [System.IO.File]::OpenRead($ExeTemp)
        $ActualDigest = ([System.BitConverter]::ToString($Sha.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant()
        $Stream.Close()
        if ($ActualDigest -ne $ManifestDigest.ToLowerInvariant()) {
            Fail ("sha256 mismatch: manifest=$ManifestDigest actual=$ActualDigest")
        }
        if ($env:XENOLITH_SHA256 -and $ActualDigest -ne $env:XENOLITH_SHA256.ToLowerInvariant()) {
            Fail ("sha256 pin mismatch: XENOLITH_SHA256=$($env:XENOLITH_SHA256) actual=$ActualDigest")
        }

        # 4. Atomic publish.
        $OutDir = Split-Path -Parent $OutPath
        if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
        $Staged = "$OutPath.tmp"
        Copy-Item $ExeTemp $Staged -Force
        Move-Item $Staged $OutPath -Force
        Write-Host "fetch-xenolith: wrote $OutPath tag=$Tag sha256=$ActualDigest"
        exit 0
    } finally {
        $Archive.Dispose()
    }
} finally {
    Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
