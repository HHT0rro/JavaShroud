# Formal Windows builds use XENOLITH_SHA256 from a trusted, independent source.
# Set XENOLITH_RELEASE_TAG to fetch that release, or XENOLITH_EXE for a local file.
# XENOLITH_VERSION optionally identifies a local build without executing it.
# XENOLITH_MIRRORS is a semicolon-separated prefix list; '-' uses GitHub directly.
param(
    [string]$OutPath,
    [switch]$RequirePin,
    [string]$ZipFrom,
    [string]$VerifyZip,
    [string]$PublishRelease,
    [string]$ReleaseInputRoot,
    [string]$DesktopExe,
    [string]$EngineExe,
    [string]$XenolithDirectory,
    [switch]$ExpectXenolith,
    [ValidateSet('Restore', 'Save')][string]$NativeCache
)

$ErrorActionPreference = 'Stop'
$RepoUrl = 'https://github.com/HHT0rro/Xenolith'
$DigestPattern = '\A[0-9a-fA-F]{64}\z'
$Pin = $env:XENOLITH_SHA256
$Tag = $env:XENOLITH_RELEASE_TAG
$InfoName = 'xenolith-info.json'
$LegalFiles = @('LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md')
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Read-EntryJson($Entry) {
    $reader = [IO.StreamReader]::new($Entry.Open())
    try { ConvertFrom-Json -InputObject $reader.ReadToEnd() }
    finally { $reader.Dispose() }
}

function Get-StreamSha256([IO.Stream]$Stream) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($sha.ComputeHash($Stream)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-PathSha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    try { Get-StreamSha256 $stream }
    finally { $stream.Dispose() }
}

function Get-PlainPath([string]$Path, [switch]$Directory, [switch]$AllowMissing) {
    $provider = $null
    $drive = $null
    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path, [ref]$provider, [ref]$drive)
    if ($provider.Name -ne 'FileSystem' -or $fullPath -match '^[\\/]{2}[?.][\\/]' -or
        ($fullPath -replace '^[A-Za-z]:') -match ':' -or
        $Path -match '(?:^|[\\/])(?!\.{1,2}(?:[\\/]|$))[^\\/]*[. ](?:[\\/]|$)' -or
        $fullPath -match '(?:^|[\\/])(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(?:\.[^\\/]*)?(?:[\\/]|$)' -or
        (-not $Directory -and $Path -match '[\\/]$')) {
        throw "Expected a plain filesystem path: $Path"
    }
    $fullPath = [IO.Path]::GetFullPath($fullPath)
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ($fullPath.Length -gt $root.Length) { $fullPath = $fullPath.TrimEnd([char[]]@('\', '/')) }
    $item = $null
    try { $item = Get-Item -LiteralPath $fullPath -Force }
    catch [System.Management.Automation.ItemNotFoundException] { if (-not $AllowMissing) { throw } }
    if ($null -ne $item -and ($item.PSIsContainer -ne [bool]$Directory -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.LinkType -eq 'HardLink' -or
        $item.FullName -ine $fullPath)) {
        throw "Expected a plain $(if ($Directory) { 'directory' } else { 'file' }) at $fullPath."
    }
    for ($parent = [IO.Directory]::GetParent($fullPath); $parent; $parent = $parent.Parent) {
        if ($parent.Exists -and ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Release path crosses a directory link: $($parent.FullName)"
        }
    }
    $fullPath
}

function Set-VerifiedFile([string]$Stage, [string]$Destination, [string]$Backup) {
    $Destination = Get-PlainPath $Destination -AllowMissing
    if ([IO.File]::Exists($Destination)) {
        if ($Backup) { [IO.File]::Replace($Stage, $Destination, $Backup) }
        else { [IO.File]::Replace($Stage, $Destination, [NullString]::Value) }
    } else {
        [IO.File]::Move($Stage, $Destination)
    }
}

function Assert-PinConfiguration([switch]$Required) {
    if (($Required -or $Pin) -and $Pin -notmatch $DigestPattern) {
        throw 'Set XENOLITH_SHA256 to an independently obtained 64-digit SHA-256 digest.'
    }
}

function Assert-PinMatch([string]$Actual) {
    if ($Pin -and $Actual -ne $Pin) {
        throw "Xenolith SHA-256 pin mismatch: expected $Pin, found $Actual."
    }
}

function Get-PackageNames($Info) {
    if ($Info.included -isnot [bool]) { throw 'Invalid Xenolith inclusion flag.' }
    if ($Info.included) {
        if ($Info.source -isnot [string] -or [string]::IsNullOrWhiteSpace($Info.source) -or
            $Info.version -isnot [string] -or [string]::IsNullOrWhiteSpace($Info.version) -or
            $Info.sha256 -isnot [string] -or $Info.sha256 -notmatch $DigestPattern) {
            throw 'Invalid Xenolith source, version, or SHA-256 in the release manifest.'
        }
        if ($Tag -and ($Info.version -cne $Tag -or -not $Info.source.StartsWith("$RepoUrl/releases/download/", [StringComparison]::OrdinalIgnoreCase))) {
            throw 'The release manifest does not identify the configured Xenolith release.'
        }
        'tools/xenolith.exe'
    } elseif ($Pin -or $RequirePin) {
        throw 'The release ZIP does not include the pinned Xenolith executable.'
    }
    $LegalFiles
    'README.txt', 'engine/obfuscator-engine.exe', 'javashroud.exe', $InfoName
}

function Assert-ReleaseZip([string]$Path, [hashtable]$ExpectedHashes) {
    $Path = Get-PlainPath $Path
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $manifests = @($archive.Entries | Where-Object { $_.FullName -ceq $InfoName })
        if ($manifests.Count -ne 1) { throw "Expected exactly one $InfoName in the release ZIP." }
        $info = Read-EntryJson $manifests[0]
        $names = @(Get-PackageNames $info)
        if ($archive.Entries.Count -ne $names.Count) { throw 'Unexpected number of entries in the release ZIP.' }
        foreach ($name in $names) {
            $entries = @($archive.Entries | Where-Object { $_.FullName -ceq $name })
            if ($entries.Count -ne 1 -or $entries[0].Length -eq 0) {
                throw "Missing, duplicate, or empty release ZIP entry: $name"
            }
            if ($ExpectedHashes -and $ExpectedHashes.ContainsKey($name)) {
                $stream = $entries[0].Open()
                try { $digest = Get-StreamSha256 $stream }
                finally { $stream.Dispose() }
                if ($digest -ne $ExpectedHashes[$name]) { throw "ZIP entry differs from staged release file: $name" }
            }
        }
        if ($info.included) {
            $stream = $archive.GetEntry('tools/xenolith.exe').Open()
            try { $actual = Get-StreamSha256 $stream }
            finally { $stream.Dispose() }
            if ($actual -ne $info.sha256) { throw 'ZIP Xenolith executable does not match xenolith-info.json.' }
            Assert-PinMatch $actual
        }
    } finally {
        $archive.Dispose()
    }
}

function Write-ReleaseZip([string]$Directory, [string]$Path, [hashtable]$ExpectedHashes) {
    $Directory = Get-PlainPath $Directory -Directory
    $Path = Get-PlainPath $Path -AllowMissing
    $manifestPath = Get-PlainPath (Join-Path $Directory $InfoName)
    $info = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $names = @(Get-PackageNames $info)
    [Array]::Sort($names, [StringComparer]::Ordinal)
    $tempZip = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $archive = [IO.Compression.ZipFile]::Open($tempZip, [IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($name in $names) {
                $file = Get-PlainPath (Join-Path $Directory $name)
                if ($file -ieq $Path) { throw "The ZIP destination aliases a release input: $name" }
                $entry = $archive.CreateEntry($name, [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
                $inputStream = [IO.File]::OpenRead($file)
                try {
                    $entryStream = $entry.Open()
                    try { $inputStream.CopyTo($entryStream) }
                    finally { $entryStream.Dispose() }
                } finally {
                    $inputStream.Dispose()
                }
            }
        } finally {
            $archive.Dispose()
        }
        Assert-ReleaseZip $tempZip $ExpectedHashes
        Set-VerifiedFile $tempZip $Path
    } finally {
        Remove-Item -LiteralPath $tempZip -Force -ErrorAction SilentlyContinue
    }
}

function Publish-ReleasePair {
    $directory = Get-PlainPath $PublishRelease -Directory -AllowMissing
    $zip = Get-PlainPath $OutPath -AllowMissing
    $parent = [IO.Path]::GetDirectoryName($directory)
    if (-not $parent -or $parent -ine [IO.Path]::GetDirectoryName($zip) -or $directory -ieq $zip) {
        throw 'The release directory and ZIP must be distinct siblings.'
    }
    $lockPath = Get-PlainPath (Join-Path $parent '.javashroud-release.lock') -AllowMissing
    if ($zip -ieq $lockPath -or $directory -ieq $lockPath) { throw 'A release destination aliases its publication lock.' }

    $inputs = @{ 'javashroud.exe' = $DesktopExe; 'engine/obfuscator-engine.exe' = $EngineExe; $InfoName = (Join-Path $XenolithDirectory $InfoName) }
    foreach ($name in $LegalFiles) { $inputs[$name] = Join-Path $ReleaseInputRoot $name }
    if ($ExpectXenolith) { $inputs['tools/xenolith.exe'] = Join-Path $XenolithDirectory 'xenolith.exe' }
    foreach ($name in @($inputs.Keys)) {
        $source = Get-PlainPath $inputs[$name]
        if ($source -ieq $zip -or $source.StartsWith($directory + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Release destination aliases an input: $source"
        }
        $inputs[$name] = $source
    }

    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $work = Join-Path $parent ('.release-' + [guid]::NewGuid().ToString('N'))
    $stage = Join-Path $work 'directory'
    $stageZip = Join-Path $work 'package.zip'
    $prior = Join-Path $work 'prior-directory'
    $priorZip = Join-Path $work 'prior.zip'
    $preserveWork = $false
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    try {
        $hashes = @{}
        foreach ($name in $inputs.Keys) {
            $source = $inputs[$name]
            $target = Join-Path $stage $name
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
            $hashes[$name] = Get-PathSha256 $source
            [IO.File]::Copy($source, $target)
            if ((Get-PathSha256 $target) -ne $hashes[$name]) { throw "Release copy differs from its source: $name" }
        }
        $info = Get-Content -LiteralPath (Join-Path $stage $InfoName) -Raw | ConvertFrom-Json
        if ($info.included -isnot [bool] -or $info.included -ne [bool]$ExpectXenolith) {
            throw 'Xenolith release metadata disagrees with the desktop build inputs.'
        }
        $readme = @('JavaShroud Windows AMD64 Release', '', 'Files:', '- javashroud.exe', '- engine\obfuscator-engine.exe')
        if ($ExpectXenolith) { $readme += '- tools\xenolith.exe (GPL-3.0, source: https://github.com/HHT0rro/Xenolith)' }
        $readme += '- xenolith-info.json', '- LICENSE, NOTICE, THIRD_PARTY_NOTICES.md'
        $readmePath = Join-Path $stage 'README.txt'
        [IO.File]::WriteAllLines($readmePath, $readme, [Text.UTF8Encoding]::new($false))
        $hashes['README.txt'] = Get-PathSha256 $readmePath
        Write-ReleaseZip $stage $stageZip $hashes

        $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $null = Get-PlainPath $directory -Directory -AllowMissing
            $null = Get-PlainPath $zip -AllowMissing
            $oldDirectoryMoved = $false
            $newDirectoryMoved = $false
            try {
                if ([IO.Directory]::Exists($directory)) {
                    [IO.Directory]::Move($directory, $prior)
                    $oldDirectoryMoved = $true
                }
                [IO.Directory]::Move($stage, $directory)
                $newDirectoryMoved = $true
                # Commit the verified ZIP last. File.Replace preserves a backup of the previous ZIP.
                Set-VerifiedFile $stageZip $zip $priorZip
            } catch {
                $promotionError = $_
                $rollbackErrors = @()
                if ([IO.File]::Exists($priorZip)) {
                    try { Set-VerifiedFile $priorZip $zip }
                    catch { $rollbackErrors += $_.Exception.Message }
                }
                if ($newDirectoryMoved) {
                    try { [IO.Directory]::Move($directory, $stage) }
                    catch { $rollbackErrors += $_.Exception.Message }
                }
                if ($oldDirectoryMoved) {
                    try { [IO.Directory]::Move($prior, $directory) }
                    catch { $rollbackErrors += $_.Exception.Message }
                }
                if ($rollbackErrors.Count) {
                    $preserveWork = $true
                    throw "Release promotion failed: $promotionError. Rollback failed: $($rollbackErrors -join ' | '). Recovery files: $work"
                }
                throw $promotionError
            }
        } finally {
            $lock.Dispose()
        }
    } finally {
        if (-not $preserveWork) {
            try { [IO.Directory]::Delete($work, $true) }
            catch { Write-Warning "Could not remove release workspace $work. $($_.Exception.Message)" }
        }
    }
    Write-Host "Published verified release directory and ZIP: $zip"
}

function Get-NativeCacheInputs {
    $inputs = [ordered]@{
        jar = Get-PathSha256 $env:ENGINE_JAR
        resourceConfig = Get-PathSha256 $env:ENGINE_RESOURCE_CONFIG
        batchScript = Get-PathSha256 $env:NATIVE_BUILD_SCRIPT
        nativeImage = Get-PathSha256 $env:NATIVE_IMAGE_CMD
        nativeImagePath = $env:NATIVE_IMAGE_CMD
        vcvarsall = Get-PathSha256 $env:VCVARSALL
        nativeArguments = $env:NATIVE_IMAGE_TUNING_ARGS
    }
    $graalBin = [IO.Path]::GetDirectoryName($env:NATIVE_IMAGE_CMD)
    foreach ($name in @('native-image.exe', 'java.exe', '..\release')) {
        $path = Join-Path $graalBin $name
        if ([IO.File]::Exists($path)) { $inputs[$name] = Get-PathSha256 $path }
    }
    foreach ($name in @('cl.exe', 'link.exe')) {
        $tool = Get-Command -Name $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($tool) { $inputs[$name] = Get-PathSha256 $tool.Source }
    }
    $inputs
}

function Invoke-NativeCache {
    $output = Join-Path $env:NATIVE_OUTPUT_DIR 'obfuscator-engine.exe'
    $snapshot = Join-Path $env:NATIVE_OUTPUT_DIR 'native-inputs.json'
    $inputs = Get-NativeCacheInputs
    $inputJson = $inputs | ConvertTo-Json -Compress
    if ($NativeCache -eq 'Restore') {
        [IO.File]::WriteAllText($snapshot, $inputJson)
        if ($env:ENGINE_NATIVE_CACHE_DISABLED) { return $false }
    } else {
        if ([IO.File]::ReadAllText($snapshot) -cne $inputJson) { throw 'Native build inputs changed during compilation.' }
        if ($env:ENGINE_NATIVE_CACHE_DISABLED) { return $true }
    }

    $recordPath = Get-PlainPath $OutPath -AllowMissing
    $cacheDirectory = [IO.Path]::GetDirectoryName($recordPath)
    $cachedOutput = Get-PlainPath (Join-Path $cacheDirectory 'obfuscator-engine.exe') -AllowMissing
    $lockPath = Get-PlainPath (Join-Path $cacheDirectory '.native-cache.lock') -AllowMissing
    $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        if ($NativeCache -eq 'Restore') {
            if (-not ([IO.File]::Exists($recordPath) -and [IO.File]::Exists($cachedOutput))) { return $false }
            try { $record = [IO.File]::ReadAllText($recordPath) | ConvertFrom-Json }
            catch { return $false }
            if ($record.version -ne 2 -or $record.outputSha256 -notmatch $DigestPattern -or
                ($record.inputs | ConvertTo-Json -Compress) -cne $inputJson) { return $false }
            try {
                [IO.File]::Copy($cachedOutput, $output)
                if (([IO.FileInfo]::new($output)).Length -gt 0 -and (Get-PathSha256 $output) -eq $record.outputSha256) {
                    return $true
                }
            } catch {
                # A standalone build can replace the shared executable while the release stages it.
            }
            [IO.File]::Delete($output)
            return $false
        }

        $tempOutput = "$cachedOutput.$([guid]::NewGuid().ToString('N')).tmp"
        $tempRecord = "$recordPath.$([guid]::NewGuid().ToString('N')).tmp"
        try {
            $outputHash = Get-PathSha256 $output
            [IO.File]::Copy($output, $tempOutput)
            if ((Get-PathSha256 $tempOutput) -ne $outputHash) { throw 'Native executable changed while staging its cache entry.' }
            $record = [ordered]@{ version = 2; inputs = $inputs; outputSha256 = $outputHash }
            [IO.File]::WriteAllText($tempRecord, ($record | ConvertTo-Json -Compress))
            Set-VerifiedFile $tempOutput $cachedOutput
            Set-VerifiedFile $tempRecord $recordPath
        } finally {
            [IO.File]::Delete($tempOutput)
            [IO.File]::Delete($tempRecord)
        }
        return $true
    } finally {
        $lock.Dispose()
    }
}

function Get-ReleaseExecutable([string]$ZipPath, [string]$StagePath) {
    $archive = [IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $manifests = @($archive.Entries | Where-Object { $_.Name -ceq 'manifest.json' })
        $executables = @($archive.Entries | Where-Object { $_.Name -ceq 'xenolith.exe' })
        if ($manifests.Count -ne 1 -or $executables.Count -ne 1 -or $executables[0].Length -eq 0) {
            throw 'Xenolith release ZIP must contain one manifest.json and one nonempty xenolith.exe.'
        }
        $manifest = Read-EntryJson $manifests[0]
        $records = @($manifest.artifacts | Where-Object { $_.name -ceq 'xenolith.exe' })
        if ($records.Count -ne 1 -or $records[0].sha256 -isnot [string] -or $records[0].sha256 -notmatch $DigestPattern) {
            throw 'The Xenolith manifest must contain exactly one valid executable digest.'
        }
        [IO.Compression.ZipFileExtensions]::ExtractToFile($executables[0], $StagePath, $true)
        $actual = Get-PathSha256 $StagePath
        if ($actual -ne $records[0].sha256) { throw 'Xenolith executable does not match the upstream manifest.' }
        Assert-PinMatch $actual
        $actual
    } finally {
        $archive.Dispose()
    }
}

function Get-RemoteXenolith([string]$StagePath) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $encodedTag = [Uri]::EscapeDataString($Tag)
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/HHT0rro/Xenolith/releases/tags/$encodedTag" -Headers @{ 'User-Agent' = 'javashroud-build' } -TimeoutSec 60
    $assets = @($release.assets | Where-Object { $_.name -like '*-Windows.zip' })
    if ($release.tag_name -cne $Tag -or $assets.Count -ne 1) {
        throw "Expected exactly one Xenolith Windows ZIP for configured tag $Tag."
    }
    $assetUrl = $assets[0].browser_download_url
    if ($assetUrl -isnot [string] -or -not $assetUrl.StartsWith("$RepoUrl/releases/download/", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Invalid Xenolith asset URL for configured tag $Tag."
    }

    $prefixes = @()
    if ($env:XENOLITH_MIRRORS -ne '-') {
        $mirrors = if ($env:XENOLITH_MIRRORS) { $env:XENOLITH_MIRRORS } else { 'https://ghfast.top/;https://gh-proxy.com/;https://ghproxy.net/' }
        $prefixes = @($mirrors.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    $zipPath = "$StagePath.zip"
    try {
        foreach ($prefix in ($prefixes + '')) {
            try {
                Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
                Invoke-WebRequest -Uri "$prefix$assetUrl" -OutFile $zipPath -UseBasicParsing -TimeoutSec 300
                $digest = Get-ReleaseExecutable $zipPath $StagePath
                return [ordered]@{ included = $true; source = $assetUrl; version = $Tag; sha256 = $digest }
            } catch {
                $label = if ($prefix) { $prefix } else { 'GitHub directly' }
                Write-Warning "Xenolith fetch via ${label} failed: $($_.Exception.Message)"
            }
        }
        throw "No download for Xenolith tag $Tag passed SHA-256 verification."
    } finally {
        Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
    }
}

if ($NativeCache) {
    if (Invoke-NativeCache) { exit 0 }
    exit 20
}

if ($PublishRelease -or $ZipFrom -or $VerifyZip) {
    Assert-PinConfiguration -Required:$RequirePin
    if ($PublishRelease) {
        if ($ZipFrom -or $VerifyZip -or -not ($OutPath -and $ReleaseInputRoot -and $DesktopExe -and $EngineExe -and $XenolithDirectory)) {
            throw 'Release publication requires its directory, ZIP, and build inputs.'
        }
        Publish-ReleasePair
    } elseif ($VerifyZip) {
        Assert-ReleaseZip $VerifyZip
        Write-Host "Verified release ZIP: $VerifyZip"
    } else {
        if (-not $OutPath) { throw 'Set -OutPath to the destination release ZIP.' }
        Write-ReleaseZip $ZipFrom $OutPath
        Write-Host "Wrote verified release ZIP: $OutPath"
    }
    return
}

if (-not $OutPath) { $OutPath = Join-Path $PSScriptRoot 'embedded/xenolith.exe' }
$OutPath = Get-PlainPath $OutPath -AllowMissing
$outDir = Split-Path -Parent $OutPath
$infoPath = Get-PlainPath (Join-Path $outDir $InfoName) -AllowMissing
if ($OutPath -ieq $infoPath) { throw 'The Xenolith executable destination aliases its manifest.' }
Assert-PinConfiguration -Required:($RequirePin -or [bool]$Tag)
$localPath = $null
$source = $null
if ($env:XENOLITH_EXE) {
    $localPath = Get-PlainPath $env:XENOLITH_EXE
    $source = 'local:explicit'
}
if ($localPath -and $Tag) { throw 'Choose either XENOLITH_EXE or XENOLITH_RELEASE_TAG.' }
if (($RequirePin -or $Pin) -and -not ($localPath -or $Tag)) {
    throw 'A pinned Xenolith requires XENOLITH_EXE or XENOLITH_RELEASE_TAG.'
}

if (-not ($localPath -or $Tag)) {
    $fallbacks = [ordered]@{}
    if ($env:XENOLITH_DIST) { $fallbacks['local:dist'] = Join-Path $env:XENOLITH_DIST 'xenolith.exe' }
    $fallbacks['local:sibling-target-release'] = Join-Path $PSScriptRoot '../../Xenolith/target/release/xenolith.exe'
    $fallbacks['local:sibling-dist'] = Join-Path $PSScriptRoot '../../Xenolith/dist/xenolith.exe'
    foreach ($candidate in $fallbacks.GetEnumerator()) {
        if (Test-Path -LiteralPath $candidate.Value -PathType Leaf) {
            $localPath = Get-PlainPath $candidate.Value
            $source = $candidate.Key
            break
        }
    }
}
if ($localPath -ieq $infoPath) { throw 'The Xenolith manifest destination aliases its executable input.' }
$lockPath = Get-PlainPath (Join-Path $outDir '.xenolith-fetch.lock') -AllowMissing
if ($OutPath -ieq $lockPath -or $localPath -ieq $lockPath) {
    throw 'A Xenolith executable path aliases its publication lock.'
}

[IO.Directory]::CreateDirectory($outDir) | Out-Null
$lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::Write, [IO.FileShare]::None)
$work = $null
$preserveWork = $false
try {
    $workspacePath = Join-Path $outDir ('.xenolith-fetch-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $workspacePath | Out-Null
    $work = $workspacePath
    $stagePath = Join-Path $work 'xenolith.exe'
    $stageInfo = Join-Path $work $InfoName
    $priorExe = Join-Path $work 'prior.exe'
    $priorInfo = Join-Path $work 'prior-info.json'
    if ($Tag) {
        $info = Get-RemoteXenolith $stagePath
    } elseif ($localPath) {
        if (-not (Test-Path -LiteralPath $localPath -PathType Leaf)) { throw "Xenolith file not found: $localPath" }
        [IO.File]::Copy($localPath, $stagePath)
        if ((Get-Item -LiteralPath $stagePath).Length -eq 0) { throw 'The local Xenolith executable is empty.' }
        $digest = Get-PathSha256 $stagePath
        Assert-PinMatch $digest
        $version = if ($env:XENOLITH_VERSION) { $env:XENOLITH_VERSION.Trim() } else { (Get-Item -LiteralPath $stagePath).VersionInfo.ProductVersion }
        if ([string]::IsNullOrWhiteSpace($version)) { $version = 'unversioned' }
        $info = [ordered]@{ included = $true; source = $source; version = $version; sha256 = $digest }
    } else {
        Write-Warning 'No local Xenolith found. Building without embedded Xenolith.'
        $info = [ordered]@{ included = $false; source = $null; version = $null; sha256 = $null }
    }
    $json = ($info | ConvertTo-Json -Compress) + "`n"
    [IO.File]::WriteAllText($stageInfo, $json, [Text.UTF8Encoding]::new($false))
    $executableChanged = $false
    try {
        if ($info.included) {
            if ($localPath -ine $OutPath) {
                Set-VerifiedFile $stagePath $OutPath $priorExe
                $executableChanged = $true
            }
        } else {
            $null = Get-PlainPath $OutPath -AllowMissing
            if ([IO.File]::Exists($OutPath)) {
                [IO.File]::Move($OutPath, $priorExe)
                $executableChanged = $true
            }
        }
        if ($info.included -and (Get-PathSha256 $OutPath) -ne $info.sha256) {
            throw 'The Xenolith executable changed before its manifest was committed.'
        }
        Set-VerifiedFile $stageInfo $infoPath $priorInfo
    } catch {
        $promotionError = $_
        $rollbackErrors = @()
        if ([IO.File]::Exists($priorInfo)) {
            try { Set-VerifiedFile $priorInfo $infoPath }
            catch { $rollbackErrors += $_.Exception.Message }
        }
        if ($executableChanged -or [IO.File]::Exists($priorExe)) {
            try {
                if ([IO.File]::Exists($priorExe)) { Set-VerifiedFile $priorExe $OutPath }
                else { [IO.File]::Delete((Get-PlainPath $OutPath)) }
            } catch { $rollbackErrors += $_.Exception.Message }
        }
        if ($rollbackErrors.Count) {
            $preserveWork = $true
            throw "Xenolith publication failed: $promotionError. Rollback failed: $($rollbackErrors -join ' | '). Recovery files: $work"
        }
        throw $promotionError
    }
    Write-Host "Xenolith information written to $infoPath"
} finally {
    try {
        if ($work -and -not $preserveWork -and [IO.Directory]::Exists($work)) {
            try { [IO.Directory]::Delete((Get-PlainPath $work -Directory), $true) }
            catch { Write-Warning "Could not remove Xenolith workspace $work. $($_.Exception.Message)" }
        }
    } finally {
        $lock.Dispose()
    }
}
