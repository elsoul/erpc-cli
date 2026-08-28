& {
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version 3.0

    $ReleaseBaseUrl = if ($env:ERPC_RELEASE_BASE_URL) {
        $env:ERPC_RELEASE_BASE_URL.TrimEnd('/')
    }
    else {
        'https://storage.erpc.global/erpc'
    }
    $InstallDirectory = if ($env:ERPC_INSTALL_DIR) {
        $env:ERPC_INSTALL_DIR
    }
    else {
        Join-Path $HOME '.erpc\bin'
    }

    function Fail([string]$Message) {
        throw "erpc installer: $Message"
    }

    if ($PSVersionTable.PSVersion.Major -lt 6) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }

    if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::Windows
        )) {
        Fail 'this installer supports Windows only; use the shell installer on Linux or macOS'
    }

    $ArchitectureCandidates = @(
        $env:PROCESSOR_ARCHITEW6432,
        $env:PROCESSOR_ARCHITECTURE,
        [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    ) | Where-Object { $_ } | ForEach-Object { $_.ToUpperInvariant() }
    if ($ArchitectureCandidates -contains 'ARM64') {
        $Target = 'aarch64-pc-windows-msvc'
    }
    elseif (
        $ArchitectureCandidates -contains 'AMD64' -or
        $ArchitectureCandidates -contains 'X64'
    ) {
        $Target = 'x86_64-pc-windows-msvc'
    }
    else {
        Fail "unsupported Windows architecture: $($ArchitectureCandidates -join ', ')"
    }

    $TemporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ("erpc-install-" + [guid]::NewGuid())
    $TemporaryInstall = $null
    New-Item -ItemType Directory -Path $TemporaryDirectory | Out-Null

    try {
        $VersionFile = Join-Path $TemporaryDirectory 'latest'
        Invoke-WebRequest -UseBasicParsing -Uri "$ReleaseBaseUrl/latest" -OutFile $VersionFile
        $Version = (Get-Content -Raw $VersionFile).Trim()
        if ($Version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') {
            Fail 'the published version pointer is invalid'
        }

        $Archive = "erpc-$Target.zip"
        $ArchivePath = Join-Path $TemporaryDirectory $Archive
        $ChecksumsPath = Join-Path $TemporaryDirectory 'SHA256SUMS'
        Invoke-WebRequest -UseBasicParsing -Uri "$ReleaseBaseUrl/$Version/$Archive" -OutFile $ArchivePath
        Invoke-WebRequest -UseBasicParsing -Uri "$ReleaseBaseUrl/$Version/SHA256SUMS" -OutFile $ChecksumsPath

        $EscapedArchive = [regex]::Escape($Archive)
        $ChecksumLines = @(Get-Content $ChecksumsPath | Where-Object {
                $_ -match "^([a-fA-F0-9]{64})\s+\*?$EscapedArchive$"
            })
        if ($ChecksumLines.Count -ne 1) {
            Fail 'the checksum entry is missing or ambiguous'
        }
        $Expected = ([regex]::Match($ChecksumLines[0], '^[a-fA-F0-9]{64}')).Value.ToLowerInvariant()
        $Actual = (Get-FileHash -Algorithm SHA256 -Path $ArchivePath).Hash.ToLowerInvariant()
        if ($Actual -ne $Expected) {
            Fail 'binary checksum verification failed'
        }

        $UnpackedDirectory = Join-Path $TemporaryDirectory 'unpacked'
        Expand-Archive -LiteralPath $ArchivePath -DestinationPath $UnpackedDirectory
        $Entries = @(Get-ChildItem -Force -LiteralPath $UnpackedDirectory)
        if (
            $Entries.Count -ne 1 -or
            $Entries[0].Name -ne 'erpc.exe' -or
            $Entries[0].PSIsContainer -or
            ($Entries[0].Attributes -band [IO.FileAttributes]::ReparsePoint)
        ) {
            Fail 'the release archive contains unexpected paths'
        }

        $BinaryPath = $Entries[0].FullName
        $BinaryVersion = (& $BinaryPath --version | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or "v$BinaryVersion" -ne $Version) {
            Fail 'binary version does not match the release'
        }

        New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null
        $TemporaryInstall = Join-Path $InstallDirectory (".erpc-install-" + [guid]::NewGuid() + '.exe')
        Copy-Item -LiteralPath $BinaryPath -Destination $TemporaryInstall
        Move-Item -Force -LiteralPath $TemporaryInstall -Destination (Join-Path $InstallDirectory 'erpc.exe')

        Write-Host "Installed erpc $BinaryVersion at $(Join-Path $InstallDirectory 'erpc.exe')"
        $PathEntries = @($env:PATH -split ';' | ForEach-Object { $_.TrimEnd('\') })
        if ($PathEntries -notcontains $InstallDirectory.TrimEnd('\')) {
            Write-Host 'Add this directory to PATH:'
            Write-Host "  $InstallDirectory"
        }
    }
    finally {
        if ($TemporaryInstall -and (Test-Path -LiteralPath $TemporaryInstall)) {
            Remove-Item -Force -ErrorAction SilentlyContinue $TemporaryInstall
        }
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue $TemporaryDirectory
    }
}
