function Get-PersistenceItems {
    [CmdletBinding()]
    param(
        [switch]$SkipVirusTotalLookup
    )

    
    # Download and Load VirustTotal Module
        $VirusTotalModuleUri  = "https://raw.githubusercontent.com/Andreas6920/BlueTrace/refs/heads/main/modules/Start-VirusTotalLookup.ps1"
        $VirusTotalModulePath = Join-Path $env:ProgramData "AM\Modules\Start-VirusTotalLookup.ps1"

            # Create subfolder
                try {
                    $dir = Split-Path -Parent $VirusTotalModulePath
                    if (-not (Test-Path $dir)) {
                        New-Item -ItemType Directory -Path $dir -Force | Out-Null}
            
            # Download Module
                if (-not (Test-Path $VirusTotalModulePath)) {
                    Invoke-RestMethod -Uri $VirusTotalModuleUri -ErrorAction Stop | Set-Content -Path $VirusTotalModulePath -Encoding UTF8 -Force}

            # Execute moule
                . $VirusTotalModulePath
                if (-not (Get-Command Start-VirusTotalLookup -CommandType Function -ErrorAction SilentlyContinue)) {throw "Start-VirusTotalLookup function not found after module import."}}

                catch {throw "Failed to load VirusTotal module: $($_.Exception.Message)"}

    # Helpers
    function Resolve-StartupCommandToPath {
        param([Parameter(Mandatory)][string]$CommandLine)

        $cmd = $CommandLine.Trim()
        if (-not $cmd) { return $null }

        if ($cmd.StartsWith('"')) {
            $end = $cmd.IndexOf('"', 1)
            if ($end -gt 1) {
                return [Environment]::ExpandEnvironmentVariables(
                    $cmd.Substring(1, $end - 1)
                )
            }
        }

        return [Environment]::ExpandEnvironmentVariables(
            ($cmd -split '\s+')[0]
        )
    }

    # Cache per SHA256
    $VtCache = @{}

    # Registry persistence locations
    $registryRoots = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",

        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",

        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    )

    # Expand HKU:\*
    $userSids = Get-ChildItem HKU:\ -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'HKEY_USERS\\S-1-5-21' }

    foreach ($sid in $userSids) {
        $registryRoots += @(
            "Registry::$($sid.Name)\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "Registry::$($sid.Name)\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "Registry::$($sid.Name)\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            "Registry::$($sid.Name)\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "Registry::$($sid.Name)\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            "Registry::$($sid.Name)\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        )
    }

    $registryRoots = $registryRoots | Sort-Object -Unique
    $raw = @()

    foreach ($rk in $registryRoots) {
        if (Test-Path $rk) {
            $props = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -match '^PS') { continue }

                $command = [string]$p.Value
                $path = if ($command) {
                    Resolve-StartupCommandToPath -CommandLine $command
                }

                $raw += [PSCustomObject]@{
                    SourceType  = "Registry"
                    SourcePath  = $rk
                    EntryName   = $p.Name
                    CommandLine = $command
                    FilePath    = $path
                }
            }
        }
    }

    
    # Startup folders
    
    $startupFolders = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $userStartup = Join-Path $_.FullName "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        if (Test-Path $userStartup) { $startupFolders += $userStartup }
    }

    $startupFolders = $startupFolders | Sort-Object -Unique

    foreach ($sf in $startupFolders) {
        Get-ChildItem -Path $sf -File -ErrorAction SilentlyContinue | ForEach-Object {
            $raw += [PSCustomObject]@{
                SourceType  = "StartupFolder"
                SourcePath  = $sf
                EntryName   = $_.Name
                CommandLine = $null
                FilePath    = $_.FullName
            }
        }
    }

    # Final deduplication    
    $raw = $raw | Sort-Object SourceType, SourcePath, EntryName, CommandLine, FilePath -Unique

    # Enrich with hash + VirusTotal    
    foreach ($i in $raw) {
        $resolvedPath = $null
        $sha = $null
        $vt = $null

        if ($i.FilePath) {
            $candidate = [Environment]::ExpandEnvironmentVariables($i.FilePath)
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                $resolvedPath = (Resolve-Path -LiteralPath $candidate).Path
                try {
                    $sha = (Get-FileHash -Path $resolvedPath -Algorithm SHA256).Hash.ToLowerInvariant()
                } catch {}
            }
        }

        if (-not $SkipVirusTotalLookup -and $sha) {
            if (-not $VtCache.ContainsKey($sha)) {
                $VtCache[$sha] = Start-VirusTotalLookup -FileHash $sha
            }
            $vt = $VtCache[$sha]
        }

        [PSCustomObject]@{
            SourceType        = $i.SourceType
            SourcePath        = $i.SourcePath
            EntryName         = $i.EntryName
            CommandLine       = $i.CommandLine
            FilePath          = $resolvedPath

            SHA256            = $sha
            KnownToVirusTotal = $vt.KnownToVirusTotal
            Harmless          = $vt.Harmless
            Malicious         = $vt.Malicious
            Suspicious        = $vt.Suspicious
            Undetected        = $vt.Undetected
            Timeout           = $vt.Timeout
            Permalink         = $vt.Permalink
            VTSource          = $vt.Source
        }
    }
}
