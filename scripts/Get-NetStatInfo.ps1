function Get-NetStatInfo {
    <#
    .SYNOPSIS
        Lists established external TCP connections and optionally enriches remote IPs with AbuseIPDB data.

    .DESCRIPTION
        Returns clean objects suitable for CSV export.
        Downloads and dot-sources Start-AbuseIPDBLookup from GitHub before enrichment.

    .PARAMETER MaxAgeInDays
        How far back AbuseIPDB should look.

    .PARAMETER TimeoutSec
        Request timeout in seconds.

    .PARAMETER SkipAbuseIPDBLookup
        Skip enrichment calls to AbuseIPDB.

    .EXAMPLE
        Get-NetStatInfo | Export-Csv -Path C:\net.csv -NoTypeInformation -Encoding UTF8 -Force
    #>

        [CmdletBinding()]
    param(
        [int]$MaxAgeInDays = 90,
        [int]$TimeoutSec = 10,
        [switch]$SkipAbuseIPDBLookup
    )

    # Load Start-AbuseIPDBLookup from GitHub (always attempt)
    $LookupUri  = "https://raw.githubusercontent.com/Andreas6920/BlueTrace/main/modules/Start-AbuseIPDBLookup.ps1"
    $LookupPath = Join-Path $env:ProgramData "BlueTrace\Modules\Start-AbuseIPDBLookup.ps1"

    $LookupAvailable = $false
    try {
        $dir = Split-Path -Parent $LookupPath
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

        if (-not (Test-Path $LookupPath)) {
            Invoke-RestMethod -Uri $LookupUri -ErrorAction Stop |
                Set-Content -Path $LookupPath -Encoding UTF8 -Force
        }

        . $LookupPath

        if (Get-Command Start-AbuseIPDBLookup -CommandType Function -ErrorAction SilentlyContinue) {
            $LookupAvailable = $true
        }
    }
    catch {
        $LookupAvailable = $false
    }

    # Online check
    $ThisMachineIsOnline = $false
    try {
        $ThisMachineIsOnline = Test-Connection -ComputerName 1.1.1.1 -Count 1 -Quiet -ErrorAction Stop
    } catch {
        $ThisMachineIsOnline = $false
    }

    # Collect connections
    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object {
            $_.State -eq "Established" -and
            $_.RemoteAddress -and
            $_.RemoteAddress -notmatch '^(::|::1|0\.0\.0\.0|127\.0\.0\.1)$'
        }

    if (-not $connections) { return }

    # AbuseIPDB cache (per unique IP)
    $AbuseCache = @{}

    $results = foreach ($conn in $connections) {

        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $remoteIp = [string]$conn.RemoteAddress

        $abuse = $null
        if (-not $SkipAbuseIPDBLookup -and $ThisMachineIsOnline -and $LookupAvailable) {
            if (-not $AbuseCache.ContainsKey($remoteIp)) {
                $AbuseCache[$remoteIp] = Start-AbuseIPDBLookup -IpAddress $remoteIp -MaxAgeInDays $MaxAgeInDays -TimeoutSec $TimeoutSec
            }
            $abuse = $AbuseCache[$remoteIp]
        }

        [PSCustomObject]@{
            DestinationIP   = $remoteIp
            DestinationPort = $conn.RemotePort
            State           = $conn.State
            PID             = $conn.OwningProcess
            ProcessName     = if ($proc) { $proc.ProcessName } else { "N/A" }

            Domain          = $abuse.Domain
            ISP             = $abuse.ISP
            Country         = $abuse.Country
            AbusedReports   = $abuse.TotalReports
            ConfidenceScore = $abuse.AbuseScore
            LastReportedAt  = $abuse.LastReportedAt
            AbuseLookupErr  = $abuse.Error
        }
    }

    $results | Sort-Object ISP, Domain, DestinationIP, DestinationPort}
