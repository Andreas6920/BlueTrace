function Get-HostNetworkInterfaces {
    [CmdletBinding()]
    param()

    $results = @()

    # Get all adapters with valid MAC and IfIndex
    $adapters = Get-NetAdapter |
        Where-Object {
            $_.MacAddress -and
            $_.MacAddress -ne "00-00-00-00-00-00" -and
            $_.IfIndex
        }

    foreach ($adapter in $adapters) {

        # Normalize MAC format 00-11-22-33-44-55 -> 00:11:22:33:44:55
        $mac = $adapter.MacAddress -replace '-', ':'

        # Adapter type
        $adapterType = $adapter.InterfaceDescription

        # DNS servers
        try {
            $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.IfIndex -ErrorAction Stop
            $dnsList = $dns.ServerAddresses -join ', '
        }
        catch {
            $dnsList = ''
        }

        # Gateways (IPv4 and IPv6)
        try {
            $gw4 = Get-NetRoute -InterfaceIndex $adapter.IfIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop
            $gw4List = $gw4.NextHop -join ', '
        }
        catch { $gw4List = '' }

        try {
            $gw6 = Get-NetRoute -InterfaceIndex $adapter.IfIndex -DestinationPrefix "::/0" -ErrorAction Stop
            $gw6List = $gw6.NextHop -join ', '
        }
        catch { $gw6List = '' }

        $gateway = ($gw4List, $gw6List | Where-Object { $_ -ne '' }) -join ', '

        # IP addresses
        try {
            $ips = Get-NetIPAddress -InterfaceIndex $adapter.IfIndex -ErrorAction Stop
        }
        catch {
            $ips = @()
        }

        # No IPs at all
        if (-not $ips -or $ips.Count -eq 0) {
            $results += [PSCustomObject]@{
                AdapterName   = $adapter.Name
                IPAddress     = ''
                Gateway       = $gateway
                DnsServers    = $dnsList
                MACAddress    = $mac
                Status        = $adapter.Status   # moved here
                IfIndex       = $adapter.IfIndex
                AdapterType   = $adapterType
                AddressFamily = ''
            }
            continue
        }

        # Adapter with multiple IPs
        foreach ($ip in $ips) {

            $results += [PSCustomObject]@{
                AdapterName   = $adapter.Name
                IPAddress     = $ip.IPAddress
                Gateway       = $gateway
                DnsServers    = $dnsList
                MACAddress    = $mac
                Status        = $adapter.Status   # moved here
                IfIndex       = $adapter.IfIndex
                AdapterType   = $adapterType
                AddressFamily = $ip.AddressFamily
            }
        }
    }

    # ------------------------------------------------------------------------
    # Sortering stadig:
    # 1) Status
    # 2) IfIndex
    # 3) AddressFamily (IPv4 før IPv6)
    # ------------------------------------------------------------------------

    $results = $results |
        Sort-Object `
            @{ Expression = {
                switch ($_.Status) {
                    "Up"           { 1 }
                    "Disconnected" { 2 }
                    "Down"         { 3 }
                    default        { 4 }
                }
            }},
            IfIndex,
            @{ Expression = {
                switch ($_.AddressFamily) {
                    "IPv4" { 1 }
                    "IPv6" { 2 }
                    default { 3 }
                }
            }}

    return $results
}
