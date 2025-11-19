$Results  = New-Object System.Collections.Generic.List[object]

# Get all adapters with a non-empty MAC and a valid IfIndex
$Adapters = Get-NetAdapter |
    Where-Object { $_.MacAddress -and $_.MacAddress -ne "00-00-00-00-00-00" -and $_.IfIndex -ne $null }

foreach ($Adapter in $Adapters) {
    # Convert MAC format from 00-11-22-33-44-55 to 00:11:22:33:44:55
    $Mac = $Adapter.MacAddress -replace '-', ':'

    try {
        # Make the error terminating so catch will handle "not found"
        $IpAddresses = Get-NetIPAddress -InterfaceIndex $Adapter.IfIndex -ErrorAction Stop} 
    catch {
        $IpAddresses = @()}

    if ($IpAddresses.Count -eq 0) {
        # Adapter without IP addresses
        $Results.Add([PSCustomObject]@{
            AdapterName   = $Adapter.Name
            MACAddress    = $Mac
            IfIndex       = $Adapter.IfIndex
            Status        = $Adapter.Status
            AddressFamily = ""
            IPAddress     = ""
        }) | Out-Null} 
    
    else {
        foreach ($Ip in $IpAddresses) {
            $Results.Add([PSCustomObject]@{
                AdapterName   = $Adapter.Name
                MACAddress    = $Mac
                IfIndex       = $Adapter.IfIndex
                Status        = $Adapter.Status
                AddressFamily = $Ip.AddressFamily
                IPAddress     = $Ip.IPAddress
            }) | Out-Null
        }
    }
}
