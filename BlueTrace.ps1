$Banner = @"
██████  ██      ██    ██ ███████ ████████ ██████   █████   ██████ ███████ 
██   ██ ██      ██    ██ ██         ██    ██   ██ ██   ██ ██      ██      
██████  ██      ██    ██ █████      ██    ██████  ███████ ██      █████   
██   ██ ██      ██    ██ ██         ██    ██   ██ ██   ██ ██      ██      
██████  ███████  ██████  ███████    ██    ██   ██ ██   ██  ██████ ███████ 
"@

$Version = '0.0.0'



# Module Execution
    function Import-RemoteModule {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Url)

        # Create modules folder
        $modulePath = Join-Path $env:TEMP "BlueTrace-Modules"
        if (-not (Test-Path $modulePath)) { New-Item -ItemType Directory -Path $modulePath | Out-Null }

        # Define scriptname
        $FileName = Split-path $Url -Leaf
        $localFile = Join-path $modulePath $FileName

        # Ensure TLS 1.2 on older systems
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

        # Download script - Change download method for older systems.
        $useIRM = $false
        if ($PSVersionTable.PSVersion.Major -ge 5) { $useIRM = $true }
        try {
            if ($useIRM) {Invoke-RestMethod -Uri $Url -OutFile $localFile -ErrorAction Stop} 
            else {Invoke-WebRequest -Uri $Url -OutFile $localFile -UseBasicParsing -ErrorAction Stop}}
        catch {
            throw "Download failed for $Url : $($_.Exception.Message)"}

        # Execute script
        . $localFile
    }

# Create a directory for all the logs

    # Define root path
    function Get-RootPath {
        # Preferred: Desktop for interactive sessions
        $desktop = [Environment]::GetFolderPath("Desktop")
        if ($desktop -and (Test-Path $desktop) -and $env:USERNAME -ne "SYSTEM") {return $desktop}
    
        # Next: SystemDrive
        if ($env:SystemDrive -and (Test-Path $env:SystemDrive)) {return $env:SystemDrive}

        # Fallback: C:\
        return "C:\"}


    # Define directory name
    function Get-RootFolder {
        $Date = Get-Date -Format "yyyy.MM.dd"
        "Logs_" + $Date + "_" + $Env:COMPUTERNAME + "_" + $Env:USERNAME}

    # Create folder
        $BasePath = Join-Path -Path (Get-RootPath) -ChildPath (Get-RootFolder)
            New-Item -Path $BasePath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
            

Write-Host "`n"
Write-Host $Banner -ForegroundColor Blue
Write-Host "`n"
Write-Host "Version : $Version | Developer: Andreas6920 | Github: https://github.com/andreas6920"
Write-Host "`t - Logs: $BasePath"
Write-Host "============================================================================="

    do {
    
    
    Write-Host "`n";
    Write-Host "`tMENU" -f Yellow;"";
    Write-Host "`t[1] `tAuto-collect logs"
    Write-Host "`t[2] `tHost Information" -NoNewline; Write-Host "`t`t// Host specs, network config, defender config..." -ForegroundColor Gray
    Write-Host "`t[3] `tNetwork Suite" -NoNewline; Write-Host "`t`t`t// Network Connections DNS, IP, SMB, RDP..." -ForegroundColor Gray
    Write-Host "`t[4] `tProcess Suite" -NoNewline; Write-Host "`t`t`t// Event viewer, Processes, Jobs, Services, Commands.." -ForegroundColor Gray
    Write-Host "`t[5] `tFiles Suite"  -NoNewline; Write-Host "`t`t`t// File related artifacts..." -ForegroundColor Gray
    Write-Host "`t[6] `tPersistence Suite" -NoNewline; Write-Host "`t`t// Startup items and keys..." -ForegroundColor Gray
    Write-Host "`t[7] `tZip and send logs" -NoNewline; Write-Host "`t`t// Compress, Encrypt and Send logs" -ForegroundColor Gray
    "";
    Write-Host "`t[8] `tDownload Tools" -NoNewline; Write-Host "`t`t`t// Forensics and Incident Response Tools" -ForegroundColor Gray
    "";
    Write-Host "`t[9] `tIsolate Host"
    
    "";
    Write-Host "`t[0] `tExit"
    Write-Host ""; Write-Host "";
    Write-Host "`tOption: " -f Yellow -nonewline; ;
    $option = Read-Host
    Switch ($option) { 
        0 {exit}
        
        2 {     
            
            # System settings - AV Settings, Firewall Settings, Security Settings, Local Admins, PC Specs etc..
            $CSVFile = (Join-Path $BasePath "Host-Information.csv")
            $Url = "https://raw.githubusercontent.com/Andreas6920/BlueTrace/refs/heads/main/scripts/Get-HostInformation.ps1"
            Invoke-RestMethod $Url | Invoke-Expression
            Get-HostInformation | Export-Csv -Path $CSVFile -NoTypeInformation -Encoding UTF8 -Force
            
            # Network settings - Network Interfaces, MACS, IPS
            $CSVFile = (Join-Path $BasePath "Host-NetInterfaces.csv")
            $Url = "https://raw.githubusercontent.com/Andreas6920/BlueTrace/refs/heads/main/scripts/Get-HostNetInterfaces.ps1"
            Invoke-RestMethod $Url | Invoke-Expression
            Get-HostNetInterfaces | Export-Csv -Path $CSVFile -NoTypeInformation -Encoding UTF8 -Force
            
            # User sessions - Concurrent logged on users on system
            $CSVFile = (Join-Path $BasePath "Host-LoggedOnUsers.csv")
            $Url = "https://raw.githubusercontent.com/Andreas6920/BlueTrace/refs/heads/main/scripts/Get-HostLoggedOnUsers.ps1"
            Invoke-RestMethod $Url | Invoke-Expression
            Get-HostLoggedOnUsers | Export-Csv -Path $CSVFile -NoTypeInformation -Encoding UTF8 -Force

        }

        3 {
            
            # Open TCP Connections (Netstat), binded with application and domain/ISP lookup
            $CSVFile = (Join-Path $BasePath "Network-OpenConnections.csv")
            $Url = "https://raw.githubusercontent.com/Andreas6920/BlueTrace/refs/heads/main/scripts/Get-NetStatInfo.ps1"
            Invoke-RestMethod $Url | Invoke-Expression
            Get-NetStatInfo | Format-Table -AutoSize
            Get-NetStatInfo | Export-Csv -Path $CSVFile -NoTypeInformation -Encoding UTF8 -Force

        }

        6 {

            # Get all statupitems, Lookup the files in VirusTotal
            $CSVFile = (Join-Path $BasePath "Persistence-StartupItems.csv")
            $Url = "https://raw.githubusercontent.com/Andreas6920/BlueTrace/refs/heads/main/scripts/Get-PersistenceItems.ps1"
            Invoke-RestMethod $Url | Invoke-Expression
            Get-PersistenceItems | Export-Csv -Path $CSVFile -NoTypeInformation -Encoding UTF8 -Force

            # Confirmed Healthy
            $healthy = Import-Csv $CSVFile | Where-Object { $_.KnownToVirusTotal -eq 'True' -and [int]$_.Undetected -gt 67 } | Select-Object EntryName, KnownToVirusTotal, Harmless, Malicious, Suspicious, Undetected, Permalink | Format-Table -AutoSize
            If ($null -ne $healthy){
                Write-host "`n`n CONFIRMED KNOWN HEALTHY STARTUP ITEMS:" -BackgroundColor DarkGreen -ForegroundColor White
                $healthy}
            
            # NOT confirmed healthy
            $unhealthy = Import-Csv $CSVFile | Where-Object { ($_.KnownToVirusTotal -eq 'True' -and [int]$_.Undetected -lt 68) -or $_.KnownToVirusTotal -eq 'False' }  | Select-Object FilePath, KnownToVirusTotal, Harmless, Malicious, Suspicious, Undetected, Permalink | Format-Table -AutoSize
            If ($null -ne $unhealthy){
                Write-host "SUSPECIOUS - HIGH DETECTION RATE OR UNKNOWN STARTUP ITEMS, HAVE A LOOK:" -BackgroundColor Red -ForegroundColor White
                $unhealthy}

        }

        
        Default {}}}
    
    while ($option -ne 9 )