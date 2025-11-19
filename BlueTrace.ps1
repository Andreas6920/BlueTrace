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
        param([string]$Url)
            # Create or make sure presence of temp folder
                $modulePath = Join-Path $env:TEMP "BlueTrace-Modules"
                if (-not (Test-Path $modulePath)) { New-Item $modulePath -ItemType Directory | Out-Null }
            # Download file to temp folder
                $localFile = Join-path -Path $modulePath -Childpath (Split-path $Url -Leaf)
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    # if older powershell (windows 7, Vista, Server 2008)
                    if ($PSVersionTable.PSVersion.Major -lt 3) { Invoke-WebRequest -UseBasicParsing $Url -OutFile $localFile }
                else {Invoke-RestMethod $Url -OutFile $localFile}
            # Execute file
                . $localFile}

# Create a directory for all the logs

    # Define root path
    function Get-RootPath {
        $desktop = [Environment]::GetFolderPath("Desktop")
        if ($desktop -and (Test-Path $desktop)) { return $desktop }
            if ($env:SystemDrive -and (Test-Path $env:SystemDrive)) {return $env:SystemDrive}
                if (Test-Path "C:\") {return "C:\"}}

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
    Write-Host "`t[5] `tFiles Suite"  -NoNewline; Write-Host "`t`t`t`t// File related artifacts..." -ForegroundColor Gray
    Write-Host "`t[6] `tPersistence Suite" -NoNewline; Write-Host "`t`t// Startup items and keys..." -ForegroundColor Gray
    Write-Host "`t[7] `tZip and send logs" -NoNewline; Write-Host "`t`t`t// Compress, Encrypt and Send logs" -ForegroundColor Gray
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
        
        1 {     Import-RemoteModule -Url "https://raw.githubusercontent.com/Andreas6920/BlueTrace/main/modules/Network-Interfaces.ps1"
                $CSVFile = (Join-Path $BasePath "windows-activation.csv")
                Network-Interfaces -Windows | Export-Csv $CSVFile}

        

        
        Default {}}}
    
    while ($option -ne 9 )