# Module Execution
    function Import-RemoteModule {
        param([string]$Url)
        # Create or make sure presence of temp folder
            $modulePath = Join-Path $env:TEMP "BlueTrace-Modules"
            if (-not (Test-Path $modulePath)) { New-Item $modulePath -ItemType Directory | Out-Null }
        # Download file to temp folder
            $localFile = Join-path -Path $modulePath -Childpath (Split-path $Url -Leaf)
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-RestMethod $Url -OutFile $localFile
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
            Write-Host "Log directory created: $BasePath" -f Green




            

do {
    Write-Host "`n";
    Write-Host "`tMENU" -f Yellow;"";
    Write-Host "`t[1] `tModule: Windows-Optimizer"
    Write-Host "`t[2] `tModule: Windows-Server-Automator"
    Write-Host "`t[3] `tInstall Microsoft Office 2016 Professional Retail"
    Write-Host "`t[4] `tDownload Windows"
    Write-Host "`t[5] `tActivate Microsoft Office"
    Write-Host "`t[6] `tActivate Windows"
    
    "";
    Write-Host "`t[0] - Exit"
    Write-Host ""; Write-Host "";
    Write-Host "`tOption: " -f Yellow -nonewline; ;
    $option = Read-Host
    Switch ($option) { 
        0 {exit}
        
        1 {     Import-RemoteModule -Url "https://raw.githubusercontent.com/Andreas6920/BlueTrace/main/modules/Network-Interfaces.ps1"
                $CSVFile = (Join-Path $BasePath "windows-activation.csv")
                Network-Interfaces -Windows | Export-Csv $CSVFile}

        

        
        Default {}}
}
while ($option -ne 6 )