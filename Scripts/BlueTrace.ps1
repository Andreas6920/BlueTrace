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

            