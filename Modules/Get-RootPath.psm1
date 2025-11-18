function Get-RootPath {
    $desktop = [Environment]::GetFolderPath("Desktop")
    if ($desktop -and (Test-Path $desktop)) { return $desktop }
        if ($env:SystemDrive -and (Test-Path $env:SystemDrive)) {return $env:SystemDrive}
            if (Test-Path "C:\") {return "C:\"}}