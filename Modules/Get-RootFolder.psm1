function Get-RootFolder {
    $Date = Get-Date -Format "yyyy.MM.dd"
    "Logs_" + $Date + "_" + $Env:COMPUTERNAME + "_" + $Env:USERNAME}
