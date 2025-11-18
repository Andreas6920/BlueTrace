

# Create a folder for logs
    $BasePath = Join-Path -Path (Get-RootPath) -ChildPath (Get-RootFolder)
        New-Item -Path $BasePath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Log directory created: $BasePath" -f Green