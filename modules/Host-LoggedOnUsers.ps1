function Get-HostLoggedOnUsers {
    $raw = quser.exe 2>$null
    if (-not $raw) { return @() }

    $lines = $raw | Select-Object -Skip 1

    $list = foreach ($line in $lines) {

        # Normalize variable spacing
        $clean = $line -replace '\s{2,}', "`t"
        $parts = $clean -split "`t"

        # Detect and strip current-session marker ">"
        $rawUser = $parts[0]
        $isCurrent = $rawUser.StartsWith(">")

        $user = $rawUser.TrimStart(">")

        [PSCustomObject]@{
            UserName         = $user
            IsCurrentSession = $isCurrent
            SessionName      = $parts[1]
            ID               = $parts[2]
            State            = $parts[3]
            IdleTime         = $parts[4]
            LogonTime        = $parts[5]
        }
    }

    return $list
}
