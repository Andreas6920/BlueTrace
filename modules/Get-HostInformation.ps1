function Get-HostInformation {
    [CmdletBinding()]
    param()

    function Try-Exec($scriptBlock) {
        try { & $scriptBlock } catch { $null }
    }

    # Core WMI / CIM
    $os   = Try-Exec { Get-CimInstance Win32_OperatingSystem }
    $cs   = Try-Exec { Get-CimInstance Win32_ComputerSystem }
    $bios = Try-Exec { Get-CimInstance Win32_BIOS }
    $cpu  = Try-Exec { Get-CimInstance Win32_Processor }
    $disk = Try-Exec { Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" }

    # Defender fallback
    $defender = Try-Exec { Get-MpComputerStatus }
    if (-not $defender) {
        $defender = Try-Exec { 
            Get-CimInstance -Namespace "root/Microsoft/Windows/Defender" -ClassName MSFT_MpComputerStatus 
        }
    }

    # BitLocker
    $bitlocker = Try-Exec { Get-BitLockerVolume -MountPoint "C:" }
    if ($bitlocker) {
        $bitStatus = switch ($bitlocker.ProtectionStatus) {
            0 { "Off" }
            1 { "On" }
            default { "Unknown" }
        }
    }
    else {
        $bitStatus = ""
    }

    # Secure boot
    $secureBoot = Try-Exec { Confirm-SecureBootUEFI 2>$null }

    # TPM
    $tpm = Try-Exec {
        Get-CimInstance -Namespace "root\cimv2\security\microsofttpm" -Class Win32_TPM
    }
    $tpmEnabled = if ($tpm) { $tpm.IsEnabled_InitialValue } else { "" }

    # Uptime
    $lastBoot = Try-Exec { $os.LastBootUpTime }
    $uptimeHours = if ($lastBoot) {
        [math]::Round((New-TimeSpan -Start $lastBoot -End (Get-Date)).TotalHours, 1)
    } else { "" }

    # RDP enabled?
    $rdpStatus = Try-Exec {
        $reg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
        if ($reg.fDenyTSConnections -eq 0) { "Enabled" } else { "Disabled" }
    }

    # Firewall profiles
    $fwState = Try-Exec {
        (Get-NetFirewallProfile |
            Select-Object Name, Enabled |
            ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join "; "
    }

    # Installed AV besides Defender
    $otherAV = Try-Exec {
        Get-CimInstance -Namespace "root\SecurityCenter2" -Class AntiVirusProduct |
            Where-Object { $_.displayName -ne "Windows Defender" } |
            Select-Object -ExpandProperty displayName
    }
    if ($otherAV) { $otherAV = $otherAV -join ", " } else { $otherAV = "" }

    # Local admins
    $localAdmins = Try-Exec {
        Get-LocalGroupMember -Group "Administrators" |
            Select-Object -ExpandProperty Name
    }
    if ($localAdmins) { $localAdmins = $localAdmins -join ", " } else { $localAdmins = "" }

    # System drive size
    $systemDriveSize = if ($disk) { 
        [math]::Round($disk.Size / 1GB, 2)
    } else { "" }

    # System drive free
    $systemDriveFree = if ($disk) { 
        [math]::Round($disk.FreeSpace / 1GB, 2)
    } else { "" }

    # Final object
    $obj = [PSCustomObject]@{
        Hostname              = $env:COMPUTERNAME
        Domain                = $cs.Domain
        OSName                = $os.Caption
        OSVersion             = $os.Version
        OSBuild               = $os.BuildNumber
        InstallDate           = $os.InstallDate

        LastBoot              = $lastBoot
        UptimeHours           = $uptimeHours
        UserExecuting         = $env:USERNAME

        Manufacturer          = $cs.Manufacturer
        Model                 = $cs.Model
        BIOSVersion           = $bios.SMBIOSBIOSVersion

        CPUName               = $cpu.Name

        "RAM, GB"             = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)

        "SystemDriveSize, GB" = $systemDriveSize
        "SystemDriveFree, GB" = $systemDriveFree

        BitLockerStatus       = $bitStatus
        SecureBootEnabled     = $secureBoot
        TPMEnabled            = $tpmEnabled

        DefenderEnabled       = if ($defender) { $defender.AntivirusEnabled } else { "" }
        DefenderRealTime      = if ($defender) { $defender.RealTimeProtectionEnabled } else { "" }
        DefenderSignatureAge  = if ($defender) { $defender.AntivirusSignatureLastUpdated } else { "" }

        RDPEenabled           = $rdpStatus
        FirewallProfiles      = $fwState
        OtherAntivirus        = $otherAV
        LocalAdmins           = $localAdmins
    }

    return $obj
}
