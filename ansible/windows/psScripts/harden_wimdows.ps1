param (
    [switch] $installSSH = $false,
    [switch] $keepRPC = $false,
    [switch] $keepSMB = $false
)

if (Get-Command Set-PSReadlineOption -ErrorAction SilentlyContinue) {
    Set-PSReadlineOption -HistorySaveStyle SaveNothing
}

$NEW_PASSWORD = ''
$PUBKEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEuQxB1JXTrDHo7Cgmyy4uLK4oTCSgLybzhju8grET10 user@host'
$StrictMode = $false
$SSHD_MSI_LINK = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.8.1.0p1-Preview/OpenSSH-Win64-v9.8.1.0.msi"

$user = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "Error: Must run as Administrator"
    exit 1
}
if (-not $NEW_PASSWORD) {
    Write-Output "Error: Need to set NEW_PASSWORD"
    exit 1
}
if (-not $PUBKEY) {
    Write-Output "Error: Need to set PUBKEY"
    exit 1
}
try {
    $isDomainController = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType -eq 2
} catch {
    $isDomainController = (Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2
}
if ($isDomainController) {
    Write-Output "Computer $env:COMPUTERNAME is a domain controller"
} else {
    Write-Output "Computer $env:COMPUTERNAME is NOT a domain controller"
}
function RollPasswords {
    Write-Output "Rolling passwords"
    net user Administrator $NEW_PASSWORD
    if ($isDomainController) {
        net user krbtgt $NEW_PASSWORD
        net user krbtgt $NEW_PASSWORD
    }
}
function ApplyHardening {
    Write-Output "Applying hardening"
    if (-not $keepSMB) {
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d 0 /f | Out-Null
    }
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LmCompatibilityLevel" /t REG_DWORD /d 5 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "RestrictSendingNTLMTraffic" /t REG_DWORD /d 2 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLmHash /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RunAsPPL" /t REG_DWORD /d 1 /f | Out-Null
    Stop-Service -Name "Spooler" -Force
    Set-Service -Name "Spooler" -StartupType Disabled
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f | Out-Null
    Stop-Service -Name "Schedule" -Force
    Get-ChildItem "HKLM:SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" | ForEach-Object {
        Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 2
    }
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f 2>$null | Out-Null
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /f 2>$null | Out-Null
    reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f 2>$null | Out-Null
    reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /f 2>$null | Out-Null
    auditpol /set /category:* /failure:enable /success:enable
    net user Guest /active:no
    if ($isDomainController) {
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "FullSecureChannelProtection" /t REG_DWORD /d 1 /f | Out-Null
        $spnUsers = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName | Where-Object { $_.SamAccountName -ne "krbtgt" }
        $noPreAuthUsers = Get-ADUser -Filter {userAccountControl -band 0x400000}
        @($spnUsers) + @($noPreAuthUsers) | ForEach-Object {
            Write-Output "Disabling account: $($_.SamAccountName)"
            Disable-ADAccount -Identity $_.SamAccountName
        }
        Get-DnsServerZone |
            Where-Object {$_.ZoneType -like "Primary" -and -not $_.IsAutoCreated} |
            Select-Object -Property ZoneName,ZoneType |
            Set-DnsServerPrimaryZone -DynamicUpdate None -Notify Notify -SecureSecondaries TransferToZoneNameServer
        Get-DnsServerZone |
            Where-Object {$_.ZoneType -like "Primary" -and -not $_.IsAutoCreated} |
            Select-Object -Property ZoneName,ZoneType |
            Set-DnsServerPrimaryZone -DynamicUpdate None -Notify NoNotify -SecureSecondaries NoTransfer
        $dnsServerForwarders = Get-DnsServerForwarder | Select-Object -ExpandProperty IPAddress
        Write-Output "DNS Server Forwarders: $dnsServerForwarders"
    }
}
function InstallSSH {
    Write-Output "Installing SSH"
    if (Get-Service -Name sshd -ErrorAction SilentlyContinue) {
        Write-Output "SSH is already installed"
        return
    }
    [System.Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls11, Tls, Ssl3"
    Invoke-WebRequest -Uri $SSHD_MSI_LINK -OutFile "C:\sshd.msi"
    Start-Process msiexec -Wait -ArgumentList '/i "C:\sshd.msi" ADDLOCAL=Server'
    rm "C:\sshd.msi"
}
function ProcessAuthorizedKeys {
    param (
        [Parameter(Mandatory = $true)]
        [string] $authorizedKeysPath
    )
    $backupPath = $authorizedKeysPath + ".bak"
    if ((Test-Path $authorizedKeysPath) -and -not (Test-Path $backupPath)) {
        Copy-Item -Path $authorizedKeysPath -Destination $backupPath -Force
    }
    Set-Content -Path $authorizedKeysPath -Value $PUBKEY -Force
}
function ConfigureSSH {
    Write-Output "Configuring SSH"
    ProcessAuthorizedKeys -authorizedKeysPath $env:ProgramData\ssh\administrators_authorized_keys
    icacls.exe ""$env:ProgramData\ssh\administrators_authorized_keys"" /inheritance:r /grant ""Administrators:F"" /grant ""SYSTEM:F""
    New-Item -Force -ItemType Directory -Path $env:USERPROFILE\.ssh | Out-Null
    ProcessAuthorizedKeys -authorizedKeysPath $env:USERPROFILE\.ssh\authorized_keys
    Add-Content -Force -Path "$env:ProgramData\ssh\sshd_config" -Value "PasswordAuthentication no"
}
function SetUpSSH {
    Write-Output "Setting up SSH"
    if ($installSSH) {
        InstallSSH
    }
    if (Get-Service -Name sshd -ErrorAction SilentlyContinue) {
        ConfigureSSH
        Restart-Service -Name sshd
    }
}
function GetListeningPorts {
    $firstRun = netstat -an | Select-String "0.0.0.0:(?!0\s).+LISTEN" | ForEach-Object { $_.Line.Split(':')[1].Trim().Split(' ')[0] }
    Start-Sleep -Seconds 10
    $secondRun = netstat -an | Select-String "0.0.0.0:(?!0\s).+LISTEN" | ForEach-Object { $_.Line.Split(':')[1].Trim().Split(' ')[0] }
    $commonPorts = $firstRun | Where-Object { $secondRun -contains $_ } | Sort-Object { [int]$_ } -Unique
    return ($commonPorts -join ',')
}
function ConfigureFirewall {
    $firewallService = Get-Service -Name MpsSvc
    if ($firewallService.Status -ne "Running") {
        reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpssvc /v Start /t REG_DWORD /d 0x2 /f | Out-Null
        Write-Output "Firewall service not enabled. Manually reboot to configure"
        return
    }
    Write-Output "Configuring firewall"
    if (-not (Test-Path "C:\original.wfw")) {
        Write-Output "Backing up original firewall to C:\original.wfw"
        netsh advfirewall export "C:\original.wfw"
    }
    $allowedTCPPorts = "21,22,25,80,110,135,139,143,389,443,445,465,993,995,3389,5985,5986,8080,8443"
    $listeningPorts = ""
    if (-not $StrictMode ) {
        $listeningPorts = GetListeningPorts
        Write-Output "Listening ports: $listeningPorts"
    }
    netsh advfirewall set allprofiles state off | Out-Null
    netsh advfirewall firewall set rule name=all new enable=no | Out-Null
    netsh advfirewall firewall add rule name="AUTOMATED RULE Default TCP ports ALLOW" dir=in protocol=TCP localport=$allowedTCPPorts action=allow enable=yes | Out-Null
    if ($listeningPorts) {
        netsh advfirewall firewall add rule name="AUTOMATED RULE Listening ports ALLOW" dir=in protocol=TCP localport=$listeningPorts action=allow enable=yes | Out-Null
    }
    if ($isDomainController) {
        netsh advfirewall firewall add rule name="AUTOMATED RULE Domain Controller DNS ALLOW" dir=in protocol=UDP localport=53 action=allow enable=yes | Out-Null
        if (-not $keepRPC) {
            netsh advfirewall firewall add rule name="AUTOMATED RULE Domain Controller RPC BLOCK" dir=in protocol=TCP localport=135 action=block enable=yes | Out-Null
        }
    }
    Write-Output "Enabling firewall"
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
    netsh advfirewall set allprofiles state on | Out-Null
    Write-Output "Finished configuring firewall"
}
RollPasswords
ApplyHardening
SetUpSSH
ConfigureFirewall

if (Test-Path $script:MyInvocation.MyCommand.Path) {
    Remove-Item $script:MyInvocation.MyCommand.Path -Force
}