#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows 11 Security Hardening Script
.DESCRIPTION
    Applies security hardening settings for Windows 11 including firewall,
    SSH, RDP, account policies, audit policies, services, telemetry,
    Windows Defender, and miscellaneous security settings.
    Safe to re-run (idempotent).
.PARAMETER AuditOnly
    When set, only reports current state without making changes.
.EXAMPLE
    .\windows-hardening.ps1
    .\windows-hardening.ps1 -AuditOnly
#>

param(
    [switch]$AuditOnly
)

$ErrorActionPreference = "Continue"

function Write-Section($title) {
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Write-Setting($name, $status) {
    if ($status -eq "Applied") {
        Write-Host "  [+] $name" -ForegroundColor Green
    } elseif ($status -eq "Already Set") {
        Write-Host "  [=] $name" -ForegroundColor DarkGray
    } elseif ($status -eq "Audit") {
        Write-Host "  [?] $name" -ForegroundColor Yellow
    } else {
        Write-Host "  [-] $name : $status" -ForegroundColor Red
    }
}

if ($AuditOnly) {
    Write-Host "`n  AUDIT MODE - No changes will be made`n" -ForegroundColor Yellow
}

# ============================================================
# 1. FIREWALL
# ============================================================
Write-Section "1. Windows Firewall"

try {
    $profiles = Get-NetFirewallProfile
    foreach ($profile in $profiles) {
        $name = $profile.Name
        if ($AuditOnly) {
            Write-Setting "$name - Enabled: $($profile.Enabled), Inbound: $($profile.DefaultInboundAction), Outbound: $($profile.DefaultOutboundAction)" "Audit"
        } else {
            if ($profile.Enabled -and $profile.DefaultInboundAction -eq "Block" -and $profile.DefaultOutboundAction -eq "Allow") {
                Write-Setting "$name profile: Enabled, Inbound=Block, Outbound=Allow" "Already Set"
            } else {
                Set-NetFirewallProfile -Name $name -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
                Write-Setting "$name profile: Enabled, Inbound=Block, Outbound=Allow" "Applied"
            }
        }
    }
} catch {
    Write-Setting "Firewall configuration" "Error: $_"
}

# ============================================================
# 2. SSH HARDENING
# ============================================================
Write-Section "2. OpenSSH Configuration"

try {
    # Ensure OpenSSH Server is installed
    $sshServer = Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Server*" }
    if ($AuditOnly) {
        Write-Setting "OpenSSH Server: $($sshServer.State)" "Audit"
    } else {
        if ($sshServer.State -ne "Installed") {
            Add-WindowsCapability -Online -Name $sshServer.Name
            Write-Setting "OpenSSH Server installed" "Applied"
        } else {
            Write-Setting "OpenSSH Server installed" "Already Set"
        }
    }

    $sshdConfig = "$env:ProgramData\ssh\sshd_config"
    if (Test-Path $sshdConfig) {
        $config = Get-Content $sshdConfig -Raw

        $hardeningRules = @{
            "PasswordAuthentication"     = "no"
            "PermitRootLogin"            = "no"
            "PermitEmptyPasswords"       = "no"
            "MaxAuthTries"               = "3"
            "ClientAliveInterval"        = "300"
            "ClientAliveCountMax"        = "2"
            "AllowTcpForwarding"         = "no"
            "X11Forwarding"              = "no"
        }

        if ($AuditOnly) {
            foreach ($key in $hardeningRules.Keys) {
                $match = [regex]::Match($config, "(?m)^\s*$key\s+(.+)")
                $current = if ($match.Success) { $match.Groups[1].Value.Trim() } else { "(not set)" }
                Write-Setting "$key = $current (want: $($hardeningRules[$key]))" "Audit"
            }
        } else {
            $modified = $false
            foreach ($key in $hardeningRules.Keys) {
                $desired = $hardeningRules[$key]
                $pattern = "(?m)^\s*#?\s*$key\s+.*$"
                $replacement = "$key $desired"

                if ($config -match "(?m)^\s*$key\s+$desired\s*$") {
                    Write-Setting "$key $desired" "Already Set"
                } else {
                    if ($config -match $pattern) {
                        $config = $config -replace $pattern, $replacement
                    } else {
                        $config += "`n$replacement"
                    }
                    Write-Setting "$key $desired" "Applied"
                    $modified = $true
                }
            }

            if ($modified) {
                $config | Set-Content $sshdConfig -Force
                Restart-Service sshd -ErrorAction SilentlyContinue
                Write-Setting "SSHD restarted with new config" "Applied"
            }
        }
    } else {
        Write-Setting "sshd_config not found (OpenSSH may not be installed)" "Skipped"
    }
} catch {
    Write-Setting "SSH configuration" "Error: $_"
}

# ============================================================
# 3. RDP LOCKDOWN
# ============================================================
Write-Section "3. Remote Desktop"

try {
    $rdpEnabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections).fDenyTSConnections

    if ($AuditOnly) {
        $state = if ($rdpEnabled -eq 1) { "Disabled" } else { "Enabled" }
        Write-Setting "RDP is currently: $state" "Audit"
    } else {
        # Disable RDP
        if ($rdpEnabled -eq 1) {
            Write-Setting "RDP disabled" "Already Set"
        } else {
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 1
            Write-Setting "RDP disabled" "Applied"
        }

        # If RDP is left enabled, enforce NLA
        $nla = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
        if ($nla -eq 1) {
            Write-Setting "NLA (Network Level Authentication) required" "Already Set"
        } else {
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1
            Write-Setting "NLA (Network Level Authentication) required" "Applied"
        }
    }

    # Remove RDP firewall rule
    $rdpRule = Get-NetFirewallRule -DisplayName "Remote Desktop*" -ErrorAction SilentlyContinue
    if ($AuditOnly) {
        if ($rdpRule) { Write-Setting "RDP firewall rules exist" "Audit" }
        else { Write-Setting "No RDP firewall rules" "Audit" }
    } else {
        if ($rdpRule) {
            $rdpRule | Disable-NetFirewallRule
            Write-Setting "RDP firewall rules disabled" "Applied"
        } else {
            Write-Setting "RDP firewall rules" "Already Set"
        }
    }
} catch {
    Write-Setting "RDP configuration" "Error: $_"
}

# ============================================================
# 4. ACCOUNT POLICIES
# ============================================================
Write-Section "4. Account Policies"

try {
    if ($AuditOnly) {
        $lockout = net accounts 2>&1
        Write-Setting "Current account policies:" "Audit"
        $lockout | ForEach-Object { Write-Host "      $_" -ForegroundColor Yellow }
    } else {
        # Account lockout: 5 attempts, 30 min lockout, 30 min reset
        net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 | Out-Null
        Write-Setting "Account lockout: 5 attempts, 30 min lockout" "Applied"

        # Password policy: min 8 chars, max age 90 days
        net accounts /minpwlen:8 /maxpwage:90 /minpwage:1 /uniquepw:5 | Out-Null
        Write-Setting "Password policy: min 8 chars, 90 day max age, 5 history" "Applied"

        # Disable Guest account
        net user Guest /active:no 2>$null | Out-Null
        Write-Setting "Guest account disabled" "Applied"
    }
} catch {
    Write-Setting "Account policies" "Error: $_"
}

# ============================================================
# 5. AUDIT POLICIES
# ============================================================
Write-Section "5. Audit Policies"

try {
    $auditCategories = @(
        @{ Name = "Logon/Logoff";      Guid = "{69979849-797A-11D9-BED3-505054503030}" },
        @{ Name = "Account Logon";     Guid = "{69979850-797A-11D9-BED3-505054503030}" },
        @{ Name = "Object Access";     Guid = "{6997984A-797A-11D9-BED3-505054503030}" },
        @{ Name = "Privilege Use";     Guid = "{6997984B-797A-11D9-BED3-505054503030}" },
        @{ Name = "Account Management";Guid = "{6997984E-797A-11D9-BED3-505054503030}" },
        @{ Name = "Policy Change";     Guid = "{6997984D-797A-11D9-BED3-505054503030}" }
    )

    foreach ($cat in $auditCategories) {
        if ($AuditOnly) {
            $result = auditpol /get /category:"$($cat.Name)" 2>&1
            Write-Setting "Audit: $($cat.Name)" "Audit"
        } else {
            auditpol /set /category:"$($cat.Name)" /success:enable /failure:enable 2>&1 | Out-Null
            Write-Setting "Audit: $($cat.Name) (Success+Failure)" "Applied"
        }
    }
} catch {
    Write-Setting "Audit policies" "Error: $_"
}

# ============================================================
# 6. DISABLE UNNECESSARY SERVICES
# ============================================================
Write-Section "6. Unnecessary Services"

$servicesToDisable = @(
    @{ Name = "RemoteRegistry";    Desc = "Remote Registry" },
    @{ Name = "XblAuthManager";    Desc = "Xbox Live Auth Manager" },
    @{ Name = "XblGameSave";       Desc = "Xbox Live Game Save" },
    @{ Name = "XboxGipSvc";        Desc = "Xbox Accessory Management" },
    @{ Name = "XboxNetApiSvc";     Desc = "Xbox Live Networking" },
    @{ Name = "Fax";               Desc = "Fax" },
    @{ Name = "lfsvc";             Desc = "Geolocation Service" },
    @{ Name = "MapsBroker";        Desc = "Downloaded Maps Manager" },
    @{ Name = "RetailDemo";        Desc = "Retail Demo Service" },
    @{ Name = "WMPNetworkSvc";     Desc = "Windows Media Player Sharing" },
    @{ Name = "DiagTrack";         Desc = "Connected User Experiences and Telemetry" },
    @{ Name = "dmwappushservice";   Desc = "Device Management WAP Push" }
)

foreach ($svc in $servicesToDisable) {
    try {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            Write-Setting "$($svc.Desc) - not installed" "Already Set"
            continue
        }

        if ($AuditOnly) {
            Write-Setting "$($svc.Desc): $($service.Status), StartType: $($service.StartType)" "Audit"
        } else {
            if ($service.StartType -eq "Disabled") {
                Write-Setting "$($svc.Desc) disabled" "Already Set"
            } else {
                Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svc.Name -StartupType Disabled
                Write-Setting "$($svc.Desc) disabled" "Applied"
            }
        }
    } catch {
        Write-Setting "$($svc.Desc)" "Error: $_"
    }
}

# ============================================================
# 7. TELEMETRY & PRIVACY
# ============================================================
Write-Section "7. Telemetry & Privacy"

$telemetrySettings = @(
    @{
        Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        Name  = "AllowTelemetry"
        Value = 0
        Type  = "DWord"
        Desc  = "Telemetry set to Security (minimum)"
    },
    @{
        Path  = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
        Name  = "Enabled"
        Value = 0
        Type  = "DWord"
        Desc  = "Advertising ID disabled"
    },
    @{
        Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        Name  = "EnableActivityFeed"
        Value = 0
        Type  = "DWord"
        Desc  = "Activity History disabled"
    },
    @{
        Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        Name  = "PublishUserActivities"
        Value = 0
        Type  = "DWord"
        Desc  = "Publish User Activities disabled"
    },
    @{
        Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        Name  = "UploadUserActivities"
        Value = 0
        Type  = "DWord"
        Desc  = "Upload User Activities disabled"
    },
    @{
        Path  = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        Name  = "SubscribedContent-338393Enabled"
        Value = 0
        Type  = "DWord"
        Desc  = "Suggested content in Settings disabled"
    },
    @{
        Path  = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        Name  = "SubscribedContent-353694Enabled"
        Value = 0
        Type  = "DWord"
        Desc  = "Suggested content in Start disabled"
    },
    @{
        Path  = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        Name  = "SilentInstalledAppsEnabled"
        Value = 0
        Type  = "DWord"
        Desc  = "Silent app installs disabled"
    },
    @{
        Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        Name  = "DisableWindowsConsumerFeatures"
        Value = 1
        Type  = "DWord"
        Desc  = "Consumer features (bloatware) disabled"
    }
)

foreach ($setting in $telemetrySettings) {
    try {
        if (-not (Test-Path $setting.Path)) {
            if ($AuditOnly) {
                Write-Setting "$($setting.Desc) - registry path does not exist" "Audit"
                continue
            }
            New-Item -Path $setting.Path -Force | Out-Null
        }

        $current = Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue

        if ($AuditOnly) {
            $val = if ($null -ne $current) { $current.$($setting.Name) } else { "(not set)" }
            Write-Setting "$($setting.Desc): $val (want: $($setting.Value))" "Audit"
        } else {
            if ($null -ne $current -and $current.$($setting.Name) -eq $setting.Value) {
                Write-Setting $setting.Desc "Already Set"
            } else {
                New-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -PropertyType $setting.Type -Force | Out-Null
                Write-Setting $setting.Desc "Applied"
            }
        }
    } catch {
        Write-Setting $setting.Desc "Error: $_"
    }
}

# ============================================================
# 8. WINDOWS DEFENDER
# ============================================================
Write-Section "8. Windows Defender"

try {
    $defenderPrefs = Get-MpPreference -ErrorAction Stop

    $defenderSettings = @(
        @{ Name = "DisableRealtimeMonitoring";      Desired = $false;  Desc = "Real-time protection enabled" },
        @{ Name = "MAPSReporting";                   Desired = 2;      Desc = "Cloud-delivered protection (Advanced)" },
        @{ Name = "SubmitSamplesConsent";             Desired = 1;      Desc = "Automatic sample submission" },
        @{ Name = "PUAProtection";                   Desired = 1;      Desc = "Potentially Unwanted App protection" },
        @{ Name = "DisableIOAVProtection";           Desired = $false;  Desc = "Download scanning enabled" },
        @{ Name = "DisableScriptScanning";           Desired = $false;  Desc = "Script scanning enabled" }
    )

    foreach ($s in $defenderSettings) {
        $current = $defenderPrefs.$($s.Name)
        if ($AuditOnly) {
            Write-Setting "$($s.Desc): current=$current, want=$($s.Desired)" "Audit"
        } else {
            if ($current -eq $s.Desired) {
                Write-Setting $s.Desc "Already Set"
            } else {
                $params = @{ $s.Name = $s.Desired }
                Set-MpPreference @params
                Write-Setting $s.Desc "Applied"
            }
        }
    }

    # Enable controlled folder access
    if ($AuditOnly) {
        Write-Setting "Controlled Folder Access: $($defenderPrefs.EnableControlledFolderAccess)" "Audit"
    } else {
        if ($defenderPrefs.EnableControlledFolderAccess -eq 1) {
            Write-Setting "Controlled Folder Access" "Already Set"
        } else {
            Set-MpPreference -EnableControlledFolderAccess Enabled
            Write-Setting "Controlled Folder Access enabled" "Applied"
        }
    }

    # Update signatures
    if (-not $AuditOnly) {
        Write-Setting "Updating Defender signatures..." "Applied"
        Update-MpSignature -ErrorAction SilentlyContinue
    }
} catch {
    Write-Setting "Windows Defender" "Error: $_ (may be managed by organization policy)"
}

# ============================================================
# 9. MISCELLANEOUS SECURITY
# ============================================================
Write-Section "9. Miscellaneous Security"

# --- SMBv1 ---
try {
    $smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
    if ($AuditOnly) {
        Write-Setting "SMBv1: $smb1" "Audit"
    } else {
        if ($smb1 -eq $false) {
            Write-Setting "SMBv1 disabled" "Already Set"
        } else {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
            Write-Setting "SMBv1 disabled" "Applied"
        }
    }
} catch {
    Write-Setting "SMBv1" "Error: $_"
}

# --- Autorun / AutoPlay ---
$autorunSettings = @(
    @{
        Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        Name  = "NoDriveTypeAutoRun"
        Value = 255
        Desc  = "AutoRun disabled for all drives"
    },
    @{
        Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        Name  = "NoAutorun"
        Value = 1
        Desc  = "AutoRun commands disabled"
    }
)

foreach ($setting in $autorunSettings) {
    try {
        if (-not (Test-Path $setting.Path)) {
            if ($AuditOnly) { Write-Setting "$($setting.Desc) - path missing" "Audit"; continue }
            New-Item -Path $setting.Path -Force | Out-Null
        }
        $current = Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue
        if ($AuditOnly) {
            $val = if ($null -ne $current) { $current.$($setting.Name) } else { "(not set)" }
            Write-Setting "$($setting.Desc): $val" "Audit"
        } else {
            if ($null -ne $current -and $current.$($setting.Name) -eq $setting.Value) {
                Write-Setting $setting.Desc "Already Set"
            } else {
                New-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -PropertyType DWord -Force | Out-Null
                Write-Setting $setting.Desc "Applied"
            }
        }
    } catch {
        Write-Setting $setting.Desc "Error: $_"
    }
}

# --- Speculative Execution Mitigations ---
try {
    $specPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    $specCurrent = Get-ItemProperty -Path $specPath -Name "FeatureSettingsOverride" -ErrorAction SilentlyContinue

    if ($AuditOnly) {
        $val = if ($null -ne $specCurrent) { $specCurrent.FeatureSettingsOverride } else { "(not set)" }
        Write-Setting "Speculative Execution mitigations: $val" "Audit"
    } else {
        # Enable all mitigations
        if ($null -ne $specCurrent -and $specCurrent.FeatureSettingsOverride -eq 72) {
            Write-Setting "Speculative Execution mitigations" "Already Set"
        } else {
            New-ItemProperty -Path $specPath -Name "FeatureSettingsOverride" -Value 72 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $specPath -Name "FeatureSettingsOverrideMask" -Value 3 -PropertyType DWord -Force | Out-Null
            Write-Setting "Speculative Execution mitigations enabled" "Applied"
        }
    }
} catch {
    Write-Setting "Speculative Execution" "Error: $_"
}

# --- PowerShell Script Block Logging ---
try {
    $psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $psLogPath)) {
        if (-not $AuditOnly) { New-Item -Path $psLogPath -Force | Out-Null }
    }
    $psLog = Get-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue

    if ($AuditOnly) {
        $val = if ($null -ne $psLog) { $psLog.EnableScriptBlockLogging } else { "(not set)" }
        Write-Setting "PowerShell Script Block Logging: $val" "Audit"
    } else {
        if ($null -ne $psLog -and $psLog.EnableScriptBlockLogging -eq 1) {
            Write-Setting "PowerShell Script Block Logging" "Already Set"
        } else {
            New-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force | Out-Null
            Write-Setting "PowerShell Script Block Logging enabled" "Applied"
        }
    }
} catch {
    Write-Setting "PowerShell Logging" "Error: $_"
}

# --- LSA Protection ---
try {
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $lsa = Get-ItemProperty -Path $lsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue

    if ($AuditOnly) {
        $val = if ($null -ne $lsa) { $lsa.RunAsPPL } else { "(not set)" }
        Write-Setting "LSA Protection (RunAsPPL): $val" "Audit"
    } else {
        if ($null -ne $lsa -and $lsa.RunAsPPL -eq 1) {
            Write-Setting "LSA Protection enabled" "Already Set"
        } else {
            New-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1 -PropertyType DWord -Force | Out-Null
            Write-Setting "LSA Protection enabled" "Applied"
        }
    }
} catch {
    Write-Setting "LSA Protection" "Error: $_"
}

# ============================================================
# SUMMARY
# ============================================================
Write-Host "`n============================================================" -ForegroundColor Cyan
if ($AuditOnly) {
    Write-Host "  AUDIT COMPLETE - No changes were made" -ForegroundColor Yellow
} else {
    Write-Host "  HARDENING COMPLETE" -ForegroundColor Green
    Write-Host "  Some changes may require a reboot to take effect." -ForegroundColor Yellow
}
Write-Host "============================================================`n" -ForegroundColor Cyan
