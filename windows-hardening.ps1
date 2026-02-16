#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows 11 Security Hardening Script
.DESCRIPTION
    Applies comprehensive security and privacy hardening for Windows 11.
    Covers firewall, SSH, RDP, account policies, audit policies, services,
    telemetry/privacy, Windows Defender, network hardening, and exploit
    mitigations. Safe to re-run (idempotent).
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

# Helper: apply a registry setting (creates path if needed)
function Set-RegistrySetting {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = "DWord",
        [string]$Desc
    )
    try {
        if (-not (Test-Path $Path)) {
            if ($AuditOnly) {
                Write-Setting "$Desc - registry path does not exist" "Audit"
                return
            }
            New-Item -Path $Path -Force | Out-Null
        }
        $current = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($AuditOnly) {
            $val = if ($null -ne $current) { $current.$Name } else { "(not set)" }
            Write-Setting "${Desc}: $val (want: $Value)" "Audit"
        } else {
            if ($null -ne $current -and $current.$Name -eq $Value) {
                Write-Setting $Desc "Already Set"
            } else {
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
                Write-Setting $Desc "Applied"
            }
        }
    } catch {
        Write-Setting $Desc "Error: $_"
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
        if ($rdpEnabled -eq 1) {
            Write-Setting "RDP disabled" "Already Set"
        } else {
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 1
            Write-Setting "RDP disabled" "Applied"
        }

        # Enforce NLA even with RDP off
        $nla = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
        if ($nla -eq 1) {
            Write-Setting "NLA (Network Level Authentication) required" "Already Set"
        } else {
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1
            Write-Setting "NLA (Network Level Authentication) required" "Applied"
        }
    }

    # Disable RDP firewall rules
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

# --- Remote Assistance ---
Set-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" `
    -Name "fAllowToGetHelp" -Value 0 -Desc "Remote Assistance disabled"

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
        net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 | Out-Null
        Write-Setting "Account lockout: 5 attempts, 30 min lockout" "Applied"

        net accounts /minpwlen:8 /maxpwage:90 /minpwage:1 /uniquepw:5 | Out-Null
        Write-Setting "Password policy: min 8 chars, 90 day max age, 5 history" "Applied"

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
    @{ Name = "dmwappushservice";  Desc = "Device Management WAP Push" }
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

# --- CEIP Scheduled Tasks ---
$ceipTasks = @(
    @{ Path = '\Microsoft\Windows\Customer Experience Improvement Program\'; Name = 'Consolidator';  Desc = "CEIP Consolidator task" },
    @{ Path = '\Microsoft\Windows\Customer Experience Improvement Program\'; Name = 'UsbCeip';       Desc = "CEIP USB telemetry task" }
)

foreach ($task in $ceipTasks) {
    try {
        $t = Get-ScheduledTask -TaskPath $task.Path -TaskName $task.Name -ErrorAction SilentlyContinue
        if ($null -eq $t) {
            Write-Setting "$($task.Desc) - not found" "Already Set"
            continue
        }
        if ($AuditOnly) {
            Write-Setting "$($task.Desc): $($t.State)" "Audit"
        } else {
            if ($t.State -eq "Disabled") {
                Write-Setting "$($task.Desc) disabled" "Already Set"
            } else {
                Disable-ScheduledTask -TaskPath $task.Path -TaskName $task.Name | Out-Null
                Write-Setting "$($task.Desc) disabled" "Applied"
            }
        }
    } catch {
        Write-Setting $task.Desc "Error: $_"
    }
}

# ============================================================
# 7. TELEMETRY & PRIVACY
# ============================================================
Write-Section "7. Telemetry & Privacy"

$telemetrySettings = @(
    # --- Telemetry Level ---
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
       Name = "AllowTelemetry"; Value = 0; Type = "DWord"
       Desc = "Telemetry set to Security (minimum)" },

    # --- Activity History ---
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
       Name = "EnableActivityFeed"; Value = 0; Type = "DWord"
       Desc = "Activity Feed disabled" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
       Name = "PublishUserActivities"; Value = 0; Type = "DWord"
       Desc = "Publish User Activities disabled" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
       Name = "UploadUserActivities"; Value = 0; Type = "DWord"
       Desc = "Upload User Activities disabled" },

    # --- Online Speech Recognition ---
    @{ Path = "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy"
       Name = "HasAccepted"; Value = 0; Type = "DWord"
       Desc = "Online Speech Recognition disabled" },

    # --- Inking & Typing Personalization ---
    @{ Path = "HKCU:\Software\Microsoft\InputPersonalization"
       Name = "RestrictImplicitInkCollection"; Value = 1; Type = "DWord"
       Desc = "Implicit ink collection restricted" },
    @{ Path = "HKCU:\Software\Microsoft\InputPersonalization"
       Name = "RestrictImplicitTextCollection"; Value = 1; Type = "DWord"
       Desc = "Implicit text collection restricted" },
    @{ Path = "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore"
       Name = "HarvestContacts"; Value = 0; Type = "DWord"
       Desc = "Contact harvesting for personalization disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Personalization\Settings"
       Name = "AcceptedPrivacyPolicy"; Value = 0; Type = "DWord"
       Desc = "Typing personalization privacy policy rejected" },

    # --- Advertising ID ---
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
       Name = "Enabled"; Value = 0; Type = "DWord"
       Desc = "Advertising ID disabled" },

    # --- App Launch Tracking ---
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
       Name = "Start_TrackProgs"; Value = 0; Type = "DWord"
       Desc = "App launch tracking disabled" },

    # --- Feedback Prompts ---
    @{ Path = "HKCU:\Software\Microsoft\Siuf\Rules"
       Name = "NumberOfSIUFInPeriod"; Value = 0; Type = "DWord"
       Desc = "Feedback prompts disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Siuf\Rules"
       Name = "PeriodInNanoSeconds"; Value = 0; Type = "DWord"
       Desc = "Feedback period set to zero" },

    # --- Suggested Content & Ads (all 14 channels) ---
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
       Name = "SubscribedContent-338393Enabled"; Value = 0; Type = "DWord"
       Desc = "Settings suggestions disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
       Name = "SubscribedContent-353694Enabled"; Value = 0; Type = "DWord"
       Desc = "Start suggestions disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
       Name = "SubscribedContent-353696Enabled"; Value = 0; Type = "DWord"
       Desc = "Notification suggestions disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
       Name = "SubscribedContent-310093Enabled"; Value = 0; Type = "DWord"
       Desc = "Welcome Experience disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
       Name = "SubscribedContent-338388Enabled"; Value = 0; Type = "DWord"
       Desc = "Timeline suggestions disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
       Name = "SubscribedContent-338389Enabled"; Value = 0; Type = "DWord"
       Desc = "Tips and tricks disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
       Name = "SystemPaneSuggestionsEnabled"; Value = 0; Type = "DWord"
       Desc = "Start menu ads disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
       Name = "SoftLandingEnabled"; Value = 0; Type = "DWord"
       Desc = "Spotlight suggestions disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
       Name = "SilentInstalledAppsEnabled"; Value = 0; Type = "DWord"
       Desc = "Silent app installs disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
       Name = "ContentDeliveryAllowed"; Value = 0; Type = "DWord"
       Desc = "Content delivery disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
       Name = "FeatureManagementEnabled"; Value = 0; Type = "DWord"
       Desc = "Feature suggestions disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
       Name = "OemPreInstalledAppsEnabled"; Value = 0; Type = "DWord"
       Desc = "OEM app suggestions disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
       Name = "PreInstalledAppsEnabled"; Value = 0; Type = "DWord"
       Desc = "Pre-installed app ads disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
       Name = "PreInstalledAppsEverEnabled"; Value = 0; Type = "DWord"
       Desc = "Pre-installed apps ever-enabled flag cleared" },

    # --- Consumer Features / Bloatware ---
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
       Name = "DisableWindowsConsumerFeatures"; Value = 1; Type = "DWord"
       Desc = "Consumer features (bloatware) disabled" },

    # --- Clipboard Cloud Sync ---
    @{ Path = "HKCU:\Software\Microsoft\Clipboard"
       Name = "EnableCloudClipboard"; Value = 0; Type = "DWord"
       Desc = "Clipboard cloud sync disabled" },

    # --- Location History ---
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
       Name = "Value"; Value = "Deny"; Type = "String"
       Desc = "Location history sending disabled" },

    # --- Error Reporting ---
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent"
       Name = "DefaultConsent"; Value = 1; Type = "DWord"
       Desc = "Error reporting set to ask before sending" },

    # --- Bing Search & Cortana in Start ---
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
       Name = "BingSearchEnabled"; Value = 0; Type = "DWord"
       Desc = "Bing search in Start disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
       Name = "CortanaConsent"; Value = 0; Type = "DWord"
       Desc = "Cortana consent disabled" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
       Name = "DisableSearchBoxSuggestions"; Value = 1; Type = "DWord"
       Desc = "Search box suggestions disabled" },

    # --- Widgets & News ---
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"
       Name = "AllowNewsAndInterests"; Value = 0; Type = "DWord"
       Desc = "Widgets & News feed disabled" },

    # --- Background App Permissions ---
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation"
       Name = "Value"; Value = "Deny"; Type = "String"
       Desc = "Background access to account info denied" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory"
       Name = "Value"; Value = "Deny"; Type = "String"
       Desc = "Background access to call history denied" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts"
       Name = "Value"; Value = "Deny"; Type = "String"
       Desc = "Background access to contacts denied" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email"
       Name = "Value"; Value = "Deny"; Type = "String"
       Desc = "Background access to email denied" }
)

foreach ($setting in $telemetrySettings) {
    Set-RegistrySetting @setting
}

# --- Edge Tracking ---
Write-Section "7b. Edge Tracking"

$edgeSettings = @(
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
       Name = "PersonalizationReportingEnabled"; Value = 0; Type = "DWord"
       Desc = "Edge personalization reporting disabled" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
       Name = "SendSiteInfoToImproveServices"; Value = 0; Type = "DWord"
       Desc = "Edge send site info disabled" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
       Name = "ResolveNavigationErrorsUseWebService"; Value = 0; Type = "DWord"
       Desc = "Edge navigation error web service disabled" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
       Name = "AlternateErrorPagesEnabled"; Value = 0; Type = "DWord"
       Desc = "Edge alternate error pages disabled" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
       Name = "SpotlightExperiencesAndSuggestionsEnabled"; Value = 0; Type = "DWord"
       Desc = "Edge spotlight suggestions disabled" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
       Name = "EdgeShoppingAssistantEnabled"; Value = 0; Type = "DWord"
       Desc = "Edge shopping assistant disabled" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
       Name = "DiagnosticData"; Value = 0; Type = "DWord"
       Desc = "Edge diagnostic telemetry disabled" }
)

foreach ($setting in $edgeSettings) {
    Set-RegistrySetting @setting
}

# ============================================================
# 8. WINDOWS DEFENDER
# ============================================================
Write-Section "8. Windows Defender"

try {
    $defenderPrefs = Get-MpPreference -ErrorAction Stop

    $defenderSettings = @(
        @{ Name = "DisableRealtimeMonitoring";  Desired = $false; Desc = "Real-time protection enabled" },
        @{ Name = "MAPSReporting";              Desired = 2;      Desc = "Cloud-delivered protection (Advanced)" },
        @{ Name = "SubmitSamplesConsent";        Desired = 1;      Desc = "Automatic sample submission" },
        @{ Name = "PUAProtection";              Desired = 1;      Desc = "Potentially Unwanted App protection" },
        @{ Name = "DisableIOAVProtection";      Desired = $false; Desc = "Download scanning enabled" },
        @{ Name = "DisableScriptScanning";      Desired = $false; Desc = "Script scanning enabled" }
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

    # Network Protection
    if ($AuditOnly) {
        Write-Setting "Network Protection: $($defenderPrefs.EnableNetworkProtection)" "Audit"
    } else {
        if ($defenderPrefs.EnableNetworkProtection -eq 1) {
            Write-Setting "Network Protection enabled" "Already Set"
        } else {
            Set-MpPreference -EnableNetworkProtection Enabled
            Write-Setting "Network Protection enabled (blocks C2, phishing, malicious domains)" "Applied"
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
# 9. NETWORK HARDENING
# ============================================================
Write-Section "9. Network Hardening"

# --- LLMNR ---
Set-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -Value 0 -Desc "LLMNR disabled (prevents credential theft on local network)"

# --- NetBIOS over TCP ---
try {
    $adapters = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue
    if ($AuditOnly) {
        $nbCount = ($adapters | Where-Object {
            (Get-ItemProperty $_.PSPath -Name "NetbiosOptions" -ErrorAction SilentlyContinue).NetbiosOptions -eq 2
        }).Count
        Write-Setting "NetBIOS disabled on $nbCount / $($adapters.Count) adapters" "Audit"
    } else {
        $changed = 0
        foreach ($adapter in $adapters) {
            $current = (Get-ItemProperty $adapter.PSPath -Name "NetbiosOptions" -ErrorAction SilentlyContinue).NetbiosOptions
            if ($current -ne 2) {
                Set-ItemProperty $adapter.PSPath -Name "NetbiosOptions" -Value 2
                $changed++
            }
        }
        if ($changed -gt 0) {
            Write-Setting "NetBIOS over TCP disabled on $changed adapter(s)" "Applied"
        } else {
            Write-Setting "NetBIOS over TCP disabled on all adapters" "Already Set"
        }
    }
} catch {
    Write-Setting "NetBIOS" "Error: $_"
}

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

# --- SMB Signing ---
Set-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
    -Name "RequireSecuritySignature" -Value 1 -Desc "SMB Signing required (server)"
Set-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -Name "RequireSecuritySignature" -Value 1 -Desc "SMB Signing required (client)"

# --- DNS-over-HTTPS ---
Set-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" `
    -Name "EnableAutoDoh" -Value 2 -Desc "DNS-over-HTTPS enabled (auto mode)"

# --- WPAD ---
Set-RegistrySetting -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" `
    -Name "WpadOverride" -Value 1 -Desc "WPAD disabled (prevents MITM proxy attacks)"
Set-RegistrySetting -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" `
    -Name "WpadOverride" -Value 1 -Desc "WPAD disabled system-wide"

# ============================================================
# 10. EXPLOIT MITIGATIONS & SECURITY HARDENING
# ============================================================
Write-Section "10. Exploit Mitigations & Security Hardening"

# --- Exploit Protection: ASLR & SEHOP ---
try {
    if ($AuditOnly) {
        $mitigations = Get-ProcessMitigation -System
        Write-Setting "ASLR BottomUp: $($mitigations.Aslr.BottomUp)" "Audit"
        Write-Setting "ASLR HighEntropy: $($mitigations.Aslr.HighEntropy)" "Audit"
        Write-Setting "SEHOP: $($mitigations.SEHOP.Enable)" "Audit"
    } else {
        Set-ProcessMitigation -System -Enable BottomUp
        Write-Setting "ASLR BottomUp enabled (randomizes memory layout)" "Applied"
        Set-ProcessMitigation -System -Enable HighEntropy
        Write-Setting "ASLR HighEntropy enabled (64-bit address randomization)" "Applied"
        Set-ProcessMitigation -System -Enable SEHOP
        Write-Setting "SEHOP enabled (prevents SEH overwrite exploits)" "Applied"
    }
} catch {
    Write-Setting "Exploit Protection" "Error: $_"
}

# --- Speculative Execution Mitigations ---
try {
    $specPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    $specCurrent = Get-ItemProperty -Path $specPath -Name "FeatureSettingsOverride" -ErrorAction SilentlyContinue

    if ($AuditOnly) {
        $val = if ($null -ne $specCurrent) { $specCurrent.FeatureSettingsOverride } else { "(not set)" }
        Write-Setting "Speculative Execution mitigations: $val" "Audit"
    } else {
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
Set-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -Value 1 -Desc "PowerShell Script Block Logging enabled"

# --- LSA Protection ---
Set-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RunAsPPL" -Value 1 -Desc "LSA Protection enabled (prevents credential dumping)"

# --- WDigest ---
Set-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -Name "UseLogonCredential" -Value 0 -Desc "WDigest disabled (no cleartext passwords in memory)"

# --- Windows Script Host ---
Set-RegistrySetting -Path "HKCU:\Software\Microsoft\Windows Script Host\Settings" `
    -Name "Enabled" -Value 0 -Desc "Windows Script Host disabled (blocks .vbs/.js malware)"

# --- AutoRun / AutoPlay ---
Set-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name "NoDriveTypeAutoRun" -Value 255 -Desc "AutoRun disabled for all drive types"
Set-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name "NoAutorun" -Value 1 -Desc "AutoRun commands disabled"
Set-RegistrySetting -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" `
    -Name "DisableAutoplay" -Value 1 -Desc "AutoPlay disabled (prevents USB-based malware)"

# --- Screen Lock Timeout ---
Set-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "InactivityTimeoutSecs" -Value 600 -Desc "Screen lock timeout set to 10 minutes"

# --- File Extensions & Hidden Files ---
Set-RegistrySetting -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
    -Name "HideFileExt" -Value 0 -Desc "File extensions always visible (spots disguised executables)"
Set-RegistrySetting -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
    -Name "Hidden" -Value 1 -Desc "Hidden files visible (spots hidden malware)"

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
