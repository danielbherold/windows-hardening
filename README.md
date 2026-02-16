# Windows 11 Hardening Script

PowerShell script that applies security and privacy hardening to Windows 11. Idempotent — safe to re-run. Requires Administrator.

## Usage

```powershell
# Apply all hardening
.\windows-hardening.ps1

# Audit only (no changes, just reports current state)
.\windows-hardening.ps1 -AuditOnly
```

## What It Does

### 1. Firewall
Enables Windows Firewall on all profiles with inbound blocked by default. Outbound remains allowed. This ensures unsolicited connections are dropped unless explicitly permitted by a rule.

### 2. SSH Hardening
Configures OpenSSH Server for key-only authentication. Disables password auth, root login, empty passwords, and TCP/X11 forwarding. Limits auth attempts to 3 with idle timeout.

### 3. Remote Desktop & Remote Assistance
Disables RDP entirely and removes its firewall rules. Enforces Network Level Authentication as a fallback. Disables Remote Assistance to close the remote control vector.

### 4. Account Policies
Sets account lockout (5 attempts, 30 min), password requirements (8 char min, 90 day max age, 5 password history), and disables the Guest account.

### 5. Audit Policies
Enables success and failure auditing for logon/logoff, account logon, object access, privilege use, account management, and policy changes. Provides a forensic trail for security events.

### 6. Services & Scheduled Tasks
Disables services that increase attack surface or leak telemetry:
- **DiagTrack** — the main telemetry pipeline that collects and transmits usage data
- **Remote Registry** — allows remote access to the Windows registry
- **Xbox services** (4) — unnecessary background services
- **Fax, Geolocation, Maps, Retail Demo, WMP Sharing, WAP Push**
- **CEIP tasks** (Consolidator, UsbCeip) — periodic telemetry collection

### 7. Telemetry & Privacy
Shuts down 40+ data collection channels:

| Category | What it stops |
|----------|--------------|
| **Telemetry** | Sets to Security level (minimum). Disables DiagTrack service |
| **Activity History** | Stops logging and uploading app/document/website activity to Microsoft |
| **Speech Recognition** | Stops sending voice input to Microsoft cloud for processing |
| **Inking & Typing** | Stops collecting every keystroke and handwriting input |
| **Advertising ID** | Disables the cross-app tracking identifier |
| **App Launch Tracking** | Stops recording every app you open |
| **Feedback** | Disables feedback prompts and their telemetry |
| **Ads & Suggestions** | Kills all 14 ad channels — Start menu ads, notification suggestions, silent app installs, spotlight, tips, OEM apps, welcome experience, etc. |
| **Bloatware** | Disables consumer features that auto-install Candy Crush, TikTok, etc. |
| **Clipboard** | Disables cloud sync (local clipboard still works) |
| **Location** | Stops sending location history to Microsoft |
| **Error Reporting** | Changes from auto-send to ask first (crash dumps can contain passwords) |
| **Bing & Cortana** | Stops sending Start menu searches to Bing |
| **Widgets & News** | Disables the engagement-tracking news feed |
| **Background Apps** | Denies silent access to account info, contacts, email, call history |
| **Edge** | Disables 7 tracking policies — personalization, site info reporting, shopping assistant, diagnostics, spotlight suggestions |

### 8. Windows Defender
Ensures real-time protection, cloud-delivered protection (Advanced), PUA blocking, download scanning, and script scanning are all enabled. Adds **Network Protection** which blocks outbound connections to known C2 servers, phishing sites, and malicious domains. Updates signatures.

### 9. Network Hardening

| Setting | Why |
|---------|-----|
| **LLMNR disabled** | Prevents trivial credential theft on local networks via name resolution spoofing |
| **NetBIOS disabled** | Stops broadcasting computer name/shares to the network. Prevents NBNS spoofing |
| **SMBv1 disabled** | Legacy protocol exploited by WannaCry and EternalBlue |
| **SMB Signing required** | Prevents interception and modification of file sharing traffic (relay attacks) |
| **DNS-over-HTTPS** | Encrypts DNS queries so ISPs and network attackers can't see domains you visit |
| **WPAD disabled** | Prevents attackers from serving malicious proxy configs on your network (MITM) |

### 10. Exploit Mitigations

| Setting | Why |
|---------|-----|
| **ASLR BottomUp** | Randomizes memory layout so attackers can't predict where code lives |
| **ASLR HighEntropy** | Uses full 64-bit address space for stronger randomization |
| **SEHOP** | Prevents Structured Exception Handler overwrite exploits |
| **Speculative Execution** | Mitigates Spectre/Meltdown CPU vulnerabilities |
| **PowerShell Logging** | Logs all script blocks — PowerShell is the #1 attacker tool on Windows |
| **LSA Protection** | Prevents tools like Mimikatz from dumping credentials from memory |
| **WDigest disabled** | Stops storing passwords in cleartext in memory |
| **Windows Script Host disabled** | Blocks .vbs/.js malware execution on double-click |
| **AutoRun/AutoPlay disabled** | Prevents USB-based malware (BadUSB, Rubber Ducky) |
| **Screen lock** | 10 minute inactivity timeout |
| **File extensions visible** | Spots disguised executables like `document.pdf.exe` |
| **Hidden files visible** | Spots malware that marks itself as hidden |

## What It Intentionally Does NOT Change

| Setting | Why |
|---------|-----|
| Controlled Folder Access | Blocks apps from writing to Desktop/Documents unless whitelisted — too disruptive for daily use |
| Credential Guard | Can break VMware Workstation and some enterprise apps |
| PowerShell Execution Policy | Left at current setting for development workflows |
| BitLocker encryption level | XtsAes128 is already strong; 256 requires full re-encryption for negligible benefit |
| Windows Update | Already configured correctly |
| Find My Device | Useful if laptop is lost or stolen |
