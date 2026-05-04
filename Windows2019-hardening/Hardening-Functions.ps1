<#
.SYNOPSIS
    Remediation functions for CIS Windows Server 2019 Benchmark v1.2.0.
.NOTES
    Run as Administrator. All registry settings are driven by CIS_Data.csv.
    Do NOT add manual Set-ItemProperty calls here - keep everything in the CSV
    so that hardening and audit always check the exact same path/name/value.
#>

# ── Helper: create every intermediate registry key in a path ─────────────────
function New-RegistryKeyPath {
    param([string]$FullPath)
    # e.g. HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy
    # New-Item -Force only creates ONE level at a time if parent is missing.
    # This function walks every segment and creates each one if absent.
    $segments = $FullPath -split '\\'
    $current  = $segments[0]   # e.g. "HKLM:"
    for ($i = 1; $i -lt $segments.Count; $i++) {
        $current = "$current\$($segments[$i])"
        if (-not (Test-Path $current)) {
            New-Item -Path $current -Force -ErrorAction Stop | Out-Null
        }
    }
}

# ── Helper: cast CSV string value to the correct registry type ────────────────
function ConvertTo-RegistryValue {
    param([string]$Value, [string]$Type)
    switch ($Type.ToUpper()) {
        'DWORD'  { return [int32]$Value }
        'QWORD'  { return [int64]$Value }
        'BINARY' { return [byte[]]($Value -split ',' | ForEach-Object { [byte]$_ }) }
        default  { return $Value }   # String, ExpandString, MultiString
    }
}

# ─────────────────────────────────────────────────────────────────────────────
function Start-CISHardening {
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "   CIS HARDENING - Windows Server 2019 v1.2.0  " -ForegroundColor White
    Write-Host "================================================" -ForegroundColor Cyan

    Set-CIS-AccountPolicies   # Section 1   - secedit (password/lockout)
    Set-CIS-UserRights        # Section 2.2 - secedit (privilege rights)
    Set-CIS-AuditPolicies     # Section 17  - auditpol
    Set-CIS-RegistryFromCSV   # Sections 2.3, 9, 18, 19 - all from CIS_Data.csv
    Set-CIS-Services          # Section 5   - disable unnecessary services
    Set-CIS-PostCleanup       # Temp file removal only (no gpupdate here)

    Write-Host "`n[+] All hardening modules applied." -ForegroundColor Green
    Write-Host "[!] Reboot or run 'gpupdate /force' to finalise policy propagation." -ForegroundColor Yellow
}

# ─────────────────────────────────────────────────────────────────────────────
# Section 1 - Account Policies (secedit only, no registry equivalent)
# ─────────────────────────────────────────────────────────────────────────────
function Set-CIS-AccountPolicies {
    Write-Host "[*] Section 1 - Account Policies (secedit)..." -ForegroundColor Cyan
    $Path = "$env:TEMP\CIS_Accounts.inf"
    @"
[Unicode]
Unicode=yes
[System Access]
PasswordHistorySize = 24
MaximumPasswordAge = 60
MinimumPasswordAge = 1
MinimumPasswordLength = 14
PasswordComplexity = 1
ClearTextPassword = 0
LockoutBadCount = 10
ResetLockoutCount = 15
LockoutDuration = 15
[Version]
signature="`$CHICAGO`$"
Revision=1
"@ | Out-File $Path -Encoding unicode
    secedit /configure /db "$env:windir\security\local.sdb" /cfg $Path /areas SECURITYPOLICY /overwrite /quiet
    Write-Host "  [OK] Account policies applied." -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────────────────
# Section 2.2 - User Rights Assignments (secedit only)
# ─────────────────────────────────────────────────────────────────────────────
function Set-CIS-UserRights {
    Write-Host "[*] Section 2.2 - User Rights (secedit)..." -ForegroundColor Cyan
    $Path = "$env:TEMP\CIS_Rights.inf"
    @"
[Unicode]
Unicode=yes
[Privilege Rights]
SeNetworkLogonRight       = *S-1-5-32-544,*S-1-5-32-551
SeTcbPrivilege            =
SeInteractiveLogonRight   = *S-1-5-32-544
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeBackupPrivilege         = *S-1-5-32-544
SeSystemtimePrivilege     = *S-1-5-32-544,*S-1-5-19
SeTimeZonePrivilege       = *S-1-5-32-544,*S-1-5-19,*S-1-5-32-545
SeCreatePagefilePrivilege = *S-1-5-32-544
SeCreateTokenPrivilege    =
SeCreateGlobalPrivilege   = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6
SeCreatePermanentPrivilege =
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeDebugPrivilege          = *S-1-5-32-544
SeDenyNetworkLogonRight   = *S-1-5-32-546
SeDenyInteractiveLogonRight = *S-1-5-32-546
SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546
SeEnableDelegationPrivilege =
SeRemoteShutdownPrivilege = *S-1-5-32-544
SeAuditPrivilege          = *S-1-5-19,*S-1-5-20
SeImpersonatePrivilege    = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544
SeLoadDriverPrivilege     = *S-1-5-32-544
SeLockMemoryPrivilege     =
SeBatchLogonRight         = *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-559
SeServiceLogonRight       =
SeSecurityPrivilege       = *S-1-5-32-544
SeRelabelPrivilege        =
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeManageVolumePrivilege   = *S-1-5-32-544
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeSystemProfilePrivilege  = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
SeRestorePrivilege        = *S-1-5-32-544
SeShutdownPrivilege       = *S-1-5-32-544
SeSyncAgentPrivilege      =
SeTakeOwnershipPrivilege  = *S-1-5-32-544
[Version]
signature="`$CHICAGO`$"
Revision=1
"@ | Out-File $Path -Encoding unicode
    secedit /configure /db "$env:windir\security\local.sdb" /cfg $Path /areas USER_RIGHTS /overwrite /quiet
    Write-Host "  [OK] User rights applied." -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────────────────
# Section 17 - Advanced Audit Policies (auditpol only)
# ─────────────────────────────────────────────────────────────────────────────
function Set-CIS-AuditPolicies {
    Write-Host "[*] Section 17 - Advanced Audit Policies (auditpol)..." -ForegroundColor Cyan
    $auditSettings = @(
        # 17.1 - Account Logon
        @{ Sub="Credential Validation";              S="enable"; F="enable"  },  # 17.1.1
        @{ Sub="Kerberos Authentication Service";    S="enable"; F="enable"  },  # 17.1.2 DC
        @{ Sub="Kerberos Service Ticket Operations"; S="enable"; F="enable"  },  # 17.1.3 DC
        # 17.2 - Account Management
        @{ Sub="Computer Account Management";        S="enable"; F="enable"  },  # 17.2.1 DC
        @{ Sub="Distribution Group Management";      S="enable"; F="disable" },  # 17.2.2 DC
        @{ Sub="Other Account Management Events";    S="enable"; F="enable"  },  # 17.2.3
        @{ Sub="Security Group Management";          S="enable"; F="enable"  },  # 17.2.4
        @{ Sub="User Account Management";            S="enable"; F="enable"  },  # 17.2.5
        # 17.3 - Detailed Tracking
        @{ Sub="Plug and Play Events";               S="enable"; F="disable" },  # 17.3.1
        @{ Sub="Process Creation";                   S="enable"; F="disable" },  # 17.3.2
        # 17.4 - DS Access (DC only)
        @{ Sub="Directory Service Access";           S="enable"; F="enable"  },  # 17.4.1 DC
        @{ Sub="Directory Service Changes";          S="enable"; F="enable"  },  # 17.4.2 DC
        # 17.5 - Logon/Logoff
        @{ Sub="Account Lockout";                    S="enable"; F="disable" },  # 17.5.1
        @{ Sub="Group Membership";                   S="enable"; F="disable" },  # 17.5.2
        @{ Sub="Logoff";                             S="enable"; F="disable" },  # 17.5.3
        @{ Sub="Logon";                              S="enable"; F="enable"  },  # 17.5.4
        @{ Sub="Other Logon/Logoff Events";          S="enable"; F="enable"  },  # 17.5.5
        @{ Sub="Special Logon";                      S="enable"; F="disable" },  # 17.5.6
        # 17.6 - Object Access
        @{ Sub="Detailed File Share";                S="enable"; F="disable" },  # 17.6.1
        @{ Sub="File Share";                         S="enable"; F="enable"  },  # 17.6.2
        @{ Sub="Other Object Access Events";         S="enable"; F="enable"  },  # 17.6.3
        @{ Sub="Removable Storage";                  S="enable"; F="enable"  },  # 17.6.4
        # 17.7 - Policy Change
        @{ Sub="Audit Policy Change";                S="enable"; F="enable"  },  # 17.7.1
        @{ Sub="Authentication Policy Change";       S="enable"; F="disable" },  # 17.7.2
        @{ Sub="Authorization Policy Change";        S="enable"; F="disable" },  # 17.7.3
        @{ Sub="MPSSVC Rule-Level Policy Change";    S="enable"; F="enable"  },  # 17.7.4
        @{ Sub="Other Policy Change Events";         S="disable"; F="enable" },  # 17.7.5
        # 17.8 - Privilege Use
        @{ Sub="Sensitive Privilege Use";            S="enable"; F="enable"  },  # 17.8.1
        # 17.9 - System
        @{ Sub="IPsec Driver";                       S="enable"; F="enable"  },  # 17.9.1
        @{ Sub="Other System Events";                S="enable"; F="enable"  },  # 17.9.2 MS
        @{ Sub="Security State Change";              S="enable"; F="disable" },  # 17.9.3
        @{ Sub="Security System Extension";          S="enable"; F="disable" },  # 17.9.4
        @{ Sub="System Integrity";                   S="enable"; F="enable"  }   # 17.9.5
    )

    # Force subcategory settings override category settings (2.3.2.1)
    auditpol /set /option:CrashOnAuditFail /value:disable | Out-Null

    foreach ($entry in $auditSettings) {
        $result = auditpol /set /subcategory:"$($entry.Sub)" /success:$($entry.S) /failure:$($entry.F) 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] Audit: $($entry.Sub)" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] Audit: $($entry.Sub) - $result" -ForegroundColor Yellow
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# ALL registry-based controls - driven entirely by CIS_Data.csv
# Sections 2.3, 9, 18, 19
# ─────────────────────────────────────────────────────────────────────────────
function Set-CIS-RegistryFromCSV {
    param([string]$CsvPath = "$PSScriptRoot\CIS_Data.csv")

    if (-not (Test-Path $CsvPath)) {
        Write-Host "[!] CSV not found: $CsvPath" -ForegroundColor Red
        return
    }

    $Policies = Import-Csv $CsvPath
    Write-Host "[*] Applying $($Policies.Count) registry settings from CSV..." -ForegroundColor Cyan

    $ok = 0; $err = 0
    foreach ($Policy in $Policies) {
        try {
            # BUG FIX 1: Create ALL intermediate keys recursively
            New-RegistryKeyPath -FullPath $Policy.Path

            # BUG FIX 2: Cast value to correct type before writing
            $TypedValue = ConvertTo-RegistryValue -Value $Policy.Value -Type $Policy.Type

            Set-ItemProperty -Path $Policy.Path -Name $Policy.Name -Value $TypedValue -Type $Policy.Type -Force -ErrorAction Stop
            $ok++
        }
        catch {
            Write-Host "  [ERROR] $($Policy.ID) ($($Policy.Name)): $($_.Exception.Message)" -ForegroundColor Red
            $err++
        }
    }
    Write-Host "  [OK] $ok applied, $err errors." -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────────────────
# Section 5 - Disable unnecessary services
# ─────────────────────────────────────────────────────────────────────────────
function Set-CIS-Services {
    Write-Host "[*] Section 5 - Disabling non-essential services..." -ForegroundColor Cyan
    $Services = @(
        "RemoteRegistry",   # 5.27 - Remote Registry
        "bthserv",          # 5.5  - Bluetooth Support
        "XblAuthManager",   # 5.42 - Xbox Live Auth
        "XblGameSave",      # 5.43 - Xbox Game Save
        "XboxNetApiSvc"     # 5.44 - Xbox Networking
    )
    foreach ($S in $Services) {
        if (Get-Service $S -ErrorAction SilentlyContinue) {
            Set-Service $S -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service $S -Force -ErrorAction SilentlyContinue
            Write-Host "  [OK] Disabled: $S" -ForegroundColor Green
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Cleanup - temp files only, NO gpupdate (handled by main.ps1)
# ─────────────────────────────────────────────────────────────────────────────
function Set-CIS-PostCleanup {
    Write-Host "[*] Cleaning up temp files..." -ForegroundColor Cyan
    # BUG FIX 4: Removed gpupdate from here - it belongs in main.ps1 only,
    # after hardening completes, to avoid GP overwriting local registry writes.
    $TempFiles = @(
        "$env:TEMP\CIS_Accounts.inf",
        "$env:TEMP\CIS_Rights.inf",
        "$env:TEMP\CIS_Security.inf",
        "$env:TEMP\audit_export.inf"
    )
    foreach ($File in $TempFiles) {
        if (Test-Path $File) { Remove-Item $File -Force -ErrorAction SilentlyContinue }
    }
    Write-Host "  [OK] Temp files removed." -ForegroundColor Green
}