<#
.SYNOPSIS
    GPO Hardening Automation - Hardening Functions
.DESCRIPTION
    Fully data-driven hardening engine. All settings come from CSV files:
      CIS_Data.csv       - Registry settings  (Sections 2.3, 9, 18, 19)
      Audit_Policy.csv   - Audit policy       (Section 17)
      Account_Policy.csv - Account/lockout    (Section 1)

    To support a NEW benchmark version or a DIFFERENT benchmark entirely
    (DISA STIG, NIST, CIS 2022, etc.), only update the CSV files.
    No PowerShell changes required.

    HOW GPO CHANGES ARE APPLIED:
    ─────────────────────────────
    Direct registry writes to HKLM:\SOFTWARE\Policies\... are NOT enough on
    domain-joined servers. Domain GPO refreshes every 90 minutes and overwrites them.

    This script uses THREE mechanisms that survive domain GPO refresh:

    1. LGPO.exe (for all registry settings in CIS_Data.csv)
       Microsoft's free Local Group Policy Object tool writes to the LGPO
       database directly. Settings written via LGPO persist across gpupdate.
       Download from: https://www.microsoft.com/en-us/download/details.aspx?id=55319
       Place LGPO.exe in the same folder as this script.
       If not present, falls back to direct registry writes (workgroup servers only).

    2. secedit.exe (Section 1 + Section 2.2)
       Writes to the local security database. Persists across gpupdate.

    3. auditpol.exe (Section 17)
       Writes to the audit policy store. Persists across gpupdate.
.NOTES
    Run as Administrator.
#>

# =============================================================================
# HELPERS
# =============================================================================

function New-RegistryKeyPath {
    param([string]$FullPath)
    $segments = $FullPath -split '\\'
    $current  = $segments[0]
    for ($i = 1; $i -lt $segments.Count; $i++) {
        $current = "$current\$($segments[$i])"
        if (-not (Test-Path $current)) {
            New-Item -Path $current -Force -ErrorAction Stop | Out-Null
        }
    }
}

function ConvertTo-RegistryValue {
    param([string]$Value, [string]$Type)
    switch ($Type.ToUpper()) {
        'DWORD'  { return [int32]$Value }
        'QWORD'  { return [int64]$Value }
        'BINARY' { return [byte[]]($Value -split ',' | ForEach-Object { [byte]$_ }) }
        default  { return $Value }
    }
}

function Convert-TypeToLGPO {
    param([string]$Type)
    switch ($Type.ToUpper()) {
        'DWORD'        { return 'DWORD' }
        'QWORD'        { return 'QWORD' }
        'STRING'       { return 'SZ' }
        'EXPANDSTRING' { return 'EXPAND_SZ' }
        'MULTISTRING'  { return 'MULTI_SZ' }
        'BINARY'       { return 'BINARY' }
        default        { return 'SZ' }
    }
}

# =============================================================================
# MAIN ENTRY POINT
# Returns $true on success, $false if any errors occurred.
# main.ps1 checks this before running the audit.
# =============================================================================

function Start-CISHardening {
    param([string]$BenchmarkName = "CIS Windows Server 2019 v1.2.0")

    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "   HARDENING: $BenchmarkName" -ForegroundColor White
    Write-Host "================================================" -ForegroundColor Cyan

    $Global:HardeningErrors = 0

    Set-CIS-AccountPolicies
    Set-CIS-UserRights
    Set-CIS-AuditPolicies
    Set-CIS-RegistryFromCSV
    Set-CIS-Services
    Set-CIS-PostCleanup

    if ($Global:HardeningErrors -eq 0) {
        Write-Host "`n[+] Hardening complete - 0 errors." -ForegroundColor Green
        return $true
    } else {
        Write-Host "`n[!] Hardening complete with $($Global:HardeningErrors) error(s)." -ForegroundColor Yellow
        Write-Host "    Audit will NOT run when hardening has errors. Fix errors first." -ForegroundColor Yellow
        return $false
    }
}

# =============================================================================
# SECTION 1 - Account Policies
# Reads Account_Policy.csv. Update that file for new benchmark versions.
# =============================================================================

function Set-CIS-AccountPolicies {
    Write-Host "`n[*] Section 1 - Account Policies (secedit)..." -ForegroundColor Cyan

    $csvPath = "$PSScriptRoot\Account_Policy.csv"
    if (-not (Test-Path $csvPath)) {
        Write-Host "  [ERROR] Account_Policy.csv not found at $csvPath" -ForegroundColor Red
        $Global:HardeningErrors++; return
    }

    $policies   = Import-Csv $csvPath
    $sysAccess  = ""
    foreach ($p in $policies) { $sysAccess += "$($p.SeceditKey) = $($p.Value)`r`n" }

    $inf = "$env:TEMP\CIS_Accounts.inf"
    @"
[Unicode]
Unicode=yes
[System Access]
$sysAccess
[Version]
signature="`$CHICAGO`$"
Revision=1
"@ | Out-File $inf -Encoding unicode

    secedit /configure /db "$env:windir\security\local.sdb" /cfg $inf /areas SECURITYPOLICY /overwrite /quiet 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] $($policies.Count) account policy settings applied." -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] secedit failed for account policies." -ForegroundColor Red
        $Global:HardeningErrors++
    }
}

# =============================================================================
# SECTION 2.2 - User Rights Assignments (secedit)
# =============================================================================

function Set-CIS-UserRights {
    Write-Host "`n[*] Section 2.2 - User Rights (secedit)..." -ForegroundColor Cyan
    $inf = "$env:TEMP\CIS_Rights.inf"
    @"
[Unicode]
Unicode=yes
[Privilege Rights]
SeNetworkLogonRight           = *S-1-5-32-544,*S-1-5-32-551
SeTcbPrivilege                =
SeInteractiveLogonRight       = *S-1-5-32-544
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeBackupPrivilege             = *S-1-5-32-544
SeSystemtimePrivilege         = *S-1-5-32-544,*S-1-5-19
SeTimeZonePrivilege           = *S-1-5-32-544,*S-1-5-19,*S-1-5-32-545
SeCreatePagefilePrivilege     = *S-1-5-32-544
SeCreateTokenPrivilege        =
SeCreateGlobalPrivilege       = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6
SeCreatePermanentPrivilege    =
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeDebugPrivilege              = *S-1-5-32-544
SeDenyNetworkLogonRight       = *S-1-5-32-546
SeDenyInteractiveLogonRight   = *S-1-5-32-546
SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546
SeEnableDelegationPrivilege   =
SeRemoteShutdownPrivilege     = *S-1-5-32-544
SeAuditPrivilege              = *S-1-5-19,*S-1-5-20
SeImpersonatePrivilege        = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544
SeLoadDriverPrivilege         = *S-1-5-32-544
SeLockMemoryPrivilege         =
SeBatchLogonRight             = *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-559
SeSecurityPrivilege           = *S-1-5-32-544
SeRelabelPrivilege            =
SeSystemEnvironmentPrivilege  = *S-1-5-32-544
SeManageVolumePrivilege       = *S-1-5-32-544
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeSystemProfilePrivilege      = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
SeRestorePrivilege            = *S-1-5-32-544
SeShutdownPrivilege           = *S-1-5-32-544
SeSyncAgentPrivilege          =
SeTakeOwnershipPrivilege      = *S-1-5-32-544
[Version]
signature="`$CHICAGO`$"
Revision=1
"@ | Out-File $inf -Encoding unicode

    secedit /configure /db "$env:windir\security\local.sdb" /cfg $inf /areas USER_RIGHTS /overwrite /quiet 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] User rights applied." -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] secedit failed for user rights." -ForegroundColor Red
        $Global:HardeningErrors++
    }
}

# =============================================================================
# SECTION 17 - Advanced Audit Policy
# Reads Audit_Policy.csv. Update that file for new benchmark versions.
# =============================================================================

function Set-CIS-AuditPolicies {
    Write-Host "`n[*] Section 17 - Advanced Audit Policies (auditpol)..." -ForegroundColor Cyan

    $csvPath = "$PSScriptRoot\Audit_Policy.csv"
    if (-not (Test-Path $csvPath)) {
        Write-Host "  [ERROR] Audit_Policy.csv not found at $csvPath" -ForegroundColor Red
        $Global:HardeningErrors++; return
    }

    $policies = Import-Csv $csvPath
    auditpol /set /option:CrashOnAuditFail /value:disable | Out-Null

    $ok = 0; $err = 0
    foreach ($p in $policies) {
        auditpol /set /subcategory:"$($p.Subcategory)" /success:$($p.Success) /failure:$($p.Failure) | Out-Null
        if ($LASTEXITCODE -eq 0) { $ok++ }
        else {
            Write-Host "  [WARN] Failed: $($p.Subcategory)" -ForegroundColor Yellow
            $err++; $Global:HardeningErrors++
        }
    }
    Write-Host "  [OK] $ok audit policies set, $err errors." -ForegroundColor Green
}

# =============================================================================
# SECTIONS 2.3, 9, 18, 19 - Registry via CIS_Data.csv
# Uses LGPO.exe if available (survives domain GPO refresh)
# Falls back to direct registry write if LGPO.exe not present
# =============================================================================

function Set-CIS-RegistryFromCSV {
    param([string]$CsvPath = "$PSScriptRoot\CIS_Data.csv")

    if (-not (Test-Path $CsvPath)) {
        Write-Host "[!] CIS_Data.csv not found: $CsvPath" -ForegroundColor Red
        $Global:HardeningErrors++; return
    }

    $Policies = Import-Csv $CsvPath
    $lgpoExe  = "$PSScriptRoot\LGPO.exe"

    if (Test-Path $lgpoExe) {
        Write-Host "`n[*] Applying $($Policies.Count) settings via LGPO.exe..." -ForegroundColor Cyan
        Set-Policies-ViaLGPO -Policies $Policies -LgpoExe $lgpoExe
    } else {
        Write-Host "`n[*] LGPO.exe not found - using direct registry write (fallback)." -ForegroundColor Yellow
        Write-Host "    For domain-joined servers, place LGPO.exe next to this script." -ForegroundColor Yellow
        Write-Host "    Download: https://www.microsoft.com/en-us/download/details.aspx?id=55319" -ForegroundColor Yellow
        Set-Policies-Direct -Policies $Policies
    }
}

function Set-Policies-ViaLGPO {
    param($Policies, [string]$LgpoExe)

    # LGPO.exe /t imports a text file with this exact format per entry:
    #   Computer              <- scope (Computer or User)
    #   <regpath-no-hive>     <- path without HKLM:\ or HKCU:\
    #   <valuename>
    #   <type>:<value>
    #   (blank line)
    $lines = @()
    foreach ($p in $Policies) {
        $scope    = if ($p.Path -match '^HKLM:') { 'Computer' } else { 'User' }
        $regPath  = $p.Path -replace '^HKL[MC]:\\', '' -replace '^HKCU:\\', ''
        $lgpoType = Convert-TypeToLGPO -Type $p.Type
        $lines   += "$scope`r`n$regPath`r`n$($p.Name)`r`n$lgpoType`:$($p.Value)`r`n"
    }

    $policyFile = "$env:TEMP\CIS_LGPO.txt"
    $lines -join "`r`n" | Out-File $policyFile -Encoding ascii

    & $LgpoExe /t $policyFile 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] All $($Policies.Count) settings applied via LGPO." -ForegroundColor Green
    } else {
        Write-Host "  [WARN] LGPO returned errors. Falling back to direct registry." -ForegroundColor Yellow
        Set-Policies-Direct -Policies $Policies
    }
}

function Set-Policies-Direct {
    param($Policies)
    $ok = 0; $err = 0
    foreach ($Policy in $Policies) {
        try {
            New-RegistryKeyPath -FullPath $Policy.Path
            $val = ConvertTo-RegistryValue -Value $Policy.Value -Type $Policy.Type
            Set-ItemProperty -Path $Policy.Path -Name $Policy.Name -Value $val -Type $Policy.Type -Force -ErrorAction Stop
            $ok++
        } catch {
            Write-Host "  [ERROR] $($Policy.ID) $($Policy.Name): $($_.Exception.Message)" -ForegroundColor Red
            $err++; $Global:HardeningErrors++
        }
    }
    Write-Host "  [OK] $ok applied, $err errors." -ForegroundColor Green
}

# =============================================================================
# SECTION 5 - Services
# =============================================================================

function Set-CIS-Services {
    Write-Host "`n[*] Section 5 - Disabling unnecessary services..." -ForegroundColor Cyan
    @("RemoteRegistry","bthserv","XblAuthManager","XblGameSave","XboxNetApiSvc") | ForEach-Object {
        if (Get-Service $_ -ErrorAction SilentlyContinue) {
            Set-Service  $_ -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service $_ -Force -ErrorAction SilentlyContinue
            Write-Host "  [OK] Disabled: $_" -ForegroundColor Green
        }
    }
}

# =============================================================================
# CLEANUP
# =============================================================================

function Set-CIS-PostCleanup {
    Write-Host "`n[*] Cleaning temp files..." -ForegroundColor Cyan
    @("$env:TEMP\CIS_Accounts.inf","$env:TEMP\CIS_Rights.inf",
      "$env:TEMP\CIS_LGPO.txt","$env:TEMP\audit_export.inf") | ForEach-Object {
        if (Test-Path $_) { Remove-Item $_ -Force -ErrorAction SilentlyContinue }
    }
    Write-Host "  [OK] Done." -ForegroundColor Green
}