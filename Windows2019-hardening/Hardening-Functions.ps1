<#
.SYNOPSIS
    GPO Hardening Automation - Hardening Functions
.DESCRIPTION
    Automatically detects Domain Controller vs Member Server and applies
    only the CIS controls appropriate for that role.

    CIS_Data.csv       -> AppliesTo: DC | MS | Both
    Audit_Policy.csv   -> AppliesTo: DC | Both
    Account_Policy.csv -> always Both

    APPLYING GPO CHANGES:
    1. LGPO.exe  (registry) - place in script folder, survives domain refresh
       Download: https://www.microsoft.com/en-us/download/details.aspx?id=55319
    2. secedit   (Sections 1, 2.2)
    3. auditpol  (Section 17)
.NOTES
    Run as Administrator.
#>

# =============================================================================
# SERVER ROLE DETECTION
# DomainRole: 4=Backup DC, 5=Primary DC -> "DC"
#             0,1,2,3                   -> "MS" (standalone or member server)
# =============================================================================
function Get-ServerRole {
    $role = (Get-WmiObject Win32_ComputerSystem).DomainRole
    if ($role -ge 4) { return "DC" } else { return "MS" }
}

function Get-ApplicablePolicies {
    param($Policies, [string]$ServerRole)
    return $Policies | Where-Object {
        (-not $_.AppliesTo) -or ($_.AppliesTo -eq 'Both') -or ($_.AppliesTo -eq $ServerRole)
    }
}

# =============================================================================
# HELPERS
# =============================================================================
function New-RegistryKeyPath {
    param([string]$FullPath)
    $segs = $FullPath -split '\\'
    $cur  = $segs[0]
    for ($i = 1; $i -lt $segs.Count; $i++) {
        $cur = "$cur\$($segs[$i])"
        if (-not (Test-Path $cur)) { New-Item -Path $cur -Force -ErrorAction Stop | Out-Null }
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
# =============================================================================
function Start-CISHardening {
    param([string]$BenchmarkName = "CIS Windows Server 2019 v1.2.0")

    $ServerRole = Get-ServerRole
    $Global:HardeningErrors = 0
    $Global:ServerRole = $ServerRole

    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "   HARDENING: $BenchmarkName" -ForegroundColor White
    Write-Host "   Detected Role: $ServerRole" -ForegroundColor $(if ($ServerRole -eq "DC") {"Magenta"} else {"Yellow"})
    Write-Host "================================================" -ForegroundColor Cyan

    Set-CIS-AccountPolicies -ServerRole $ServerRole
    Set-CIS-UserRights      -ServerRole $ServerRole
    Set-CIS-AuditPolicies   -ServerRole $ServerRole
    Set-CIS-RegistryFromCSV -ServerRole $ServerRole
    Set-CIS-Services
    Set-CIS-PostCleanup

    if ($Global:HardeningErrors -eq 0) {
        Write-Host "`n[+] Hardening complete ($ServerRole profile) - 0 errors." -ForegroundColor Green
        return $true
    } else {
        Write-Host "`n[!] Hardening complete with $($Global:HardeningErrors) error(s). Fix before auditing." -ForegroundColor Yellow
        return $false
    }
}

# =============================================================================
# SECTION 1 - Account Policies (secedit) - Both DC and MS
# =============================================================================
function Set-CIS-AccountPolicies {
    param([string]$ServerRole)
    Write-Host "`n[*] Section 1 - Account Policies (secedit)..." -ForegroundColor Cyan

    $csvPath = "$PSScriptRoot\Account_Policy.csv"
    if (-not (Test-Path $csvPath)) {
        Write-Host "  [ERROR] Account_Policy.csv not found." -ForegroundColor Red
        $Global:HardeningErrors++; return
    }

    $policies  = Import-Csv $csvPath
    $sysAccess = ""
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
# SECTION 2.2 - User Rights (secedit) - DC and MS have different rights
# =============================================================================
function Set-CIS-UserRights {
    param([string]$ServerRole)
    Write-Host "`n[*] Section 2.2 - User Rights Assignment (Data-Driven)..." -ForegroundColor Cyan

    $csvPath = "$PSScriptRoot\User_Rights.csv"
    if (-not (Test-Path $csvPath)) {
        Write-Host "  [ERROR] User_Rights.csv not found at: $csvPath" -ForegroundColor Red
        $Global:HardeningErrors++
        return
    }

    # Import data and filter by detected role (DC or MS)
    $allRights = Import-Csv $csvPath
    $applicableRights = $allRights | Where-Object { $_.AppliesTo -eq 'Both' -or $_.AppliesTo -eq $ServerRole }

    $privilegeBlock = ""
    foreach ($r in $applicableRights) {
        $privilegeBlock += "$($r.RightName) = $($r.Value)`r`n"
    }

    $inf = "$env:TEMP\CIS_Rights.inf"
    
    # CRITICAL: The closing "@ must be at the very start of the line!
    $template = @"
[Unicode]
Unicode=yes
[Privilege Rights]
$privilegeBlock
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
    $template | Out-File $inf -Encoding unicode

    # Apply via secedit
    secedit /configure /db "$env:windir\security\local.sdb" /cfg $inf /areas USER_RIGHTS /overwrite /quiet 2>&1 | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] User rights applied from CSV ($ServerRole profile)." -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] secedit failed to apply User Rights. Check $inf for syntax." -ForegroundColor Red
        $Global:HardeningErrors++
    }
}
# =============================================================================
# SECTION 17 - Audit Policy (auditpol) - filtered by AppliesTo column
# =============================================================================
function Set-CIS-AuditPolicies {
    param([string]$ServerRole)
    Write-Host "`n[*] Section 17 - Audit Policies ($ServerRole profile)..." -ForegroundColor Cyan

    $csvPath = "$PSScriptRoot\Audit_Policy.csv"
    if (-not (Test-Path $csvPath)) {
        Write-Host "  [ERROR] Audit_Policy.csv not found." -ForegroundColor Red
        $Global:HardeningErrors++; return
    }

    $allPolicies = Import-Csv $csvPath
    $policies    = Get-ApplicablePolicies -Policies $allPolicies -ServerRole $ServerRole
    $skipped     = $allPolicies.Count - $policies.Count

    Write-Host "  Applying $($policies.Count) of $($allPolicies.Count) ($skipped skipped - not for $ServerRole)" -ForegroundColor Gray
    auditpol /set /option:CrashOnAuditFail /value:disable | Out-Null

    $ok = 0; $err = 0
    foreach ($p in $policies) {
        auditpol /set /subcategory:"$($p.Subcategory)" /success:$($p.Success) /failure:$($p.Failure) | Out-Null
        if ($LASTEXITCODE -eq 0) { $ok++ }
        else { Write-Host "  [WARN] Failed: $($p.Subcategory)" -ForegroundColor Yellow; $err++; $Global:HardeningErrors++ }
    }
    Write-Host "  [OK] $ok audit policies set, $err errors." -ForegroundColor Green
}

# =============================================================================
# SECTIONS 2.3, 9, 18, 19 - Registry (LGPO or direct) filtered by AppliesTo
# =============================================================================
function Set-CIS-RegistryFromCSV {
    param(
        [string]$CsvPath    = "$PSScriptRoot\CIS_Data.csv",
        [string]$ServerRole
    )
    if (-not (Test-Path $CsvPath)) {
        Write-Host "[!] CIS_Data.csv not found: $CsvPath" -ForegroundColor Red
        $Global:HardeningErrors++; return
    }

    $allPolicies = Import-Csv $CsvPath
    $policies    = Get-ApplicablePolicies -Policies $allPolicies -ServerRole $ServerRole
    $skipped     = $allPolicies.Count - $policies.Count

    Write-Host "`n[*] Registry: $($policies.Count) of $($allPolicies.Count) settings apply to $ServerRole ($skipped skipped)..." -ForegroundColor Cyan

    $lgpoExe = "$PSScriptRoot\LGPO.exe"
    if (Test-Path $lgpoExe) {
        Set-Policies-ViaLGPO -Policies $policies -LgpoExe $lgpoExe
    } else {
        Write-Host "  LGPO.exe not found - direct registry write (workgroup only)." -ForegroundColor Yellow
        Write-Host "  Download: https://www.microsoft.com/en-us/download/details.aspx?id=55319" -ForegroundColor Yellow
        Set-Policies-Direct -Policies $policies
    }
}

function Set-Policies-ViaLGPO {
    param($Policies, [string]$LgpoExe)
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
        Write-Host "  [OK] $($Policies.Count) settings applied via LGPO." -ForegroundColor Green
    } else {
        Write-Host "  [WARN] LGPO errors. Falling back to direct registry." -ForegroundColor Yellow
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