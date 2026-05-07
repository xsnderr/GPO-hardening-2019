<#
.SYNOPSIS
    GPO Hardening Automation - Audit Functions
.DESCRIPTION
    Detects server role (DC / MS) and audits only the controls applicable
    to that role, using the same CSV files as hardening.
.NOTES
    Run as Administrator. Audit only runs after successful hardening.
#>

# =============================================================================
# SERVER ROLE DETECTION (mirrors Hardening-Functions.ps1)
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
# MAIN ENTRY POINT
# =============================================================================
function Start-CISAudit {
    param([string]$BenchmarkName = "CIS Windows Server 2019 v1.2.0")

    $ServerRole = Get-ServerRole
    $Global:AuditResults = @()

    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "   AUDIT: $BenchmarkName" -ForegroundColor White
    Write-Host "   Detected Role: $ServerRole" -ForegroundColor $(if ($ServerRole -eq "DC") {"Magenta"} else {"Yellow"})
    Write-Host "================================================" -ForegroundColor Cyan

    Test-CIS-AccountPolicies -ServerRole $ServerRole
    Test-CIS-AuditPolicies   -ServerRole $ServerRole
    Test-CIS-RegistryFromCSV -ServerRole $ServerRole

    $ReportPath = "$PSScriptRoot\Audit_Report_${ServerRole}_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
    $Global:AuditResults | Export-Csv -Path $ReportPath -NoTypeInformation

    $pass  = ($Global:AuditResults | Where-Object Status -eq "PASS").Count
    $fail  = ($Global:AuditResults | Where-Object Status -eq "FAIL").Count
    $skip  = ($Global:AuditResults | Where-Object Status -eq "SKIP").Count
    $total = $Global:AuditResults.Count

    Write-Host "`n================================================" -ForegroundColor Cyan
    Write-Host "  RESULT ($ServerRole): $pass PASS | $fail FAIL | $skip SKIP | $total total" -ForegroundColor White
    Write-Host "  Report: $ReportPath" -ForegroundColor Yellow
    Write-Host "================================================" -ForegroundColor Cyan
}

# =============================================================================
# HELPERS
# =============================================================================
function Log-AuditResult {
    param(
        [string]$ID,
        [string]$Description,
        [string]$Status,      # PASS, FAIL, or SKIP
        [string]$Expected = "",
        [string]$Actual   = ""
    )
    $color  = switch ($Status) { "PASS" {"Green"} "SKIP" {"DarkGray"} default {"Red"} }
    $detail = if ($Status -eq "FAIL" -and $Expected) { " [Expected: $Expected | Got: $Actual]" } else { "" }
    Write-Host "  [$Status] $ID : $Description$detail" -ForegroundColor $color
    $Global:AuditResults += [PSCustomObject]@{
        CIS_ID      = $ID
        Description = $Description
        Status      = $Status
        Expected    = $Expected
        Actual      = $Actual
        Timestamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }
}

function ConvertTo-RegistryValue {
    param([string]$Value, [string]$Type)
    switch ($Type.ToUpper()) {
        'DWORD' { return [int32]$Value }
        'QWORD' { return [int64]$Value }
        default { return $Value }
    }
}

function Get-AuditpolSetting {
    <#
    .SYNOPSIS
        Returns the audit setting for one subcategory, indent-agnostic.
    .DESCRIPTION
        Calls auditpol /get /subcategory:"X" scoped to just that one subcategory.
        Skips known header lines. Splits on 2+ spaces. Matches first field exactly
        to the subcategory name. Returns last field as the setting string.
        Works regardless of indent depth (which varies by Windows build/locale).
    #>
    param([string]$Subcategory)

    $rawLines = auditpol /get /subcategory:"$Subcategory" 2>$null
    if (-not $rawLines) { return "AUDITPOL_ERROR" }

    foreach ($line in $rawLines) {
        $trimmed = $line.Trim()
        if ($trimmed -eq "")                         { continue }
        if ($trimmed -eq "System audit policy")      { continue }
        if ($trimmed -match "^Category/Subcategory") { continue }

        $fields = $trimmed -split '\s{2,}'
        if ($fields.Count -ge 2 -and $fields[0].Trim() -eq $Subcategory) {
            return [string]($fields[-1].Trim())
        }
    }
    return "NOT FOUND"
}

# =============================================================================
# SECTION 1 - Account Policies (secedit export)
# =============================================================================
function Test-CIS-AccountPolicies {
    param([string]$ServerRole)
    Write-Host "`n[*] Section 1 - Account Policies ($ServerRole)..." -ForegroundColor Cyan

    $csvPath = "$PSScriptRoot\Account_Policy.csv"
    if (-not (Test-Path $csvPath)) {
        Write-Host "  [!] Account_Policy.csv not found. Skipping." -ForegroundColor Red; return
    }

    $tmp = "$env:TEMP\audit_secedit.inf"
    secedit /export /cfg $tmp /areas SECURITYPOLICY 2>&1 | Out-Null

    function Get-SecVal([string]$key) {
        $line = Select-String -Path $tmp -Pattern "^\s*$key\s*=" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($line) { return $line.Line.Split('=')[1].Trim() }
        return $null
    }

    $policies = Import-Csv $csvPath
    foreach ($p in $policies) {
        $raw = Get-SecVal $p.SeceditKey
        if ($null -eq $raw) {
            Log-AuditResult $p.ID $p.Description "FAIL" $p.Value "NOT FOUND"; continue
        }
        $actual   = [int]$raw
        $expected = [int]$p.Value
        $pass = switch ($p.Operator) {
            "ge" { $actual -ge $expected }
            "le" { $actual -le $expected -and $actual -ne 0 }
            "eq" { $actual -eq $expected }
            default { $false }
        }
        Log-AuditResult $p.ID $p.Description $(if ($pass) {"PASS"} else {"FAIL"}) "$expected" "$actual"
    }
}

# =============================================================================
# SECTION 17 - Audit Policies (auditpol) - filtered by AppliesTo
# =============================================================================
function Test-CIS-AuditPolicies {
    param([string]$ServerRole)
    Write-Host "`n[*] Section 17 - Audit Policies ($ServerRole)..." -ForegroundColor Cyan

    $csvPath = "$PSScriptRoot\Audit_Policy.csv"
    if (-not (Test-Path $csvPath)) {
        Write-Host "  [!] Audit_Policy.csv not found. Skipping." -ForegroundColor Red; return
    }

    $allPolicies = Import-Csv $csvPath

    foreach ($p in $allPolicies) {
        # Check applicability
        $applies = (-not $p.AppliesTo) -or ($p.AppliesTo -eq 'Both') -or ($p.AppliesTo -eq $ServerRole)
        if (-not $applies) {
            Log-AuditResult $p.ID "Audit: $($p.Subcategory)" "SKIP" "" "Not applicable to $ServerRole"
            continue
        }

        $actual = Get-AuditpolSetting -Subcategory $p.Subcategory

        $expected = switch ("$($p.Success)/$($p.Failure)") {
            "enable/enable"   { "Success and Failure" }
            "enable/disable"  { "Success" }
            "disable/enable"  { "Failure" }
            "disable/disable" { "No Auditing" }
            default           { "Unknown" }
        }

        Log-AuditResult $p.ID "Audit: $($p.Subcategory)" $(if ($actual -eq $expected) {"PASS"} else {"FAIL"}) $expected $actual
    }
}

# =============================================================================
# SECTIONS 2.3, 9, 18, 19 - Registry checks via CIS_Data.csv, filtered by AppliesTo
# =============================================================================
function Test-CIS-RegistryFromCSV {
    param(
        [string]$CsvPath    = "$PSScriptRoot\CIS_Data.csv",
        [string]$ServerRole
    )
    if (-not (Test-Path $CsvPath)) {
        Write-Host "[!] CIS_Data.csv not found: $CsvPath" -ForegroundColor Red; return
    }

    $allPolicies = Import-Csv $CsvPath
    Write-Host "`n[*] Registry checks ($ServerRole): $($allPolicies.Count) total entries..." -ForegroundColor Cyan

    foreach ($p in $allPolicies) {
        # Check applicability
        $applies = (-not $p.AppliesTo) -or ($p.AppliesTo -eq 'Both') -or ($p.AppliesTo -eq $ServerRole)
        if (-not $applies) {
            Log-AuditResult $p.ID "$($p.Section): $($p.Name)" "SKIP" "" "Not applicable to $ServerRole"
            continue
        }

        if (-not (Test-Path $p.Path)) {
            Log-AuditResult $p.ID "$($p.Section): $($p.Name)" "FAIL" $p.Value "KEY MISSING"
            continue
        }

        $cur = (Get-ItemProperty -Path $p.Path -Name $p.Name -ErrorAction SilentlyContinue).$($p.Name)
        if ($null -eq $cur) {
            Log-AuditResult $p.ID "$($p.Section): $($p.Name)" "FAIL" $p.Value "VALUE MISSING"
            continue
        }

        $exp    = ConvertTo-RegistryValue -Value $p.Value -Type $p.Type
        $isPass = [bool]($cur -eq $exp)
        Log-AuditResult $p.ID "$($p.Section): $($p.Name)" $(if ($isPass) {"PASS"} else {"FAIL"}) "$exp" "$cur"
    }
}