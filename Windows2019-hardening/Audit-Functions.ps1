<#
.SYNOPSIS
    GPO Hardening Automation - Audit Functions
.DESCRIPTION
    Fully data-driven audit engine. All checks come from CSV files:
      CIS_Data.csv       - Registry checks   (Sections 2.3, 9, 18, 19)
      Audit_Policy.csv   - Audit policy      (Section 17)
      Account_Policy.csv - Account/lockout   (Section 1)

    To support a new benchmark version, only update the CSV files.
.NOTES
    Run as Administrator.
    Audit only runs after successful hardening (checked in main.ps1).
#>

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

function Start-CISAudit {
    param([string]$BenchmarkName = "CIS Windows Server 2019 v1.2.0")

    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "   AUDIT: $BenchmarkName" -ForegroundColor White
    Write-Host "================================================" -ForegroundColor Cyan
    $Global:AuditResults = @()

    Test-CIS-AccountPolicies
    Test-CIS-AuditPolicies
    Test-CIS-RegistryFromCSV

    $ReportPath = "$PSScriptRoot\Audit_Report_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
    $Global:AuditResults | Export-Csv -Path $ReportPath -NoTypeInformation

    $pass  = ($Global:AuditResults | Where-Object Status -eq "PASS").Count
    $fail  = ($Global:AuditResults | Where-Object Status -eq "FAIL").Count
    $total = $Global:AuditResults.Count

    Write-Host "`n================================================" -ForegroundColor Cyan
    Write-Host "  RESULT: $pass/$total PASS  |  $fail FAIL" -ForegroundColor White
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
        [bool]  $IsCompliant,
        [string]$Expected = "",
        [string]$Actual   = ""
    )
    $status = if ($IsCompliant) { "PASS" } else { "FAIL" }
    $color  = if ($IsCompliant) { "Green" } else { "Red" }
    $detail = if (-not $IsCompliant -and $Expected) { " [Expected: $Expected | Got: $Actual]" } else { "" }
    Write-Host "  [$status] $ID : $Description$detail" -ForegroundColor $color
    $Global:AuditResults += [PSCustomObject]@{
        CIS_ID      = $ID
        Description = $Description
        Status      = $status
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
        Returns the exact audit setting string for one subcategory.
    .DESCRIPTION
        Calls auditpol /get /subcategory:"<name>" which scopes output to only
        that subcategory - avoids all category-header substring collisions
        (e.g. "Logoff" inside "Logon/Logoff", "Logon" inside "Account Logon").

        auditpol output format (indent depth varies by Windows build/locale):
            System audit policy
            Category/Subcategory                      Setting
              Logon/Logoff
                Logoff                                Success

        FIX for NOT FOUND: instead of filtering by indent depth (which varies),
        skip the two known header lines, then for every remaining non-empty line
        split on 2+ spaces and check whether the first token exactly matches the
        subcategory name. Return the last token as the setting value.
        This is indent-agnostic and works on all Windows Server 2019 builds.
    #>
    param([string]$Subcategory)

    $rawLines = auditpol /get /subcategory:"$Subcategory" 2>$null

    if (-not $rawLines) { return "AUDITPOL_ERROR" }

    foreach ($line in $rawLines) {
        $trimmed = $line.Trim()

        # Skip known header lines and blank lines
        if ($trimmed -eq "")                          { continue }
        if ($trimmed -eq "System audit policy")       { continue }
        if ($trimmed -match "^Category/Subcategory")  { continue }

        # Split on 2 or more spaces to separate the name column from value column
        $fields = $trimmed -split '\s{2,}'

        # Subcategory lines have exactly 2 fields: [SubcategoryName, Setting]
        # Category header lines have only 1 field (no setting column)
        if ($fields.Count -ge 2 -and $fields[0].Trim() -eq $Subcategory) {
            return [string]($fields[-1].Trim())
        }
    }

    return "NOT FOUND"
}

# =============================================================================
# SECTION 1 - Account Policies
# Reads Account_Policy.csv - same file hardening uses
# =============================================================================

function Test-CIS-AccountPolicies {
    Write-Host "`n[*] Section 1 - Account Policies..." -ForegroundColor Cyan

    $csvPath = "$PSScriptRoot\Account_Policy.csv"
    if (-not (Test-Path $csvPath)) {
        Write-Host "  [!] Account_Policy.csv not found. Skipping Section 1." -ForegroundColor Red; return
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
            Log-AuditResult $p.ID $p.Description $false $p.Value "NOT FOUND"; continue
        }
        $actual = [int]$raw
        $expected = [int]$p.Value
        $pass = switch ($p.Operator) {
            "ge" { $actual -ge $expected }
            "le" { $actual -le $expected -and $actual -ne 0 }
            "eq" { $actual -eq $expected }
            default { $false }
        }
        Log-AuditResult $p.ID $p.Description ([bool]$pass) "$expected" "$actual"
    }
}

# =============================================================================
# SECTION 17 - Advanced Audit Policy
# Reads Audit_Policy.csv - same file hardening uses
# =============================================================================

function Test-CIS-AuditPolicies {
    Write-Host "`n[*] Section 17 - Advanced Audit Policies..." -ForegroundColor Cyan

    $csvPath = "$PSScriptRoot\Audit_Policy.csv"
    if (-not (Test-Path $csvPath)) {
        Write-Host "  [!] Audit_Policy.csv not found. Skipping Section 17." -ForegroundColor Red; return
    }

    $policies = Import-Csv $csvPath
    foreach ($p in $policies) {

        $actual = Get-AuditpolSetting -Subcategory $p.Subcategory

        # Build expected string from Success/Failure columns in CSV
        # enable/enable -> "Success and Failure"
        # enable/disable -> "Success"
        # disable/enable -> "Failure"
        # disable/disable -> "No Auditing"
        $expected = switch ("$($p.Success)/$($p.Failure)") {
            "enable/enable"   { "Success and Failure" }
            "enable/disable"  { "Success" }
            "disable/enable"  { "Failure" }
            "disable/disable" { "No Auditing" }
            default           { "Unknown" }
        }

        Log-AuditResult $p.ID $p.Description ([bool]($actual -eq $expected)) $expected $actual
    }
}

# =============================================================================
# SECTIONS 2.3, 9, 18, 19 - Registry checks via CIS_Data.csv
# =============================================================================

function Test-CIS-RegistryFromCSV {
    param([string]$CsvPath = "$PSScriptRoot\CIS_Data.csv")

    if (-not (Test-Path $CsvPath)) {
        Write-Host "[!] CIS_Data.csv not found: $CsvPath" -ForegroundColor Red; return
    }

    $Policies = Import-Csv $CsvPath
    Write-Host "`n[*] Checking $($Policies.Count) registry settings..." -ForegroundColor Cyan

    foreach ($p in $Policies) {
        if (-not (Test-Path $p.Path)) {
            Log-AuditResult $p.ID "$($p.Section): $($p.Name)" $false $p.Value "KEY MISSING"
            continue
        }
        $cur = (Get-ItemProperty -Path $p.Path -Name $p.Name -ErrorAction SilentlyContinue).$($p.Name)
        if ($null -eq $cur) {
            Log-AuditResult $p.ID "$($p.Section): $($p.Name)" $false $p.Value "VALUE MISSING"
            continue
        }
        $exp    = ConvertTo-RegistryValue -Value $p.Value -Type $p.Type
        $isPass = [bool]($cur -eq $exp)
        Log-AuditResult $p.ID "$($p.Section): $($p.Name)" $isPass "$exp" "$cur"
    }
}