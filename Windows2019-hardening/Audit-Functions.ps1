<#
.SYNOPSIS
    Audit functions to verify CIS Windows Server 2019 Benchmark v1.2.0 compliance.
.NOTES
    Run as Administrator.
    All registry checks are driven by CIS_Data.csv - same source of truth as hardening.
#>

# ─────────────────────────────────────────────────────────────────────────────
function Start-CISAudit {
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "   CIS AUDIT - Windows Server 2019 v1.2.0      " -ForegroundColor White
    Write-Host "================================================" -ForegroundColor Cyan
    $Global:AuditResults = @()

    Test-CIS-AccountPolicies     # Section 1   - secedit
    Test-CIS-AuditPolicies       # Section 17  - auditpol
    Test-CIS-RegistryFromCSV     # Sections 2.3, 9, 18, 19 - CSV driven

    # Save report
    $ReportPath = "$PSScriptRoot\Audit_Report_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
    $Global:AuditResults | Export-Csv -Path $ReportPath -NoTypeInformation

    $pass  = ($Global:AuditResults | Where-Object { $_.Status -eq "PASS" }).Count
    $fail  = ($Global:AuditResults | Where-Object { $_.Status -eq "FAIL" }).Count
    $total = $Global:AuditResults.Count

    Write-Host "`n================================================" -ForegroundColor Cyan
    Write-Host "  AUDIT COMPLETE: $pass/$total PASS  |  $fail FAIL" -ForegroundColor White
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "  Report: $ReportPath" -ForegroundColor Yellow
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper: log one result to screen + global collection
# BUG FIX 10: ISO timestamp, not locale-dependent Get-Date object
# ─────────────────────────────────────────────────────────────────────────────
function Log-AuditResult {
    param(
        [string]$ID,
        [string]$Description,
        [string]$Status,          # "PASS", "FAIL", or "WARN"
        [string]$Expected  = "",
        [string]$Actual    = ""
    )
    $Color = switch ($Status) { "PASS" { "Green" } "FAIL" { "Red" } default { "Yellow" } }
    $Detail = if ($Status -ne "PASS" -and $Expected) { " [Expected: $Expected | Got: $Actual]" } else { "" }

    Write-Host "  [$Status] $ID : $Description$Detail" -ForegroundColor $Color

    $Global:AuditResults += [PSCustomObject]@{
        CIS_ID      = $ID
        Description = $Description
        Status      = $Status
        Expected    = $Expected
        Actual      = $Actual
        Timestamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'   # BUG FIX 10
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper: cast CSV string value for accurate comparison against registry
# BUG FIX 7: type-aware comparison prevents string-vs-int mismatches
# ─────────────────────────────────────────────────────────────────────────────
function ConvertTo-RegistryValue {
    param([string]$Value, [string]$Type)
    switch ($Type.ToUpper()) {
        'DWORD'  { return [int32]$Value }
        'QWORD'  { return [int64]$Value }
        default  { return $Value }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Section 1 - Account Policies (secedit export)
# ─────────────────────────────────────────────────────────────────────────────
function Test-CIS-AccountPolicies {
    Write-Host "`n[*] Section 1 - Account Policies..." -ForegroundColor Cyan
    $ExportPath = "$env:TEMP\audit_export.inf"
    secedit /export /cfg $ExportPath /areas SECURITYPOLICY | Out-Null

    function Get-SecValue([string]$Key) {
        $line = Select-String -Path $ExportPath -Pattern "^\s*$Key\s*=" | Select-Object -First 1
        if ($line) { return $line.Line.Split('=')[1].Trim() }
        return $null
    }

    $checks = @(
        @{ ID="1.1.1"; Desc="Enforce password history (24+)";        Key="PasswordHistorySize";  Op="ge"; Val=24 },
        @{ ID="1.1.2"; Desc="Maximum password age (60 or fewer)";    Key="MaximumPasswordAge";   Op="le"; Val=60 },
        @{ ID="1.1.3"; Desc="Minimum password age (1+)";             Key="MinimumPasswordAge";   Op="ge"; Val=1  },
        @{ ID="1.1.4"; Desc="Minimum password length (14+)";         Key="MinimumPasswordLength";Op="ge"; Val=14 },
        @{ ID="1.1.5"; Desc="Password complexity (Enabled)";         Key="PasswordComplexity";   Op="eq"; Val=1  },
        @{ ID="1.1.6"; Desc="Reversible encryption (Disabled)";      Key="ClearTextPassword";    Op="eq"; Val=0  },
        @{ ID="1.2.1"; Desc="Lockout duration (15+ min)";            Key="LockoutDuration";      Op="ge"; Val=15 },
        @{ ID="1.2.2"; Desc="Lockout threshold (10 or fewer)";       Key="LockoutBadCount";      Op="le"; Val=10 },
        @{ ID="1.2.3"; Desc="Reset lockout counter (15+ min)";       Key="ResetLockoutCount";    Op="ge"; Val=15 }
    )

    foreach ($c in $checks) {
        $raw = Get-SecValue $c.Key
        if ($null -eq $raw) {
            Log-AuditResult $c.ID $c.Desc "WARN" $c.Val "NOT FOUND"
            continue
        }
        $intVal = [int]$raw
        $pass = switch ($c.Op) {
            "ge" { $intVal -ge $c.Val }
            "le" { $intVal -le $c.Val -and $intVal -ne 0 }
            "eq" { $intVal -eq $c.Val }
        }
        Log-AuditResult $c.ID $c.Desc $(if ($pass) {"PASS"} else {"FAIL"}) $c.Val $intVal
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Section 17 - Advanced Audit Policies (auditpol)
# ─────────────────────────────────────────────────────────────────────────────
function Test-CIS-AuditPolicies {
    Write-Host "`n[*] Section 17 - Advanced Audit Policies..." -ForegroundColor Cyan

    $checks = @(
        @{ ID="17.1.1"; Sub="Credential Validation";              S="Success and Failure" },
        @{ ID="17.2.4"; Sub="Security Group Management";          S="Success"             },
        @{ ID="17.2.5"; Sub="User Account Management";            S="Success and Failure" },
        @{ ID="17.3.1"; Sub="Plug and Play Events";               S="Success"             },
        @{ ID="17.3.2"; Sub="Process Creation";                   S="Success"             },
        @{ ID="17.5.1"; Sub="Account Lockout";                    S="Success"             },
        @{ ID="17.5.3"; Sub="Logoff";                             S="Success"             },
        @{ ID="17.5.4"; Sub="Logon";                              S="Success and Failure" },
        @{ ID="17.5.6"; Sub="Special Logon";                      S="Success"             },
        @{ ID="17.6.2"; Sub="File Share";                         S="Success and Failure" },
        @{ ID="17.6.4"; Sub="Removable Storage";                  S="Success and Failure" },
        @{ ID="17.7.1"; Sub="Audit Policy Change";                S="Success and Failure" },
        @{ ID="17.7.4"; Sub="MPSSVC Rule-Level Policy Change";    S="Success and Failure" },
        @{ ID="17.8.1"; Sub="Sensitive Privilege Use";            S="Success and Failure" },
        @{ ID="17.9.3"; Sub="Security State Change";              S="Success"             },
        @{ ID="17.9.4"; Sub="Security System Extension";          S="Success"             },
        @{ ID="17.9.5"; Sub="System Integrity";                   S="Success and Failure" }
    )

    foreach ($c in $checks) {
        $raw = auditpol /get /subcategory:"$($c.Sub)" 2>$null
        $line = $raw | Where-Object { $_ -match $c.Sub }
        $actual = if ($line) {
            $line -replace ".*$($c.Sub)\s+", "" -replace "\s+$", ""
        } else { "NOT FOUND" }
        $pass = $actual -eq $c.S
        Log-AuditResult $c.ID "Audit: $($c.Sub)" $(if ($pass) {"PASS"} else {"FAIL"}) $c.S $actual
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Sections 2.3, 9, 18, 19 - All registry checks driven by CIS_Data.csv
# BUG FIX 3: Firewall now checked via GP registry path (same as hardening writes)
# BUG FIX 7: Type-aware comparison (int vs int, not string vs int)
# BUG FIX 8: Explicit "KEY MISSING" vs "WRONG VALUE" distinction
# ─────────────────────────────────────────────────────────────────────────────
function Test-CIS-RegistryFromCSV {
    param([string]$CsvPath = "$PSScriptRoot\CIS_Data.csv")

    if (-not (Test-Path $CsvPath)) {
        Write-Host "[!] CSV not found: $CsvPath" -ForegroundColor Red
        return
    }

    $Policies = Import-Csv $CsvPath
    Write-Host "`n[*] Checking $($Policies.Count) registry settings from CSV..." -ForegroundColor Cyan

    foreach ($Policy in $Policies) {
        # BUG FIX 8: distinguish missing key from wrong value
        if (-not (Test-Path $Policy.Path)) {
            Log-AuditResult $Policy.ID "$($Policy.Section): $($Policy.Name)" "FAIL" $Policy.Value "KEY MISSING"
            continue
        }

        $CurrentVal = (Get-ItemProperty -Path $Policy.Path -Name $Policy.Name -ErrorAction SilentlyContinue).$($Policy.Name)

        if ($null -eq $CurrentVal) {
            Log-AuditResult $Policy.ID "$($Policy.Section): $($Policy.Name)" "FAIL" $Policy.Value "VALUE MISSING"
            continue
        }

        # BUG FIX 7: cast expected value to same type as what registry returns
        $ExpectedVal = ConvertTo-RegistryValue -Value $Policy.Value -Type $Policy.Type
        $IsCompliant = ($CurrentVal -eq $ExpectedVal)

        Log-AuditResult $Policy.ID "$($Policy.Section): $($Policy.Name)" `
            $(if ($IsCompliant) {"PASS"} else {"FAIL"}) `
            $ExpectedVal $CurrentVal
    }
}