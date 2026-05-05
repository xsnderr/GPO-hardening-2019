<#
.SYNOPSIS
    GPO Hardening Automation - Main Controller
.NOTES
    Run as Administrator.

    FOLDER STRUCTURE:
    ─────────────────
    Place all files in the same folder:
      main.ps1
      Hardening-Functions.ps1
      Audit-Functions.ps1
      CIS_Data.csv           <- registry settings
      Audit_Policy.csv       <- Section 17 audit policy
      Account_Policy.csv     <- Section 1 account/lockout policy
      LGPO.exe               <- optional but recommended for domain servers
                                Download: https://www.microsoft.com/en-us/download/details.aspx?id=55319

    USING A DIFFERENT BENCHMARK:
    ─────────────────────────────
    To switch to a different benchmark (e.g. CIS 2022, DISA STIG, NIST):
      1. Replace CIS_Data.csv with registry settings for the new benchmark
      2. Replace Audit_Policy.csv with the new audit policy settings
      3. Replace Account_Policy.csv with the new account/lockout policy
      4. Update the BenchmarkName parameter in the switch block below
      No changes to any .ps1 file are needed.

    KEEPING UP WITH BENCHMARK UPDATES:
    ────────────────────────────────────
      1. Download the new benchmark PDF from cisecurity.org
      2. Check the Changelog section at the end of the PDF
      3. For registry changes: edit CIS_Data.csv only
      4. For audit policy changes: edit Audit_Policy.csv only
      5. For account policy changes: edit Account_Policy.csv only
      6. Test on a non-production server with option 3 first
#>

# ── Admin check ───────────────────────────────────────────────────────────────
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Not running as Administrator." -ForegroundColor Red
    Write-Host "Right-click main.ps1 -> Run as Administrator"
    Pause; exit
}

# ── Load modules ──────────────────────────────────────────────────────────────
. "$PSScriptRoot\Hardening-Functions.ps1"
. "$PSScriptRoot\Audit-Functions.ps1"

# ── Benchmark selection (change name here when updating versions) ─────────────
$BenchmarkName = "CIS Windows Server 2019 v1.2.0"

# ── LGPO status ───────────────────────────────────────────────────────────────
$lgpoPresent = Test-Path "$PSScriptRoot\LGPO.exe"

# ── Menu ──────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   GPO HARDENING AUTOMATION TOOL               " -ForegroundColor White
Write-Host "   $BenchmarkName" -ForegroundColor Gray
Write-Host "================================================" -ForegroundColor Cyan
if ($lgpoPresent) {
    Write-Host "  [LGPO.exe] Found - domain-persistent mode active" -ForegroundColor Green
} else {
    Write-Host "  [LGPO.exe] Not found - direct registry mode (workgroup only)" -ForegroundColor Yellow
    Write-Host "  Download LGPO.exe for domain-joined server support." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "  1. Audit only         (read-only scan, no changes)"
Write-Host "  2. Harden only        (apply all settings)"
Write-Host "  3. Harden then Audit  (apply + verify, audit skipped if errors)"
Write-Host "  4. Exit"
Write-Host ""

$choice = Read-Host "Select [1-4]"

switch ($choice) {

    "1" {
        Write-Host "`nStarting audit..." -ForegroundColor Yellow
        Start-CISAudit -BenchmarkName $BenchmarkName
    }

    "2" {
        $confirm = Read-Host "This modifies system settings. Continue? (Y/N)"
        if ($confirm -ieq "Y") {
            $success = Start-CISHardening -BenchmarkName $BenchmarkName
            if ($success) {
                Write-Host "`nRefreshing local policy..." -ForegroundColor Cyan
                gpupdate /force
                Write-Host "[!] Reboot recommended to fully apply all settings." -ForegroundColor Yellow
            }
        } else {
            Write-Host "Cancelled." -ForegroundColor Yellow
        }
    }

    "3" {
        $confirm = Read-Host "Apply hardening then audit? (Y/N)"
        if ($confirm -ieq "Y") {
            # Hardening
            $success = Start-CISHardening -BenchmarkName $BenchmarkName

            if ($success) {
                Write-Host "`nRefreshing local policy..." -ForegroundColor Cyan
                gpupdate /force

                # Audit only runs if hardening had 0 errors
                Write-Host "`nStarting audit..." -ForegroundColor Yellow
                Start-CISAudit -BenchmarkName $BenchmarkName
            } else {
                Write-Host "`nAudit skipped - fix hardening errors first, then re-run." -ForegroundColor Red
            }
        } else {
            Write-Host "Cancelled." -ForegroundColor Yellow
        }
    }

    "4" { exit }

    default { Write-Host "Invalid selection." -ForegroundColor Red }
}

Write-Host "`nPress any key to exit..."
$null = [Console]::ReadKey($true)