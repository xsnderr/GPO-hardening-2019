<#
.SYNOPSIS
    Master Controller for CIS Windows Server 2019 Hardening Automation.
.NOTES
    Run this script as Administrator.
    Place CIS_Data.csv in the same folder as this script.
#>

# ── Admin check ───────────────────────────────────────────────────────────────
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: YOU ARE NOT AN ADMINISTRATOR!" -ForegroundColor Red
    Write-Host "Please close this window, right-click Main.ps1, and 'Run as Administrator'."
    Pause
    exit
}

# ── Load modules ──────────────────────────────────────────────────────────────
. "$PSScriptRoot\Hardening-Functions.ps1"
. "$PSScriptRoot\Audit-Functions.ps1"

# ── Menu ──────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   CIS WINDOWS SERVER 2019 AUTOMATION TOOL      " -ForegroundColor White
Write-Host "   Benchmark v1.2.0                             " -ForegroundColor Gray
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  1. Run Full Audit   (Scan only, no changes)"
Write-Host "  2. Run Full Hardening (Apply all CIS settings)"
Write-Host "  3. Exit"
Write-Host ""

$choice = Read-Host "Select an option [1-3]"

switch ($choice) {

    "1" {
        Write-Host "`nStarting Audit..." -ForegroundColor Yellow
        Start-CISAudit
    }

    "2" {
        $confirm = Read-Host "WARNING: This will modify system settings. Continue? (Y/N)"
        if ($confirm -eq "Y") {
            Write-Host "`nApplying hardening..." -ForegroundColor Yellow
            Start-CISHardening

            # BUG FIX 11: gpupdate only runs if user confirmed hardening (was outside the if block before)
            # BUG FIX 4:  gpupdate only runs here in main, NOT inside Set-CIS-PostCleanup,
            #             so it runs AFTER all registry writes are complete.
            Write-Host "`nRefreshing system policies..." -ForegroundColor Cyan
            gpupdate /force

            Write-Host "`n[+] Hardening and policy refresh complete." -ForegroundColor Green
            Write-Host "[!] A reboot is recommended to fully apply all settings." -ForegroundColor Yellow
        } else {
            Write-Host "Hardening cancelled." -ForegroundColor Yellow
        }
    }

    "3" { exit }

    Default {
        Write-Host "Invalid selection." -ForegroundColor Red
    }
}

Write-Host "`nPress any key to exit..."
$null = [Console]::ReadKey($true)