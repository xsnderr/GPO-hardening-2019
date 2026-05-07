<#
.SYNOPSIS
    GPO Hardening Automation - Main Controller
.NOTES
    Run as Administrator.
    Automatically detects DC vs Member Server and applies the correct profile.

    FOLDER STRUCTURE:
      main.ps1, Hardening-Functions.ps1, Audit-Functions.ps1
      CIS_Data.csv, Audit_Policy.csv, Account_Policy.csv
      LGPO.exe  (optional - get from Microsoft for domain-joined servers)

    WHAT HAPPENS ON EACH SERVER TYPE:
    ───────────────────────────────────
    Domain Controller (DomainRole 4 or 5):
      - Applies CIS DC profile (AppliesTo: DC + Both)
      - Skips MS-only controls (e.g. RDS/Terminal Services settings)
      - Applies DC-specific user rights (SeAddWorkstationPrivilege etc.)
      - Applies DC-only audit settings (Kerberos, DS Access)

    Member Server (DomainRole 0-3):
      - Applies CIS MS profile (AppliesTo: MS + Both)
      - Skips DC-only controls (e.g. Directory Service Access audit)
      - Applies MS-specific user rights

    Both profiles share: Section 1, firewall (Section 9),
    security options (Section 2.3), most of Section 18/19.

    HOW TO KEEP UPDATED:
    ──────────────────────
    When a new CIS benchmark version releases:
      1. Check the PDF changelog (last section of the PDF)
      2. Registry changes  -> edit CIS_Data.csv
      3. Audit changes     -> edit Audit_Policy.csv
      4. Password/lockout  -> edit Account_Policy.csv
      5. No PS1 changes needed unless secedit/auditpol commands change
#>

function Check-Prerequisites {
    $required = @("LGPO.exe", "CIS_Data.csv", "Audit_Policy.csv", "Account_Policy.csv")
    foreach ($f in $required) {
        if (-not (Test-Path "$PSScriptRoot\$f")) {
            Write-Host "[!] Missing component: $f" -ForegroundColor Red
            return $false
        }
    }
    return $true
}

if (-not (Check-Prerequisites)) { exit }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Not running as Administrator." -ForegroundColor Red
    Write-Host "Right-click main.ps1 -> Run as Administrator"
    Pause; exit
}

. "$PSScriptRoot\Hardening-Functions.ps1"
. "$PSScriptRoot\Audit-Functions.ps1"

$BenchmarkName = "CIS Windows Server 2019 v1.2.0"
$ServerRole    = Get-ServerRole
$lgpoPresent   = Test-Path "$PSScriptRoot\LGPO.exe"

Clear-Host
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   GPO HARDENING AUTOMATION TOOL               " -ForegroundColor White
Write-Host "   $BenchmarkName" -ForegroundColor Gray
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Detected Role : $ServerRole" -ForegroundColor $(if ($ServerRole -eq "DC") {"Magenta"} else {"Yellow"})
Write-Host "  LGPO.exe      : $(if ($lgpoPresent) {'Found (domain-persistent mode)'} else {'Not found (direct registry fallback)'})" -ForegroundColor $(if ($lgpoPresent) {"Green"} else {"Yellow"})
if (-not $lgpoPresent) {
    Write-Host "  -> Download LGPO.exe for domain-joined server support." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "  1. Audit only         (read-only scan, no changes)"
Write-Host "  2. Harden only        (apply all settings for $ServerRole profile)"
Write-Host "  3. Harden then Audit  (apply + verify, audit skipped if errors)"
Write-Host "  4. Exit"
Write-Host ""

$choice = Read-Host "Select [1-4]"

switch ($choice) {

    "1" {
        Write-Host "`nStarting audit ($ServerRole profile)..." -ForegroundColor Yellow
        Start-CISAudit -BenchmarkName $BenchmarkName
    }

    "2" {
        $confirm = Read-Host "Apply $ServerRole hardening profile? This modifies system settings. (Y/N)"
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
        $confirm = Read-Host "Harden ($ServerRole profile) then audit? (Y/N)"
        if ($confirm -ieq "Y") {
            $success = Start-CISHardening -BenchmarkName $BenchmarkName
            if ($success) {
                Write-Host "`nRefreshing local policy..." -ForegroundColor Cyan
                gpupdate /force
                Write-Host "`nStarting audit ($ServerRole profile)..." -ForegroundColor Yellow
                Start-CISAudit -BenchmarkName $BenchmarkName
            } else {
                Write-Host "`nAudit skipped - fix hardening errors first then re-run." -ForegroundColor Red
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