# Section 18.8.28.5: Turn off app notifications on the lock screen
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$name = "DisableLockScreenAppNotifications"
$value = 1

# Check if the folder exists, if not, create it
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force
}

# Set the security value
Set-ItemProperty -Path $registryPath -Name $name -Value $value
Write-Host "Lock screen notifications have been disabled."