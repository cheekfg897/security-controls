<#
.SYNOPSIS
    SentinelOne Sanity Check - Verify EDR is actively protecting

.DESCRIPTION
    Creates the EICAR antivirus test file to verify SentinelOne is:
    - Actively monitoring file creation
    - Detecting known signatures
    - Quarantining threats
    - Logging detections

.NOTES
    - EICAR file is harmless and recognized by all AV solutions
    - Expected: File should be quarantined/deleted within seconds
    - If file persists, SentinelOne may not be active or properly configured

.EXAMPLE
    .\sentinelone-sanity-check.ps1

#>#>

# EICAR Standard Antivirus Test File
$eicarTestFile = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

# Possible save locations (try each one)
$testLocations = @(
    "$env:USERPROFILE\Desktop\eicar.com",
    "$env:USERPROFILE\Downloads\eicar.com",
    "$env:TEMP\eicar.com",
    "C:\Windows\Temp\eicar.com"
)

Write-Host "`n"
Write-Host "╔════════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    SENTINELONE SANITY CHECK                                       ║" -ForegroundColor Cyan
Write-Host "║           Verify SentinelOne is actively protecting this system                   ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`n[*] EICAR Test File: $eicarTestFile" -ForegroundColor Yellow
Write-Host "[*] This file is recognized by all antivirus solutions as a test threat" -ForegroundColor Yellow
Write-Host "`n[!] Expected behavior:" -ForegroundColor Yellow
Write-Host "    1. File creation will be attempted" -ForegroundColor Yellow
Write-Host "    2. SentinelOne should quarantine/delete the file within seconds" -ForegroundColor Yellow
Write-Host "    3. A detection event should appear in SentinelOne console" -ForegroundColor Yellow
Write-Host "    4. File should NOT persist on disk" -ForegroundColor Yellow

Write-Host "`n[*] Press Enter to create the EICAR test file..." -ForegroundColor Green
Read-Host

$fileCreated = $false
$createdPath = $null

foreach ($path in $testLocations) {
    try {
        Write-Host "`n[*] Attempting to create: $path" -ForegroundColor Yellow

        # Create the file with the EICAR content
        Set-Content -Path $path -Value $eicarTestFile -ErrorAction Stop

        Write-Host "[+] File created successfully at: $path" -ForegroundColor Green
        $fileCreated = $true
        $createdPath = $path
        break
    }
    catch {
        Write-Host "[-] Failed to create at $path : $($_.Exception.Message)" -ForegroundColor Red
    }
}

if (-not $fileCreated) {
    Write-Host "`n[-] Could not create EICAR file at any location" -ForegroundColor Red
    exit 1
}

Write-Host "`n[*] Waiting 3 seconds for SentinelOne to detect and quarantine the file..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# Check if file still exists
if (Test-Path $createdPath) {
    Write-Host "`n[-] FAILED: File still exists on disk!" -ForegroundColor Red
    Write-Host "    This suggests SentinelOne may not be actively protecting" -ForegroundColor Red
    Write-Host "    Path: $createdPath" -ForegroundColor Red
    Write-Host "`n[!] Possible issues:" -ForegroundColor Yellow
    Write-Host "    • SentinelOne is disabled or not running" -ForegroundColor Yellow
    Write-Host "    • Real-time protection is turned off" -ForegroundColor Yellow
    Write-Host "    • Agent may need to be reinstalled or reconfigured" -ForegroundColor Yellow
    Write-Host "    • Check SentinelOne console for agent status" -ForegroundColor Yellow
}
else {
    Write-Host "`n[+] SUCCESS: File was quarantined/deleted!" -ForegroundColor Green
    Write-Host "    SentinelOne is actively protecting this system" -ForegroundColor Green
    Write-Host "`n[+] SentinelOne is working properly. Safe to proceed with security tests." -ForegroundColor Green
}

Write-Host "`n[*] Check SentinelOne console for detection events" -ForegroundColor Cyan
