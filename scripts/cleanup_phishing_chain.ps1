<#
====================================================================
 CLEANUP SCRIPT for the phishing simulation
 Removes the dropped file and the registry Run key created by
 simulate_phishing_chain.ps1. Run this AFTER you've finished
 collecting evidence from Event Viewer, if you want to reset the
 VM back to a clean state without rolling back to the snapshot.
====================================================================
#>

Write-Host "=== Cleaning up simulation artifacts ===" -ForegroundColor Cyan

$dropPath = "$env:APPDATA\Microsoft\Windows\update_cache.tmp"
if (Test-Path $dropPath) {
    Remove-Item $dropPath -Force
    Write-Host "Removed dropped file: $dropPath"
} else {
    Write-Host "Dropped file not found (already removed?): $dropPath"
}

$runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$valueName  = "WindowsUpdateCacheSvc"

if (Get-ItemProperty -Path $runKeyPath -Name $valueName -ErrorAction SilentlyContinue) {
    Remove-ItemProperty -Path $runKeyPath -Name $valueName -Force
    Write-Host "Removed registry Run key: $valueName"
} else {
    Write-Host "Registry Run key not found (already removed?): $valueName"
}

Write-Host "`n=== Cleanup complete ===" -ForegroundColor Cyan
