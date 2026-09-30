<#
====================================================================
 PHISHING-TO-COMPROMISE SIMULATION SCRIPT
 Purpose: Generate benign, safe artifacts that mimic the behavioral
          pattern of a phishing-delivered payload, for use in a
          personal Incident Response lab (isolated VM only).

 IMPORTANT: This script does NOT download, execute, or contain any
 real malicious code. It only mimics the *shape* of an attack
 (process spawning, file creation, a failed network attempt, and a
 registry write) so that Sysmon generates realistic, investigable
 log data. Only run this inside an isolated, network-disconnected VM.
====================================================================
#>

Write-Host "=== Starting phishing-to-compromise simulation ===" -ForegroundColor Cyan
Write-Host "Timestamp: $(Get-Date)" -ForegroundColor Cyan

# --------------------------------------------------------------
# STEP 1: Simulated "initial execution"
# Real-world equivalent: victim opens a malicious email attachment
# (e.g. a Word doc with a macro), which silently runs a script.
# MITRE ATT&CK: T1566 (Phishing) -> T1059 (Command and Scripting
# Interpreter)
# --------------------------------------------------------------
Write-Host "`n[Stage 1] Simulating initial execution (attachment opened)..." -ForegroundColor Yellow
Start-Sleep -Seconds 1

# --------------------------------------------------------------
# STEP 2: Simulated "dropper" - child process spawned
# Real-world equivalent: the macro/script launches a second process
# to do the actual dirty work. This parent->child relationship
# (powershell.exe spawning another process) is one of the most
# important things Sysmon Event ID 1 captures for investigators.
# MITRE ATT&CK: T1059 (Command and Scripting Interpreter)
# --------------------------------------------------------------
Write-Host "[Stage 2] Spawning child process (simulated dropper)..." -ForegroundColor Yellow

# We spawn a harmless built-in Windows binary (calc.exe) as a stand-in
# "child process" so Sysmon logs a realistic parent-child chain.
# In a real attack this might be powershell.exe spawning another
# instance of itself, or cmd.exe, or a downloaded binary.
Start-Process -FilePath "calc.exe"
Start-Sleep -Seconds 2
Get-Process calc -ErrorAction SilentlyContinue | Stop-Process -Force

# --------------------------------------------------------------
# STEP 3: Simulated "payload drop"
# Real-world equivalent: the dropper writes a malicious file to disk
# (e.g. a second-stage payload, a stealer, a ransomware binary).
# MITRE ATT&CK: T1105 (Ingress Tool Transfer)
# --------------------------------------------------------------
Write-Host "[Stage 3] Dropping simulated payload file..." -ForegroundColor Yellow

$dropPath = "$env:APPDATA\Microsoft\Windows\update_cache.tmp"
"This is a benign placeholder file simulating a dropped payload. No real payload content." | Out-File -FilePath $dropPath -Encoding ASCII
Write-Host "  -> File written to: $dropPath"

# --------------------------------------------------------------
# STEP 4: Simulated "command-and-control callout"
# Real-world equivalent: the payload tries to reach out to an
# attacker-controlled server to receive further instructions or
# exfiltrate data. Since this VM is network-isolated, this
# connection attempt will FAIL - and that failure is expected and
# fine. Sysmon Event ID 3 (or a failed-connection trace) still
# shows the attempt was made, which is exactly what we want to see
# and explain in the report.
# MITRE ATT&CK: T1071 (Application Layer Protocol) / T1105
# --------------------------------------------------------------
Write-Host "[Stage 4] Attempting simulated C2 callout (expected to fail - VM is isolated)..." -ForegroundColor Yellow

$fakeC2 = "203.0.113.55"  # TEST-NET-3 address reserved for documentation, not a real attacker IP
try {
    Test-NetConnection -ComputerName $fakeC2 -Port 443 -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
} catch {
    Write-Host "  -> Callout attempt failed as expected (no network access)." -ForegroundColor DarkGray
}

# --------------------------------------------------------------
# STEP 5: Simulated persistence attempt
# Real-world equivalent: malware adds itself to a registry Run key
# so it survives a reboot and keeps running.
# MITRE ATT&CK: T1547.001 (Boot or Logon Autostart Execution:
# Registry Run Keys)
# --------------------------------------------------------------
Write-Host "[Stage 5] Simulating persistence via registry Run key..." -ForegroundColor Yellow

$runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$valueName  = "WindowsUpdateCacheSvc"   # deliberately named to look plausible, like real malware would
$valueData  = "$dropPath"

New-ItemProperty -Path $runKeyPath -Name $valueName -Value $valueData -PropertyType String -Force | Out-Null
Write-Host "  -> Registry value '$valueName' added under $runKeyPath"

Write-Host "`n=== Simulation complete ===" -ForegroundColor Cyan
Write-Host "Go to Event Viewer > Applications and Services Logs > Microsoft > Windows > Sysmon > Operational"
Write-Host "and look for events starting from: $(Get-Date)"
Write-Host "`nCLEANUP: to remove the artifacts this script created, run cleanup_phishing_chain.ps1"
