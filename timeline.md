# Incident Timeline — Simulated Phishing-to-Compromise Chain

**Host:** WIN-JE46FAVJ3TV
**Analyst:** Mandara
**Lab environment:** Isolated Windows 11 (ARM64) VM, UTM on Apple Silicon, no network adapter attached
**Detection source:** Sysmon v15.22 (SwiftOnSecurity configuration)
**Simulation date:** 20 September 2026
**All timestamps below are UTC, as recorded by Sysmon.**

---

## 1. Scenario Overview

This timeline documents a controlled, benign simulation of a phishing-delivered
compromise. A PowerShell script (`simulate_phishing_chain.ps1`) was executed
locally to mimic the behavioural pattern of a phishing payload — process
spawning, a dropped file, an attempted command-and-control callout, and a
registry-based persistence mechanism — without using any real malicious code.
The goal was to generate realistic Sysmon telemetry and practise the
investigation workflow an analyst would follow against a genuine incident.

The host was fully isolated from any network (no virtual network adapter
attached in UTM) before the simulation was run, so any "callout" behaviour
was expected to fail — the value being tested was whether the *attempt*
would be logged.

---

## 2. Confirmed Evidence Timeline

| # | Time (UTC) | Event ID | Description | Key Detail |
|---|---|---|---|---|
| 1 | 23:38:18.847 | 1 (Process Create) | `powershell.exe` (PID 5052) spawns `calc.exe` (PID 6920) as a stand-in dropped process | `ParentImage` confirms PowerShell as the origin process; SHA256 hash captured |
| 2 | 23:38:23.497 | 13 (Registry value set) | Same PowerShell process (PID 5052) writes a Run key: `WindowsUpdateCacheSvc` pointing to the dropped file | Sysmon automatically tagged this event `RuleName: T1060,RunKey` — the config recognised it as a known persistence technique without manual analysis |
| 3 | — | — | Existence of dropped file `%APPDATA%\Microsoft\Windows\update_cache.tmp` confirmed independently via `Test-Path` (returned `True`) | Verified via direct filesystem check, not a Sysmon log entry — see Section 3 |

Process linkage: Event 1 and Event 2 share the same `ProcessId` (5052) for the
PowerShell parent, allowing both actions to be attributed to a single
originating process — the expected behaviour of a dropper script performing
more than one action.

---

## 3. Documented Detection Gaps

Two expected pieces of evidence did **not** appear as standalone Sysmon
events. Both were investigated and explained rather than treated as
inconclusive:

### 3.1 File creation (Event ID 11) not logged
The dropped file (`update_cache.tmp`) did not generate a `FileCreate` event.
The SwiftOnSecurity Sysmon configuration deliberately excludes common
transient file extensions, including `.tmp`, from `FileCreate` logging to
reduce noise from legitimate Windows temp-file activity. The file's location
was still recoverable through the registry persistence event (Event 13),
whose `Details` field explicitly referenced the file's full path — allowing
reconstruction of the artifact without a direct file-creation log entry.
Existence was confirmed independently via `Test-Path`.

**Takeaway:** default Sysmon configs trade completeness for noise reduction.
An attacker using an excluded extension (or a legitimate-looking one) could
partially evade file-creation monitoring under this configuration.

### 3.2 Network callout attempt (Event ID 3 / 22) not logged
The script's `Test-NetConnection` attempt to a reserved documentation IP
(`203.0.113.55`, TEST-NET-3) generated no Sysmon network-connection or DNS
event. This is consistent with the SwiftOnSecurity configuration's selective
network logging, and with the connection likely failing at the DNS/routing
stage before a monitored connection attempt occurred.

**Takeaway:** this is a second real detection gap. A more thorough config,
or a dedicated network-monitoring layer (e.g. Sentinel, a proxy log, or
packet capture), would be needed to catch failed or blocked C2 attempts
reliably.

---

## 4. Noise Investigated and Ruled Out

Several unrelated events appeared in the same log window and were reviewed
to confirm they were not part of the simulated chain:

| Time (UTC) | Event | Why it was ruled out |
|---|---|---|
| 23:37:22–23:37:27 (×4) | `CreateRemoteThread` (Event 8): `dwm.exe` → `csrss.exe` | Both are legitimate, core Windows system processes; this pattern is a normal part of Windows desktop rendering/session management, not indicative of code injection by the simulated payload |
| 23:37:05 | `FileCreate` (Event 11): `__PSScriptPolicyTest_*.ps1` | A temporary file PowerShell creates automatically when evaluating script execution policy — routine PowerShell internals, unrelated to the payload |
| 23:38:18 | `ProcessCreate` (Event 1): `ApplicationFrameHost.exe` | Standard Windows process that hosts modern app window frames; consistent with the Calculator window opening as part of Stage 2 |
| 23:38:19 | `ProcessCreate` (Event 1): `svchost.exe -k LocalService -p -s NPSMSvc` | Routine Windows service-host activity spawned by `services.exe`, coincidentally timed near the simulation but causally unrelated (different parent process) |

Ruling these out by checking `ParentImage`/`SourceImage`/`TargetImage`
against known-legitimate Windows binaries — rather than by proximity in
time alone — reflects standard analyst practice: correlation should be
based on causal/process relationships, not just a shared time window.

---

## 5. MITRE ATT&CK Mapping

| Stage | Technique | ID |
|---|---|---|
| Initial execution (simulated attachment) | Command and Scripting Interpreter | T1059 |
| Dropped/spawned process | Ingress Tool Transfer (simulated) | T1105 |
| Attempted C2 callout | Application Layer Protocol (simulated, failed) | T1071 |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 (logged by Sysmon under legacy ID T1060) |

---

## 6. Next Steps

- Build the full incident report (executive summary, technical findings,
  containment actions, recommendations) from this timeline.
- Extract IOCs (process names, hashes, file path, registry key, fake C2 IP)
  into a standalone IOC list.
- Optionally: re-run with a tuned Sysmon config that captures `.tmp`
  FileCreate events and broader network logging, to compare detection
  coverage before/after — a strong "lessons learned" addition to the report.
