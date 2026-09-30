# Incident Response Report — Simulated Phishing-to-Compromise Incident

| | |
|---|---|
| **Report date** | 21 September 2026 |
| **Analyst** | Mandara |
| **Host** | WIN-JE46FAVJ3TV |
| **Environment** | Isolated Windows 11 (ARM64) VM — UTM, Apple Silicon host, no network adapter attached |
| **Detection tooling** | Sysmon v15.22 (SwiftOnSecurity configuration) |
| **Classification** | Simulated / lab exercise — no real malicious code used |

---

## Executive Summary

On 20 September 2026, a controlled simulation of a phishing-delivered
compromise was run against an isolated lab host to practise incident
investigation and to generate realistic forensic telemetry. The simulation
mimicked the pattern of a user opening a malicious email attachment,
resulting in a script-driven process spawning a secondary process,
attempting to drop a payload file, attempting to contact an external
server, and establishing persistence via a registry Run key.

No real malware was used at any stage. The exercise's purpose was to
generate evidence an analyst would need to investigate and to evaluate how
completely a standard, well-regarded Sysmon configuration (SwiftOnSecurity)
captures that activity.

**Key findings:**
- The core process-execution and persistence steps were fully captured and,
  in one case, automatically flagged by Sysmon's own rule set as a known
  attacker technique (T1060 / Registry Run Key).
- Two stages of the simulated chain — the file drop and the network
  callout — were **not** captured by default logging, revealing two
  concrete, explainable gaps in out-of-the-box Sysmon coverage.
- Several unrelated background events were investigated and correctly
  ruled out as false leads, demonstrating a causal (not just time-based)
  approach to log correlation.

No containment actions were required, as this was a controlled exercise on
an isolated host with no real payload. Recommendations below are framed as
they would be for a genuine finding of this nature.

---

## 1. Incident Narrative

A script execution (simulating an opened phishing attachment) launched
PowerShell, which in turn:

1. Spawned a secondary process to represent a dropped/executed payload.
2. Attempted to write a payload file to a user-writable directory.
3. Attempted to contact an external IP address, representing a
   command-and-control callout.
4. Wrote a registry Run key to establish persistence across reboots,
   pointing at the dropped file.

The host was network-isolated throughout, so the callout attempt was
expected to fail — the objective was to determine whether the *attempt*
itself would be logged, which is exactly the kind of evidence a defender
relies on even when an attack is ultimately unsuccessful.

Full timestamped detail is provided in the companion document,
[`timeline.md`](./timeline.md).

---

## 2. Technical Findings

### 2.1 Process execution
`powershell.exe` (PID 5052) spawned `calc.exe` (PID 6920) at
`2026-09-20 23:38:18.847 UTC`, representing the dropper-to-payload
handoff. Sysmon captured the full process metadata, including the
parent-child relationship and a SHA256 hash of the executed binary —
exactly the data an analyst would pivot on to check reputation against a
threat-intelligence source in a real investigation.

### 2.2 Persistence
The same PowerShell process (PID 5052) wrote a registry value at
`2026-09-20 23:38:23.497 UTC`, adding
`WindowsUpdateCacheSvc` under
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, pointing to the
dropped file. Sysmon's own rule engine automatically labelled this event
`T1060,RunKey` — flagging it as a known persistence technique without any
manual analyst interpretation required. This demonstrates the real,
practical value of a well-tuned Sysmon configuration beyond raw logging.

### 2.3 Detection gaps identified

**File creation not logged.** The dropped file
(`%APPDATA%\Microsoft\Windows\update_cache.tmp`) produced no `FileCreate`
Sysmon event. The SwiftOnSecurity configuration excludes common transient
extensions, including `.tmp`, from file-creation logging by design, to
reduce noise from legitimate temp-file activity. The file's path was still
recoverable via the registry event's `Details` field, and its existence
was independently confirmed with `Test-Path` (returned `True`).

**Network callout not logged.** The attempted connection to a
documentation-reserved test IP (`203.0.113.55`) produced no network or DNS
event in Sysmon. This is consistent with the configuration's selective
network-event logging and the connection likely failing before a monitored
stage was reached.

Both gaps are documented in detail, with explanations, in
[`timeline.md`](./timeline.md#3-documented-detection-gaps).

### 2.4 False leads investigated and ruled out
Four `CreateRemoteThread` events (`dwm.exe` → `csrss.exe`) and two
additional process-creation events (`ApplicationFrameHost.exe`,
`svchost.exe`) occurred in the same time window and were individually
reviewed. All were attributed to normal, legitimate Windows background
activity based on process identity and parent-child relationships, not
dismissed merely because they seemed coincidental — full reasoning is in
the timeline document.

---

## 3. Indicators of Compromise (IOCs)

| Type | Value | Notes |
|---|---|---|
| Process (simulated payload) | `calc.exe` | SHA256: `03D4E02A614ED0A53566AF0292FC3CB9657EDF8C0416959D5DEEF30B43A14F31` |
| Parent process | `powershell.exe` (PID 5052) | Origin of both the process spawn and the registry write |
| Dropped file path | `%APPDATA%\Microsoft\Windows\update_cache.tmp` | Not logged directly; recovered via registry event correlation |
| Persistence mechanism | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateCacheSvc` | Auto-flagged by Sysmon as T1060/RunKey |
| Attempted C2 address | `203.0.113.55` (TEST-NET-3, reserved/non-routable) | Connection attempt not captured in logs |

*Note: these IOCs are artifacts of a controlled simulation, not indicators
of a real-world threat actor. They are listed here in the same format a
genuine incident report would use, for portfolio demonstration purposes.*

---

## 4. Containment Actions Taken

Not applicable — this was a controlled, isolated lab exercise using
benign simulated artifacts. In a genuine incident matching this profile,
appropriate containment would include:

- Isolating the affected host from the network immediately.
- Terminating the identified malicious process tree.
- Removing the persistence registry key.
- Deleting the dropped payload file.
- Blocking the C2 IP/domain at the network perimeter.
- Rotating any credentials used on the host during the suspected
  compromise window.

A cleanup script (`cleanup_phishing_chain.ps1`) was used in this exercise
to reverse the simulated artifacts once evidence collection was complete.

---

## 5. Recommendations

1. **Tune Sysmon's FileCreate filtering.** The default SwiftOnSecurity
   exclusion of `.tmp` files creates a monitoring blind spot. Consider a
   narrower exclusion list, or supplementary monitoring on high-risk
   directories such as `%APPDATA%` and `%TEMP%`.
2. **Expand network-event logging.** Broaden Sysmon's network-connection
   rules, or pair Sysmon with a dedicated network-monitoring layer (e.g.
   a SIEM ingesting firewall/proxy logs) to catch failed or blocked
   outbound connection attempts, which are often the only visible sign of
   an unsuccessful C2 callout.
3. **Retain and alert on registry Run-key writes.** Sysmon's automatic
   T1060 tagging in this exercise demonstrates real detective value; this
   event type should be forwarded to a SIEM and alerted on in any
   production environment, as legitimate Run-key writes by user processes
   are comparatively rare.
4. **Maintain a process-hash allowlist/denylist workflow.** Sysmon
   captured a SHA256 hash for every process automatically; operationalising
   this (e.g. checking hashes against VirusTotal or an internal
   allowlist) would close much of the gap left by the missing file/network
   visibility.

---

## 6. Lessons Learned (Personal / Portfolio Note)

This exercise reinforced that a "default" or widely-recommended
configuration (SwiftOnSecurity) is a strong starting point but not a
complete solution — two real, explainable gaps emerged even in a fully
controlled, small-scale test. Investigating *why* evidence is missing,
rather than treating a gap as a dead end, is as important a skill as
finding evidence in the first place. This report and its companion
timeline reflect that investigative process end-to-end, from initial
execution through to documented limitations and recommendations.
