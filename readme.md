# phishing-ir-lab

A hands-on Incident Response / DFIR portfolio project simulating a
phishing-to-compromise attack chain, investigated end-to-end using Sysmon
telemetry in an isolated Windows lab environment.

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red)]()
[![Sysmon](https://img.shields.io/badge/Sysmon-SwiftOnSecurity%20config-blue)]()

## Why This Project

In a real security incident, an analyst isn't handed a summary — they're
handed raw logs and have to reconstruct what happened. This project builds
a small, fully controlled version of that problem: a benign simulated
"attack" was run against an isolated Windows VM, and then investigated
using the same tools, evidence, and reasoning a SOC analyst would apply to
a genuine incident.

This project is designed around the practical work of incident response
and threat detection:

- generating and capturing forensic-grade telemetry with Sysmon
- reconstructing an attack timeline from raw event logs
- distinguishing genuine evidence from unrelated background noise
- identifying and explaining real gaps in default detection coverage
- mapping findings to the MITRE ATT&CK framework
- producing analyst-style reporting for technical and non-technical audiences

## What Was Simulated

A PowerShell script mimicked the behavioural pattern of a phishing-delivered
payload — without using any real malicious code:

1. **Initial execution** — stands in for a user opening a malicious attachment
2. **Process spawn** — PowerShell launches a secondary process (dropper → payload pattern)
3. **File drop** — a benign placeholder file written to disk, mimicking a payload
4. **C2 callout attempt** — a connection attempt to a non-routable test IP (host was fully network-isolated)
5. **Persistence** — a registry Run key added, mimicking malware surviving a reboot

Each stage maps to a named MITRE ATT&CK technique (T1059, T1105, T1071,
T1547.001) — see the full report for details.

## Key Findings

- The process-spawn and persistence steps were fully captured by Sysmon,
  with the registry write **automatically flagged** by the SwiftOnSecurity
  ruleset as a known technique (`T1060, RunKey`) — no manual tagging required.
- Two stages — the file drop and the network callout — were **not**
  captured by default logging. Both gaps are investigated and explained
  in the report, rather than left as unexplained blanks.
- Several unrelated background events (e.g. a `CreateRemoteThread` between
  two legitimate Windows processes) were investigated and correctly ruled
  out using causal analysis, not just timestamp proximity.

Full reasoning, evidence, and analysis: [`incident_report.md`](./incident_report.md)

## Lab Environment

| | |
|---|---|
| Host | Windows 11 (ARM64) |
| Virtualization | UTM on Apple Silicon (macOS) |
| Detection tooling | Sysmon v15.22, SwiftOnSecurity configuration |
| Network state | Fully isolated — no virtual network adapter attached |
| Simulation | Custom PowerShell script (this repo) |

The host was verified as genuinely network-isolated (not just
"NAT-restricted") before evidence collection, after an early attempt using
UTM's Emulated VLAN mode was found to still permit outbound connectivity.

## Repository Structure

```
phishing-ir-lab/
├── scripts/
│   ├── simulate_phishing_chain.ps1   # generates the simulated attack chain
│   └── cleanup_phishing_chain.ps1    # removes artifacts after evidence collection
├── timeline.md                       # timestamped evidence timeline
├── incident_report.md                # full analyst-style incident report
└── readme.md
```

## Reproducing This Lab

1. Set up an isolated Windows VM (this project used UTM + Windows 11 ARM64
   on Apple Silicon; any hypervisor works).
2. Install Sysmon with the [SwiftOnSecurity configuration](https://github.com/SwiftOnSecurity/sysmon-config).
3. Fully isolate the VM's network (remove the virtual network adapter
   entirely — NAT/"isolated" modes may still permit outbound traffic).
4. Run `scripts/simulate_phishing_chain.ps1` from an elevated PowerShell
   session.
5. Investigate the generated evidence in Event Viewer
   (`Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`).
6. Run `scripts/cleanup_phishing_chain.ps1` to remove the simulated
   artifacts afterward.

## Portfolio Value

This repository demonstrates a DFIR/SOC-style analyst workflow:

- **Detection engineering fundamentals**: Sysmon deployment, configuration,
  and platform-specific troubleshooting (ARM64 driver architecture, network
  isolation verification)
- **Evidence-based investigation**: building a timeline from raw telemetry,
  correlating related events across multiple log entries
- **Critical tooling assessment**: identifying and explaining real gaps in
  default detection coverage, rather than assuming full visibility
- **False-positive triage**: distinguishing genuine findings from benign
  background activity using causal reasoning
- **MITRE ATT&CK mapping**: framing findings in industry-standard terms
- **Analyst reporting**: producing an executive summary, technical
  findings, IOC list, containment guidance, and recommendations
