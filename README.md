# Home SIEM Lab — Detection Engineering & Troubleshooting

A self-built Security Onion SIEM lab used to practice detection engineering, threat emulation (MITRE ATT&CK), and Linux/network troubleshooting. Built entirely in VMware Workstation on a single host, with a focus on understanding *why* detections do or don't fire — not just running tools and screenshotting green checkmarks.

## Why this project

I'm a cleared IT/security professional (COMSEC, information assurance, tactical network integration) transitioning toward security analyst and software development roles. This lab is where I'm building hands-on SOC/detection experience to complement that background.

## Architecture

```
┌─────────────────────────────────────────────┐
│              VMware Workstation Pro           │
│                                               │
│  ┌────────────────┐      ┌─────────────────┐ │
│  │ Security Onion  │◄────►│  VMnet2 (host-  │ │
│  │ (Standalone)     │      │  only, isolated)│ │
│  │ 16GB RAM, 4 CPU  │      │  192.168.50.0/24│ │
│  │ Zeek + Suricata  │      └────────┬────────┘ │
│  │ + Elastic Stack   │              │          │
│  └────────────────┘      ┌──────────┴───────┐ │
│                            │                  │ │
│                    ┌───────▼──────┐  ┌────────▼──────┐
│                    │ Windows 11   │  │ Kali Linux    │
│                    │ (target)     │  │ (attacker box)│
│                    │ Atomic Red   │  │               │
│                    │ Team         │  │               │
│                    └──────────────┘  └───────────────┘
└─────────────────────────────────────────────┘
```

- **Sensor:** Security Onion 2.4 (Standalone) — Zeek, Suricata, Elasticsearch, Kibana-based "Hunt"/Alerts UI
- **Target:** Windows 11, running [Atomic Red Team](https://github.com/redcanaryco/invoke-atomicredteam) to emulate specific MITRE ATT&CK techniques
- **Attacker vantage point:** Kali Linux, used as a real network peer for techniques requiring cross-host traffic
- **Isolated network:** All lab traffic confined to a host-only VMnet, separate from the home network

## Detection Investigations

### 1. T1046 — Network Service Scanning
Ran a PowerShell-based `/24` subnet port scan (T1046-10) from the Windows target. Confirmed via `tcpdump` and Zeek's `conn.log` that the scan traffic was captured and logged correctly (`S0` connection states across many destination IPs, port 445) — but **no Suricata alert fired**.

**Finding:** Horizontal port-scan detection signatures are disabled by default in Suricata's ET Open ruleset (a conservative default to reduce noise in production). This is a legitimate, common analyst scenario: traffic can be fully visible in logs while still not triggering an alert, depending on which signatures are enabled. Confirmed the detection pipeline itself was healthy via a separate real alert, ruling out a broken sensor.

### 2. T1003 — OS Credential Dumping (NTLM hash disclosure via RPC)
Ran the same technique (`T1003-7`, forcing an NTLM hash negotiation via `rpcping`) against three different targets to understand what a network sensor can and can't see:

| Target | Result |
|---|---|
| Gateway (no listening service) | Connection attempts logged by Zeek; no alert (no app-layer content to inspect) |
| **Windows' own IP (self)** | **Zero visibility at all** — traffic almost certainly stayed on loopback and never reached the network sensor |
| Kali (real peer, active listener) | **2 Suricata alerts fired**, including a full NTLM negotiation capture |

**Finding:** This progression demonstrates a core truth about network-based detection: a sensor can only see traffic that actually crosses the wire. A technique that "runs successfully" (exit code 0) can still be completely invisible to monitoring if it never leaves the host — a real blind spot that pure network monitoring has, and part of why production environments pair network sensors with endpoint telemetry (EDR/Sysmon).

The successful alert (`ET INFO NTLM Session Setup Request - Negotiate`, sid 2067085) was traced end-to-end: from the Suricata signature match, back to the raw payload bytes on the wire, confirming the literal `NTLMSSP` protocol string and the source machine's hostname were what the signature matched against.

## Notable Troubleshooting

Building this lab surfaced a wide range of real infrastructure problems — solving them is arguably as valuable as the detection work itself:

- **Security Onion install failures:** insufficient NICs, insufficient RAM, and a disk-space/LVM issue traced to root partition sizing (diagnosed via `df -h`, `vgs`, `lvs`, resolved by rebuilding with a properly-sized disk)
- **Hypervisor conflict:** VMware couldn't access VT-x/EPT due to Windows Memory Integrity (Core Isolation / VBS) silently claiming the virtualization layer — not visible through Hyper-V feature toggles or BIOS settings alone
- **Host-based firewall (default-deny):** Security Onion blocks all ports except explicitly allowed ones; had to work through hostgroup/portgroup configuration to open SSH and recover from a firewall misconfiguration that temporarily locked out the web UI
- **Resource planning:** documented actual RAM math showing how 16GB (sensor) + target + attacker VM allocations consume nearly all of a 32GB host's capacity, and adjusted VM sizing/boot sequencing accordingly
- **Elasticsearch/Kibana query lessons:** learned that guessing field names (e.g., raw Zeek field names vs. ECS-normalized fields) is unreliable — clicking real data values to auto-generate filters is a more robust approach when exploring unfamiliar data schemas

## Skills Demonstrated

`Linux administration` `Security Onion / Zeek / Suricata` `Elasticsearch & Kibana query fundamentals` `MITRE ATT&CK / Atomic Red Team` `VMware networking (NAT, host-only, promiscuous mode)` `LVM & disk troubleshooting` `Windows hypervisor/VBS internals` `Host-based firewall configuration` `PowerShell` `Root-cause troubleshooting methodology`

## What's Next

- Enable a horizontal port-scan detection rule and re-run T1046-10 to confirm it alerts once tuned
- Add endpoint-level telemetry (Sysmon or Elastic Agent on the Windows target) to close the network-visibility gap identified in the T1003 investigation
- Expand to additional ATT&CK techniques with more built-in signature coverage

---
*Full raw troubleshooting log and session-by-session notes available in [`LAB_NOTES.md`](./LAB_NOTES.md).*
